#include "asn1c_internal.h"
#include "asn1c_out.h"

/*
 * Add an elementary chunk of target language text
 * into appropriate output stream.
 */
int
asn1c_compiled_output(arg_t *arg, const char *source, int lineno, const char *func, const char *fmt,
                      ...) {
	struct compiler_stream_destination_s *dst;
	const char *p;
	int lf_found;
	va_list ap;
	out_chunk_t *m;
	int ret;

	switch(arg->target->target) {
	case OT_IGNORE:
		return 0;
	default:
		dst = &arg->target->destination[arg->target->target];
		break;
	}

	/*
	 * Make sure the output has a single LF and only at the end.
	 */
	for(lf_found = 0, p = fmt; *p; p++) {
		if(*p == '\n') {
			lf_found++;
			assert(p[1] == '\0');
		}
	}
	assert(lf_found <= 1);

	/*
	 * Print out the indentation.
	 */
	if(dst->indented == 0) {
		int i = dst->indent_level;
		if (i < 0) {
			/* fatal error */
			fprintf(stderr, "target %d : Indent level %d ?!\n", arg->target->target, i);
			exit(1);
		}
		dst->indented = 1;
		while(i--) {
			ret = asn1c_compiled_output(arg, source, lineno, func, "\t");
			if(ret == -1) return -1;
		}
	}
	if(lf_found)
		dst->indented = 0;

    size_t debug_reserve_size = 0;
    if(lf_found && (arg->flags & A1C_DEBUG_OUTPUT_ORIGIN_LINES)) {
        debug_reserve_size =
            sizeof("\t// :100000 ()") + strlen(source) + strlen(func);
    }

	/*
	 * Allocate buffer.
	 */
	m = calloc(1, sizeof(out_chunk_t));
	if(m == NULL) return -1;

	m->len = 16;
	do {
		void *tmp;
		m->len <<= 2;
		tmp = realloc(m->buf, m->len + debug_reserve_size);
		if(tmp) {
			m->buf = (char *)tmp;
		} else {
			free(m->buf);
			free(m);
			return -1;
		}
		va_start(ap, fmt);
		ret = vsnprintf(m->buf, m->len, fmt, ap);
		va_end(ap);
	} while(ret >= (m->len - 1) || ret < 0);

	m->len = ret;

    /* Print out the origin of the lines */
    if(lf_found && (arg->flags & A1C_DEBUG_OUTPUT_ORIGIN_LINES)) {
        assert(m->buf[m->len - 1] == '\n');
        ret = snprintf(m->buf + m->len - 1, debug_reserve_size,
                       "\t// %s:%03d %s()\n", source, lineno, func);
        assert(ret > 0 && (size_t)ret < debug_reserve_size);
        m->len = m->len - 1 + ret;
    }

	if(arg->target->target == OT_INCLUDES
	|| arg->target->target == OT_FWD_DECLS
	|| arg->target->target == OT_POST_INCLUDE) {
		out_chunk_t *v;
		TQ_FOR(v, &dst->chunks, next) {
			if(m->len == v->len
			&& !memcmp(m->buf, v->buf, m->len))
				break;
		}
		if(v) {
			/* Entry is already present. Skip it. */
			free(m->buf);
			free(m);
			return 0;
		}
	}

	TQ_ADD(&dst->chunks, m, next);

	return 0;
}

void
asn1c_note_wide_long(arg_t *arg, const char *what, asn1c_integer_t lo,
                     asn1c_integer_t hi, int strict) {
	compiler_streams_t *cs = arg->target;
	const asn1c_integer_t i32min = -2147483647L - 1;
	const asn1c_integer_t i32max = 2147483647L;
	const asn1c_integer_t u32max = 4294967295UL;

	if(!cs || lo > hi) return;
	if(lo >= i32min && hi <= i32max) return;
	if(!strict && lo >= 0 && hi <= u32max) return;

	if(!cs->long_need) {
		const char *id = arg->expr ? arg->expr->Identifier : 0;
		cs->long_need = 1;
		cs->long_min = lo;
		cs->long_max = hi;
		char slo[64], shi[64];
		if(asn1p_itoa_s(slo, sizeof(slo), lo) < 0) slo[0] = '\0';
		if(asn1p_itoa_s(shi, sizeof(shi), hi) < 0) shi[0] = '\0';
		if(lo == hi)
			snprintf(cs->long_what, sizeof(cs->long_what), "%s%s%s %s",
				id ? id : "", id ? ": " : "", what, slo);
		else
			snprintf(cs->long_what, sizeof(cs->long_what),
				"%s%s%s (%s..%s)", id ? id : "", id ? ": " : "",
				what, slo, shi);
	} else {
		if(lo < cs->long_min) cs->long_min = lo;
		if(hi > cs->long_max) cs->long_max = hi;
	}
}

/* A decimal constant for #if, which must not be written as a plain literal
 * for the most negative 64-bit value. */
static void
long_guard_literal(char *buf, size_t size, asn1c_integer_t v) {
	if(v == (asn1c_integer_t)(-9223372036854775807LL - 1))
		snprintf(buf, size, "(-9223372036854775807 - 1)");
	else
		snprintf(buf, size, "%s", asn1p_itoa(v));
}

int
asn1c_make_long_guard(arg_t *arg, compiler_streams_t *cs) {
	struct compiler_stream_destination_s *dst;
	char hi[64], lo[64], text[1024];
	char what[sizeof(cs->long_what)];
	char cond[256];
	out_chunk_t *m;
	size_t i, j;
	int n;

	(void)arg;
	if(!cs || !cs->long_need) return 0;
	dst = &cs->destination[OT_LONG_GUARD];
	if(TQ_FIRST(&dst->chunks)) return 0;	/* Already made */

	/* Keep the text of the #error a plain C string. */
	for(i = j = 0; cs->long_what[i] && j + 1 < sizeof(what); i++) {
		unsigned char c = cs->long_what[i];
		what[j++] = (c == '"' || c == '\\' || c < 32 || c > 126) ? '?' : c;
	}
	what[j] = '\0';

	cond[0] = '\0';
	if(cs->long_max > 2147483647L) {
		/* Not more than a 64-bit long can ever hold: that is the
		 * width asked for (the bound is then handled as a value that
		 * does not fit, as on every platform). */
		asn1c_integer_t m = cs->long_max;
		if(m > (asn1c_integer_t)9223372036854775807LL)
			m = (asn1c_integer_t)9223372036854775807LL;
		long_guard_literal(hi, sizeof(hi), m);
		snprintf(cond, sizeof(cond), "LONG_MAX < %s", hi);
	}
	if(cs->long_min < -2147483647L - 1) {
		size_t l = strlen(cond);
		asn1c_integer_t m = cs->long_min;
		if(m < (asn1c_integer_t)(-9223372036854775807LL - 1))
			m = (asn1c_integer_t)(-9223372036854775807LL - 1);
		long_guard_literal(lo, sizeof(lo), m);
		snprintf(cond + l, sizeof(cond) - l, "%sLONG_MIN > %s",
			l ? " || " : "", lo);
	}
	if(!cond[0]) return 0;

	n = snprintf(text, sizeof(text),
		"/*\n"
		" * Some constants of this type do not fit a 32-bit long, which is what\n"
		" * long is on LLP64 systems (Windows). They would be silently truncated.\n"
		" */\n"
		"#include <limits.h>\n"
		"#if %s\n"
		"#error \"%s needs a 64-bit long; "
		"this platform has a 32-bit long (Windows LLP64), which is not supported\"\n"
		"#endif\n"
		"\n", cond, what);
	if(n <= 0 || (size_t)n >= sizeof(text)) return -1;

	m = calloc(1, sizeof(out_chunk_t));
	if(!m) return -1;
	m->buf = strdup(text);
	if(!m->buf) { free(m); return -1; }
	m->len = n;
	TQ_ADD(&dst->chunks, m, next);
	return 0;
}
