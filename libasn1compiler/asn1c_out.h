#ifndef	ASN1_COMPILED_OUTPUT_H
#define	ASN1_COMPILED_OUTPUT_H

/*
 * An elementary chunk of target language text.
 */
typedef struct out_chunk {
	char *buf;
	int len;

	TQ_ENTRY(struct out_chunk) next;
} out_chunk_t;

typedef struct compiler_streams {
	enum {
		OT_IGNORE,	/* Ignore this output */
		OT_INCLUDES,	/* #include files */
		OT_DEPS,	/* Dependencies (other than #includes) */
		OT_FWD_DECLS,	/* Forward declarations */
		OT_FWD_DEFS,	/* Forward definitions */
		OT_TYPE_DECLS,	/* Type declarations */
		OT_FUNC_DECLS,	/* Function declarations */
		OT_POST_INCLUDE,/* #include after type definition */
		OT_LONG_GUARD,	/* Platform guard: constants need a 64-bit long */
		OT_IOC_TABLES,	/* Information Object Class tables */
		OT_CTABLES,	/* Constraint tables */
		OT_CODE,	/* Some code */
		OT_CTDEFS,	/* Constraint definitions */
		OT_STAT_DEFS,	/* Static definitions */
		OT_MAX
	} target;

	struct compiler_stream_destination_s {
		TQ_HEAD(out_chunk_t) chunks;
		int indent_level;
		int indented;
	} destination[OT_MAX];

	/*
	 * Constants emitted for this type which do not fit a 32-bit long
	 * (see asn1c_note_wide_long()); turned into the OT_LONG_GUARD text
	 * when the streams are saved or printed.
	 */
	int long_need;
	asn1c_integer_t long_min, long_max;
	char long_what[160];
} compiler_streams_t;

static char *_compiler_stream2str[] __attribute__ ((unused))
    = { "IGNORE", "INCLUDES", "DEPS", "FWD-DECLS", "FWD-DEFS", "TYPE-DECLS", "FUNC-DECLS", "POST-INCLUDE", "LONG-GUARD", "IOC-TABLES", "CTABLES", "CODE", "CTDEFS", "STAT-DEFS" };

int asn1c_compiled_output(arg_t *arg, const char *file, int lineno,
                          const char *func, const char *fmt, ...)
    __attribute__((format(ASN1_PRINTF, 5, 6)));

/*
 * Record that a C constant of the type being generated (what) does not fit
 * a 32-bit long, where long is the type that holds it (PER bounds, DEFAULT
 * values, comparisons in the constraint function). With strict, only the
 * range [-2^31, 2^31-1] is acceptable; without it, the range [0, 2^32-1]
 * is too, which an unsigned long holds on every platform. The generated .c
 * file then refuses to compile where long is 32 bits (Windows).
 */
void asn1c_note_wide_long(arg_t *arg, const char *what, asn1c_integer_t lo,
                          asn1c_integer_t hi, int strict);

/* Turn a recorded need into the text of the OT_LONG_GUARD stream. */
int asn1c_make_long_guard(arg_t *arg, compiler_streams_t *cs);


/*****************************************************************
 * Useful macros for invoking asn1c_compiled_output() and friends.
 */

/* Redirect output to a different stream. */
#define	REDIR(foo)	do { arg->target->target = foo; } while(0)
#define INDENT_LEVEL	\
		arg->target->destination[arg->target->target].indent_level
#define	INDENT(val)	INDENT_LEVEL += (val)
#define	INDENTED(code)	do {					\
		INDENT(+1);					\
		do { code; } while(0);				\
		INDENT(-1);					\
	} while(0)

#define EMBED(ev)                                        \
    do {                                                 \
        arg->embed++;                                    \
        INDENTED(arg_t _tmp = *arg; _tmp.expr = ev;      \
                 _tmp.default_cb(&_tmp, NULL););         \
        arg->embed--;                                    \
        assert(arg->target->target == OT_TYPE_DECLS      \
               || arg->target->target == OT_FWD_DEFS);   \
    } while(0)

#define EMBED_WITH_IOCT(ev, ioc)                                   \
    do {                                                           \
        arg->embed++;                                              \
        INDENTED(arg_t _tmp = *arg; _tmp.expr = ev;                \
                 _tmp.default_cb(&_tmp, ((ioc).ioct ? &ioc : 0));); \
        arg->embed--;                                              \
        assert(arg->target->target == OT_TYPE_DECLS                \
               || arg->target->target == OT_FWD_DEFS);             \
    } while(0)

/* Output a piece of text into a default stream */
#define OUT(fmt, args...) \
    asn1c_compiled_output(arg, __FILE__, __LINE__, __func__, fmt, ##args)
#define	OUT_NOINDENT(fmt, args...)	do {			\
	int _saved_indent = INDENT_LEVEL;			\
	INDENT_LEVEL = 0;					\
	OUT(fmt, ##args);					\
	INDENT_LEVEL = _saved_indent;				\
} while(0)
#define	OUT_DEBUG(fmt, args...) do {				\
		if(arg->flags & A1C_DEBUG) OUT(fmt, ##args);	\
	} while(0)

/* Generate #include line */
#define GEN_INCLUDE_STD(typename)	do {			\
	if((arg->flags & A1C_INCLUDES_QUOTED)) {		\
		GEN_INCLUDE("\"" typename ".h\"");		\
	} else {						\
		GEN_INCLUDE("<" typename ".h>");		\
	} } while(0)
#define GEN_INCLUDE(filename)					\
	GEN_POS_INCLUDE(OT_INCLUDES, filename)
#define GEN_POSTINCLUDE(filename)				\
	GEN_POS_INCLUDE(OT_POST_INCLUDE, filename)
#define GEN_POS_INCLUDE(pos, filename)	do {			\
	int saved_target = arg->target->target;			\
	if(!filename) break;					\
	REDIR(pos);						\
	OUT_NOINDENT("#include %s\n", filename);		\
	REDIR(saved_target);					\
} while(0)
#define GEN_POS_INCLUDE_BASE(pos, expr) do {			\
	asn1p_expr_t *rhs_pspecs = expr->rhs_pspecs;		\
	expr->rhs_pspecs = (asn1p_expr_t *)0;			\
	int saved_target = arg->target->target;			\
	REDIR(pos);						\
	OUT_NOINDENT("#include %s\n",				\
		asn1c_type_name(arg, expr, TNF_INCLUDE));	\
	expr->rhs_pspecs = rhs_pspecs;				\
	REDIR(saved_target);					\
} while(0)

/* Generate ASN.1 type declaration */
#define	GEN_DECLARE(type_name, expr)	do {				\
	int saved_target = arg->target->target;				\
	REDIR(OT_FUNC_DECLS);						\
	OUT_NOINDENT("extern asn_TYPE_descriptor_t "			\
			"asn_DEF_%s;\n", MKID(expr));			\
	if (expr->_type_referenced) {					\
		OUT_NOINDENT("extern asn_%s_specifics_t "		\
				"asn_SPC_%s_specs_%d;\n", type_name,	\
				MKID(expr), expr->_type_unique_index);	\
		if(expr_elements_count(arg, expr))			\
			OUT_NOINDENT("extern asn_TYPE_member_t "	\
				"asn_MBR_%s_%d[%d];\n",			\
				MKID(expr), expr->_type_unique_index, 	\
				expr_elements_count(arg, expr));	\
	} 								\
	REDIR(saved_target);						\
} while(0)

/*
 * Format LONG_MIN according to C90 rules.
 */
#define OINT(iv)                       \
    do {                               \
        if(iv == (-2147483647L - 1))   \
            OUT("(-2147483647L - 1)"); \
        else                           \
            OUT("%s", asn1p_itoa(iv)); \
    } while(0)

#define OINTS(iv)                                              \
    do {                                                       \
        if(iv == (-2147483647L - 1))                           \
            OUT("(-2147483647L - 1)");                         \
        else                                                   \
            OUT("%s%s", (iv >= 0) ? " " : "", asn1p_itoa(iv)); \
    } while(0)

#endif	/* ASN1_COMPILED_OUTPUT_H */
