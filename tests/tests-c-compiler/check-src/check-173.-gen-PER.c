/*
 * DEFAULT of a named-bit BIT STRING, of OBJECT IDENTIFIER and of RELATIVE-OID:
 *  - an absent member decodes to the default, and the default is stored in the
 *    form PER produces (padded to the lower bound of a SIZE constraint);
 *  - a member equal to the default is omitted (presence bit 0); for a named-bit
 *    BIT STRING "equal" ignores trailing 0 bits (X.680 22.7);
 *  - any other value is encoded and round-trips.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <T.h>
#include <U.h>

#define	NPRESENCE	8	/* a e h f x o n r */

static T_t *roundtrip(int aper, T_t *ti, uint8_t *buf, size_t bufsz, ssize_t *bits) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	T_t *to = 0;
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	er = aper ? aper_encode_to_buffer(&asn_DEF_T, 0, ti, buf, bufsz)
		  : uper_encode_to_buffer(&asn_DEF_T, 0, ti, buf, bufsz);
	assert(er.encoded > 0);
	*bits = er.encoded;

	rv = aper ? aper_decode(&ctx, &asn_DEF_T, (void *)&to, buf, bufsz, 0, 0)
		  : uper_decode(&ctx, &asn_DEF_T, (void *)&to, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(to);
	return to;
}

static void bs(BIT_STRING_t *b, uint8_t *buf, size_t size, int unused) {
	memset(b, 0, sizeof(*b));
	b->buf = buf;
	b->size = size;
	b->bits_unused = unused;
}

static void check_oid(const OBJECT_IDENTIFIER_t *o, const asn_oid_arc_t *want, size_t n) {
	asn_oid_arc_t arcs[16];
	assert(o);
	assert((size_t)OBJECT_IDENTIFIER_get_arcs(o, arcs, 16) == n);
	assert(memcmp(arcs, want, n * sizeof(arcs[0])) == 0);
}

static void check_roid(const RELATIVE_OID_t *o, const asn_oid_arc_t *want, size_t n) {
	asn_oid_arc_t arcs[16];
	assert(o);
	assert((size_t)RELATIVE_OID_get_arcs(o, arcs, 16) == n);
	assert(memcmp(arcs, want, n * sizeof(arcs[0])) == 0);
}

/* Every default, as stored by the decoder for an absent member. */
static void check_defaults(const T_t *t) {
	static const asn_oid_arc_t o[] = { 1, 3, 6, 1, 4, 1, 9363 };
	static const asn_oid_arc_t n[] = { 1, 3, 6 };
	static const asn_oid_arc_t r[] = { 1, 2, 300 };

	/* { p, r }: bits 0 and 2, 3 bits */
	assert(t->a && t->a->size == 1 && t->a->bits_unused == 5
		&& t->a->buf[0] == 0xA0);
	/* { }: no bit */
	assert(t->e && t->e->size == 0 && t->e->bits_unused == 0);
	/* '60'H: bits 1 and 2; the trailing 0 bits are dropped: 3 bits */
	assert(t->h && t->h->size == 1 && t->h->bits_unused == 5
		&& t->h->buf[0] == 0x60);
	/* { q } under (SIZE (8..16)): padded to 8 bits */
	assert(t->f && t->f->size == 1 && t->f->bits_unused == 0
		&& t->f->buf[0] == 0x40);
	/* { app } under (SIZE (8)): 8 bits */
	assert(t->x && t->x->size == 1 && t->x->bits_unused == 0
		&& t->x->buf[0] == 0x80);
	check_oid(t->o, o, 7);
	check_oid(t->n, n, 3);
	check_roid(t->r, r, 3);
}

static void run(int aper) {
	uint8_t buf[128];
	ssize_t bits;
	T_t t, *to;
	/* b = TRUE after NPRESENCE presence bits */
	const ssize_t omitted_bits = NPRESENCE + 1;

	/* Everything absent: only b is encoded; decoding fills the defaults. */
	memset(&t, 0, sizeof(t));
	t.b = 1;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &t, buf, sizeof(buf), &bits);
	assert(bits == omitted_bits);
	assert(buf[0] == 0x00 && (buf[1] & 0x80));
	check_defaults(to);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* Members equal to their default are omitted. */
	{
		/* a = { p, r } with the unused bits garbage, and again with trailing 0 bits */
		uint8_t av[] = { 0xA7 };		/* unused bits are ignored */
		uint8_t hv[] = { 0x60, 0x00 };		/* '60'H plus 8 more 0 bits */
		uint8_t ev[] = { 0x00 };		/* no bit set, 5 bits wide */
		uint8_t fv[] = { 0x40, 0x00 };		/* { q } as 16 bits */
		uint8_t xv[] = { 0x80 };		/* { app }, 8 bits */
		uint8_t ov[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0xc9, 0x13 };
		BIT_STRING_t a, e, h, f, x;
		OBJECT_IDENTIFIER_t o, n;
		RELATIVE_OID_t r;
		asn_oid_arc_t narcs[] = { 1, 3, 6 };
		asn_oid_arc_t rarcs[] = { 1, 2, 300 };

		bs(&a, av, 1, 5);
		bs(&e, ev, 1, 3);
		bs(&h, hv, 2, 0);
		bs(&f, fv, 2, 0);
		bs(&x, xv, 1, 0);
		memset(&o, 0, sizeof(o));
		memset(&n, 0, sizeof(n));
		memset(&r, 0, sizeof(r));
		o.buf = ov; o.size = sizeof(ov);
		assert(OBJECT_IDENTIFIER_set_arcs(&n, narcs, 3) == 0);
		assert(RELATIVE_OID_set_arcs(&r, rarcs, 3) == 0);
		memset(&t, 0, sizeof(t));
		t.a = &a; t.e = &e; t.h = &h; t.f = &f; t.x = &x;
		t.o = &o; t.n = &n; t.r = &r;
		t.b = 1;
		memset(buf, 0xff, sizeof(buf));
		to = roundtrip(aper, &t, buf, sizeof(buf), &bits);
		assert(bits == omitted_bits);
		assert(buf[0] == 0x00);
		check_defaults(to);
		ASN_STRUCT_FREE(asn_DEF_T, to);
		FREEMEM(n.buf);
		FREEMEM(r.buf);
	}

	/* A different value is encoded, and decodes to itself. */
	{
		uint8_t av[] = { 0x80 };		/* { p } */
		uint8_t xv[] = { 0x00 };		/* 8 zero bits: not { app } */
		uint8_t fv[] = { 0x40, 0x80 };		/* { q, 8 } */
		BIT_STRING_t a, x, f;
		OBJECT_IDENTIFIER_t o;
		RELATIVE_OID_t r;
		asn_oid_arc_t oarcs[] = { 1, 3, 6, 1, 4, 1, 9364 };
		asn_oid_arc_t rarcs[] = { 1, 2 };
		asn_oid_arc_t o2[] = { 1, 3, 6, 1, 4, 1, 9364 };
		asn_oid_arc_t r2[] = { 1, 2 };

		bs(&a, av, 1, 7);
		bs(&x, xv, 1, 0);
		bs(&f, fv, 2, 0);
		memset(&o, 0, sizeof(o));
		memset(&r, 0, sizeof(r));
		assert(OBJECT_IDENTIFIER_set_arcs(&o, oarcs, 7) == 0);
		assert(RELATIVE_OID_set_arcs(&r, rarcs, 2) == 0);
		memset(&t, 0, sizeof(t));
		t.a = &a; t.x = &x; t.f = &f; t.o = &o; t.r = &r;
		t.b = 0;
		memset(buf, 0, sizeof(buf));
		to = roundtrip(aper, &t, buf, sizeof(buf), &bits);
		assert(bits > omitted_bits);
		/* presence of a, f, x, o, r; absent e h n */
		assert((buf[0] & 0xF8) != 0);
		assert(to->a && to->a->size == 1 && to->a->bits_unused == 7
			&& to->a->buf[0] == 0x80);
		assert(to->x && to->x->size == 1 && to->x->buf[0] == 0x00);
		assert(to->f && to->f->size == 2 && to->f->buf[0] == 0x40
			&& to->f->buf[1] == 0x80);
		check_oid(to->o, o2, 7);
		check_roid(to->r, r2, 2);
		/* the others stay the default */
		assert(to->e && to->e->size == 0);
		assert(to->h && to->h->buf[0] == 0x60);
		ASN_STRUCT_FREE(asn_DEF_T, to);
		FREEMEM(o.buf);
		FREEMEM(r.buf);
	}

	/* Prefixes and extensions of the default arcs are not the default. */
	{
		OBJECT_IDENTIFIER_t o;
		asn_oid_arc_t shorter[] = { 1, 3, 6, 1, 4, 1 };
		asn_oid_arc_t longer[] = { 1, 3, 6, 1, 4, 1, 9363, 0 };
		int i;
		for(i = 0; i < 2; i++) {
			memset(&o, 0, sizeof(o));
			assert(OBJECT_IDENTIFIER_set_arcs(&o, i ? longer : shorter,
				i ? 8 : 6) == 0);
			memset(&t, 0, sizeof(t));
			t.o = &o;
			t.b = 1;
			memset(buf, 0, sizeof(buf));
			to = roundtrip(aper, &t, buf, sizeof(buf), &bits);
			assert(bits > omitted_bits);
			assert(to->o && to->o->size == o.size
				&& memcmp(to->o->buf, o.buf, o.size) == 0);
			ASN_STRUCT_FREE(asn_DEF_T, to);
			FREEMEM(o.buf);
		}
	}
}

/*
 * DEFAULT of an OBJECT IDENTIFIER / RELATIVE-OID given by value references:
 * U.a .. U.i, the arcs they resolve to.
 */
static const asn_oid_arc_t ua[] = { 1, 3, 6, 1 };
static const asn_oid_arc_t ub[] = { 1, 3, 6, 1, 5 };
static const asn_oid_arc_t uc[] = { 1, 3, 6, 1, 4, 1 };
static const asn_oid_arc_t ue[] = { 2, 5, 29, 15 };
static const asn_oid_arc_t uf[] = { 1, 3, 6, 1, 8, 9 };
static const asn_oid_arc_t ug[] = { 1, 3, 6, 1, 42 };
static const asn_oid_arc_t ui[] = { 8, 9, 1 };

static void check_u_defaults(const U_t *u) {
	check_oid(u->a, ua, 4);
	check_oid(u->b, ub, 5);
	check_oid(u->c, uc, 6);
	check_oid(u->d, ua, 4);	/* id-alias ::= id-base */
	check_oid(u->e, ue, 4);	/* imported id-ext */
	check_oid(u->f, uf, 6);
	check_oid(u->g, ug, 5);
	check_roid(u->i, ui, 3);
}

static void run_u(int aper) {
	uint8_t buf[128];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	U_t t, *to = 0;
	OBJECT_IDENTIFIER_t a, b, c, d, e, f, g;
	RELATIVE_OID_t i;
	asn_oid_arc_t other[] = { 1, 3, 6, 2 };
	asn_oid_arc_t irel[] = { 8, 9, 2 };
	OBJECT_IDENTIFIER_t *os[] = { &a, &b, &c, &d, &e, &f, &g };
	const asn_oid_arc_t *dv[] = { ua, ub, uc, ua, ue, uf, ug };
	const size_t dn[] = { 4, 5, 6, 4, 4, 6, 5 };
	size_t k;
	memset(&ctx, 0, sizeof(ctx));

	/* Absent: only z is encoded (8 presence bits + 1). */
	memset(&t, 0, sizeof(t));
	t.z = 1;
	memset(buf, 0xff, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf));
	assert(er.encoded == 9);
	assert(buf[0] == 0x00 && (buf[1] & 0x80));
	rv = aper ? aper_decode(&ctx, &asn_DEF_U, (void *)&to, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_U, (void *)&to, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && to);
	check_u_defaults(to);
	ASN_STRUCT_FREE(asn_DEF_U, to);
	to = 0;

	/* Every member equal to its default is omitted. */
	memset(&t, 0, sizeof(t));
	for(k = 0; k < 7; k++) {
		memset(os[k], 0, sizeof(*os[k]));
		assert(OBJECT_IDENTIFIER_set_arcs(os[k], dv[k], dn[k]) == 0);
	}
	memset(&i, 0, sizeof(i));
	assert(RELATIVE_OID_set_arcs(&i, ui, 3) == 0);
	t.a = &a; t.b = &b; t.c = &c; t.d = &d; t.e = &e; t.f = &f; t.g = &g;
	t.i = &i;
	t.z = 1;
	memset(buf, 0xff, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf));
	assert(er.encoded == 9);
	assert(buf[0] == 0x00);
	for(k = 0; k < 7; k++) FREEMEM(os[k]->buf);
	FREEMEM(i.buf);

	/* Different values are encoded and round-trip. */
	memset(&a, 0, sizeof(a));
	memset(&i, 0, sizeof(i));
	assert(OBJECT_IDENTIFIER_set_arcs(&a, other, 4) == 0);
	assert(RELATIVE_OID_set_arcs(&i, irel, 3) == 0);
	memset(&t, 0, sizeof(t));
	t.a = &a; t.i = &i;
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_U, 0, &t, buf, sizeof(buf));
	assert(er.encoded > 9);
	assert((buf[0] & 0x81) == 0x81);	/* a and i present */
	rv = aper ? aper_decode(&ctx, &asn_DEF_U, (void *)&to, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_U, (void *)&to, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && to);
	check_oid(to->a, other, 4);
	check_roid(to->i, irel, 3);
	check_oid(to->b, ub, 5);
	check_oid(to->e, ue, 4);
	ASN_STRUCT_FREE(asn_DEF_U, to);
	FREEMEM(a.buf);
	FREEMEM(i.buf);
}

int main() {
	run(1);
	run(0);
	run_u(1);
	run_u(0);
	return 0;
}
