/*
 * DEFAULT of a SEQUENCE / SET / SEQUENCE OF / SET OF member:
 *  - an absent member decodes to the default (nested DEFAULTs included);
 *  - a member equal to the default is omitted (presence bit 0);
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
#include <R.h>

#define	T_NPRESENCE	6	/* f a b d e g */
#define	U_NPRESENCE	13	/* h i j k l m n o p q r s t */

static void *roundtrip(int aper, const asn_TYPE_descriptor_t *td, void *ti,
		uint8_t *buf, size_t bufsz, ssize_t *bits) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	void *to = 0;
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	er = aper ? aper_encode_to_buffer(td, 0, ti, buf, bufsz)
		  : uper_encode_to_buffer(td, 0, ti, buf, bufsz);
	assert(er.encoded > 0);
	*bits = er.encoded;

	rv = aper ? aper_decode(&ctx, td, &to, buf, bufsz, 0, 0)
		  : uper_decode(&ctx, td, &to, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(to);
	return to;
}

static void chk_pt(const Pt_t *p, long x, long y) {
	assert(p);
	assert(p->x == x);
	assert(p->y && *p->y == y);
}

static void chk_str(const OCTET_STRING_t *s, const char *want) {
	assert(s);
	assert(s->size == strlen(want));
	assert(memcmp(s->buf, want, s->size) == 0);
}

/* ---------------------------------------------------------------- T */

static void check_T_defaults(const T_t *t) {
	assert(t->f && t->f->m == 5);
	chk_pt(t->a, 1, 2);
	chk_pt(t->b, 1, 2);
	assert(t->d && t->d->list.count == 0);
	assert(t->e && t->e->list.count == 2);
	assert(*t->e->list.array[0] == 1 && *t->e->list.array[1] == 2);
	chk_pt(t->g, 4, 7);	/* g's y is filled from Pt's own DEFAULT */
}

static void run_T(int aper) {
	uint8_t buf[64];
	ssize_t bits;
	T_t t, *to, *to2;
	Pt_t pt;
	long y;
	long *e0;

	/* Everything absent: only z is encoded ("02"). */
	memset(&t, 0, sizeof(t));
	t.z = 1;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &asn_DEF_T, &t, buf, sizeof(buf), &bits);
	assert(bits == T_NPRESENCE + 1);
	assert(buf[0] == 0x02);
	check_T_defaults(to);

	/* The decoded defaults equal the defaults: omitted again. */
	memset(buf, 0xff, sizeof(buf));
	to2 = roundtrip(aper, &asn_DEF_T, to, buf, sizeof(buf), &bits);
	assert(bits == T_NPRESENCE + 1);
	assert(buf[0] == 0x02);
	check_T_defaults(to2);
	ASN_STRUCT_FREE(asn_DEF_T, to2);

	/* a.y = 3: a is not the default. */
	*to->a->y = 3;
	memset(buf, 0xff, sizeof(buf));
	to2 = roundtrip(aper, &asn_DEF_T, to, buf, sizeof(buf), &bits);
	if(aper) {
		assert(bits == 25);
		assert(buf[0] == 0x42 && buf[1] == 0x01
		    && buf[2] == 0x03 && buf[3] == 0x80);
	}
	assert(bits > T_NPRESENCE + 1);
	chk_pt(to2->a, 1, 3);
	chk_pt(to2->b, 1, 2);
	assert(to2->f && to2->f->m == 5);
	ASN_STRUCT_FREE(asn_DEF_T, to2);
	*to->a->y = 2;

	/* d = { 0 }: not the default { }. */
	e0 = calloc(1, sizeof(*e0));
	assert(to->d && ASN_SEQUENCE_ADD(&to->d->list, e0) == 0);
	memset(buf, 0xff, sizeof(buf));
	to2 = roundtrip(aper, &asn_DEF_T, to, buf, sizeof(buf), &bits);
	if(aper) {
		assert(bits == 14);
		assert(buf[0] == 0x10 && buf[1] == 0x84);
	}
	assert(to2->d && to2->d->list.count == 1 && *to2->d->list.array[0] == 0);
	chk_pt(to2->a, 1, 2);
	chk_pt(to2->g, 4, 7);
	ASN_STRUCT_FREE(asn_DEF_T, to2);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* g = { x 4 } with y absent: equal to the default { x 4, y 7 }. */
	memset(&t, 0, sizeof(t));
	t.z = 1;
	memset(&pt, 0, sizeof(pt));
	pt.x = 4;
	t.g = &pt;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &asn_DEF_T, &t, buf, sizeof(buf), &bits);
	assert(bits == T_NPRESENCE + 1);
	assert(buf[0] == 0x02);
	check_T_defaults(to);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* g = { x 4, y 7 } explicitly: still the default. */
	y = 7;
	pt.y = &y;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &asn_DEF_T, &t, buf, sizeof(buf), &bits);
	assert(bits == T_NPRESENCE + 1);
	assert(buf[0] == 0x02);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* g = { x 4, y 8 } is not. */
	y = 8;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &asn_DEF_T, &t, buf, sizeof(buf), &bits);
	assert(bits > T_NPRESENCE + 1);
	chk_pt(to->g, 4, 8);
	chk_pt(to->a, 1, 2);
	ASN_STRUCT_FREE(asn_DEF_T, to);
}

/* ---------------------------------------------------------------- U */

static void check_U_defaults(const U_t *u) {
	static const asn_oid_arc_t oi[] = { 1, 3, 6, 1, 4 };
	asn_oid_arc_t arcs[16];

	/* SET given out of order */
	assert(u->h && u->h->p == 3 && u->h->q);
	chk_str(u->h->r, "x");
	/* SEQUENCE OF SEQUENCE, the nested DEFAULT y filled in */
	assert(u->i && u->i->list.count == 2);
	chk_pt(u->i->list.array[0], 1, 7);
	chk_pt(u->i->list.array[1], 2, 3);
	/* XMLValueList: BOOLEAN and ENUMERATED */
	assert(u->j && u->j->list.count == 2);
	assert(*u->j->list.array[0] && !*u->j->list.array[1]);
	assert(u->k && u->k->list.count == 2);
	assert(*u->k->list.array[0] == Color_red);
	assert(*u->k->list.array[1] == Color_blue);
	/* nested SEQUENCE holding a SEQUENCE OF */
	assert(u->l && u->l->n.v.list.count == 2 && u->l->n.w == 9);
	assert(*u->l->n.v.list.array[0] == 3 && *u->l->n.v.list.array[1] == 4);
	/* extensible SEQUENCE with an extension addition given */
	assert(u->m && u->m->a == 1 && !u->m->b);
	assert(u->m->c && *u->m->c == 2);
	assert(u->m->d && *u->m->d);
	/* value reference to an imported value */
	assert(u->n && u->n->x == 9 && u->n->y && *u->n->y == 8);
	/* strings with & and < */
	chk_str(&u->o->s, "a&b");
	chk_str(&u->o->t, "x<y>z");
	/* OCTET STRING and OBJECT IDENTIFIER leaves */
	assert(u->p && u->p->oc.size == 4);
	assert(memcmp(u->p->oc.buf, "\xDE\xAD\xBE\xEF", 4) == 0);
	assert(OBJECT_IDENTIFIER_get_arcs(&u->p->oi, arcs, 16) == 5);
	assert(memcmp(arcs, oi, sizeof(oi)) == 0);
	/* a list of four numbers (quadruple) and a SEQUENCE OF a type name */
	assert(u->q && u->q->list.count == 4);
	assert(*u->q->list.array[0] == 1 && *u->q->list.array[3] == 4);
	assert(u->r && u->r->list.count == 2);
	assert(*u->r->list.array[0] == 5 && *u->r->list.array[1] == 6);
	/* a named element, a SET OF IA5String */
	assert(u->s && u->s->list.count == 1 && *u->s->list.array[0] == 7);
	assert(u->t && u->t->list.count == 2);
	chk_str(u->t->list.array[0], "A");
	chk_str(u->t->list.array[1], "B");
}

static void run_U(int aper) {
	uint8_t buf[256];
	ssize_t bits;
	U_t u, *to, *to2;
	const ssize_t omitted = U_NPRESENCE + 1;

	memset(&u, 0, sizeof(u));
	u.z = 1;
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(aper, &asn_DEF_U, &u, buf, sizeof(buf), &bits);
	assert(bits == omitted);
	assert(buf[0] == 0x00 && buf[1] == 0x04);
	check_U_defaults(to);

	/* Equal to the defaults: omitted again. */
	memset(buf, 0xff, sizeof(buf));
	to2 = roundtrip(aper, &asn_DEF_U, to, buf, sizeof(buf), &bits);
	assert(bits == omitted);
	assert(buf[0] == 0x00 && buf[1] == 0x04);
	check_U_defaults(to2);
	ASN_STRUCT_FREE(asn_DEF_U, to2);

#define	DIFFER(mutate, check)						\
	do {								\
		mutate;							\
		memset(buf, 0xff, sizeof(buf));				\
		to2 = roundtrip(aper, &asn_DEF_U, to, buf, sizeof(buf), &bits);\
		assert(bits > omitted);					\
		check;							\
		ASN_STRUCT_FREE(asn_DEF_U, to2);			\
	} while(0)

	/* Different from the default: encoded and round-trips. */
	DIFFER(to->h->p = 4, assert(to2->h->p == 4); chk_str(to2->h->r, "x"));
	DIFFER(to->h->p = 3; to->i->list.array[1]->x = 99,
		chk_pt(to2->i->list.array[1], 99, 3));
	DIFFER(to->i->list.array[1]->x = 2; *to->j->list.array[1] = 1,
		assert(*to2->j->list.array[1]));
	DIFFER(*to->j->list.array[1] = 0; *to->k->list.array[1] = Color_green,
		assert(*to2->k->list.array[1] == Color_green));
	DIFFER(*to->k->list.array[1] = Color_blue; to->l->n.w = 0,
		assert(to2->l->n.w == 0));
	DIFFER(to->l->n.w = 9; to->m->a = 2, assert(to2->m->a == 2));
	DIFFER(to->m->a = 1; *to->n->y = 0, assert(*to2->n->y == 0));
	DIFFER(*to->n->y = 8; to->o->s.buf[0] = 'b',
		assert(to2->o->s.buf[0] == 'b'));
	DIFFER(to->o->s.buf[0] = 'a'; to->p->oc.buf[0] = 0xDF,
		assert(to2->p->oc.buf[0] == 0xDF));
	DIFFER(to->p->oc.buf[0] = 0xDE; *to->q->list.array[3] = 5,
		assert(*to2->q->list.array[3] == 5));
	DIFFER(*to->q->list.array[3] = 4; *to->r->list.array[0] = 9,
		assert(*to2->r->list.array[0] == 9));
	DIFFER(*to->r->list.array[0] = 5; *to->s->list.array[0] = 8,
		assert(*to2->s->list.array[0] == 8));
	DIFFER(*to->s->list.array[0] = 7; to->t->list.array[0]->buf[0] = 'C',
		/* a SET OF is sorted by PER */
		assert(to2->t->list.array[1]->buf[0] == 'C'));
	to->t->list.array[0]->buf[0] = 'A';

	/* ... and back to the defaults. */
	memset(buf, 0xff, sizeof(buf));
	to2 = roundtrip(aper, &asn_DEF_U, to, buf, sizeof(buf), &bits);
	assert(bits == omitted);
	ASN_STRUCT_FREE(asn_DEF_U, to2);
	ASN_STRUCT_FREE(asn_DEF_U, to);
}

/* ---------------------------------------------------------------- R */

static void run_R(void) {
	/* No default callbacks for r (recursive DEFAULT): it behaves like
	 * OPTIONAL and the type still works. */
	uint8_t buf[16];
	R_t r, *to = 0;
	asn_codec_ctx_t ctx;
	asn_dec_rval_t rv;
	asn_enc_rval_t er;
	memset(&r, 0, sizeof(r));
	memset(&ctx, 0, sizeof(ctx));
	r.v = 3;
	er = uper_encode_to_buffer(&asn_DEF_R, 0, &r, buf, sizeof(buf));
	assert(er.encoded > 0);
	rv = uper_decode(&ctx, &asn_DEF_R, (void **)&to, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK);
	assert(to && to->v == 3 && to->r == 0);
	ASN_STRUCT_FREE(asn_DEF_R, to);
	assert(asn_DEF_R.elements[1].default_value_cmp == 0);
	assert(asn_DEF_R.elements[1].default_value_set == 0);
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	run_T(1);
	run_T(0);
	run_U(1);
	run_U(0);
	run_R();
	return 0;
}
