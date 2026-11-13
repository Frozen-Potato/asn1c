/*
 * Nested and wide-INTEGER SEQUENCE OF / SET OF: the generated C compiles
 * (an unsigned INTEGER element has its own type descriptor; a list nested in
 * a list no longer interleaves the two typedefs; SIZE on both lists parses),
 * and values round-trip through UPER.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <WideTop.h>
#include <WideTopSet.h>
#include <WideMember.h>
#include <NestSeq.h>
#include <NestSet.h>
#include <NestChoice.h>
#include <NestChoiceSet.h>
#include <NestWide.h>
#include <Deep.h>
#include <Sized.h>
#include <SizedSet.h>
#include <SizedWide.h>
#include <SizedMember.h>

static void *
mk(size_t sz) {
	void *p = calloc(1, sz);
	assert(p);
	return p;
}

static unsigned long *
mkulong(unsigned long v) {
	unsigned long *p = mk(sizeof(*p));
	*p = v;
	return p;
}

/*
 * Constraints, then UPER encode, decode, re-encode: the bytes must match.
 * Returns the number of bits of the encoding.
 */
static ssize_t
roundtrip(const asn_TYPE_descriptor_t *td, const void *in, uint8_t *buf,
		size_t bufsz) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	void *out = 0;
	uint8_t buf2[256];
	char errbuf[128];
	size_t errlen = sizeof(errbuf);

	memset(&ctx, 0, sizeof(ctx));
	assert(asn_check_constraints(td, in, errbuf, &errlen) == 0);

	memset(buf, 0, bufsz);
	er = uper_encode_to_buffer(td, 0, in, buf, bufsz);
	assert(er.encoded > 0);
	rv = uper_decode(&ctx, td, &out, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(out);
	assert(td->op->compare_struct(td, in, out) == 0);

	memset(buf2, 0, sizeof(buf2));
	{
		asn_enc_rval_t er2 =
			uper_encode_to_buffer(td, 0, out, buf2, sizeof(buf2));
		assert(er2.encoded == er.encoded);
		assert(memcmp(buf, buf2, (er.encoded + 7) / 8) == 0);
	}
	ASN_STRUCT_FREE(*td, out);
	return er.encoded;
}

static int
violates(const asn_TYPE_descriptor_t *td, const void *in) {
	char errbuf[128];
	size_t errlen = sizeof(errbuf);
	return asn_check_constraints(td, in, errbuf, &errlen) != 0;
}

#define	RT(td, v)	roundtrip(&asn_DEF_##td, (v), buf, sizeof(buf))

int main() {
	uint8_t buf[128];
	ssize_t bits;

	/* SEQUENCE OF INTEGER (0..4294967295): 8-bit count + 32-bit value */
	{
		WideTop_t t;
		memset(&t, 0, sizeof(t));
		ASN_SEQUENCE_ADD(&t.list, mkulong(5));
		bits = RT(WideTop, &t);
		assert(bits == 40);
		assert(buf[0] == 0x01 && buf[4] == 0x05);
		ASN_SEQUENCE_ADD(&t.list, mkulong(4294967295UL));
		bits = RT(WideTop, &t);
		assert(bits == 72);
		ASN_STRUCT_RESET(asn_DEF_WideTop, &t);
	}
	{
		WideTopSet_t t;
		memset(&t, 0, sizeof(t));
		ASN_SEQUENCE_ADD(&t.list, mkulong(70000));
		ASN_SEQUENCE_ADD(&t.list, mkulong(0));
		bits = RT(WideTopSet, &t);
		assert(bits > 0);
		ASN_STRUCT_RESET(asn_DEF_WideTopSet, &t);
	}

	/* A wide element in sized lists, one of them OPTIONAL */
	{
		WideMember_t *t = mk(sizeof(*t));
		ASN_SEQUENCE_ADD(&t->l.list, mkulong(1));
		ASN_SEQUENCE_ADD(&t->l.list, mkulong(4294967295UL));
		bits = RT(WideMember, t);
		assert(bits > 0);
		/* Lists of 0 and of 5 elements violate SIZE(1..4). */
		assert(!violates(&asn_DEF_WideMember, t));
		t->s = mk(sizeof(*t->s));
		assert(violates(&asn_DEF_WideMember, t));
		ASN_SEQUENCE_ADD(&t->s->list, mkulong(0));	/* below (1..) */
		assert(violates(&asn_DEF_WideMember, t));
		*t->s->list.array[0] = 9;
		bits = RT(WideMember, t);
		assert(bits > 0);
		ASN_STRUCT_FREE(asn_DEF_WideMember, t);
	}

	/* Two levels of SEQUENCE OF around a SEQUENCE { a BOOLEAN } */
	{
		NestSeq_t t;
		struct NestSeq__Member *m = mk(sizeof(*m));
		struct NestSeq__Member__Member *e = mk(sizeof(*e));
		memset(&t, 0, sizeof(t));
		e->a = 1;
		ASN_SEQUENCE_ADD(&m->list, e);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(NestSeq, &t);
		assert(bits == 17);	/* two 8-bit counts + the BOOLEAN */
		assert(buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 0x80);
		ASN_STRUCT_RESET(asn_DEF_NestSeq, &t);
	}
	{
		NestSet_t t;
		struct NestSet__Member *m = mk(sizeof(*m));
		struct NestSet__Member__Member *e = mk(sizeof(*e));
		memset(&t, 0, sizeof(t));
		e->a = 1;
		ASN_SEQUENCE_ADD(&m->list, e);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(NestSet, &t);
		assert(bits == 17);
		ASN_STRUCT_RESET(asn_DEF_NestSet, &t);
	}

	/* ... around a CHOICE */
	{
		NestChoice_t t;
		struct NestChoice__Member *m = mk(sizeof(*m));
		struct NestChoice__Member__Member *e = mk(sizeof(*e));
		struct NestChoice__Member__Member *f = mk(sizeof(*f));
		memset(&t, 0, sizeof(t));
		e->present = NestChoice__Member__Member_PR_b;
		e->choice.b = 6;
		f->present = NestChoice__Member__Member_PR_a;
		f->choice.a = 1;
		ASN_SEQUENCE_ADD(&m->list, e);
		ASN_SEQUENCE_ADD(&m->list, f);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(NestChoice, &t);
		assert(bits > 0);
		ASN_STRUCT_RESET(asn_DEF_NestChoice, &t);
	}
	{
		NestChoiceSet_t t;
		struct NestChoiceSet__Member *m = mk(sizeof(*m));
		struct NestChoiceSet__Member__Member *e = mk(sizeof(*e));
		memset(&t, 0, sizeof(t));
		e->present = NestChoiceSet__Member__Member_PR_b;
		e->choice.b = 7;
		ASN_SEQUENCE_ADD(&m->list, e);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(NestChoiceSet, &t);
		assert(bits > 0);
		ASN_STRUCT_RESET(asn_DEF_NestChoiceSet, &t);
	}

	/* ... around a wide INTEGER; the constraint reaches the element */
	{
		NestWide_t t;
		struct NestWide__Member *m = mk(sizeof(*m));
		memset(&t, 0, sizeof(t));
		ASN_SEQUENCE_ADD(&m->list, mkulong(123456789));
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(NestWide, &t);
		assert(bits == 48);	/* 8 + 8 + 32 */
		ASN_STRUCT_RESET(asn_DEF_NestWide, &t);
	}

	/* Three levels, the middle one inside a SEQUENCE member */
	{
		Deep_t t;
		struct Deep__Member *m = mk(sizeof(*m));
		struct Deep__Member__x__Member *l2 = mk(sizeof(*l2));
		struct Deep__Member__x__Member__Member *e = mk(sizeof(*e));
		memset(&t, 0, sizeof(t));
		e->a = 1;
		ASN_SEQUENCE_ADD(&l2->list, e);
		ASN_SEQUENCE_ADD(&m->x.list, l2);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(Deep, &t);
		assert(bits == 25);	/* three 8-bit counts + the BOOLEAN */
		ASN_STRUCT_RESET(asn_DEF_Deep, &t);
	}

	/* SIZE(1..4) on both lists: 2 + 2 + 1 bits */
	{
		Sized_t t;
		struct Sized__Member *m = mk(sizeof(*m));
		struct Sized__Member__Member *e = mk(sizeof(*e));
		memset(&t, 0, sizeof(t));
		/* An empty outer list is rejected by the UPER encoder. */
		assert(uper_encode_to_buffer(&asn_DEF_Sized, 0, &t, buf,
			sizeof(buf)).encoded == -1);
		e->a = 1;
		ASN_SEQUENCE_ADD(&m->list, e);
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(Sized, &t);
		assert(bits == 5);
		assert(buf[0] == 0x08);
		/* an empty inner list violates SIZE(1..4) */
		ASN_SEQUENCE_ADD(&t.list, mk(sizeof(struct Sized__Member)));
		assert(violates(&asn_DEF_Sized, &t));
		ASN_STRUCT_RESET(asn_DEF_Sized, &t);
	}
	{
		SizedSet_t t;
		struct SizedSet__Member *m = mk(sizeof(*m));
		memset(&t, 0, sizeof(t));
		ASN_SEQUENCE_ADD(&m->list, mk(sizeof(struct SizedSet__Member__Member)));
		ASN_SEQUENCE_ADD(&t.list, m);
		assert(violates(&asn_DEF_SizedSet, &t));	/* inner needs 2..3 */
		ASN_SEQUENCE_ADD(&m->list, mk(sizeof(struct SizedSet__Member__Member)));
		bits = RT(SizedSet, &t);
		assert(bits > 0);
		ASN_STRUCT_RESET(asn_DEF_SizedSet, &t);
	}
	{
		SizedWide_t t;
		struct SizedWide__Member *m = mk(sizeof(*m));
		memset(&t, 0, sizeof(t));
		ASN_SEQUENCE_ADD(&m->list, mkulong(4294967295UL));
		ASN_SEQUENCE_ADD(&t.list, m);
		bits = RT(SizedWide, &t);
		assert(bits == 35);	/* 1 (outer SIZE) + 2 (inner SIZE) + 32 */
		ASN_STRUCT_RESET(asn_DEF_SizedWide, &t);
	}
	{
		SizedMember_t *t = mk(sizeof(*t));
		struct SizedMember__m__Member *m = mk(sizeof(*m));
		ASN_SEQUENCE_ADD(&m->list, mk(sizeof(long)));
		ASN_SEQUENCE_ADD(&m->list, mk(sizeof(long)));
		*(long *)m->list.array[1] = 7;
		ASN_SEQUENCE_ADD(&t->m.list, m);
		bits = RT(SizedMember, t);
		assert(bits > 0);
		*(long *)m->list.array[1] = 8;	/* (0..7) */
		assert(violates(&asn_DEF_SizedMember, t));
		ASN_STRUCT_FREE(asn_DEF_SizedMember, t);
	}

	return 0;
}
