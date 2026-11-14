/*
 * Verify OCTET STRING / BIT STRING DEFAULT values given as hstring/bstring:
 * absent members decode to the default, members equal to the default are
 * omitted (presence bit 0) and other values round-trip. A named-bit BIT STRING
 * DEFAULT { x } is equal to every value that differs from it only in trailing
 * 0 bits.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <T.h>

static T_t *roundtrip(T_t *ti, uint8_t *buf, size_t bufsz, ssize_t *bits) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	T_t *to = 0;
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	er = uper_encode_to_buffer(&asn_DEF_T, 0, ti, buf, bufsz);
	assert(er.encoded > 0);
	*bits = er.encoded;

	rv = uper_decode(&ctx, &asn_DEF_T, (void *)&to, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(to);
	return to;
}

static void check_defaults(const T_t *t) {
	assert(t->o && t->o->size == 1 && t->o->buf[0] == 0xAB);
	assert(t->b && t->b->size == 1 && t->b->bits_unused == 5
		&& t->b->buf[0] == 0xA0);	/* '101'B */
	assert(t->w && t->w->size == 1 && t->w->bits_unused == 0
		&& t->w->buf[0] == 0xA5);
	assert(t->n && t->n->size == 1 && t->n->bits_unused == 7
		&& t->n->buf[0] == 0x80);	/* { x }: bit 0 */
}

int main() {
	uint8_t buf[64];
	ssize_t bits;
	T_t t, *to;

	/* Absent members: encoded as defaults (presence bits 0), decoded filled. */
	memset(&t, 0, sizeof(t));
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	assert(bits == 4);
	assert((buf[0] & 0xf0) == 0);
	check_defaults(to);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* Values equal to the defaults are omitted. */
	{
		uint8_t ov[] = { 0xAB };
		uint8_t bv[] = { 0xA0 };	/* '101'B */
		uint8_t wv[] = { 0xA5 };
		uint8_t nv[] = { 0x80, 0x00 };	/* { x } and 8 more 0 bits */
		OCTET_STRING_t o; BIT_STRING_t b, w, n;
		memset(&o, 0, sizeof(o));
		o.buf = ov; o.size = 1;
		b.buf = bv; b.size = 1; b.bits_unused = 5;
		w.buf = wv; w.size = 1; w.bits_unused = 0;
		n.buf = nv; n.size = 2; n.bits_unused = 0;
		memset(&t, 0, sizeof(t));
		t.o = &o; t.b = &b; t.w = &w; t.n = &n;
		memset(buf, 0xff, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert(bits == 4);
		assert((buf[0] & 0xf0) == 0);
		check_defaults(to);
		ASN_STRUCT_FREE(asn_DEF_T, to);

		/* Unused bits in the last octet must not affect equality. */
		bv[0] = 0xA7;
		memset(buf, 0xff, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert(bits == 4);
		check_defaults(to);
		ASN_STRUCT_FREE(asn_DEF_T, to);
	}

	/* Different values round-trip, presence bits set. */
	{
		uint8_t ov[] = { 0xAB, 0xCD };
		uint8_t bv[] = { 0xC0 };	/* '11'B */
		uint8_t wv[] = { 0x5A };
		uint8_t nv[] = { 0x40 };	/* { y } */
		OCTET_STRING_t o; BIT_STRING_t b, w, n;
		memset(&o, 0, sizeof(o));
		o.buf = ov; o.size = 2;
		b.buf = bv; b.size = 1; b.bits_unused = 6;
		w.buf = wv; w.size = 1; w.bits_unused = 0;
		n.buf = nv; n.size = 1; n.bits_unused = 6;
		memset(&t, 0, sizeof(t));
		t.o = &o; t.b = &b; t.w = &w; t.n = &n;
		memset(buf, 0, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert(bits > 4);
		assert((buf[0] & 0xe0) == 0xe0);
		assert(to->o && to->o->size == 2
			&& memcmp(to->o->buf, ov, 2) == 0);
		assert(to->b && to->b->size == 1 && to->b->bits_unused == 6
			&& to->b->buf[0] == 0xC0);
		assert(to->w && to->w->size == 1 && to->w->buf[0] == 0x5A);
		assert(to->n && to->n->size == 1 && to->n->bits_unused == 6
			&& to->n->buf[0] == 0x40);
		ASN_STRUCT_FREE(asn_DEF_T, to);
	}

	/* '1011'B: size not a multiple of 8, differs from the DEFAULT '101'B. */
	{
		uint8_t bv[] = { 0xB0 };
		BIT_STRING_t b;
		b.buf = bv; b.size = 1; b.bits_unused = 4;
		memset(&t, 0, sizeof(t));
		t.b = &b;
		memset(buf, 0, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert((buf[0] & 0x40) == 0x40);
		assert(to->b->size == 1 && to->b->bits_unused == 4
			&& to->b->buf[0] == 0xB0);
		ASN_STRUCT_FREE(asn_DEF_T, to);
	}

	return 0;
}
