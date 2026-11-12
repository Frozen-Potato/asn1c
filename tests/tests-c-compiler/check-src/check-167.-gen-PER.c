/*
 * Named-bit BIT STRING: the C enum of bit positions (numbers neither
 * contiguous nor sorted), and the PER behaviour the Go backend inherits:
 * trailing zero bits are dropped and the value padded up to the SIZE lower
 * bound.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <Caps.h>
#include <Fixed.h>
#include <Ranged.h>
#include <Holder.h>
#include <Selector.h>

/* UPER round trip; returns the number of bits written. */
static ssize_t
roundtrip(const asn_TYPE_descriptor_t *td, const void *in, void **out,
		uint8_t *buf, size_t bufsz) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	memset(buf, 0, bufsz);
	er = uper_encode_to_buffer(td, 0, in, buf, bufsz);
	assert(er.encoded > 0);
	*out = 0;
	rv = uper_decode(&ctx, td, out, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(*out);
	return er.encoded;
}

int main() {
	uint8_t buf[64];
	void *out;
	ssize_t bits;

	/* The bit-position enums, in declaration order. */
	assert(Caps_c == 7 && Caps_a == 0 && Caps_b == 3);
	assert(opt_x == 1 && opt_y == 4);
	assert(flags_on == 0 && flags_off == 1);

	/* Ranged ::= BIT STRING { p(0), q(2) } (SIZE(4..12)):
	 * only p set (0x80, one significant bit) is padded to the lower bound. */
	{
		uint8_t v[] = { 0x80 };
		Ranged_t r;
		Ranged_t *d;
		memset(&r, 0, sizeof(r));
		r.buf = v; r.size = 1; r.bits_unused = 7;
		bits = roundtrip(&asn_DEF_Ranged, &r, &out, buf, sizeof(buf));
		/* 4-bit length determinant (0 = 4 bits) + 4 bits of value */
		assert(bits == 8);
		assert(buf[0] == 0x08);
		d = out;
		assert(d->size == 1 && d->bits_unused == 4 && d->buf[0] == 0x80);
		ASN_STRUCT_FREE(asn_DEF_Ranged, d);
	}

	/* No bits set: the empty value is padded to four zero bits. */
	{
		Ranged_t r;
		Ranged_t *d;
		memset(&r, 0, sizeof(r));
		bits = roundtrip(&asn_DEF_Ranged, &r, &out, buf, sizeof(buf));
		assert(bits == 8);
		assert(buf[0] == 0x00);
		d = out;
		assert(d->size == 1 && d->bits_unused == 4 && d->buf[0] == 0x00);
		ASN_STRUCT_FREE(asn_DEF_Ranged, d);
	}

	/* Fixed ::= BIT STRING { lo(0), hi(5) } (SIZE(8)): highest bit set. */
	{
		uint8_t v[] = { 0x04 };	/* bit 5 */
		Fixed_t f;
		Fixed_t *d;
		memset(&f, 0, sizeof(f));
		f.buf = v; f.size = 1; f.bits_unused = 0;
		bits = roundtrip(&asn_DEF_Fixed, &f, &out, buf, sizeof(buf));
		assert(bits == 8);
		assert(buf[0] == 0x04);
		d = out;
		assert(d->size == 1 && d->bits_unused == 0 && d->buf[0] == 0x04);
		ASN_STRUCT_FREE(asn_DEF_Fixed, d);
	}

	/* Caps ::= BIT STRING { c(7), a(0), b(3) }: trailing zero bits are
	 * compactified: only bit 0 set encodes as one significant bit. */
	{
		uint8_t v[] = { 0x80, 0x00 };	/* bit 0 set, 16 bits */
		Caps_t c;
		Caps_t *d;
		memset(&c, 0, sizeof(c));
		c.buf = v; c.size = 2; c.bits_unused = 0;
		bits = roundtrip(&asn_DEF_Caps, &c, &out, buf, sizeof(buf));
		d = out;
		assert(d->size == 1 && d->bits_unused == 7 && d->buf[0] == 0x80);
		ASN_STRUCT_FREE(asn_DEF_Caps, d);
	}

	return 0;
}
