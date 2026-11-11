/*
 * Verify aligned PER with DEFAULT members: a root member equal to its
 * DEFAULT is omitted (presence bit 0), any other value is encoded (it used to
 * be dropped by the aPER encoder), and absent root members and absent
 * extension additions decode to their DEFAULT.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <T.h>

static T_t *roundtrip(const T_t *ti, uint8_t *buf, size_t bufsz, ssize_t *bits) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	T_t *to = 0;
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	er = aper_encode_to_buffer(&asn_DEF_T, 0, ti, buf, bufsz);
	assert(er.encoded > 0);
	*bits = er.encoded;

	rv = aper_decode(&ctx, &asn_DEF_T, (void *)&to, buf, bufsz, 0, 0);
	assert(rv.code == RC_OK);
	assert(to);
	return to;
}

int main() {
	uint8_t buf[64];
	ssize_t bits;
	T_t t, *to;
	BOOLEAN_t a = 0;
	long c = 3, y = 1;

	/* Everything absent: ext(0) + presence bits a,b,c (000), decoded filled. */
	memset(&t, 0, sizeof(t));
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	assert(bits == 4 && (buf[0] & 0xf0) == 0);
	assert(to->a && *to->a == 1);
	assert(to->b == 0);
	assert(to->c && *to->c == 5);
	assert(to->x && *to->x == 1);
	assert(to->y && *to->y == 5);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* Non-default root values are kept: a=FALSE, b=2, c=3. */
	memset(&t, 0, sizeof(t));
	t.a = &a; t.b = 2; t.c = &c;
	memset(buf, 0, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	/* ext 0 | presence 1,1,1 | a=0 | b=010 | c=011 -> 0111 0010 011(00000) */
	assert(bits == 11 && buf[0] == 0x72 && (buf[1] & 0xe0) == 0x60);
	assert(to->a && *to->a == 0);
	assert(to->b == 2);
	assert(to->c && *to->c == 3);
	assert(to->y && *to->y == 5);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* A DEFAULT-equal root value is omitted: c == 5. */
	{
		long c5 = 5;
		memset(&t, 0, sizeof(t));
		t.c = &c5;
		memset(buf, 0xff, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert(bits == 4 && (buf[0] & 0xf0) == 0);
		assert(to->c && *to->c == 5);
		ASN_STRUCT_FREE(asn_DEF_T, to);
	}

	/* Extension addition y present: root members still decode to defaults,
	 * x (absent in the bitmap) is filled with its DEFAULT 1 */
	memset(&t, 0, sizeof(t));
	t.y = &y;
	memset(buf, 0, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	assert(to->a && *to->a == 1);
	assert(to->c && *to->c == 5);
	assert(to->x && *to->x == 1);
	assert(to->y && *to->y == 1);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	return 0;
}
