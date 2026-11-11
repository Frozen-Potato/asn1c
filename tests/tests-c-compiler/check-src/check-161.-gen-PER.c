/*
 * Verify that DEFAULT values which are negative (or the 64-bit minimum)
 * produce compilable callbacks and behave correctly in UPER.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <T.h>

static long i2l(const INTEGER_t *i) {
    long l;
    int ret = asn_INTEGER2long(i, &l);
    assert(ret == 0);
    return l;
}

static void l2i(INTEGER_t *i, long l) {
    int ret = asn_long2INTEGER(i, l);
    assert(ret == 0);
}

static T_t *roundtrip(T_t *ti, uint8_t *buf, size_t bufsz, ssize_t *bits) {
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	T_t *to = 0;
	/* Explicit context: max_stack_size=0 disables the stack check, which
	 * misfires under ASAN fake stacks when the default context is used. */
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

int main() {
	uint8_t buf[64];
	ssize_t bits;
	T_t t, *to;
	long neg = -1, pos = 5;
	INTEGER_t min64;

	/* All members equal to their DEFAULTs: all presence bits are 0. */
	memset(&t, 0, sizeof(t));
	memset(&min64, 0, sizeof(min64));
	l2i(&min64, (-9223372036854775807L - 1));
	t.neg = &neg;
	t.min64 = &min64;
	t.pos = &pos;

	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	assert(bits == 3);
	assert((buf[0] & 0xe0) == 0);	/* neg, min64, pos all omitted */
	assert(to->neg && *to->neg == -1);
	assert(to->min64 && i2l(to->min64) == (-9223372036854775807L - 1));
	assert(to->pos && *to->pos == 5);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* Absent members (NULL) are encoded as defaults and decoded filled in. */
	memset(&t, 0, sizeof(t));
	memset(buf, 0xff, sizeof(buf));
	to = roundtrip(&t, buf, sizeof(buf), &bits);
	assert(bits == 3);
	assert((buf[0] & 0xe0) == 0);
	assert(to->neg && *to->neg == -1);
	assert(to->min64 && i2l(to->min64) == (-9223372036854775807L - 1));
	assert(to->pos && *to->pos == 5);
	ASN_STRUCT_FREE(asn_DEF_T, to);

	/* Non-default values round-trip and set the presence bits. */
	{
		long n2 = 7, p2 = -10;
		INTEGER_t m2;
		memset(&m2, 0, sizeof(m2));
		l2i(&m2, 9223372036854775807L);
		memset(&t, 0, sizeof(t));
		t.neg = &n2;
		t.min64 = &m2;
		t.pos = &p2;
		memset(buf, 0, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert(bits > 3);
		assert((buf[0] & 0xe0) == 0xe0);
		assert(to->neg && *to->neg == 7);
		assert(to->min64 && i2l(to->min64) == 9223372036854775807L);
		assert(to->pos && *to->pos == -10);
		ASN_STRUCT_FREE(asn_DEF_T, to);
		ASN_STRUCT_RESET(asn_DEF_INTEGER, &m2);
	}

	/* Mixed: only neg differs from its default (-1 -> -2). */
	{
		long n3 = -2;
		memset(&t, 0, sizeof(t));
		t.neg = &n3;
		memset(buf, 0, sizeof(buf));
		to = roundtrip(&t, buf, sizeof(buf), &bits);
		assert((buf[0] & 0xe0) == 0x80);
		assert(*to->neg == -2);
		assert(i2l(to->min64) == (-9223372036854775807L - 1));
		assert(*to->pos == 5);
		ASN_STRUCT_FREE(asn_DEF_T, to);
	}

	ASN_STRUCT_RESET(asn_DEF_INTEGER, &min64);
	return 0;
}
