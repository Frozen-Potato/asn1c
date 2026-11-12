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
#include <U.h>

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


/*
 * U: extension additions equal to their DEFAULT are omitted, in APER and
 * UPER. extZero (DEFAULT 0) is stored by value, extNon (DEFAULT 5) behind a
 * pointer.
 */
static void u_check(int aper, const U_t *ui, const uint8_t *want, size_t wbytes,
                    ssize_t wbits, long zero, long non) {
	uint8_t buf[64];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	U_t *uo = 0;

	memset(&ctx, 0, sizeof(ctx));
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_U, 0, ui, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_U, 0, ui, buf, sizeof(buf));
	assert(er.encoded > 0);
	if(wbits >= 0) assert(er.encoded == wbits);
	assert(memcmp(buf, want, wbytes) == 0);
	rv = aper ? aper_decode(&ctx, &asn_DEF_U, (void *)&uo, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_U, (void *)&uo, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && uo);
	assert(uo->extZero == zero);
	assert(uo->extNon && *uo->extNon == non);
	ASN_STRUCT_FREE(asn_DEF_U, uo);
}

static void u_cases(int aper) {
	U_t u;
	BOOLEAN_t f = 0;
	long n6 = 6, n5 = 5, n3 = 3;

	/* All defaults: ext(0) + presence of a (0) -> 00 (2 bits), both PERs. */
	memset(&u, 0, sizeof(u));
	{ const uint8_t w[] = {0x00}; u_check(aper, &u, w, 1, 2, 0, 5); }

	/* Explicit default values behave the same as absent ones: extNon=5. */
	memset(&u, 0, sizeof(u));
	u.extNon = &n5;
	{ const uint8_t w[] = {0x00}; u_check(aper, &u, w, 1, 2, 0, 5); }

	/* a=FALSE, additions defaulted: ext(0) pres(1) a(0) -> 010 -> 40. */
	memset(&u, 0, sizeof(u));
	u.a = &f;
	{ const uint8_t w[] = {0x40}; u_check(aper, &u, w, 1, 3, 0, 5); }

	/* Only extNon=6 != 5: ext(1) pres(0) nslength(0|000001 = 2 additions)
	 * bitmap(01), then the open type (length 01, 6 = '110'):
	 * APER: 1000 0000 | 101(00000) | 01 | 110(00000)       -> 80 a0 01 c0
	 * UPER (no alignment, but the open type content is a whole octet):
	 * 1 0 0000001 01 | 00000001 | 110(00000)  (27 bits)   -> 80 a0 38 00 */
	memset(&u, 0, sizeof(u));
	u.extNon = &n6;
	if(aper) { const uint8_t w[] = {0x80, 0xa0, 0x01, 0xc0}; u_check(1, &u, w, 4, -1, 0, 6); }
	else     { const uint8_t w[] = {0x80, 0xa0, 0x38, 0x00}; u_check(0, &u, w, 4, 27, 0, 6); }

	/* Only extZero=3 != 0 (extNon defaulted): bitmap(10), open type 3='011':
	 * APER: 1000 0000 | 110(00000) | 01 | 011(00000)       -> 80 c0 01 60
	 * UPER: 1 0 0000001 10 | 00000001 | 011(00000) (27 bits) -> 80 c0 2c 00 */
	memset(&u, 0, sizeof(u));
	u.extZero = 3;
	if(aper) { const uint8_t w[] = {0x80, 0xc0, 0x01, 0x60}; u_check(1, &u, w, 4, -1, 3, 5); }
	else     { const uint8_t w[] = {0x80, 0xc0, 0x2c, 0x00}; u_check(0, &u, w, 4, 27, 3, 5); }

	/* Both non-default: bitmap(11), open types 01 60 and 01 c0 (APER). */
	memset(&u, 0, sizeof(u));
	u.extZero = 3;
	u.extNon = &n6;
	if(aper) { const uint8_t w[] = {0x80, 0xe0, 0x01, 0x60, 0x01, 0xc0}; u_check(1, &u, w, 6, -1, 3, 6); }
	(void)n3;
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

	u_cases(1);
	u_cases(0);

	return 0;
}
