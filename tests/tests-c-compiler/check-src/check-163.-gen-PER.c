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
#include <V.h>
#include <W.h>

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

/*
 * V: a BMPString / UniversalString DEFAULT is held as UCS-2 / UCS-4
 * big-endian, so "hi" is 00 68 00 69 and 00 00 00 68 00 00 00 69. A decoder
 * fills an absent member with exactly that, and an encoder omits a value equal
 * to it (presence bits 00, then b=TRUE: 001 -> 0x20, 3 bits).
 */
static void v_cases(int aper) {
	static const uint8_t bmp[] = {0x00, 0x68, 0x00, 0x69};
	static const uint8_t uni[] = {0, 0, 0, 0x68, 0, 0, 0, 0x69};
	uint8_t buf[64];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	V_t v, *vo = 0;
	int i;

	memset(&ctx, 0, sizeof(ctx));
	/* Absent members decode to the DEFAULT */
	{
		static const uint8_t in[] = {0x20};
		rv = aper ? aper_decode(&ctx, &asn_DEF_V, (void *)&vo, in, 1, 0, 0)
			  : uper_decode(&ctx, &asn_DEF_V, (void *)&vo, in, 1, 0, 0);
		assert(rv.code == RC_OK && vo);
		assert(vo->a && vo->a->size == sizeof(bmp));
		assert(memcmp(vo->a->buf, bmp, sizeof(bmp)) == 0);
		assert(vo->u && vo->u->size == sizeof(uni));
		assert(memcmp(vo->u->buf, uni, sizeof(uni)) == 0);
		assert(vo->b == 1);
		/* ... and re-encode omits them again */
		memset(buf, 0, sizeof(buf));
		er = aper ? aper_encode_to_buffer(&asn_DEF_V, 0, vo, buf, sizeof(buf))
			  : uper_encode_to_buffer(&asn_DEF_V, 0, vo, buf, sizeof(buf));
		assert(er.encoded == 3 && buf[0] == 0x20);
		ASN_STRUCT_FREE(asn_DEF_V, vo);
		vo = 0;
	}
	/* Explicit "hi" (UCS-2 / UCS-4) is omitted too */
	memset(&v, 0, sizeof(v));
	v.a = calloc(1, sizeof(*v.a));
	v.u = calloc(1, sizeof(*v.u));
	assert(OCTET_STRING_fromBuf((OCTET_STRING_t *)v.a, (const char *)bmp, 4) == 0);
	assert(OCTET_STRING_fromBuf((OCTET_STRING_t *)v.u, (const char *)uni, 8) == 0);
	v.b = 1;
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_V, 0, &v, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_V, 0, &v, buf, sizeof(buf));
	assert(er.encoded == 3 && buf[0] == 0x20);
	/* A different value is encoded, and survives the round trip */
	for(i = 0; i < 2; i++) {
		OCTET_STRING_t *o = i ? (OCTET_STRING_t *)v.u : (OCTET_STRING_t *)v.a;
		o->buf[o->size - 1] = 0x6a; /* "hj" */
	}
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_V, 0, &v, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_V, 0, &v, buf, sizeof(buf));
	assert(er.encoded > 3 && (buf[0] & 0xc0) == 0xc0);
	rv = aper ? aper_decode(&ctx, &asn_DEF_V, (void *)&vo, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_V, (void *)&vo, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && vo);
	assert(vo->a->size == 4 && vo->a->buf[3] == 0x6a);
	assert(vo->u->size == 8 && vo->u->buf[7] == 0x6a);
	ASN_STRUCT_FREE(asn_DEF_V, vo);
	ASN_STRUCT_RESET(asn_DEF_V, &v);
}

/*
 * W: a UTF8String / UTCTime DEFAULT is held as the bytes of the literal as
 * written ("é€" is the UTF-8 c3 a9 e2 82 ac). The generator does not check the
 * time syntax of a UTCTime literal; an invalid one is stored as it is, and
 * the constraint check (asn_check_constraints) then rejects a decoded
 * default that is not a valid time.
 */
static void w_cases(int aper) {
	static const uint8_t utf[] = {0xc3, 0xa9, 0xe2, 0x82, 0xac};
	static const char tm[] = "250102030405Z";
	uint8_t buf[64];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	W_t w, *wo = 0;

	memset(&ctx, 0, sizeof(ctx));
	/* Absent members decode to the DEFAULT */
	{
		static const uint8_t in[] = {0x20};
		rv = aper ? aper_decode(&ctx, &asn_DEF_W, (void *)&wo, in, 1, 0, 0)
			  : uper_decode(&ctx, &asn_DEF_W, (void *)&wo, in, 1, 0, 0);
		assert(rv.code == RC_OK && wo);
		assert(wo->a && wo->a->size == sizeof(utf));
		assert(memcmp(wo->a->buf, utf, sizeof(utf)) == 0);
		assert(wo->t && wo->t->size == sizeof(tm) - 1);
		assert(memcmp(wo->t->buf, tm, sizeof(tm) - 1) == 0);
		assert(wo->b == 1);
		/* ... and re-encode omits them again */
		memset(buf, 0, sizeof(buf));
		er = aper ? aper_encode_to_buffer(&asn_DEF_W, 0, wo, buf, sizeof(buf))
			  : uper_encode_to_buffer(&asn_DEF_W, 0, wo, buf, sizeof(buf));
		assert(er.encoded == 3 && buf[0] == 0x20);
		ASN_STRUCT_FREE(asn_DEF_W, wo);
		wo = 0;
	}
	/* Explicit equal values are omitted too */
	memset(&w, 0, sizeof(w));
	w.a = calloc(1, sizeof(*w.a));
	w.t = calloc(1, sizeof(*w.t));
	assert(OCTET_STRING_fromBuf((OCTET_STRING_t *)w.a, (const char *)utf, sizeof(utf)) == 0);
	assert(OCTET_STRING_fromBuf((OCTET_STRING_t *)w.t, tm, sizeof(tm) - 1) == 0);
	w.b = 1;
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_W, 0, &w, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_W, 0, &w, buf, sizeof(buf));
	assert(er.encoded == 3 && buf[0] == 0x20);
	/* A different time is encoded */
	w.t->buf[11] = '6';
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_W, 0, &w, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_W, 0, &w, buf, sizeof(buf));
	assert(er.encoded > 3 && (buf[0] & 0xc0) == 0x40);
	ASN_STRUCT_RESET(asn_DEF_W, &w);
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
	v_cases(1);
	v_cases(0);
	w_cases(1);
	w_cases(0);

	return 0;
}
