/*
 * Verify NULL and REAL DEFAULT members under -fwide-types (a REAL member is a
 * REAL_t there): an absent member decodes to its DEFAULT, a value equal to the
 * DEFAULT is omitted, any other value is encoded. The same specification as
 * check-163 (see its X and Y).
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <X.h>
#include <Y.h>

#include <math.h>
/* With -fwide-types every REAL member is a REAL_t (BER/DER/PER REAL bytes) */
#define ISINF(d)	isinf(d)
#define ISNAN(d)	isnan(d)
#define SIGNBIT(d)	signbit(d)
#define PLUSINF		INFINITY
#define NANV		NAN
#define GETV(p, d)	assert(asn_REAL2double((p), &(d)) == 0)
#define SETV(p, v)	assert(asn_double2REAL((p), (v)) == 0)
#define NEWV(p, v)	do { (p) = calloc(1, sizeof(*(p))); assert(p); \
			     assert(asn_double2REAL((p), (v)) == 0); } while(0)

/*
 * X: a NULL DEFAULT. A present NULL always equals the default, so the encoder
 * omits it (presence bit 0, then b=TRUE: 01 -> 0x40, 2 bits) and a decoder
 * fills an absent one in.
 */
static void x_cases(int aper) {
	uint8_t buf[16];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	X_t x, *xo = 0;

	memset(&ctx, 0, sizeof(ctx));
	memset(&x, 0, sizeof(x));
	x.b = 1;
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_X, 0, &x, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_X, 0, &x, buf, sizeof(buf));
	assert(er.encoded == 2 && buf[0] == 0x40);
	rv = aper ? aper_decode(&ctx, &asn_DEF_X, (void *)&xo, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_X, (void *)&xo, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && xo);
	assert(xo->n);			/* filled in with the default */
	assert(xo->b == 1);
	/* ... which re-encodes to the same bits */
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_X, 0, xo, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_X, 0, xo, buf, sizeof(buf));
	assert(er.encoded == 2 && buf[0] == 0x40);
	ASN_STRUCT_FREE(asn_DEF_X, xo);
}

/*
 * Y: REAL DEFAULTs. With every member at its default the preamble is seven
 * zero bits and b=TRUE: 0000000 1 -> 0x01 (8 bits); a decoder fills the
 * defaults in.
 * Equality is exact: NaN equals NaN, and -0.0 is not the default 0.0.
 */
static void y_cases(int aper) {
	uint8_t buf[64], ref[64];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	Y_t y, *yo = 0;
	double d;

	memset(&ctx, 0, sizeof(ctx));
	memset(&y, 0, sizeof(y));
	y.b = 1;
	memset(ref, 0xff, sizeof(ref));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Y, 0, &y, ref, sizeof(ref))
		  : uper_encode_to_buffer(&asn_DEF_Y, 0, &y, ref, sizeof(ref));
	assert(er.encoded == 8 && ref[0] == 0x01);

	rv = aper ? aper_decode(&ctx, &asn_DEF_Y, (void *)&yo, ref, sizeof(ref), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_Y, (void *)&yo, ref, sizeof(ref), 0, 0);
	assert(rv.code == RC_OK && yo);
	assert(yo->r && yo->z && yo->m && yo->p && yo->q && yo->na && yo->nz);
	GETV(yo->r, d); assert(d == 1.5);
	GETV(yo->z, d); assert(d == 0.0 && !SIGNBIT(d));
	GETV(yo->m, d); assert(d == -2.25);
	GETV(yo->p, d); assert(ISINF(d) && d > 0);
	GETV(yo->q, d); assert(ISINF(d) && d < 0);
	GETV(yo->na, d); assert(ISNAN(d));
	GETV(yo->nz, d); assert(d == 0.0 && SIGNBIT(d));
	/* ... and re-encoding omits them all again */
	memset(buf, 0xff, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Y, 0, yo, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_Y, 0, yo, buf, sizeof(buf));
	assert(er.encoded == 8 && buf[0] == 0x01);
	ASN_STRUCT_FREE(asn_DEF_Y, yo);
	yo = 0;

	/* Explicit values equal to the defaults are omitted too */
	memset(&y, 0, sizeof(y));
	y.b = 1;
	NEWV(y.r, 1.5); NEWV(y.z, 0.0); NEWV(y.m, -2.25);
	NEWV(y.p, PLUSINF); NEWV(y.q, -PLUSINF); NEWV(y.na, NANV);
	NEWV(y.nz, -0.0);
	memset(buf, 0xff, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Y, 0, &y, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_Y, 0, &y, buf, sizeof(buf));
	assert(er.encoded == 8 && buf[0] == 0x01);

	/* Each one that differs is encoded (its presence bit is set) and
	 * survives a round trip */
	SETV(y.z, -0.0);	/* -0.0 is not the default 0.0 */
	SETV(y.nz, 0.0);	/* ... and 0.0 is not the default -0.0 */
	SETV(y.r, 2.5);
	SETV(y.p, 7.0);
	SETV(y.na, 1.0);
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Y, 0, &y, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_Y, 0, &y, buf, sizeof(buf));
	assert(er.encoded > 8);
	/* presence bits r z m p q na nz = 1 1 0 1 0 1 1 */
	assert((buf[0] & 0xfe) == 0xd6);
	rv = aper ? aper_decode(&ctx, &asn_DEF_Y, (void *)&yo, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_Y, (void *)&yo, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && yo);
	GETV(yo->r, d); assert(d == 2.5);
	GETV(yo->z, d); assert(d == 0.0 && SIGNBIT(d));
	GETV(yo->m, d); assert(d == -2.25);		/* defaulted */
	GETV(yo->p, d); assert(d == 7.0);
	GETV(yo->q, d); assert(ISINF(d) && d < 0);	/* defaulted */
	GETV(yo->na, d); assert(d == 1.0);
	GETV(yo->nz, d); assert(d == 0.0 && !SIGNBIT(d));
	ASN_STRUCT_FREE(asn_DEF_Y, yo);
	ASN_STRUCT_RESET(asn_DEF_Y, &y);
}

int main() {
	x_cases(1);
	x_cases(0);
	y_cases(1);
	y_cases(0);
	return 0;
}
