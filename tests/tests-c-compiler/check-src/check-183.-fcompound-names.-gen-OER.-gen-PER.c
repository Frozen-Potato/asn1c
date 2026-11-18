/*
 * Types written directly in information objects (183-ioc-object-types-OK):
 * - each value is decoded from canonical XER, whose element is the type's
 *   X.693 name (INTEGER, OCTET_STRING, ENUMERATED, SET, SEQUENCE), and
 *   encoded back to the same XER;
 * - APER and OER of the open type use the alternative's own constraints
 *   (INTEGER (0..7) in 3 bits / 1 octet, OCTET STRING (SIZE(2)) without a
 *   length) and the module's AUTOMATIC TAGS (SET in p, q order);
 * - OER wraps the open type value in a length (X.696 #30), it was written
 *   as a CHOICE (tag + value) that the decoder could not read back;
 * - ids 6 and 7 share one alternative; id 1 names K183's Named, which K183B
 *   also defines (the object set refers to asn_DEF_K183_Named);
 * - a value outside the alternative's constraint is refused.
 * Vectors worked out by hand from X.691 (APER) and X.696 (OER).
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "IE.h"

struct vec {
	const char *xer;
	const char *aper;    /* hex */
	const char *oer;    /* hex; NULL: the runtime has no OER for SET */
};

#define IEX(id, v) "<IE><id>" #id "</id><value>" v "</value></IE>"

static const struct vec vecs[] = {
	{ IEX(1, "<Named>200</Named>"), "0101c8", "0101c8" },
	{ IEX(2, "<INTEGER>5</INTEGER>"), "0201a0", "020105" },
	{ IEX(3, "<OCTET_STRING>ABCD</OCTET_STRING>"), "0302abcd", "0302abcd" },
	{ IEX(4, "<ENUMERATED><green/></ENUMERATED>"), "040140", "040101" },
	{ IEX(5, "<SET><p>9</p><q><true/></q></SET>"), "0501cc", NULL },
	{ IEX(6, "<SEQUENCE><a>2</a></SEQUENCE>"), "060180", "060102" },
	{ IEX(7, "<SEQUENCE><a>3</a></SEQUENCE>"), "0701c0", "070103" },
};

static size_t
unhex(const char *h, unsigned char *b) {
	size_t n = 0;
	for(; h[0] && h[1]; h += 2) {
		unsigned v;
		sscanf(h, "%2x", &v);
		b[n++] = (unsigned char)v;
	}
	return n;
}

static void
check_bytes(const char *what, const char *xer, enum asn_transfer_syntax ts,
			const IE_t *ie, const char *want_hex) {
	unsigned char want[64], got[64];
	size_t wn = unhex(want_hex, want);
	asn_enc_rval_t er = asn_encode_to_buffer(0, ts, &asn_DEF_IE, ie, got,
											 sizeof(got));
	if(er.encoded < 0 || (size_t)er.encoded != wn || memcmp(got, want, wn)) {
		fprintf(stderr, "%s of %s: encoded %zd bytes, want %s\n", what, xer,
				er.encoded, want_hex);
		exit(1);
	}
	IE_t *back = 0;
	asn_dec_rval_t dr = asn_decode(0, ts, &asn_DEF_IE, (void **)&back, got, wn);
	if(dr.code != RC_OK || dr.consumed != wn) {
		fprintf(stderr, "%s of %s: decode code %d consumed %zu\n", what, xer,
				(int)dr.code, dr.consumed);
		exit(1);
	}
	char xb[256];
	asn_enc_rval_t xr = asn_encode_to_buffer(0, ATS_CANONICAL_XER, &asn_DEF_IE,
											 back, xb, sizeof(xb) - 1);
	assert(xr.encoded > 0);
	xb[xr.encoded] = 0;
	if(strcmp(xb, xer)) {
		fprintf(stderr, "%s of %s: decoded back as %s\n", what, xer, xb);
		exit(1);
	}
	ASN_STRUCT_FREE(asn_DEF_IE, back);
}

int
main(void) {
	for(size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		const struct vec *v = &vecs[i];
		IE_t *ie = 0;
		asn_dec_rval_t dr = xer_decode(0, &asn_DEF_IE, (void **)&ie, v->xer,
									   strlen(v->xer));
		if(dr.code != RC_OK) {
			fprintf(stderr, "XER decode of %s failed\n", v->xer);
			return 1;
		}
		char xb[256];
		asn_enc_rval_t xr = asn_encode_to_buffer(0, ATS_CANONICAL_XER,
												 &asn_DEF_IE, ie, xb,
												 sizeof(xb) - 1);
		assert(xr.encoded > 0);
		xb[xr.encoded] = 0;
		if(strcmp(xb, v->xer)) {
			fprintf(stderr, "XER of %s re-encoded as %s\n", v->xer, xb);
			return 1;
		}
		check_bytes("APER", v->xer, ATS_ALIGNED_BASIC_PER, ie, v->aper);
		if(v->oer) check_bytes("OER", v->xer, ATS_BASIC_OER, ie, v->oer);
		ASN_STRUCT_FREE(asn_DEF_IE, ie);
	}

	/* ids 6 and 7 share one alternative of the union */
	assert(IE__value_PR_SEQUENCE_a_INTEGER_0_3_ > 0);

	/* INTEGER (0..7): 8 is refused */
	IE_t bad;
	memset(&bad, 0, sizeof(bad));
	bad.id = 2;
	bad.value.present = IE__value_PR_INTEGER_0_7_;
	bad.value.choice.INTEGER_0_7_ = 8;
	char eb[64];
	asn_enc_rval_t er = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER,
											 &asn_DEF_IE, &bad, eb, sizeof(eb));
	if(er.encoded >= 0) {
		fprintf(stderr, "INTEGER (0..7) value 8 was encoded\n");
		return 1;
	}

	printf("%zu values: XER, APER and OER OK\n", sizeof(vecs) / sizeof(vecs[0]));
	return 0;
}
