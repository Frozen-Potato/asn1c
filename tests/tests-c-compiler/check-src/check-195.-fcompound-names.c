/*
 * BER: [1] EXPLICIT ANY (195-ber-explicit-any-OK, X.690 8.14.2). The EXPLICIT
 * tag holds one TLV; the decoder used to accept several of them inside the
 * tag, in the definite and in the indefinite form. (An empty tag is still
 * accepted as an empty value, which is what the encoder writes for one.)
 * - one TLV (primitive or constructed, definite or indefinite length) inside
 *   a definite or an indefinite length tag decodes, also one byte at a time,
 *   keeping the raw bytes of the TLV; DER encoding and decoding it again
 *   gives the same bytes;
 * - two TLVs inside the tag are refused.
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "S.h"

struct vec {
	asn_TYPE_descriptor_t *td;
	const char *ber;	/* hex */
	const char *raw;	/* hex: the TLV kept */
};

static const struct vec vecs[] = {
	{ &asn_DEF_S, "3080 a103 040141 0000", "040141" },
	{ &asn_DEF_S, "3005 a103 040141", "040141" },
	{ &asn_DEF_S, "3080 a180 040141 0000 0000", "040141" },
	{ &asn_DEF_S, "3007 a180 040141 0000", "040141" },
	{ &asn_DEF_S, "3009 a107 2480 040141 0000", "2480040141 0000" },
	{ &asn_DEF_S, "3080 a180 2480 040141 0000 0000 0000",
	  "2480040141 0000" },
	{ &asn_DEF_S, "300a a108 3006 020105 020106", "3006 020105 020106" },
};

static const struct vec refused[] = {
	{ &asn_DEF_S, "3080 a180 040141 040142 0000 0000", 0 },
	{ &asn_DEF_S, "3008 a106 040141 040142", 0 },
	{ &asn_DEF_S, "3006 a104 3000 3000", 0 },
	{ &asn_DEF_S, "3080 a180 3080 0000 3080 0000 0000 0000", 0 },
	{ &asn_DEF_S, "3080 a107 040141 0000 0500", 0 },
};

static size_t
unhex(const char *h, unsigned char *b) {
	size_t n = 0;
	while(*h) {
		unsigned v;
		if(*h == ' ') { h++; continue; }
		sscanf(h, "%2x", &v);
		b[n++] = (unsigned char)v;
		h += 2;
	}
	return n;
}

static OCTET_STRING_t *
raw_of(asn_TYPE_descriptor_t *td, void *st) {
	(void)td;
	return &((S_t *)st)->t;
}

/* Decode buf[0..n) handing the decoder one more byte at a time. */
static void *
decode_bytewise(asn_TYPE_descriptor_t *td, const unsigned char *buf,
				size_t n) {
	void *st = 0;
	size_t off = 0, avail = 1;
	for(;;) {
		asn_dec_rval_t dr = ber_decode(0, td, &st, buf + off, avail - off);
		off += dr.consumed;
		if(dr.code == RC_OK) break;
		assert(dr.code == RC_WMORE);
		assert(avail < n);
		avail++;
	}
	assert(off == n);
	return st;
}

static void
check_raw(asn_TYPE_descriptor_t *td, void *st, const unsigned char *want,
		  size_t wlen) {
	const OCTET_STRING_t *os = raw_of(td, st);
	unsigned char der[128];
	asn_enc_rval_t er;
	void *back = 0;
	asn_dec_rval_t dr;

	assert(os->size == wlen);
	assert(wlen == 0 || !memcmp(os->buf, want, wlen));

	/* Round trip */
	er = asn_encode_to_buffer(0, ATS_DER, td, st, der, sizeof(der));
	assert(er.encoded > 0 && (size_t)er.encoded <= sizeof(der));
	dr = ber_decode(0, td, &back, der, er.encoded);
	assert(dr.code == RC_OK && dr.consumed == (size_t)er.encoded);
	os = raw_of(td, back);
	assert(os->size == wlen);
	assert(wlen == 0 || !memcmp(os->buf, want, wlen));
	ASN_STRUCT_FREE(*td, back);
}

int
main(void) {
	size_t i, k;

	for(i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		const struct vec *v = &vecs[i];
		unsigned char b[128], raw[128];
		size_t n = unhex(v->ber, b);
		size_t rn = unhex(v->raw, raw);
		void *st = 0;
		asn_dec_rval_t dr;

		dr = ber_decode(0, v->td, &st, b, n);
		if(dr.code != RC_OK || dr.consumed != n) {
			fprintf(stderr, "%s %s: code %d, consumed %zu of %zu\n",
					v->td->name, v->ber, dr.code, dr.consumed, n);
			assert(!"BER decode");
		}
		check_raw(v->td, st, raw, rn);
		ASN_STRUCT_FREE(*v->td, st);

		st = decode_bytewise(v->td, b, n);
		check_raw(v->td, st, raw, rn);
		ASN_STRUCT_FREE(*v->td, st);

		/* Every proper prefix: more data expected */
		for(k = 0; k < n; k++) {
			st = 0;
			dr = ber_decode(0, v->td, &st, b, k);
			if(dr.code != RC_WMORE) {
				fprintf(stderr, "%s %s: prefix %zu: code %d\n",
						v->td->name, v->ber, k, dr.code);
				assert(!"prefix");
			}
			ASN_STRUCT_FREE(*v->td, st);
		}
	}

	for(i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
		const struct vec *v = &refused[i];
		unsigned char b[128];
		size_t n = unhex(v->ber, b);
		void *st = 0;
		asn_dec_rval_t dr = ber_decode(0, v->td, &st, b, n);
		if(dr.code == RC_OK) {
			fprintf(stderr, "%s %s: accepted\n", v->td->name, v->ber);
			assert(!"refused");
		}
		ASN_STRUCT_FREE(*v->td, st);
	}

	return 0;
}
