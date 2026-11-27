/*
 * BER: a definite length explicit tag around an indefinite length encoding
 * (194-ber-definite-indefinite-explicit-OK, X.690 8.1.3.2, 8.14). The BER
 * decoder refused any definite length TLV enclosing an indefinite length one
 * in a chain of tags: [0] EXPLICIT SEQUENCE { ... } as
 * A0 07 30 80 02 01 05 00 00 failed, for every kind of constructed type.
 * The length of the outer TLV must be that of the inner one with its
 * end-of-contents octets, and is checked.
 * - each encoding decodes (also one byte at a time, RC_WMORE resumed),
 *   consuming all of it, to the value given as XER, whose DER decodes too;
 * - every proper prefix of an encoding asks for more data;
 * - an outer length shorter or longer than the inner TLV, wrong or missing
 *   end-of-contents octets are refused.
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Sq.h"
#include "St.h"
#include "So.h"
#include "Ss.h"
#include "Ch.h"
#include "Ch2.h"
#include "Os.h"
#include "Vs.h"
#include "Sq2.h"
#include "Is.h"
#include "W.h"

struct vec {
	asn_TYPE_descriptor_t *td;
	const char *ber; /* hex */
	const char *xer; /* canonical; "" for an unknown CHOICE alternative */
};

static const struct vec vecs[] = {
	/* as before: all definite, all indefinite */
	{ &asn_DEF_Sq, "a005 3003 020105", "<Sq><x>5</x></Sq>" },
	{ &asn_DEF_Sq, "a080 3080 020105 0000 0000", "<Sq><x>5</x></Sq>" },
	/* definite around indefinite */
	{ &asn_DEF_Sq, "a007 3080 020105 0000", "<Sq><x>5</x></Sq>" },
	{ &asn_DEF_Sq, "a00a 3080 020105 0101ff 0000",
	  "<Sq><x>5</x><y><true/></y></Sq>" },
	{ &asn_DEF_St, "a007 3180 020105 0000", "<St><x>5</x></St>" },
	{ &asn_DEF_So, "a00a 3080 020101 020102 0000",
	  "<So><INTEGER>1</INTEGER><INTEGER>2</INTEGER></So>" },
	{ &asn_DEF_Ss, "a00a 3180 020101 020102 0000",
	  "<Ss><INTEGER>1</INTEGER><INTEGER>2</INTEGER></Ss>" },
	{ &asn_DEF_Ch, "a007 a280 020107 0000", "<Ch><q><x>7</x></q></Ch>" },
	{ &asn_DEF_Ch, "a009 a307 3080 020107 0000", "<Ch><r><x>7</x></r></Ch>" },
	{ &asn_DEF_Ch, "a00b a380 3080 020107 0000 0000",
	  "<Ch><r><x>7</x></r></Ch>" },
	{ &asn_DEF_Ch, "a007 a580 020107 0000", "" }, /* unknown, skipped */
	{ &asn_DEF_Ch2, "a109 a007 a280 020107 0000", "<Ch2><q><x>7</x></q></Ch2>" },
	{ &asn_DEF_Ch2, "a10b a080 a280 020107 0000 0000",
	  "<Ch2><q><x>7</x></q></Ch2>" },
	{ &asn_DEF_Ch2, "a180 a007 a280 020107 0000 0000",
	  "<Ch2><q><x>7</x></q></Ch2>" },
	{ &asn_DEF_Os, "a00a 2480 040141 040142 0000", "<Os>4142</Os>" },
	{ &asn_DEF_Vs, "a00a 3a80 040141 040142 0000", "<Vs>AB</Vs>" },
	/* chains of three tags: every combination of the lengths */
	{ &asn_DEF_Sq2, "a407 a505 3003 020105", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a409 a507 3080 020105 0000", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a40b a580 3080 020105 0000 0000", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a480 a507 3080 020105 0000 0000", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a480 a580 3080 020105 0000 0000 0000",
	  "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a480 a505 3003 020105 0000", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Sq2, "a409 a580 3003 020105 0000", "<Sq2><x>5</x></Sq2>" },
	{ &asn_DEF_Is, "a409 a007 3080 020105 0000", "<Is><x>5</x></Is>" },
	{ &asn_DEF_Is, "a409 a080 3003 020105 0000", "<Is><x>5</x></Is>" },
	/* as members, of a definite and of an indefinite length SEQUENCE */
	{ &asn_DEF_W,
	  "3021 a107 3080 020105 0000 a20a 2480 040141 040142 0000"
	  " a007 a280 020107 0000 0101ff",
	  "<W><a><x>5</x></a><b>4142</b><ch><q><x>7</x></q></ch>"
	  "<d><true/></d></W>" },
	{ &asn_DEF_W,
	  "3080 a107 3080 020105 0000 a20a 2480 040141 040142 0000"
	  " a007 a280 020107 0000 0101ff 0000",
	  "<W><a><x>5</x></a><b>4142</b><ch><q><x>7</x></q></ch>"
	  "<d><true/></d></W>" },
};

static const struct vec refused[] = {
	/* the length of the tag: shorter or longer than the inner TLV */
	{ &asn_DEF_Sq, "a006 3080 020105 0000", 0 },
	{ &asn_DEF_Sq, "a005 3080 020105 0000", 0 },
	{ &asn_DEF_Sq, "a008 3080 020105 0000", 0 },
	{ &asn_DEF_Sq, "a008 3080 020105 0000 0500", 0 },
	{ &asn_DEF_Sq, "a009 3080 020105 0000 0500", 0 },
	{ &asn_DEF_Sq, "a009 3080 020105 0000 0000", 0 },
	{ &asn_DEF_Sq, "a002 3080 020105 0000", 0 },
	{ &asn_DEF_So, "a009 3080 020101 020102 0000", 0 },
	{ &asn_DEF_Os, "a00b 2480 040141 040142 0000", 0 },
	{ &asn_DEF_Ch, "a006 a280 020107 0000", 0 },
	{ &asn_DEF_Ch, "a008 a280 020107 0000", 0 },
	{ &asn_DEF_Sq2, "a40a a507 3080 020105 0000", 0 },
	{ &asn_DEF_Sq2, "a408 a507 3080 020105 0000", 0 },
	{ &asn_DEF_Sq2, "a409 a508 3080 020105 0000", 0 },
	{ &asn_DEF_Sq2, "a409 a506 3080 020105 0000", 0 },
	{ &asn_DEF_Sq2, "a480 a506 3080 020105 0000 0000", 0 },
	{ &asn_DEF_Sq2, "a40a a580 3080 020105 0000 0000", 0 },
	{ &asn_DEF_Sq2, "a40c a580 3080 020105 0000 0000", 0 },
	{ &asn_DEF_Is, "a408 a080 3003 020105 0000", 0 },
	{ &asn_DEF_Is, "a40a a080 3003 020105 0000", 0 },
	{ &asn_DEF_W,
	  "3080 a106 3080 020105 0000 a20a 2480 040141 040142 0000"
	  " a007 a280 020107 0000 0101ff 0000", 0 },
	{ &asn_DEF_W,
	  "301f a108 3080 020105 0000 a20a 2480 040141 040142 0000"
	  " a007 a280 020107 0000 0101ff", 0 },
	/* wrong or missing end-of-contents octets */
	{ &asn_DEF_Sq, "a007 3080 020105 0001", 0 },
	{ &asn_DEF_Sq, "a007 3080 020105 0100", 0 },
	{ &asn_DEF_Sq, "a005 3080 020105", 0 },
	{ &asn_DEF_Sq, "a007 3080 020105 00", 0 },
	{ &asn_DEF_Is, "a409 a080 3003 020105 0001", 0 },
	{ &asn_DEF_Is, "a409 a080 3003 020105 0100", 0 },
	/* a second TLV inside the tag */
	{ &asn_DEF_Sq, "a00c 3080 020105 0000 3003020105", 0 },
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
check_value(asn_TYPE_descriptor_t *td, void *st, const char *want) {
	char got[256];
	unsigned char der[128];
	asn_enc_rval_t er;
	void *back = 0;
	asn_dec_rval_t dr;

	if(!*want) {
		/* An unknown alternative of the extensible CHOICE: skipped */
		const Ch_t *ch = (const Ch_t *)st;
		assert(td == &asn_DEF_Ch);
		assert(ch->present == Ch_PR_NOTHING);
		return;
	}

	er = asn_encode_to_buffer(0, ATS_CANONICAL_XER, td, st, got,
							  sizeof(got) - 1);
	assert(er.encoded > 0 && (size_t)er.encoded < sizeof(got));
	got[er.encoded] = 0;
	if(strcmp(got, want)) {
		fprintf(stderr, "%s: XER %s, want %s\n", td->name, got, want);
		assert(!"XER");
	}

	er = asn_encode_to_buffer(0, ATS_DER, td, st, der, sizeof(der));
	assert(er.encoded > 0 && (size_t)er.encoded <= sizeof(der));
	dr = ber_decode(0, td, &back, der, er.encoded);
	assert(dr.code == RC_OK && dr.consumed == (size_t)er.encoded);
	ASN_STRUCT_FREE(*td, back);
}

int
main(void) {
	size_t i, k;

	for(i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
		const struct vec *v = &vecs[i];
		unsigned char b[128];
		size_t n = unhex(v->ber, b);
		void *st = 0;
		asn_dec_rval_t dr;

		dr = ber_decode(0, v->td, &st, b, n);
		if(dr.code != RC_OK || dr.consumed != n) {
			fprintf(stderr, "%s %s: code %d, consumed %zu of %zu\n",
					v->td->name, v->ber, dr.code, dr.consumed, n);
			assert(!"BER decode");
		}
		check_value(v->td, st, v->xer);
		ASN_STRUCT_FREE(*v->td, st);

		st = decode_bytewise(v->td, b, n);
		check_value(v->td, st, v->xer);
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

		/* Data after the value is not consumed */
		b[n] = 0xff;
		st = 0;
		dr = ber_decode(0, v->td, &st, b, n + 1);
		assert(dr.code == RC_OK && dr.consumed == n);
		ASN_STRUCT_FREE(*v->td, st);
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
