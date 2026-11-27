/*
 * BER: an indefinite length explicit tag around a definite length encoding
 * (192-ber-indefinite-explicit-OK, X.690 8.1.3.2, 8.14). The BER decoder
 * accepted a chain of tags with either all lengths indefinite or all
 * definite: [0] EXPLICIT INTEGER as A0 80 02 01 07 00 00 failed, for every
 * kind of type. A constructed string under a tag of its own ([0] EXPLICIT
 * OCTET STRING, [APPLICATION 1] IMPLICIT OCTET STRING) failed too, and so
 * did any constructed character string with OCTET STRING segments, as
 * X.690 8.23.6 has them (only segments with its own tag were taken). A tagged
 * CHOICE left the end-of-contents octets after an unknown extension
 * alternative, and looped forever on 00 followed by a non-zero octet in
 * their place. Resumed decoding (RC_WMORE in the middle of a chain of tags)
 * lost the count of indefinite lengths.
 * - each encoding decodes (also one byte at a time, RC_WMORE resumed),
 *   consuming all of it, to the value given as XER, whose DER decodes too;
 * - a second TLV inside an EXPLICIT tag is refused (it was taken for more
 *   segments of a constructed string);
 * - wrong or missing end-of-contents octets are refused.
 * (A definite length around an indefinite one: check-194.)
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "I.h"
#include "I2.h"
#include "Bo.h"
#include "R.h"
#include "Nu.h"
#include "O.h"
#include "En.h"
#include "Os.h"
#include "Oi.h"
#include "Bs.h"
#include "Us.h"
#include "Vx.h"
#include "On.h"
#include "Vs.h"
#include "VsS.h"
#include "Vp.h"
#include "Up.h"
#include "Sq.h"
#include "St.h"
#include "So.h"
#include "Ch.h"
#include "Ch2.h"
#include "W.h"

struct vec {
	asn_TYPE_descriptor_t *td;
	const char *ber; /* hex */
	const char *xer; /* canonical; "" for an unknown CHOICE alternative */
};

static const struct vec vecs[] = {
	/* definite, all indefinite (as before) */
	{ &asn_DEF_I, "a003 020107", "<I>7</I>" },
	{ &asn_DEF_Sq, "a080 3080 020101 0000 0000", "<Sq><x>1</x></Sq>" },
	/* indefinite around definite: primitive types */
	{ &asn_DEF_I, "a080 020107 0000", "<I>7</I>" },
	{ &asn_DEF_I2, "a480 a580 020107 0000 0000", "<I2>7</I2>" },
	{ &asn_DEF_I2, "a480 a503 020107 0000", "<I2>7</I2>" },
	{ &asn_DEF_Bo, "a080 0101ff 0000", "<Bo><true/></Bo>" },
	{ &asn_DEF_R, "a080 090380fb05 0000", "<R>1.5625E-1</R>" },
	{ &asn_DEF_Nu, "a080 0500 0000", "<Nu></Nu>" },
	{ &asn_DEF_O, "a080 0603510401 0000", "<O>2.1.4.1</O>" },
	{ &asn_DEF_En, "a080 0a0101 0000", "<En><b/></En>" },
	/* strings: primitive and constructed */
	{ &asn_DEF_Os, "a080 040141 0000", "<Os>41</Os>" },
	{ &asn_DEF_Os, "a080 2403 040141 0000", "<Os>41</Os>" },
	{ &asn_DEF_Os, "a080 2480 040141 0000 0000", "<Os>41</Os>" },
	{ &asn_DEF_Os, "a005 2403 040141", "<Os>41</Os>" },
	{ &asn_DEF_Oi, "4102 4142", "<Oi>4142</Oi>" },
	{ &asn_DEF_Oi, "6106 040141 040142", "<Oi>4142</Oi>" },
	{ &asn_DEF_Oi, "6180 040141 040142 0000", "<Oi>4142</Oi>" },
	{ &asn_DEF_Bs, "a080 03020780 0000", "<Bs>1</Bs>" },
	{ &asn_DEF_Bs, "a080 2380 03020780 0000 0000", "<Bs>1</Bs>" },
	/* segments: the OCTET STRING tag (X.690), or as before the string's */
	{ &asn_DEF_Vs, "a580 04026c6f 2480 040176 0402655f 0000 04026974 0000",
	  "<Vs>love_it</Vs>" },
	{ &asn_DEF_Vs, "a580 1a026c6f 3a80 040176 0402655f 0000 1a026974 0000",
	  "<Vs>love_it</Vs>" },
	{ &asn_DEF_VsS,
	  "3080 a580 04026c6f 2480 040176 0402655f 0000 04026974 0000 0000",
	  "<VsS><f>love_it</f></VsS>" },
	{ &asn_DEF_VsS,
	  "3080 a580 1a026c6f 3a80 040176 0402655f 0000 1a026974 0000 0000",
	  "<VsS><f>love_it</f></VsS>" },
	{ &asn_DEF_Vp, "3a80 04026c6f 0000", "<Vp>lo</Vp>" },
	{ &asn_DEF_Vp, "3a80 1a026c6f 0000", "<Vp>lo</Vp>" },
	{ &asn_DEF_Up, "2c80 040141 0000", "<Up>A</Up>" },
	{ &asn_DEF_Us, "a080 0c0141 0000", "<Us>A</Us>" },
	{ &asn_DEF_Vx, "a080 3a03 1a0141 0000", "<Vx>A</Vx>" },
	{ &asn_DEF_On, "a180 a280 2403 040141 0000 0000", "<On>41</On>" },
	/* constructed types */
	{ &asn_DEF_Sq, "a080 3003020101 0000", "<Sq><x>1</x></Sq>" },
	{ &asn_DEF_Sq, "a080 3006020101 0101ff 0000",
	  "<Sq><x>1</x><y><true/></y></Sq>" },
	{ &asn_DEF_St, "a080 3103020101 0000", "<St><x>1</x></St>" },
	{ &asn_DEF_So, "a080 3006020101020102 0000",
	  "<So><INTEGER>1</INTEGER><INTEGER>2</INTEGER></So>" },
	{ &asn_DEF_Ch, "a080 a103020107 0000", "<Ch><x>7</x></Ch>" },
	{ &asn_DEF_Ch, "a080 a180020107 0000 0000", "<Ch><x>7</x></Ch>" },
	{ &asn_DEF_Ch2, "a180 a005 a103020107 0000", "<Ch2><x>7</x></Ch2>" },
	{ &asn_DEF_Ch, "a080 850107 0000", "" },
	{ &asn_DEF_Ch, "a003 850107", "" },
	/* as members */
	{ &asn_DEF_W,
	  "3080 a180020101 0000 a280040141 0000 a3803003020101 0000"
	  " a080a103020107 0000 0101ff 0000",
	  "<W><a>1</a><b>41</b><c><x>1</x></c><ch><x>7</x></ch>"
	  "<d><true/></d></W>" },
	{ &asn_DEF_W,
	  "301b a103020101 a203040141 a305 3003020101 a005a103020107 0101ff",
	  "<W><a>1</a><b>41</b><c><x>1</x></c><ch><x>7</x></ch>"
	  "<d><true/></d></W>" },
};

static const struct vec refused[] = {
	{ &asn_DEF_I, "a080 020107 0001", 0 },
	{ &asn_DEF_I, "a080 020107 00", 0 },
	{ &asn_DEF_Sq, "a080 3003020101 0100", 0 },
	{ &asn_DEF_Os, "a080 040141 0100", 0 },
	{ &asn_DEF_Oi, "6180 040141 040142 0001", 0 },
	{ &asn_DEF_So, "a080 3003020101 0001", 0 },
	{ &asn_DEF_Ch, "a080 a103020107 0001", 0 },
	/* an EXPLICIT tag encloses one TLV, not several */
	{ &asn_DEF_Os, "a080 2403 040141 2403 040142 0000", 0 },
	{ &asn_DEF_Os, "a080 2403 040141 040142 0000", 0 },
	{ &asn_DEF_Os, "a080 2480 040141 0000 2480 040142 0000 0000", 0 },
	{ &asn_DEF_Os, "a080 040141 040142 0000", 0 },
	{ &asn_DEF_Bs, "a080 2304 03020080 2304 03020080 0000", 0 },
	{ &asn_DEF_Vx, "a080 3a03 1a0141 3a03 1a0142 0000", 0 },
	{ &asn_DEF_On, "a180 a280 2403 040141 2403 040142 0000 0000", 0 },
	{ &asn_DEF_Os, "a00a 2403 040141 2403 040142", 0 },
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
	size_t i;

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
