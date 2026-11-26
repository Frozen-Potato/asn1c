/*
 * -fopen-type-unknown: the value of an id that the extensible object set
 * does not know (a newer peer's id) decodes as <T>_PR_unknown, keeping the
 * octets it was received as and the codec that decoded them, in every
 * codec (BER, OER, UPER, APER, JER). It encodes again byte for byte with
 * that codec and with no other. A closed object set still refuses such an
 * id. The vectors were encoded by the same module with the ids added.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <asn_application.h>
#include <Msg.h>
#include <MsgE.h>
#include <FieldE.h>
#include <MsgC.h>
#include <MsgU.h>

static const uint8_t msg_ber[] = {
	0x30, 0x10, 0x80, 0x01, 0x05, 0xa1, 0x08, 0x80, 0x01, 0x03, 0xa1, 0x03,
	0x01, 0x01, 0xff, 0x82, 0x01, 0xff,
};
static const uint8_t msg_oer[] = {
	0x05, 0x00, 0x03, 0x01, 0xff, 0xff,
};
static const uint8_t msg_uper[] = {
	0xa0, 0x00, 0x60, 0x30, 0x10,
};
static const uint8_t msg_aper[] = {
	0xa0, 0x00, 0x03, 0x01, 0x80, 0x80,
};
static const uint8_t msg_jer[] = {
	0x7b, 0x22, 0x61, 0x22, 0x3a, 0x35, 0x2c, 0x22, 0x66, 0x22, 0x3a, 0x7b,
	0x22, 0x69, 0x64, 0x22, 0x3a, 0x33, 0x2c, 0x22, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x22, 0x3a, 0x74, 0x72, 0x75, 0x65, 0x7d, 0x2c, 0x22, 0x62, 0x22,
	0x3a, 0x74, 0x72, 0x75, 0x65, 0x7d,
};
static const uint8_t msge_ber[] = {
	0x30, 0x16, 0xa0, 0x14, 0x30, 0x08, 0x80, 0x01, 0x05, 0xa1, 0x03, 0x02,
	0x01, 0x09, 0x30, 0x08, 0x80, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x04,
};
static const uint8_t msge_oer[] = {
	0x01, 0x02, 0x00, 0x05, 0x01, 0x09, 0x00, 0x05, 0x01, 0x04,
};
static const uint8_t msge_uper[] = {
	0x40, 0x00, 0xa0, 0x32, 0x00, 0x00, 0xa0, 0x28, 0x00,
};
static const uint8_t msge_aper[] = {
	0x40, 0x00, 0x05, 0x01, 0x90, 0x00, 0x05, 0x01, 0x40,
};
static const uint8_t msge_jer[] = {
	0x7b, 0x22, 0x66, 0x22, 0x3a, 0x5b, 0x7b, 0x22, 0x69, 0x64, 0x22, 0x3a,
	0x35, 0x2c, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x3a, 0x39, 0x7d,
	0x2c, 0x7b, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x35, 0x2c, 0x22, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x22, 0x3a, 0x34, 0x7d, 0x5d, 0x7d,
};
static const uint8_t msgc_ber[] = {
	0x30, 0x0a, 0xa0, 0x08, 0x80, 0x01, 0x03, 0xa1, 0x03, 0x02, 0x01, 0x07,
};
static const uint8_t msgc_oer[] = {
	0x00, 0x03, 0x01, 0x07,
};
static const uint8_t msgc_uper[] = {
	0x00, 0x03, 0x01, 0x07,
};
static const uint8_t msgc_aper[] = {
	0x00, 0x03, 0x01, 0x07,
};
static const uint8_t msgc_jer[] = {
	0x7b, 0x22, 0x66, 0x22, 0x3a, 0x7b, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x33,
	0x2c, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x3a, 0x37, 0x7d, 0x7d,
};
static const uint8_t msgu_ber[] = {
	0x30, 0x07, 0x02, 0x01, 0x04, 0x04, 0x02, 0x68, 0x69,
};
static const uint8_t msgu_oer[] = {
	0x00, 0x04, 0x03, 0x02, 0x68, 0x69,
};
static const uint8_t msgu_uper[] = {
	0x00, 0x04, 0x03, 0x02, 0x68, 0x69,
};
static const uint8_t msgu_aper[] = {
	0x00, 0x04, 0x03, 0x02, 0x68, 0x69,
};
static const uint8_t msgu_jer[] = {
	0x7b, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x34, 0x2c, 0x22, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x3a, 0x22, 0x36, 0x38, 0x36, 0x39, 0x22, 0x7d,
};

static const enum asn_transfer_syntax dec_ats[] = {
	ATS_BER, ATS_CANONICAL_OER, ATS_UNALIGNED_BASIC_PER,
	ATS_ALIGNED_BASIC_PER, ATS_JER
};
static const enum asn_transfer_syntax enc_ats[] = {
	ATS_DER, ATS_CANONICAL_OER, ATS_UNALIGNED_CANONICAL_PER,
	ATS_ALIGNED_CANONICAL_PER, ATS_JER_MINIFIED
};
static const long raw_codec[] = {
	OPEN_TYPE_RAW_BER, OPEN_TYPE_RAW_OER, OPEN_TYPE_RAW_UPER,
	OPEN_TYPE_RAW_APER, OPEN_TYPE_RAW_JER
};
static const char *names[] = { "BER", "OER", "UPER", "APER", "JER" };

struct vec {
	const uint8_t *buf;
	size_t size;
};
#define VEC(a)	{ a, sizeof(a) }

static void *
decode(asn_TYPE_descriptor_t *td, int c, const struct vec *in) {
	void *st = 0;
	asn_dec_rval_t rv = asn_decode(0, dec_ats[c], td, &st, in->buf, in->size);
	if(rv.code != RC_OK || rv.consumed != in->size) {
		fprintf(stderr, "%s %s: decode rc=%d consumed=%zu of %zu\n",
			td->name, names[c], rv.code, rv.consumed, in->size);
		assert(0);
	}
	return st;
}

/* The same octets again with codec c, an error with each other codec. */
static void
reencode(asn_TYPE_descriptor_t *td, int c, const void *st,
         const struct vec *in) {
	int e;
	char errbuf[128];
	size_t errlen = sizeof(errbuf);

	assert(asn_check_constraints(td, st, errbuf, &errlen) == 0);
	for(e = 0; e < 5; e++) {
		asn_encode_to_new_buffer_result_t er =
			asn_encode_to_new_buffer(0, enc_ats[e], td, st);
		if(e == c) {
			if(!er.buffer || er.result.encoded != (ssize_t)in->size
			   || memcmp(er.buffer, in->buf, in->size)) {
				fprintf(stderr, "%s %s: not encoded back as received\n",
					td->name, names[c]);
				assert(0);
			}
		} else if(er.result.encoded >= 0) {
			fprintf(stderr, "%s: a %s value encoded as %s\n", td->name,
				names[c], names[e]);
			assert(0);
		}
		free(er.buffer);
	}
}

static void
check_raw(const OPEN_TYPE_raw_t *u, int c, const char *raw, size_t raw_size) {
	assert(u->codec == raw_codec[c]);
	assert(u->raw.size > 0);
	if(raw) {
		assert(u->raw.size == raw_size);
		assert(memcmp(u->raw.buf, raw, raw_size) == 0);
	}
}

static int
discard(const void *buf, size_t size, void *key) {
	(void)buf;
	(void)size;
	(void)key;
	return 0;
}

int
main(void) {
	static const struct vec msg[] = { VEC(msg_ber), VEC(msg_oer),
		VEC(msg_uper), VEC(msg_aper), VEC(msg_jer) };
	static const struct vec msge[] = { VEC(msge_ber), VEC(msge_oer),
		VEC(msge_uper), VEC(msge_aper), VEC(msge_jer) };
	static const struct vec msgc[] = { VEC(msgc_ber), VEC(msgc_oer),
		VEC(msgc_uper), VEC(msgc_aper), VEC(msgc_jer) };
	static const struct vec msgu[] = { VEC(msgu_ber), VEC(msgu_oer),
		VEC(msgu_uper), VEC(msgu_aper), VEC(msgu_jer) };
	/* the octets of BOOLEAN TRUE in each codec (BER: inside [1]) */
	static const char *msg_raw[] = { "\x01\x01\xff", "\xff", "\x80",
		"\x80", "true" };
	static const size_t msg_raw_size[] = { 3, 1, 1, 1, 4 };
	int c;

	for(c = 0; c < 5; c++) {
		Msg_t *m = decode(&asn_DEF_Msg, c, &msg[c]);
		MsgE_t *e = decode(&asn_DEF_MsgE, c, &msge[c]);
		MsgU_t *u = decode(&asn_DEF_MsgU, c, &msgu[c]);
		MsgC_t *mc = 0;
		asn_dec_rval_t rv;
		int i;

		assert(m->a == 5 && m->b && m->f.id == 3);
		assert(m->f.value.present == Field__value_PR_unknown);
		check_raw(&m->f.value.choice.unknown, c, msg_raw[c],
			msg_raw_size[c]);
		assert(asn_fprint(stdout, &asn_DEF_Msg, m) == 0);
		reencode(&asn_DEF_Msg, c, m, &msg[c]);

		/* an empty extensible set: every id is unknown */
		assert(e->f.list.count == 2);
		for(i = 0; i < 2; i++) {
			assert(e->f.list.array[i]->id == 5);
			assert(e->f.list.array[i]->value.present
			       == FieldE__value_PR_unknown);
			check_raw(&e->f.list.array[i]->value.choice.unknown, c, 0, 0);
		}
		reencode(&asn_DEF_MsgE, c, e, &msge[c]);

		/* a value without a tag of its own: BER keeps its own TLV */
		assert(u->id == 4 && u->value.present == MsgU__value_PR_unknown);
		check_raw(&u->value.choice.unknown, c,
			c == 0 ? "\x04\x02hi" : 0, 4);
		reencode(&asn_DEF_MsgU, c, u, &msgu[c]);

		/* a closed set refuses an id it does not know */
		rv = asn_decode(0, dec_ats[c], &asn_DEF_MsgC, (void **)&mc,
			msgc[c].buf, msgc[c].size);
		assert(rv.code != RC_OK);
		ASN_STRUCT_FREE(asn_DEF_MsgC, mc);

		ASN_STRUCT_FREE(asn_DEF_Msg, m);
		ASN_STRUCT_FREE(asn_DEF_MsgE, e);
		ASN_STRUCT_FREE(asn_DEF_MsgU, u);
	}

	/* values built by hand */
	{
		Msg_t m;
		asn_enc_rval_t er;
		char errbuf[128];
		size_t errlen = sizeof(errbuf);

		memset(&m, 0, sizeof(m));
		m.a = 5;
		m.b = 1;
		m.f.id = 9;
		m.f.value.present = Field__value_PR_unknown;
		/* no codec: refused */
		assert(asn_check_constraints(&asn_DEF_Msg, &m, errbuf, &errlen));
		er = asn_encode(0, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Msg, &m,
			discard, 0);
		assert(er.encoded < 0);
		/* empty contents: only OER has them (the encoding of NULL) */
		m.f.value.choice.unknown.codec = OPEN_TYPE_RAW_APER;
		er = asn_encode(0, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Msg, &m,
			discard, 0);
		assert(er.encoded < 0);
		m.f.value.choice.unknown.codec = OPEN_TYPE_RAW_OER;
		errlen = sizeof(errbuf);
		assert(asn_check_constraints(&asn_DEF_Msg, &m, errbuf, &errlen) == 0);
		er = asn_encode(0, ATS_CANONICAL_OER, &asn_DEF_Msg, &m, discard, 0);
		assert(er.encoded == 5);	/* 05 | 00 09 | 00 | ff */
		ASN_STRUCT_RESET(asn_DEF_Msg, &m);
	}

	return 0;
}
