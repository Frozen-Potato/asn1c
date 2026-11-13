/*
 * SET OF APER encoder: canonical order (elements sorted by their standalone
 * encodings, then re-encoded in that order), size constraints, and clean
 * failure when an element cannot be encoded.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <SoInt.h>
#include <SoOcts.h>
#include <SoSeq.h>

static void
check_bytes(const void *got, ssize_t bits, const uint8_t *exp, size_t n) {
	assert(bits == (ssize_t)(8 * n) || (bits > (ssize_t)(8 * (n - 1))
					     && bits <= (ssize_t)(8 * n)));
	assert(memcmp(got, exp, n) == 0);
}

static void
add_int(SoInt_t *s, long v) {
	long *p = calloc(1, sizeof(*p));
	*p = v;
	assert(asn_set_add(&s->list, p) == 0);
}

static void
add_oct(SoOcts_t *s, const char *d, size_t n) {
	OCTET_STRING_t *o = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, d, n);
	assert(o);
	assert(asn_set_add(&s->list, o) == 0);
}

static void
add_seq(SoSeq_t *s, int f, const char *d, size_t n) {
	Member *m = calloc(1, sizeof(*m));
	m->f = f;
	assert(OCTET_STRING_fromBuf(&m->o, d, n) == 0);
	assert(asn_set_add(&s->list, m) == 0);
}

static void
roundtrip(const asn_TYPE_descriptor_t *td, void *v, const uint8_t *aper,
	  size_t an, const uint8_t *uper, size_t un) {
	uint8_t buf[64];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	void *out = 0;
	asn_codec_ctx_t ctx;

	memset(&ctx, 0, sizeof(ctx));
	memset(buf, 0, sizeof(buf));
	er = aper_encode_to_buffer(td, 0, v, buf, sizeof(buf));
	assert(er.encoded > 0 || an == 1);
	check_bytes(buf, er.encoded, aper, an);

	rv = aper_decode(&ctx, td, &out, buf, an, 0, 0);
	assert(rv.code == RC_OK);
	/* Both are in canonical order on re-encode, so compare re-encodings. */
	{
		uint8_t b2[64];
		memset(b2, 0, sizeof(b2));
		er = aper_encode_to_buffer(td, 0, out, b2, sizeof(b2));
		assert(memcmp(b2, aper, an) == 0);
	}
	ASN_STRUCT_FREE(*td, out);

	memset(buf, 0, sizeof(buf));
	er = uper_encode_to_buffer(td, 0, v, buf, sizeof(buf));
	assert(er.encoded >= 0);
	assert(memcmp(buf, uper, un) == 0);
}

int main() {
	/* SoInt_a */
	{
		static const uint8_t a[] = {0x60, 0x01, 0x03, 0xc8};
		static const uint8_t u[] = {0x60, 0x20, 0x79, 0x00};
		SoInt_t s;
		memset(&s, 0, sizeof(s));
		add_int(&s, 3); add_int(&s, 1); add_int(&s, 200);
		roundtrip(&asn_DEF_SoInt, &s, a, 4, u, 4);
		ASN_STRUCT_RESET(asn_DEF_SoInt, &s);
	}
	/* SoInt_e */
	{
		static const uint8_t a[] = {0x00};
		SoInt_t s;
		uint8_t buf[8] = {0xff};
		void *out = 0;
		asn_dec_rval_t rv;
		asn_enc_rval_t er;
		asn_codec_ctx_t ctx;
		memset(&ctx, 0, sizeof(ctx));
		memset(&s, 0, sizeof(s));
		er = aper_encode_to_buffer(&asn_DEF_SoInt, 0, &s, buf, sizeof(buf));
		assert(er.encoded == 3);
		assert(buf[0] == a[0]);
		memset(buf, 0, sizeof(buf));
		er = uper_encode_to_buffer(&asn_DEF_SoInt, 0, &s, buf, sizeof(buf));
		assert(er.encoded == 3 && buf[0] == 0);
		rv = aper_decode(&ctx, &asn_DEF_SoInt, &out, buf, 1, 0, 0);
		assert(rv.code == RC_OK);
		assert(((SoInt_t *)out)->list.count == 0);
		ASN_STRUCT_FREE(asn_DEF_SoInt, out);
	}
	/* SoOcts_a */
	{
		static const uint8_t a[] = {3, 0, 1, 1, 2, 1, 2};
		SoOcts_t s;
		memset(&s, 0, sizeof(s));
		add_oct(&s, "\x01\x02", 2); add_oct(&s, "\x01", 1); add_oct(&s, "", 0);
		roundtrip(&asn_DEF_SoOcts, &s, a, 7, a, 7);
		ASN_STRUCT_RESET(asn_DEF_SoOcts, &s);
	}
	/* SoSeq_a */
	{
		static const uint8_t a[] = {0x24, 0xbb, 0xcc, 0x90, 0xaa};
		static const uint8_t u[] = {0x25, 0x77, 0x99, 0x35, 0x40};
		SoSeq_t s;
		memset(&s, 0, sizeof(s));
		add_seq(&s, 1, "\xaa", 1);
		add_seq(&s, 0, "\xbb\xcc", 2);
		roundtrip(&asn_DEF_SoSeq, &s, a, 5, u, 5);
		ASN_STRUCT_RESET(asn_DEF_SoSeq, &s);
	}
	/* Failures: element out of constraint, size out of constraint. */
	{
		SoInt_t s;
		uint8_t buf[16];
		asn_enc_rval_t er;
		memset(&s, 0, sizeof(s));
		add_int(&s, 1); add_int(&s, 300);
		er = aper_encode_to_buffer(&asn_DEF_SoInt, 0, &s, buf, sizeof(buf));
		assert(er.encoded == -1);
		er = uper_encode_to_buffer(&asn_DEF_SoInt, 0, &s, buf, sizeof(buf));
		assert(er.encoded == -1);
		ASN_STRUCT_RESET(asn_DEF_SoInt, &s);
		memset(&s, 0, sizeof(s));
		add_int(&s, 1); add_int(&s, 2); add_int(&s, 3); add_int(&s, 4);
		add_int(&s, 5);
		er = aper_encode_to_buffer(&asn_DEF_SoInt, 0, &s, buf, sizeof(buf));
		assert(er.encoded == -1);
		ASN_STRUCT_RESET(asn_DEF_SoInt, &s);
	}
	return 0;
}
