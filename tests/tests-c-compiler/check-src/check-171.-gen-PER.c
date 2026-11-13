/*
 * SET UPER/APER (X.691 clause 21): root components in canonical tag order
 * (presence bitmap and values), untagged CHOICE sorted by its smallest tag,
 * extension additions and [[ ]] groups like SEQUENCE, root components after
 * the additions, presence bits set by the decoder, truncated input.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <SetBasic.h>
#include <SetGrp.h>
#include <SetTail.h>
#include <SetTags.h>
#include <SetCh.h>

static void
check_enc(const asn_TYPE_descriptor_t *td, const void *v, int aper,
	  const uint8_t *exp, size_t n) {
	uint8_t buf[64];
	asn_enc_rval_t er;

	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(td, 0, v, buf, sizeof(buf))
		  : uper_encode_to_buffer(td, 0, v, buf, sizeof(buf));
	assert(er.encoded >= 0);
	assert((size_t)er.encoded <= 8 * n && (size_t)er.encoded > 8 * (n - 1));
	assert(memcmp(buf, exp, n) == 0);
}

/* Decode exp back, re-encode and compare; every strict prefix must fail. */
static void *
check_dec(const asn_TYPE_descriptor_t *td, int aper, const uint8_t *exp,
	  size_t n) {
	asn_codec_ctx_t ctx;
	asn_dec_rval_t rv;
	void *out = 0;
	size_t k;

	memset(&ctx, 0, sizeof(ctx));
	rv = aper ? aper_decode(&ctx, td, &out, exp, n, 0, 0)
		  : uper_decode(&ctx, td, &out, exp, n, 0, 0);
	assert(rv.code == RC_OK);
	check_enc(td, out, aper, exp, n);

	for(k = 0; k < n; k++) {
		void *part = 0;
		rv = aper ? aper_decode(&ctx, td, &part, exp, k, 0, 0)
			  : uper_decode(&ctx, td, &part, exp, k, 0, 0);
		assert(rv.code != RC_OK);
		ASN_STRUCT_FREE(*td, part);
	}
	return out;
}

static void
both(const asn_TYPE_descriptor_t *td, const void *v, const uint8_t *a,
     size_t an, const uint8_t *u, size_t un, void **out_a, void **out_u) {
	check_enc(td, v, 1, a, an);
	check_enc(td, v, 0, u, un);
	*out_a = check_dec(td, 1, a, an);
	*out_u = check_dec(td, 0, u, un);
}

#define PRES(p, T, m) (ASN_SET_ISPRESENT(p, T##_PR_##m) != 0)

int main() {
	void *oa, *ou;

	/* SetBasic_a: optional b present, canonical order a, b, c */
	{
		static const uint8_t a[] = {0x6c, 0x02, 0x0a, 0x0b};
		static const uint8_t u[] = {0x6c, 0x08, 0x28, 0x2c};
		SetBasic_t s;
		SetBasic_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.a = 5;
		s.b = calloc(1, sizeof(*s.b));
		*s.b = 1;
		assert(OCTET_STRING_fromBuf(&s.c, "\x0a\x0b", 2) == 0);
		both(&asn_DEF_SetBasic, &s, a, 4, u, 4, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->a == 5 && p->b && *p->b == 1 && !p->d);
			assert(p->c.size == 2 && p->c.buf[1] == 0x0b);
			assert(PRES(p, SetBasic, a) && PRES(p, SetBasic, b)
			       && PRES(p, SetBasic, c) && !PRES(p, SetBasic, d));
			ASN_STRUCT_FREE(asn_DEF_SetBasic, p);
		}
		ASN_STRUCT_RESET(asn_DEF_SetBasic, &s);
	}
	/* SetBasic_x: extension addition d, b absent */
	{
		static const uint8_t a[] = {0xa8, 0x01, 0x0a, 0x01, 0x01, 0x80};
		static const uint8_t u[] = {0xa8, 0x08, 0x50, 0x08, 0x0c, 0x00};
		SetBasic_t s;
		SetBasic_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.a = 5;
		assert(OCTET_STRING_fromBuf(&s.c, "\x0a", 1) == 0);
		s.d = calloc(1, sizeof(*s.d));
		*s.d = 2;
		both(&asn_DEF_SetBasic, &s, a, 6, u, 6, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->a == 5 && !p->b && p->d && *p->d == 2);
			assert(PRES(p, SetBasic, a) && !PRES(p, SetBasic, b)
			       && PRES(p, SetBasic, c) && PRES(p, SetBasic, d));
			ASN_STRUCT_FREE(asn_DEF_SetBasic, p);
		}
		ASN_STRUCT_RESET(asn_DEF_SetBasic, &s);
	}
	/* SetGrp_a and SetGrp_g */
	{
		static const uint8_t a1[] = {0x10};
		static const uint8_t a2[] = {0x90, 0x10, 0x01, 0xf0};
		static const uint8_t u2[] = {0x90, 0x10, 0x1f, 0x00};
		SetGrp_t s;
		SetGrp_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.a = 1;
		both(&asn_DEF_SetGrp, &s, a1, 1, a1, 1, &oa, &ou);
		assert(!((SetGrp_t *)oa)->ext1 && !((SetGrp_t *)ou)->ext1);
		ASN_STRUCT_FREE(asn_DEF_SetGrp, oa);
		ASN_STRUCT_FREE(asn_DEF_SetGrp, ou);

		s.ext1 = calloc(1, sizeof(*s.ext1));
		s.ext1->g1 = 1;
		s.ext1->g2 = calloc(1, sizeof(*s.ext1->g2));
		*s.ext1->g2 = 3;
		both(&asn_DEF_SetGrp, &s, a2, 4, u2, 4, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->a == 1 && p->ext1 && p->ext1->g1 == 1
			       && p->ext1->g2 && *p->ext1->g2 == 3);
			assert(PRES(p, SetGrp, a) && PRES(p, SetGrp, Member));
			ASN_STRUCT_FREE(asn_DEF_SetGrp, p);
		}
		ASN_STRUCT_RESET(asn_DEF_SetGrp, &s);
	}
	/* SetTail: root component e follows the additions in the type */
	{
		static const uint8_t a[] = {0x98, 0x08, 0x01, 0x80};
		static const uint8_t u[] = {0x98, 0x08, 0x0c, 0x00};
		SetTail_t s;
		SetTail_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.a = 1;
		s.e = 1;
		s.d = calloc(1, sizeof(*s.d));
		*s.d = 2;
		both(&asn_DEF_SetTail, &s, a, 4, u, 4, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->a == 1 && p->e == 1 && p->d && *p->d == 2);
			assert(PRES(p, SetTail, a) && PRES(p, SetTail, e)
			       && PRES(p, SetTail, d));
			ASN_STRUCT_FREE(asn_DEF_SetTail, p);
		}
		ASN_STRUCT_RESET(asn_DEF_SetTail, &s);
	}
	/* SetTags_a: canonical order y[0], x[1], z[2] gives e9, not ce */
	{
		static const uint8_t a[] = {0xe9};
		SetTags_t s;
		SetTags_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.z = 9;
		s.y = 1;
		s.x = calloc(1, sizeof(*s.x));
		*s.x = 2;
		both(&asn_DEF_SetTags, &s, a, 1, a, 1, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->z == 9 && p->y == 1 && p->x && *p->x == 2);
			assert(PRES(p, SetTags, z) && PRES(p, SetTags, y)
			       && PRES(p, SetTags, x));
			ASN_STRUCT_FREE(asn_DEF_SetTags, p);
		}
		ASN_STRUCT_RESET(asn_DEF_SetTags, &s);
	}
	/* SetCh_a, SetCh_b: untagged CHOICE sorts by its smallest tag */
	{
		static const uint8_t a[] = {0x60};
		static const uint8_t b[] = {0xb0};
		SetCh_t s;
		SetCh_t *p;
		int i;
		memset(&s, 0, sizeof(s));
		s.n = 6;
		s.u.present = u_PR_q;
		both(&asn_DEF_SetCh, &s, a, 1, a, 1, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->n == 6 && p->u.present == u_PR_q);
			assert(PRES(p, SetCh, n) && PRES(p, SetCh, u));
			ASN_STRUCT_FREE(asn_DEF_SetCh, p);
		}
		s.u.present = u_PR_p;
		s.u.choice.p = 0;
		both(&asn_DEF_SetCh, &s, b, 1, b, 1, &oa, &ou);
		for(i = 0; i < 2; i++) {
			p = i ? ou : oa;
			assert(p->n == 6 && p->u.present == u_PR_p
			       && p->u.choice.p == 0);
			ASN_STRUCT_FREE(asn_DEF_SetCh, p);
		}
	}
	/* A mandatory member that is missing on encode is an error. */
	{
		SetCh_t s;
		uint8_t buf[8];
		asn_enc_rval_t er;
		memset(&s, 0, sizeof(s)); /* u.present == none */
		er = aper_encode_to_buffer(&asn_DEF_SetCh, 0, &s, buf, sizeof(buf));
		assert(er.encoded == -1);
		er = uper_encode_to_buffer(&asn_DEF_SetCh, 0, &s, buf, sizeof(buf));
		assert(er.encoded == -1);
	}
	return 0;
}
