/*
 * Verify PER "normally small" values >= 64 (X.691 #11.9.3.4 and #11.6):
 *  - Seq70: the extension-addition bitmap length (70 additions);
 *  - Ch70:  the CHOICE extension alternative index (70 alternatives);
 *  - En70:  the ENUMERATED extension value (70 values).
 * Both aligned and unaligned PER. Round-trips at indices 0, 63, 64, 65, 69;
 * the encoding of index 64 is also compared with HAND-COMPUTED bytes (the
 * codec under test cannot vouch for itself); truncated long forms and a zero
 * octet count must fail to decode.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <Seq70.h>
#include <Ch70.h>
#include <En70.h>

#define	IDXLIST(X)	X(0) X(63) X(64) X(65) X(69)

static const int idx[] = { 0, 63, 64, 65, 69 };

/* ---- hand-computed encodings of index 64 (BOOLEAN TRUE payload) ----
 *
 * Seq70 { r TRUE, e64 TRUE }, 70 additions, bitmap bit 64 set.
 *   UPER: ext '1' | r '1' | nslength: '1' + 8-bit length 70 (01000110)
 *         | 70-bit bitmap (64 zeros, '1', 5 zeros)
 *         | open type: length 00000001, content 10000000
 *         = 97 bits: E8 C0 00 00 00 00 00 00 00 10 00 C0 00
 *   APER: ext '1' | r '1' | '1' | pad to octet (5 zeros) | length 0x46
 *         | 70-bit bitmap (same) | pad 2 bits to octet
 *         | open type (aligned): 0x01, 0x80
 *         = 104 bits: E0 46 00 00 00 00 00 00 00 00 80 01 80
 *
 * Ch70 c64 TRUE (one root alternative -> no root index bits).
 *   UPER: ext '1' | nsnnwn(64): '1' + 8-bit octet count 00000001 + 01000000
 *         | open type: 00000001, 10000000
 *         = 34 bits: C0 50 00 60 00
 *   APER: ext '1' | nsnnwn(64): '1', pad to octet (6 zeros),
 *         length 0x01, octet 0x40 | open type (aligned): 0x01, 0x80
 *         = 40 bits: C0 01 40 01 80
 *
 * En70 v64 (extension value index 64).
 *   UPER: ext '1' | '1' + 00000001 + 01000000 = 18 bits: C0 50 00
 *   APER: ext '1' | '1', pad (6 zeros), 0x01, 0x40 = 24 bits: C0 01 40
 */
static const uint8_t seq_u[] = { 0xE8, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0xC0, 0x00 };
static const uint8_t seq_a[] = { 0xE0, 0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x01, 0x80 };
static const uint8_t ch_u[] = { 0xC0, 0x50, 0x00, 0x60, 0x00 };
static const uint8_t ch_a[] = { 0xC0, 0x01, 0x40, 0x01, 0x80 };
static const uint8_t en_u[] = { 0xC0, 0x50, 0x00 };
static const uint8_t en_a[] = { 0xC0, 0x01, 0x40 };

static asn_enc_rval_t
do_enc(int aligned, const asn_TYPE_descriptor_t *td, const void *p, uint8_t *buf, size_t sz) {
	return aligned ? aper_encode_to_buffer(td, 0, p, buf, sz)
		       : uper_encode_to_buffer(td, 0, p, buf, sz);
}

static asn_dec_rval_t
do_dec(int aligned, const asn_TYPE_descriptor_t *td, void **p, const uint8_t *buf, size_t sz) {
	asn_codec_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	return aligned ? aper_decode(&ctx, td, p, buf, sz, 0, 0)
		       : uper_decode(&ctx, td, p, buf, sz, 0, 0);
}

/* The decode of buf[0..sz) must fail, cleanly. */
static void
must_fail(int aligned, const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t sz) {
	void *p = 0;
	asn_dec_rval_t rv = do_dec(aligned, td, &p, buf, sz);
	assert(rv.code != RC_OK);
	ASN_STRUCT_FREE(*td, p);
}

#define	EXPECT_BYTES(aligned, td, ptr, exp, nbits) do {			\
	uint8_t b_[64];							\
	asn_enc_rval_t er_;						\
	memset(b_, 0xAA, sizeof(b_));					\
	er_ = do_enc(aligned, td, ptr, b_, sizeof(b_));			\
	assert(er_.encoded == (nbits));					\
	assert(memcmp(b_, exp, sizeof(exp)) == 0);			\
	/* and the hand-computed bytes decode back */			\
	{ void *q_ = 0; asn_dec_rval_t rv_ = do_dec(aligned, td, &q_, exp, sizeof(exp)); \
	  assert(rv_.code == RC_OK); assert(q_); ASN_STRUCT_FREE(*td, q_); } \
} while(0)

/* ---------------- Seq70 ---------------- */

static void
set_seq(Seq70_t *t, BOOLEAN_t *tr, int k) {
	memset(t, 0, sizeof(*t));
	t->r = 1;
	switch(idx[k]) {
#define	CASE(i)	case i: t->e##i = tr; break;
	IDXLIST(CASE)
#undef	CASE
	default: assert(!"index");
	}
}

static void
check_seq(int aligned) {
	int k;
	for(k = 0; k < 5; k++) {
		uint8_t buf[64], buf2[64];
		BOOLEAN_t tr = 1;
		Seq70_t t, *to = 0;
		asn_enc_rval_t er, er2;
		asn_dec_rval_t rv;
		set_seq(&t, &tr, k);
		er = do_enc(aligned, &asn_DEF_Seq70, &t, buf, sizeof(buf));
		assert(er.encoded > 0);
		rv = do_dec(aligned, &asn_DEF_Seq70, (void **)&to, buf, sizeof(buf));
		assert(rv.code == RC_OK);
		assert(to && to->r);
#define	CHK(i)	if(idx[k] == i) assert(to->e##i && *to->e##i); else assert(!to->e##i);
		IDXLIST(CHK)
#undef	CHK
		er2 = do_enc(aligned, &asn_DEF_Seq70, to, buf2, sizeof(buf2));
		assert(er2.encoded == er.encoded);
		assert(memcmp(buf, buf2, (er.encoded + 7) / 8) == 0);
		ASN_STRUCT_FREE(asn_DEF_Seq70, to);
		if(idx[k] == 64) {
			if(aligned) {
				assert(er.encoded == 104);
				assert(memcmp(buf, seq_a, sizeof(seq_a)) == 0);
			} else {
				assert(er.encoded == 97);
				assert(memcmp(buf, seq_u, sizeof(seq_u)) == 0);
			}
		}
	}
	/* Hand-computed bytes, also decoded back */
	{
		BOOLEAN_t tr = 1;
		Seq70_t t;
		set_seq(&t, &tr, 2);
		if(aligned) EXPECT_BYTES(1, &asn_DEF_Seq70, &t, seq_a, 104);
		else EXPECT_BYTES(0, &asn_DEF_Seq70, &t, seq_u, 97);
	}
	/* Truncated long form: cut inside the length, bitmap and open type */
	{
		const uint8_t *full = aligned ? seq_a : seq_u;
		size_t n = aligned ? sizeof(seq_a) : sizeof(seq_u);
		size_t cut[] = { 1, 2, 3, 6, n - 3, n - 1 };
		size_t c;
		for(c = 0; c < sizeof(cut) / sizeof(cut[0]); c++)
			must_fail(aligned, &asn_DEF_Seq70, full, cut[c]);
	}
	/* Zero length after the long-form flag */
	{
		/* ext 1 | r 1 | '1' | (APER: pad) | length 0, rest zeros */
		const uint8_t z[] = { 0xE0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		must_fail(aligned, &asn_DEF_Seq70, z, sizeof(z));
	}
}

/* ---------------- Ch70 ---------------- */

static void
set_ch(Ch70_t *t, int k) {
	memset(t, 0, sizeof(*t));
	switch(idx[k]) {
#define	CASE(i)	case i: t->present = Ch70_PR_c##i; t->choice.c##i = 1; break;
	IDXLIST(CASE)
#undef	CASE
	default: assert(!"index");
	}
}

static void
check_ch(int aligned) {
	int k;
	for(k = 0; k < 5; k++) {
		uint8_t buf[64], buf2[64];
		Ch70_t t, *to = 0;
		asn_enc_rval_t er, er2;
		asn_dec_rval_t rv;
		set_ch(&t, k);
		er = do_enc(aligned, &asn_DEF_Ch70, &t, buf, sizeof(buf));
		assert(er.encoded > 0);
		rv = do_dec(aligned, &asn_DEF_Ch70, (void **)&to, buf, sizeof(buf));
		assert(rv.code == RC_OK);
		assert(to);
		switch(idx[k]) {
#define	CASE(i)	case i: assert(to->present == Ch70_PR_c##i && to->choice.c##i == 1); break;
		IDXLIST(CASE)
#undef	CASE
		}
		er2 = do_enc(aligned, &asn_DEF_Ch70, to, buf2, sizeof(buf2));
		assert(er2.encoded == er.encoded);
		assert(memcmp(buf, buf2, (er.encoded + 7) / 8) == 0);
		ASN_STRUCT_FREE(asn_DEF_Ch70, to);
	}
	{
		Ch70_t t;
		set_ch(&t, 2);
		if(aligned) EXPECT_BYTES(1, &asn_DEF_Ch70, &t, ch_a, 40);
		else EXPECT_BYTES(0, &asn_DEF_Ch70, &t, ch_u, 34);
	}
	{
		const uint8_t *full = aligned ? ch_a : ch_u;
		size_t n = aligned ? sizeof(ch_a) : sizeof(ch_u);
		size_t cut[] = { 0, 1, 2, n - 2, n - 1 };
		size_t c;
		for(c = 0; c < sizeof(cut) / sizeof(cut[0]); c++)
			must_fail(aligned, &asn_DEF_Ch70, full, cut[c]);
	}
	/* Zero octet count: ext '1' | '1' | count 0 */
	{
		const uint8_t z[] = { 0xC0, 0x00, 0x00, 0x00, 0x00 };
		must_fail(aligned, &asn_DEF_Ch70, z, sizeof(z));
	}
}

/* ---------------- En70 ---------------- */

static void
check_en(int aligned) {
	static const long vals[] = { En70_v0, En70_v63, En70_v64, En70_v65, En70_v69 };
	int k;
	for(k = 0; k < 5; k++) {
		uint8_t buf[64], buf2[64];
		En70_t t = vals[k], *to = 0;
		asn_enc_rval_t er, er2;
		asn_dec_rval_t rv;
		assert(vals[k] == idx[k] + 1);
		er = do_enc(aligned, &asn_DEF_En70, &t, buf, sizeof(buf));
		assert(er.encoded > 0);
		rv = do_dec(aligned, &asn_DEF_En70, (void **)&to, buf, sizeof(buf));
		assert(rv.code == RC_OK);
		assert(to && *to == vals[k]);
		er2 = do_enc(aligned, &asn_DEF_En70, to, buf2, sizeof(buf2));
		assert(er2.encoded == er.encoded);
		assert(memcmp(buf, buf2, (er.encoded + 7) / 8) == 0);
		ASN_STRUCT_FREE(asn_DEF_En70, to);
	}
	{
		En70_t t = En70_v64;
		if(aligned) EXPECT_BYTES(1, &asn_DEF_En70, &t, en_a, 24);
		else EXPECT_BYTES(0, &asn_DEF_En70, &t, en_u, 18);
	}
	{
		const uint8_t *full = aligned ? en_a : en_u;
		size_t n = aligned ? sizeof(en_a) : sizeof(en_u);
		size_t cut[] = { 0, 1, 2 };
		size_t c;
		for(c = 0; c < sizeof(cut) / sizeof(cut[0]) && cut[c] < n; c++)
			must_fail(aligned, &asn_DEF_En70, full, cut[c]);
	}
	{
		const uint8_t z[] = { 0xC0, 0x00, 0x00, 0x00 };
		must_fail(aligned, &asn_DEF_En70, z, sizeof(z));
	}
	/* Octet count 4 is not produced and not accepted */
	{
		/* UPER: '1' '1' 00000100 ...; APER: '1' pad 0x04 ... */
		const uint8_t zu[] = { 0xC1, 0x00, 0x00, 0x00, 0x00, 0x01 };
		const uint8_t za[] = { 0xC0, 0x04, 0x00, 0x00, 0x00, 0x01 };
		must_fail(aligned, &asn_DEF_En70, aligned ? za : zu, sizeof(zu));
	}
}

int main() {
	int aligned;
	for(aligned = 0; aligned <= 1; aligned++) {
		check_seq(aligned);
		check_ch(aligned);
		check_en(aligned);
	}
	return 0;
}
