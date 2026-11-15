/*
 * Float-narrowed REAL (it is held in a C float) as a named type, as an inline
 * member of a SEQUENCE, an OPTIONAL member, a CHOICE alternative and as the
 * element of a SEQUENCE OF.  Every codec must encode the float exactly as it
 * encodes the double holding the same value, and decode back the same float.
 * The expected encodings are built by hand from the encoding of a plain
 * double REAL, so they do not depend on how the member is stored.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include <REAL.h>
#include <Fl.h>
#include <N.h>
#include <M.h>
#include <O.h>
#include <C.h>
#include <L.h>
#include <LF.h>
#include <M2.h>

enum { S_Fl, S_N, S_M, S_O, S_C, S_L, S_LF, S_COUNT };
enum { E_UPER, E_APER, E_DER, E_XER };

static const asn_TYPE_descriptor_t *tds[S_COUNT] = {
	&asn_DEF_Fl, &asn_DEF_N, &asn_DEF_M, &asn_DEF_O,
	&asn_DEF_C, &asn_DEF_L, &asn_DEF_LF
};
static const char *names[S_COUNT] = {"Fl", "N", "M", "O", "C", "L", "LF"};

typedef struct { uint8_t b[128]; size_t n; } bits_t;

static int to_buf(const void *data, size_t size, void *key) {
	char *dst = key;
	size_t at = strlen(dst);
	if(at + size >= 255) return -1;
	memcpy(dst + at, data, size);
	dst[at + size] = 0;
	return 0;
}

/* Canonical XER into a zero-terminated buffer of 256 bytes */
static void xer_to_buf(const asn_TYPE_descriptor_t *td, const void *s, char *out) {
	asn_enc_rval_t er;
	out[0] = 0;
	er = xer_encode(td, s, XER_F_CANONICAL, to_buf, out);
	assert(er.encoded > 0);
}

static void put_bit(bits_t *x, int bit) {
	if(bit) x->b[x->n >> 3] |= 0x80 >> (x->n & 7);
	x->n++;
}
static void put_byte(bits_t *x, int v) {
	int i;
	for(i = 7; i >= 0; i--) put_bit(x, (v >> i) & 1);
}
static void align(bits_t *x) { x->n = (x->n + 7) & ~(size_t)7; }

/* The DER encoding of the double REAL: 09 len content */
static size_t real_der(double d, uint8_t *out) {
	REAL_t r;
	asn_enc_rval_t er;
	memset(&r, 0, sizeof(r));
	assert(asn_double2REAL(&r, d) == 0);
	er = der_encode_to_buffer(&asn_DEF_REAL, &r, out, 64);
	assert(er.encoded >= 2 && out[0] == 0x09 && out[1] < 0x80);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &r);
	return er.encoded;
}

static void put_real_per(bits_t *x, int aper, double d) {
	uint8_t der[64];
	size_t n = real_der(d, der), i;
	if(aper) align(x);
	for(i = 1; i < n; i++) put_byte(x, der[i]);
}

/* The expected PER encoding; returns the number of bits */
static size_t expect_per(int shape, int aper, double d, bits_t *x) {
	memset(x, 0, sizeof(*x));
	switch(shape) {
	case S_Fl:
		put_real_per(x, aper, d);
		break;
	case S_N:
	case S_M:
		put_bit(x, 1);	/* a */
		put_real_per(x, aper, d);
		break;
	case S_O:
		put_bit(x, 1);	/* r is present */
		put_bit(x, 1);	/* a */
		put_real_per(x, aper, d);
		break;
	case S_C:
		put_bit(x, 1);	/* the choice index: r */
		put_real_per(x, aper, d);
		break;
	case S_L:
	case S_LF:
		if(aper) align(x);
		put_byte(x, 2);	/* two elements */
		put_real_per(x, aper, d);
		put_real_per(x, aper, d);
		break;
	}
	return x->n;
}

static size_t put_tlv(uint8_t *out, int tag, const uint8_t *c, size_t n) {
	out[0] = tag;
	out[1] = n;
	memcpy(out + 2, c, n);
	return n + 2;
}

static size_t expect_der(int shape, double d, uint8_t *out) {
	uint8_t der[64], in[64];
	size_t n = real_der(d, der), m = 0;
	size_t cn = n - 2;
	switch(shape) {
	case S_Fl:
		memcpy(out, der, n);
		return n;
	case S_N:
	case S_M:
	case S_O:
		m += put_tlv(in + m, 0x80, (const uint8_t *)"\xff", 1);
		m += put_tlv(in + m, 0x81, der + 2, cn);
		return put_tlv(out, 0x30, in, m);
	case S_C:
		return put_tlv(out, 0x81, der + 2, cn);
	case S_L:
	case S_LF:
		memcpy(in, der, n);
		memcpy(in + n, der, n);
		return put_tlv(out, 0x30, in, 2 * n);
	}
	return 0;
}

/* The expected canonical XER */
static void expect_xer(int shape, double d, char *out, size_t sz) {
	REAL_t r;
	char body[128];
	size_t i, j = 0;
	char tmp[256];

	memset(&r, 0, sizeof(r));
	assert(asn_double2REAL(&r, d) == 0);
	xer_to_buf(&asn_DEF_REAL, &r, tmp);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &r);
	/* <REAL>body</REAL> */
	for(i = 6; strncmp(tmp + i, "</REAL>", 7); i++) body[j++] = tmp[i];
	body[j] = 0;
	switch(shape) {
	case S_Fl: snprintf(out, sz, "<Fl>%s</Fl>", body); break;
	case S_N: snprintf(out, sz, "<N><a><true/></a><f>%s</f></N>", body); break;
	case S_M: snprintf(out, sz, "<M><a><true/></a><r>%s</r></M>", body); break;
	case S_O: snprintf(out, sz, "<O><a><true/></a><r>%s</r></O>", body); break;
	case S_C: snprintf(out, sz, "<C><r>%s</r></C>", body); break;
	case S_L:
		snprintf(out, sz, "<L><REAL>%s</REAL><REAL>%s</REAL></L>", body, body);
		break;
	case S_LF:
		snprintf(out, sz, "<LF><Fl>%s</Fl><Fl>%s</Fl></LF>", body, body);
		break;
	}
}

static void *build(int shape, float v) {
	switch(shape) {
	case S_Fl: { Fl_t *p = calloc(1, sizeof(*p)); *p = v; return p; }
	case S_N: { N_t *p = calloc(1, sizeof(*p)); p->a = 1; p->f = v; return p; }
	case S_M: { M_t *p = calloc(1, sizeof(*p)); p->a = 1; p->r = v; return p; }
	case S_O: {
		O_t *p = calloc(1, sizeof(*p));
		p->a = 1;
		p->r = calloc(1, sizeof(*p->r));
		*p->r = v;
		return p;
	}
	case S_C: {
		C_t *p = calloc(1, sizeof(*p));
		p->present = C_PR_r;
		p->choice.r = v;
		return p;
	}
	case S_L: {
		L_t *p = calloc(1, sizeof(*p));
		int i;
		for(i = 0; i < 2; i++) {
			float *e = calloc(1, sizeof(*e));
			*e = v;
			asn_sequence_add(&p->list, e);
		}
		return p;
	}
	default: {
		LF_t *p = calloc(1, sizeof(*p));
		int i;
		for(i = 0; i < 2; i++) {
			Fl_t *e = calloc(1, sizeof(*e));
			*e = v;
			asn_sequence_add(&p->list, e);
		}
		return p;
	}
	}
}

/* Check the decoded structure holds the (two) values v */
static void same(int shape, void *s, float v) {
	float got[2] = {0, 0};
	int n = 1, i;
	switch(shape) {
	case S_Fl: got[0] = *(Fl_t *)s; break;
	case S_N: assert(((N_t *)s)->a); got[0] = ((N_t *)s)->f; break;
	case S_M: assert(((M_t *)s)->a); got[0] = ((M_t *)s)->r; break;
	case S_O:
		assert(((O_t *)s)->a && ((O_t *)s)->r);
		got[0] = *((O_t *)s)->r;
		break;
	case S_C:
		assert(((C_t *)s)->present == C_PR_r);
		got[0] = ((C_t *)s)->choice.r;
		break;
	case S_L:
		assert(((L_t *)s)->list.count == 2);
		got[0] = *((L_t *)s)->list.array[0];
		got[1] = *((L_t *)s)->list.array[1];
		n = 2;
		break;
	case S_LF:
		assert(((LF_t *)s)->list.count == 2);
		got[0] = *((LF_t *)s)->list.array[0];
		got[1] = *((LF_t *)s)->list.array[1];
		n = 2;
		break;
	}
	for(i = 0; i < n; i++) {
		if(isinf(v)) assert(isinf(got[i]) && (got[i] > 0) == (v > 0));
		else assert(got[i] == v);
	}
}

static void one(int shape, float v) {
	const asn_TYPE_descriptor_t *td = tds[shape];
	double d = (double)v;
	uint8_t buf[128], exp[128];
	char xer[256], xexp[256];
	bits_t x;
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	void *s = build(shape, v), *back;
	int mode;
	size_t n;

	memset(&ctx, 0, sizeof(ctx));

	fprintf(stderr, "%s %.9g\n", names[shape], d);
	assert(asn_check_constraints(td, s, 0, 0) == 0);

	for(mode = E_UPER; mode <= E_XER; mode++) {
		back = 0;
		memset(buf, 0, sizeof(buf));
		switch(mode) {
		case E_UPER:
		case E_APER:
			n = expect_per(shape, mode == E_APER, d, &x);
			er = mode == E_APER
			     ? aper_encode_to_buffer(td, 0, s, buf, sizeof(buf))
			     : uper_encode_to_buffer(td, 0, s, buf, sizeof(buf));
			assert(er.encoded == (ssize_t)n);
			assert(memcmp(buf, x.b, (n + 7) / 8) == 0);
			rv = mode == E_APER
			     ? aper_decode(&ctx, td, &back, buf, sizeof(buf), 0, 0)
			     : uper_decode(&ctx, td, &back, buf, sizeof(buf), 0, 0);
			break;
		case E_DER:
			n = expect_der(shape, d, exp);
			er = der_encode_to_buffer(td, s, buf, sizeof(buf));
			assert(er.encoded == (ssize_t)n);
			assert(memcmp(buf, exp, n) == 0);
			rv = ber_decode(&ctx, td, &back, buf, n);
			break;
		default:
			expect_xer(shape, d, xexp, sizeof(xexp));
			xer_to_buf(td, s, xer);
			if(strcmp(xer, xexp)) {
				fprintf(stderr, "XER: %s\nexp: %s\n", xer, xexp);
				assert(!"XER differs");
			}
			rv = xer_decode(&ctx, td, &back, xer, strlen(xer));
			break;
		}
		assert(rv.code == RC_OK && back);
		same(shape, back, v);
		assert(asn_check_constraints(td, back, 0, 0) == 0);
		ASN_STRUCT_FREE(*td, back);
	}
	ASN_STRUCT_FREE(*td, s);
}

/* A plain REAL member is a double, or a REAL_t with -fwide-types */
static void set_dbl(double *p, double v) { *p = v; }
static void set_real(REAL_t *p, double v) { assert(asn_double2REAL(p, v) == 0); }
static double get_dbl(const double *p) { return *p; }
static double get_real(const REAL_t *p) {
	double d = 0;
	assert(asn_REAL2double(p, &d) == 0);
	return d;
}
#define SET_R(x, v) _Generic((x), double: set_dbl, REAL_t: set_real)(&(x), (v))
#define GET_R(x) _Generic((x), double: get_dbl, REAL_t: get_real)(&(x))

/* A double REAL member is not changed: 1.5 is 03 80 ff 03 */
static void double_member(void) {
	M2_t m, *b = 0;
	uint8_t buf[16];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	static const uint8_t want[] = {0x80, 0x03, 0x80, 0xff, 0x03};

	memset(&ctx, 0, sizeof(ctx));
	memset(&m, 0, sizeof(m));
	m.a = 1;
	SET_R(m.r, 1.5);
	memset(buf, 0, sizeof(buf));
	er = aper_encode_to_buffer(&asn_DEF_M2, 0, &m, buf, sizeof(buf));
	assert(er.encoded == 40 && memcmp(buf, want, 5) == 0);
	rv = aper_decode(&ctx, &asn_DEF_M2, (void **)&b, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && b && GET_R(b->r) == 1.5);
	ASN_STRUCT_FREE(asn_DEF_M2, b);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_M2, &m);
}

int main() {
	static const float vals[] = {1.5f, -2.25f, 0.1f, 0.0f, 0};
	int shape, i;

	for(shape = 0; shape < S_COUNT; shape++) {
		for(i = 0; i < 4; i++) one(shape, vals[i]);
		one(shape, INFINITY);
	}
	double_member();
	return 0;
}
