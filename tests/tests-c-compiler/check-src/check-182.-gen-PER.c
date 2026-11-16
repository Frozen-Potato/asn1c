/*
 * The decoders' stack guard (ASN__STACK_OVERFLOW_CHECK) measures the stack
 * used since the codec context was created, from the addresses of two stack
 * locals. AddressSanitizer with detect_stack_use_after_return=1 (the default
 * of GCC 13+ and Clang 15+) puts locals on a heap "fake stack", so the
 * guard used to see a bogus distance and fail every decode with RC_FAIL.
 * Checks, for APER and BER:
 * - valid shallow input decodes with the default context (NULL) and with a
 *   caller's stack-local context;
 * - input nested 100000 levels deep is refused with RC_FAIL (no stack
 *   overflow), so the guard still works (also under ASan).
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "R.h"

#define DEEP 100000

/* APER: per level 1 presence bit + 3 bits v (v = 0); the last level has no r */
static unsigned char *
aper_wire(int depth, size_t *size) {
	size_t n = ((size_t)depth * 4 + 7) / 8;
	unsigned char *b = calloc(n, 1);
	assert(b);
	for(int i = 0; i < depth - 1; i++)
		b[(i * 4) / 8] |= 0x80 >> ((i * 4) % 8);
	*size = n;
	return b;
}

/* BER, indefinite lengths: 30 80 { 80 01 00  A1 80 { ... } 00 00 } 00 00 */
static unsigned char *
ber_wire(int depth, size_t *size) {
	size_t n = 2 + (size_t)depth * 7 + 2 * (size_t)depth;
	unsigned char *b = malloc(n), *p = b;
	assert(b);
	*p++ = 0x30; *p++ = 0x80;
	for(int i = 0; i < depth; i++) {
		*p++ = 0x80; *p++ = 0x01; *p++ = 0x00;         /* v [0] INTEGER 0 */
		if(i < depth - 1) { *p++ = 0xA1; *p++ = 0x80; } /* r [1] */
	}
	for(int i = 0; i < depth; i++) { *p++ = 0x00; *p++ = 0x00; }
	*size = (size_t)(p - b);
	assert(*size <= n);
	return b;
}

static int
depth_of(const R_t *r) {
	int d = 0;
	for(; r; r = r->r) d++;
	return d;
}

static enum asn_dec_rval_code_e
decode(int ber, int depth, int own_ctx) {
	size_t size;
	unsigned char *buf = ber ? ber_wire(depth, &size) : aper_wire(depth, &size);
	asn_codec_ctx_t ctx;   /* stack local: the guard measures from it */
	memset(&ctx, 0, sizeof(ctx));
	ctx.max_stack_size = 30000;
	R_t *r = 0;
	asn_dec_rval_t rv;
	if(ber)
		rv = ber_decode(own_ctx ? &ctx : 0, &asn_DEF_R, (void **)&r, buf, size);
	else
		rv = aper_decode_complete(own_ctx ? &ctx : 0, &asn_DEF_R, (void **)&r,
					  buf, size);
	if(rv.code == RC_OK) assert(depth_of(r) == depth);
	ASN_STRUCT_FREE(asn_DEF_R, r);
	free(buf);
	return rv.code;
}

int
main(void) {
	for(int ber = 0; ber <= 1; ber++) {
		const char *c = ber ? "BER" : "APER";
		for(int own = 0; own <= 1; own++) {
			for(int d = 1; d <= 8; d++) {
				enum asn_dec_rval_code_e rc = decode(ber, d, own);
				if(rc != RC_OK) {
					fprintf(stderr, "%s depth %d (%s ctx): code %d, want RC_OK\n",
						c, d, own ? "own" : "default", (int)rc);
					return 1;
				}
			}
			enum asn_dec_rval_code_e rc = decode(ber, DEEP, own);
			if(rc != RC_FAIL) {
				fprintf(stderr, "%s depth %d (%s ctx): code %d, want RC_FAIL\n",
					c, DEEP, own ? "own" : "default", (int)rc);
				return 1;
			}
		}
		printf("%s: shallow decodes OK, %d levels refused\n", c, DEEP);
	}
	return 0;
}
