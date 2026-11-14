/*
 * A REAL DEFAULT on a float-narrowed member: the default is held as the float
 * nearest to 0.1 (and +inf for g), an absent member decodes to it, and the
 * decoded value is recognised as the default again, so it is omitted.
 * Only the DEFAULT callbacks are exercised: the member descriptors of a float
 * member in a SEQUENCE name the generic NativeReal type (no float size), so
 * the runtime cannot yet encode or decode a float member that is not the
 * DEFAULT.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include <Z.h>

static void z_cases(int aper) {
	uint8_t buf[32];
	asn_enc_rval_t er;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	Z_t z, *zo = 0;

	memset(&ctx, 0, sizeof(ctx));
	memset(&z, 0, sizeof(z));
	z.b = 1;
	/* presence bits f g = 00, b=1: 001 -> 0x20, 3 bits */
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Z, 0, &z, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_Z, 0, &z, buf, sizeof(buf));
	assert(er.encoded == 3 && buf[0] == 0x20);
	rv = aper ? aper_decode(&ctx, &asn_DEF_Z, (void *)&zo, buf, sizeof(buf), 0, 0)
		  : uper_decode(&ctx, &asn_DEF_Z, (void *)&zo, buf, sizeof(buf), 0, 0);
	assert(rv.code == RC_OK && zo && zo->f && zo->g);
	assert(*zo->f == 0.1f);
	assert(isinf(*zo->g) && *zo->g > 0);
	/* the decoded defaults re-encode to the same bits */
	memset(buf, 0, sizeof(buf));
	er = aper ? aper_encode_to_buffer(&asn_DEF_Z, 0, zo, buf, sizeof(buf))
		  : uper_encode_to_buffer(&asn_DEF_Z, 0, zo, buf, sizeof(buf));
	assert(er.encoded == 3 && buf[0] == 0x20);
	ASN_STRUCT_FREE(asn_DEF_Z, zo);
}

int main() {
	z_cases(1);
	z_cases(0);
	return 0;
}
