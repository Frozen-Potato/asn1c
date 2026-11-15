/*
 * JER of the primitive types through the generator: round trip of the
 * X.697 vectors, and the fixed-size BIT STRING constraints tables.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <asn_application.h>
#include <B12.h>
#include <BV.h>
#include <BX.h>
#include <BN.h>
#include <O2.h>
#include <I.h>
#include <E.h>
#include <Fx.h>

static void
roundtrip(const asn_TYPE_descriptor_t *td, const char *jer) {
	void *st = 0;
	asn_dec_rval_t dr;
	asn_encode_to_new_buffer_result_t er;
	void *st2 = 0;

	dr = asn_decode(0, ATS_JER, td, &st, jer, strlen(jer));
	if(dr.code != RC_OK) {
		fprintf(stderr, "%s: decode of %s failed\n", td->name, jer);
		assert(dr.code == RC_OK);
	}

	er = asn_encode_to_new_buffer(0, ATS_JER_MINIFIED, td, st);
	assert(er.buffer);
	if(er.result.encoded != (ssize_t)strlen(jer)
	   || memcmp(er.buffer, jer, strlen(jer))) {
		fprintf(stderr, "%s: expected %s, got %.*s\n", td->name, jer,
			(int)er.result.encoded, (char *)er.buffer);
		assert(0);
	}
	free(er.buffer);

	/* Pretty output decodes back to the same value. */
	er = asn_encode_to_new_buffer(0, ATS_JER, td, st);
	assert(er.buffer);
	dr = asn_decode(0, ATS_JER, td, &st2, er.buffer, er.result.encoded);
	assert(dr.code == RC_OK);
	assert(td->op->compare_struct(td, st, st2) == 0);
	free(er.buffer);

	ASN_STRUCT_FREE(*td, st);
	ASN_STRUCT_FREE(*td, st2);
}

static void
must_fail(const asn_TYPE_descriptor_t *td, const char *jer) {
	void *st = 0;
	asn_dec_rval_t dr = asn_decode(0, ATS_JER, td, &st, jer, strlen(jer));
	if(dr.code == RC_OK) {
		fprintf(stderr, "%s: %s must not decode\n", td->name, jer);
		assert(dr.code != RC_OK);
	}
	ASN_STRUCT_FREE(*td, st);
}

int main(void) {
	const asn_jer_constraints_t *c;

	roundtrip(&asn_DEF_B12, "\"ABC0\"");
	roundtrip(&asn_DEF_BV, "{\"value\":\"80\",\"length\":1}");
	roundtrip(&asn_DEF_BV, "{\"value\":\"FFFF\",\"length\":16}");
	roundtrip(&asn_DEF_BX, "{\"value\":\"FF\",\"length\":8}");
	roundtrip(&asn_DEF_BN, "{\"value\":\"90\",\"length\":4}");
	roundtrip(&asn_DEF_O2, "\"01FE\"");
	roundtrip(&asn_DEF_I, "200");
	roundtrip(&asn_DEF_E, "\"green\"");

	/* The constraints tables. */
	c = asn_DEF_Fx.elements[0].encoding_constraints.jer_constraints;
	assert(c && c->size == 12);
	c = asn_DEF_B12.encoding_constraints.jer_constraints;
	assert(c && c->size == 12);
	assert(asn_DEF_BV.encoding_constraints.jer_constraints == NULL);
	assert(asn_DEF_BX.encoding_constraints.jer_constraints == NULL);

	must_fail(&asn_DEF_B12, "{\"value\":\"ABC0\",\"length\":12}");
	must_fail(&asn_DEF_BV, "\"80\"");
	must_fail(&asn_DEF_B12, "\"ABCF\"");

	return 0;
}
