/*
 * JER of the constructed types through the generator: SEQUENCE with an
 * extension group, SET, CHOICE, SEQUENCE OF, SET OF, open types.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <asn_application.h>
#include <S.h>
#include <N.h>
#include <T.h>
#include <G.h>
#include <C.h>
#include <L.h>
#include <SL.h>
#include <Deep.h>
#include <O.h>

static void *
decode(const asn_TYPE_descriptor_t *td, const char *jer) {
	void *st = 0;
	asn_dec_rval_t dr = asn_decode(0, ATS_JER, td, &st, jer, strlen(jer));
	if(dr.code != RC_OK) {
		fprintf(stderr, "%s: decode of %s failed\n", td->name, jer);
		assert(dr.code == RC_OK);
	}
	return st;
}

static void
expect(const asn_TYPE_descriptor_t *td, const void *st, int ats,
       const char *expected) {
	asn_encode_to_new_buffer_result_t er
		= asn_encode_to_new_buffer(0, ats, td, st);
	assert(er.buffer);
	if(er.result.encoded != (ssize_t)strlen(expected)
	   || memcmp(er.buffer, expected, strlen(expected))) {
		fprintf(stderr, "%s: expected\n%s\ngot\n%.*s\n", td->name, expected,
			(int)er.result.encoded, (char *)er.buffer);
		assert(0);
	}
	free(er.buffer);
}

/* Decode, re-encode (minified) == the vector; pretty output decodes back. */
static void
roundtrip(const asn_TYPE_descriptor_t *td, const char *jer) {
	void *st = decode(td, jer);
	void *st2 = 0;
	asn_encode_to_new_buffer_result_t er;
	asn_dec_rval_t dr;

	expect(td, st, ATS_JER_MINIFIED, jer);

	er = asn_encode_to_new_buffer(0, ATS_JER, td, st);
	assert(er.buffer);
	dr = asn_decode(0, ATS_JER, td, &st2, er.buffer, er.result.encoded);
	assert(dr.code == RC_OK);
	expect(td, st2, ATS_JER_MINIFIED, jer);
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
	void *st;
	S_t *s;
	T_t *t;
	O_t *o;

	roundtrip(&asn_DEF_S, "{\"a\":1}");
	roundtrip(&asn_DEF_S, "{\"a\":1,\"c\":0}");
	roundtrip(&asn_DEF_S, "{\"a\":-5,\"b\":true,\"c\":2,\"e\":5}");
	roundtrip(&asn_DEF_S, "{\"a\":1,\"c\":2,\"d\":false}");
	roundtrip(&asn_DEF_N, "{\"a\":1,\"b\":false}");
	roundtrip(&asn_DEF_T, "{\"x\":3}");
	roundtrip(&asn_DEF_T, "{\"x\":3,\"y\":false}");
	roundtrip(&asn_DEF_G, "{\"p\":1}");
	roundtrip(&asn_DEF_G, "{\"p\":1,\"q\":true}");
	roundtrip(&asn_DEF_C, "{\"i\":7}");
	roundtrip(&asn_DEF_C, "{\"s\":{\"z\":null}}");
	roundtrip(&asn_DEF_L, "[]");
	roundtrip(&asn_DEF_L, "[1,2,3]");
	roundtrip(&asn_DEF_SL, "[true,false]");
	roundtrip(&asn_DEF_Deep,
		"{\"l\":[{\"i\":1},{\"s\":{\"z\":null}}],"
		"\"t\":{\"x\":0,\"y\":false},\"f\":\"ABC0\"}");
	roundtrip(&asn_DEF_O, "{\"id\":1,\"value\":42}");
	roundtrip(&asn_DEF_O, "{\"id\":2,\"value\":true}");

	/* A group that is absent stays NULL; a present one is created. */
	s = decode(&asn_DEF_S, "{\"a\":1}");
	assert(s->ext1 == NULL && s->b == NULL && s->e == NULL);
	ASN_STRUCT_FREE(asn_DEF_S, s);
	s = decode(&asn_DEF_S, "{\"a\":1,\"c\":0}");
	assert(s->ext1 != NULL && s->ext1->c == 0 && s->ext1->d == NULL);
	ASN_STRUCT_FREE(asn_DEF_S, s);

	/* Members in any order; they are written in definition order. */
	s = decode(&asn_DEF_S, "{\"e\":5,\"a\":1,\"c\":2}");
	assert(s->a == 1 && s->ext1 && s->ext1->c == 2 && s->e && *s->e == 5);
	expect(&asn_DEF_S, s, ATS_JER_MINIFIED, "{\"a\":1,\"c\":2,\"e\":5}");
	ASN_STRUCT_FREE(asn_DEF_S, s);

	/* Whitespace anywhere. */
	s = decode(&asn_DEF_S, " {\n\t\"a\" : 1 ,\r\n \"c\":2 } ");
	assert(s->a == 1 && s->ext1 && s->ext1->c == 2);
	ASN_STRUCT_FREE(asn_DEF_S, s);

	/* An unknown key is skipped in an extensible type, not otherwise. */
	s = decode(&asn_DEF_S, "{\"a\":1,\"c\":2,\"zz\":[1,{\"k\":null}]}");
	assert(s->a == 1 && s->ext1 && s->ext1->c == 2);
	ASN_STRUCT_FREE(asn_DEF_S, s);
	must_fail(&asn_DEF_N, "{\"a\":1,\"b\":true,\"zz\":1}");

	/* SET: any order; an absent DEFAULT member is filled in on decoding
	 * and (being equal to its default) omitted again on encoding. */
	t = decode(&asn_DEF_T, "{\"y\":false,\"x\":3}");
	assert(t->x == 3 && t->y && *t->y == 0);
	ASN_STRUCT_FREE(asn_DEF_T, t);
	t = decode(&asn_DEF_T, "{\"x\":3}");
	assert(t->x == 3);
	assert(t->y != NULL && *t->y == 1);	/* y took its DEFAULT, TRUE */
	expect(&asn_DEF_T, t, ATS_JER_MINIFIED, "{\"x\":3}");
	ASN_STRUCT_FREE(asn_DEF_T, t);
	t = decode(&asn_DEF_T, "{\"x\":3,\"y\":true}");
	expect(&asn_DEF_T, t, ATS_JER_MINIFIED, "{\"x\":3}");
	ASN_STRUCT_FREE(asn_DEF_T, t);

	/* Failures. */
	must_fail(&asn_DEF_S, "{\"a\":1,\"d\":true}");	/* group lacks c */
	must_fail(&asn_DEF_S, "{\"a\":1,\"a\":2}");		/* duplicate */
	must_fail(&asn_DEF_S, "{\"a\":1,}");
	must_fail(&asn_DEF_S, "{\"a\":1");
	must_fail(&asn_DEF_S, "[1]");
	must_fail(&asn_DEF_N, "{\"a\":1}");			/* b is missing */
	must_fail(&asn_DEF_T, "{\"y\":true}");
	must_fail(&asn_DEF_T, "{\"x\":1,\"x\":2}");
	must_fail(&asn_DEF_G, "{\"q\":true}");
	must_fail(&asn_DEF_C, "{}");
	must_fail(&asn_DEF_C, "{\"i\":1,\"s\":{\"z\":null}}");
	must_fail(&asn_DEF_C, "{\"x\":1}");
	must_fail(&asn_DEF_L, "[1,]");
	must_fail(&asn_DEF_L, "[1,true]");
	must_fail(&asn_DEF_L, "{}");
	must_fail(&asn_DEF_O, "{\"value\":42,\"id\":1}");	/* id comes first */
	must_fail(&asn_DEF_O, "{\"id\":3,\"value\":1}");	/* unknown id */
	must_fail(&asn_DEF_O, "{\"id\":1,\"value\":true}");

	o = decode(&asn_DEF_O, "{\"id\":2,\"value\":true}");
	assert(o->id == 2 && o->value.present == O__value_PR_BOOLEAN
	       && o->value.choice.BOOLEAN == 1);
	ASN_STRUCT_FREE(asn_DEF_O, o);

	/* A truncated value asks for more data and consumes nothing. */
	{
		asn_dec_rval_t dr;
		st = 0;
		dr = asn_decode(0, ATS_JER, &asn_DEF_S, &st, "{\"a\":1", 6);
		assert(dr.code == RC_WMORE && dr.consumed == 0);
		ASN_STRUCT_FREE(asn_DEF_S, st);
	}

	/* The pretty layout. */
	st = decode(&asn_DEF_Deep,
		"{\"l\":[{\"i\":1},{\"s\":{\"z\":null}}],"
		"\"t\":{\"x\":0,\"y\":false},\"f\":\"ABC0\"}");
	expect(&asn_DEF_Deep, st, ATS_JER,
		"{\n"
		"    \"l\": [\n"
		"        {\n"
		"            \"i\": 1\n"
		"        },\n"
		"        {\n"
		"            \"s\": {\n"
		"                \"z\": null\n"
		"            }\n"
		"        }\n"
		"    ],\n"
		"    \"t\": {\n"
		"        \"x\": 0,\n"
		"        \"y\": false\n"
		"    },\n"
		"    \"f\": \"ABC0\"\n"
		"}");
	ASN_STRUCT_FREE(asn_DEF_Deep, st);

	return 0;
}
