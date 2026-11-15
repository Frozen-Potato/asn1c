/*
 * JER of the remaining leaf types inside constructed types (REAL with its
 * special values, the character strings, the time types, OBJECT IDENTIFIER,
 * RELATIVE-OID, NULL, ENUMERATED with DEFAULT, OCTET STRING, BIT STRING,
 * an extension group), checked against fixed vectors: each JER input
 * decodes, re-encodes to the expected minified JER and to the expected
 * aligned PER, and that PER decodes back to the same value. The PER bytes
 * agree with an independent ASN.1 implementation wherever it supports the
 * construct. Also: inputs that must not decode, inputs that decode but
 * violate a constraint, and the padding bits of a BIT STRING.
 */
#undef    NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <asn_application.h>
#include <Leaves.h>
#include <Alt.h>
#include <Lists.h>
#include <Fl.h>
#include <B12.h>

static void
expect(const asn_TYPE_descriptor_t *td, const void *st, int ats,
       const char *expected, size_t len) {
    asn_encode_to_new_buffer_result_t er
        = asn_encode_to_new_buffer(0, ats, td, st);
    if(!er.buffer || er.result.encoded != (ssize_t)len
       || memcmp(er.buffer, expected, len)) {
        fprintf(stderr, "%s: encoding %d differs from the expected one\n",
            td->name, ats);
        assert(0);
    }
    free(er.buffer);
}

/*
 * A zeroed codec context turns off the decoders' stack-depth guard, which
 * measures the distance between stack frames: under AddressSanitizer with
 * detect_stack_use_after_return (the default in recent compilers) the frames
 * live on a separate fake stack, so the guard would fail valid inputs.
 */
static asn_codec_ctx_t no_guard;

static size_t
unhex(const char *hex, char *out) {
    size_t n = 0;
    unsigned int b;
    for(; *hex; hex += 2) {
        assert(sscanf(hex, "%2x", &b) == 1);
        out[n++] = (char)b;
    }
    return n;
}

/*
 * The JER decodes; it re-encodes to `minified` (JER) and to `aper` (hex);
 * the aligned PER and the pretty JER both decode back to `minified`.
 */
static void
vector(const asn_TYPE_descriptor_t *td, const char *jer, const char *minified,
       const char *aper) {
    char bin[512];
    size_t blen = unhex(aper, bin);
    void *st = 0, *st2 = 0, *st3 = 0;
    asn_encode_to_new_buffer_result_t er;
    asn_dec_rval_t dr = asn_decode(&no_guard, ATS_JER, td, &st, jer, strlen(jer));
    if(dr.code != RC_OK) {
        fprintf(stderr, "%s: decode of %s failed\n", td->name, jer);
        assert(0);
    }
    assert(asn_check_constraints(td, st, 0, 0) == 0);
    expect(td, st, ATS_JER_MINIFIED, minified, strlen(minified));
    expect(td, st, ATS_ALIGNED_BASIC_PER, bin, blen);

    dr = asn_decode(&no_guard, ATS_ALIGNED_BASIC_PER, td, &st2, bin, blen);
    assert(dr.code == RC_OK && dr.consumed == blen);
    expect(td, st2, ATS_JER_MINIFIED, minified, strlen(minified));

    er = asn_encode_to_new_buffer(0, ATS_JER, td, st);
    assert(er.buffer);
    dr = asn_decode(&no_guard, ATS_JER, td, &st3, er.buffer, er.result.encoded);
    assert(dr.code == RC_OK);
    expect(td, st3, ATS_JER_MINIFIED, minified, strlen(minified));
    free(er.buffer);

    ASN_STRUCT_FREE(*td, st);
    ASN_STRUCT_FREE(*td, st2);
    ASN_STRUCT_FREE(*td, st3);
}

/* Does not decode, or decodes only a prefix (trailing input). */
static void
must_fail(const asn_TYPE_descriptor_t *td, const char *jer) {
    void *st = 0;
    asn_dec_rval_t dr = asn_decode(&no_guard, ATS_JER, td, &st, jer, strlen(jer));
    if(dr.code == RC_OK && dr.consumed == strlen(jer)) {
        fprintf(stderr, "%s: %s must not decode\n", td->name, jer);
        assert(0);
    }
    ASN_STRUCT_FREE(*td, st);
}

/* Decodes, but asn_check_constraints() rejects the value. */
static void
must_violate(const asn_TYPE_descriptor_t *td, const char *jer) {
    char errbuf[128];
    size_t errlen = sizeof(errbuf);
    void *st = 0;
    asn_dec_rval_t dr = asn_decode(&no_guard, ATS_JER, td, &st, jer, strlen(jer));
    if(dr.code != RC_OK) {
        fprintf(stderr, "%s: decode of %s failed\n", td->name, jer);
        assert(0);
    }
    if(asn_check_constraints(td, st, errbuf, &errlen) == 0) {
        fprintf(stderr, "%s: %s must violate a constraint\n", td->name, jer);
        assert(0);
    }
    ASN_STRUCT_FREE(*td, st);
}

/*
 * The bits after the last value bit of a BIT STRING are written as 0,
 * whatever the buffer holds there (the PER and XER encoders ignore them too).
 */
static void
padding(void) {
    static const char jer[] = "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\","
        "\"bs\":{\"value\":\"A0\",\"length\":3}}";
    Leaves_t *l = 0;
    B12_t *b = 0;
    asn_dec_rval_t dr = asn_decode(&no_guard, ATS_JER, &asn_DEF_Leaves, (void **)&l,
                                   jer, strlen(jer));
    assert(dr.code == RC_OK && l->bs);
    l->bs->buf[0] = 0xbf;    /* value bits 101, padding bits 11111 */
    expect(&asn_DEF_Leaves, l, ATS_JER_MINIFIED,
           "{\"r\":1.0,\"u8\":\"q\",\"ia\":\"b\","
           "\"bs\":{\"value\":\"A0\",\"length\":3}}",
           strlen("{\"r\":1.0,\"u8\":\"q\",\"ia\":\"b\","
                  "\"bs\":{\"value\":\"A0\",\"length\":3}}"));
    ASN_STRUCT_FREE(asn_DEF_Leaves, l);

    dr = asn_decode(&no_guard, ATS_JER, &asn_DEF_B12, (void **)&b, "\"ABC0\"", 6);
    assert(dr.code == RC_OK);
    b->buf[1] = 0xcf;    /* value bits 1100, padding bits 1111 */
    expect(&asn_DEF_B12, b, ATS_JER_MINIFIED, "\"ABC0\"", 6);
    ASN_STRUCT_FREE(asn_DEF_B12, b);
}

int main(void) {
    vector(&asn_DEF_Leaves,
        "{\"r\":1.5,\"u8\":\"h\\u00e9llo\",\"ia\":\"abc\"}",
        "{\"r\":1.5,\"u8\":\"h\303\251llo\",\"ia\":\"abc\"}",
        "00000380ff030668c3a96c6c6f30616263");
    vector(&asn_DEF_Leaves,
        "{\"r\":0,\"u8\":\"\",\"ia\":\"\"}",
        "{\"r\":0.0,\"u8\":\"\",\"ia\":\"\"}",
        "0000000000");
    vector(&asn_DEF_Leaves,
        "{\"r\":-2.25,\"u8\":\"x\",\"ia\":\"a\",\"pr\":\"Ab 1\",\"vis\":"
        "\"v~\",\"bmp\":\"\\u00e9\\u4e2d\",\"uni\":\"\\ud83d\\ude00z\","
        "\"gt\":\"20261115123000Z\",\"ut\":\"261115123000Z\",\"oid\":\"1.3."
        "6.1\",\"roid\":\"5.6\",\"nul\":null,\"en\":\"c\",\"os\":\"00FF"
        "\",\"bs\":{\"value\":\"A0\",\"length\":3},\"nb\":{\"value\":\"90"
        "\",\"length\":4}}",
        "{\"r\":-2.25,\"u8\":\"x\",\"ia\":\"a\",\"pr\":\"Ab 1\",\"vis\":"
        "\"v~\",\"bmp\":\"\303\251\344\270\255\",\"uni\":\"\360\237\230"
        "\200z\",\"gt\":\"20261115123000Z\",\"ut\":\"261115123000Z\",\"oid"
        "\":\"1.3.6.1\",\"roid\":\"5.6\",\"nul\":null,\"en\":\"c\",\"os"
        "\":\"00FF\",\"bs\":{\"value\":\"A0\",\"length\":3},\"nb\":{\"value"
        "\":\"90\",\"length\":4}}",
        "6ffe03c0fe0901781061044162203102767e0200e94e2d020001f6000000007a0f"
        "32303236313131353132333030305a0d3236313131353132333030305a032b0601"
        "020506800200ff03a00490");
    vector(&asn_DEF_Leaves,
        "{\"r\":1e300,\"u8\":\"q\",\"ia\":\"b\",\"en\":\"b\"}",
        "{\"r\":1e+300,\"u8\":\"q\",\"ia\":\"b\"}",
        "00000a8103b205f90f22001d6701711062");
    vector(&asn_DEF_Leaves,
        "{\"r\":\"INF\",\"u8\":\"q\",\"ia\":\"b\"}",
        "{\"r\":\"INF\",\"u8\":\"q\",\"ia\":\"b\"}",
        "0000014001711062");
    vector(&asn_DEF_Leaves,
        "{\"r\":\"-INF\",\"u8\":\"q\",\"ia\":\"b\"}",
        "{\"r\":\"-INF\",\"u8\":\"q\",\"ia\":\"b\"}",
        "0000014101711062");
    vector(&asn_DEF_Leaves,
        "{\"r\":\"NaN\",\"u8\":\"q\",\"ia\":\"b\"}",
        "{\"r\":\"NaN\",\"u8\":\"q\",\"ia\":\"b\"}",
        "0000014201711062");
    vector(&asn_DEF_Leaves,
        "{\"r\":\"-0\",\"u8\":\"q\",\"ia\":\"b\"}",
        "{\"r\":\"-0\",\"u8\":\"q\",\"ia\":\"b\"}",
        "0000014301711062");
    vector(&asn_DEF_Leaves,
        "{\"r\":0.1,\"u8\":\"q\",\"ia\":\"b\",\"g1\":3.5,\"g2\":\"g\"}",
        "{\"r\":0.1,\"u8\":\"q\",\"ia\":\"b\",\"g1\":3.5,\"g2\":\"g\"}",
        "80000980c90ccccccccccccd01711062030007c00380ff070167");
    vector(&asn_DEF_Leaves,
        "{\"r\":100,\"u8\":\"q\",\"ia\":\"b\",\"z\":7}",
        "{\"r\":100.0,\"u8\":\"q\",\"ia\":\"b\",\"z\":7}",
        "80000380021901711062028001e0");
    vector(&asn_DEF_Leaves,
        "{\"z\":7,\"ia\":\"b\",\"u8\":\"q\",\"r\":100}",
        "{\"r\":100.0,\"u8\":\"q\",\"ia\":\"b\",\"z\":7}",
        "80000380021901711062028001e0");
    vector(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0001\",\"ia\":\"b\"}",
        "{\"r\":1.0,\"u8\":\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\",\"ia\":\"b\"}",
        "00000380000109225c2f080c0a0d09011062");
    vector(&asn_DEF_Alt,
        "{\"r\":-1e-5}",
        "{\"r\":-1e-05}",
        "0009c0bb14f8b588e368f1");
    vector(&asn_DEF_Alt,
        "{\"s\":\"\\u4e2d\\u6587\"}",
        "{\"s\":\"\344\270\255\346\226\207\"}",
        "2006e4b8ade69687");
    vector(&asn_DEF_Alt,
        "{\"t\":\"20261115123000.5Z\"}",
        "{\"t\":\"20261115123000.5Z\"}",
        "401132303236313131353132333030302e355a");
    vector(&asn_DEF_Alt,
        "{\"o\":\"2.999.1\"}",
        "{\"o\":\"2.999.1\"}",
        "6003883701");
    vector(&asn_DEF_Alt,
        "{\"b\":\"\303\251\"}",
        "{\"b\":\"\303\251\"}",
        "80030100e9");
    vector(&asn_DEF_Lists,
        "{\"reals\":[],\"strs\":[],\"alts\":[]}",
        "{\"reals\":[],\"strs\":[],\"alts\":[]}",
        "000000");
    vector(&asn_DEF_Lists,
        "{\"reals\":[1,2.5,-3,\"INF\"],\"strs\":[\"a\",\"b\"],\"alts\":[{"
        "\"r\":1},{\"s\":\"x\"},{\"b\":\"y\"}],\"times\":[\"000101000000Z"
        "\"]}",
        "{\"reals\":[1.0,2.5,-3.0,\"INF\"],\"strs\":[\"a\",\"b\"],\"alts"
        "\":[{\"r\":1.0},{\"s\":\"x\"},{\"b\":\"y\"}],\"times\":[\"00010100"
        "0000Z"
        "\"]}",
        "c0038000010380ff0503c000030140020161016203000380000120017880030100"
        "79010d3030303130313030303030305a");
    vector(&asn_DEF_Fl,
        "{\"f\":1.5,\"d\":0.1}",
        "{\"f\":1.5,\"d\":0.1}",
        "0380ff030980c90ccccccccccccd");
    vector(&asn_DEF_Fl,
        "{\"f\":16777215,\"d\":-1e-300}",
        "{\"f\":16777215.0,\"d\":-1e-300}",
        "06800000ffffff0ac1fbe7156e1fc2f8f359");

    must_fail(&asn_DEF_Leaves, "{\"r\":\"inf\",\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":\"Infinity\",\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1e400,\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":\"1.5\",\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":true,\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"\\ud83d\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"\\udc00x\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"bmp\":\"\\ud83d\\ude00\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"oid\":\"1\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"oid\":\"3.1\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"oid\":\"1..2\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"oid\":\"1.40\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"oid\":\"1.2.\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"roid\":\"\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"nul\":0}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"en\":\"d\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"os\":\"0\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"os\":\"0G\"}");
    must_fail(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"bs\":{\"value\":\"FF\",\"leng"
        "th\":9}}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"r\":2}");
    must_fail(&asn_DEF_Leaves, "{\"u8\":\"q\",\"ia\":\"b\"}");
    must_fail(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\"}x");
    must_fail(&asn_DEF_Alt, "{}");
    must_fail(&asn_DEF_Alt, "{\"r\":1,\"s\":\"x\"}");
    must_fail(&asn_DEF_Alt, "{\"zz\":1}");
    must_fail(&asn_DEF_Lists, "{\"reals\":[],\"strs\":[],\"alts\":[{}]}");
    must_fail(&asn_DEF_B12, "\"ABC\"");
    must_fail(&asn_DEF_B12, "\"ABCD\"");

    must_violate(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"\\u00e9\"}");
    must_violate(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"123456789\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"pr\":\"a!\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"num\":\"a\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"vis\":\"\\n\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"gt\":\"2026\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"gt\":\"20261315123000Z\"}");
    must_violate(&asn_DEF_Leaves,
        "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"ut\":\"26111512300Z\"}");
    must_violate(&asn_DEF_Leaves, "{\"r\":1,\"u8\":\"q\",\"ia\":\"b\",\"z\":8}");
    must_violate(&asn_DEF_Lists,
        "{\"reals\":[1,2,3,4,5],\"strs\":[],\"alts\":[]}");

    padding();
    return 0;
}
