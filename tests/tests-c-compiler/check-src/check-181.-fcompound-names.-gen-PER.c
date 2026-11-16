/*
 * PER (APER and UPER) encoding of character strings, X.691 (02/2021) #30:
 * - APER rounds the bits per character up to 1, 2, 4, 8 or 16 (#30.5.2):
 *   NumericString uses 4 bits, IA5String (FROM("AB")) 1 bit; the encoder and
 *   decoder used 8 bits for every 8-bit string type.
 * - a character value is sent as is only if ub <= 2^b - 1 (#30.5.4), else
 *   as its index: IA5String (FROM(" ".."@")) in UPER (b = 6, '@' = 64), and
 *   always for NumericString.
 * - octet alignment in APER: a fixed-size string is aligned only if
 *   aub * b > 16 (#30.5.6), a variable-size one only if aub * b >= 16
 *   (#30.5.7); asn1c aligned every variable-size string.
 * - a size outside an extensible SIZE root keeps the permitted alphabet
 *   (#30.4).
 * - a bare PrintableString member uses the PrintableString alphabet (the
 *   runtime default constraint was NumericString's).
 * - a NumericString type without FROM() sends the character index, and an
 *   alias of an alias (N2 ::= N, P2 ::= P with P ::= PrintableString)
 *   keeps the alphabet of the type it names.
 * Each value is decoded from XER, encoded and compared with the vector,
 * decoded back and compared with the original.
 * Vectors: equal to Erlang/OTP asn1 (5.0.21) in UPER for every case and in
 * APER except S1, T2, T3 and T8 (fixed size, aub * b == 16): Erlang aligns
 * those, #30.5.6 says not to.
 */
#undef    NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <B1.h>
#include <B2.h>
#include <B3.h>
#include <B4.h>
#include <B5.h>
#include <B6.h>
#include <B7.h>
#include <B8.h>
#include <B9.h>
#include <B10.h>
#include <S1.h>
#include <S2.h>
#include <S3.h>
#include <S4.h>
#include <S5.h>
#include <S6.h>
#include <S7.h>
#include <S8.h>
#include <S9.h>
#include <S10.h>
#include <S11.h>
#include <S12.h>
#include <T1.h>
#include <T2.h>
#include <T3.h>
#include <T4.h>
#include <T5.h>
#include <T6.h>
#include <T8.h>
#include <U1.h>
#include <U2.h>
#include <U3.h>
#include <U4.h>
#include <U5.h>
#include <U6.h>
#include <V1.h>
#include <V2.h>
#include <V3.h>
#include <V4.h>
#include <V5.h>
#include <V6.h>
#include <V7.h>
#include <W1.h>
#include <W2.h>
#include <W3.h>
#include <W4.h>
#include <W5.h>
#include <X1.h>
#include <X2.h>
#include <X3.h>
#include <X4.h>
#include <X5.h>

struct vec {
    const asn_TYPE_descriptor_t *td;
    const char *xer;
    const char *aper;
    const char *uper;
};

static const struct vec vectors[] = {
    { &asn_DEF_S1, "<S1><f><true/></f><s>1234</s></S1>",
        "91a280", "91a280" },
    { &asn_DEF_S2, "<S2><f><true/></f><s>12345</s></S2>",
        "80234560", "91a2b0" },
    { &asn_DEF_S3, "<S3><f><true/></f><s>12</s></S3>",
        "a460", "a460" },
    { &asn_DEF_S3, "<S3><f><true/></f><s>123</s></S3>",
        "c468", "c468" },
    { &asn_DEF_S4, "<S4><f><true/></f><s>123</s></S4>",
        "902340", "911a00" },
    { &asn_DEF_S5, "<S5><f><true/></f><s>123</s></S5>",
        "80032340", "8191a0" },
    { &asn_DEF_S6, "<S6><f><true/></f><s>ABBA</s></S6>",
        "b6", "b6" },
    { &asn_DEF_S7, "<S7><f><true/></f><s>ABC</s></S7>",
        "8090", "8090" },
    { &asn_DEF_S8, "<S8><f><true/></f><s>0123ABCD</s></S8>",
        "800123abcd", "8091d5e680" },
    { &asn_DEF_S9, "<S9><f><true/></f><s>12</s></S9>",
        "9180", "9180" },
    { &asn_DEF_S10, "<S10><f><true/></f><s>123</s></S10>",
        "a02340", "a234" },
    { &asn_DEF_S10, "<S10><f><true/></f><s>12345</s></S10>",
        "c005234560", "c148d158" },
    { &asn_DEF_S11, "<S11><f><true/></f><s>abc</s></S11>",
        "a0616263", "a00440" },
    { &asn_DEF_S12, "<S12><f><true/></f><s>07</s></S12>",
        "c0e0", "c380" },
    { &asn_DEF_S12, "<S12><f><true/></f><s></s></S12>",
        "80", "80" },
    { &asn_DEF_T1, "<T1><f><true/></f><s>A</s></T1>",
        "a080", "c1" },
    { &asn_DEF_T2, "<T2><f><true/></f><s>AB</s></T2>",
        "a0a100", "c184" },
    { &asn_DEF_T3, "<T3><f><true/></f><s>AB</s></T3>",
        "a0a100", "c184" },
    { &asn_DEF_T4, "<T4><f><true/></f><s>ABC</s></T4>",
        "80414243", "c1850c" },
    { &asn_DEF_T5, "<T5><f><true/></f><s>AB</s></T5>",
        "c04142", "e0c2" },
    { &asn_DEF_T6, "<T6><f><true/></f><s>0A</s></T6>",
        "900a", "90a0" },
    { &asn_DEF_T8, "<T8><f><true/></f><s>A</s></T8>",
        "802080", "802080" },
    { &asn_DEF_U1, "<U1><f><true/></f><s>HELLO</s></U1>",
        "c048454c4c4f", "c3916b70" },
    { &asn_DEF_U2, "<U2><f><true/></f><s>AB</s></U2>",
        "a8", "a8" },
    { &asn_DEF_U2, "<U2><f><true/></f><s>ABA</s></U2>",
        "c00340", "c0d0" },
    { &asn_DEF_U3, "<U3><f><true/></f><s> @9</s></U3>",
        "a0204039", "a02064" },
    { &asn_DEF_U4, "<U4><f><true/></f><s>abcd</s></U4>",
        "e360", "e360" },
    { &asn_DEF_U5, "<U5><f><true/></f><s>0123456789 0123456789</s></U5>",
        "95123456789a0123456789a0", "95123456789a0123456789a0" },
    { &asn_DEF_U6, "<U6><f><true/></f><s>12345</s></U6>",
        "80123450", "891a28" },
    { &asn_DEF_B1, "<B1><f><true/></f><s>any-Printable-value'()+,./:=?Zz09 </s></B1>",
        "8022616e792d5072696e7461626c652d76616c75652728292b2c2e2f3a3d3f5a7a303920", "9161dde56d0e5a7774c38b6655bdb0eceb953a852ad62e5ee9ebfb5e983940" },
    { &asn_DEF_B2, "<B2><f><true/></f><s>0123456789 </s></B2>",
        "800b123456789a00", "85891a2b3c4d00" },
    { &asn_DEF_B3, "<B3><f><true/></f><s>Hello~</s></B3>",
        "800648656c6c6f7e", "8348cbb366ffc0" },
    { &asn_DEF_B4, "<B4><f><true/></f><s>Hello~</s></B4>",
        "800648656c6c6f7e", "8348cbb366ffc0" },
    { &asn_DEF_B5, "<B5><f><true/></f><s>Hi</s></B5>",
        "800200480069", "810024003480" },
    { &asn_DEF_B6, "<B6><f><true/></f><s>Hi</s></B6>",
        "80020000004800000069", "81000000240000003480" },
    { &asn_DEF_B7, "<B7><f><true/></f><s>Hi</s></B7>",
        "80024869", "81243480" },
    { &asn_DEF_B8, "<B8><f><true/></f><s>any-Printable-value</s></B8>",
        "8480616e792d5072696e7461626c652d76616c7565", "84b0eef2b6872d3bba61c5b32aded87675ca" },
    { &asn_DEF_B9, "<B9><f><true/></f><s>ABCDEFG</s></B9>",
        "c00741424344454647", "c1e0c287122c68e0" },
    { &asn_DEF_B10, "<B10><f><true/></f><s>ABCDEFG</s></B10>",
        "c00741424344454647", "c1e0c287122c68e0" },
    { &asn_DEF_V1, "<V1><f><true/></f><s>0 9</s></V1>",
        "800310a0", "818850" },
    { &asn_DEF_V2, "<V2><f><true/></f><s>1234</s></V2>",
        "80042345", "8211a280" },
    { &asn_DEF_V3, "<V3><f><true/></f><s>98765432109</s></V3>",
        "c00ba987654321a0", "c2ea61d950c868" },
    { &asn_DEF_V4, "<V4><f><true/></f><s><NumericString>12</NumericString><NumericString> </NumericString></s></V4>",
        "800202230100", "8101118080" },
    { &asn_DEF_V5, "<V5><f><true/></f><s><a>55</a></s></V5>",
        "800266", "809980" },
    { &asn_DEF_V5, "<V5><f><true/></f><s><b>66</b></s></V5>",
        "c00277", "c09dc0" },
    { &asn_DEF_V6, "<V6><f><true/></f><s>123</s></V6>",
        "c8d0", "c8d0" },
    { &asn_DEF_V7, "<V7><f><true/></f><s><N>7</N></s></V7>",
        "80010180", "8080c0" },
    { &asn_DEF_W1, "<W1><f><true/></f><s>1234</s></W1>",
        "80042345", "8211a280" },
    { &asn_DEF_W2, "<W2><f><true/></f><s>Ab1z</s></W2>",
        "80044162317a", "8241c4c7d0" },
    { &asn_DEF_W3, "<W3><f><true/></f><s>Ab~</s></W3>",
        "800341627e", "81c1c5f8" },
    { &asn_DEF_W4, "<W4><f><true/></f><s>Ab~</s></W4>",
        "800341627e", "81c1c5f8" },
    { &asn_DEF_W5, "<W5><f><true/></f><s>Ab</s></W5>",
        "800200410062", "810020803100" },
    { &asn_DEF_X1, "<X1><f><true/></f><s>A</s></X1>",
        "d040", "e080" },
    { &asn_DEF_X2, "<X2><f><true/></f><s>A</s></X2>",
        "c00041", "c01040" },
    { &asn_DEF_X3, "<X3><f><true/></f><s>12</s></X3>",
        "a023", "a460" },
    { &asn_DEF_X4, "<X4><f><true/></f><s>ABABABAB</s></X4>",
        "8550", "8550" },
    { &asn_DEF_X5, "<X5><f><true/></f><s>ABABABAB</s></X5>",
        "8055", "82a8" },
};

static void hex(char *dst, const uint8_t *b, size_t n) {
    size_t i;
    for(i = 0; i < n; i++) sprintf(dst + 2 * i, "%02x", b[i]);
    dst[2 * n] = 0;
}

static void check(const struct vec *v, int aligned) {
    const char *want = aligned ? v->aper : v->uper;
    asn_codec_ctx_t ctx;
    void *val = 0, *back = 0;
    uint8_t buf[256];
    char got[2 * sizeof(buf) + 1];
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t len;

    dr = xer_decode(0, v->td, &val, v->xer, strlen(v->xer));
    assert(dr.code == RC_OK);
    er = aligned
        ? aper_encode_to_buffer(v->td, 0, val, buf, sizeof(buf))
        : uper_encode_to_buffer(v->td, 0, val, buf, sizeof(buf));
    assert(er.encoded > 0);
    len = (er.encoded + 7) / 8;
    hex(got, buf, len);
    if(strcmp(got, want)) {
        fprintf(stderr, "%s %s: got %s, want %s\n", v->td->name,
            aligned ? "APER" : "UPER", got, want);
        assert(!"encoding differs");
    }
    memset(&ctx, 0, sizeof(ctx));
    dr = aligned
        ? aper_decode_complete(&ctx, v->td, &back, buf, len)
        : uper_decode_complete(&ctx, v->td, &back, buf, len);
    assert(dr.code == RC_OK);
    assert(v->td->op->compare_struct(v->td, val, back) == 0);
    ASN_STRUCT_FREE(*v->td, val);
    ASN_STRUCT_FREE(*v->td, back);
}

int main(void) {
    size_t i;
    for(i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        check(&vectors[i], 1);
        check(&vectors[i], 0);
    }
    printf("%d vectors OK\n", (int)i);
    return 0;
}
