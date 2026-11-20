/*
 * Extension addition groups [[ ]] in BER, DER and XER (191-ext-group-ber-OK).
 * asn1c encoded a group as a nested SEQUENCE, with a tag of its own: DER
 * 30 08 80 01 01 a1 03 80 01 ff for { a 1, b TRUE } where X.690 has
 * 30 06 80 01 01 81 01 ff, and XER <GS><a>1</a><ext1><b><true/></b></ext1>
 * where X.693 has <GS><a>1</a><b><true/></b></GS>; the components of a group
 * are those of the type holding it, also for automatic tagging, so b is [1],
 * not [0] of the group. A SET without AUTOMATIC TAGS with two groups was
 * refused ("has the same tag").
 * - each value (written as XER) encodes to the DER of X.690 (SEQUENCE:
 *   checked with asn1tools; SET: in the canonical order of the tags of all
 *   its components, X.690 10.3), and to the APER of X.691, which is not
 *   changed;
 * - its DER decodes back (also one byte at a time, RC_WMORE resumed), and
 *   so do the canonical XER, BER with the SET components in another order,
 *   and BER with indefinite lengths;
 * - a group with a component but without a mandatory one is refused in
 *   BER and in XER.
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "GS.h"
#include "GT.h"
#include "HS.h"
#include "HT.h"

struct vec {
    asn_TYPE_descriptor_t *td;
    const char *xer;    /* canonical */
    const char *der;    /* hex */
    const char *aper;   /* hex */
};

static const struct vec vecs[] = {
    { &asn_DEF_GS, "<GS><a>1</a></GS>", "3003800101", "0001" },
    { &asn_DEF_GS, "<GS><a>1</a><b><true/></b></GS>", "3006800101 8101ff",
      "800105000120" },
    { &asn_DEF_GS,
      "<GS><a>1</a><b><true/></b><c>2</c><s><x>5</x></s><d>3</d><e>AB</e></GS>",
      "3014800101 8101ff 820102 a303800105 840103 8501ab",
      "800105c003f0010501c00201ab" },
    { &asn_DEF_GT, "<GT><a>1</a><b><false/></b><c>3</c><d>1</d></GT>",
      "310c800101 810100 820103 830101", "" },
    { &asn_DEF_GT, "<GT><a>1</a><b><true/></b><c>1</c><d>2</d></GT>",
      "310c800101 8101ff 820101 830102", "8001038001d00180" },
    { &asn_DEF_GT, "<GT><a>1</a><d>2</d></GT>", "3106800101 830102", "" },
    { &asn_DEF_HS, "<HS><a>1</a><b><true/></b><c>7</c><d>9</d></HS>",
      "3014a003020101 a1030101ff a203020107 a303020109", "" },
    { &asn_DEF_HT,
      "<HT><s><x>2</x></s><b><true/></b><d>4</d><a>1</a></HT>",
      "3114 3003020102 a1030101ff a303020104 a503020101", "" },
    { &asn_DEF_HT, "<HT><s><x>2</x></s><a>1</a></HT>",
      "310a 3003020102 a503020101", "" },
};

static size_t
unhex(const char *h, unsigned char *b) {
    size_t n = 0;
    while(*h) {
        unsigned v;
        if(*h == ' ') { h++; continue; }
        sscanf(h, "%2x", &v);
        b[n++] = (unsigned char)v;
        h += 2;
    }
    return n;
}

/* Decode buf[0..n) handing the decoder one more byte at a time. */
static void *
decode_bytewise(asn_TYPE_descriptor_t *td, const unsigned char *buf,
                size_t n) {
    void *st = 0;
    size_t off = 0, avail = 1;
    for(;;) {
        asn_dec_rval_t dr = ber_decode(0, td, &st, buf + off, avail - off);
        off += dr.consumed;
        if(dr.code == RC_OK) break;
        assert(dr.code == RC_WMORE);
        assert(avail < n);
        avail++;
    }
    assert(off == n);
    return st;
}

static void
check_der(asn_TYPE_descriptor_t *td, void *st, const unsigned char *want,
          size_t wn) {
    unsigned char got[128];
    asn_enc_rval_t er =
        asn_encode_to_buffer(0, ATS_DER, td, st, got, sizeof(got));
    if(er.encoded < 0 || (size_t)er.encoded != wn || memcmp(got, want, wn)) {
        size_t i;
        fprintf(stderr, "%s: DER", td->name);
        for(i = 0; er.encoded > 0 && i < (size_t)er.encoded; i++)
            fprintf(stderr, " %02x", got[i]);
        fprintf(stderr, " (%zd bytes, want %zu)\n", er.encoded, wn);
        assert(!"DER");
    }
}

static void
check_xer(asn_TYPE_descriptor_t *td, void *st, const char *want) {
    char got[256];
    asn_enc_rval_t er = asn_encode_to_buffer(0, ATS_CANONICAL_XER, td, st,
                                             got, sizeof(got) - 1);
    assert(er.encoded > 0 && (size_t)er.encoded < sizeof(got));
    got[er.encoded] = 0;
    if(strcmp(got, want)) {
        fprintf(stderr, "%s: XER %s, want %s\n", td->name, got, want);
        assert(!"XER");
    }
}

static void *
from_xer(asn_TYPE_descriptor_t *td, const char *xer) {
    void *st = 0;
    asn_dec_rval_t dr = xer_decode(0, td, &st, xer, strlen(xer));
    if(dr.code != RC_OK) {
        fprintf(stderr, "XER decode of %s failed\n", xer);
        assert(!"XER decode");
    }
    return st;
}

static void
check_ber(asn_TYPE_descriptor_t *td, const char *ber_hex, const char *xer) {
    unsigned char b[128];
    size_t n = unhex(ber_hex, b);
    void *st = 0;
    asn_dec_rval_t dr = ber_decode(0, td, &st, b, n);
    assert(dr.code == RC_OK && dr.consumed == n);
    check_xer(td, st, xer);
    ASN_STRUCT_FREE(*td, st);
    st = decode_bytewise(td, b, n);
    check_xer(td, st, xer);
    ASN_STRUCT_FREE(*td, st);
}

static void
refuse_ber(asn_TYPE_descriptor_t *td, const char *ber_hex) {
    unsigned char b[128];
    size_t n = unhex(ber_hex, b);
    void *st = 0;
    asn_dec_rval_t dr = ber_decode(0, td, &st, b, n);
    assert(dr.code != RC_OK);
    ASN_STRUCT_FREE(*td, st);
}

static void
refuse_xer(asn_TYPE_descriptor_t *td, const char *xer) {
    void *st = 0;
    asn_dec_rval_t dr = xer_decode(0, td, &st, xer, strlen(xer));
    assert(dr.code != RC_OK);
    ASN_STRUCT_FREE(*td, st);
}

int
main(void) {
    for(size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const struct vec *v = &vecs[i];
        unsigned char want[128];
        size_t wn = unhex(v->der, want);
        void *st = from_xer(v->td, v->xer);
        check_der(v->td, st, want, wn);
        check_xer(v->td, st, v->xer);
        if(*v->aper) {
            unsigned char aper[128], got[128];
            size_t an = unhex(v->aper, aper);
            asn_enc_rval_t er = asn_encode_to_buffer(
                0, ATS_ALIGNED_BASIC_PER, v->td, st, got, sizeof(got));
            assert(er.encoded == (ssize_t)an && !memcmp(got, aper, an));
        }
        ASN_STRUCT_FREE(*v->td, st);

        void *back = 0;
        asn_dec_rval_t dr = ber_decode(0, v->td, &back, want, wn);
        assert(dr.code == RC_OK && dr.consumed == wn);
        check_der(v->td, back, want, wn);
        ASN_STRUCT_FREE(*v->td, back);
        back = decode_bytewise(v->td, want, wn);
        check_der(v->td, back, want, wn);
        ASN_STRUCT_FREE(*v->td, back);
    }

    /* BER: SET components in any order; indefinite lengths */
    check_ber(&asn_DEF_GT, "310c 830102 820101 800101 8101ff",
              "<GT><a>1</a><b><true/></b><c>1</c><d>2</d></GT>");
    check_ber(&asn_DEF_GS, "3080 800101 8101ff 820102 a380800105 0000 0000",
              "<GS><a>1</a><b><true/></b><c>2</c><s><x>5</x></s></GS>");
    check_ber(&asn_DEF_HT, "3180 a303020104 3080020102 0000 a503020101 0000",
              "<HT><s><x>2</x></s><d>4</d><a>1</a></HT>");

    /* a group without its mandatory component b */
    refuse_ber(&asn_DEF_GS, "3006 800101 820102");
    refuse_ber(&asn_DEF_GT, "3106 800101 820102");
    refuse_ber(&asn_DEF_HT, "310f 3003020102 a503020101 a203020105");
    refuse_xer(&asn_DEF_GS, "<GS><a>1</a><c>2</c></GS>");
    refuse_xer(&asn_DEF_HT, "<HT><a>1</a><s><x>2</x></s><c>5</c></HT>");

    printf("OK\n");
    return 0;
}
