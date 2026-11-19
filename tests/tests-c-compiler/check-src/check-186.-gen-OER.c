/*
 * OER of SET types (186-set-oer-OK). The SET type had no OER codec:
 * oer_encode() / oer_decode() called a NULL function pointer (crash) and
 * asn_encode_to_buffer() failed. Also oer_open_type_skip() returned only the
 * size of the length determinant, so an extension addition unknown to the
 * receiver was not skipped (SEQUENCE too).
 * - each value encodes to the bytes worked out from X.696 (cross-checked
 *   with asn1tools), decodes back to the same encoding, also when the input
 *   arrives one byte at a time (RC_WMORE, resumed);
 * - no proper prefix of an encoding decodes;
 * - an absent DEFAULT addition is filled in on decoding;
 * - additions from a newer sender are skipped (SET and SEQUENCE).
 * A SEQUENCE with extensions (Q3) failed to decode when its input arrived
 * in pieces (the extension bitmap's length determinant was consumed, then
 * more data was asked for and the length read again from the wrong place).
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "T1.h"
#include "T2.h"
#include "T3.h"
#include "T4.h"
#include "T6.h"
#include "T8.h"
#include "T9.h"
#include "T11.h"
#include "Q3.h"

struct vec {
    asn_TYPE_descriptor_t *td;
    const char *xer;
    const char *oer; /* hex, canonical */
};

static const struct vec vecs[] = {
    { &asn_DEF_T1, "<T1><z>5</z><m>0102</m></T1>", "000201020105" },
    { &asn_DEF_T1, "<T1><z>-1</z><a><true/></a><m></m></T1>", "80ff0001ff" },
    /* untagged CHOICE first (smallest tag [3]), DEFAULT value omitted */
    { &asn_DEF_T2, "<T2><c>7</c><ch><x>4</x></ch></T2>", "00830104" },
    { &asn_DEF_T2, "<T2><c>9</c><ch><y><true/></y></ch><b><false/></b></T2>",
      "c089ff000109" },
    { &asn_DEF_T3, "<T3><a>2</a><e1><false/></e1><e2>77</e2></T3>",
      "8001020206c0010002014d" },
    /* r2 after the second extension marker is a root component */
    { &asn_DEF_T4, "<T4><r1>1</r1><x2>5</x2><r2>3</r2></T4>",
      "c001030101020640020105" },
    /* UNIVERSAL < APPLICATION < context-specific < PRIVATE */
    { &asn_DEF_T6, "<T6><p>1</p><c>2</c><u>3</u><app><true/></app></T6>",
      "800103ff01020101" },
    { &asn_DEF_T8, "<T8><a>0</a><e1>1</e1><e8>8</e8><e9>9</e9></T8>",
      "80010003068180020101020108020109" },
    { &asn_DEF_T9,
      "<T9><inner><z>1</z><a><false/></a><m>78</m></inner>"
      "<n><a>5</a><e1><true/></e1></n><d>6</d></T9>",
      "c080000178010180010502068001ff0106" },
    { &asn_DEF_T11, "<T11><a>1</a><e1>4</e1></T11>", "800101020780020104" },
    { &asn_DEF_Q3, "<Q3><a>1</a><e1><true/></e1></Q3>", "80010102068001ff" },
    { &asn_DEF_Q3, "<Q3><a>2</a><e1><false/></e1><e2>77</e2></Q3>",
      "8001020206c0010002014d" },
};

static size_t
unhex(const char *h, unsigned char *b) {
    size_t n = 0;
    for(; h[0] && h[1]; h += 2) {
        unsigned v;
        sscanf(h, "%2x", &v);
        b[n++] = (unsigned char)v;
    }
    return n;
}

static int
count_cb(const void *buf, size_t size, void *key) {
    (void)buf;
    *(size_t *)key += size;
    return 0;
}

/* Decode buf[0..n) handing the decoder one more byte at a time. */
static void *
decode_bytewise(asn_TYPE_descriptor_t *td, const unsigned char *buf,
                size_t n) {
    void *st = 0;
    size_t off = 0, avail = 1;
    for(;;) {
        asn_dec_rval_t dr = oer_decode(0, td, &st, buf + off, avail - off);
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
check_reencode(asn_TYPE_descriptor_t *td, void *st, const unsigned char *want,
               size_t wn) {
    unsigned char got[64];
    asn_enc_rval_t er =
        asn_encode_to_buffer(0, ATS_CANONICAL_OER, td, st, got, sizeof(got));
    assert(er.encoded >= 0 && (size_t)er.encoded == wn);
    assert(memcmp(got, want, wn) == 0);
}

int
main(void) {
    for(size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const struct vec *v = &vecs[i];
        unsigned char want[64];
        size_t wn = unhex(v->oer, want);
        void *sptr = 0;
        asn_dec_rval_t dr =
            xer_decode(0, v->td, &sptr, v->xer, strlen(v->xer));
        if(dr.code != RC_OK) {
            fprintf(stderr, "XER decode of %s failed\n", v->xer);
            return 1;
        }
        unsigned char got[64];
        asn_enc_rval_t er = asn_encode_to_buffer(0, ATS_CANONICAL_OER, v->td,
                                                 sptr, got, sizeof(got));
        if(er.encoded < 0 || (size_t)er.encoded != wn
           || memcmp(got, want, wn)) {
            fprintf(stderr, "OER of %s: %zd bytes, want %s\n", v->xer,
                    er.encoded, v->oer);
            return 1;
        }
        size_t counted = 0;
        er = oer_encode(v->td, sptr, count_cb, &counted);
        assert(er.encoded == (ssize_t)wn && counted == wn);
        ASN_STRUCT_FREE(*v->td, sptr);

        void *back = 0;
        dr = oer_decode(0, v->td, &back, want, wn);
        assert(dr.code == RC_OK && dr.consumed == wn);
        check_reencode(v->td, back, want, wn);
        ASN_STRUCT_FREE(*v->td, back);

        back = decode_bytewise(v->td, want, wn);
        check_reencode(v->td, back, want, wn);
        ASN_STRUCT_FREE(*v->td, back);

        for(size_t n = 0; n < wn; n++) {
            back = 0;
            dr = oer_decode(0, v->td, &back, want, n);
            assert(dr.code != RC_OK);
            ASN_STRUCT_FREE(*v->td, back);
        }
    }

    /* An absent DEFAULT addition takes its default value. */
    {
        static const unsigned char b[] = {0x00, 0x01, 0x01};
        T11_t *t = 0;
        asn_dec_rval_t dr = oer_decode(0, &asn_DEF_T11, (void **)&t, b, 3);
        assert(dr.code == RC_OK && dr.consumed == 3);
        assert(t->a == 1 && t->e1 && *t->e1 == 3);
        check_reencode(&asn_DEF_T11, t, b, 3);
        ASN_STRUCT_FREE(asn_DEF_T11, t);
    }

    /* A newer sender with additions e3 OCTET STRING, e4 INTEGER (a, e1, e3
     * present): e3 is skipped. */
    {
        unsigned char b[16], want[16];
        size_t n = unhex("8001010204a001ff03027a7a", b);
        size_t wn = unhex("80010102068001ff", want);
        T3_t *t = 0;
        asn_dec_rval_t dr = oer_decode(0, &asn_DEF_T3, (void **)&t, b, n);
        assert(dr.code == RC_OK && dr.consumed == n);
        check_reencode(&asn_DEF_T3, t, want, wn);
        ASN_STRUCT_FREE(asn_DEF_T3, t);
        t = decode_bytewise(&asn_DEF_T3, b, n);
        check_reencode(&asn_DEF_T3, t, want, wn);
        ASN_STRUCT_FREE(asn_DEF_T3, t);
    }

    /* The same for a SEQUENCE. */
    {
        unsigned char b[16], want[16];
        size_t n = unhex("8001010205a001ff03027a7a", b);
        size_t wn = unhex("80010102068001ff", want);
        Q3_t *q = 0;
        asn_dec_rval_t dr = oer_decode(0, &asn_DEF_Q3, (void **)&q, b, n);
        assert(dr.code == RC_OK && dr.consumed == n);
        check_reencode(&asn_DEF_Q3, q, want, wn);
        ASN_STRUCT_FREE(asn_DEF_Q3, q);
        q = decode_bytewise(&asn_DEF_Q3, b, n);
        check_reencode(&asn_DEF_Q3, q, want, wn);
        ASN_STRUCT_FREE(asn_DEF_Q3, q);
    }

    printf("OK\n");
    return 0;
}
