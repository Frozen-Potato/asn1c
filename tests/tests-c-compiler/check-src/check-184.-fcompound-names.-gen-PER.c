/*
 * A parameterized type used from a module other than its own
 * (184-param-cross-module-OK): K184B defines ProtocolIE-Field before
 * ProtocolIE-Container and K184C instantiates the container twice. The C
 * code did not compile (asn_PER_memb_id_constr_0 undeclared): the clone made
 * for the later module missed the fixer's phases and AUTOMATIC TAGS. K184D
 * instantiates Pair inside Pairs and Alt inside Alts, both defined after
 * them in one module: those clones missed AUTOMATIC TAGS too, so the DER of
 * Holder had universal tags and Alt's alternatives were ordered by their
 * universal tags (BOOLEAN b got PER index 0).
 * - APER and DER of Message, Message2, Holder and Choices, worked out by
 *   hand from X.691 and X.690; the DER shows the module's AUTOMATIC TAGS
 *   ([0] [1] IMPLICIT, the open type [2] EXPLICIT) and APER 57 has a as
 *   alternative 0;
 * - a value outside Small (INTEGER (0..7)) is refused.
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Message.h"
#include "Message2.h"
#include "Holder.h"
#include "Choices.h"

struct vec {
    asn_TYPE_descriptor_t *td;
    const char *xer;
    const char *aper;    /* hex */
    const char *der;    /* hex */
};

#define IE(id, crit, v)                                                  \
    "<id>" #id "</id><criticality><" crit "/></criticality><value>" v   \
    "</value>"

static const struct vec vecs[] = {
    { &asn_DEF_Message,
      "<Message><protocolIEs>"
      "<Msg-IEs>" IE(1, "reject", "<Small>5</Small>") "</Msg-IEs>"
      "<Msg-IEs>" IE(2, "ignore", "<Flag><true/></Flag>") "</Msg-IEs>"
      "</protocolIEs></Message>",
      "0400010001a00002400180",
      "301ca01a300b800101810100a203020105"
      "300b800102810101a2030101ff" },
    { &asn_DEF_Message2,
      "<Message2><protocolIEs>"
      "<Msg2-IEs>" IE(1, "ignore", "<Small>3</Small>") "</Msg2-IEs>"
      "</protocolIEs></Message2>",
      "020001400160",
      "300fa00d300b800101810101a203020103" },
    { &asn_DEF_Holder,
      "<Holder><pairs><Pair><first>6</first><second>1</second></Pair>"
      "</pairs></Holder>",
      "3880",
      "300aa0083006800106810101" },
    { &asn_DEF_Choices,
      "<Choices><x><a>5</a><b><true/></b></x></Choices>",
      "57",
      "3008a0068001058101ff" },
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

static void
check_bytes(const char *what, const struct vec *v, enum asn_transfer_syntax ts,
            const void *sptr, const char *want_hex) {
    unsigned char want[64], got[64];
    size_t wn = unhex(want_hex, want);
    asn_enc_rval_t er = asn_encode_to_buffer(0, ts, v->td, sptr, got,
                                             sizeof(got));
    if(er.encoded < 0 || (size_t)er.encoded != wn || memcmp(got, want, wn)) {
        fprintf(stderr, "%s of %s: encoded %zd bytes, want %s\n", what, v->xer,
                er.encoded, want_hex);
        exit(1);
    }
    void *back = 0;
    asn_dec_rval_t dr = asn_decode(0, ts, v->td, &back, got, wn);
    if(dr.code != RC_OK || dr.consumed != wn) {
        fprintf(stderr, "%s of %s: decode code %d consumed %zu\n", what,
                v->xer, (int)dr.code, dr.consumed);
        exit(1);
    }
    char xb[512];
    asn_enc_rval_t xr = asn_encode_to_buffer(0, ATS_CANONICAL_XER, v->td,
                                             back, xb, sizeof(xb) - 1);
    assert(xr.encoded > 0);
    xb[xr.encoded] = 0;
    if(strcmp(xb, v->xer)) {
        fprintf(stderr, "%s of %s: decoded back as %s\n", what, v->xer, xb);
        exit(1);
    }
    ASN_STRUCT_FREE(*v->td, back);
}

int
main(void) {
    for(size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const struct vec *v = &vecs[i];
        void *sptr = 0;
        asn_dec_rval_t dr = xer_decode(0, v->td, &sptr, v->xer,
                                       strlen(v->xer));
        if(dr.code != RC_OK) {
            fprintf(stderr, "XER decode of %s failed\n", v->xer);
            return 1;
        }
        check_bytes("APER", v, ATS_ALIGNED_BASIC_PER, sptr, v->aper);
        check_bytes("DER", v, ATS_DER, sptr, v->der);
        ASN_STRUCT_FREE(*v->td, sptr);
    }

    /* Small is INTEGER (0..7): 8 is refused */
    Message_t *m = 0;
    asn_dec_rval_t dr = xer_decode(0, &asn_DEF_Message, (void **)&m,
                                   vecs[0].xer, strlen(vecs[0].xer));
    assert(dr.code == RC_OK);
    m->protocolIEs.list.array[0]->value.choice.Small = 8;
    char eb[64];
    asn_enc_rval_t er = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER,
                                             &asn_DEF_Message, m, eb,
                                             sizeof(eb));
    if(er.encoded >= 0) {
        fprintf(stderr, "Small value 8 was encoded\n");
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_Message, m);

    printf("%zu values: APER and DER OK\n", sizeof(vecs) / sizeof(vecs[0]));
    return 0;
}
