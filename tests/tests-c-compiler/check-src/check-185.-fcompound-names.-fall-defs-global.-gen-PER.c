/*
 * -fall-defs-global (185-all-defs-global-OK): the C code did not compile
 * (asn_DEF_y undeclared: the inline descriptor was defined as asn_DEF_y_3
 * and referred to as asn_DEF_y) nor link (the top-level descriptor was
 * defined as asn_DEF_C_1, the header declares asn_DEF_C), and two inline
 * types named Member clashed (redefinition of Member_constraint).
 * - the inline descriptors are global, named asn_DEF_<name>_<index>, and
 *   are the ones the outer types use;
 * - APER of C, Q and W, worked out by hand from X.691, round trips.
 */
#undef  NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "C.h"
#include "Q.h"
#include "W.h"

/* inline descriptors, global with -fall-defs-global (W.h declares the
 * Member ones itself) */
extern asn_TYPE_descriptor_t asn_DEF_y_3;
extern asn_TYPE_descriptor_t asn_DEF_z_5;
extern asn_TYPE_descriptor_t asn_DEF_l_2;
extern asn_TYPE_descriptor_t asn_DEF_s_4;

struct vec {
    asn_TYPE_descriptor_t *td;
    const char *xer;
    const char *aper;    /* hex */
};

static const struct vec vecs[] = {
    { &asn_DEF_C, "<C><y><a><true/></a></y></C>", "60" },
    { &asn_DEF_C, "<C><z><q><false/></q></z></C>", "a0" },
    { &asn_DEF_Q, "<Q><y><a><false/></a></y><z><p></p></z></Q>", "80" },
    { &asn_DEF_W, "<W><l><INTEGER>5</INTEGER></l></W>", "0005" },
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

int
main(void) {
    assert(asn_DEF_C.elements[1].type == &asn_DEF_y_3);
    assert(asn_DEF_C.elements[2].type == &asn_DEF_z_5);
    assert(asn_DEF_W.elements[0].type == &asn_DEF_l_2);
    assert(asn_DEF_W.elements[1].type == &asn_DEF_s_4);
    assert(asn_DEF_l_2.elements[0].type == &asn_DEF_Member_3);
    assert(asn_DEF_s_4.elements[0].type == &asn_DEF_Member_5);

    for(size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const struct vec *v = &vecs[i];
        void *sptr = 0;
        asn_dec_rval_t dr = xer_decode(0, v->td, &sptr, v->xer,
                                       strlen(v->xer));
        if(dr.code != RC_OK) {
            fprintf(stderr, "XER decode of %s failed\n", v->xer);
            return 1;
        }
        unsigned char want[16], got[16];
        size_t wn = unhex(v->aper, want);
        asn_enc_rval_t er = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER,
                                                 v->td, sptr, got, sizeof(got));
        if(er.encoded < 0 || (size_t)er.encoded != wn || memcmp(got, want, wn)) {
            fprintf(stderr, "APER of %s: %zd bytes, want %s\n", v->xer,
                    er.encoded, v->aper);
            return 1;
        }
        void *back = 0;
        dr = asn_decode(0, ATS_ALIGNED_BASIC_PER, v->td, &back, got, wn);
        if(dr.code != RC_OK || dr.consumed != wn) {
            fprintf(stderr, "APER decode of %s failed\n", v->xer);
            return 1;
        }
        char xb[256];
        asn_enc_rval_t xr = asn_encode_to_buffer(0, ATS_CANONICAL_XER, v->td,
                                                 back, xb, sizeof(xb) - 1);
        assert(xr.encoded > 0);
        xb[xr.encoded] = 0;
        if(strcmp(xb, v->xer)) {
            fprintf(stderr, "%s decoded back as %s\n", v->xer, xb);
            return 1;
        }
        ASN_STRUCT_FREE(*v->td, sptr);
        ASN_STRUCT_FREE(*v->td, back);
    }

    printf("%zu values: APER OK\n", sizeof(vecs) / sizeof(vecs[0]));
    return 0;
}
