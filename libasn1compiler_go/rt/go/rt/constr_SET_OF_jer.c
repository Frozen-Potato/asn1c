/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET_OF.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <asn_SET_OF.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 SET OF (and SEQUENCE OF): a JSON array, the elements in the order
 * they are stored. The SIZE constraint is checked by asn_check_constraints().
 */

asn_enc_rval_t
SET_OF_encode_jer(const asn_TYPE_descriptor_t *td,
                  const asn_jer_constraints_t *constraints, const void *sptr,
                  int ilevel, enum jer_encoder_flags_e flags,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
    int jmin = (flags & JER_F_MINIFIED);
    int i;

    (void)constraints;
    if(!sptr || !elm || !elm->type->op->jer_encoder) ASN__ENCODE_FAILED;

    ASN__CALLBACK("[", 1);
    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper;
        void *memb_ptr = list->array[i];
        if(!memb_ptr) continue;

        if(i) ASN__CALLBACK(",", 1);
        if(!jmin) ASN__TEXT_INDENT(1, ilevel + 1);
        tmper = elm->type->op->jer_encoder(
            elm->type, elm->encoding_constraints.jer_constraints, memb_ptr,
            ilevel + 1, flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
    }
    if(list->count && !jmin) ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK("]", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

asn_dec_rval_t
SET_OF_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td,
                  const asn_jer_constraints_t *constraints, void **sptr,
                  const void *buf_ptr, size_t size) {
    const asn_SET_OF_specifics_t *specs =
        (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *element = td->elements;
    asn_dec_rval_t rval = {RC_OK, 0};
    jer_cursor_t cur;
    const char *val;
    size_t val_size, vs, ve;
    asn_anonymous_set_ *list;
    void *st;
    int ret;

    (void)constraints;
    ret = jer_value_span(buf_ptr, size, &vs, &ve);
    if(ret == 0) ASN__DECODE_STARVED;
    if(ret < 0 || jer_array_open(&cur, buf_ptr, size)) ASN__DECODE_FAILED;
    if(!element || !element->type->op->jer_decoder) ASN__DECODE_FAILED;

    if(*sptr == 0) {
        *sptr = CALLOC(1, specs->struct_size);
        if(*sptr == 0) ASN__DECODE_FAILED;
    }
    st = *sptr;
    list = _A_SET_FROM_VOID(st);

    while((ret = jer_array_next(&cur, &val, &val_size)) == 1) {
        asn_dec_rval_t tmprval;
        void *item = 0;

        tmprval = element->type->op->jer_decoder(
            opt_codec_ctx, element->type,
            element->encoding_constraints.jer_constraints, &item, val,
            val_size);
        if(tmprval.code != RC_OK) {
            if(item) ASN_STRUCT_FREE(*element->type, item);
            ASN__DECODE_FAILED;
        }
        if(ASN_SET_ADD(list, item) != 0) {
            ASN_STRUCT_FREE(*element->type, item);
            ASN__DECODE_FAILED;
        }
    }
    if(ret < 0) ASN__DECODE_FAILED;

    rval.consumed = ve + jer_whitespace_span((const char *)buf_ptr + ve,
                                             size - ve);
    return rval;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
