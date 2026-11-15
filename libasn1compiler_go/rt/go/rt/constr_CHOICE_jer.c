/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_CHOICE.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 CHOICE: a JSON object with exactly one member, the key is the
 * identifier of the alternative.
 */

asn_enc_rval_t
CHOICE_encode_jer(const asn_TYPE_descriptor_t *td,
                  const asn_jer_constraints_t *constraints, const void *sptr,
                  int ilevel, enum jer_encoder_flags_e flags,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    asn_enc_rval_t tmper;
    const asn_TYPE_member_t *elm;
    const void *memb_ptr;
    unsigned present;
    int jmin = (flags & JER_F_MINIFIED);

    (void)constraints;
    if(!sptr) ASN__ENCODE_FAILED;

    present = CHOICE_variant_get_presence(td, sptr);
    if(present == 0 || present > td->elements_count) ASN__ENCODE_FAILED;
    elm = &td->elements[present - 1];
    if(!elm->type->op->jer_encoder) ASN__ENCODE_FAILED;

    if(elm->flags & ATF_POINTER) {
        memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
    }

    ASN__CALLBACK("{", 1);
    if(!jmin) ASN__TEXT_INDENT(1, ilevel + 1);
    if(jmin) {
        ASN__CALLBACK3("\"", 1, elm->name, strlen(elm->name), "\":", 2);
    } else {
        ASN__CALLBACK3("\"", 1, elm->name, strlen(elm->name), "\": ", 3);
    }
    tmper = elm->type->op->jer_encoder(
        elm->type, elm->encoding_constraints.jer_constraints, memb_ptr,
        ilevel + 1, flags, cb, app_key);
    if(tmper.encoded == -1) return tmper;
    er.encoded += tmper.encoded;
    if(!jmin) ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK("}", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

asn_dec_rval_t
CHOICE_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td,
                  const asn_jer_constraints_t *constraints, void **sptr,
                  const void *buf_ptr, size_t size) {
    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;
    asn_dec_rval_t rval = {RC_OK, 0};
    asn_dec_rval_t tmprval;
    jer_cursor_t cur;
    const asn_TYPE_member_t *elm;
    const char *key, *val;
    size_t key_size, val_size;
    size_t vs, ve, edx;
    void *st;
    void *memb_ptr;
    void **memb_ptr2;
    int ret;

    (void)constraints;
    ret = jer_value_span(buf_ptr, size, &vs, &ve);
    if(ret == 0) ASN__DECODE_STARVED;
    if(ret < 0 || jer_object_open(&cur, buf_ptr, size)) ASN__DECODE_FAILED;

    if(*sptr == 0) {
        *sptr = CALLOC(1, specs->struct_size);
        if(*sptr == 0) ASN__DECODE_FAILED;
    }
    st = *sptr;

    /* Exactly one member. */
    if(jer_object_next(&cur, &key, &key_size, &val, &val_size) != 1)
        ASN__DECODE_FAILED;
    for(edx = 0; edx < td->elements_count; edx++)
        if(jer_key_equals(key, key_size, td->elements[edx].name)) break;
    /* An unknown alternative cannot be stored, extensible or not. */
    if(edx >= td->elements_count) ASN__DECODE_FAILED;
    {
        const char *key2, *val2;
        size_t key2_size, val2_size;
        if(jer_object_next(&cur, &key2, &key2_size, &val2, &val2_size) != 0)
            ASN__DECODE_FAILED;
    }

    elm = &td->elements[edx];
    if(!elm->type->op->jer_decoder) ASN__DECODE_FAILED;

    /* Set the presence first, to be able to free it properly at any time. */
    if(CHOICE_variant_set_presence(td, st, (unsigned)(edx + 1)))
        ASN__DECODE_FAILED;

    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)st + elm->memb_offset);
    } else {
        memb_ptr = (char *)st + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }
    tmprval = elm->type->op->jer_decoder(
        opt_codec_ctx, elm->type, elm->encoding_constraints.jer_constraints,
        memb_ptr2, val, val_size);
    if(tmprval.code != RC_OK) ASN__DECODE_FAILED;

    rval.consumed = ve + jer_whitespace_span((const char *)buf_ptr + ve,
                                             size - ve);
    return rval;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
