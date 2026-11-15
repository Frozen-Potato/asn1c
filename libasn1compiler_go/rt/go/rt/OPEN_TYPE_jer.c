/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697: the value of an open type is the JER of the type the Information
 * Object Set selects (by the identifier member), with no wrapper.
 */

asn_dec_rval_t
OPEN_TYPE_jer_get(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void *sptr,
                  const asn_TYPE_member_t *elm, const void *ptr, size_t size) {
    asn_type_selector_result_t selected;
    const asn_CHOICE_specifics_t *cspecs;
    const asn_TYPE_member_t *ielm;
    asn_dec_rval_t rv;
    void *memb_ptr;     /* Pointer to the member */
    void **memb_ptr2;   /* Pointer to that pointer */
    void *inner_ptr;
    void **inner_ptr2;

    if(!(elm->flags & ATF_OPEN_TYPE) || !elm->type_selector) {
        ASN_DEBUG("Type selector is not defined for Open Type %s->%s->%s",
                  td->name, elm->name, elm->type->name);
        ASN__DECODE_FAILED;
    }

    /* The identifier member must have been decoded: unknown means failure. */
    selected = elm->type_selector(td, sptr);
    if(!selected.presence_index
       || selected.presence_index > elm->type->elements_count
       || !selected.type_descriptor->op->jer_decoder) {
        ASN__DECODE_FAILED;
    }
    cspecs = (const asn_CHOICE_specifics_t *)elm->type->specifics;

    /* Fetch the pointer to this member */
    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
        if(!*memb_ptr2) {
            *memb_ptr2 = CALLOC(1, cspecs->struct_size);
            if(!*memb_ptr2) ASN__DECODE_FAILED;
        }
    } else {
        memb_ptr = (char *)sptr + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }
    /* Make sure we reset the structure first before decoding */
    if(CHOICE_variant_set_presence(elm->type, *memb_ptr2, 0) != 0)
        ASN__DECODE_FAILED;

    ielm = &elm->type->elements[selected.presence_index - 1];
    if(ielm->flags & ATF_POINTER) {
        inner_ptr2 = (void **)((char *)*memb_ptr2 + ielm->memb_offset);
    } else {
        inner_ptr = (char *)*memb_ptr2 + ielm->memb_offset;
        inner_ptr2 = &inner_ptr;
    }

    /* Presence first, to be able to free the value properly at any time. */
    if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                   selected.presence_index))
        ASN__DECODE_FAILED;

    rv = selected.type_descriptor->op->jer_decoder(
        opt_codec_ctx, selected.type_descriptor,
        ielm->encoding_constraints.jer_constraints, inner_ptr2, ptr, size);
    if(rv.code != RC_OK) ASN__DECODE_FAILED;
    return rv;
}

asn_enc_rval_t
OPEN_TYPE_encode_jer(const asn_TYPE_descriptor_t *td,
                     const asn_jer_constraints_t *constraints,
                     const void *sptr, int ilevel,
                     enum jer_encoder_flags_e flags,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_member_t *ielm;
    const void *inner;
    unsigned present;

    (void)constraints;
    if(!sptr) ASN__ENCODE_FAILED;

    present = CHOICE_variant_get_presence(td, sptr);
    if(present == 0 || present > td->elements_count) ASN__ENCODE_FAILED;
    ielm = &td->elements[present - 1];
    if(!ielm->type->op->jer_encoder) ASN__ENCODE_FAILED;

    if(ielm->flags & ATF_POINTER) {
        inner = *(const void *const *)((const char *)sptr + ielm->memb_offset);
        if(!inner) ASN__ENCODE_FAILED;
    } else {
        inner = (const void *)((const char *)sptr + ielm->memb_offset);
    }

    /* Just the value, unwrapped. */
    return ielm->type->op->jer_encoder(
        ielm->type, ielm->encoding_constraints.jer_constraints, inner, ilevel,
        flags, cb, app_key);
}

asn_enc_rval_t
OPEN_TYPE_jer_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                  const asn_TYPE_member_t *elm, int ilevel,
                  enum jer_encoder_flags_e flags,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    const void *memb_ptr;

    if(!(elm->flags & ATF_OPEN_TYPE)) ASN__ENCODE_FAILED;

    if(elm->flags & ATF_POINTER) {
        memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
    }

    /* The stored value must be the one the identifier selects. */
    if(elm->type_selector) {
        asn_type_selector_result_t selected = elm->type_selector(td, sptr);
        if(!selected.presence_index
           || selected.presence_index
                  != CHOICE_variant_get_presence(elm->type, memb_ptr))
            ASN__ENCODE_FAILED;
    }

    return OPEN_TYPE_encode_jer(elm->type, elm->encoding_constraints.jer_constraints,
                                memb_ptr, ilevel, flags, cb, app_key);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
