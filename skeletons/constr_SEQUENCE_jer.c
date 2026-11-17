/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <OPEN_TYPE.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 SEQUENCE: a JSON object, the members in the order of definition,
 * the key of a member is its identifier. An absent OPTIONAL member is
 * omitted, so is a DEFAULT member that is absent or equals its default.
 * The members of an extension addition group [[ ]] are flattened into the
 * object of the SEQUENCE; the group itself has no key.
 */

/* The members of a group and the structure that holds them. */
#define JER_IS_GROUP(elm) (((elm)->flags & ATF_EXTENSION_GROUP) != 0)

static const void *
SEQUENCE__jer_memb(const void *sptr, const asn_TYPE_member_t *elm) {
    if(elm->flags & ATF_POINTER)
        return *(const void *const *)((const char *)sptr + elm->memb_offset);
    return (const void *)((const char *)sptr + elm->memb_offset);
}

/*
 * Encode the members of one structure (the SEQUENCE itself or a group).
 * *any is set when something has been written to the object.
 */
static asn_enc_rval_t
SEQUENCE__jer_members(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key, int *any) {
    asn_enc_rval_t er = {0, 0, 0};
    int jmin = (flags & JER_F_MINIFIED);
    size_t edx;

    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr = SEQUENCE__jer_memb(sptr, elm);
        asn_enc_rval_t tmper;
        const char *mname = elm->name;

        if(!memb_ptr) {
            if(JER_IS_GROUP(elm) || elm->optional || elm->default_value_set)
                continue;
            ASN__ENCODE_FAILED;	/* A mandatory member is missing */
        }

        if(JER_IS_GROUP(elm)) {
            tmper = SEQUENCE__jer_members(elm->type, memb_ptr, ilevel, flags,
                                          cb, app_key, any);
            if(tmper.encoded == -1) return tmper;
            er.encoded += tmper.encoded;
            continue;
        }

        /* Eliminate default values */
        if(elm->default_value_cmp && elm->default_value_cmp(memb_ptr) == 0)
            continue;

        if(*any) ASN__CALLBACK(",", 1);
        *any = 1;
        if(!jmin) ASN__TEXT_INDENT(1, ilevel + 1);
        if(jmin) {
            ASN__CALLBACK3("\"", 1, mname, strlen(mname), "\":", 2);
        } else {
            ASN__CALLBACK3("\"", 1, mname, strlen(mname), "\": ", 3);
        }

        if(elm->flags & ATF_OPEN_TYPE) {
            tmper = OPEN_TYPE_jer_put(td, sptr, elm, ilevel + 1, flags, cb,
                                      app_key);
        } else if(elm->type->op->jer_encoder) {
            tmper = elm->type->op->jer_encoder(
                elm->type, elm->encoding_constraints.jer_constraints,
                memb_ptr, ilevel + 1, flags, cb, app_key);
        } else {
            ASN__ENCODE_FAILED;
        }
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

asn_enc_rval_t
SEQUENCE_encode_jer(const asn_TYPE_descriptor_t *td,
                    const asn_jer_constraints_t *constraints, const void *sptr,
                    int ilevel, enum jer_encoder_flags_e flags,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    asn_enc_rval_t tmper;
    int any = 0;

    (void)constraints;
    if(!sptr) ASN__ENCODE_FAILED;

    ASN__CALLBACK("{", 1);
    tmper = SEQUENCE__jer_members(td, sptr, ilevel, flags, cb, app_key, &any);
    if(tmper.encoded == -1) return tmper;
    er.encoded += tmper.encoded;
    if(any && !(flags & JER_F_MINIFIED)) ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK("}", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}


/*
 * Where the bookkeeping of the decoder keeps "member decoded": one byte per
 * member of the SEQUENCE, then one per member of each group, in order.
 */
static size_t
SEQUENCE__jer_slots(const asn_TYPE_descriptor_t *td) {
    size_t n = td->elements_count;
    size_t edx;
    for(edx = 0; edx < td->elements_count; edx++)
        if(JER_IS_GROUP(&td->elements[edx]))
            n += td->elements[edx].type->elements_count;
    return n;
}

/* The first slot of the group edx. */
static size_t
SEQUENCE__jer_group_slot(const asn_TYPE_descriptor_t *td, size_t edx) {
    size_t n = td->elements_count;
    size_t i;
    for(i = 0; i < edx; i++)
        if(JER_IS_GROUP(&td->elements[i]))
            n += td->elements[i].type->elements_count;
    return n;
}

/* Find the member of that key; *gdx is (size_t)-1 for a member of the root. */
static int
SEQUENCE__jer_find(const asn_TYPE_descriptor_t *td, const char *key,
                   size_t key_size, size_t *edx_out, size_t *gdx_out) {
    size_t edx, gdx;

    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        if(JER_IS_GROUP(elm)) {
            for(gdx = 0; gdx < elm->type->elements_count; gdx++) {
                if(jer_key_equals(key, key_size,
                                  elm->type->elements[gdx].name)) {
                    *edx_out = edx;
                    *gdx_out = gdx;
                    return 1;
                }
            }
        } else if(jer_key_equals(key, key_size, elm->name)) {
            *edx_out = edx;
            *gdx_out = (size_t)-1;
            return 1;
        }
    }
    return 0;
}

static int
SEQUENCE__jer_is_mandatory(const asn_TYPE_member_t *elm) {
    return !elm->optional && !elm->default_value_set;
}

/* Install the DEFAULT value of an absent member. */
static int
SEQUENCE__jer_fill_default(void *sptr, const asn_TYPE_member_t *elm) {
    void *memb_ptr;
    void **memb_ptr2;

    if(!elm->default_value_set) return 0;
    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
        if(*memb_ptr2) return 0;
    } else {
        memb_ptr = (char *)sptr + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }
    return elm->default_value_set(memb_ptr2);
}

/* Decode the value of the member elm of the structure sptr. */
static int
SEQUENCE__jer_member(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void *sptr,
                     const asn_TYPE_member_t *elm, const char *val,
                     size_t val_size) {
    asn_dec_rval_t rv;
    void *memb_ptr;
    void **memb_ptr2;

    if(elm->flags & ATF_OPEN_TYPE) {
        rv = OPEN_TYPE_jer_get(opt_codec_ctx, td, sptr, elm, val, val_size);
        return rv.code == RC_OK ? 0 : -1;
    }

    if(!elm->type->op->jer_decoder) return -1;
    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
    } else {
        memb_ptr = (char *)sptr + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }
    rv = elm->type->op->jer_decoder(opt_codec_ctx, elm->type,
                                    elm->encoding_constraints.jer_constraints,
                                    memb_ptr2, val, val_size);
    return rv.code == RC_OK ? 0 : -1;
}

/*
 * An open-type member, decoded after all the other members: the type of its
 * value is selected by its identifier member, which may come later in the
 * object (JSON member order is free) or be an absent DEFAULT.
 */
typedef struct {
    const asn_TYPE_descriptor_t *td;
    void *sptr;
    const asn_TYPE_member_t *elm;
    const char *val;
    size_t val_size;
} SEQUENCE__jer_deferred_t;

asn_dec_rval_t
SEQUENCE_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_jer_constraints_t *constraints, void **sptr,
                    const void *buf_ptr, size_t size) {
    const asn_SEQUENCE_specifics_t *specs =
        (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    jer_cursor_t cur;
    uint8_t *seen = 0;
    SEQUENCE__jer_deferred_t *deferred = 0;
    size_t ndeferred = 0;
    void *st;
    size_t vs, ve, edx, gdx;
    const char *key, *val;
    size_t key_size, val_size;
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

    seen = (uint8_t *)CALLOC(SEQUENCE__jer_slots(td) + 1, 1);
    if(!seen) ASN__DECODE_FAILED;
    deferred = (SEQUENCE__jer_deferred_t *)CALLOC(
        SEQUENCE__jer_slots(td) + 1, sizeof(*deferred));
    if(!deferred) {
        FREEMEM(seen);
        ASN__DECODE_FAILED;
    }

    while((ret = jer_object_next(&cur, &key, &key_size, &val, &val_size))
          == 1) {
        const asn_TYPE_member_t *elm;
        const asn_TYPE_descriptor_t *mtd = td;
        void *mst = st;
        uint8_t *mseen = seen;
        const asn_TYPE_member_t *melements = td->elements;
        size_t midx;

        if(!SEQUENCE__jer_find(td, key, key_size, &edx, &gdx)) {
            if(specs->first_extension >= 0) continue;	/* Unknown: skip */
            goto fail;
        }

        if(gdx != (size_t)-1) {
            /* A member of an extension group; make the group exist. */
            const asn_TYPE_member_t *gelm = &td->elements[edx];
            const asn_SEQUENCE_specifics_t *gspecs =
                (const asn_SEQUENCE_specifics_t *)gelm->type->specifics;
            void **gptr = (void **)((char *)st + gelm->memb_offset);

            if(!(gelm->flags & ATF_POINTER)) goto fail;
            if(!*gptr) {
                *gptr = CALLOC(1, gspecs->struct_size);
                if(!*gptr) goto fail;
            }
            mtd = gelm->type;
            mst = *gptr;
            melements = gelm->type->elements;
            mseen = seen + SEQUENCE__jer_group_slot(td, edx);
            midx = gdx;
        } else {
            midx = edx;
        }
        elm = &melements[midx];

        if(mseen[midx]) goto fail;	/* A duplicate key */
        if(elm->flags & ATF_OPEN_TYPE) {
            deferred[ndeferred].td = mtd;
            deferred[ndeferred].sptr = mst;
            deferred[ndeferred].elm = elm;
            deferred[ndeferred].val = val;
            deferred[ndeferred].val_size = val_size;
            ndeferred++;
        } else if(SEQUENCE__jer_member(opt_codec_ctx, mtd, mst, elm, val,
                                       val_size)) {
            goto fail;
        }
        mseen[midx] = 1;
    }
    if(ret < 0) goto fail;

    /* Mandatory members, DEFAULT values. */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        if(JER_IS_GROUP(elm)) {
            void *gst = *(void **)((char *)st + elm->memb_offset);
            const uint8_t *gseen = seen + SEQUENCE__jer_group_slot(td, edx);
            if(!gst) continue;	/* No key of the group: no group */
            for(gdx = 0; gdx < elm->type->elements_count; gdx++) {
                const asn_TYPE_member_t *gm = &elm->type->elements[gdx];
                if(gseen[gdx]) continue;
                if(SEQUENCE__jer_is_mandatory(gm)) goto fail;
                if(SEQUENCE__jer_fill_default(gst, gm)) goto fail;
            }
        } else if(!seen[edx]) {
            if(SEQUENCE__jer_is_mandatory(elm)) goto fail;
            if(SEQUENCE__jer_fill_default(st, elm)) goto fail;
        }
    }

    /* The open types, now that their identifiers are known. */
    for(edx = 0; edx < ndeferred; edx++) {
        const SEQUENCE__jer_deferred_t *dt = &deferred[edx];
        if(SEQUENCE__jer_member(opt_codec_ctx, dt->td, dt->sptr, dt->elm,
                                dt->val, dt->val_size))
            goto fail;
    }

    FREEMEM(deferred);
    FREEMEM(seen);
    rval.code = RC_OK;
    rval.consumed = ve + jer_whitespace_span((const char *)buf_ptr + ve,
                                             size - ve);
    return rval;
fail:
    FREEMEM(deferred);
    FREEMEM(seen);
    rval.code = RC_FAIL;
    rval.consumed = 0;
    return rval;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
