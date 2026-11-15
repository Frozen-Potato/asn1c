/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_codecs_prim.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>

/*
 * Local internal type passed around as an argument.
 */
struct jdp_arg_s {
    const asn_TYPE_descriptor_t *type_descriptor;
    void *struct_key;
    jer_primitive_body_decoder_f *prim_body_decoder;
    int decoded_something;
    int want_more;
};

/*
 * Receives the whole JSON value of a primitive (the tokenizer delivers a
 * value only when it is complete, so there is no partial state to keep).
 */
static ssize_t
jer_decode__primitive_body(void *key, const void *chunk_buf, size_t chunk_size,
                           int have_more) {
    struct jdp_arg_s *arg = (struct jdp_arg_s *)key;
    enum jer_pbd_rval bret;

    if(arg->decoded_something) {
        /* Decoding was done once already. Only whitespace may follow. */
        if(jer_whitespace_span(chunk_buf, chunk_size) == chunk_size)
            return chunk_size;
        return -1;
    }

    if(!have_more || jer_whitespace_span(chunk_buf, chunk_size) == chunk_size) {
        /* Nothing but white space so far: the value is still to come. */
        arg->want_more = 1;
        return -1;
    }

    /* The body decoders skip the surrounding whitespace themselves. */
    bret = arg->prim_body_decoder(arg->type_descriptor, arg->struct_key,
                                  chunk_buf, chunk_size);
    switch(bret) {
    case JPBD_SYSTEM_FAILURE:
    case JPBD_DECODER_LIMIT:
    case JPBD_BROKEN_ENCODING:
        break;
    case JPBD_BODY_CONSUMED:
        arg->decoded_something = 1;
        /* Fall through */
    case JPBD_NOT_BODY_IGNORE:  /* Safe to proceed further */
        return chunk_size;
    }

    return -1;
}

asn_dec_rval_t
jer_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void **sptr,
                     size_t struct_size, const void *buf_ptr, size_t size,
                     jer_primitive_body_decoder_f *prim_body_decoder) {
    asn_struct_ctx_t s_ctx;
    struct jdp_arg_s s_arg;
    asn_dec_rval_t rc;

    /*
     * Create the structure if does not exist.
     */
    if(!*sptr) {
        *sptr = CALLOC(1, struct_size);
        if(!*sptr) ASN__DECODE_FAILED;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
    s_arg.type_descriptor = td;
    s_arg.struct_key = *sptr;
    s_arg.prim_body_decoder = prim_body_decoder;
    s_arg.decoded_something = 0;
    s_arg.want_more = 0;

    rc = jer_decode_general(opt_codec_ctx, &s_ctx, &s_arg, buf_ptr, size, 0,
                            jer_decode__primitive_body);
    switch(rc.code) {
    case RC_OK:
        if(!s_arg.decoded_something) {
            /* A value that no body decoder accepted (e.g. only a bracket). */
            ASN__DECODE_FAILED;
        }
        break;
    case RC_WMORE:
        /*
         * Redo the whole thing later: the tokenizer reports a value only
         * when it is complete, so nothing was stored in the structure.
         */
        rc.consumed = 0;
        break;
    case RC_FAIL:
        rc.consumed = 0;
        if(s_arg.want_more)
            rc.code = RC_WMORE;
        else
            ASN__DECODE_FAILED;
        break;
    }
    return rc;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
