/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <limits.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * ANY is carried as the hexadecimal string of its (BER) contents, like
 * an OCTET STRING.
 * ANY_t keeps its size in an int, so it is not laid out like OCTET_STRING_t:
 * both directions go through an OCTET_STRING_t of their own.
 */
asn_enc_rval_t
ANY_encode_jer(const asn_TYPE_descriptor_t *td,
               const asn_jer_constraints_t *constraints, const void *sptr,
               int ilevel, enum jer_encoder_flags_e flags,
               asn_app_consume_bytes_f *cb, void *app_key) {
    const ANY_t *st = (const ANY_t *)sptr;
    OCTET_STRING_t view;

    if(!st || st->size < 0 || (!st->buf && st->size)) ASN__ENCODE_FAILED;
    memset(&view, 0, sizeof(view));
    view.buf = st->buf;
    view.size = (size_t)st->size;
    return OCTET_STRING_encode_jer(td, constraints, &view, ilevel, flags, cb,
                                   app_key);
}

asn_dec_rval_t
ANY_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td,
               const asn_jer_constraints_t *constraints, void **sptr,
               const void *buf_ptr, size_t size) {
    asn_dec_rval_t rval;
    OCTET_STRING_t tmp;
    void *tmp_ptr = &tmp;
    ANY_t *st = (ANY_t *)*sptr;

    memset(&tmp, 0, sizeof(tmp));
    rval = OCTET_STRING_decode_jer_hex(opt_codec_ctx, td, constraints,
                                       &tmp_ptr, buf_ptr, size);
    if(rval.code == RC_OK) {
        if(tmp.size > (size_t)INT_MAX) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
        } else {
            if(!st) st = (ANY_t *)CALLOC(1, sizeof(*st));
            if(!st) {
                rval.code = RC_FAIL;
                rval.consumed = 0;
            } else {
                if(st->buf) FREEMEM(st->buf);
                st->buf = tmp.buf;
                st->size = (int)tmp.size;
                tmp.buf = 0;
                *sptr = st;
            }
        }
    } else {
        rval.consumed = 0;
    }
    FREEMEM(tmp.buf);
    return rval;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
