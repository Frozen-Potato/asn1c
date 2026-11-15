/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeReal.h>
#include <REAL.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * Decode the chunk of JSON text encoding REAL.
 */
asn_dec_rval_t
NativeReal_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints, void **sptr,
                      const void *buf_ptr, size_t size) {
    asn_dec_rval_t rval;
    REAL_t st = { 0, 0 };
    REAL_t *stp = &st;

    rval = REAL_decode_jer(opt_codec_ctx, td, constraints, (void **)&stp,
                           buf_ptr, size);
    if(rval.code == RC_OK) {
        double d;
        if(asn_REAL2double(&st, &d) || NativeReal__set(td, sptr, d) < 0) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
        }
    } else {
        /* Convert all errors into RC_FAIL */
        rval.consumed = 0;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &st);
    return rval;
}

asn_enc_rval_t
NativeReal_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    double d;

    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!sptr) ASN__ENCODE_FAILED;
    d = NativeReal__get_double(td, sptr);
    /* A float is written with the digits that identify it as a float. */
    er.encoded = REAL__jer_dump(d, NativeReal__float_size(td) == sizeof(float),
                                cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
