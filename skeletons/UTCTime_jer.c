/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <UTCTime.h>
#include <errno.h>
#include <time.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_encoder.h>

#if !defined(ASN___INTERNAL_TEST_MODE)

/*
 * X.697 31: a time is a JSON string with the usual text of the value;
 * the decoder is OCTET_STRING_decode_jer_utf8. Unlike XER (which checks
 * only in the canonical mode) the encoder always refuses a value that
 * is not a valid time.
 */
asn_enc_rval_t
UTCTime_encode_jer(const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints, const void *sptr,
                   int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t rv;
    UTCTime_t *ut;
    struct tm tm;

    errno = EPERM;
    if(asn_UT2time((const UTCTime_t *)sptr, &tm, 1) == -1 && errno != EPERM)
        ASN__ENCODE_FAILED;

    /* Fractions are not allowed in UTCTime */
    ut = asn_time2UT(0, &tm, 1);
    if(!ut) ASN__ENCODE_FAILED;
    OCTET_STRING_free(&asn_DEF_UTCTime, ut, 0);

    rv = OCTET_STRING_encode_jer_utf8(td, constraints, sptr, ilevel, flags, cb,
                                      app_key);
    return rv;
}

#endif  /* !defined(ASN___INTERNAL_TEST_MODE) */

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
