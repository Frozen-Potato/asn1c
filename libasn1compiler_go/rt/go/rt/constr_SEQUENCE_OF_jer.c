/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE_OF.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_encoder.h>

/*
 * The JER of SEQUENCE OF and SET OF is the same JSON array; the decoder is
 * SET_OF_decode_jer (see constr_SEQUENCE_OF.h).
 */
asn_enc_rval_t
SEQUENCE_OF_encode_jer(const asn_TYPE_descriptor_t *td,
                       const asn_jer_constraints_t *constraints,
                       const void *sptr, int ilevel,
                       enum jer_encoder_flags_e flags,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    return SET_OF_encode_jer(td, constraints, sptr, ilevel, flags, cb,
                             app_key);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
