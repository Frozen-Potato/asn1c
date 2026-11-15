/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ENUMERATED.h>
#include <INTEGER.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 21: ENUMERATED is the JSON string holding the enumeration
 * identifier. (Unlike INTEGER, a number is not accepted.)
 */
static enum jer_pbd_rval
ENUMERATED__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                            const void *chunk_buf, size_t chunk_size) {
    INTEGER_t *st = (INTEGER_t *)sptr;
    const asn_INTEGER_enum_map_t *el;
    const char *content;
    size_t content_size;
    uint8_t *name;
    size_t name_size;

    if(jer_string_span(chunk_buf, chunk_size, &content, &content_size))
        return JPBD_BROKEN_ENCODING;
    if(jer_unescape(content, content_size, JER_UNESC_UTF8, &name, &name_size))
        return JPBD_BROKEN_ENCODING;
    el = INTEGER_map_name2enum((const asn_INTEGER_specifics_t *)td->specifics,
                               (const char *)name,
                               (const char *)name + name_size);
    FREEMEM(name);
    if(!el) {
        ASN_DEBUG("Unknown identifier for ENUMERATED");
        return JPBD_BROKEN_ENCODING;
    }
    if(asn_imax2INTEGER(st, el->nat_value)) return JPBD_SYSTEM_FAILURE;
    return JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
ENUMERATED_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints, void **sptr,
                      const void *buf_ptr, size_t size) {
    (void)constraints;
    return jer_decode_primitive(opt_codec_ctx, td, sptr, sizeof(INTEGER_t),
                                buf_ptr, size, ENUMERATED__jer_body_decode);
}

asn_enc_rval_t
ENUMERATED_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    long value;
    const asn_INTEGER_enum_map_t *el;

    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || !st->buf) ASN__ENCODE_FAILED;
    if(asn_INTEGER2long(st, &value)) ASN__ENCODE_FAILED;

    el = INTEGER_map_value2enum(specs, value);
    if(!el) {
        ASN_DEBUG("ASN.1 forbids dealing with unknown value of ENUMERATED type");
        ASN__ENCODE_FAILED;
    }
    er.encoded = asn__format_to_callback(cb, app_key, "\"%s\"", el->enum_name);
    if(er.encoded < 0) ASN__ENCODE_FAILED;
    ASN__ENCODED_OK(er);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
