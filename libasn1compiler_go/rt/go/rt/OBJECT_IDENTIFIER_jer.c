/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OBJECT_IDENTIFIER.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 25: OBJECT IDENTIFIER is the JSON string of its dotted arcs
 * ("1.2.840.113549"). Only that form: no names, no braces.
 */
static enum jer_pbd_rval
OBJECT_IDENTIFIER__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                                   const void *chunk_buf, size_t chunk_size) {
    OBJECT_IDENTIFIER_t *st = (OBJECT_IDENTIFIER_t *)sptr;
    const char *content;
    size_t content_size, i;
    const char *endptr;
    asn_oid_arc_t s_arcs[10];
    asn_oid_arc_t *arcs = s_arcs;
    ssize_t num_arcs;
    int ret;

    (void)td;

    if(jer_string_span(chunk_buf, chunk_size, &content, &content_size))
        return JPBD_BROKEN_ENCODING;
    /* Digits and dots only: parse_arcs() would also accept white space. */
    for(i = 0; i < content_size; i++)
        if(!((content[i] >= '0' && content[i] <= '9') || content[i] == '.'))
            return JPBD_BROKEN_ENCODING;

    num_arcs = OBJECT_IDENTIFIER_parse_arcs(content, content_size, arcs,
                                            sizeof(s_arcs) / sizeof(s_arcs[0]),
                                            &endptr);
    if(num_arcs <= 0 || endptr != content + content_size)
        return JPBD_BROKEN_ENCODING;

    if((size_t)num_arcs > sizeof(s_arcs) / sizeof(s_arcs[0])) {
        arcs = (asn_oid_arc_t *)MALLOC(num_arcs * sizeof(asn_oid_arc_t));
        if(!arcs) return JPBD_SYSTEM_FAILURE;
        if(OBJECT_IDENTIFIER_parse_arcs(content, content_size, arcs, num_arcs,
                                        &endptr) != num_arcs) {
            FREEMEM(arcs);
            return JPBD_SYSTEM_FAILURE;
        }
    }

    ret = OBJECT_IDENTIFIER_set_arcs(st, arcs, num_arcs);
    if(arcs != s_arcs) FREEMEM(arcs);

    /* Fails for a first arc above 2 or a second one above 39 under 0/1. */
    return ret ? JPBD_BROKEN_ENCODING : JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
OBJECT_IDENTIFIER_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             void **sptr, const void *buf_ptr, size_t size) {
    (void)constraints;
    return jer_decode_primitive(opt_codec_ctx, td, sptr,
                                sizeof(OBJECT_IDENTIFIER_t), buf_ptr, size,
                                OBJECT_IDENTIFIER__jer_body_decode);
}

asn_enc_rval_t
OBJECT_IDENTIFIER_encode_jer(const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             const void *sptr, int ilevel,
                             enum jer_encoder_flags_e flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    const OBJECT_IDENTIFIER_t *st = (const OBJECT_IDENTIFIER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t oid_encoded;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || !st->buf) ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    oid_encoded = OBJECT_IDENTIFIER__dump_body(st, cb, app_key);
    if(oid_encoded < 0) goto cb_failed;
    er.encoded += oid_encoded;
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
