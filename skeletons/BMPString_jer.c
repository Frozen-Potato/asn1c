/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BMPString.h>
#include <UTF8String.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * BMPString: a JSON string of the characters (X.697 29); the value holds
 * big-endian 2-byte characters. The decoder reads the JSON string as UTF-8
 * (the escapes, including surrogate pairs, are resolved first) and widens it;
 * a character that does not fit the type (above U+FFFF) is an error.
 */
asn_dec_rval_t
BMPString_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints, void **sptr,
                const void *buf_ptr, size_t size) {
    asn_dec_rval_t rc;

    rc = OCTET_STRING_decode_jer_utf8(opt_codec_ctx, td, constraints, sptr,
                                      buf_ptr, size);
    if(rc.code == RC_OK) {
        /* Now we have a whole string in UTF-8 format. Widen it. */
        uint32_t *wcs;
        size_t wcs_len, i;
        UTF8String_t *st;
        uint8_t *out;

        assert(*sptr);
        st = (UTF8String_t *)*sptr;
        assert(st->buf);
        wcs_len = UTF8String_to_wcs(st, 0, 0);
        if(wcs_len == 0 && st->size != 0) {  /* Malformed UTF-8 */
            rc.code = RC_FAIL;
            rc.consumed = 0;
            return rc;
        }

        wcs = (uint32_t *)MALLOC(4 * (wcs_len + 1));
        out = (uint8_t *)MALLOC(2 * (wcs_len + 1));
        if(!wcs || !out || UTF8String_to_wcs(st, wcs, wcs_len) != wcs_len) {
            FREEMEM(wcs);
            FREEMEM(out);
            rc.code = RC_FAIL;
            rc.consumed = 0;
            return rc;
        }
        for(i = 0; i < wcs_len; i++) {
            uint32_t wch = wcs[i];
            if(wch > 0xffff || (wch >= 0xd800 && wch <= 0xdfff)) {
                FREEMEM(wcs);
                FREEMEM(out);
                rc.code = RC_FAIL;
                rc.consumed = 0;
                return rc;
            }
            out[2 * i + 0] = (uint8_t)(wch >> 8);
            out[2 * i + 1] = (uint8_t)wch;
        }
        out[2 * wcs_len] = out[2 * wcs_len + 1] = 0;  /* nul-terminate */
        FREEMEM(wcs);
        FREEMEM(st->buf);
        st->buf = out;
        st->size = 2 * wcs_len;
    }
    return rc;
}

asn_enc_rval_t
BMPString_encode_jer(const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints, const void *sptr,
                int ilevel, enum jer_encoder_flags_e flags,
                asn_app_consume_bytes_f *cb, void *app_key) {
    const BMPString_t *st = (const BMPString_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    size_t offset;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size) || (st->size % 2) || !cb)
        ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    for(offset = 0; offset < st->size; offset += 2) {
        uint32_t codepoint = 0;
        ssize_t written;
        size_t k;
        for(k = 0; k < 2; k++)
            codepoint = (codepoint << 8) | st->buf[offset + k];
        written = jer_write_escaped_codepoint(codepoint, cb, app_key);
        if(written < 0) goto cb_failed;
        er.encoded += written;
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
