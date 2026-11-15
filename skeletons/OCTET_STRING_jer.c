/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <asn_codecs_prim.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 22: OCTET STRING is a JSON string of upper-case hexadecimal digits.
 * The character string types derived from OCTET STRING are JSON strings
 * with the JSON escapes (the _utf8 pair: the octets are UTF-8 text; the
 * _latin1 pair: each octet is one character U+0000..U+00FF).
 *
 * Decoding keeps no state between calls: the tokenizer hands a string
 * over only when it is complete (see jer_decode_primitive()), the result is
 * assembled in a private buffer and swapped into the structure at the very
 * end. A call that returns RC_WMORE or RC_FAIL leaves the octets untouched.
 */

/*
 * Replace the contents of the string with a freshly allocated buffer.
 */
static void
OCTET_STRING__jer_store(OCTET_STRING_t *st, uint8_t *buf, size_t size) {
    if(st->buf) FREEMEM(st->buf);
    st->buf = buf;
    st->size = size;
}

asn_enc_rval_t
OCTET_STRING_encode_jer(const asn_TYPE_descriptor_t *td,
                        const asn_jer_constraints_t *constraints,
                        const void *sptr, int ilevel,
                        enum jer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    static const char h2c[] = "0123456789ABCDEF";
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    char scratch[64];
    size_t i, n = 0;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    for(i = 0; i < st->size; i++) {
        if(n + 2 > sizeof(scratch)) {
            ASN__CALLBACK(scratch, n);
            n = 0;
        }
        scratch[n++] = h2c[(st->buf[i] >> 4) & 0x0F];
        scratch[n++] = h2c[st->buf[i] & 0x0F];
    }
    if(n) {
        ASN__CALLBACK(scratch, n);
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Common encoder of the string types. With latin1 each octet is a
 * character (escaped to UTF-8 above 0x7F); otherwise the octets are
 * UTF-8 text and only the characters JSON requires are escaped.
 */
static asn_enc_rval_t
OCTET_STRING__encode_jer_text(const asn_TYPE_descriptor_t *td,
                              const void *sptr, int latin1,
                              asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    const uint8_t *buf, *end, *ss;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    buf = st->buf;
    end = buf + st->size;
    ASN__CALLBACK("\"", 1);
    for(ss = buf; buf < end; buf++) {
        unsigned ch = *buf;
        if(ch >= 0x20 && ch != '"' && ch != '\\' && (ch < 0x80 || !latin1))
            continue;  /* Verbatim */
        if(buf > ss) {
            ASN__CALLBACK(ss, buf - ss);
        }
        {
            ssize_t w = jer_write_escaped_codepoint(ch, cb, app_key);
            if(w < 0) goto cb_failed;
            er.encoded += w;
        }
        ss = buf + 1;
    }
    if(buf > ss) {
        ASN__CALLBACK(ss, buf - ss);
    }
    ASN__CALLBACK("\"", 1);
    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

asn_enc_rval_t
OCTET_STRING_encode_jer_utf8(const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             const void *sptr, int ilevel,
                             enum jer_encoder_flags_e flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    (void)constraints;
    (void)ilevel;
    (void)flags;
    return OCTET_STRING__encode_jer_text(td, sptr, 0, cb, app_key);
}

asn_enc_rval_t
OCTET_STRING_encode_jer_latin1(const asn_TYPE_descriptor_t *td,
                               const asn_jer_constraints_t *constraints,
                               const void *sptr, int ilevel,
                               enum jer_encoder_flags_e flags,
                               asn_app_consume_bytes_f *cb, void *app_key) {
    (void)constraints;
    (void)ilevel;
    (void)flags;
    return OCTET_STRING__encode_jer_text(td, sptr, 1, cb, app_key);
}

static int
OCTET_STRING__hexval(int ch) {
    if(ch >= '0' && ch <= '9') return ch - '0';
    if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

/* Hexadecimal digits only; an odd digit count is an error. */
static enum jer_pbd_rval
OCTET_STRING__jer_body_hex(const asn_TYPE_descriptor_t *td, void *sptr,
                           const void *chunk_buf, size_t chunk_size) {
    const char *content;
    size_t n, i;
    uint8_t *buf;

    (void)td;
    if(jer_string_span(chunk_buf, chunk_size, &content, &n))
        return JPBD_BROKEN_ENCODING;
    if(n & 1) return JPBD_BROKEN_ENCODING;
    buf = (uint8_t *)MALLOC(n / 2 + 1);
    if(!buf) return JPBD_SYSTEM_FAILURE;
    for(i = 0; i < n; i += 2) {
        int hi = OCTET_STRING__hexval(content[i]);
        int lo = OCTET_STRING__hexval(content[i + 1]);
        if(hi < 0 || lo < 0) {
            FREEMEM(buf);
            return JPBD_BROKEN_ENCODING;
        }
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    buf[n / 2] = 0;  /* Courtesy termination */
    OCTET_STRING__jer_store((OCTET_STRING_t *)sptr, buf, n / 2);
    return JPBD_BODY_CONSUMED;
}

static enum jer_pbd_rval
OCTET_STRING__jer_body_text(void *sptr, const void *chunk_buf,
                            size_t chunk_size,
                            enum jer_unescape_mode_e mode) {
    const char *content;
    size_t n, out_size;
    uint8_t *buf;

    if(jer_string_span(chunk_buf, chunk_size, &content, &n))
        return JPBD_BROKEN_ENCODING;
    if(jer_unescape(content, n, mode, &buf, &out_size))
        return JPBD_BROKEN_ENCODING;
    OCTET_STRING__jer_store((OCTET_STRING_t *)sptr, buf, out_size);
    return JPBD_BODY_CONSUMED;
}

static enum jer_pbd_rval
OCTET_STRING__jer_body_utf8(const asn_TYPE_descriptor_t *td, void *sptr,
                            const void *chunk_buf, size_t chunk_size) {
    (void)td;
    return OCTET_STRING__jer_body_text(sptr, chunk_buf, chunk_size,
                                       JER_UNESC_UTF8);
}

static enum jer_pbd_rval
OCTET_STRING__jer_body_latin1(const asn_TYPE_descriptor_t *td, void *sptr,
                              const void *chunk_buf, size_t chunk_size) {
    (void)td;
    return OCTET_STRING__jer_body_text(sptr, chunk_buf, chunk_size,
                                       JER_UNESC_LATIN1);
}

static asn_dec_rval_t
OCTET_STRING__decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const void *buf_ptr, size_t size,
                         jer_primitive_body_decoder_f *body) {
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_OCTET_STRING_specs;
    return jer_decode_primitive(opt_codec_ctx, td, sptr, specs->struct_size,
                                buf_ptr, size, body);
}

asn_dec_rval_t
OCTET_STRING_decode_jer_hex(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td,
                            const asn_jer_constraints_t *constraints,
                            void **sptr, const void *buf_ptr, size_t size) {
    (void)constraints;
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr, buf_ptr, size,
                                    OCTET_STRING__jer_body_hex);
}

asn_dec_rval_t
OCTET_STRING_decode_jer_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             void **sptr, const void *buf_ptr, size_t size) {
    (void)constraints;
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr, buf_ptr, size,
                                    OCTET_STRING__jer_body_utf8);
}

asn_dec_rval_t
OCTET_STRING_decode_jer_latin1(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td,
                               const asn_jer_constraints_t *constraints,
                               void **sptr, const void *buf_ptr,
                               size_t size) {
    (void)constraints;
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr, buf_ptr, size,
                                    OCTET_STRING__jer_body_latin1);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
