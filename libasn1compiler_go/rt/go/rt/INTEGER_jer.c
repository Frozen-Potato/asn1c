/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 20: INTEGER is a JSON number without fraction or exponent.
 * The value is converted to and from decimal text of any length (the
 * INTEGER_t is a big-endian two's complement byte string), so values wider
 * than intmax_t are not an error.
 */

/*
 * Convert "[-]digits" (already validated) into an INTEGER body.
 */
static enum jer_pbd_rval
INTEGER__jer_set_decimal(INTEGER_t *st, const char *digits, size_t ndigits,
                         int negative) {
    size_t cap = ndigits / 2 + 3;  /* 10^n < 2^(3.33 n); + sign byte */
    uint8_t *mag = (uint8_t *)CALLOC(1, cap);
    uint8_t *out;
    size_t used = 0;  /* Significant low-order bytes of mag */
    size_t i, j, start;

    if(!mag) return JPBD_SYSTEM_FAILURE;

    for(i = 0; i < ndigits; i++) {
        unsigned carry = (unsigned)(digits[i] - '0');
        for(j = 0; j < used || carry; j++) {
            unsigned cur;
            uint8_t *b = &mag[cap - 1 - j];
            cur = (j < used ? (unsigned)*b * 10u : 0u) + carry;
            *b = (uint8_t)cur;
            carry = cur >> 8;
            if(j >= used) used = j + 1;
        }
    }

    if(negative) {  /* Two's complement over the whole width */
        unsigned carry = 1;
        for(j = cap; j-- > 0;) {
            unsigned cur = (uint8_t)~mag[j] + carry;
            mag[j] = (uint8_t)cur;
            carry = cur >> 8;
        }
    }

    /* Drop redundant sign-extension bytes (X.690 8.3.2). */
    for(start = 0; start + 1 < cap; start++) {
        if(mag[start] == 0x00 && !(mag[start + 1] & 0x80)) continue;
        if(mag[start] == 0xff && (mag[start + 1] & 0x80)) continue;
        break;
    }

    out = (uint8_t *)MALLOC(cap - start + 1);
    if(!out) {
        FREEMEM(mag);
        return JPBD_SYSTEM_FAILURE;
    }
    memcpy(out, mag + start, cap - start);
    out[cap - start] = 0;
    FREEMEM(mag);
    if(st->buf) FREEMEM(st->buf);
    st->buf = out;
    st->size = cap - start;
    return JPBD_BODY_CONSUMED;
}

static enum jer_pbd_rval
INTEGER__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    const char *p = (const char *)chunk_buf;
    const char *end = p + chunk_size;
    const char *digits;
    int negative = 0;

    (void)td;

    p += jer_whitespace_span(p, chunk_size);
    if(p < end && *p == '-') {
        negative = 1;
        p++;
    }
    digits = p;
    while(p < end && *p >= '0' && *p <= '9') p++;
    if(p == digits) return JPBD_BROKEN_ENCODING;  /* No digits */
    /* JSON forbids leading zeroes; fractions and exponents are not INTEGERs. */
    if(digits[0] == '0' && p - digits > 1) return JPBD_BROKEN_ENCODING;
    if(jer_whitespace_span(p, (size_t)(end - p)) != (size_t)(end - p))
        return JPBD_BROKEN_ENCODING;

    return INTEGER__jer_set_decimal((INTEGER_t *)sptr, digits,
                                    (size_t)(p - digits), negative);
}

asn_dec_rval_t
INTEGER_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints, void **sptr,
                   const void *buf_ptr, size_t size) {
    (void)constraints;
    return jer_decode_primitive(opt_codec_ctx, td, sptr, sizeof(INTEGER_t),
                                buf_ptr, size, INTEGER__jer_body_decode);
}

asn_enc_rval_t
INTEGER_encode_jer(const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints, const void *sptr,
                   int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    intmax_t value;
    uint8_t *tmp;
    char *digits;
    size_t n, nd = 0, i;
    int negative;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || !st->buf || !st->size) ASN__ENCODE_FAILED;

    if(asn_INTEGER2imax(st, &value) == 0) {
        er.encoded = asn__format_to_callback(cb, app_key, "%" ASN_PRIdMAX,
                                             value);
        if(er.encoded < 0) ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }

    /* Wider than intmax_t: repeated division of the magnitude by 10. */
    n = st->size;
    tmp = (uint8_t *)MALLOC(n);
    digits = (char *)MALLOC(n * 5 / 2 + 3);  /* log10(256) < 2.41 */
    if(!tmp || !digits) {
        FREEMEM(tmp);
        FREEMEM(digits);
        ASN__ENCODE_FAILED;
    }
    memcpy(tmp, st->buf, n);
    negative = (tmp[0] & 0x80) != 0;
    if(negative) {
        unsigned carry = 1;
        for(i = n; i-- > 0;) {
            unsigned cur = (uint8_t)~tmp[i] + carry;
            tmp[i] = (uint8_t)cur;
            carry = cur >> 8;
        }
    }
    for(;;) {
        unsigned rem = 0;
        int nonzero = 0;
        for(i = 0; i < n; i++) {
            unsigned cur = rem * 256u + tmp[i];
            tmp[i] = (uint8_t)(cur / 10u);
            rem = cur % 10u;
            if(tmp[i]) nonzero = 1;
        }
        digits[nd++] = (char)('0' + rem);
        if(!nonzero) break;
    }
    if(negative) digits[nd++] = '-';
    for(i = 0; i < nd / 2; i++) {  /* Reverse */
        char c = digits[i];
        digits[i] = digits[nd - 1 - i];
        digits[nd - 1 - i] = c;
    }
    if(cb(digits, nd, app_key) < 0) {
        FREEMEM(tmp);
        FREEMEM(digits);
        ASN__ENCODE_FAILED;
    }
    er.encoded = (ssize_t)nd;
    FREEMEM(tmp);
    FREEMEM(digits);
    ASN__ENCODED_OK(er);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
