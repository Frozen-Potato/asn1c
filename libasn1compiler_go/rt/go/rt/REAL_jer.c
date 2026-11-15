/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <stdlib.h>	/* for strtod(3) */
#include <math.h>
#include <float.h>
#include <errno.h>
#include <REAL.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

#ifndef	NAN
#define	NAN	(0.0/0.0)
#endif
#ifndef	INFINITY
#define	INFINITY	HUGE_VAL
#endif

/*
 * X.697 23: a finite REAL is a JSON number; the special values are the
 * JSON strings "INF", "-INF", "NaN" and "-0" (minus zero).
 * Private to this file (the XER table in REAL.c has different spellings).
 */
enum jer_srv_e { JSRV_NAN, JSRV_MINUS_INFINITY, JSRV_PLUS_INFINITY, JSRV_MINUS_ZERO };
static const struct jer_special_real_s {
    const char *string;  /* Without the quotes */
    size_t length;
} jer_special_real[] = {
#define	JSRV_SET(foo)	{ foo, sizeof(foo) - 1 }
    JSRV_SET("NaN"),
    JSRV_SET("-INF"),
    JSRV_SET("INF"),
    JSRV_SET("-0"),
#undef	JSRV_SET
};

/*
 * Emit the shortest decimal text that reads back as the same value (as a
 * float if is_float). Plain decimal notation is used for 1e-4 <= |d| < 1e16,
 * the exponent notation outside it. A finite value always contains either a
 * decimal point or an exponent, so that it stays recognizable as a REAL.
 */
ssize_t
REAL__jer_dump(double d, int is_float, asn_app_consume_bytes_f *cb,
               void *app_key) {
    char buf[64];
    const char *s;
    size_t len;
    double ad;
    int i, max_prec;

    if(d != d) {
        s = "\"NaN\"";
    } else if(d > DBL_MAX) {
        s = "\"INF\"";
    } else if(d < -DBL_MAX) {
        s = "\"-INF\"";
    } else if(d == 0.0) {
        s = (copysign(1.0, d) < 0.0) ? "\"-0\"" : "0.0";
    } else {
        s = 0;
    }
    if(s) {
        len = strlen(s);
        return (cb(s, len, app_key) < 0) ? -1 : (ssize_t)len;
    }

    ad = d < 0 ? -d : d;
    max_prec = is_float ? 9 : 17;
    buf[0] = 0;
    if(ad >= 1e-4 && ad < 1e16) {
        /* Fewest decimals that round-trip. */
        for(i = 0; i <= 25; i++) {
            double back;
            snprintf(buf, sizeof(buf), "%.*f", i, d);
            back = strtod(buf, 0);
            if(is_float ? ((float)back == (float)d) : (back == d)) break;
        }
    } else {
        for(i = 1; i <= max_prec; i++) {
            double back;
            snprintf(buf, sizeof(buf), "%.*g", i, d);
            back = strtod(buf, 0);
            if(is_float ? ((float)back == (float)d) : (back == d)) break;
        }
    }
    len = strlen(buf);
    {
        /* The locale may have given a comma; keep a dot. */
        size_t k;
        int dot_or_exp = 0;
        for(k = 0; k < len; k++) {
            if(buf[k] == ',') buf[k] = '.';
            if(buf[k] == '.' || buf[k] == 'e' || buf[k] == 'E')
                dot_or_exp = 1;
        }
        if(!dot_or_exp) {
            buf[len++] = '.';
            buf[len++] = '0';
            buf[len] = 0;
        }
    }
    return (cb(buf, len, app_key) < 0) ? -1 : (ssize_t)len;
}

asn_enc_rval_t
REAL_encode_jer(const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints, const void *sptr,
                int ilevel, enum jer_encoder_flags_e flags,
                asn_app_consume_bytes_f *cb, void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    double d;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || !st->buf || asn_REAL2double(st, &d))
        ASN__ENCODE_FAILED;

    er.encoded = REAL__jer_dump(d, 0, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}

/*
 * Check the JSON number grammar:
 *   -? (0 | [1-9][0-9]*) ( . [0-9]+ )? ( [eE] [+-]? [0-9]+ )?
 * Returns the length of the number, or 0.
 */
static size_t
REAL__jer_scan_number(const char *p, const char *end) {
    const char *s = p;
    const char *digits;

    if(s < end && *s == '-') s++;
    digits = s;
    while(s < end && *s >= '0' && *s <= '9') s++;
    if(s == digits) return 0;
    if(digits[0] == '0' && s - digits > 1) return 0;  /* Leading zero */
    if(s < end && *s == '.') {
        const char *f = ++s;
        while(s < end && *s >= '0' && *s <= '9') s++;
        if(s == f) return 0;
    }
    if(s < end && (*s == 'e' || *s == 'E')) {
        const char *e;
        s++;
        if(s < end && (*s == '+' || *s == '-')) s++;
        e = s;
        while(s < end && *s >= '0' && *s <= '9') s++;
        if(s == e) return 0;
    }
    return (size_t)(s - p);
}

static enum jer_pbd_rval
REAL__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                      const void *chunk_buf, size_t chunk_size) {
    REAL_t *st = (REAL_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *end = p + chunk_size;
    double value;
    char *b;
    size_t n;

    (void)td;

    p += jer_whitespace_span(p, chunk_size);
    if(p >= end) return JPBD_BROKEN_ENCODING;

    if(*p == '"') {
        /* A JSON special real value: "INF", "-INF", "NaN", "-0". */
        const char *content;
        size_t content_size, i;
        if(jer_string_span(p, (size_t)(end - p), &content, &content_size))
            return JPBD_BROKEN_ENCODING;
        for(i = 0; i < sizeof(jer_special_real) / sizeof(jer_special_real[0]);
            i++) {
            if(jer_special_real[i].length != content_size
               || memcmp(jer_special_real[i].string, content, content_size))
                continue;
            switch((enum jer_srv_e)i) {
            case JSRV_NAN: value = NAN; break;
            case JSRV_MINUS_INFINITY: value = -INFINITY; break;
            case JSRV_PLUS_INFINITY: value = INFINITY; break;
            default: value = -0.0; break;
            }
            return asn_double2REAL(st, value) ? JPBD_SYSTEM_FAILURE
                                              : JPBD_BODY_CONSUMED;
        }
        ASN_DEBUG("Unknown JSON special real value");
        return JPBD_BROKEN_ENCODING;
    }

    n = REAL__jer_scan_number(p, end);
    if(!n || jer_whitespace_span(p + n, (size_t)(end - (p + n)))
                 != (size_t)(end - (p + n)))
        return JPBD_BROKEN_ENCODING;

    b = (char *)MALLOC(n + 1);
    if(!b) return JPBD_SYSTEM_FAILURE;
    memcpy(b, p, n);
    b[n] = 0;
    errno = 0;
    value = strtod(b, 0);
    FREEMEM(b);
    if(value > DBL_MAX || value < -DBL_MAX)
        return JPBD_DECODER_LIMIT;  /* Does not fit a double */

    return asn_double2REAL(st, value) ? JPBD_SYSTEM_FAILURE
                                      : JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
REAL_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints, void **sptr,
                const void *buf_ptr, size_t size) {
    (void)constraints;
    return jer_decode_primitive(opt_codec_ctx, td, sptr, sizeof(REAL_t),
                                buf_ptr, size, REAL__jer_body_decode);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
