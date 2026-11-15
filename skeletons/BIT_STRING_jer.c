/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>

#if !defined(ASN_DISABLE_JER_SUPPORT)

#include <jer_decoder.h>
#include <jer_encoder.h>

/*
 * X.697 24: a BIT STRING of unconstrained or variable size is the JSON
 * object { "value": <upper-case hex string>, "length": <number of bits> };
 * a fixed-size BIT STRING (SIZE(n)) is just the hex string.
 * "Fixed size" is known from the JER constraints (asn_jer_constraints_t.size,
 * from the argument or the type descriptor); while nothing sets them every
 * BIT STRING takes the object form.
 *
 * The decoder parses the value itself (the generic tokenizer delivers
 * objects as delimiters) and is transactional: the structure changes only
 * when the whole value is valid.
 */

#define BS_INCOMPLETE 0
#define BS_OK 1
#define BS_BAD (-1)

static void
BIT_STRING__jer_skip_ws(const char **cur, const char *end) {
    *cur += jer_whitespace_span(*cur, (size_t)(end - *cur));
}

/* Match one punctuation byte after optional whitespace. */
static int
BIT_STRING__jer_expect_char(const char **cur, const char *end, int expected) {
    BIT_STRING__jer_skip_ws(cur, end);
    if(*cur == end) return BS_INCOMPLETE;
    if(**cur != expected) return BS_BAD;
    ++*cur;
    return BS_OK;
}

/* Scan an escape-free JSON string; *start / *len delimit its content. */
static int
BIT_STRING__jer_scan_string(const char **cur, const char *end,
                            const char **start, size_t *len) {
    const char *p;
    BIT_STRING__jer_skip_ws(cur, end);
    if(*cur == end) return BS_INCOMPLETE;
    if(**cur != '"') return BS_BAD;
    *start = p = *cur + 1;
    for(; p < end && *p != '"'; p++) {
        if(*p == '\\' || (unsigned char)*p < 0x20) return BS_BAD;
    }
    if(p == end) return BS_INCOMPLETE;
    *len = (size_t)(p - *start);
    *cur = p + 1;
    return BS_OK;
}

static int
BIT_STRING__jer_hexval(int ch) {
    if(ch >= '0' && ch <= '9') return ch - '0';
    if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

/* A hex string value into a new buffer (with a courtesy NUL). */
static int
BIT_STRING__jer_parse_hex(const char **cur, const char *end, uint8_t **bytes,
                          size_t *byte_count) {
    const char *start;
    size_t len, i;
    uint8_t *buf;
    int r = BIT_STRING__jer_scan_string(cur, end, &start, &len);

    if(r != BS_OK) return r;
    if(len & 1) return BS_BAD;
    buf = (uint8_t *)MALLOC(len / 2 + 1);
    if(!buf) return BS_BAD;
    for(i = 0; i < len; i += 2) {
        int hi = BIT_STRING__jer_hexval(start[i]);
        int lo = BIT_STRING__jer_hexval(start[i + 1]);
        if(hi < 0 || lo < 0) {
            FREEMEM(buf);
            return BS_BAD;
        }
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    buf[len / 2] = 0;
    *bytes = buf;
    *byte_count = len / 2;
    return BS_OK;
}

/* A non-negative integer without sign, fraction or exponent. */
static int
BIT_STRING__jer_parse_length(const char **cur, const char *end,
                             size_t *bit_count) {
    const char *p;
    size_t value = 0, digits = 0;

    BIT_STRING__jer_skip_ws(cur, end);
    p = *cur;
    while(p < end && *p >= '0' && *p <= '9') {
        unsigned d = (unsigned)(*p - '0');
        if(value > (SIZE_MAX - d) / 10) return BS_BAD;
        value = value * 10 + d;
        digits++;
        p++;
    }
    if(p == end) return BS_INCOMPLETE;  /* More digits may follow */
    if(!digits) return BS_BAD;
    if(digits > 1 && **cur == '0') return BS_BAD;
    if(*p == '.' || *p == 'e' || *p == 'E') return BS_BAD;
    *cur = p;
    *bit_count = value;
    return BS_OK;
}

asn_enc_rval_t
BIT_STRING_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    static const char hex[] = "0123456789ABCDEF";
    asn_enc_rval_t er = {0, 0, 0};
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    const asn_jer_constraints_t *cts = constraints;
    int minified = (flags & JER_F_MINIFIED) != 0;
    ssize_t fixed_bits = -1;
    size_t bit_count, i, n = 0;
    char scratch[64];

    if(!cts && td) cts = td->encoding_constraints.jer_constraints;
    if(cts) fixed_bits = cts->size;

    /* Validate the storage. The padding bits of the last octet are not
     * part of the value: they are written as 0 (as the PER and XER
     * encoders ignore them), whatever the buffer holds. */
    if(!cb || !st || (st->size && !st->buf) || st->bits_unused < 0
       || st->bits_unused > 7 || st->size > SIZE_MAX / 8
       || (st->size == 0 && st->bits_unused != 0))
        ASN__ENCODE_FAILED;
    bit_count = st->size * 8 - (size_t)st->bits_unused;
    if(fixed_bits >= 0
       && ((size_t)fixed_bits != bit_count
           || st->size != ((size_t)fixed_bits + 7) / 8))
        ASN__ENCODE_FAILED;

    if(fixed_bits < 0) {
        ASN__CALLBACK("{", 1);
        if(!minified) ASN__TEXT_INDENT(1, ilevel + 1);
        ASN__CALLBACK(minified ? "\"value\":" : "\"value\": ",
                      minified ? 8 : 9);
    }
    ASN__CALLBACK("\"", 1);
    for(i = 0; i < st->size; i++) {
        unsigned int b = st->buf[i];
        if(i + 1 == st->size)
            b &= 0xffu << st->bits_unused; /* Zero the padding bits */
        if(n + 2 > sizeof(scratch)) {
            ASN__CALLBACK(scratch, n);
            n = 0;
        }
        scratch[n++] = hex[(b >> 4) & 0x0f];
        scratch[n++] = hex[b & 0x0f];
    }
    if(n) {
        ASN__CALLBACK(scratch, n);
    }
    ASN__CALLBACK("\"", 1);
    if(fixed_bits < 0) {
        int written;
        ASN__CALLBACK(",", 1);
        if(!minified) ASN__TEXT_INDENT(1, ilevel + 1);
        ASN__CALLBACK(minified ? "\"length\":" : "\"length\": ",
                      minified ? 9 : 10);
        written = snprintf(scratch, sizeof(scratch), "%lu",
                           (unsigned long)bit_count);
        if(written < 0 || (size_t)written >= sizeof(scratch))
            ASN__ENCODE_FAILED;
        ASN__CALLBACK(scratch, (size_t)written);
        if(!minified) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK("}", 1);
    }
    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

#undef RETURN
#define RETURN(_code)                                  \
    do {                                               \
        rval.code = (_code);                           \
        rval.consumed = (rval.code == RC_OK)           \
                            ? (ssize_t)(p - input) : 0; \
        FREEMEM(new_buf);                              \
        return rval;                                   \
    } while(0)

asn_dec_rval_t
BIT_STRING_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints, void **sptr,
                      const void *buf_ptr, size_t size) {
    static const char empty_input[] = "";
    BIT_STRING_t *st;
    const asn_jer_constraints_t *cts = constraints;
    const char *input = 0, *p = 0, *end;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    uint8_t *new_buf = 0;
    size_t byte_count = 0, bit_count = 0;
    int variable, r;

    (void)opt_codec_ctx;
    if(!sptr || (size && !buf_ptr) || (ssize_t)size < 0) RETURN(RC_FAIL);
    if(!cts && td) cts = td->encoding_constraints.jer_constraints;
    if(cts && cts->size < -1) RETURN(RC_FAIL);
    variable = !cts || cts->size == -1;
    input = buf_ptr ? (const char *)buf_ptr : empty_input;
    p = input;
    end = input + size;

#define BS_CHECK(call) do { r = (call); \
        if(r != BS_OK) RETURN(r == BS_INCOMPLETE ? RC_WMORE : RC_FAIL); \
    } while(0)

    if(variable) {
        int seen_value = 0, seen_length = 0, k;

        BS_CHECK(BIT_STRING__jer_expect_char(&p, end, '{'));
        for(k = 0; k < 2; k++) {
            const char *kstart;
            size_t klen;

            if(k) BS_CHECK(BIT_STRING__jer_expect_char(&p, end, ','));
            BS_CHECK(BIT_STRING__jer_scan_string(&p, end, &kstart, &klen));
            BS_CHECK(BIT_STRING__jer_expect_char(&p, end, ':'));
            if(klen == 5 && memcmp(kstart, "value", 5) == 0 && !seen_value) {
                seen_value = 1;
                BS_CHECK(BIT_STRING__jer_parse_hex(&p, end, &new_buf,
                                                   &byte_count));
            } else if(klen == 6 && memcmp(kstart, "length", 6) == 0
                      && !seen_length) {
                seen_length = 1;
                BS_CHECK(BIT_STRING__jer_parse_length(&p, end, &bit_count));
            } else {
                RETURN(RC_FAIL);  /* Unknown or duplicate member */
            }
        }
        BS_CHECK(BIT_STRING__jer_expect_char(&p, end, '}'));
    } else {
        BS_CHECK(BIT_STRING__jer_parse_hex(&p, end, &new_buf, &byte_count));
        bit_count = (size_t)cts->size;
        if(byte_count != (bit_count + 7) / 8) RETURN(RC_FAIL);
    }

    /* The byte count, the length and the padding bits must agree. */
    if(byte_count > SIZE_MAX / 8 || bit_count > byte_count * 8
       || byte_count * 8 - bit_count > 7)
        RETURN(RC_FAIL);
    if(byte_count && (byte_count * 8 != bit_count)
       && (new_buf[byte_count - 1]
           & ((1u << (byte_count * 8 - bit_count)) - 1u)))
        RETURN(RC_FAIL);

    st = (BIT_STRING_t *)*sptr;
    if(!st) {
        st = (BIT_STRING_t *)CALLOC(1, sizeof(*st));
        if(!st) RETURN(RC_FAIL);
        *sptr = st;
    }
    if(st->buf) FREEMEM(st->buf);
    st->buf = new_buf;
    st->size = byte_count;
    st->bits_unused = (int)(byte_count * 8 - bit_count);
    new_buf = 0;
    RETURN(RC_OK);
}

#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
