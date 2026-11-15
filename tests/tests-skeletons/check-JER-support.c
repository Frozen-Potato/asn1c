/*
 * JER (X.697) support code: the JSON tokenizer (pjson_parse,
 * jer_next_token), jer_check_sym(), jer_whitespace_span(), jer_skip_unknown(),
 * and the generic asn_encode()/asn_decode() entry points while no type
 * implements JER yet. Built with ASN_ENABLE_JER_SUPPORT.
 * (check-JER-disabled.c checks the same entry points with JER compiled out.)
 */
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <asn_internal.h>
#include <asn_application.h>
#include <BOOLEAN.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

#ifdef ASN_DISABLE_JER_SUPPORT
#error This test must be built with ASN_ENABLE_JER_SUPPORT
#endif

/*
 * Tokenize the whole of "in" with jer_next_token() and render the tokens as
 * "<kind><text>" separated by spaces: T text, K key, V value, D delimiter.
 * A trailing "~" means that the tokenizer asked for more data.
 */
static void
tokenize(const char *in, char *out, size_t out_size) {
    size_t n = strlen(in);
    size_t off = 0;
    int state = 0;
    out[0] = '\0';
    while(off < n) {
        pjer_chunk_type_e t = PJER_WMORE;
        ssize_t r = jer_next_token(&state, in + off, n - off, &t);
        size_t len = strlen(out);
        assert(r >= 0);
        if(r == 0) {
            assert(t == PJER_WMORE);
            assert(len + 2 < out_size);
            strcpy(out + len, "~");
            return;
        }
        assert((size_t)r <= n - off);
        assert(t != PJER_WMORE);
        assert(len + (size_t)r + 4 < out_size);
        snprintf(out + len, out_size - len, "%s%c%.*s", len ? " " : "",
                 t == PJER_TEXT ? 'T' : t == PJER_KEY ? 'K'
                 : t == PJER_VALUE ? 'V' : 'D',
                 (int)r, in + off);
        off += (size_t)r;
    }
}

static void
check_tokens(const char *in, const char *expected) {
    char out[512];
    tokenize(in, out, sizeof(out));
    printf("[%s] => [%s] (expected [%s])\n", in, out, expected);
    assert(strcmp(out, expected) == 0);
}

/* Every prefix of the input must be tokenized without overrunning it. */
static void
check_prefixes(const char *in) {
    size_t n = strlen(in);
    size_t len;
    char out[512];
    char *copy = (char *)malloc(n + 1);
    assert(copy);
    for(len = 0; len <= n; len++) {
        /* Exact-size heap copy: sanitizers catch a read past the end */
        char *exact = (char *)malloc(len ? len : 1);
        assert(exact);
        memcpy(exact, in, len);
        memcpy(copy, in, len);
        copy[len] = '\0';
        tokenize(copy, out, sizeof(out));
        {
            int state = 0;
            size_t off = 0;
            while(off < len) {
                pjer_chunk_type_e t;
                ssize_t r = jer_next_token(&state, exact + off, len - off, &t);
                assert(r >= 0 && (size_t)r <= len - off);
                if(r == 0) break;
                off += (size_t)r;
            }
        }
        free(exact);
    }
    free(copy);
}

static void
check_sym(const char *buf, const char *key, jer_check_sym_e expected) {
    jer_check_sym_e r = jer_check_sym(buf, (int)strlen(buf), key);
    printf("jer_check_sym([%s], %s%s%s) = %d (expected %d)\n", buf,
           key ? "[" : "", key ? key : "NULL", key ? "]" : "", (int)r,
           (int)expected);
    assert(r == expected);
}

static void
check_whitespace(const char *buf, size_t expected) {
    size_t r = jer_whitespace_span(buf, strlen(buf));
    printf("jer_whitespace_span([%s]) = %zu (expected %zu)\n", buf, r,
           expected);
    assert(r == expected);
}

/* pjson_parse() with a callback that accepts every chunk. */
struct collect {
    int chunks;
    size_t bytes;
    int saw_key_end;
    int saw_value_end;
};
static int
collect_cb(pjson_chunk_type_e type, const void *data, size_t size, void *key) {
    struct collect *c = (struct collect *)key;
    (void)data;
    c->chunks++;
    c->bytes += size;
    if(type == PJSON_KEY_END) c->saw_key_end = 1;
    if(type == PJSON_VALUE_END) c->saw_value_end = 1;
    return (int)size;
}

static void
check_pjson_parse(void) {
    static const char in[] = "{\"k\": [1, \"a\\\"b\"]}";
    struct collect c;
    int state = 0;
    ssize_t consumed;
    memset(&c, 0, sizeof(c));
    consumed = pjson_parse(&state, in, sizeof(in) - 1, collect_cb, &c);
    printf("pjson_parse: consumed %ld of %lu, %d chunks\n", (long)consumed,
           (unsigned long)(sizeof(in) - 1), c.chunks);
    assert(consumed >= 0 && (size_t)consumed <= sizeof(in) - 1);
    assert(c.bytes == (size_t)consumed);
    assert(c.chunks > 0);
    assert(c.saw_key_end);

    /* An empty buffer consumes nothing and keeps the state. */
    state = 0;
    memset(&c, 0, sizeof(c));
    consumed = pjson_parse(&state, "", 0, collect_cb, &c);
    assert(consumed == 0 && c.chunks == 0 && state == 0);
}

static void
check_skip_unknown(void) {
    ber_tlv_len_t depth = 1;
    /* A key opens one more level; a comma/closer at depth 1 ends the skip. */
    assert(jer_skip_unknown(JCK_KEY, &depth) == 0 && depth == 2);
    assert(jer_skip_unknown(JCK_COMMA, &depth) == 0 && depth == 1);
    assert(jer_skip_unknown(JCK_COMMA, &depth) == 1 && depth == 0);
    depth = 1;
    assert(jer_skip_unknown(JCK_OEND, &depth) == 2 && depth == 0);
    depth = 1;
    assert(jer_skip_unknown(JCK_BROKEN, &depth) == -1);
    assert(jer_skip_unknown(JCK_OSTART, &depth) == -1);
}

/*
 * The generic entry points must fail cleanly (and not crash) for a type with
 * empty JER slots. The primitive types implement JER now (see check-JER.c),
 * so this is a BOOLEAN descriptor with its JER slots cleared.
 */
static void
check_type_without_jer(void) {
    static asn_TYPE_operation_t op_nojer;
    static asn_TYPE_descriptor_t td_nojer;
    BOOLEAN_t b = 1;
    BOOLEAN_t *decoded = NULL;
    char buf[64];
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    asn_encode_to_new_buffer_result_t nb;

    assert(asn_DEF_BOOLEAN.op->jer_encoder != NULL);
    assert(asn_DEF_BOOLEAN.op->jer_decoder != NULL);
    assert(asn_DEF_BOOLEAN.encoding_constraints.jer_constraints == NULL);
    op_nojer = asn_OP_BOOLEAN;
    op_nojer.jer_encoder = NULL;
    op_nojer.jer_decoder = NULL;
    td_nojer = asn_DEF_BOOLEAN;
    td_nojer.op = &op_nojer;

    errno = 0;
    er = asn_encode_to_buffer(0, ATS_JER, &td_nojer, &b, buf,
                              sizeof(buf));
    assert(er.encoded == -1 && errno == ENOENT);
    errno = 0;
    er = asn_encode_to_buffer(0, ATS_JER_MINIFIED, &td_nojer, &b, buf,
                              sizeof(buf));
    assert(er.encoded == -1 && errno == ENOENT);
    errno = 0;
    nb = asn_encode_to_new_buffer(0, ATS_JER, &td_nojer, &b);
    assert(nb.result.encoded == -1 && errno == ENOENT);
    free(nb.buffer); /* may be non-NULL on failure; free(NULL) is fine */

    errno = 0;
    dr = asn_decode(0, ATS_JER, &td_nojer, (void **)&decoded, "true",
                    4);
    assert(dr.code == RC_FAIL && dr.consumed == 0 && errno == ENOENT);
    assert(decoded == NULL);
    errno = 0;
    dr = asn_decode(0, ATS_JER_MINIFIED, &td_nojer,
                    (void **)&decoded, "true", 4);
    assert(dr.code == RC_FAIL && errno == ENOENT);
    assert(decoded == NULL);

    /* The direct entry points have the same contract. */
    dr = jer_decode(0, &td_nojer, (void **)&decoded, "true", 4);
    assert(dr.code == RC_FAIL && decoded == NULL);
    er = jer_encode(&td_nojer, &b, JER_F, 0, 0);
    assert(er.encoded == -1);
}

int
main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* keep the output when an assert aborts */

    /* Scalars, strings and escapes */
    check_tokens("true", "Vtrue");
    check_tokens("42", "V42");
    check_tokens("\"abc\"", "V\"abc\"");
    check_tokens("\"q\\\"uote\"", "V\"q\\\"uote\"");
    check_tokens("\"back\\\\slash\"", "V\"back\\\\slash\"");
    check_tokens("\"a,b}c]\"", "V\"a,b}c]\"");

    /* Flat objects, whitespace around keys and values */
    check_tokens("{\"a\":1}", "D{ K\"a\" T: V1 V}");
    check_tokens("{\"a\":1,\"b\":2}",
                 "D{ K\"a\" T: V1 V, K\"b\" T: V2 V}");
    check_tokens("{\"a\": \"x\"}", "D{ K\"a\" T:  V\"x\" V}");
    check_tokens("{\"a\":true}", "D{ K\"a\" T: Vtrue V}");
    check_tokens("{ \"a\" : 1 }", "D{ T  K\"a\" T :  V1  V}");
    check_tokens("{\"a\": 1, \"b\": \"x,y}\"}",
                 "D{ K\"a\" T:  V1 V, T  K\"b\" T:  V\"x,y}\" V}");
    check_tokens("{\"a\": \"q\\\"uote\"}",
                 "D{ K\"a\" T:  V\"q\\\"uote\" V}");
    check_tokens("{\"a\\\"b\":1}", "D{ K\"a\\\"b\" T: V1 V}");

    /* Arrays, nested arrays */
    check_tokens("[1]", "D[ V1 V]");
    check_tokens("[]", "D[ D]");
    check_tokens("[1, 2, 3]", "D[ V1 T,  V2 T,  V3 V]");
    check_tokens("[\"a,b\", \"c]\"]", "D[ V\"a,b\" T,  V\"c]\" V]");
    check_tokens("[[1,2],[3]]", "D[ D[ V1 T, V2 V] D,[ V3 V] V]");

    /* Truncated buffers ask for more data */
    check_tokens("", "");
    check_tokens("{\"a", "D{~");
    check_tokens("{\"a\":1", "D{ K\"a\" T:~");
    check_tokens("{\"a\":\"x", "D{ K\"a\" T:~");
    check_tokens("[1", "D[~");

    check_prefixes("{\"a\": 1, \"b\": \"x,y}\"}");
    check_prefixes("{\"a\":[1,\"q\\\"\",[2]],\"b\":{}}");
    check_prefixes("[[1,2],[\"s\\\\\"],[]]");
    check_prefixes("\"unterminated \\");

    check_pjson_parse();

    /* Key and delimiter matching */
    check_sym("\"abc\"", "abc", JCK_KEY);
    check_sym("\"abd\"", "abc", JCK_UNKNOWN);
    check_sym("\"abcd\"", "abc", JCK_UNKNOWN);
    check_sym("\"ab\"", "abc", JCK_UNKNOWN);
    check_sym("\"abc def\"", "abc", JCK_KEY);
    check_sym("\"\"", "", JCK_KEY);
    check_sym("abc", "abc", JCK_BROKEN);
    check_sym("\"abc", "abc", JCK_BROKEN);
    check_sym("\"", "abc", JCK_BROKEN);
    check_sym("{", NULL, JCK_OSTART);
    check_sym("}", NULL, JCK_OEND);
    check_sym("[", NULL, JCK_ASTART);
    check_sym("]", NULL, JCK_AEND);
    check_sym(",", NULL, JCK_COMMA);
    check_sym(",[", NULL, JCK_ASTART);
    check_sym("1", NULL, JCK_UNKNOWN);

    check_whitespace("", 0);
    check_whitespace("abc", 0);
    check_whitespace("   abc", 3);
    check_whitespace(" \t\r\n x", 5);
    check_whitespace("   ", 3);
    assert(jer_whitespace_span(NULL, 0) == 0);

    check_skip_unknown();
    check_type_without_jer();

    printf("check-JER-support: OK\n");
    return 0;
}
