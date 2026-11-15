/*
 * JER is opt-in: without ASN_ENABLE_JER_SUPPORT the generic entry points
 * must fail cleanly (ENOENT / RC_FAIL) and must not crash. This test is built
 * WITHOUT that macro and linked with the library built without it.
 */
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <asn_application.h>
#include <BOOLEAN.h>

#ifndef ASN_DISABLE_JER_SUPPORT
#error JER must be compiled out in this test
#endif

int
main(void) {
    BOOLEAN_t b = 1;
    BOOLEAN_t *decoded = NULL;
    char buf[64];
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    asn_encode_to_new_buffer_result_t nb;

    /* The slots exist (same layout either way) and are empty. */
    assert(asn_DEF_BOOLEAN.op->jer_encoder == NULL);
    assert(asn_DEF_BOOLEAN.op->jer_decoder == NULL);
    assert(asn_DEF_BOOLEAN.encoding_constraints.jer_constraints == NULL);

    errno = 0;
    er = asn_encode_to_buffer(0, ATS_JER, &asn_DEF_BOOLEAN, &b, buf,
                              sizeof(buf));
    assert(er.encoded == -1 && errno == ENOENT);
    errno = 0;
    er = asn_encode_to_buffer(0, ATS_JER_MINIFIED, &asn_DEF_BOOLEAN, &b, buf,
                              sizeof(buf));
    assert(er.encoded == -1 && errno == ENOENT);
    errno = 0;
    nb = asn_encode_to_new_buffer(0, ATS_JER, &asn_DEF_BOOLEAN, &b);
    assert(nb.result.encoded == -1 && errno == ENOENT);
    free(nb.buffer); /* may be non-NULL on failure; free(NULL) is fine */

    errno = 0;
    dr = asn_decode(0, ATS_JER, &asn_DEF_BOOLEAN, (void **)&decoded, "true",
                    4);
    assert(dr.code == RC_FAIL && dr.consumed == 0 && errno == ENOENT);
    assert(decoded == NULL);
    errno = 0;
    dr = asn_decode(0, ATS_JER_MINIFIED, &asn_DEF_BOOLEAN,
                    (void **)&decoded, "true", 4);
    assert(dr.code == RC_FAIL && errno == ENOENT);
    assert(decoded == NULL);

    /* Other syntaxes are unaffected. */
    er = asn_encode_to_buffer(0, ATS_BASIC_XER, &asn_DEF_BOOLEAN, &b, buf,
                              sizeof(buf));
    assert(er.encoded > 0);

    printf("check-JER-disabled: OK\n");
    return 0;
}
