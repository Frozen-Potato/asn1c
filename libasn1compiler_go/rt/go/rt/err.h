/*
 * asn1cgo error model.
 * Shared across all spec packages.
 */
#ifndef ASN1CGO_RT_ERR_H
#define ASN1CGO_RT_ERR_H

#include <stddef.h>

#define ASN1CGO_MAX_DEPTH 64   /* recursion cap */

typedef enum {
    ASN1CGO_OK               =  0,
    ASN1CGO_E_ARG            = -1,   /* NULL argument */
    ASN1CGO_E_ALLOC          = -2,
    ASN1CGO_E_CONSTRAINT     = -3,   /* asn_check_constraints failed */
    ASN1CGO_E_ENCODE         = -4,   /* asn_encode_* failed */
    ASN1CGO_E_DECODE         = -5,   /* asn_decode failed */
    ASN1CGO_E_TRAILING       = -6,   /* bytes left after the PDU */
    ASN1CGO_E_CHOICE_NOTHING = -7,
    ASN1CGO_E_CHOICE_BAD     = -8,
    ASN1CGO_E_IOC_UNKNOWN    = -9,   /* IE id not in the governing IOC object set.
                                      * Encode: checked first. (Decode: asn1c's
                                      * decoder already rejects unknown ids as
                                      * E_DECODE, so it is defensive only.) */
    ASN1CGO_E_IOC_MISMATCH   = -10,  /* known IE id, but the selected value
                                      * alternative is not the one it governs */
    ASN1CGO_E_DEPTH          = -11,  /* recursion depth cap exceeded */
    ASN1CGO_E_INTERNAL       = -12   /* generator invariant violated at runtime */
} asn1cgo_err_code;

typedef struct {
    asn1cgo_err_code code;
    const char *type_name;   /* innermost type; static string from generated code or td->name */
    const char *field;       /* innermost member, or NULL */
    char        msg[256];    /* constraint path / codec message, NUL-terminated */
    int         depth;       /* recursion depth counter, internal */
} asn1cgo_err;

/*
 * Populate *e with code/type/field (msg truncated from the optional 4th
 * var-arg string). Returns the code passed in, so call sites can write
 * `return asn1cgo_fail(err, C, T, F);`. e may be NULL (used by tests that
 * discard detail).
 */
int asn1cgo_fail(asn1cgo_err *e, asn1cgo_err_code c, const char *type,
                 const char *field, const char *msg_fmt, ...);

/* Length of the message currently held in e (excluding NUL). */
size_t asn1cgo_err_msg_len(const asn1cgo_err *e);

#endif /* ASN1CGO_RT_ERR_H */
