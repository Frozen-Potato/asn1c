/*
 * asn1cgo shared Flat primitives.
 * Hand-authored; included by every unit's _flat.h.
 */
#ifndef ASN1CGO_RT_TYPES_H
#define ASN1CGO_RT_TYPES_H

#include <stddef.h>
#include <stdint.h>

/*
 * Bytes-shaped Flat member, used for OCTET STRING, all the character string
 * types (PrintableString/UTF8String/...), OBJECT IDENTIFIER, REAL-as-
 * bytes, and the big INTEGER_t row. `buf` points into the owning arena for
 * `_from_tree` output, or into the Go-side malloc'd block for encode (Flat
 * is read-only to the C side). Owned by the enclosing block's
 * lifetime either way.
 *
 * `len` is in bytes. There is intentionally no NUL terminator carried: the
 * codec layer copies the exact `len` bytes.
 */
typedef struct asn1cgo_bytes_flat {
    uint8_t *buf;
    size_t   len;
} asn1cgo_bytes_flat;

/*
 * BIT STRING Flat: {buf, len, bits_unused}.
 */
typedef struct asn1cgo_bits_flat {
    uint8_t *buf;
    size_t   len;          /* byte length of buf */
    int32_t  bits_unused;  /* 0..7 in the final byte */
} asn1cgo_bits_flat;

#endif /* ASN1CGO_RT_TYPES_H */
