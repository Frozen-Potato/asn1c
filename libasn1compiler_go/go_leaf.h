/*
 * go_leaf.h — the leaf body kinds shared by the Go back end's TUs.
 *
 * go_names.c sets a kind during its walk (it holds the live arg_t/terminal
 * context asn1c_type_fits_long needs); go_types.c maps it to the Go type text;
 * go_flat.c maps it to the Flat column C prim token and the string/OID flags.
 * One definition, so the three tables cannot drift. Cross-TU prototypes keep
 * the kind as a plain int (go_constructs.h stays construct-vocabulary-only).
 */
#ifndef GO_LEAF_H
#define GO_LEAF_H

typedef enum {
    GLEAF_NONE = 0,      /* not a leaf / no body data (structs, choices...) */
    GLEAF_INT64,         /* INTEGER → int64 (wide, signed)                   */
    GLEAF_UINT64,        /* INTEGER → uint64 (wide unsigned / INTEGER_t
                            range fitting uint64)                           */
    GLEAF_BOOL,          /* BOOLEAN → bool                                  */
    GLEAF_NULL,          /* NULL → struct{}                                 */
    GLEAF_REAL,          /* REAL → float64                                  */
    GLEAF_OCTETS,        /* OCTET STRING / unresolved open type → []byte    */
    GLEAF_OID,           /* OBJECT IDENTIFIER → []uint64 arcs               */
    GLEAF_STRING,        /* retired: no longer produced (PrintableString is
                            GLEAF_STRING_Z now); the enumerator stays so the
                            numbering of the kinds below is unchanged       */
    GLEAF_BITSTRING,     /* BIT STRING → the BitString helper type          */
    GLEAF_ENUM,          /* ENUMERATED → int32 + const block                */
    GLEAF_STRING_BMP,    /* BMPString → string (UCS-2 in C, UTF-8 in Go)    */
    GLEAF_STRING_UNIV,   /* UniversalString → string (UCS-4 in C, UTF-8)    */
    GLEAF_STRING_Z,      /* every restricted string / time type (PrintableString
                            included) → string, bytes as-is, buffer allocated
                            even when empty */
    GLEAF_ROID           /* RELATIVE-OID → []uint64 arcs                    */
} go_leaf_kind;

/* The Flat-column C prim token of a leaf kind; NULL for GLEAF_NONE and
 * GLEAF_NULL (a NULL TYPE assignment mints no Flat leaf; an OPTIONAL NULL
 * member is an int32 prim row elsewhere). */
static inline const char *
go_leaf_flat_prim(int k) {
    switch(k) {
    case GLEAF_INT64:      return "int64_t";
    case GLEAF_UINT64:     return "uint64_t";
    case GLEAF_BOOL:       return "_bool32";
    case GLEAF_REAL:       return "double";
    case GLEAF_OCTETS:
    case GLEAF_OID:
    case GLEAF_STRING:
    case GLEAF_STRING_BMP:
    case GLEAF_STRING_UNIV:
    case GLEAF_STRING_Z:
    case GLEAF_ROID:       return "asn1cgo_bytes_flat";
    case GLEAF_BITSTRING:  return "asn1cgo_bits_flat";
    case GLEAF_ENUM:       return "int32_t";
    default:               return NULL;
    }
}

#endif /* GO_LEAF_H */
