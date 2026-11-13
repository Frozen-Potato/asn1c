/*
 * go_constructs.h — classification of ASN.1 constructs for the Go backend.
 *
 * This is the generator's own vocabulary: an enum of the construct kinds it
 * recognizes, plus the runtime helpers that classify an ASN.1 expression into
 * one of them. Anything that does not map onto a supported kind is reported as
 * GO_CONSTR_UNSUPPORTED, which the walker turns into a loud, non-zero failure
 * naming the module, type and member.
 */
#ifndef	GO_CONSTRUCTS_H
#define	GO_CONSTRUCTS_H

#include <stddef.h>             /* size_t (needed before asn1_*.h headers) */
#include <stdio.h>              /* FILE (go_types_emit_* prototypes below) */
#include <asn1parser.h>     /* asn1p_expr_t, asn1p_t */

/*
 * Walk the AST, classify every construct, write optional coverage. Implemented
 * in go_walk.c; declared here so go_backend.c sees a prototype (avoids
 * -Wmissing-prototypes at definition).
 */
int go_walk_asts(asn1p_t *asn);

/*
 * SEQUENCE OF and SET OF share one C layout (A_SEQUENCE_OF(T) is A_SET_OF(T))
 * and one Go shape ([]Elem), so every raw expr_type test that means "a list"
 * goes through this predicate. Only the canonical-order sort on Encode and the
 * ASN_SET_ADD / ASN_SEQUENCE_ADD spelling differ.
 */
#define go_is_list_kind(t) ((t) == ASN_CONSTR_SEQUENCE_OF || (t) == ASN_CONSTR_SET_OF)

typedef enum go_construct {
    GO_CONSTR_SEQUENCE,         /* SEQUENCE (record)            asn1p_expr.h ASN_CONSTR_SEQUENCE  */
    GO_CONSTR_CHOICE,           /* CHOICE                        ASN_CONSTR_CHOICE  */
    GO_CONSTR_SEQUENCE_OF,      /* SEQUENCE OF / SET OF          ASN_CONSTR_SEQUENCE_OF ASN_CONSTR_SET_OF  */
    GO_CONSTR_ENUMERATED,       /* ENUMERATED                    ASN_BASIC_ENUMERATED  */
    GO_CONSTR_OPTIONAL,         /* OPTIONAL member (marker)      EM_OPTIONAL  */
    GO_CONSTR_DEFAULT,          /* DEFAULT member (marker)       EM_DEFAULT  */
    GO_CONSTR_EXTMARK,          /* extension marker "..."        A1TC_EXTENSIBLE  */
    GO_CONSTR_BIT_STRING,       /* BIT STRING                    ASN_BASIC_BIT_STRING  */
    GO_CONSTR_OCTET_STRING,     /* OCTET STRING                  ASN_BASIC_OCTET_STRING  */
    GO_CONSTR_INTEGER,          /* INTEGER (width resolved later) ASN_BASIC_INTEGER  */
    GO_CONSTR_BOOLEAN,          /* BOOLEAN                       ASN_BASIC_BOOLEAN  */
    GO_CONSTR_NULL,             /* NULL                          ASN_BASIC_NULL  */
    GO_CONSTR_REAL,             /* REAL                          ASN_BASIC_REAL  */
    GO_CONSTR_OID,              /* OBJECT IDENTIFIER / RELATIVE-OID  ASN_BASIC_OBJECT_IDENTIFIER ASN_BASIC_RELATIVE_OID  */
    GO_CONSTR_STRING,           /* every restricted string type + UTCTime/GeneralizedTime  ASN_STRING_* ASN_BASIC_UTCTime ASN_BASIC_GeneralizedTime  */
    GO_CONSTR_IOC_CLASS,        /* Information Object Class      AMT_OBJECTCLASS / A1TC_CLASSDEF  */
    GO_CONSTR_IOC_OBJSET,       /* object-set {{ }} usage        AMT_VALUESET / AMT_OBJECT  */
    GO_CONSTR_OPEN_TYPE,        /* open type class-field (&F)    lowercase &F reference (asn1c_C.c:305)  */
    GO_CONSTR_RECURSIVE_REF,    /* recursive back-reference      marker EM_UNRECURSE (asn1c_C.c:3483)  */

    GO_CONSTR_UNSUPPORTED,
    GO_CONSTR__COUNT            /* sentinel: number of real kinds, excl. UNSUPPORTED */
} go_construct_e;

/*
 * classify() returns the construct kind of an expression's *terminal* type
 * (the caller is responsible for dereferencing). Markers (OPTIONAL / DEFAULT /
 * RECURSIVE_REF) are NOT applied here — they annotate the terminal kind at the
 * caller, they never replace it (see go_walk.c). classify() of a member's bare
 * reference expression therefore first goes through the reference-shape path
 * (open type / fixed-type class field) in the walker.
 */
go_construct_e go_construct_classify(const asn1p_expr_t *terminal);

/* Short, stable tag for diagnostics + tooling. Never NULL. */
const char *go_construct_name(go_construct_e);

/*
 * GO_CONSTR_STRING covers every restricted character string type and both
 * time types; they differ only in what the Go glue does with the C buffer.
 * go_string_subkind picks that (plain: the same bytes; BMP: UCS-2 big-endian
 * <-> UTF-8; Universal: UCS-4 big-endian <-> UTF-8). go_construct_name_of
 * is go_construct_name for a classified terminal but prints the real ASN.1
 * type name for a GO_CONSTR_STRING ("IA5String", "UTCTime", ...);
 * go_string_ctype is the C typedef name of such a terminal ("IA5String_t").
 */
typedef enum go_string_sub {
    GO_STR_PLAIN = 0,           /* bytes as-is (including UTF8String, times)  */
    GO_STR_BMP,                 /* UCS-2 big-endian in C, UTF-8 in Go          */
    GO_STR_UNIVERSAL            /* UCS-4 big-endian in C, UTF-8 in Go          */
} go_string_sub_e;
go_string_sub_e go_string_subkind(const asn1p_expr_t *terminal);
const char *go_construct_name_of(const asn1p_expr_t *terminal);
const char *go_string_ctype(const asn1p_expr_t *terminal);

/*
 * GO_CONSTR_OID covers OBJECT IDENTIFIER and RELATIVE-OID: both are
 * ASN__PRIMITIVE_TYPE_t in C and []uint64 arcs in Go. go_oid_is_relative
 * tells them apart (the C arc functions differ).
 */
int go_oid_is_relative(const asn1p_expr_t *terminal);

/*
 * The skeleton headers (beyond the always-copied set) the string types
 * classified so far need in internal/cspec/rt. A bitmask over
 * go_string_hdr_name() indices; the entry copies exactly those. A tree
 * without such a type copies none (byte-identical to the PrintableString-only
 * output).
 */
unsigned go_string_hdr_mask(void);
const char *go_string_hdr_name(int idx);   /* NULL past the end */

/*
 * Reference-shape predicates. These read a member that is still an
 * A1TC_REFERENCE and decide how to resolve it — BEFORE any terminal chase:
 *
 *   go_construct_is_open_type        — uppercase "&Value" open-type field.
 *                                      Mirrors is_open_type() in asn1c_C.c:305.
 *   go_construct_is_classfield_ref   — any 2-component "&field" class-field
 *                                      reference (upper- or lowercase). The
 *                                      caller distinguishes the two; lowercase
 *                                      (&id/&criticality/&presence) is resolved
 *                                      to the class's declared field type, the
 *                                      way asn1c_C.c:2653-2655/2710-2720 do.
 *   go_construct_is_classfield_fixedtype — lowercase "&field" only.
 */
int go_construct_is_open_type(const asn1p_expr_t *expr);
int go_construct_is_classfield_ref(const asn1p_expr_t *expr);
int go_construct_is_classfield_fixedtype(const asn1p_expr_t *expr);

/*
 * No "[[ ... ]]" bracket-group predicate: the C emit pass mints `ext<N>` on the
 * shared AST (asn1c_C.c:378-385/618-633) before this walker runs, so a group
 * is an OPTIONAL inline SEQUENCE member named ext<N> and needs no special
 * case. See go_constructs.c.
 *
 * A named-bit BIT STRING (`BIT STRING { a(0), b(1) }`) is supported: it maps
 * exactly like a plain BIT STRING (the value type is unchanged) and only adds
 * a block of int bit-position constants (go_names.c, emit_bit_names).
 */

/*
 * Leaf-type emission (go_types.c). Flat prototypes here (no new
 * header): go_names.c drives them while it holds the per-module types.go
 * FILE open.
 */
int go_types_emit_leaf(FILE *out, const char *go_name, int leaf_kind);
int go_types_emit_slice(FILE *out, const char *go_name, const char *elem);
int go_types_emit_bitstring(FILE *out);
int go_types_emit_const(FILE *out, const char *name, const char *type,
                        const char *value, int name_w, int type_w);
int go_types_emit_const_open(FILE *out);
int go_types_emit_const_open_bits(FILE *out, const char *asn1_type);
int go_types_emit_const_close(FILE *out);

/*
 * Struct-body emission (go_types.c). The leaf-kind-to-Go-type mapping-table
 * text for a
 * leaf kind (NULL when the kind is not a bare primitive — GLEAF_ENUM's type
 * is the ENUM assignment's own named type). Un-enumerated int return
 * (the go_leaf_kind enum stays private to the two go TUs). go_names.c's
 * member walk resolves each field's Go type through this same table.
 */
const char *go_types_leaf_underlying(int leaf_kind);

/*
 * Struct-body emission (go_types.c): open a `type X struct {` decl,
 * write one column-aligned `Name Type` field line, close it. Column widths are
 * the caller's (two-pass over the whole struct, like the const block).
 */
int go_types_emit_struct_open(FILE *out, const char *go_name);
int go_types_emit_struct_field(FILE *out, const char *name, const char *type,
                               int name_w, int type_w);
int go_types_emit_struct_close(FILE *out);

#endif	/* GO_CONSTRUCTS_H */
