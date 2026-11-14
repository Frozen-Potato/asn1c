/*
 * go_types.c — leaf-type body emission (declarations only).
 *
 * Consumes the leaf body data the go_names.c walk attaches to name rows and
 * writes the DECLARATION side of each package's types.go:
 *
 *   type X <underlying>            one per leaf type assignment (every
 *                                  type assignment is a named Go type; the
 *                                  underlying is the leaf-kind-to-Go-type
 *                                  mapping table):
 *                                    INTEGER  int64 / uint64 (wide; the class
 *                                             comes from asn1c_type_fits_long
 *                                             — asn1c's own decision — plus,
 *                                             for the INTEGER_t case, the PER
 *                                             range asn1c itself computes)
 *                                             INTEGER_t fitting neither int64
 *                                             nor uint64, or unconstrained
 *                                             under -fwide-types → the walk
 *                                             already FAILED (exit 70); a
 *                                             leaf row never carries "neither"
 *                                    BOOLEAN  bool
 *                                    NULL     struct{}
 *                                    REAL     float64
 *                                    OCTET STRING / unresolved open type
 *                                             []byte (the mapping table's
 *                                             OCTET STRING row)
 *                                    OBJECT IDENTIFIER []byte
 *                                    string types string
 *                                    BIT STRING BitString (the helper below)
 *                                    ENUMERATED int32 + a const block
 *   type X BitString struct {...}  the shared helper, once per module that
 *                                  owns a BIT-STRING member (the mapping
 *                                  table's BIT STRING row)
 *   type XPr int32                 CHOICE discriminants + const block
 *                                  <X>PrNothing = 0 and one const per alt,
 *                                  values mirroring asn1c's own numbering:
 *                                  sequential from NOTHING=0 over the alt
 *                                  list (asn1c_C.c:984-996 emits the _PR
 *                                  enum with NO explicit values — implicit
 *                                  0,1,2,... — over the same TQ_FOR order)
 *   const N T = v                 ENUMERATED consts; the value
 *                                  is the enumerator's own ASN.1 value
 *                                  (v->value->value.v_integer — the same
 *                                  field asn1c_C.c:152 prints as " = N").
 *   const N T = v                 value consts: typed by the governing
 *                                  named type, value from the same
 *                                  expr->value->value.v_integer asn1c_C.c:
 *                                  1264 prints.
 *
 * Bodies (struct fields, CHOICE alt pointer sets, flat structs, converters)
 * are struct-body stage — this file emits exactly the self-contained declaration set.
 *
 * The value-union const blocks (<X>ValuePr) mirror the open-type
 * emission order asn1c itself uses (asn1c_C.c asn1c_lang_C_OpenType:1078-
 * 1093: object-set ROW order, deduped by Identifier) — NOT the ASN.1 object
 * set's numeric procedureCode/id. Verified: InitiatingMessage__value_PR
 * numbers SubscriptionRequest=1 (row 1) and ErrorIndication=23 (row 23 of
 * an ELEMENTARY-PROCEDURES set — object rows keep their set order across the
 * class-merge and the extension marker); procedureCode(ErrorIndication)=2
 * would number it 3 — the .h says 23 (InitiatingMessage.h:88-110).
 *
 * This TU owns NO walk of its own: everything it prints comes from row data
 * go_names.c recorded. The interface between the two is one function
 * per declaration family below; go_names.c calls them as it emits each row
 * into its per-module buffer (go_names.c owns the FILE lifecycle).
 */
/* go_types.c */
#include "go_constructs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "go_leaf.h"

/* go_leaf_underlying: the mapping-table Go text for a leaf kind. go_names.c
 * reaches it through go_types_leaf_underlying below (the int-typed public
 * face), so a plain leaf member's field type and the leaf's own `type X`
 * declaration both come from this one map. GLEAF_ENUM maps to "int32" (the
 * decl emission needs it: `type X int32`); a leaf ENUM MEMBER's field type is
 * the ENUM assignment's own named type instead, which the field-type
 * resolution in go_names.c decides BEFORE consulting this table. */
static const char *
go_leaf_underlying(go_leaf_kind k) {
    switch(k) {
    case GLEAF_INT64:     return "int64";
    case GLEAF_UINT64:    return "uint64";
    case GLEAF_BOOL:      return "bool";
    case GLEAF_NULL:      return "struct{}";
    case GLEAF_REAL:      return "float64";
    case GLEAF_OCTETS:    return "[]byte";
    case GLEAF_OID:
    case GLEAF_ROID:      return "[]uint64";
    case GLEAF_STRING:
    case GLEAF_STRING_BMP:
    case GLEAF_STRING_UNIV:
    case GLEAF_STRING_Z:  return "string";
    case GLEAF_BITSTRING: return "BitString";
    case GLEAF_ENUM:      return "int32";
    default:              return NULL;
    }
}

/* Public alias for the header prototype (go_constructs.h): the un-enumerated
 * int form go_names.c calls (the int ABI keeps go_constructs.h free of the
 * go_leaf_kind enum). */
const char *
go_types_leaf_underlying(int leaf_kind) {
    return go_leaf_underlying((go_leaf_kind)leaf_kind);
}

/*
 * go_types_emit_leaf - write one leaf type-row's `type X <underlying>` line
 * into the module's types.go (FILE owned by go_names.c). Returns 0 ok, -1 on
 * write error (caller fails the run).
 */
int
go_types_emit_leaf(FILE *out, const char *go_name, int leaf_kind) {
    const char *under = go_leaf_underlying((go_leaf_kind)leaf_kind);
    if(!under) return 0;             /* not a leaf row: nothing to declare */
    if(fprintf(out, "type %s %s\n", go_name, under) < 0) return -1;
    return 0;
}

/*
 * go_types_emit_slice (slice stage) - write one slice-owner row's named slice
 * alias `type X []Elem`: a SEQUENCE-OF type assignment (the naming rule's
 * slice-alias row), an anonymous inline SEQUENCE-OF at a member, or a
 * parameterized container specialization use (`<Msg>ProtocolIEs`), both the
 * anonymous-inline naming rule's `type
 * <Parent><Member> []Elem` form. The element text is verbatim what the walk
 * stored (slice_element_type: a reference element's assignment goName —
 * cross-module qualified by the prepass — or the leaf-kind mapping table for a leaf).
 */
int
go_types_emit_slice(FILE *out, const char *go_name, const char *elem) {
    if(fprintf(out, "type %s []%s\n", go_name, elem) < 0) return -1;
    return 0;
}

/*
 * go_types_emit_bitstring - the shared BIT STRING helper (the mapping
 * table's BIT STRING row
 * text), fixed text
 * (`struct { Bytes []byte; BitsUnused int32 }`). One per module
 * that owns a BIT-STRING member; go_names.c calls it once per such module.
 */
int
go_types_emit_bitstring(FILE *out) {
    if(fprintf(out,
               "type BitString struct {\n"
               "\tBytes      []byte\n"
               "\tBitsUnused int32\n"
               "}\n") < 0)
        return -1;
    return 0;
}

/*
 * go_types_emit_const - write one const line into a (caller-opened,
 * caller-closed) const block: `Name Type = value`, COLUMN-ALIGNED the way
 * gofmt aligns a const block (gofmt is the formatting gate; the emitted bytes must be gofmt-clean verbatim — verified:
 * gofmt pads the name column to maxNameLen+1, then the type column to
 * maxTypeLen+1, single spaces, "= value"; a wrong layout keeps the semantic
 * content but fails `gofmt -l`). Every const re-states its type. value is the decimal string asn1p_itoa produced during the walk
 * (asn1c's own rendering; asn1p_integer.h:39).
 *
 * The caller buffers the block (name/type/value triples) so the columns are
 * computed over the WHOLE block in one pass: this function writes one
 * pre-aligned line given the two column widths.
 */
int
go_types_emit_const(FILE *out, const char *name, const char *type,
                    const char *value, int name_w, int type_w) {
    /* name_w/type_w already include the +1 separator column (caller added
     * it when computing maxima), so pad each field to exactly its width. */
    if(fprintf(out, "\t%-*s %-*s = %s\n",
               name_w - 1, name, type_w - 1, type, value) < 0)
        return -1;
    return 0;
}

/*
 * go_types_emit_const_open / _close - the const-block fence, in gofmt's
 * canonical layout: a BLANK line separates the previous decl from a const
 * block (and the block from the next decl) — gofmt inserts one wherever
 * decl groups meet. The close writes ")\n" only; the blank line BEFORE the
 * next decl is the next decl's own leading blank (see go_types_emit_leaf:
 * every decl after a closed const block leads with "\n").
 */
int
go_types_emit_const_open(FILE *out) {
    return fputs("\nconst (\n", out) < 0 ? -1 : 0;
}

/*
 * go_types_emit_const_open_bits - the const-block fence of a named-bit
 * BIT STRING's bit positions: the same canonical layout as _open, with a
 * `// bit positions of <ASN.1 type>` comment attached directly above the
 * `const (` (no blank line in between, so gofmt keeps it a doc comment).
 */
int
go_types_emit_const_open_bits(FILE *out, const char *asn1_type) {
    return fprintf(out, "\n// bit positions of %s\nconst (\n", asn1_type) < 0
        ? -1 : 0;
}
int
go_types_emit_const_close(FILE *out) {
    return fputs(")\n", out) < 0 ? -1 : 0;
}

/*
 * Struct bodies (SEQUENCE type assignments, anonymous inline
 * SEQUENCEs, field-shaped specializations, open-type value unions; the
 * <T>Pr-decl + alt-struct CHOICE bodies come with their steps).
 *
 * go_types_emit_struct_open - `type X struct {`. The trailing newline-less
 * brace line; fields follow one per line; go_types_emit_struct_close writes
 * the closing brace. Blank-line separation is the caller's (the decl-walk
 * state machine in go_names.c): the same leading-"\n" rule the leaf/const
 * decls use.
 */
int
go_types_emit_struct_open(FILE *out, const char *go_name) {
    if(fprintf(out, "type %s struct {\n", go_name) < 0) return -1;
    return 0;
}

/*
 * go_types_emit_struct_field - one `Name Type` line, COLUMN-ALIGNED the way
 * gofmt aligns consecutive field lines in a struct: the NAME column pads to
 * the max name width (+1 separator) so the types align; the TYPE is written
 * verbatim — gofmt never pads after a struct field's type (the last column
 * on the line), so trailing-pad here would fail `gofmt -l`. (The const block
 * DOES pad its type column — there an `= value` follows; here nothing does.
 * Verified against gofmt's own output.) The name width
 * is computed by the caller over the WHOLE struct (two-pass), like the const
 * block.
 */
int
go_types_emit_struct_field(FILE *out, const char *name, const char *type,
                           int name_w, int type_w) {
    (void)type_w;   /* never padded (see above); kept for symmetry with consts */
    if(fprintf(out, "\t%-*s %s\n", name_w - 1, name, type) < 0)
        return -1;
    return 0;
}

/*
 * go_types_emit_struct_close - the closing brace (gofmt: "}" alone on its
 * line).
 */
int
go_types_emit_struct_close(FILE *out) {
    return fputs("}\n", out) < 0 ? -1 : 0;
}
