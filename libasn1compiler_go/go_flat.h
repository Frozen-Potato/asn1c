/*
 * go_flat.h — the Flat-IR surface between go_names.c (which walks the AST
 * and owns every structural decision) and go_flat.c (which owns the IR, the
 * x86-64 SysV layout engine, and the file writers). Flat side of the
 * split: go_flat.c emits <CIdent>_flat structs + layout checks.
 *
 * Every hook takes the DECIDED facts by argument (cid, member token, star
 * flags, minted nested names) — go_flat.c never re-derives a decision the
 * walk already made, and the walk never formats a Flat line itself.
 */
#ifndef GO_FLAT_H
#define GO_FLAT_H

#include <stddef.h>

/* forward decls (the IR is private to go_flat.c; the walk holds opaque
 * handles only — a nested construct's member list is populated through the
 * returned handle, then attached by the mint calls). */
typedef struct flat_type flat_type;

/* ---- IR construction hooks (called during the name walk) ----------------
 *
 * cid arguments are the REAL prefixed asn1c C identifiers (GO_MKID output +
 * the compound forms the walk computes); go_flat.c adds the _flat / prefix
 * surface per the prefix + Flat naming rules itself. `stars` = 1 for a pointer slot (OPTIONAL /
 * CHOICE pointer-alt / recursion break — the walk's already-decided fact).
 */

/* A package-scoped struct type (SEQUENCE / CHOICE / field-shaped spec
 * envelope): members are added by the go_flat_member_* calls below while
 * the walk is INSIDE this construct; go_flat.c re-binds "current struct" on
 * each go_flat_struct call (the walk walks one construct at a time). */
void go_flat_struct(const char *cid, const char *module);

/* go_flat_choice: the mint for a CHOICE container (present-first layout;
 * slot stars decided by the caller's EM_INDIRECT read). */
void go_flat_choice(const char *cid, const char *module);
void go_flat_mark_c_alias(const char *cid, const char *target_cid);

/* A nested anonymous construct with its own cid (an inline CHOICE wrapper /
 * the open-type __value union): populate via returned handle + mint calls,
 * then attach with the token it rides under (go_flat_member_nested). The
 * IR node is NOT a package-scoped typedef of its own (nested per the Flat naming rule). */
int go_flat_struct_nested(const char *cid, const char *module);

/* Save/restore the current-struct register (the cur_ix the member hooks
 * target): the walk saves before recursing into an inline construct's CHOICE
 * / SEQUENCE member body and restores after, so a member AFTER the inline
 * construct lands on the ENCLOSING struct again (the flatemit-check
 * member-class check: nextMathOp landed inside the paramType inline CHOICE). */
int go_flat_cur_get(void);
void go_flat_cur_restore(int ix);

/* A bare leaf typedef: `typedef <prim> <P><CIdent>_flat;`. prim is
 * the leaf-kind-to-Flat-C mapping-table token (int8_t..uint64_t, double,
 * asn1cgo_bytes_flat, asn1cgo_bits_flat — native width included). */
int go_flat_leaf(const char *cid, const char *prim, const char *module);

/* display-label recording (post-hoc, right after the mint/member call
 * each labels): go_flat_label_cur sets the CUR node's label;
 * go_flat_label_last_member sets the label of the LAST member row any
 * go_flat_member_* hook landed. label = the ASN.1 expr->Identifier verbatim
 * (the td->name string asn1c emits: asn1c_C.c:3194 type, :3119 member —
 * prefix-free, hyphens kept). NULL/absent = emission falls back to the
 * C-ident/token form. First label wins (a dedup'd mint keeps its first). */
void go_flat_label_cur(const char *label);
void go_flat_label_last_member(const char *label);

/* Mark the LAST member row as a DEFAULT member: its Flat slot is by value
 * (stars=0), while the C tree slot is a pointer iff tree_ptr (the
 * post-C-pass EM_INDIRECT bit). The conv arms read both. */
void go_flat_last_member_default(int tree_ptr);

/* Mark the LAST member row as an INTEGER_t-backed wide int64/uint64 member:
 * the Flat slot is the native 8-byte scalar, the C tree slot an INTEGER_t
 * (asn_imax2INTEGER / asn_umax2INTEGER and back in the conv). */
void go_flat_last_member_wide(void);

/* The LAST member row (a prim) is a string leaf of the given GLEAF_* kind:
 * GLEAF_STRING_BMP / GLEAF_STRING_UNIV (the glue converts UTF-8 <->
 * UCS-2/UCS-4), GLEAF_STRING_Z any other restricted string / time type,
 * GLEAF_OID / GLEAF_ROID (arcs); kinds in go_leaf.h. Other kinds: no effect. */
void go_flat_last_member_gleaf(int gleaf);

/* Record the C tree's name for the LAST member row when it differs from the
 * Flat member token: a CHOICE alt named `present` is the Flat member
 * `presentAlt` (the Flat struct already has the discriminant `present`) but
 * the tree member `choice.present` and the enumerator <X>_PR_present. */
void go_flat_last_member_tree_token(const char *tree_token);
void go_flat_last_member_tree_member(const char *m);

/* The same mint keyed by the walk's GLEAF_* kind (the SAME int the Go side
 * passed row_set_leaf — one classification, both columns; the C-prim token
 * derives from the identical table go_types.c maps to the Go column). */
int go_flat_leaf_gleaf(const char *cid, int gleaf, const char *module);

/* A named SEQ OF: `typedef struct { <elem>_flat *items; size_t
 * count; } <P><CIdent>_flat;`. elem is the ELEMENT cid (or a prim token
 * when elem_is_prim). */
int go_flat_seqof(const char *cid, const char *elem, int elem_is_prim,
                  int is_set_of, const char *module);

/* An alias (the SingleContainer clone form): `typedef <of>_flat
 * <P><CIdent>_flat;`. */
int go_flat_alias(const char *cid, const char *of_cid, const char *module);

/* A param-container clone struct (the ProtocolIE-Container_85P0 form):
 * `typedef struct { <elem>_flat *items; size_t count; } <cid>_flat;` —
 * the cid arrives AS the clone's own id (85P0 suffix included); the name
 * keeps it VERBATIM (no run prefix on clone family names, the frozen
 * units' bare ProtocolIE_Container_85P0_flat / ..._88P0_flat). */
int go_flat_seqof_container(const char *cid, const char *elem_cid,
                            const char *module);

/* Members land on the CURRENT struct (the last go_flat_struct /
 * go_flat_struct_nested-target set by the mint calls above — the walk emits
 * a construct's members consecutively). */
void go_flat_member_prim(const char *prim, const char *token, int stars);
void go_flat_member_ref(const char *cid, const char *token, int stars);
void go_flat_member_nested(int nested_ix, const char *token, int stars);
/* attach a nested node onto the ENCLOSED struct's row for node `on_ix`. */
void go_flat_member_nested_on(int on_ix, int nested_ix, const char *token,
                              int stars);
/* the _on forms: populate the NESTED node `ix` (from go_flat_struct_nested)
 * instead of cur — the value-union/inline-wrapper alt rows. */
void go_flat_member_prim_on(int ix, const char *prim, const char *token, int stars);
void go_flat_member_ref_on(int ix, const char *cid, const char *token, int stars);

/* An inline SEQ OF member ({items,count} nested anonymous): minted
 * and attached in one call. */
void go_flat_member_seqof(const char *elem_cid, int elem_is_prim,
                          int is_set_of, const char *token, int stars);
/* Mark the CUR node (the one just minted) an inline element/alt type: no
 * `<cid>_t` typedef and no asn_DEF_<cid> exist in the C tree (the element is
 * an anonymous type inside its SEQUENCE OF / CHOICE). tree_ctype = the C
 * spelling the conv file aliases `<cid>_t` to; go_type = the unnamed Go
 * element type for a hidden leaf (NULL when the Go type is a named one). */
void go_flat_mark_null_leaf(void);
void go_flat_mark_inline_elem(const char *tree_ctype, const char *go_type);

/* the _on form: attach onto the ENCLOSING struct's nested node index (the
 * inline-SEQ-OF member whose node was pre-minted by go_flat_struct_nested). */
void go_flat_member_seqof_on(int nest_ix, const char *elem_cid,
                             int elem_is_prim, int is_set_of,
                             const char *token, int stars);

/* A BARE-NAMED alias (the SingleContainer collapse): `typedef
 * <of_cid>_flat <cid>_flat;` — NO run prefix on either side (clone family
 * names are bare, matching the frozen units). */
int go_flat_alias_bare(const char *cid, const char *of_cid,
                       const char *module);

/* ---- post-walk passes (called by go_generate) -------------------------- */

/* Compute every size/align/offset under x86-64 SysV (the Flat struct
 * layout rule; re-entrant: memoized per node). */
void go_flat_layout_all(void);

/* Write every package's <P><pkg>_flat.h + <P><pkg>_layout_check.c under
 * <go_outdir>/c/, copy the rt files (arena/err/types) into c/rt/, and write
 * each package's layout.go under <go_outdir>/<pkg>/. Returns 0/-1. */
int go_flat_emit(const char *go_outdir, const char *go_module_basename);

#endif /* GO_FLAT_H */
