/*
 * go_names_internal.h — shared declarations of the Go-name generator pass.
 *
 * Private to the go_names*.c files (go_names.c has the pass overview): the
 * includes they all use, the name-row / name-bag / walk-context types, the
 * file-scope state one piece defines and others read, and the functions one
 * piece defines and others call. Nothing outside go_names*.c includes it.
 */
#ifndef GO_NAMES_INTERNAL_H
#define GO_NAMES_INTERNAL_H
#include "go_constructs.h"
#include "go_flat.h"         /* go_flat_* hooks: the Flat IR minted at each
                               * structural decision site below (the Flat
                               * layout stage) */
#include "go_leaf.h"         /* go_leaf_kind: shared leaf body kinds */
#include "go_strmap.h"
#include "go_rows.h"          /* the name-row surface defined in go_names.c */
#include "go_conv.h"         /* go_conv_record_*: the conv facts the walk
                               * reads (IOC rows, NULL alts, PDUs, wide
                               * INTEGERs; the conv/entry stages) */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <asn1parser.h>         /* asn1p_t, asn1p_expr_t, asn1p_module_t */
#include <asn1p_list.h>         /* TQ_FOR, TQ_FIRST */
#include <asn1_namespace.h>     /* asn1_namespace_t */
#include <asn1_ref.h>           /* asn1p_ref_t, RLT_*, asn1p_ref_string */
#include <asn1fix_export.h>     /* asn1f_find_terminal_type_ex, asn1f_class_access_ex */
#include <asn1compiler.h>       /* enum asn1c_flags */
#include "asn1c_internal.h"     /* arg_t (required before asn1c_misc.h, which uses it) */
#include "asn1c_misc.h"         /* asn1c_make_identifier, AMI_USE_PREFIX (asn1c_misc.c:56);
                                   asn1c_type_fits_long, FL_* (asn1c_misc.c:408) */
#include "asn1c_ioc.h"          /* asn1c_get_ioc_table (asn1c_ioc.c), asn1c_ioc_table_and_objset_t */
#include <asn1fix_crange.h>     /* asn1constraint_compute_PER_range, asn1cnst_range_t,
                                   ARE edge kinds + ACT range kinds (libasn1fix,
                                   asn1fix_crange.h:62; the C backend includes it
                                   at asn1c_C.c:13) */
#include <asn1p_class.h>        /* asn1p_ioc_table_t, asn1p_ioc_row_t/cell_s */
#include "go_flat.h"         /* go_flat_* hooks: the Flat IR minted at each
                               * structural decision site below (section 5) */

/* asn1c C-identifier source of truth (asn1c_C.c:97). Sharing MKID makes rawCid
 * exactly the symbol asn1c stamps into its .h, byte-for-byte. */
#define GO_MKID(expr) (asn1c_make_identifier(AMI_USE_PREFIX, (expr), 0))

/* Forward decl for go_emit.c: it owns file emission; we call it once the name
 * pass is clean. Declared here (not in a header) to keep the hook surface flat
 * (the read-only rule: no edits beyond the pinned hook in libasn1compiler proper). */
extern int go_emit_files(asn1p_t *asn, const char *go_outdir);
/* Self-prototype so -Wmissing-prototypes is satisfied (same flat-extern style
 * as the driver's asn1cgo_generate forward decl in go_backend.c). */
int go_generate(asn1p_t *asn, const char *go_outdir, enum asn1c_flags flags);
/* Likewise for go_check_outdir (go_backend.c keeps its own extern). */
int go_check_outdir(const char *go_outdir);

/* Glue emission (go_glue.c), called by go_generate above after
 * go_conv_emit (flat-extern style: no header churn). */
int go_glue_emit(const char *go_outdir, const char *go_module_basename,
                 const char *go_rt_module);

/* IE-constructor emission (go_ctor.c), called after go_glue_emit in
 * go_generate (flat-extern style; reads the name rows + go_ioc tables). */
int go_ctor_emit(const char *go_outdir);

/* go.work maintenance (go_entry.c) + all-or-nothing -Fgo publication
 * (go_emit.c); see go_generate. */
int go_workfile_plan(const char *go_outdir, char **new_text);
int go_workfile_write(const char *go_outdir, const char *new_text);
int go_workfile_lock(const char *go_outdir, int *fd);
void go_workfile_unlock(int fd);
int go_outdir_stage(const char *go_outdir, char **tmp_out);
int go_outdir_publish(const char *go_outdir, const char *tmp, char **old_out);
void go_outdir_rollback(const char *go_outdir, const char *tmp, char *old);
int go_outdir_commit(char *old);
void go_outdir_discard(const char *tmp);

/* ------------------------------------------------------------------------- */
/* Name kinds. A row's kind_tag is the closed string set below; a produced
 * name must map to exactly one. Unknown -> dump failure. */
typedef enum {
    GK_TYPE, GK_FIELD, GK_CHOICE_PR, GK_CHOICE_CONST, GK_ENUM_CONST,
    GK_VALUE_CONST, GK_INLINE, GK_SPEC_KEY, GK_SPEC_VALUE, GK_SPEC_PR,
    GK_HELPER, GK_PKG_DIR, GK_DEFAULT_VALUE, GK__COUNT
} go_kind_e;

/* ------------------------------------------------------------------------- */
/* The name bag: rows (retained for sorted dump output) + collision tables.
 * All tables are flat dynamic arrays with linear search — row counts are
 * small (a few thousand per spec group), and linear search keeps the collision
 * diagnostic simple and dependency-free. */
struct name_row {
    const char *module;     /* module->ModuleName (borrowed)               */
    char *path;             /* dotted ASN.1 path (owned)                   */
    go_kind_e kind;
    char *rawCid;           /* the asn1c C identifier (owned)             */
    char *goName;           /* GoName(rawCid) (owned)                         */
    /* leaf-stage body data (leaf declarations). goName is the decl name;
     * leaf_kind is set for rows whose declaration is a self-contained
     * leaf `type` line; intval is the decimal value string for enum-const /
     * choice-const / value-const rows (asn1p_itoa output, owned); goType is
     * the const's declared Go type name (owned). */
    int leaf_kind;          /* GLEAF_* (go_types.c); 0 = GLEAF_NONE        */
    char *intval;           /* const value text, NULL for non-const rows   */
    char *goType;           /* const's Go type name, NULL outside consts   */
    /* struct-body data. A struct-owner row (type/inline/spec-key/
     * spec-value that declares a Go struct) carries is_struct=1; its FIELD
     * rows carry field_type (the field's Go type text, pointer-starred iff
     * EM_OPTIONAL/EM_INDIRECT, package-qualified across modules)
     * and sf_owner (the owning struct's goName — the emit matches fields to
     * their struct by name, so ord-order interleaving across structs is
     * harmless; per-struct field order is still ord order within the match).
     */
    int is_struct;          /* 1 = emit a Go struct body at this row        */
    char *field_type;       /* GK_FIELD rows: the field's Go type text      */
    char *sf_owner;         /* GK_FIELD rows: the owning struct's goName    */
    /* slice-stage data. A slice-owner row (a SEQUENCE-OF type assignment's
     * `type` row, an anonymous-inline SEQ-OF's or a container specialization
     * use's `inline` row) carries slice_elem — the ELEMENT type text of the
     * named slice alias `type X []Elem` it declares. A reference
     * element stores the referenced assignment's own goName UNQUALIFIED;
     * the post-walk prepass (go_qualify_slice_elems, the slice side of
     * go_qualify_field_types) applies cross-module qualification once the
     * whole name table exists. A leaf element stores the leaf-kind-to-Go-type
     * mapping-table text. */
    char *slice_elem;       /* slice-owner rows: element type text, or NULL  */
    /* Non-zero iff this FIELD row's member is
     * OPTIONAL and its marker carries bits BEYOND EM_OPTIONAL (the nested-
     * mask shape go_member_stars's containment test must still star — a fixer-
     * added EM_INDIRECT/EM_UNRECURSE on an OPTIONAL member, e.g. 0x17).
     * Reported as a run-end stderr census; purely informational. */
    int opt_extra_bits;     /* extra marker bits beyond EM_OPTIONAL, or 0   */
    /* GK_DEFAULT_VALUE rows: the exported Go declaration of one DEFAULT
     * member's value. dflt_form: 1 = `const Name T = dflt_lit`, 2 =
     * `var Name = T{dflt_lit}` (slice/struct valued), 3 =
     * `var Name T = T(dflt_lit)` (a float64 expression with no Go constant:
     * an infinity, NaN, minus zero). dflt_owner/dflt_field
     * name the member's Go struct and field (the field row, found at emit
     * time, supplies the final package-qualified Go type T). */
    int dflt_form;
    char *dflt_lit;
    char *dflt_owner;
    char *dflt_field;
    /* dflt_form 4 (a SEQUENCE / SET / SEQUENCE OF / SET OF value): no
     * declaration in types.go; the glue emits a func <Name>() returning a
     * new value, built by a C helper from the owner's top-level descriptor. */
    struct go_dflt_fn *dfn;
    int dflt_field_row;     /* the member's field row (its Go type) */
    /* GK_ENUM_CONST rows that are the bit-position constants of a named-bit
     * BIT STRING (`BIT STRING { a(0), b(1) }`): bit_group is non-zero and
     * identical for all bits of one type (the first bit row's ord + 1),
     * bit_type is the ASN.1 path of the BIT STRING type (for the comment).
     * Such a row has goType "int" and belongs to no owner type row: its block
     * is emitted at the first bit row, in walk order. */
    int bit_group;
    char *bit_type;
    /* struct-owner rows: types.go declares func New<goName>() *<goName>,
     * which sets every DEFAULT member (and every mandatory member of a type
     * that has such a func) — see go_mark_ctors. */
    int has_ctor;
    /* GK_TYPE rows of a type assignment that only renames a SEQUENCE, SET
     * or CHOICE (Alias ::= Msg): the Go type it is declared as
     * (`type Alias Msg`), package-qualified after the walk. */
    char *alias_of;
    /* GK_FIELD rows of a struct with has_ctor: the ord of the member's
     * GK_DEFAULT_VALUE row (ctor_dflt) or of the struct row of its type when
     * that type has a constructor (ctor_type); -1 when neither. */
    int ctor_dflt;
    int ctor_type;
    int ord;                /* insertion (WALK) order; dump sorting does
                             * not preserve it, but const-block ORDER inside
                             * one block must (PrNothing first, alts in
                             * ASN.1 order). Emission iterates by ord.     */
};

struct pkg_owner {          /* first claimant of a package-scoped name     */
    char *goName;           /* (owned)                                     */
    char *path;             /* ASN.1 path (owned)                          */
    go_kind_e kind;
};

struct field_owner {        /* first claimant of a struct-scoped field name */
    char *goName;           /* (owned)                                     */
    char *path;             /* ASN.1 path (owned)                          */
};

struct pkgdir_owner {       /* first module to claim a package dir         */
    char *dir;              /* (owned)                                     */
    const char *module;     /* module->ModuleName (borrowed)              */
};

struct name_bag {
    struct name_row *rows;
    int n_rows, cap_rows;
    int failed;

    /* Package-scoped table, per module: parallel arrays keyed by module ptr. */
    const char **ps_module;             /* module->ModuleName per scope    */
    struct pkg_owner **ps_owners;       /* owner list per scope            */
    int *ps_n, *ps_cap;                 /* list sizes per scope            */
    gsmap *ps_ix;                       /* goName -> first owner, per scope */
    int n_ps, cap_ps;

    /* Per-struct field table (reset at each struct). */
    struct field_owner *fields;
    int n_fields, cap_fields;
    /* Enclosing structs' saved field tables (go_field_scope_push/pop): an inline
     * struct node gets its own scope and the outer one is restored on exit. */
    struct field_scope_save {
        struct field_owner *fields;
        int n_fields, cap_fields;
    } *fs_stack;
    int n_fs, cap_fs;

    /* struct-body: the OPEN struct scope's owner name (the struct's goName; NULL
     * = no open scope). GK_FIELD rows emitted while a scope is open record it
     * on the row (sf_owner); the emit prints each is_struct row's fields from
     * the rows whose sf_owner matches, in ord order. */
    char *sf_cur_owner;

    /* pkg-dir table (across modules). */
    struct pkgdir_owner *dirs;
    int n_dirs, cap_dirs;

    /* Modules owning a BIT-STRING member (helper row emission). */
    const char **bs_modules;
    int n_bs, cap_bs;

    /* Inline SEQUENCE OF elements already minted (module + element cid ->
     * Go element text): a second reach of the same owner (an alias
     * assignment `U ::= T` of an inline-element SEQUENCE OF) reuses it. */
    struct minted_elem { const char *module; char *cid; char *go_elem; }
        *minted;
    int n_minted, cap_minted;
};

/* ------------------------------------------------------------------------- */
/* Walk state threaded through the recursion. Mirrors go_walk.c's walk_ctx but
 * carries the per-struct field scope and the live parent goName (for inline
 * naming: <Parent><Member>) AND the live parent REAL asn1c C-ident prefix
 * parent_cid (for inline RAW-symbol compound: parent_cid + "__" + member cid,
 * the verbatim asn1c nested-tag form). Both are threaded everywhere the walker
 * recurses into an inline construct. */
struct walk_ctx {
    const char *module;     /* active module->ModuleName          */
    const char *parent_go;  /* enclosing goName (empty = top level) */
    const char *parent_cid; /* enclosing real asn1c C-id prefix ("" top level) */
    asn1_namespace_t *ns;
    asn1p_t *asn;
    struct name_bag *bag;
    /* go_member_stars out-param: marker bits beyond
     * EM_OPTIONAL on an OPTIONAL member of the LAST go_member_stars call
     * (0 otherwise). The field-row caller copies it onto the member's row. */
    int last_opt_extra;
    /* classify_integer_leaf: when set, a wide-INTEGER result is recorded
     * under this cid (an inline SEQUENCE OF element has no Identifier of
     * its own; its Flat node is <Owner>__Member) and wide_hit is raised. */
    const char *wide_cid;
    int wide_hit;
    /* classify_integer_leaf: set while classifying an inline MEMBER / CHOICE
     * ALT leaf. Such a leaf has no node of its own, so nothing is recorded in
     * the wide-leaf registry; the caller reads wide_hit and flags the Flat
     * member row itself (go_flat_last_member_wide). */
    int wide_nr;
};

/* --------------------------------------------------------------------- */
/* File-scope state shared between the go_names*.c files. */

/* go_names_rows.c */
extern const char *const g_go_kind_tag[GK__COUNT];

/* go_names_decls.c */
extern struct name_bag *g_go_emit_bag;
extern char *g_go_module_path;
extern char *g_go_rt_module_path;

/* --------------------------------------------------------------------- */
/* Functions shared between the go_names*.c files. */

/* go_names.c */
char *go_make_path(const char *parent, const char *leaf);
void go_mark_bitstring_module(struct name_bag *b, const char *module);
int go_pdu_selected(const asn1p_expr_t *expr);
void go_pdu_record(const asn1p_expr_t *expr, const char *cid);
void go_pdu_record_alias(const asn1p_expr_t *expr, const char *alias_cid,
                         const char *target_cid, const char *alias_go,
                         const char *module);
int go_classify_leaf(struct walk_ctx *ctx, asn1p_expr_t *terminal,
                  const char *path_for_diag);

/* go_names_rows.c */
int go_kind_is_package_scoped(go_kind_e k);
char *go_cid_to_go_name(const char *cid);
char *go_str_append(char *a, const char *b);
char *go_own(const char *s);
char *go_own_mkid(asn1p_expr_t *e);
char *go_mk_member(asn1p_expr_t *e);
char *go_mk_suffix(asn1p_expr_t *e);
char *go_cid_compound(const char *a, const char *sep, const char *b);
char *go_alt_spell(const char *cid);
void go_clash_reset(void);
char *go_type_go(asn1p_expr_t *t);
char *go_value_go(asn1p_expr_t *gov, asn1p_expr_t *val);
char *go_module_pkg_name(const char *module_name);
void *go_xrealloc(void *p, size_t n);
void go_reset_field_scope(struct name_bag *b);
void go_field_scope_push(struct name_bag *b);
void go_field_scope_pop(struct name_bag *b);
void go_struct_scope_open(struct name_bag *b, const char *owner_go);
void go_struct_scope_reset(struct name_bag *b);
char *go_bag_sf_restore(struct name_bag *b, char *saved);
void go_alt_register(const char *name, const char *tok, const char *go);
void go_alt_reset(void);
void go_row_set_const(struct name_bag *b, const char *value, const char *go_type);
void go_row_set_leaf(struct name_bag *b, int leaf_kind);
void go_row_set_slice_elem(struct name_bag *b, const char *elem);
void go_row_set_slice_elem_at(struct name_bag *b, int ix, const char *elem);
void go_emit_name(struct name_bag *b, const char *module,
               char *path, go_kind_e kind, char *rawCid, char *goName);
void go_row_set_field_type(struct name_bag *b, const char *field_type);
void go_row_set_field_type_at(struct name_bag *b, int ix, const char *field_type);
void go_row_set_is_struct_at(struct name_bag *b, int ix);
void go_row_set_is_struct(struct name_bag *b);

/* go_names_decls.c */
int go_check_module_prefix(const char *pfx);
char *go_path_join2(const char *a, const char *b);
void go_set_module_paths(const char *go_outdir);
void go_clear_module_paths(void);
int go_collect_module_imports(struct name_bag *b, const char *module,
                           char **imps, int max_imps);

/* go_names_choice.c */
void go_emit_choice(struct walk_ctx *ctx, const char *choice_go,
                 const char *choice_cid, const char *parent_path,
                 asn1p_expr_t *choice_expr);
char *go_member_go(asn1p_expr_t *e);
void go_emit_enum(struct walk_ctx *ctx, const char *enum_go,
               const char *enum_cid, const char *parent_path,
               asn1p_expr_t *enum_expr);
void go_emit_bit_names(struct walk_ctx *ctx, const char *type_go,
                    const char *type_cid, const char *type_path,
                    asn1p_expr_t *bs);

/* go_names_spec.c */
asn1p_expr_t *go_is_field_shaped_spec(asn1p_expr_t *seq_terminal);
void go_emit_spec(struct walk_ctx *ctx, const char *x_go, const char *x_cid,
               const char *parent_path, asn1p_expr_t *seq_terminal);
int go_member_is_default(const asn1p_expr_t *child);
const char *go_member_stars(struct walk_ctx *ctx, asn1p_expr_t *child, const char *path);

/* go_names_check.c */
void go_qualify_field_types(struct name_bag *b);
void go_qualify_slice_elems(struct name_bag *b);
int go_check_import_cycles(struct name_bag *b);
int go_mark_ctors(struct name_bag *b);
int go_check_cycles(struct name_bag *b);

/* go_names_dflt.c */
int go_seqof_elem_is_inline(asn1p_expr_t *elem);
int go_mint_inline_seqof_elem(struct walk_ctx *ctx, asn1p_expr_t *elem,
                           const char *owner_path, const char *owner_go,
                           const char *owner_cid, char **go_elem,
                           char **flat_cid);
char *go_slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                         const char *path_for_diag);
void go_note_default_value(struct walk_ctx *ctx, asn1p_expr_t *child,
                        const char *member_path, int field_row_ix);

/* go_names_walk.c */
int go_walk_names_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
                       const char *parent_path);
int go_walk_names_expr(struct walk_ctx *ctx, asn1p_expr_t *expr);

#endif /* GO_NAMES_INTERNAL_H */
