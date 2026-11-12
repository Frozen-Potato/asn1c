/*
 * go_names.c — Go-name generator pass.
 *
 * Produces every package-level Go identifier the backend will emit, plus the
 * published name set consumed by the name-distribution check (dump compare).
 * It owns its OWN AST walk, separate from the (frozen, classify-only) walk in
 * go_walk.c. The two must agree on which (module, path) nodes carry a Go name
 * — the dump is cross-referenced against the real asn1c .h index and against
 * the frozen comparison units — but they serve different purposes:
 * go_walk classifies (support gate), go_names resolves (naming).
 *
 * What is named here (rule base frozen; each row cites the asn1c path
 * that makes the rawCid authoritative):
 *
 *   type        one Go type per top-level type assignment (the R2 transform,
 *               the naming rule base).
 *               rawCid = GO_MKID(expr); goName = R2(rawCid). A reference
 *               assignment mints its OWN named Go type too: every type
 *               assignment is a named Go type.
 *   field       one Go struct field per member of a SEQUENCE/CHOICE / per field-shaped
 *               specialization value-union alt (pointer per alt). rawCid =
 *               GO_MKID(child) (the C member token: ranFunction-ShortName ->
 *               ranFunction_ShortName, asn1c_misc.c:168-180). Struct-scoped:
 *               collides only with siblings of the SAME struct.
 *   inline      one Go type per anonymous inline SEQUENCE/CHOICE/ENUMERATED/
 *               SEQUENCE-OF at a member: <Parent><Member> (the anonymous-inline
 *               naming rule). That name
 *               becomes the <Parent> for its OWN members (inlines stack).
 *   choice-pr   one per CHOICE: <Choice>Pr (discriminant-type name).
 *   choice-const <Choice>PrNothing + <Choice>Pr<Alt> per alt (const
 *               discriminants). Package-scoped.
 *   enum-const  <Enum><Enumerator> per enumerator of a top-level or inline
 *               ENUMERATED const naming). Package-scoped.
 *   value-const R2 of a typed value-assignment #define symbol
 *               `#define <T>_id_<X> ((<T>_t)<n>)` — emitted only when the value
 *               assignment's governing type is INTEGER or ENUMERATED
 *               (asn1c_C.c asn1c_lang_C_type_REFERENCE_Value). rawCid =
 *               GO_MKID(governing-type) + "_" + GO_MKID(value-expr). Bare
 *               INTEGER value assigns (`maxno-X INTEGER ::= n`) emit the
 *               UNTYPED `#define X (n)` (asn1c_save.c generate_constant_
 *               collection) and are NOT value-consts: excluded.
 *   spec-*      field-shaped specialization (ProtocolIE-Field /
 *               SingleContainer {{X}} whose clone is a SEQUENCE with an
 *               open-type &Value member): R2(X), R2(X)+Value, R2(X)+ValuePr,
 *               plus one field per value-union alt. A container-shaped clone
 *               (no open-type member) collapses — mints NO new Go name.
 *   helper      the shared BitString Go type, once per module that owns a
 *               BIT-STRING member (no ASN.1 source). Package-scoped.
 *   pkg-dir     one per module: package dir = module identifier lowercased,
 *               '-'->'_'. Two modules -> same dir is a collision.
 *
 * Collisions: two scopes. Package-scoped kinds collide within one
 * module; field rows collide only with siblings of the same struct; pkg-dir
 * rows collide across modules. Any collision prints a both-paths diagnostic and
 * fails the run (non-zero -> driver EX_SOFTWARE, exit 70); the walk continues
 * to surface further collisions.
 *
 * Emission: gated on a non-empty go_outdir (go_emit writes the files); the dump
 * (ASN1CGO_DUMP_NAMES) writes every row as
 *   module \t path \t kind \t rawCid \t goName
 * sorted by (module, path). A row whose kind is not in the closed set fails the
 * dump.
 *
 * Citations are path:line into the asn1c fork (the ground truth for what asn1c
 * emits); no external-spec identifiers in source.
 */
#include "go_constructs.h"
#include "go_flat.h"         /* go_flat_* hooks: the Flat IR minted at each
                               * structural decision site below (the Flat
                               * layout stage) */
#include "go_conv.h"         /* go_conv_record_*: the conv facts the walk
                               * reads (IOC rows, NULL alts, PDUs, wide
                               * INTEGERs; the conv/entry stages) */

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

static const char *const g_kind_tag[GK__COUNT] = {
    "type", "field", "choice-pr", "choice-const", "enum-const", "value-const",
    "inline", "spec-key", "spec-value", "spec-pr", "helper", "pkg-dir",
    "default-value",
};

/* Kinds whose goName is package-scoped (collide within one module). field is
 * struct-scoped (a fresh per-struct table); pkg-dir collides across modules
 * (its own table). */
static int
kind_is_package_scoped(go_kind_e k) {
    return k == GK_TYPE || k == GK_INLINE || k == GK_CHOICE_PR
        || k == GK_CHOICE_CONST || k == GK_ENUM_CONST || k == GK_VALUE_CONST
        || k == GK_SPEC_KEY || k == GK_SPEC_VALUE || k == GK_SPEC_PR
        || k == GK_HELPER || k == GK_DEFAULT_VALUE;
}

/* ------------------------------------------------------------------------- */
/* R2 transform: split the C identifier on '_', upper-case the first
 * char of each segment, join. Everything else passes through verbatim. Mirrors
 * the comparator and the frozen units — no curation, no aliasing.
 *
 *   ranFunction_ShortName    -> RanFunctionShortName
 *   ProtocolIE_ID_id_Cause   -> ProtocolIEIDIdCause
 *   RANfunction_Name         -> RANfunctionName
 *   ProcedureCode_id_E2setup -> ProcedureCodeIdE2setup
 *
 * Returns a malloc'd NUL-terminated string; empty in -> empty out.
 *
 * prefix strip: asn1c_make_identifier(AMI_USE_PREFIX, ...) prepends
 * asn1c_prefix() (the ASN1C_PREFIX env var, asn1c_misc.c:42-49) to every C
 * identifier, so a prefixed RUN's rawCids all start with the prefix. Go names
 * are computed WITHOUT the prefix (Go namespacing is by package), so
 * R2 strips the run prefix BEFORE the segment pass — rawCid keeps the real
 * prefixed .h token, goName is prefix-free (as in an unprefixed
 * run). Without ASN1C_PREFIX asn1c_prefix() is "" and this is the identity
 * (all name-walk steps ran unprefixed; nothing changes for them). */
static char *
go_r2(const char *cid) {
    const char *prefix = asn1c_prefix();
    size_t plen = prefix ? strlen(prefix) : 0;
    if(cid && plen && strncmp(cid, prefix, plen) == 0)
        cid += plen;            /* strip the run prefix */
    size_t n = cid ? strlen(cid) : 0;
    char *out = malloc(n + 1);
    if(!out) return strdup("");
    int cap = 1;            /* upper-case the next alpha (segment start) */
    size_t j = 0;
    for(size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)cid[i];
        if(c == '_') { cap = 1; continue; }   /* consumed, never copied */
        if(cap && isalpha(c)) {
            out[j++] = (char)toupper(c);
        } else {
            out[j++] = (char)c;
        }
        cap = 0;
    }
    out[j] = '\0';
    return out;
}

/* Append "<b>" to a malloc'd string; frealloc-style growth. Never fails
 * visibly: on OOM the result is left as-is (a generator that cannot allocate
 * surfaces the failure via the row's eventual emit). */
static char *
str_append(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0;
    size_t lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;            /* leave a unchanged on OOM */
    memcpy(r + la, b ? b : "", lb);
    r[la + lb] = '\0';
    return r;
}

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
    char *goName;           /* R2(rawCid) (owned)                         */
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
     * the post-walk prepass (qualify_slice_elems, the slice side of
     * qualify_field_types) applies cross-module qualification once the
     * whole name table exists. A leaf element stores the leaf-kind-to-Go-type
     * mapping-table text. */
    char *slice_elem;       /* slice-owner rows: element type text, or NULL  */
    /* Non-zero iff this FIELD row's member is
     * OPTIONAL and its marker carries bits BEYOND EM_OPTIONAL (the nested-
     * mask shape member_stars's containment test must still star — a fixer-
     * added EM_INDIRECT/EM_UNRECURSE on an OPTIONAL member, e.g. 0x17).
     * Reported as a run-end stderr census; purely informational. */
    int opt_extra_bits;     /* extra marker bits beyond EM_OPTIONAL, or 0   */
    /* GK_DEFAULT_VALUE rows: the exported Go declaration of one DEFAULT
     * member's value. dflt_form: 1 = `const Name T = dflt_lit`, 2 =
     * `var Name = T{dflt_lit}` (slice/struct valued). dflt_owner/dflt_field
     * name the member's Go struct and field (the field row, found at emit
     * time, supplies the final package-qualified Go type T). */
    int dflt_form;
    char *dflt_lit;
    char *dflt_owner;
    char *dflt_field;
    /* GK_ENUM_CONST rows that are the bit-position constants of a named-bit
     * BIT STRING (`BIT STRING { a(0), b(1) }`): bit_group is non-zero and
     * identical for all bits of one type (the first bit row's ord + 1),
     * bit_type is the ASN.1 path of the BIT STRING type (for the comment).
     * Such a row has goType "int" and belongs to no owner type row: its block
     * is emitted at the first bit row, in walk order. */
    int bit_group;
    char *bit_type;
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
    int n_ps, cap_ps;

    /* Per-struct field table (reset at each struct). */
    struct field_owner *fields;
    int n_fields, cap_fields;

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

/* Borrowed strdup: strdup the C-identifier return of GO_MKID (which returns a
 * pointer into an asn1c static buffer reused on the next call) into an owned
 * copy. Never returns NULL (returns "" on OOM). */
static char *
own(const char *s) {
    char *r = strdup(s ? s : "");
    return r ? r : strdup("");
}
static char *own_mkid(asn1p_expr_t *e) { return own(GO_MKID(e)); }

/* prefix-free identifier forms. Under ASN1C_PREFIX=<P>_ asn1c does NOT
 * stamp the prefix on every identifier uniformly; the real .h rules are:
 *   - struct-member declaration tokens: make_identifier WITHOUT prefix
 *     (MKID_safe at asn1c_C.c:98 — AMI_CHECK_RESERVED, no AMI_USE_PREFIX; the
 *     member emit at asn1c_C.c:1353): `nR_Beam_ID`, never `KPM_nR_Beam_ID`;
 *   - the alt/enumerator PART of a _PR enumerant (c_presence_name's suffix,
 *     asn1c_naming.c:304): make_identifier(0, expr, 0) — no prefix;
 *   - every AGGREGATE name (type tags, `asn_DEF_*`, the `_PR` enum tag, the
 *     `__value` tags, compound `<Parent>__<member>` tags): the prefix ONCE at
 *     the front + parts compounded WITHOUT prefix (construct_base_name's
 *     flag=0 path, asn1c_naming.c:186/185; the per-part-prefixed form exists
 *     ONLY in the internal union tag `<X>__<P>_u`, out_name_chain
 *     asn1c_C.c:3405-3434, which the dump never targets).
 * With no ASN1C_PREFIX set all three forms coincide with GO_MKID — the whole
 * the tree ran unprefixed, so this only changes prefixed runs.
 *
 * go_mk_member: a STRUCT-MEMBER DECLARATION token (MKID_safe, asn1c_C.c:98 —
 *     AMI_CHECK_RESERVED: an identifier that IS a reserved keyword gets its
 *     first char upper-cased). Not the enumerant path.
 * go_mk_suffix: the enumerant/alt SUFFIX of a c_member_name / c_presence_name
 *     token (make_identifier flags 0 — asn1c_naming.c:304 — NO reserved-word
 *     upcasing: the real .h carries `..._true`, lowercase, even though 'true'
 *     is in res_kwd). Not the member-decl path.
 * go_cid_compound: prefix + compound of unprefixed parts (an aggregate rawCid).
 * All return owned strings (own() semantics: "" on OOM). */
static char *go_mk_member(asn1p_expr_t *e) {
    return own(asn1c_make_identifier(AMI_CHECK_RESERVED, (e), 0));
}
static char *go_mk_suffix(asn1p_expr_t *e) {
    return own(asn1c_make_identifier(0, (e), 0));
}
static char *go_cid_compound(const char *a, const char *sep, const char *b) {
    /* strip the prefix from each part (parts come prefixed from GO_MKID),
     * compound, then put the prefix back ONCE at the front. */
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *as = a, *bs = b;
    if(pl && a && strncmp(a, pfx, pl) == 0) as = a + pl;
    if(pl && b && strncmp(b, pfx, pl) == 0) bs = b + pl;
    size_t sl = sep ? strlen(sep) : 0;
    size_t n = (pfx ? pl : 0) + strlen(as ? as : "") + sl + strlen(bs ? bs : "") + 1;
    char *r = malloc(n);
    if(!r) return own("");
    snprintf(r, n, "%s%s%s%s", pfx ? pfx : "", as ? as : "", sep ? sep : "",
             bs ? bs : "");
    return r;
}

/* module_pkg: module identifier lowercased, '-' -> '_'. malloc'd, never NULL.
 * (package dir = this. Mirrors go_emit.c's same-named helper.) */
static char *
module_pkg_go(const char *module_name) {
    const char *s = module_name ? module_name : "_";
    char *out = malloc(strlen(s) + 1);
    if(!out) return strdup("");
    size_t j = 0;
    for(size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        out[j++] = (c == '-') ? '_' : (char)tolower(c);
    }
    out[j] = '\0';
    return out;
}

static void *
xrealloc(void *p, size_t n) {
    void *r = realloc(p, n);
    return r;   /* caller handles NULL */
}

static int
ps_grow(struct name_bag *b) {
    if(b->n_ps + 1 <= b->cap_ps) return 1;
    int nc = b->cap_ps ? b->cap_ps * 2 : 16;
    const char **nm = xrealloc(b->ps_module, (size_t)nc * sizeof(char *));
    if(!nm) return 0;
    b->ps_module = nm;
    struct pkg_owner **no = xrealloc(b->ps_owners, (size_t)nc * sizeof(*no));
    if(!no) return 0;
    b->ps_owners = no;
    int *nn = xrealloc(b->ps_n, (size_t)nc * sizeof(int));
    if(!nn) return 0;
    b->ps_n = nn;
    int *ncp = xrealloc(b->ps_cap, (size_t)nc * sizeof(int));
    if(!ncp) return 0;
    b->ps_cap = ncp;
    for(int i = b->cap_ps; i < nc; i++) {
        b->ps_module[i] = NULL; b->ps_owners[i] = NULL;
        b->ps_n[i] = 0; b->ps_cap[i] = 0;
    }
    b->cap_ps = nc;
    return 1;
}

/* Find or open the package-scoped table for `module` (a pointer-identity key).
 * Returns its index, or -1 on OOM. */
static int
ps_scope_for(struct name_bag *b, const char *module) {
    for(int i = 0; i < b->n_ps; i++)
        if(b->ps_module[i] == module) return i;
    if(!ps_grow(b)) return -1;
    int i = b->n_ps++;
    b->ps_module[i] = module;
    b->ps_owners[i] = NULL; b->ps_n[i] = 0; b->ps_cap[i] = 0;
    return i;
}

static int
ps_append(int i, struct name_bag *b, struct pkg_owner o) {
    if(b->ps_n[i] + 1 > b->ps_cap[i]) {
        int nc = b->ps_cap[i] ? b->ps_cap[i] * 2 : 16;
        struct pkg_owner *np = xrealloc(b->ps_owners[i],
                                        (size_t)nc * sizeof(struct pkg_owner));
        if(!np) return 0;
        b->ps_owners[i] = np; b->ps_cap[i] = nc;
    }
    b->ps_owners[i][b->ps_n[i]++] = o;
    return 1;
}

/* Record a package-scoped name in the module's scope. If `module` already
 * claimed the same goName in a DIFFERENT row, that is a collision: emit the
 * both-paths diagnostic and set failed. (Two rows with identical (path,kind)
 * would denote a double-visit bug; those are accepted as idempotent.) */
static void
record_package(struct name_bag *b, const char *module,
               const char *path, go_kind_e kind,
               char *rawCid, char *goName) {
    int i = ps_scope_for(b, module);
    if(i < 0) { b->failed = 1; return; }
    for(int j = 0; j < b->ps_n[i]; j++) {
        struct pkg_owner *o = &b->ps_owners[i][j];
        if(strcmp(o->goName, goName) == 0) {
            /* Same (path, kind) row meaning a re-visit: idempotent, no row. */
            if(strcmp(o->path, path) == 0 && o->kind == kind)
                return;
            fprintf(stderr,
                    "asn1cgo: collision in module %s: %s <- %s (%s) and %s (%s)\n",
                    module ? module : "?", goName,
                    o->path, g_kind_tag[o->kind],
                    path, g_kind_tag[kind]);
            b->failed = 1;
            return;
        }
    }
    struct pkg_owner o = { strdup(goName), strdup(path), kind };
    ps_append(i, b, o);
}

/* Record a struct-scoped field name in the CURRENT struct's field table. */
static void
record_field(struct name_bag *b, const char *module,
             const char *path, char *rawCid, char *goName) {
    (void)module; (void)rawCid; (void)path;
    for(int j = 0; j < b->n_fields; j++) {
        if(strcmp(b->fields[j].goName, goName) == 0) {
            fprintf(stderr,
                    "asn1cgo: collision in module %s: %s <- %s (field) and %s (field)\n",
                    module ? module : "?", goName,
                    b->fields[j].path, path);
            b->failed = 1;
            return;
        }
    }
    if(b->n_fields + 1 > b->cap_fields) {
        int nc = b->cap_fields ? b->cap_fields * 2 : 16;
        struct field_owner *np = xrealloc(b->fields,
                                          (size_t)nc * sizeof(struct field_owner));
        if(!np) { b->failed = 1; return; }
        b->fields = np; b->cap_fields = nc;
    }
    b->fields[b->n_fields].goName = strdup(goName);
    b->fields[b->n_fields].path = strdup(path);
    b->n_fields++;
}

static void
reset_field_scope(struct name_bag *b) {
    for(int j = 0; j < b->n_fields; j++) {
        free(b->fields[j].goName); free(b->fields[j].path);
    }
    b->n_fields = 0;
}

/* ---- struct-body recording ------------------------------------ */

/* struct_scope_open: open a struct-owner scope named `owner_go` (the struct's
 * goName). Every GK_FIELD row emitted while the scope is open (until the next
 * open/reset) records `owner_go` in its sf_owner — exactly the scope
 * discipline the field collision table uses (reset_field_scope), now retained
 * for emission. Owner by NAME: the emit matches fields to their struct by
 * goName (ord-order interleaving across structs is harmless; within one
 * match, ord order is the walk order = AST member order). */
static void
struct_scope_open(struct name_bag *b, const char *owner_go) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = strdup(owner_go ? owner_go : "");
}

/* struct_scope_reset: close the open scope (fields emitted after this attach
 * to no struct — e.g. a leftover guard between top-level assignments). */
static void
struct_scope_reset(struct name_bag *b) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = NULL;
}

/* bag_sf_restore: reopen a SAVED struct-owner scope after a nested struct's
 * walk finished with struct_scope_reset (an inline CHOICE/SEQUENCE member
 * walk). Returns the saved pointer it consumed (free() it), NULL- and
 * strdup-safe. The member walk of an OUTER struct continues after a nested
 * construct; without the restore, every later member of the outer struct
 * lands scopeless (emit skips fields with no sf_owner — RRC-MessageID's
 * messageID after the inline rrcType CHOICE). */
static char *
bag_sf_restore(struct name_bag *b, char *saved) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = saved ? strdup(saved) : NULL;
    return saved;
}

/* struct_field_note: stamp the open struct scope's owner onto the row just
 * appended (a GK_FIELD row). Called from emit_name right after add_row. */
static void
struct_field_note(struct name_bag *b) {
    if(!b->sf_cur_owner) return;
    struct name_row *r = &b->rows[b->n_rows - 1];
    free(r->sf_owner);
    r->sf_owner = strdup(b->sf_cur_owner);
}

/* Record a pkg-dir claim across modules. (Same module re-claim is idempotent.) */
static void
record_pkg_dir(struct name_bag *b, const char *module,
               const char *dir, const char *path) {
    for(int j = 0; j < b->n_dirs; j++) {
        if(strcmp(b->dirs[j].dir, dir) == 0) {
            if(b->dirs[j].module == module) return;   /* idempotent */
            fprintf(stderr,
                    "asn1cgo: collision in module %s: %s <- %s (pkg-dir) and %s (pkg-dir)\n",
                    module ? module : "?", dir,
                    b->dirs[j].module ? b->dirs[j].module : "?",
                    module ? module : "?");
            (void)path;
            b->failed = 1;
            return;
        }
    }
    if(b->n_dirs + 1 > b->cap_dirs) {
        int nc = b->cap_dirs ? b->cap_dirs * 2 : 8;
        struct pkgdir_owner *np = xrealloc(b->dirs,
                                           (size_t)nc * sizeof(struct pkgdir_owner));
        if(!np) { b->failed = 1; return; }
        b->dirs = np; b->cap_dirs = nc;
    }
    b->dirs[b->n_dirs].dir = strdup(dir);
    b->dirs[b->n_dirs].module = module;
    b->n_dirs++;
}

/* Append a retained row. module is borrowed; path/rawCid/goName owned. */
static void
add_row(struct name_bag *b, const char *module,
        char *path, go_kind_e kind, char *rawCid, char *goName) {
    if(b->n_rows + 1 > b->cap_rows) {
        int nc = b->cap_rows ? b->cap_rows * 2 : 128;
        struct name_row *nr = xrealloc(b->rows,
                                       (size_t)nc * sizeof(struct name_row));
        if(!nr) { b->failed = 1; return; }
        b->rows = nr; b->cap_rows = nc;
    }
    b->rows[b->n_rows].module = module;
    b->rows[b->n_rows].path = path;
    b->rows[b->n_rows].kind = kind;
    b->rows[b->n_rows].rawCid = rawCid;
    b->rows[b->n_rows].goName = goName;
    b->rows[b->n_rows].leaf_kind = 0;   /* GLEAF_NONE; set later if leaf */
    b->rows[b->n_rows].intval = NULL;
    b->rows[b->n_rows].goType = NULL;
    b->rows[b->n_rows].is_struct = 0;
    b->rows[b->n_rows].field_type = NULL;
    b->rows[b->n_rows].sf_owner = NULL;
    b->rows[b->n_rows].slice_elem = NULL;
    b->rows[b->n_rows].opt_extra_bits = 0;
    b->rows[b->n_rows].dflt_form = 0;
    b->rows[b->n_rows].dflt_lit = NULL;
    b->rows[b->n_rows].dflt_owner = NULL;
    b->rows[b->n_rows].dflt_field = NULL;
    b->rows[b->n_rows].bit_group = 0;
    b->rows[b->n_rows].bit_type = NULL;
    b->rows[b->n_rows].ord = b->n_rows;
    b->n_rows++;
}

/* Attach leaf-stage const body data to the row just appended (the LAST row).
 * value is the decimal const value text (asn1p_itoa output, owned copy);
 * go_type the const's declared Go type name (owned copy; "" if none). */
static void
row_set_const(struct name_bag *b, const char *value, const char *go_type) {
    struct name_row *r = &b->rows[b->n_rows - 1];
    r->intval = own(value);
    r->goType = own(go_type ? go_type : "");
}

/* Attach a leaf-stage kind (GLEAF_*) to the row just appended. */
static void
row_set_leaf(struct name_bag *b, int leaf_kind) {
    b->rows[b->n_rows - 1].leaf_kind = leaf_kind;
}

/* Attach a slice-stage ELEMENT type text to the row just appended (a
 * slice-owner row: the SEQUENCE-OF type assignment's `type` row or the
 * minted anonymous/container `inline` row). Owned copy. */
static void
row_set_slice_elem(struct name_bag *b, const char *elem) {
    b->rows[b->n_rows - 1].slice_elem = own(elem);
}

/* the same, by row index (an inline element's rows are appended after the
 * slice owner's own row). */
static void
row_set_slice_elem_at(struct name_bag *b, int ix, const char *elem) {
    b->rows[ix].slice_elem = own(elem);
}

/* One name, fully recorded into BOTH the right collision scope and the dump
 * rows. Routes on kind, then hands path/rawCid/goName to the scope recorder.
 * path/rawCid/goName ownership is taken on all paths (freed at teardown).
 * leaf-stage body data (leaf_kind/intval/goType) attaches AFTER this call via
 * row_set_leaf/row_set_const (rows are address-stable between add_row calls:
 * the walker sets the fields immediately, before the next emit_name). */
static void
emit_name(struct name_bag *b, const char *module,
          char *path, go_kind_e kind, char *rawCid, char *goName) {
    if(kind_is_package_scoped(kind))
        record_package(b, module, path, kind, rawCid, goName);
    else if(kind == GK_FIELD)
        record_field(b, module, path, rawCid, goName);
    else if(kind == GK_PKG_DIR)
        record_pkg_dir(b, module, goName, path);
    add_row(b, module, path, kind, rawCid, goName);
    if(kind == GK_FIELD)
        struct_field_note(b);   /* struct-body pass: retain per-owner, in walk order */
}

/* row_set_field_type: attach a struct-body field's Go TYPE text to the row just
 * appended (a GK_FIELD row). Owned copy; pointer-star and cross-module
 * qualification are the caller's (computed by field_go_type below). */
static void
row_set_field_type(struct name_bag *b, const char *field_type) {
    struct name_row *r = &b->rows[b->n_rows - 1];
    free(r->field_type);
    r->field_type = own(field_type ? field_type : "");
}

/* row_set_field_type_at: the by-INDEX form for the one site that emits rows
 * BETWEEN the field row and its field_type computation (the SEQ-OF mint: the
 * inline row lands after the field row; the n_rows-1 form would type the
 * inline row and leave the field row untyped — the emitted struct body then
 * drops the field entirely). */
static void
row_set_field_type_at(struct name_bag *b, int ix, const char *field_type) {
    struct name_row *r = &b->rows[ix];
    free(r->field_type);
    r->field_type = own(field_type ? field_type : "");
}

/* row_set_is_struct: mark the row just appended as a STRUCT-OWNER row (its
 * declaration is `type X struct {...}` over the recorded field rows).
 * row_set_is_struct_at: the by-INDEX form for emit_choice, which appends its
 * choice-pr row between the owner row and the call (the owner row is a GK_TYPE
 * or GK_INLINE row emitted by the caller). */
static void
row_set_is_struct_at(struct name_bag *b, int ix) {
    b->rows[ix].is_struct = 1;
}

static void
row_set_is_struct(struct name_bag *b) {
    row_set_is_struct_at(b, b->n_rows - 1);
}

/* ------------------------------------------------------------------------- */
/* leaf-declaration emission. go_emit.c calls go_emit_module_decls once per
 * module (it owns the FILE); this side owns the row data (name_bag — no
 * struct mirroring across TUs). Although the dump is sorted (module, path,
 * kind, goName), DECLARATION order must be the ASN.1 WALK order (ord) — the
 * frozen comparison units pair each `type X int32` with ITS const block in ASN.1 order
 * (PrNothing heads its block; alts follow in spec order; the E2AP-PDU Pr
 * precedes the envelope ValuePr chain it introduces) and a sorted-by-path
 * order would interleave foreign blocks between a decl and its consts.
 *
 * struct-body forward decl: go_generate (below) calls qualify_field_types after
 * the walk loop; the definition lives with qualify_type (which it uses).
 * Slice stage: qualify_slice_elems beside it (the slice-element side). */
static void qualify_field_types(struct name_bag *b);
static void qualify_slice_elems(struct name_bag *b);
static int check_go_cycles(struct name_bag *b);
static int check_go_import_cycles(struct name_bag *b);

static struct name_bag *g_emit_bag;

/* g_go_module_path: the go.mod module path — `module <path>` and the
 * qualifier of every generated import line. Unset env: the path IS
 * basename(go_outdir). With ASN1CGO_GO_MODULE_PREFIX set (validated in
 * go_generate), the path is `<prefix>/<basename>`. go_conv/go_glue receive
 * this composed string through their go_module_basename params (every use
 * they make of it is import-path composition). The rt import lines compose
 * from g_go_rt_module_path the same way. Owned by this TU, freed via
 * clear_go_module_paths after the emit chain. */
static char *g_go_module_path;
static char *g_go_rt_module_path;   /* the rt module path (ASN1CGO_RT_MODULE) */

/* Prefix validation, per Go module-path rules: each '/'-separated segment is
 * a valid path element (same char class + dot rules the basename uses), and
 * the whole value has no leading/trailing '/'. Returns 0 valid, -1 invalid
 * (diagnostic already printed). Same failure route as the basename check. */
static int
check_go_module_prefix(const char *pfx) {
    int bad = 0;
    if(!pfx || !*pfx) bad = 1;              /* set-but-empty = empty first segment */
    if(!bad && (pfx[0] == '/' || pfx[strlen(pfx) - 1] == '/'))
        bad = 1;                             /* empty segment via trailing/leading slash */
    const char *seg = pfx;
    while(!bad && seg && *seg) {
        const char *slash = strchr(seg, '/');
        size_t len = slash ? (size_t)(slash - seg) : strlen(seg);
        if(len == 0) { bad = 1; break; }     /* "//" inside */
        if(seg[0] == '.' && (len == 1 || (len == 2 && seg[1] == '.')))
            { bad = 1; break; }              /* "." or ".." segment */
        for(size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)seg[i];
            if(!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == '~'))
                { bad = 1; break; }
        }
        if(bad) break;
        if(seg[0] == '.' || seg[len - 1] == '.') { bad = 1; break; }
        seg = slash ? slash + 1 : NULL;
    }
    if(bad) {
        fprintf(stderr, "asn1cgo: invalid go module prefix '%s'\n",
                pfx ? pfx : "(empty)");
        return -1;
    }
    return 0;
}

/* Compose g_go_module_path/g_go_rt_module_path from go_outdir + the env.
 * Unset env -> basename form (the historical layout, byte-identical). Both
 * outputs are malloc'd (strdup-shape, never NULL... malloc failure leaves
 * NULL; the emit's NULL guards degrade exactly like the old borrowed
 * pointer); callers free via clear_go_module_paths. */
static char *path_join2(const char *a, const char *b) {
    size_t n = strlen(a) + 1 + strlen(b) + 1;
    char *r = malloc(n);
    if(r) snprintf(r, n, "%s/%s", a, b);
    return r;
}

static char *path_dup2(const char *a) {
    size_t n = strlen(a) + 1;
    char *r = malloc(n);
    if(r) memcpy(r, a, n);
    return r;
}

static void
set_go_module_paths(const char *go_outdir) {
    const char *slash = strrchr(go_outdir, '/');
    const char *base = slash ? slash + 1 : go_outdir;
    const char *pfx = getenv("ASN1CGO_GO_MODULE_PREFIX");
    if(pfx && *pfx) {
        g_go_module_path = path_join2(pfx, base);
    } else {
        g_go_module_path = path_dup2(base);
    }
    /* the rt path is fixed: the prefix never applies to it */
    g_go_rt_module_path = path_dup2(ASN1CGO_RT_MODULE);
}

static void
clear_go_module_paths(void) {
    free(g_go_module_path); g_go_module_path = NULL;
    free(g_go_rt_module_path); g_go_rt_module_path = NULL;
}

/* Read access for sibling emitters (go_emit.c writes the go.mod module line
 * under go_emit_files, while the paths are live). */
const char *go_names_module_path(void);
const char *
go_names_module_path(void) { return g_go_module_path; }

/* ord_cmp: qsort comparator over row INDICES by r->ord (stable insertion
 * order; indices are unique so the sort is total). */
static int
ord_cmp(const void *pa, const void *pb) {
    const struct name_row *a = &g_emit_bag->rows[*(const int *)pa];
    const struct name_row *b = &g_emit_bag->rows[*(const int *)pb];
    return a->ord < b->ord ? -1 : a->ord > b->ord ? 1 : 0;
}

/* Self-prototype (-Wmissing-prototypes; declared extern in go_emit.c). */
int go_emit_module_imports(FILE *out, const char *module);
int go_emit_module_decls(FILE *out, const char *module);

/* qualify_foreign_const_types: cross-module value consts. A value const
 * typed by a governing type whose own `type` row is in ANOTHER module
 * references the type package-qualified: `pkg.TypeName`. Rewrites the
 * const rows' goType in place (idempotent — the second call sees the '.' and
 * stops). Returns nothing; the import writer and the decl emitter read the
 * qualified goType afterwards. */
static void
qualify_foreign_const_types(struct name_bag *b, const char *module) {
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *c = &b->rows[i];
        if(c->module != module || c->kind != GK_VALUE_CONST) continue;
        if(!c->goType || !*c->goType || strchr(c->goType, '.')) continue;
        /* Local governing type row? Then no qualification. */
        int local = 0;
        for(int j = 0; j < b->n_rows; j++) {
            struct name_row *t = &b->rows[j];
            if(t->module == module && t->kind == GK_TYPE
               && strcmp(t->goName, c->goType) == 0) { local = 1; break; }
        }
        if(local) continue;
        const char *tmod = NULL;
        for(int j = 0; j < b->n_rows; j++) {
            struct name_row *t = &b->rows[j];
            if(t->kind == GK_TYPE && strcmp(t->goName, c->goType) == 0) {
                tmod = t->module;
                break;
            }
        }
        if(!tmod || tmod == module) continue;
        char *q = module_pkg_go(tmod);
        q = str_append(q, ".");
        q = str_append(q, c->goType);
        free(c->goType);
        c->goType = q;
    }
}

/*
 * go_emit_module_decls — write one module's leaf DECLARATIONS into its
 * open types.go: leaf `type X <underlying>` lines, the BitString helper
 * (helper rows are per-module; go_types_emit_bitstring writes the frozen
 * comparison text), and const blocks.
 *
 * Emission order (within one module; matches the frozen units' shape):
 * rows are visited in dump sort order; a `type`/`inline`/`spec-key` row
 * with a leaf kind prints its leaf line; a `helper` row prints the
 * BitString struct; and every run of const rows sharing one goType prints
 * as ONE `const (` block emitted right AFTER the goType's own decl row
 * (the pairing: `type Criticality int32` + its const block). The
 * Pr/enum/value consts of one owner are contiguous in sort order (their
 * paths share the owner prefix), so one forward scan per decl row groups
 * them; a straggler const whose owner row precedes it non-contiguously
 * still lands in the block scanned at the owner row (the scan takes ALL
 * rows of that goType in the module, contiguous or not).
 *
 * value consts group by governing type across the module (frozen units:
 * one const block per governing type, e.g. the ProtocolIEID block in
 * ioc-container-subscription), which the same per-goType grouping
 * produces: their "owner row" is the governing type's own `type` row.
 */
/* collect_module_imports — the ONE place that decides which sibling
 * packages a module's types.go imports (used by go_emit_module_imports for
 * emission and by the import-cycle check, so they cannot drift). Fills
 * imps[] (sorted, malloc'd package-dir names; caller frees) and returns the
 * count. */
static int
collect_module_imports(struct name_bag *b, const char *module,
                       char **imps, int max_imps) {
    qualify_foreign_const_types(b, module);
    /* Collect distinct qualified `pkg.` prefixes across this module's value
     * consts (governing types) AND its field types (the
     * cross-module references qualify_field_types rewrote — `pkg.Type`,
     * `*pkg.Type`), deterministic sort, one import line each. The import
     * path form: <module_pkg> alone is NOT a full path — the
     * module root prefix is added by go_emit.c (it owns the basename); here
     * only the trailing package dir is known. */
    int n_imps = 0;
    /* note_import: dedup+sort-in one qualified prefix (the text before the
     * first '.'). from = the qualified text, plen = its prefix length. */
    #define NOTE_IMPORT(from, plen) do { \
        int seen_ = 0; \
        for(int j_ = 0; j_ < n_imps; j_++) { \
            if(strncmp(imps[j_], (from), (plen)) == 0 \
               && strlen(imps[j_]) == (plen)) { seen_ = 1; break; } \
        } \
        if(!seen_ && n_imps < max_imps) { \
            char *p_ = malloc((plen) + 1); \
            if(p_) { \
                memcpy(p_, (from), (plen)); \
                p_[(plen)] = '\0'; \
                int k_ = n_imps; \
                while(k_ > 0 && strcmp(imps[k_ - 1], p_) > 0) { \
                    imps[k_] = imps[k_ - 1]; \
                    k_--; \
                } \
                imps[k_] = p_; \
                n_imps++; \
            } \
        } \
    } while(0)
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *c = &b->rows[i];
        if(c->module != module) continue;
        if(c->kind == GK_VALUE_CONST) {
            const char *dot = c->goType ? strchr(c->goType, '.') : NULL;
            if(dot)
                NOTE_IMPORT(c->goType, (size_t)(dot - c->goType));
        } else if(c->kind == GK_FIELD) {
            const char *ft = c->field_type;
            if(ft && *ft == '*') ft++;
            const char *dot = ft ? strchr(ft, '.') : NULL;
            if(dot)
                NOTE_IMPORT(ft, (size_t)(dot - ft));
        }
    }
    #undef NOTE_IMPORT
    return n_imps;
}

int
go_emit_module_imports(FILE *out, const char *module) {
    struct name_bag *b = g_emit_bag;
    if(!b) return 0;
    char *imps[64];
    int n_imps = collect_module_imports(b, module, imps, 64);
    if(n_imps == 0) return 0;
    int rc = 0;
    if(fputs("\nimport (\n", out) >= 0) {
        for(int j = 0; j < n_imps && rc == 0; j++) {
            /* The import path is <module path>/<module_pkg>, where the
             * module path is basename-only or <prefix>/<basename> per env. */
            if(fprintf(out, "\t\"%s/%s\"\n",
                       g_go_module_path ? g_go_module_path : "",
                       imps[j]) < 0)
                rc = -1;
        }
        if(rc == 0 && fputs(")\n", out) < 0) rc = -1;
    } else
        rc = -1;
    for(int j = 0; j < n_imps; j++) free(imps[j]);
    if(rc < 0) return -1;
    return n_imps;
}

int
go_emit_module_decls(FILE *out, const char *module) {
    struct name_bag *b = g_emit_bag;
    if(!b) return 0;
    int rc = 0;
    int prev_block = 0;   /* the previous decl ended a const block: the next
                           * decl leads with a blank line (gofmt canon). */
    int wrote_any = 0;    /* any decl written: gofmt also wants ONE blank line
                           * after the package clause (before the first decl),
                           * so the first written line leads with "\n" too. */

    /* Walk-order index (the rows array is dump-sorted; decl order is ord). */
    int *ordx = malloc((size_t)b->n_rows * sizeof(int));
    if(!ordx) return -1;
    for(int i = 0; i < b->n_rows; i++) ordx[i] = i;
    qsort(ordx, (size_t)b->n_rows, sizeof(int), ord_cmp);

    for(int x = 0; x < b->n_rows && rc == 0; x++) {
        struct name_row *r = &b->rows[ordx[x]];
        if(r->module != module) continue;
        switch(r->kind) {
        case GK_HELPER:
            if((prev_block || !wrote_any) && fputs("\n", out) < 0) { rc = -1; break; }
            rc = go_types_emit_bitstring(out);
            prev_block = 0;
            wrote_any = 1;
            break;
        case GK_TYPE:
        case GK_INLINE:
        case GK_SPEC_KEY:
        case GK_SPEC_VALUE:
        case GK_CHOICE_PR:     /* <T>Pr decl + its PrNothing/Pr<Alt> block    */
        case GK_SPEC_PR:       /* <X>ValuePr decl + the value-union block     */
            /* struct-body stage: a struct-owner row (SEQUENCE assignment / inline SEQ /
             * field-shaped spec / the <X>Value union) writes its STRUCT BODY
             * here — `type X struct {` + one column-aligned field line per
             * GK_FIELD row whose sf_owner == this struct (in ord order = AST
             * member order), + `}`. The fields' field_type was set during the
             * walk (named refs qualified post-walk, mapping-table leaves, minted
             * inline names; pointer-star per the marker rule). Two passes:
             * widths first (gofmt alignment), then the lines. */
            if(r->is_struct) {
                int name_w = 0, type_w = 0;
                for(int s = 0; s < b->n_rows; s++) {
                    struct name_row *f = &b->rows[ordx[s]];
                    if(!f->sf_owner || strcmp(f->sf_owner, r->goName) != 0)
                        continue;
                    if(!f->field_type || !*f->field_type) continue;
                    int nw = (int)strlen(f->goName) + 1;
                    int tw = (int)strlen(f->field_type) + 1;
                    if(nw > name_w) name_w = nw;
                    if(tw > type_w) type_w = tw;
                }
                if((prev_block || !wrote_any) && fputs("\n", out) < 0) {
                    rc = -1;
                    break;
                }
                rc = go_types_emit_struct_open(out, r->goName);
                if(rc == 0) {
                    for(int s = 0; s < b->n_rows && rc == 0; s++) {
                        struct name_row *f = &b->rows[ordx[s]];
                        if(!f->sf_owner || strcmp(f->sf_owner, r->goName) != 0)
                            continue;
                        if(!f->field_type || !*f->field_type) continue;
                        rc = go_types_emit_struct_field(
                            out, f->goName, f->field_type, name_w, type_w);
                    }
                }
                if(rc == 0)
                    rc = go_types_emit_struct_close(out);
                /* The DEFAULT values of this struct's DEFAULT members,
                 * exported next to the type. */
                int emitted_default = 0;
                for(int d = 0; d < b->n_rows && rc == 0; d++) {
                    struct name_row *dr = &b->rows[ordx[d]];
                    if(dr->kind != GK_DEFAULT_VALUE || dr->module != module
                       || !dr->dflt_owner
                       || strcmp(dr->dflt_owner, r->goName) != 0)
                        continue;
                    const char *ft = NULL;
                    for(int s2 = 0; s2 < b->n_rows; s2++) {
                        struct name_row *f = &b->rows[s2];
                        if(f->kind == GK_FIELD && f->sf_owner
                           && f->module == module
                           && strcmp(f->sf_owner, dr->dflt_owner) == 0
                           && strcmp(f->goName, dr->dflt_field) == 0) {
                            ft = f->field_type;
                            break;
                        }
                    }
                    if(!ft || !*ft) {
                        fprintf(stderr, "asn1cgo: DEFAULT member %s has no Go "
                                "type\n", dr->path);
                        rc = -1;
                        break;
                    }
                    emitted_default = 1;
                    if(fprintf(out,
                               "\n// %s is the ASN.1 DEFAULT of %s.%s. The Go zero value is not\n"
                               "// the DEFAULT: set the field explicitly.\n",
                               dr->goName, dr->dflt_owner, dr->dflt_field) < 0)
                        rc = -1;
                    else if(dr->dflt_form == 1)
                        rc = fprintf(out, "const %s %s = %s\n", dr->goName, ft,
                                     dr->dflt_lit) < 0 ? -1 : 0;
                    else
                        rc = fprintf(out, "var %s = %s{%s}\n", dr->goName, ft,
                                     dr->dflt_lit) < 0 ? -1 : 0;
                }
                prev_block = emitted_default;
                wrote_any = 1;
                break;
            }
            if(r->kind == GK_TYPE || r->kind == GK_INLINE
               || r->kind == GK_SPEC_KEY) {
                /* slice stage: a slice-owner row (a SEQUENCE-OF type
                 * assignment's `type` row or a minted anonymous/container
                 * `inline` row) declares the named slice alias
                 * `type X []Elem` here — before the leaf arm (a slice row
                 * carries GLEAF_NONE and no is_struct). A row carrying NEITHER
                 * slice_elem nor a leaf kind nor is_struct is a constructed
                 * body of a later step — skip silently (the CHOICE arms of
                 * the CHOICE pass emits its own Pr/alt decls). */
                if(r->slice_elem && *r->slice_elem) {
                    if((prev_block || !wrote_any) && fputs("\n", out) < 0) {
                        rc = -1;
                        break;
                    }
                    rc = go_types_emit_slice(out, r->goName, r->slice_elem);
                    prev_block = 0;
                    wrote_any = 1;
                    break;
                }
                if(r->leaf_kind == 0) break;   /* constructed, not a struct
                                                * owner: later steps (CHOICE
                                                * bodies by the CHOICE pass). */
                if((prev_block || !wrote_any) && fputs("\n", out) < 0) {
                    rc = -1;
                    break;
                }
                rc = go_types_emit_leaf(out, r->goName, r->leaf_kind);
                prev_block = 0;
                wrote_any = 1;
            } else {
                /* The discriminant decl `type <T>Pr int32` / `type <X>ValuePr
                 * int32` — the frozen form pairs it with its const block. */
                if((prev_block || !wrote_any) && fputs("\n", out) < 0) {
                    rc = -1;
                    break;
                }
                if(fprintf(out, "type %s int32\n", r->goName) < 0) {
                    rc = -1;
                    break;
                }
                wrote_any = 1;
            }
            /* A leaf with consts (GLEAF_ENUM), a Pr/ValuePr discriminant, or
             * a governing leaf prints its const block right after the
             * decl line: every const row in this module whose goType ==
             * r->goName, in WALK order. Column widths computed over the whole
             * block first (gofmt alignment). Value consts (typed by the
             * governing leaf) attach to the governing type's own row; in the
             * governing type's module. If that type row is foreign, the consts
             * still emit HERE (the const lives in the DEFINING module of
             * the value assignment = this module), as a standalone block with
             * the qualified type. */
            if(rc == 0) {
                int name_w = 0, type_w = 0, nblk = 0;
                for(int y = 0; y < b->n_rows; y++) {
                    struct name_row *c = &b->rows[ordx[y]];
                    if(c->module != module) continue;
                    if(c->kind != GK_ENUM_CONST && c->kind != GK_CHOICE_CONST
                       && c->kind != GK_VALUE_CONST)
                        continue;
                    if(c->bit_group) continue;   /* named-bit consts: own block */
                    if(!c->goType || !strstr(c->goType, r->goName)
                       || strcmp(c->goType, r->goName) != 0) {
                        /* qualified (contains '.' or a foreign qualifier) —
                         * match on the suffix after the LAST '.'. */
                        const char *dot = strrchr(c->goType, '.');
                        if(!dot || strcmp(dot + 1, r->goName) != 0)
                            continue;
                    }
                    int nw = (int)strlen(c->goName) + 1;
                    int tw = (int)strlen(c->goType) + 1;
                    if(nw > name_w) name_w = nw;
                    if(tw > type_w) type_w = tw;
                    nblk++;
                }
                if(nblk > 0) {
                    if(go_types_emit_const_open(out) < 0) { rc = -1; break; }
                    for(int y = 0; y < b->n_rows && rc == 0; y++) {
                        struct name_row *c = &b->rows[ordx[y]];
                        if(c->module != module) continue;
                        if(c->kind != GK_ENUM_CONST
                           && c->kind != GK_CHOICE_CONST
                           && c->kind != GK_VALUE_CONST)
                            continue;
                        if(c->bit_group) continue;
                        const char *dot = c->goType
                            ? strrchr(c->goType, '.') : NULL;
                        if(!c->goType
                           || (dot ? strcmp(dot + 1, r->goName) != 0
                                   : strcmp(c->goType, r->goName) != 0))
                            continue;
                        rc = go_types_emit_const(out, c->goName, c->goType,
                                                 c->intval ? c->intval : "0",
                                                 name_w, type_w);
                    }
                    if(rc == 0)
                        rc = go_types_emit_const_close(out);
                    prev_block = 1;
                }
            }
            break;
        case GK_ENUM_CONST:
            /* A named-bit BIT STRING's bit positions: one standalone block of
             * `Name int = N` per type, emitted at its first bit row (the bits
             * of one type are contiguous in walk order). Every other
             * enum-const row is emitted at its owner's decl row above. */
            if(r->bit_group && (x == 0
               || b->rows[ordx[x - 1]].bit_group != r->bit_group)) {
                int name_w = 0, type_w = 0, y;
                for(y = x; y < b->n_rows
                           && b->rows[ordx[y]].bit_group == r->bit_group; y++) {
                    struct name_row *c = &b->rows[ordx[y]];
                    int nw = (int)strlen(c->goName) + 1;
                    int tw = (int)strlen(c->goType) + 1;
                    if(nw > name_w) name_w = nw;
                    if(tw > type_w) type_w = tw;
                }
                rc = go_types_emit_const_open_bits(out, r->bit_type);
                for(int z = x; z < y && rc == 0; z++) {
                    struct name_row *c = &b->rows[ordx[z]];
                    rc = go_types_emit_const(out, c->goName, c->goType,
                                             c->intval, name_w, type_w);
                }
                if(rc == 0)
                    rc = go_types_emit_const_close(out);
                prev_block = 1;
                wrote_any = 1;
            }
            break;
        default:
            break;   /* field/pkg-dir rows; choice-/value-const rows are
                       emitted grouped at their owner's decl row above */
        }
    }

    /* Standalone const blocks: value consts whose governing type row is
     * NOT in this module (e.g. a ProtocolIE-ID const defined in
     * E2AP-Constants: the const lives HERE, its governing type is foreign).
     * Emitted after the local decls, walk order, gofmt-aligned, with the
     * package-qualified type the prepass set. */
    {
        int name_w = 0, type_w = 0, nblk = 0;
        for(int y = 0; y < b->n_rows; y++) {
            struct name_row *c = &b->rows[ordx[y]];
            if(c->module != module || c->kind != GK_VALUE_CONST) continue;
            if(!c->goType || !strchr(c->goType, '.')) continue;   /* local */
            int nw = (int)strlen(c->goName) + 1;
            int tw = (int)strlen(c->goType) + 1;
            if(nw > name_w) name_w = nw;
            if(tw > type_w) type_w = tw;
            nblk++;
        }
        if(nblk > 0 && rc == 0) {
            /* go_types_emit_const_open's leading "\n" is the separator (the
             * import block / prior decl ended with a single "\n"). */
            if(go_types_emit_const_open(out) < 0) rc = -1;
            for(int y = 0; y < b->n_rows && rc == 0; y++) {
                struct name_row *c = &b->rows[ordx[y]];
                if(c->module != module || c->kind != GK_VALUE_CONST) continue;
                if(!c->goType || !strchr(c->goType, '.')) continue;
                rc = go_types_emit_const(out, c->goName, c->goType,
                                         c->intval ? c->intval : "0",
                                         name_w, type_w);
            }
            if(rc == 0)
                rc = go_types_emit_const_close(out);
        }
    }

    free(ordx);
    return rc;
}

/* Leaf body kinds: what a leaf `type` row's declaration is. Declared here
 * (both walkers and the emit read it; go_constructs.h stays construct-
 * vocabulary-only per its charter). Set by this file's walk (which holds the
 * live arg_t/terminal context asn1c_type_fits_long needs); read by
 * go_types.c via the int-typed prototype. */
typedef enum {
    GLEAF_NONE = 0,      /* not a leaf / no body data (structs, choices...) */
    GLEAF_INT64,         /* INTEGER → int64 (wide, signed)                   */
    GLEAF_UINT64,        /* INTEGER → uint64 (wide unsigned / INTEGER_t
                            range fitting uint64)                           */
    GLEAF_BOOL,          /* BOOLEAN → bool                                  */
    GLEAF_NULL,          /* NULL → struct{}                                 */
    GLEAF_REAL,          /* REAL → float64                                  */
    GLEAF_OCTETS,        /* OCTET STRING / unresolved open type → []byte    */
    GLEAF_OID,           /* OBJECT IDENTIFIER → []byte                      */
    GLEAF_STRING,        /* restricted string types → string                */
    GLEAF_BITSTRING,     /* BIT STRING → the BitString helper type          */
    GLEAF_ENUM           /* ENUMERATED → int32 + const block                */
} go_leaf_kind;

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
    /* member_stars out-param: marker bits beyond
     * EM_OPTIONAL on an OPTIONAL member of the LAST member_stars call
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

/* ------------------------------------------------------------------------- */
/* Forward decls of the recursive walkers (mirror go_walk.c). */
static int walk_names_expr(struct walk_ctx *ctx, asn1p_expr_t *expr);
static int walk_names_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
                              const char *parent_path);

/* Build a dotted ASN.1 path. parent may be NULL/empty. malloc'd, never NULL. */
static char *
make_path(const char *parent, const char *leaf) {
    char *p = parent && *parent
        ? str_append(strdup(""), parent) : strdup("");
    if(p && *p) p = str_append(p, ".");
    return str_append(p, leaf ? leaf : "?");
}

/* Deterministic dump order: by module, then path, then kind, then goName. */
static int
row_cmp(const void *pa, const void *pb) {
    const struct name_row *a = pa, *b = pb;
    int c = strcmp(a->module ? a->module : "?", b->module ? b->module : "?");
    if(c) return c;
    c = strcmp(a->path ? a->path : "?", b->path ? b->path : "?");
    if(c) return c;
    c = strcmp(g_kind_tag[a->kind], g_kind_tag[b->kind]);
    if(c) return c;
    return strcmp(a->goName ? a->goName : "", b->goName ? b->goName : "");
}

/* Mark that `module` owns a BIT-STRING member (so go_generate emits one helper
 * row for it). Called from the member walk when a member's terminal is BIT
 * STRING. Idempotent. */
static void
mark_bitstring_module(struct name_bag *b, const char *module) {
    for(int j = 0; j < b->n_bs; j++)
        if(b->bs_modules[j] == module) return;
    if(b->n_bs + 1 > b->cap_bs) {
        int nc = b->cap_bs ? b->cap_bs * 2 : 8;
        const char **np = xrealloc(b->bs_modules, (size_t)nc * sizeof(char *));
        if(!np) { b->failed = 1; return; }
        b->bs_modules = np; b->cap_bs = nc;
    }
    b->bs_modules[b->n_bs++] = module;
}

/* go_compiler_flags: the driver's asn1c_flags, cached once per run by
 * go_generate (classify_integer_leaf's arg_t needs A1C_USE_WIDE_TYPES state).
 * Static here: one process runs one generation. */
static enum asn1c_flags go_compiler_flags;

/* go_oer_disabled: nonzero when this run was started without OER support
 * (-no-gen-OER, i.e. A1C_GEN_OER clear). The generated cgo preambles then
 * carry -DASN_DISABLE_OER_SUPPORT, matching what the C backend writes into
 * its own Makefile.am.example (asn1c_save.c). */
int go_oer_disabled(void);
int go_oer_disabled(void) { return (go_compiler_flags & A1C_GEN_OER) == 0; }

/* -------------------------------------------------------------------------
 * leaf-kind classification. The INTEGER class comes from asn1c's own
 * decision function (asn1c_type_fits_long, asn1c_misc.c:408 — note:
 * "The Go backend MUST call the same function, not re-derive the range"), fed
 * a minimal arg_t carrying the walk's asn/ns and the leaf terminal. It needs
 * a live struct arg (arg->asn, arg->ns, arg->flags) only; every field the
 * function touches is one of those (the asn1f_find_terminal_type_ex call at
 * asn1c_misc.c:414-417 uses arg->asn + the module namespace from expr, the
 * A1C_USE_WIDE_TYPES test at :449/:490/:502 reads arg->flags).
 *
 * this completes the INTEGER_t case the fits_long enum cannot express
 * (FL_NOTFIT covers both "fits neither" and "-fwide-types chose INTEGER_t"):
 * at that point asn1c emits INTEGER_t, and the Go type is decided from the
 * constrained range via the SAME engine asn1c uses (asn1constraint_compute_
 * PER_range, asn1fix_crange.h:62; asn1c_C.c's own range emission path):
 *   uint64  iff lb ≥ 0 (left edge a value) and ub ≤ 2^64−1 (right edge a
 *           value or unbounded CAN'T happen for INTEGER_t — an unbounded
 *           right is NOTFIT-able only under wide types; treat ARE_MAX with
 *           lb ≥ 0 as NOT fitting, mirroring "from the constrained
 *           range" and the unconstrained-INTEGER_t failure klaxon)
 *   int64   iff both edges are values and fit int64
 *   else    the generator FAILS (exit 70) naming the type — "no
 *           []byte fallback until a real instance and a frozen precedent
 *           exist" (none in scope today).
 * Returns the GLEAF_* for the INTEGER, printing the failure diagnostic and
 * setting failed on the bag when neither fits.
 */
static int
classify_integer_leaf(struct walk_ctx *ctx, asn1p_expr_t *terminal,
                      const char *path_for_diag) {
    arg_t a;
    memset(&a, 0, sizeof a);
    a.asn = ctx->asn;
    a.ns = ctx->ns;
    a.expr = terminal;
    a.flags = go_compiler_flags;   /* the driver's asn1c_flags (cached) */

    switch(asn1c_type_fits_long(&a, terminal)) {
    case FL_FITS_SIGNED: return GLEAF_INT64;
    case FL_FITS_UNSIGN: return GLEAF_UINT64;
    case FL_PRESUMED:
        /* Native `long` WITHOUT -fwide-types (asn1c_misc.c:453-454): an
         * unconstrained INTEGER like `RIC-Format-Type ::= INTEGER` (E2SM-
         * COMMON-IEs:132) — asn1c emits `typedef long` (RIC-Format-Type.h:
         * 22), so the Go type is int64. FL_PRESUMED is the native branch;
         * only FL_NOTFIT is the INTEGER_t branch. */
        return GLEAF_INT64;
    default: break;   /* FL_NOTFIT: INTEGER_t (or -fwide-types forced wide) */
    }

    /* INTEGER_t path: decide from the constrained PER range via
     * asn1c's own engine. Unconstrained INTEGER_t (no combined_constraints,
     * or the range not PER-visible) fails per the klaxon. */
    if(!terminal->combined_constraints) {
        fprintf(stderr,
                "asn1cgo: INTEGER %s resolves to INTEGER_t with no combined "
                "constraints (uint64/int64 undecidable) in module %s\n",
                path_for_diag ? path_for_diag : "?",
                ctx->module ? ctx->module : "?");
        ctx->bag->failed = 1;
        return 0;
    }
    asn1cnst_range_t *range = asn1constraint_compute_PER_range(
        terminal->Identifier, terminal->expr_type,
        terminal->combined_constraints, ACT_EL_RANGE, 0, 0, 0);
    if(!range || range->empty_constraint || range->incompatible
       || range->not_PER_visible) {
        fprintf(stderr,
                "asn1cgo: INTEGER %s resolves to INTEGER_t with no decidable "
                "PER range undecidable) in module %s\n",
                path_for_diag ? path_for_diag : "?",
                ctx->module ? ctx->module : "?");
        if(range) asn1constraint_range_free(range);
        ctx->bag->failed = 1;
        return 0;
    }
    asn1cnst_edge_t left = range->left, right = range->right;
    int extensible = range->extensible;
    asn1constraint_range_free(range);
    /* An extensible range's extension addition can exceed the root bound;
     * the decision uses the constraint as asn1c applies it (asn1c_type_fits_
     * long treats extensible wide ranges as NOTFIT). A (0..2^36−1,...) root
     * with open extension still fits uint64 per the integer-wide frozen unit
     * (GNB-CU-UP-ID is extensible? no — it is a plain 0..2^36−1; treat an
     * extensible range conservatively: only accept when BOTH edges are
     * concrete values). */
    if(left.type != ARE_VALUE || right.type != ARE_VALUE) {
        fprintf(stderr,
                "asn1cgo: INTEGER %s resolves to INTEGER_t whose range has an "
                "open edge (neither int64 nor uint64 applies; lb=%d ub=%d"
                "%s) in module %s\n",
                path_for_diag ? path_for_diag : "?",
                left.type == ARE_VALUE ? 0 : 1, right.type == ARE_VALUE ? 0 : 1,
                extensible ? ", extensible" : "",
                ctx->module ? ctx->module : "?");
        ctx->bag->failed = 1;
        return 0;
    }
    /* intmax arithmetic on asn1c_integer_t (128-bit here) makes the
     * bounds test exact; the constants are the C99 int64/uint64 limits. The
     * U suffix keeps the uint64 limit a well-typed constant (asn1c_integer_t
     * is signed 128-bit here, so the plain decimal literal is fine either
     * way; the suffix silences the "so large it is unsigned" warning). */
    if(left.value >= 0
       && right.value <= (asn1c_integer_t)18446744073709551615ULL) {
        /* record the wide-INTEGER leaf (its converters use the
         * asn_umax2INTEGER/asn_INTEGER2umax verb pair, not a scalar mirror). */
        if(!ctx->wide_nr)
            go_conv_record_wide_integer(ctx->wide_cid ? ctx->wide_cid
                                                      : GO_MKID(terminal));
        ctx->wide_hit = 1;
        return GLEAF_UINT64;
    }
    if(left.value >= (asn1c_integer_t)(-9223372036854775807LL - 1)
       && right.value <= (asn1c_integer_t)9223372036854775807LL) {
        if(!ctx->wide_nr)
            go_conv_record_wide_integer(ctx->wide_cid ? ctx->wide_cid
                                                      : GO_MKID(terminal));
        ctx->wide_hit = 1;
        return GLEAF_INT64;
    }
    /* asn1p_itoa returns a pointer into a small static RING: two calls in
     * one printf can render the same slot, so render each edge into its own
     * buffer (asn1p_itoa_s, asn1p_integer.h:44) for a faithful diagnostic. */
    {
        char lb[64], rb[64];
        asn1p_itoa_s(lb, sizeof lb, left.value);
        asn1p_itoa_s(rb, sizeof rb, right.value);
        /* asn1p_itoa_s tags an unsigned-long-long-sized value with a C "U". */
        for(char *e = lb + strlen(lb); e > lb && e[-1] == 'U'; ) *--e = 0;
        for(char *e = rb + strlen(rb); e > rb && e[-1] == 'U'; ) *--e = 0;
        fprintf(stderr,
                "asn1cgo: INTEGER %s range [%s..%s] fits neither int64 nor "
                "uint64, so it has no Go representation (refused) in module %s\n",
                path_for_diag ? path_for_diag : "?", lb, rb,
                ctx->module ? ctx->module : "?");
    }
    ctx->bag->failed = 1;
    return 0;
}

/* classify_leaf: the GLEAF_* kind of a non-INTEGER leaf terminal. INTEGER
 * goes through classify_integer_leaf (asn1c's own decision function). */
static int
classify_leaf(struct walk_ctx *ctx, asn1p_expr_t *terminal,
              const char *path_for_diag) {
    switch(go_construct_classify(terminal)) {
    case GO_CONSTR_INTEGER:
        return classify_integer_leaf(ctx, terminal, path_for_diag);
    case GO_CONSTR_BOOLEAN:  return GLEAF_BOOL;
    case GO_CONSTR_NULL:     return GLEAF_NULL;
    case GO_CONSTR_REAL:     return GLEAF_REAL;
    case GO_CONSTR_OCTET_STRING: return GLEAF_OCTETS;
    case GO_CONSTR_BIT_STRING:   return GLEAF_BITSTRING;
    case GO_CONSTR_PRINTABLE:    return GLEAF_STRING;
    case GO_CONSTR_ENUMERATED:   return GLEAF_ENUM;
    default: break;
    }
    /* OID and other string kinds are GO_CONSTR_UNSUPPORTED in the frozen
     * classifier (absent from the in-scope specs; the classification walk
     * already rejects them loudly). An unsupported leaf reaching here is an internal
     * ordering bug: record it as a failure named by path. */
    fprintf(stderr, "asn1cgo: leaf terminal of unsupported kind at %s "
                    "in module %s\n",
            path_for_diag ? path_for_diag : "?",
            ctx->module ? ctx->module : "?");
    ctx->bag->failed = 1;
    return 0;
}

/* Top-level path elements of the Go standard library, plus the reserved
 * patterns std, cmd, all. A module whose path is exactly one of these (no
 * ASN1CGO_GO_MODULE_PREFIX, so the module path is the bare -Fgo basename)
 * makes the generated imports ("go/<pkg>", "net/<pkg>", ...) resolve inside
 * the standard library tree. Source: `go list std`, first path elements,
 * minus vendor/internal, from go1.27.3. tests/run-stdlib-names.sh compares
 * this table with the local toolchain; keep one name per STDLIB_ROW line,
 * sorted, as that script parses them. */
#define STDLIB_ROW(n) n,
static const char *const go_stdlib_top[] = {
    STDLIB_ROW("all")
    STDLIB_ROW("archive")
    STDLIB_ROW("bufio")
    STDLIB_ROW("bytes")
    STDLIB_ROW("cmd")
    STDLIB_ROW("cmp")
    STDLIB_ROW("compress")
    STDLIB_ROW("container")
    STDLIB_ROW("context")
    STDLIB_ROW("crypto")
    STDLIB_ROW("database")
    STDLIB_ROW("debug")
    STDLIB_ROW("embed")
    STDLIB_ROW("encoding")
    STDLIB_ROW("errors")
    STDLIB_ROW("expvar")
    STDLIB_ROW("flag")
    STDLIB_ROW("fmt")
    STDLIB_ROW("go")
    STDLIB_ROW("hash")
    STDLIB_ROW("html")
    STDLIB_ROW("image")
    STDLIB_ROW("index")
    STDLIB_ROW("io")
    STDLIB_ROW("iter")
    STDLIB_ROW("log")
    STDLIB_ROW("maps")
    STDLIB_ROW("math")
    STDLIB_ROW("mime")
    STDLIB_ROW("net")
    STDLIB_ROW("os")
    STDLIB_ROW("path")
    STDLIB_ROW("plugin")
    STDLIB_ROW("reflect")
    STDLIB_ROW("regexp")
    STDLIB_ROW("runtime")
    STDLIB_ROW("slices")
    STDLIB_ROW("sort")
    STDLIB_ROW("std")
    STDLIB_ROW("strconv")
    STDLIB_ROW("strings")
    STDLIB_ROW("structs")
    STDLIB_ROW("sync")
    STDLIB_ROW("syscall")
    STDLIB_ROW("testing")
    STDLIB_ROW("text")
    STDLIB_ROW("time")
    STDLIB_ROW("unicode")
    STDLIB_ROW("unique")
    STDLIB_ROW("unsafe")
    STDLIB_ROW("uuid")
    STDLIB_ROW("weak")
    NULL
};
#undef STDLIB_ROW

/* Validate ASN1CGO_RT_LOCAL: <dir>/go.mod must exist and carry the line
 * `module ASN1CGO_RT_MODULE`. 0 ok, -1 (diagnostic printed). */
static int
go_rt_local_check(const char *dir) {
    char *gm = path_join2(dir, "go.mod");
    FILE *f = gm ? fopen(gm, "r") : NULL;
    int ok = 0;
    if(f) {
        char line[512];
        while(fgets(line, sizeof line, f)) {
            char *p = line;
            while(*p == ' ' || *p == '\t') p++;
            if(strncmp(p, "module", 6) != 0 || (p[6] != ' ' && p[6] != '\t'))
                continue;
            p += 6;
            while(*p == ' ' || *p == '\t') p++;
            size_t n = strlen(ASN1CGO_RT_MODULE);
            if(strncmp(p, ASN1CGO_RT_MODULE, n) == 0
               && (p[n] == '\n' || p[n] == '\r' || p[n] == '\0'
                   || p[n] == ' ' || p[n] == '\t'))
                ok = 1;
            break;
        }
        fclose(f);
    }
    if(!ok)
        fprintf(stderr, "asn1cgo: ASN1CGO_RT_LOCAL '%s' is not an rt checkout "
                "(%s/go.mod must declare 'module %s')\n", dir, dir,
                ASN1CGO_RT_MODULE);
    free(gm);
    return ok ? 0 : -1;
}

/* Pre-flight checks that depend only on the command line / environment
 * (not on the AST or on anything the C pass stamps): -Fgo basename and
 * ASN1CGO_GO_MODULE_PREFIX. Callable before asn1_compile. 0 ok, -1 reject. */
int
go_check_outdir(const char *go_outdir) {
    /* go_outdir basename must be a valid Go module path element: char class
     * [A-Za-z0-9._~-], no leading/trailing '.', not '.' or '..'. (A '/' cannot
     * occur in a basename by definition — it's the last path segment — so the
     * checks are char class + leading/trailing-dot + the '..' reject.) */
    if(go_outdir && *go_outdir) {
        const char *base = strrchr(go_outdir, '/');
        base = base ? base + 1 : go_outdir;
        int bad = 0;
        if(base[0] == '\0' || !strcmp(base, ".") || !strcmp(base, ".."))
            bad = 1;
        if(!bad && (base[0] == '.' || base[strlen(base) - 1] == '.'))
            bad = 1;
        for(const char *p = base; !bad && *p; p++) {
            unsigned char c = (unsigned char)*p;
            if(!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == '~'))
                bad = 1;
        }
        if(bad) {
            fprintf(stderr,
                    "asn1cgo: invalid go module path '%s'\n", base);
            return -1;          /* -> driver EX_SOFTWARE (70) */
        }
    }

    /* Without a prefix the module path is the bare basename; reject one that
     * is a standard-library top-level element (the generated imports would
     * land inside the stdlib tree and `go build` fails). With a prefix the
     * first path element contains a dot, so it cannot collide. */
    {
        const char *pfx0 = getenv("ASN1CGO_GO_MODULE_PREFIX");
        if(go_outdir && *go_outdir && !(pfx0 && *pfx0)) {
            const char *base = strrchr(go_outdir, '/');
            base = base ? base + 1 : go_outdir;
            for(size_t i = 0; go_stdlib_top[i]; i++) {
                if(!strcmp(base, go_stdlib_top[i])) {
                    fprintf(stderr,
                            "asn1cgo: go module path '%s' collides with the "
                            "Go standard library; set ASN1CGO_GO_MODULE_PREFIX "
                            "or rename the -Fgo directory\n", base);
                    return -1;      /* -> driver EX_SOFTWARE (70) */
                }
            }
        }
    }

    /* ASN1CGO_RT_LOCAL=<dir>: an rt checkout used via `replace` / go.work.
     * It must be a directory whose go.mod declares the rt module path. */
    {
        const char *loc = getenv("ASN1CGO_RT_LOCAL");
        if(loc && *loc && go_rt_local_check(loc) < 0)
            return -1;          /* -> driver EX_SOFTWARE (70) */
    }

    /* ASN1CGO_GO_MODULE_PREFIX: when set, the go.mod module line and every
     * generated import gain the prefix (release layout). Validated per Go
     * module-path segment rules; an invalid prefix fails here, before any
     * file is written. Unset -> the basename-only form above (identical
     * bytes to the historical layout). */
    {
        const char *pfx = getenv("ASN1CGO_GO_MODULE_PREFIX");
        if(pfx && *pfx && check_go_module_prefix(pfx) < 0)
            return -1;          /* -> driver EX_SOFTWARE (70) */
    }
    return 0;
}

/* The public entry: declared extern in go_backend.c. Walks every module,
 * records all names, writes the dump if requested, then defers to go_emit
 * only on a clean pass. */
int
go_generate(asn1p_t *asn, const char *go_outdir, enum asn1c_flags flags) {
    struct name_bag bag = {0};
    go_compiler_flags = flags;   /* cached for classify_integer_leaf's arg_t */

    if(go_check_outdir(go_outdir) != 0)
        return -1;          /* -> driver EX_SOFTWARE (70) */

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next) {
        /* Skip asn1c's auto-loaded standard-modules (the C backend doesn't emit
         * for them either; the marker is set at asn1c.c:539). They carry no
         * user types in the in-scope specs and would mint spurious pkg-dirs. */
        if(mod->_tags & MT_STANDARD_MODULE)
            continue;

        struct walk_ctx ctx = {0};
        ctx.module = mod->ModuleName;
        ctx.parent_go = "";
        ctx.parent_cid = "";
        ctx.ns = asn1_namespace_new_from_module(mod, 1);
        ctx.asn = asn;
        ctx.bag = &bag;

        asn1p_expr_t *expr;
        TQ_FOR(expr, &(mod->members), next) {
            if(walk_names_expr(&ctx, expr) < 0) {
                asn1_namespace_free(ctx.ns);
                /* best-effort teardown */
                goto done;
            }
        }

        /* pkg-dir: one per real module, package dir = module id lowercased. The
         * row doubles as the across-module collision probe (record_pkg_dir). */
        {
            char *pkg = module_pkg_go(mod->ModuleName);
            char *path = strdup(mod->ModuleName ? mod->ModuleName : "?");
            emit_name(&bag, mod->ModuleName, path, GK_PKG_DIR,
                      strdup(pkg), pkg);   /* rawCid=goName=the dir itself */
        }

        /* helper BitString: one row per module that owns a BIT-STRING member. */
        for(int j = 0; j < bag.n_bs; j++)
            if(bag.bs_modules[j] == mod->ModuleName) {
                emit_name(&bag, mod->ModuleName,
                          strdup(mod->ModuleName ? mod->ModuleName : "?"),
                          GK_HELPER,
                          strdup("asn1cgo_bits_flat"),
                          strdup("BitString"));
            }

        asn1_namespace_free(ctx.ns);
    }

    /* pkg-dir collisions were detected during the walk (record_pkg_dir). The
     * rows are already in the bag; nothing more to do here but emit. */

    /* struct-body prepass: cross-module qualification of field
     * types (the walk stores unqualified names; the bag must be complete
     * first — a member may reference an assignment this module, or another,
     * defines later in the walk). Runs before the dump/emit below.
     * Slice-stage: qualify_slice_elems runs beside it — the same lookup over the
     * same table, applied to every slice-owner row's ELEMENT type. */
    qualify_field_types(&bag);
    qualify_slice_elems(&bag);
    /* by-value-cycle check: a type cycle in which every edge is by
     * value (no OPTIONAL *T, no CHOICE/value-union alt *T, no slice) has no
     * finite Go representation — as flat types the SCC would expand forever.
     * Computed over the EMITTED Go reference graph (the rows themselves), so
     * specialty mint sites (spec unions, inline slices) are covered by
     * construction. Sets bag->failed + names the cycle (-> exit 70). */
    if(check_go_cycles(&bag))
        bag.failed = 1;

done:
    (void)0;
    {
        int rc = 0;
        /* Dump, if requested, regardless of failed (so the operator sees why). */
        const char *dumppath = getenv("ASN1CGO_DUMP_NAMES");
        /* Dump invariant: EVERY emitted row must carry a non-empty goName
         * AND a non-empty rawCid — a blank field means the walker emitted a node
         * that resolves to no Go name (the extension-marker leak; any future
         * such node). This is checked whether or not a dump file is requested, so
         * a real -Fgo run (no dump) still closes the gate. A blank row is a hard
         * generator error: name it (module/path/kind) and fail. */
        for(int j = 0; j < bag.n_rows; j++) {
            struct name_row *r = &bag.rows[j];
            if(!r->goName || !*r->goName || !r->rawCid || !*r->rawCid) {
                fprintf(stderr,
                        "asn1cgo: name dump invariant violated: row %d has a "
                        "blank %s%s%s (module=%s path=%s kind=%s)\n",
                        j,
                        (!r->goName || !*r->goName) ? "goName" : "",
                        ((!r->goName || !*r->goName) && (!r->rawCid || !*r->rawCid)) ? " and " : "",
                        (!r->rawCid || !*r->rawCid) ? "rawCid" : "",
                        r->module ? r->module : "?",
                        r->path ? r->path : "?",
                        g_kind_tag[r->kind]);
                bag.failed = 1;
            }
        }
        /* Census: every OPTIONAL member whose marker carries
         * bits beyond EM_OPTIONAL (the nested-mask star-loss shape the
         * containment test must still star). Report to stderr ALWAYS (the
         * answer to "how many across the specs" must not depend on a dump
         * env), one line per member + a count. Purely informational. */
        {
            int census = 0;
            for(int j = 0; j < bag.n_rows; j++) {
                struct name_row *r = &bag.rows[j];
                if(r->opt_extra_bits == 0) continue;
                fprintf(stderr,
                        "asn1cgo: census: OPTIONAL member %s (module %s) "
                        "carries extra marker bits 0x%x beyond EM_OPTIONAL\n",
                        r->path ? r->path : "?",
                        r->module ? r->module : "?",
                        r->opt_extra_bits);
                census++;
            }
            fprintf(stderr, "asn1cgo: census: %d OPTIONAL member(s) with "
                            "extra marker bits beyond EM_OPTIONAL\n", census);
        }
        if(dumppath && *dumppath) {
            FILE *f = fopen(dumppath, "w");
            if(f) {
                qsort(bag.rows, (size_t)bag.n_rows, sizeof(struct name_row),
                      row_cmp);
                for(int j = 0; j < bag.n_rows; j++) {
                    struct name_row *r = &bag.rows[j];
                    fprintf(f, "%s\t%s\t%s\t%s\t%s\n",
                            r->module ? r->module : "?",
                            r->path ? r->path : "?",
                            g_kind_tag[r->kind],
                            r->rawCid ? r->rawCid : "",
                            r->goName ? r->goName : "");
                }
                fclose(f);
            } else {
                fprintf(stderr, "asn1cgo: cannot open dump file '%s'\n", dumppath);
                bag.failed = 1;
            }
        }
        if(bag.failed) rc = -1;
        else if(go_outdir && *go_outdir) {
            /* The emit reads the rows in dump order (sorted above, whenever
             * a dump was requested; sort here too so a no-dump run emits the
             * identical order). Address stability after qsort: the bag owns
             * the array; qsort permutes in place, and no rows are added
             * between here and the emit, so go_emit_module_decls
             * (called under go_emit_files) can index it safely. */
            qsort(bag.rows, (size_t)bag.n_rows, sizeof(struct name_row),
                  row_cmp);
            g_emit_bag = &bag;   /* go_emit_module_decls reads this */
            set_go_module_paths(go_outdir);
            /* Go package import cycles are detected BEFORE any file is
             * written (the glue dry run needs the layout). */
            go_flat_layout_all();
            if(check_go_import_cycles(&bag) != 0) {
                bag.failed = 1;
                rc = -1;
            }
            /* All-or-nothing: every stage writes into a staging dir next to
             * the target; the target itself is replaced only when all stages
             * (and the go.work plan) succeeded. `stage` stands in for
             * go_outdir in every emitter; module paths were composed from the
             * REAL go_outdir above. */
            char *stage = NULL;
            if(rc == 0 && go_outdir_stage(go_outdir, &stage) != 0)
                rc = -1;
            if(rc == 0)
                rc = go_emit_files(asn, stage);
            g_emit_bag = NULL;
            /* Flat: compute every size/align/offset under
             * x86-64 SysV (no compiler), then write the per-package
             * <P><pkg>_flat.h + <P><pkg>_layout_check.c under
             * <stage>/c/ and the per-package layout.go beside types.go
             * (basename still live here; NULLed below). */
            if(rc == 0) {
                go_flat_layout_all();
                rc = go_flat_emit(stage, g_go_module_path);
            }
            /* Conv/entry (the conv/entry stages): emit the per-type conversion
             * functions + the PDU entry points into <stage>/internal/
             * cspec/ (the asn1c C copy rides ASN1C_DESTDIR; the asn1cgo-rt
             * skeleton rides ASN1CGO_FORK_SKEL; see go_conv.h). The rt
             * import line writes g_go_rt_module_path (prefix-aware). */
            if(rc == 0) {
                rc = go_conv_emit(stage, g_go_rt_module_path);
                if(rc < 0) bag.failed = 1;
            }
            /* Glue (App. G): emit the per-package glue.go
             * (Encode/Decode/xer per PDU root, the size/fill/read triples,
             * the arena/error bridge) + the layout.go init() probe. Reads
             * the name rows through the go_names_rows_* surface below (the
             * bag is still alive here; torn down below). */
            if(rc == 0) {
                g_emit_bag = &bag;   /* go_glue_emit reads this */
                rc = go_glue_emit(stage, g_go_module_path,
                                  g_go_rt_module_path);
                g_emit_bag = NULL;
                if(rc < 0) bag.failed = 1;
            }
            /* one constructor per E2AP IOC row into <pkg>/
             * constructors.go (reads the name rows through the same
             * surface + the go_ioc tables; no hook change). */
            if(rc == 0) {
                g_emit_bag = &bag;   /* go_ctor_emit reads this */
                rc = go_ctor_emit(stage);
                g_emit_bag = NULL;
                if(rc < 0) bag.failed = 1;
            }
            /* Publish: compute the new go.work text (no write), swap the
             * tree in, write go.work (atomic replace); a go.work failure
             * rolls the swap back. Nothing outside the staging dir changes
             * before this point. */
            if(rc == 0) {
                char *gw_text = NULL, *old = NULL;
                int lock_fd = -1;
                /* Held from before the plan (go.work read) until after the
                 * write/rollback, and across the publish, so a sibling
                 * generator neither loses our `use` entry nor prunes our
                 * dir while it is renamed aside. Advisory flock: see
                 * go_workfile_lock. */
                if(go_workfile_lock(go_outdir, &lock_fd) != 0) {
                    rc = -1;
                } else if(go_workfile_plan(go_outdir, &gw_text) != 0) {
                    rc = -1;
                } else if(go_outdir_publish(go_outdir, stage, &old) != 0) {
                    rc = -1;
                } else if(gw_text
                          && go_workfile_write(go_outdir, gw_text) != 0) {
                    go_outdir_rollback(go_outdir, stage, old);
                    rc = -1;
                } else {
                    go_outdir_commit(old);   /* leftover = warning only */
                    free(stage);
                    stage = NULL;            /* published: nothing to discard */
                }
                free(gw_text);
                go_workfile_unlock(lock_fd);
            }
            if(rc != 0) {
                bag.failed = 1;
                if(stage) go_outdir_discard(stage);
                fprintf(stderr, "asn1cgo: Go generation failed; %s left "
                        "unchanged\n", go_outdir);
            }
            free(stage);
            clear_go_module_paths();
        }

        /* teardown of retained rows */
        for(int j = 0; j < bag.n_rows; j++) {
            free(bag.rows[j].path);
            free(bag.rows[j].rawCid);
            free(bag.rows[j].goName);
            free(bag.rows[j].intval);
            free(bag.rows[j].goType);
            free(bag.rows[j].field_type);
            free(bag.rows[j].sf_owner);
            free(bag.rows[j].slice_elem);   /* owned copy (row_set_slice_elem) */
            free(bag.rows[j].dflt_lit);
            free(bag.rows[j].dflt_owner);
            free(bag.rows[j].dflt_field);
            free(bag.rows[j].bit_type);
        }
        free(bag.rows);
        for(int j = 0; j < bag.n_ps; j++) {
            for(int k = 0; k < bag.ps_n[j]; k++) {
                free(bag.ps_owners[j][k].goName);
                free(bag.ps_owners[j][k].path);
            }
            free(bag.ps_owners[j]);
        }
        free(bag.ps_module); free(bag.ps_owners);
        free(bag.ps_n); free(bag.ps_cap);
        for(int j = 0; j < bag.n_fields; j++) {
            free(bag.fields[j].goName); free(bag.fields[j].path);
        }
        free(bag.fields);
        for(int j = 0; j < bag.n_dirs; j++) free(bag.dirs[j].dir);
        free(bag.dirs);
        free(bag.bs_modules);
        for(int j = 0; j < bag.n_minted; j++) {
            free(bag.minted[j].cid); free(bag.minted[j].go_elem);
        }
        free(bag.minted);
        free(bag.sf_cur_owner);
        return rc;
    }
}

/* ========================================================================= *
 * Walkers — mirror go_walk.c's walk_expr / walk_child / walk_members, but
 * resolve Go names instead of classifying for the support gate. The structural
 * decisions are the SAME (parameterized-specialization iteration; skip
 * OBJECTCLASS / OBJECT / VALUESET; inline-only recursion via the child's own
 * .members; reference resolution via asn1f_find_terminal_type_ex), so the two
 * walks visit the same (module, path) node set. Naming rule invoked per node
 * is cited inline by asn1c path:line. The member path passed down is the
 * ASN.1 dotted path; the parent goName (ctx->parent_go) is the inline prefix.
 * ========================================================================= */

/* emit_choice / emit_enum are mutually recursive (a CHOICE alt may be an inline
 * CHOICE/ENUM). Both are defined just below; declared here so either may call the
 * other. Both take choice_go/enum_go (the Go name — the dump goName and the parent
 * prefix for nested inline names) AND choice_cid/enum_cid: the REAL asn1c C
 * identifier prefix of this construct, compounded exactly as asn1c does
 * (GO_MKID(expr) at top level; parent-real-cid + "__" + member-real-cid for an
 * inline). rawCid for every discriminant/const row is built FROM the real cid, so
 * it is the verbatim symbol asn1c stamps into the .h (e.g. ENB_ID_PR for the
 * ENB-ID choice, not the _-collapsed ENBID_PR the Go name would yield; an inline
 * choice's tag is <ParentCid>__<memberCid>_PR). goName and path are unaffected. */
static void emit_choice(struct walk_ctx *ctx, const char *choice_go,
                        const char *choice_cid, const char *parent_path,
                        asn1p_expr_t *choice_expr);
static void emit_enum(struct walk_ctx *ctx, const char *enum_go,
                      const char *enum_cid, const char *parent_path,
                      asn1p_expr_t *enum_expr);
static void emit_bit_names(struct walk_ctx *ctx, const char *type_go,
                           const char *type_cid, const char *type_path,
                           asn1p_expr_t *bs);
static int seqof_elem_is_inline(asn1p_expr_t *elem);
static int mint_inline_seqof_elem(struct walk_ctx *ctx, asn1p_expr_t *elem,
                                  const char *owner_path, const char *owner_go,
                                  const char *owner_cid, char **go_elem,
                                  char **flat_cid);
static char *slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                                const char *path_for_diag);

/* Emit choice discriminant rows for a CHOICE whose goName is `choice_go` and real
 * C-ident prefix is `choice_cid`, at path prefix `parent_path`. choice_expr is the
 * CHOICE construct whose .members are the alts. Emits one choice-pr, a PrNothing
 * choice-const, one choice-const per alt, AND one field per alt (pointer per alt — the alt
 * data-pointer set, struct-scoped to this CHOICE). rawCids are built from
 * choice_cid (the verbatim asn1c symbol). */
static void
emit_choice(struct walk_ctx *ctx, const char *choice_go,
            const char *choice_cid, const char *parent_path,
            asn1p_expr_t *choice_expr) {
    /* CHOICE emission: the CHOICE's own type/inline row (emitted by the caller just
     * before this call on ALL three call paths — walk_names_expr's top-level
     * GK_TYPE row, walk_names_child's inline GK_INLINE row, and emit_choice's
     * own recursion below) is declared `type <Choice> struct {...}` over the
     * Present + alt field rows this function records. Capture the owner row
     * INDEX here — at entry it is n_rows-1, but the choice-pr emit below
     * appends rows, so an n_rows-1 mark after it would stamp the PR row (the
     * live bug: `type BinRangeValuePr struct {}` + a MISSING BinRangeValue). */
    int owner_ix = ctx->bag->n_rows - 1;
    /* Flat: the CHOICE struct rides the owner row above (walk order:
     * members land on the most-recent go_flat_struct). is_choice rides
     * the mint via the go_flat_choice flag hook. */
    go_flat_choice(choice_cid, ctx->module);
    go_flat_label_cur(choice_expr->Identifier);   /* td->name label */
    /* choice-pr: <Choice>Pr (discriminant-type name). rawCid = <Cid>_PR, the
     * verbatim asn1c `<Choice>_PR` enum tag (not the _-collapsed Go name + _PR). */
    {
        char *raw = str_append(strdup(""), choice_cid);
        raw = str_append(raw, "_PR");
        char *go = str_append(strdup(""), choice_go);
        go = str_append(go, "Pr");
        char *path = make_path(parent_path, "Pr");
        emit_name(ctx->bag, ctx->module, path, GK_CHOICE_PR, raw, go);
    }
    reset_field_scope(ctx->bag);    /* CHOICE is one struct for field scope */
    row_set_is_struct_at(ctx->bag, owner_ix);
    struct_scope_open(ctx->bag, choice_go);
    /* choice-const: <Choice>PrNothing. rawCid = <Cid>_PR_NOTHING. Value 0:
     * asn1c's _PR enum lists NOTHING first with no explicit value
     * (asn1c_C.c:984), so the implicit numbering makes NOTHING=0 (the comparison unit
     * `<T>PrNothing <T>Pr = 0` row, the const-naming rule). The const's TYPE is the
     * discriminant <Choice>Pr (frozen: `E2APPDUPrNothing E2APPDUPr = 0`),
     * not the CHOICE struct itself (the struct body). */
    {
        char *raw = str_append(strdup(""), choice_cid);
        raw = str_append(raw, "_PR_NOTHING");
        char *go = str_append(strdup(""), choice_go);
        go = str_append(go, "PrNothing");
        char *type_go = str_append(strdup(""), choice_go);
        type_go = str_append(type_go, "Pr");
        char *path = make_path(parent_path, "PrNothing");
        emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
        row_set_const(ctx->bag, "0", type_go);
        free(type_go);
    }
    /* The CHOICE Go struct carries a `Present <Choice>Pr` discriminant field
     * (the holder that selects an alt); emit it as a struct-scoped field
     * alongside the alt fields. rawCid = the asn1c `present` member token
     * VERBATIM — a generic CHOICE's discriminant holder is the C member
     * `present` (constr_CHOICE.h: `Present <X>_PR present;`), not a compound
     * <Cid>_present. Storing the literal `present` makes the dump's rawCid a
     * real .h identifier token AND makes goName = R2("present") = "Present" —
     * no special case on either side (token + R2 checks both pass
     * unaided). */
    {
        char *path = make_path(parent_path, "Present");
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  strdup("present"), strdup("Present"));
        /* CHOICE emission: `Present <Choice>Pr` (the discriminant holder;
         * by VALUE, never a pointer: it is the selector, not an alt slot). */
        char *pt = str_append(strdup(""), choice_go);
        pt = str_append(pt, "Pr");
        row_set_field_type(ctx->bag, pt);
        free(pt);
    }
    /* Flat: the present member is the int32 prim row (the CHOICE mapping
     * row: present-first as a prim column). */
    go_flat_member_prim("int32_t", "present", 0);
    asn1p_expr_t *alt;
    int alt_seq = 0;   /* _PR value: sequential over emitted alts (asn1c_C.c
                        * :985-996 lists NOTHING + alts with NO explicit
                        * values, so implicit numbering 0,1,2... follows the
                        * TQ_FOR order; the PrNothing row above consumed 0). */
    TQ_FOR(alt, &(choice_expr->members), next) {
        if(alt->expr_type == A1TC_EXTENSIBLE) continue;       /* "..." */

        /* A BIT.STRING alt marks this module for the BitString helper (the same
         * membership the plain-member chase applies; a CHOICE alt may be a plain
         * inline BIT STRING or a reference to one). */
        {
            asn1p_expr_t *at = alt;
            if(alt->expr_type == A1TC_REFERENCE || alt->meta_type == AMT_TYPEREF) {
                asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt);
                if(t) at = t;
            }
            if(go_construct_classify(at) == GO_CONSTR_BIT_STRING)
                mark_bitstring_module(ctx->bag, ctx->module);
        }
        /* An alt that is itself an inline constructed type (plain inline SEQ/
         * CHOICE/ENUM) mints the inline naming + alts, exactly as a struct
         * member does — recurse over it via walk_names_child. Prefix: the alt
         * PART of every _PR_ token is an unprefixed member token
         * (c_presence_name's suffix, asn1c_naming.c:304 — make_identifier
         * flags 0), and the alt's own field row carries the unprefixed
         * member-decl token (MKID_safe, asn1c_C.c:1353). One unprefixed
         * string serves both. */
        const char *altcid = go_mk_suffix(alt);
        char *altgo = go_r2(altcid);
        /* choice-const <Choice>Pr<Alt>; rawCid = <Cid>_PR_<AltCid> (the verbatim
         * asn1c enum-member token <Choice>_PR_<AltCid>). <Cid> is the
         * aggregate prefixed form; the alt part is unprefixed. */
        {
            char *raw = str_append(strdup(""), choice_cid);
            raw = str_append(raw, "_PR_");
            raw = str_append(raw, altcid);
            char *go = str_append(strdup(""), choice_go);
            go = str_append(go, "Pr");
            go = str_append(go, altgo);
            char *type_go = str_append(strdup(""), choice_go);
            type_go = str_append(type_go, "Pr");
            char *path = make_path(parent_path, alt->Identifier);
            emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
            /* Value: the next sequential _PR slot (PrNothing=0, alt i = i+1;
             * asn1c's _PR enum carries no explicit values — asn1c_C.c:985-996
             * — so the implicit numbering follows the TQ_FOR alt order).
             * asn1p_itoa's ring buffer makes one call per row safe. */
            row_set_const(ctx->bag, asn1p_itoa(++alt_seq), type_go);
            free(type_go);
        }
        /* field row: the alt's data pointer. struct-scoped to CHOICE.
         * CHOICE emission: the alt field's TYPE — always a POINTER ("every alt a
         * pointer, leaves included"; the frozen units carry *BitString for a
         * BIT-STRING alt, *uint64 for an INTEGER alt, and NO field at all for
         * a NULL alt — a NULL alt emits no Go field, only its Pr const
         * (the C union member is NULL_t, a zero-size payload; the frozen unit
         * MeasurementRecordItem emits no NoValue/NotSatisfied field while
         * still emitting their Pr consts; the glue never raises
         * E_CHOICE_BAD for a selected NULL alt). So NO field row at all is
         * emitted for a NULL alt, keyed on the chased terminal's class ==
         * GO_CONSTR_NULL — and the dump carries no such row either (the
         * index side drops it in lockstep). The pointee follows the
         * member rules: the minted <Choice><Alt> name for an inline alt (the
         * block below mints it in this same iteration), the named
         * assignment's own Go name for a reference alt, the mapping-table Go
         * column for a plain inline leaf alt (classify_leaf — the SAME table
         * the decl emission uses; never re-spelled here). The star is NOT the
         * OPTIONAL star (member_stars): a CHOICE alt is a pointer by construction
         * whatever its marker — "*" + pointee unconditionally. */
        /* The alt's terminal (the BIT STRING chase above already resolved
         * it, but into a nested scope; re-chase here for the type — and
         * BEFORE the field emit: a NULL terminal suppresses the row ENTIRELY
         * as a NULL alt, not just its type). */
        {
            asn1p_expr_t *aterm = alt;
            if(alt->expr_type == A1TC_REFERENCE || alt->meta_type == AMT_TYPEREF) {
                asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt);
                if(t) aterm = t;
            }
            if(go_construct_classify(aterm) == GO_CONSTR_NULL) {
                /* a NULL alt emits NO Go field, only its Pr const —
                 * the comparison unit MeasurementRecordItem shape (noValue/
                 * notSatisfied carry consts but no field; the C union member
                 * is NULL_t, a zero-size payload). The dump emits NO field
                 * row for it either (the index side drops it in lockstep) —
                 * NOT an empty-typed row: the dump invariant rejects
                 * blank rows, and Check A expects no such field. Conv: the
                 * generated switch still carries its bare `case ..._PR_<alt>:
                 * break;` (a selected NULL alt must not fall to BAD). */
                go_conv_record_null_alt(choice_cid, altcid);
                free(altgo);
                free((char *)altcid);
                continue;
            }
            char *path = make_path(parent_path, alt->Identifier);
            /* An alt whose field name would be `Present` collides with the
             * discriminant field (public API, kept as is): the FIELD gets the
             * deterministic name PresentAlt. The <Choice>Pr<Alt> constant
             * (TPrPresent) and the inline type name keep altgo. The renamed
             * field is registered like any other, so an alt literally named
             * `presentAlt` is still reported as a collision. */
            emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      own(strcmp(altcid, "present") == 0 ? "presentAlt" : altcid),
                      strdup(strcmp(altgo, "Present") == 0 ? "PresentAlt" : altgo));
            /* Flat slot: a POINTER iff asn1c's union member for
             * this alt is one — the EM_INDIRECT marker expr_break_recursion
             * stamped (masked test; leaf CHOICEs are
             * all-inline, structured CHOICEs pointer-per-alt under
             * -findirect-choice). The pointee cid: the minted inline
             * compound for an inline-alt (rendered by the same rules below),
             * the terminal's own cid for a reference alt, or a prim for a
             * plain inline leaf alt (none in scope: all data-bearing leaf
             * alts here are BIT STRING / INTEGER / REAL prims — the same
             * classify_leaf table). */
            {
                int cstars = 0;
                int cwide = 0;
                char *ccid = NULL;
                const char *cprim = NULL;
                const char *star_tok = go_mk_suffix(alt);
                (void)star_tok;
                if((alt->marker.flags & EM_INDIRECT)) cstars = 1;
                if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                    /* an inline ENUMERATED alt collapses to the bare int32
                     * slot (the ENUMERATED mapping row, the same form the frozen units author
                     * for inline-enum members; the .h e_<X>__<alt> enum tag
                     * is not a scalar alias) — NO named alt leaf is minted
                     * on the Flat side (flatemit-check flat-name red on the
                     * minted-leaf form). */
                    cprim = "int32_t";
                } else if(alt->expr_type == ASN_CONSTR_SEQUENCE
                          || alt->expr_type == ASN_CONSTR_CHOICE
                          || alt->expr_type == ASN_CONSTR_SEQUENCE_OF) {
                    /* inline constructed alt: pointee = the __-compound cid
                     * the mint below creates; prim-form slot when inline */
                    const char *ac = go_mk_suffix(alt);
                    ccid = go_cid_compound(choice_cid, "__", ac);
                    free((char *)ac);
                    /* an inline CHOICE/SEQ alt under -findirect-choice
                     * carries EM_INDIRECT (constructed terminal) — cstars
                     * already 1; without the flag (leaf alts) EM_INDIRECT
                     * never set: inline slot. */
                } else if(alt->expr_type == A1TC_REFERENCE
                          || alt->meta_type == AMT_TYPEREF || aterm != alt) {
                    ccid = own(GO_MKID(aterm));
                } else {
                    /* a plain inline leaf alt: the mapping-table Flat prim slot. */
                    ctx->wide_nr = 1; ctx->wide_hit = 0;
                    int lk = classify_leaf(ctx, aterm, parent_path);
                    cwide = ctx->wide_hit;
                    ctx->wide_nr = 0; ctx->wide_hit = 0;
                    static const struct { int k; const char *p; } lk2p[] = {
                        {1, "int64_t"}, {2, "uint64_t"}, {3, "_bool32"},
                        {5, "double"}, {6, "asn1cgo_bytes_flat"},
                        {7, "asn1cgo_bytes_flat"}, {8, "asn1cgo_bytes_flat"},
                        {9, "asn1cgo_bits_flat"}, {10, "int32_t"},
                    };
                    for(size_t qi = 0;
                        qi < sizeof lk2p / sizeof lk2p[0]; qi++)
                        if(lk == lk2p[qi].k) { cprim = lk2p[qi].p; break; }
                }
                {
                    /* altcid borrows the shared static buffer (go_mk_suffix);
                     * own it before the mint (the same aliasing trap). */
                    char *flat_acid = own(altcid);
                    int alt_is_present = strcmp(altcid, "present") == 0;
                    char *flat_atok = own(alt_is_present ? "presentAlt" : altcid);
                    if(cprim) {
                        go_flat_member_prim(cprim, flat_atok, cstars);
                        if(cwide) go_flat_last_member_wide();
                    } else if(ccid)
                        go_flat_member_ref(ccid, flat_atok, cstars);
                    /* CHOICE alt member label = the alt's own ASN.1
                     * Identifier (the td-member name). */
                    go_flat_label_last_member(alt->Identifier);
                    if(alt_is_present && (cprim || ccid))
                        go_flat_last_member_tree_token("present");
                    free(flat_acid); free(flat_atok);
                }
                free(ccid);
            }
            {
                char *ft = NULL;
                if(alt->expr_type == ASN_BASIC_ENUMERATED
                   || alt->expr_type == ASN_CONSTR_SEQUENCE
                   || alt->expr_type == ASN_CONSTR_CHOICE
                   || alt->expr_type == ASN_CONSTR_SEQUENCE_OF) {
                    /* An inline constructed alt: typed by its minted
                     * <Choice><Alt> name (the anonymous-inline naming
                     * rule), same-module. */
                    ft = str_append(strdup(""), choice_go);
                    ft = str_append(ft, altgo);
                } else if(alt->expr_type == A1TC_REFERENCE
                          || alt->meta_type == AMT_TYPEREF || aterm != alt) {
                    /* A reference alt: the terminal assignment's own Go name
                     * (leaf or constructed alike). Stored UNQUALIFIED;
                     * the post-walk prepass (qualify_field_types) applies cross-module qualification
                     * cross-module qualification once the bag is complete. */
                    char *tgo = go_r2(GO_MKID(aterm));
                    ft = str_append(strdup(""), tgo);
                    free(tgo);
                } else {
                    /* A plain inline leaf alt: the shared mapping table. */
                    ctx->wide_nr = 1;
                    int lk = classify_leaf(ctx, aterm, parent_path);
                    ctx->wide_nr = 0; ctx->wide_hit = 0;
                    const char *under = go_types_leaf_underlying(lk);
                    if(under) ft = own(under);
                }
                if(ft) {
                    char *sft = str_append(strdup(""), "*");
                    sft = str_append(sft, ft);
                    row_set_field_type(ctx->bag, sft);
                    free(sft); free(ft);
                }
            }
        }
        /* An alt that is an inline ENUMERATED mints the named type
         * <Choice><Alt> + enum-consts under it (e.g. TestCond-Type.aMBR ->
         * TestCondTypeAMBR; the real .h compounds the parent into the enum and
         * every enumerator). An inline CHOICE alt mints <Choice><Alt> too and
         * recurses via emit_choice (the CHOICE pass: that recursion now marks its own
         * inline row a struct owner + types its alt slots). An inline SEQUENCE
         * alt mints <Choice><Alt> and walks its members (walk_names_members —
         * the struct-body machinery; the alt slot's type above points
         * at the minted name). The real C-ident compounds by `__`:
         * <choice_cid>__<altcid>, matching asn1c's nested tag form. An inline
         * SEQUENCE-OF alt mints the slice alias <Choice><Alt> below, with its
         * element named by mint_inline_seqof_elem when that is inline too. */
        if(alt->expr_type == ASN_BASIC_ENUMERATED
           || alt->expr_type == ASN_CONSTR_SEQUENCE
           || alt->expr_type == ASN_CONSTR_CHOICE) {
            char *inline_go = str_append(strdup(""), choice_go);
            inline_go = str_append(inline_go, altgo);
            /* an inline tag is an AGGREGATE name — prefix once, parts
             * unprefixed (asn1c's compound tag KPM_X__y, never KPM_X__KPM_y;
             * construct_base_name flag=0, asn1c_naming.c:185-186). */
            char *inline_cid = go_cid_compound(choice_cid, "__", altcid);
            char *alt_path = make_path(parent_path, alt->Identifier);
            {
                char *raw = strdup(inline_cid);
                char *go = strdup(inline_go);
                char *path = strdup(alt_path);
                emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
                if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                    row_set_leaf(ctx->bag, GLEAF_ENUM);
                    /* Flat: NO leaf typedef mint for an inline-ENUM
                     * alt — the alt slot is the bare int32 prim above; a
                     * minted <P>__<alt>_flat leaf is unresolvable by the
                     * index (flat-name red) and unreferenced. */
                }
            }
            if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                emit_enum(ctx, inline_go, inline_cid, alt_path, alt);
            } else {
                /* An inline CHOICE / SEQUENCE alt is a package-scoped Flat
                 * node of its own (the alt slot above is a ref to it; the C
                 * tree has only the struct tag `struct <choice>__<alt>`, so
                 * the conv file aliases `<cid>_t` to it: inline_elem
                 * "struct"). Both the Flat cur register and the Go
                 * struct-field scope belong to the ENCLOSING CHOICE again
                 * once the alt is done — an alt AFTER it must land on this
                 * CHOICE, not inside the inline one. */
                char *save_sf = NULL;
                if(ctx->bag->sf_cur_owner)
                    save_sf = strdup(ctx->bag->sf_cur_owner);
                int save_fcur = go_flat_cur_get();
                if(alt->expr_type == ASN_CONSTR_CHOICE) {
                    emit_choice(ctx, inline_go, inline_cid, alt_path, alt);
                    /* emit_choice minted the node and left it cur */
                    go_flat_mark_inline_elem("struct", NULL);
                } else {   /* ASN_CONSTR_SEQUENCE: a struct with member fields */
                    const char *save_go = ctx->parent_go;
                    const char *save_cid = ctx->parent_cid;
                    go_flat_struct(inline_cid, ctx->module);
                    go_flat_label_cur(alt->Identifier);   /* td->name label */
                    go_flat_mark_inline_elem("struct", NULL);
                    ctx->parent_go = inline_go;
                    ctx->parent_cid = inline_cid;
                    reset_field_scope(ctx->bag);
                    row_set_is_struct(ctx->bag);
                    struct_scope_open(ctx->bag, inline_go);
                    (void)walk_names_members(ctx, alt, alt_path);
                    struct_scope_reset(ctx->bag);
                    ctx->parent_go = save_go;
                    ctx->parent_cid = save_cid;
                }
                go_flat_cur_restore(save_fcur);
                free(bag_sf_restore(ctx->bag, save_sf));
            }
            free(inline_go); free(inline_cid); free(alt_path);
        } else if(alt->expr_type == ASN_BASIC_BIT_STRING
                  && TQ_FIRST(&alt->members)
                  && alt->meta_type != AMT_TYPEREF
                  && asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt)
                         == alt) {
            /* An inline named-bit BIT STRING alt: the alt is a plain
             * BitString; only the bit positions are named, as an inline
             * ENUMERATED alt would be (<Choice><Alt>). */
            char *bit_go = str_append(strdup(""), choice_go);
            bit_go = str_append(bit_go, altgo);
            char *bit_cid = go_cid_compound(choice_cid, "__", altcid);
            char *bit_path = make_path(parent_path, alt->Identifier);
            emit_bit_names(ctx, bit_go, bit_cid, bit_path, alt);
            free(bit_go); free(bit_cid); free(bit_path);
        } else if(alt->expr_type == ASN_CONSTR_SEQUENCE_OF) {
            /* An inline SEQUENCE OF alt: the named slice `type <Choice><Alt>
             * []Elem`, a package-scoped Flat {items,count} node of the C
             * cid <choice>__<alt> (the alt slot is a pointer to it). The C
             * struct has only a tag (`struct T__a {..} *a`), no typedef. */
            char *sq_go = str_append(strdup(""), choice_go);
            sq_go = str_append(sq_go, altgo);
            char *sq_cid = go_cid_compound(choice_cid, "__", altcid);
            char *sq_path = make_path(parent_path, alt->Identifier);
            emit_name(ctx->bag, ctx->module, strdup(sq_path), GK_INLINE,
                      strdup(sq_cid), strdup(sq_go));
            int sq_row = ctx->bag->n_rows - 1;
            asn1p_expr_t *sq_elem = TQ_FIRST(&alt->members);
            int save_fcur = go_flat_cur_get();
            char *ge = NULL, *fc = NULL;
            int mrc = 0;
            if(sq_elem && sq_elem->expr_type == ASN_BASIC_BIT_STRING)
                mark_bitstring_module(ctx->bag, ctx->module);
            if(seqof_elem_is_inline(sq_elem)) {
                mrc = mint_inline_seqof_elem(ctx, sq_elem, sq_path, sq_go,
                                             sq_cid, &ge, &fc);
            } else {
                ge = slice_element_type(ctx, sq_elem, sq_path);
                if(ctx->bag->failed) mrc = -1;
                else {
                    asn1p_expr_t *et = sq_elem;
                    asn1p_expr_t *t2 = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, sq_elem);
                    if(t2) et = t2;
                    fc = own(GO_MKID(et));
                }
            }
            if(mrc >= 0 && !ctx->bag->failed) {
                row_set_slice_elem_at(ctx->bag, sq_row, ge);
                (void)go_flat_seqof(sq_cid, fc, 0, ctx->module);
                go_flat_mark_inline_elem("struct", NULL);
                go_flat_cur_restore(save_fcur);
            }
            free(ge); free(fc);
            free(sq_go); free(sq_cid); free(sq_path);
        }
        free(altgo);
        free((char *)altcid);
    }
    struct_scope_reset(ctx->bag);
}

/* Emit enum-const rows for an ENUMERATED whose goName is `enum_go` and real
 * C-ident prefix is `enum_cid`, at path prefix `parent_path`. enumerators off
 * `enum_expr`. rawCid = <EnumCid>_<enumerator> (the verbatim asn1c enumerator
 * token: asn1c compounds the enum's C-ident prefix into every enumerator, so the
 * real token is `<enum_cid>` + "_" + GO_MKID(enumeratorChild)). goName is R2 of
 * that (=<Enum> + R2 of the enumerator suffix); path is unchanged.
 *
 * leaf-stage body data: each enum-const's VALUE is the enumerator's own ASN.1
 * value — e->value->value.v_integer, the exact field asn1c_C.c:152 prints as
 * " = N" (asn1fix_enum.c:97-99 assigns the sequential numbering for implicit
 * enumerators at fix time, so the AST value and the .h value are the same
 * number; asn1p_itoa renders it, asn1p_integer.h:39). goType is the enum's
 * own Go name (consts `<GoType>` + R2(name), typed by the enum type). */
static void
emit_enum(struct walk_ctx *ctx, const char *enum_go,
          const char *enum_cid, const char *parent_path,
          asn1p_expr_t *enum_expr) {
    asn1p_expr_t *e;
    TQ_FOR(e, &(enum_expr->members), next) {
        if(e->expr_type == A1TC_EXTENSIBLE) continue;
        if(!e->Identifier) continue;
        /* real .h: `typedef enum <Cid> { <Cid>_reject, ... }`; the enumerator
         * child's identifier is the enumerator SUFFIX (asn1c compounds the type
         * prefix at emit, not into the child), so the real token is
         * <enum_cid> + "_" + suffix. For a top-level enum the two prefixes
         * coincide (enum_go == enum_cid); for an inline-or-hyphenated enum they
         * differ, and only the real cid reproduces the .h token verbatim.
         * the per-spec prefix rule: the suffix itself carries NO prefix AND NO reserved-word
         * upcasing (c_member_name's suffix is make_identifier(0, expr, 0),
         * asn1c_naming.c:304 — the real token is `..._true`, lowercase). */
        const char *ecid = go_mk_suffix(e);
        char *raw = str_append(strdup(""), enum_cid);
        raw = str_append(raw, "_");
        raw = str_append(raw, ecid);
        char *ego = go_r2(ecid);
        char *go = str_append(strdup(""), enum_go);
        go = str_append(go, ego);
        free(ego);
        char *path = make_path(parent_path, e->Identifier);
        emit_name(ctx->bag, ctx->module, path, GK_ENUM_CONST, raw, go);
        char *etype = str_append(strdup(""), enum_go);
        if(e->expr_type == A1TC_UNIVERVAL && e->value)
            row_set_const(ctx->bag, asn1p_itoa(e->value->value.v_integer),
                          etype);
        free(etype);
        free((char *)ecid);
    }
}

/* emit_bit_names: the bit-position constants of a named-bit BIT STRING
 * (`BIT STRING { a(0), b(1) }`). The value type is a plain BitString; the
 * names only add one `int` constant per named bit, in declaration order:
 * <type_go> + R2(bit) -- the ENUMERATED enumerator scheme (emit_enum), with
 * `type_go` the name an ENUMERATED in the same position would get (the type's
 * own Go name at top level, <Parent><Member> for an inline member,
 * <Choice><Alt> for a CHOICE alt). They are package-scoped GK_ENUM_CONST
 * rows, so a clash with a type or another constant fails like every other
 * collision. The values are the C backend's own (v->value->value.v_integer,
 * asn1c_C.c asn1c_lang_C_type_BIT_STRING); the fixer resolved referenced
 * values and rejects non-integer / negative ones, anything else is refused
 * here. */
static void
emit_bit_names(struct walk_ctx *ctx, const char *type_go,
               const char *type_cid, const char *type_path,
               asn1p_expr_t *bs) {
    asn1p_expr_t *v;
    int group = 0;
    TQ_FOR(v, &(bs->members), next) {
        if(v->expr_type == A1TC_EXTENSIBLE || !v->Identifier) continue;
        if(v->expr_type != A1TC_UNIVERVAL || !v->value
           || v->value->type != ATV_INTEGER || v->value->value.v_integer < 0) {
            fprintf(stderr,
                    "asn1cgo: BIT STRING named bit %s is not a resolved "
                    "non-negative integer in module %s: %s\n",
                    v->Identifier, ctx->module ? ctx->module : "?", type_path);
            ctx->bag->failed = 1;
            return;
        }
        const char *bcid = go_mk_suffix(v);
        char *raw = str_append(strdup(""), type_cid);
        raw = str_append(raw, "_");
        raw = str_append(raw, bcid);
        char *bgo = go_r2(bcid);
        char *go = str_append(strdup(""), type_go);
        go = str_append(go, bgo);
        free(bgo);
        emit_name(ctx->bag, ctx->module, make_path(type_path, v->Identifier),
                  GK_ENUM_CONST, raw, go);
        row_set_const(ctx->bag, asn1p_itoa(v->value->value.v_integer), "int");
        struct name_row *r = &ctx->bag->rows[ctx->bag->n_rows - 1];
        if(!group) group = r->ord + 1;
        r->bit_group = group;
        r->bit_type = own(type_path);
        free((char *)bcid);
    }
}

/* is_field_shaped_spec: a top-level SEQUENCE assignment is a field-shaped
 * parameterized specialization (ProtocolIE-Field / SingleContainer {{X}}, the
 * asn1c `struct <X>__value { ... }` wrapper) iff one of its members is an
 * open-type class-field `&Value` reference (go_construct_is_open_type mirrors
 * is_open_type at asn1c_C.c:305). Returns that open-type member, or NULL. */
static asn1p_expr_t *
is_field_shaped_spec(asn1p_expr_t *seq_terminal) {
    if(!seq_terminal) return NULL;
    asn1p_expr_t *child;
    TQ_FOR(child, &(seq_terminal->members), next) {
        if(go_construct_is_open_type(child))
            return child;
    }
    return NULL;
}

/* Forward decls (struct-body field-type resolution, defined before
 * walk_names_child): classfield_declared_type resolves a lowercase &field
 * envelope member to its declared type; qualify_type applies cross-module qualification
 * cross-module qualification to a named-type reference. Both are used by
 * emit_spec (above their definitions). */
static asn1p_expr_t *
classfield_declared_type(struct walk_ctx *ctx, asn1p_expr_t *mem);
static char *
qualify_type(struct name_bag *b, const char *module, const char *go_name);
static void
qualify_field_types(struct name_bag *b);

/* The governing Go type NAME of an IOC class column's declared type (R2 of
 * the column's own type field, e.g. &id -> ProtocolIE-ID -> ProtocolIEID):
 * the name the ctor layer resolves consts BY (value-consts typed it, enum
 * consts owned by it) instead of any name-shape assumption. Malloc'd;
 * NULL when the declared type does not resolve. */
static char *column_governing_go(struct walk_ctx *ctx, asn1p_expr_t *field);
static int cell_id_is_literal(asn1p_expr_t *cv);

/* Forward decls: emit_spec_value_alts + emit_value_pr_nothing are defined
 * after emit_spec; both are called from it. */
static void emit_spec_value_alts(struct walk_ctx *ctx, const char *x_go,
                                 const char *x_cid, const char *parent_path,
                                 asn1p_expr_t *seq_terminal);
static void emit_value_pr_nothing(struct walk_ctx *ctx, const char *x_go,
                                  const char *x_cid, const char *parent_path);
static int field_shaped_element(struct walk_ctx *ctx, asn1p_expr_t *elem);


/* emit_spec: the specialization names. X is the type's goName; the
 * specialization mints a named value union (R2(X)+Value) with a discriminant
 * (R2(X)+ValuePr), exactly as asn1c emits `struct <X>__value { union {...} }` +
 * `enum <X>__value_PR {...}`. spec-key = the type name itself (R2(X)). The
 * value-union alt fields + their choice-constants come from the object set the
 * &Value resolves to; those are emitted by emit_spec_value_alts when the
 * open-type member is available.
 *
 * A field-shaped specialization is a STRUCT (named R2(X)), so in addition
 * to the spec-key/value/pr + value-union-alts, it carries STRUCT FIELD rows for
 * its envelope members — exactly as a plain SEQUENCE does. The real C
 * struct `typedef struct <X> { <id|procedureCode>; <criticality>; struct <X>
 * __value { ... } value; asn_struct_ctx_t _asn_ctx; }` carries the envelope
 * members and the `value` wrapper; the Go struct (per the frozen units) is
 * `{ Id|ProcedureCode; Criticality; Value <X>Value }` — the envelope members as
 * fields, the `value` wrapper as ONE `Value` field typed by the union. The
 * discriminant `present` lives on the <X>Value UNION (not on the IEs struct), so
 * it is NOT a field here (it is emitted as a choice-const + union alt field in
 * emit_spec_value_alts). The frozen rule: "a field-shaped specialization
 * is a type, so emit it as a struct with field rows for its members".
 *
 * Fail loud if the specialization has NO open-type &Value member (the one shape
 * invariant rests on): a field-shaped spec without it is an unforeseen
 * structure (file a Q; do not silently mis-emit). */
static void
emit_spec(struct walk_ctx *ctx, const char *x_go, const char *x_cid,
          const char *parent_path, asn1p_expr_t *seq_terminal) {
    /* a field-shaped specialization's names belong in X's module — the
     * module that DEFINES the bound object set — NOT ctx->module (the template's
     * module: asn1c attaches every clone's module back-pointer to the parameter-
     * ized type's home, e.g. E2AP-Containers for all ProtocolIE-Field clones).
     * Resolve X's module from the IOC objset (the same resolution emit_spec_
     * value_alts makes) and rebind ctx->module to it for the whole spec emit, so
     * every emit_name in this function AND emit_spec_value_alts attributes to X.
     * Falls back to ctx->module if the objset is unresolvable (a degenerate spec
     * with no object rows — emit_spec_value_alts then emits PrNothing only). */
    asn1c_ioc_table_and_objset_t ioc;
    {
        arg_t a;
        memset(&a, 0, sizeof a);
        a.asn = ctx->asn;
        a.ns = ctx->ns;
        a.expr = seq_terminal;
        ioc = asn1c_get_ioc_table(&a);
    }
    const char *save_module = ctx->module;
    if(ioc.objset && ioc.objset->module && ioc.objset->module->ModuleName)
        ctx->module = ioc.objset->module->ModuleName;

    char *path_key = strdup(parent_path);

    /* spec-key: R2(X). rawCid = the real C struct identifier of the clone
     * (asn1c's `typedef struct <X_cid> {...} <X_cid>_t;` — the verbatim tag,
     * underscore-preserving, e.g. RICaction_ToBeSetup_ItemIEs, NOT the
     * _-collapsed Go name RICactionToBeSetupItemIEs). */
    emit_name(ctx->bag, ctx->module, path_key, GK_SPEC_KEY,
              own(x_cid), strdup(x_go));
    /* struct-body stage: the specialization's Go struct (envelope + the Value union
     * holder) — the field rows below attach to this scope. */
    row_set_is_struct(ctx->bag);
    /* Flat: the field-shaped spec IS a Flat struct
     * in X's module ({id/procedureCode, criticality, value{present,alts}}),
     * the frozen E2AP_RICaction_ToBeSetup_ItemIEs_flat / <Msg>_IEs_flat
     * shape. Members land on it through the envelope walk below. */
    (void)go_flat_struct(x_cid, ctx->module);
    go_flat_label_cur(seq_terminal->Identifier);   /* td->name label */

    /* The struct's field scope is this specialization; reset before the envelope
     * member walk so struct-scoped field names collide only with siblings of THIS
     * struct. */
    reset_field_scope(ctx->bag);
    struct_scope_open(ctx->bag, x_go);

    /* Envelope field rows: walk the specialization SEQUENCE's members and emit a
     * `field` for each PLAIN envelope member (id/procedureCode/criticality) AND
     * for the open-type `value` member (which becomes the single `Value` field).
     * The open-type member is itself a member of the SEQUENCE body; detect it
     * with go_construct_is_open_type (the same test the frozen walker uses). An
     * open-type member does not carry the envelope; it becomes `Value` (typed by
     * the <X>Value union emitted below). */
    asn1p_expr_t *open_member = NULL;
    asn1p_expr_t *mem;
    TQ_FOR(mem, &(seq_terminal->members), next) {
        if(go_construct_is_open_type(mem)) {
            open_member = mem;
            continue;   /* emitted as the single `Value` field below */
        }
        /* Skip a bare reference/member with no Identifier (defensive; the
         * envelope members all carry one). */
        if(!mem->Identifier) continue;
        char *path = make_path(parent_path, mem->Identifier);
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  go_mk_member(mem), go_r2(GO_MKID(mem)));
        /* Flat: the envelope member's ref row (the class-field-declared
         * type's own cid; integer/enum leaves resolve via the declared
         * type's leaf Flat). */
        {
            char *env_cid = NULL;
            if(go_construct_is_classfield_ref(mem)) {
                asn1p_expr_t *decl = classfield_declared_type(ctx, mem);
                if(decl) env_cid = own(GO_MKID(decl));
            }
            if(env_cid) {
                char *tok = go_mk_member(mem);
                go_flat_member_ref(env_cid, tok, 0);
                go_flat_label_last_member(mem->Identifier);
                free(env_cid); free(tok);
            }
        }
        /* struct-body stage: envelope member field types — a reference to the class-field
         * declared type (&id -> ProtocolIE-ID, &procedureCode ->
         * ProcedureCode, &criticality -> Criticality): the resolved named
         * type's own name, cross-module qualified. Resolution mirrors asn1c_C.c:
         * 2653-2655/2710-2720 — an &field reference resolves to the class's
         * declared field type (find_column_index + the field's Type). */
        {
            char *ft = NULL;
            if(go_construct_is_classfield_ref(mem)) {
                asn1p_expr_t *decl = classfield_declared_type(ctx, mem);
                if(decl) {
                    char *tgo = go_r2(GO_MKID(decl));
                    ft = str_append(strdup(""), tgo);
                    free(tgo);
                }
            }
            if(!ft) {
                /* A non-class-field envelope member (a plain typed member of a
                 * directly-defined specialization): the reference target's
                 * named type, or the mapping-table leaf. */
                asn1p_expr_t *t = mem;
                if(mem->expr_type == A1TC_REFERENCE
                   || mem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *r = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, mem);
                    if(r) t = r;
                }
                if(t->expr_type == ASN_CONSTR_SEQUENCE
                   || t->expr_type == ASN_CONSTR_CHOICE
                   || t->expr_type == ASN_CONSTR_SEQUENCE_OF
                   || t->expr_type == ASN_BASIC_ENUMERATED) {
                    char *tgo = go_r2(GO_MKID(t));
                    ft = str_append(strdup(""), tgo);
                    free(tgo);
                } else {
                    int lk = classify_leaf(ctx, t, parent_path);
                    const char *under = go_types_leaf_underlying(lk);
                    if(under) ft = own(under);
                }
            }
            if(ft) {
                row_set_field_type(ctx->bag, ft);
                free(ft);
            }
        }
    }

    /* A field-shaped spec without an open-type &Value member is
     * an unforeseen structure — fail loud and file a Q rather than emit a struct
     * with no Value union. is_field_shaped_spec already guaranteed one existed at
     * the call site, so this is a consistency guard. */
    if(!open_member) {
        fprintf(stderr,
                "asn1cgo: field-shaped specialization %s has no open-type &Value "
                "member in module %s: %s\n",
                ctx->module ? ctx->module : "?", ctx->module ? ctx->module : "?",
                parent_path ? parent_path : "?");
        ctx->bag->failed = 1;
        ctx->module = save_module;
        return;
    }
    /* The open-type member becomes the single `Value` field (the union holder).
     * goName = `Value` (the envelope's value slot, matching the frozen unit
     * `Value <X>Value>`); the path leaf is the member's ASN.1 identifier so the
     * dump's provenance reflects the actual member (the index keys the field by
     * goName). struct-body stage: its field TYPE is the <X>Value union (by VALUE — the
     * envelope's value slot is the union struct itself, matching the frozen units
     * `Value RICactionToBeSetupItemIEsValue`). */
    {
        const char *leaf = open_member->Identifier ? open_member->Identifier
                                                   : "Value";
        char *path = make_path(parent_path, leaf);
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  strdup("Value"), strdup("Value"));
        char *ft = str_append(strdup(""), x_go);
        ft = str_append(ft, "Value");
        row_set_field_type(ctx->bag, ft);
        free(ft);
        /* Flat: the value member nests the open-type
         * union INLINE ({present, alts...}) — the verbatim .h `value`
         * member. Mint the nested node (its cid = <x_cid>__value so the
         * present/alt primes below find it); the alt rows attach under it
         * via the _on handle the enclosing struct records. OWN the cid (the
         * GO_MKID static buffer aliases across the compound call). */
        {
            char *flat_vtok = own("value");
            char *vx_cid = str_append(strdup(""), x_cid);
            vx_cid = str_append(vx_cid, "__value");
            int v_ix = go_flat_struct_nested(vx_cid, ctx->module);
            /* the value union IS a CHOICE layout ({present, alts}, present
             * first, exactly the .h `struct <X>__value` wrapper): the glue's
             * emit_nested dispatches on is_choice — without the flag the
             * union walked LINEARLY (fill/read of EVERY alt slot, nil *T
             * handed to the selected alt's fill, unselected pointer slots
             * deref'd on read: the E2AP-envelope round trip faults at
             * DecodeE2APPDU).
             * flat_new_type dedups by (cid, module), so this mint lands the
             * flag ON the pre-minted node above — but go_flat_choice ALSO
             * re-binds the cur register to it; emit_spec's caller keeps
             * populating the ENCLOSING struct after this, so save/restore
             * cur around the call (the walk_names_child CHOICE arm's own
             * pattern). */
            {
                int save_fcur = go_flat_cur_get();
                go_flat_choice(vx_cid, ctx->module);
                go_flat_cur_restore(save_fcur);
            }
            go_flat_member_nested(v_ix, flat_vtok, 0);
            free(flat_vtok); free(vx_cid);
        }
    }

    /* spec-value: R2(X)+Value — the open-type value union. rawCid = <X_cid>__value
     * (the real asn1c `struct <X_cid>__value {...}` wrapper tag). struct-body stage: the
     * UNION is a struct too (Present + one pointer field per alt — the pointer-per-alt form
     * alt fields emit_spec_value_alts records in the x_go+"Value" scope).
     * emit_name takes ownership of `go` (add_row retains it). */
    {
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "Value");
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value");
        char *path = make_path(parent_path, "Value");
        emit_name(ctx->bag, ctx->module, path, GK_SPEC_VALUE, raw, go);
        row_set_is_struct(ctx->bag);
    }
    /* spec-pr: R2(X)+ValuePr — the union discriminant type. rawCid =
     * <X_cid>__value_PR (the real asn1c `typedef enum <X_cid>__value_PR` tag). */
    {
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "ValuePr");
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value_PR");
        char *path = make_path(parent_path, "ValuePr");
        emit_name(ctx->bag, ctx->module, path, GK_SPEC_PR, raw, go);
    }

    /* value-union alt fields + choice-consts + PrNothing. The alts are the
     * &Value column cells of the object set the specialization binds to, exactly
     * as asn1c_C.c asn1c_lang_C_OpenType:1090-1101 iterates ioct->row[r]->column[
     * col]->value to build the open-type CHOICE. We resolve that object set via
     * asn1c_get_ioc_table (the same call the C backend makes), find the "Value"
     * column (mirroring find_column_index at asn1c_C.c:1049), and emit one
     * choice-const + field per distinct alt. */
    emit_spec_value_alts(ctx, x_go, x_cid, parent_path, seq_terminal);
    ctx->module = save_module;
}

/* emit_spec_value_alts: enumerate the open-type value-union alternatives of a
 * field-shaped specialization and emit their choice-const + field rows, plus the
 * PrNothing discriminant. The alts = the object-set &Value column cells; mirrors
 * asn1c_C.c:1090-1101. The value union's discriminant is <X>+"ValuePr"; the alts
 * are one field each, struct-scoped to the union. rawCids use the real C-ident
 * prefix x_cid (the verbatim <X_cid>__value_PR[_NOTHING|_<AltCid>] tokens). */
static void
emit_spec_value_alts(struct walk_ctx *ctx, const char *x_go,
                     const char *x_cid, const char *parent_path,
                     asn1p_expr_t *seq_terminal) {
    /* Resolve the object set the specialization binds. asn1c_get_ioc_table walks
     * the SEQUENCE's members for a component-relation constraint and returns its
     * IOC table (asn1c_ioc.c:67); it needs a minimal arg_t carrying asn/ns/expr
     * = the specialization SEQUENCE. */
    arg_t arg;
    memset(&arg, 0, sizeof arg);
    arg.asn = ctx->asn;
    arg.ns = ctx->ns;
    arg.expr = seq_terminal;
    asn1c_ioc_table_and_objset_t ioc = asn1c_get_ioc_table(&arg);
    if(!ioc.ioct || ioc.ioct->rows == 0) {
        /* No object rows: emit PrNothing only (matches a value union with no
         * alternatives, e.g. SingleContainer of an empty set). */
        emit_value_pr_nothing(ctx, x_go, x_cid, parent_path);
        return;
    }

    /* The open-type member decides WHICH class-field column holds the alts.
     * ProtocolIE-Field's value member references &Value; an envelope's value
     * member references &InitiatingMessage / &SuccessfulOutcome / ... The field
     * name is component[1] of the member's reference; the IOC row stores each
     * class-field under "&<field>". The union name is <X>+"Value" regardless (the
     * the frozen unit's InitiatingMessageValuePr<X> attests). */
    asn1p_expr_t *valmember = is_field_shaped_spec(seq_terminal);
    /* components[1].name already carries the leading '&' ("&Value",
     * "&InitiatingMessage"), exactly as the IOC row's field Identifier does — so
     * use it verbatim (no re-prefixing). */
    char wantcol[128] = "&Value";
    if(valmember && valmember->reference
       && valmember->reference->comp_count >= 2
       && valmember->reference->components[1].name) {
        snprintf(wantcol, sizeof wantcol, "%s",
                 valmember->reference->components[1].name);
    }
    ssize_t col = -1;
    for(size_t c = 0; c < ioc.ioct->row[0]->columns; c++) {
        if(ioc.ioct->row[0]->column[c].field
           && ioc.ioct->row[0]->column[c].field->Identifier
           && strcmp(ioc.ioct->row[0]->column[c].field->Identifier, wantcol) == 0) {
            col = (ssize_t)c;
            break;
        }
    }
    (void)arg;
    if(col < 0) {
        emit_value_pr_nothing(ctx, x_go, x_cid, parent_path);
        return;
    }
    /* The union struct opens its scope right after the PrNothing block below;
     * the early return here leaves no open scope (an empty union's fields are
     * none; emit_value_pr_nothing only writes a const row). */


    /* PrNothing first, then one choice-const + one field per distinct alt
     * (asn1c dedups by Identifier at asn1c_C.c:1096-1097). The field scope is the
     * whole value union, so reset once. The alt's C union-member token is
     * GO_MKID(cell value); its Go field = R2(token). The choice-const is
     * <X>+"ValuePr" + R2(token) (the discriminant-const form for owner
     * <X>Value). rawCids use x_cid (the real <X_cid>__value_PR token).
     *
     * struct-body stage: the union's own fields open a struct scope under <X>Value —
     * the alt fields (and Present, emitted by the first alt's row order below
     * — see emit_choice's Present row; here the union carries ONLY the alt
     * pointers, the discriminant lives on the union's Go struct as `Present`,
     * which emit_name<GK_FIELD> records through the open scope) attach to it. */
    reset_field_scope(ctx->bag);
    {
        char *owner = str_append(strdup(""), x_go);
        owner = str_append(owner, "Value");
        struct_scope_open(ctx->bag, owner);
        free(owner);
        /* The union's `Present` discriminant field (the holder), rawCid
         * the real `present` member token — same rule as emit_choice's. Its
         * PATH leaf keys it under the union's own dump scope (parent_path +
         * "Value" + "Present"), mirroring the index bucketing (the wrapper's
         * `present` member routes to the compounded <X>Value owner); an
         * envelope-scoped path would attribute it to the IEs struct, which
         * carries no Present (the frozen envelope is {Id, Criticality,
         * Value}). */
        {
            char *base = make_path(parent_path, "Value");
            char *path = make_path(base, "Present");
            free(base);
            emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      strdup("present"), strdup("Present"));
            char *pt = str_append(strdup(""), x_go);
            pt = str_append(pt, "ValuePr");
            row_set_field_type(ctx->bag, pt);
            free(pt);
            /* Flat: the union's present member (int32) lands on the
             * nested __value node (the register — cur is the ENCLOSING
             * spec struct here). display label: the open-type VALUE member's
             * td-member name ("value" — the &Value/&InitiatingMessage
             * Identifier names the class FIELD, not this member). */
            go_flat_member_prim_on(-1, "int32_t", "present", 0);
            go_flat_label_last_member("value");
            (void)valmember;
        }
    }
    /* PrNothing discriminant const, value 0, in this module (module already
     * rebound to X's by emit_spec). */
    {
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value_PR_NOTHING");
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "ValuePrNothing");
        char *type_go = str_append(strdup(""), x_go);
        type_go = str_append(type_go, "ValuePr");
        char *path = make_path(parent_path, "ValuePrNothing");
        emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
        /* Value 0: NOTHING heads the __value_PR enum (asn1c_C.c:2842-2843,
         * the indexToPresence table: NOTHING first, then one entry per object
         * row — the row ORDER is the numbering, i.e. the same order the alt
         * loop below walks). */
        row_set_const(ctx->bag, "0", type_go);
        free(type_go);
    }
    /* Iterate rows, dedup by the alt's ASN.1 Identifier exactly as asn1c does
     * (asn1c_C.c:1096 asn1p_lookup_child — duplicate &Value rows collapse to one
     * alt). Without this, extensible object sets with repeated Value members
     * produce spurious per-name collisions. */
    char **seen = NULL;
    size_t n_seen = 0, cap_seen = 0;
    /* leaf-stage body data: the __value_PR value is the alt's DEDUPED SEQUENCE
     * position (PrNothing=0 above, then 1,2,...), mirroring asn1c's own
     * numbering (asn1c_C.c:2842-2852 indexToPresence: NOTHING first, then one
     * entry per object row in set order; the open-type CHOICE members are
     * cloned in that same deduped row order — asn1c_lang_C_OpenType:1086-1092
     * — and the _PR enum carries no explicit values, so implicit numbering IS
     * the row order). Verified non-sequential case: InitiatingMessage__value_
     * PR_ErrorIndication = 23 (row 23 of E2AP-ELEMENTARY-PROCEDURES) while
     * procedureCode(id-ErrorIndication) = 2 — InitiatingMessage.h:88-110. */
    int value_seq = 0;
    for(size_t r = 0; r < ioc.ioct->rows; r++) {
        struct asn1p_ioc_cell_s *cell = &ioc.ioct->row[r]->column[col];
        if(!cell->value || !cell->value->Identifier)
            continue;
        size_t s;
        for(s = 0; s < n_seen; s++)
            if(strcmp(seen[s], cell->value->Identifier) == 0) break;
        int dedup_alt = (s < n_seen);
        /* dedupeded alts reuse the alt's original _PR slot (the alt was
         * emitted when first seen); new alts take the next sequence
         * position. Positioned BEFORE the seen[] append so the first
         * occurrence's slot is 1 (row order), matching ++value_seq below. */
        int present_val = dedup_alt ? (int)(s + 1) : (int)(n_seen + 1);
        char *dup = dedup_alt ? NULL : strdup(cell->value->Identifier);
        if(dup) {
            if(n_seen + 1 > cap_seen) {
                size_t nc = cap_seen ? cap_seen * 2 : 8;
                char **np = realloc(seen, nc * sizeof(char *));
                if(np) { seen = np; cap_seen = nc; } else { free(dup); goto done_seen; }
            }
            seen[n_seen++] = dup;
        }
        /* Conv (the IOC rule): record this IOC dispatch row — id/criticality off
         * the row's earlier columns (INTEGER cells: the value via
         * value->value.v_integer; criticality's Criticality numbering
         * reject=0/ignore=1/notify=2 — the enumerand's own ASN.1 value),
         * present = the deduped alt sequence position (1,2,...; the same
         * value ++value_seq renders below), alt_token = the union member
         * token, alt_msg = the payload's own prefixed cid (GO_MKID of the
         * chased terminal). The envelope marker (procedure-dispatch) keys on the id
         * member: column 0 of an E2AP-ELEMENTARY-PROCEDURES row is
         * &procedureCode, of a PROTOCOL-IES row &id.
         *
         * The recognized dispatch spellings are exactly &id, &procedureCode
         * and &criticality (the constructor rule's shape); a class field
         * spelled any other way that a row cell populates is an
         * unrecognized dispatch shape — fail loud HERE, naming the object
         * class field, rather than let the ctor layer die on an id -1
         * sentinel it cannot attribute. A class that omits &criticality
         * is a SUPPORTED shape (rows carry no criticality; the
         * constructors omit the field). */
        {
            long row_id = -1, row_crit = -1;
            const char *row_id_member = "id";
            char *id_gov = NULL;   /* R2 name of the id column's declared type */
            char *crit_gov = NULL; /* ... of &criticality; NULL = no column */
            int unknown_col = 0;
            int id_literal = 0;    /* the id cell is a bare INTEGER literal */
            /* scan every column EXCEPT the value column — procedure-dispatch rows place
             * &procedureCode/&criticality AFTER the &InitiatingMessage col */
            for(size_t oc = 0; oc < ioc.ioct->row[r]->columns; oc++) {
                if((ssize_t)oc == col) continue;
                struct asn1p_ioc_cell_s *ocell =
                    &ioc.ioct->row[r]->column[oc];
                if(!ocell->field || !ocell->field->Identifier
                   || !ocell->value || !ocell->value->Identifier)
                    continue;
                const char *fid = ocell->field->Identifier;
                /* the cell value: an INTEGER literal (id-dispatch &id rows) or a
                 * REFERENCE to a value assignment (procedure-dispatch: PROCEDURE CODE
                 * id-RICsubscription — chase the terminal for the integer;
                 * CRITICALITY reject is an ENUMERATED reference likewise). */
                /* VALUE-ASSIGNMENT chase (id-dispatch and procedure-dispatch id cells): the cell
                 * value references a value assignment (id-RICrequestID ::=
                 * 29 / id-RICsubscription ::= 8). Resolve by the SAME
                 * read-only lookup chain the C backend's IOC emitter uses
                 * (asn1c_ioc.c:161-171 — asn1f_lookup_symbol_ex loop until
                 * the value is not ATV_REFERENCED); NOT asn1f_find_terminal_
                 * value (it resolves in place and re-fatal'd the C naming
                 * pass on E2AP). */
                asn1p_expr_t *cv = ocell->value;
                while(cv && cv->value
                      && cv->value->type == ATV_REFERENCED) {
                    asn1p_expr_t *nx = WITH_MODULE_NAMESPACE(
                        cv->module, cv_ns,
                        asn1f_lookup_symbol_ex(ctx->asn, cv_ns, cv,
                                               cv->value->value.reference));
                    if(!nx)
                        nx = asn1f_lookup_symbol_ex(ctx->asn, ctx->ns, cv,
                                                    cv->value->value.reference);
                    if(!nx) {
                        /* the defining module may not IMPORT the value
                         * assignment (the PROCEDURE CODE row cell sits in
                         * PDU-Descriptions, the value in Constants) —
                         * sweep every module's namespace. */
                        asn1p_module_t *mscan;
                        TQ_FOR(mscan, &(ctx->asn->modules), mod_next) {
                            if(nx) break;
                            nx = WITH_MODULE_NAMESPACE(
                                mscan, ms_ns,
                                asn1f_lookup_symbol_ex(ctx->asn, ms_ns, cv,
                                          cv->value->value.reference));
                        }
                    }
                    if(!nx) break;
                    cv = nx;
                }
                asn1p_value_t *v = cv && cv->value
                                  && cv->value->type != ATV_REFERENCED
                                       ? cv->value : NULL;
                if(strcmp(fid, "&procedureCode") == 0) {
                    row_id_member = "procedureCode";
                    if(v) row_id = (long)v->value.v_integer;
                    free(id_gov);
                    id_gov = column_governing_go(ctx, ocell->field);
                    id_literal = cell_id_is_literal(cv);
                } else if(strcmp(fid, "&id") == 0) {
                    if(v) row_id = (long)v->value.v_integer;
                    free(id_gov);
                    id_gov = column_governing_go(ctx, ocell->field);
                    id_literal = cell_id_is_literal(cv);
                } else if(strcmp(fid, "&criticality") == 0) {
                    if(v) row_crit = (long)v->value.v_integer;
                    free(crit_gov);
                    crit_gov = column_governing_go(ctx, ocell->field);
                } else if(strcmp(fid, "&presence") == 0) {
                    /* a known non-dispatch column of the 3GPP IE classes
                     * (mandatory/optional/conditional): not part of the
                     * constructor's material — the ctor layer never reads
                     * it — but a legitimate class field, not an error. */
                } else if(strcmp(fid, "&InitiatingMessage") == 0
                          || strcmp(fid, "&SuccessfulOutcome") == 0
                          || strcmp(fid, "&UnsuccessfulOutcome") == 0) {
                    /* the procedure-dispatch class's message columns: each
                     * IS the value column of its own envelope spec (only
                     * the column matching this walk's value member is
                     * excluded above); the siblings are known payloads of
                     * the other two envelope specializations. */
                } else {
                    unknown_col = 1;
                    fprintf(stderr,
                            "asn1cgo: object class field %s of object set %s "
                            "is not a recognized dispatch field (recognized: "
                            "&id, &procedureCode, &criticality, &presence, "
                            "the procedure message columns; module %s)\n",
                            fid,
                            ioc.objset && ioc.objset->Identifier
                                ? ioc.objset->Identifier
                                : (cell->value->Identifier
                                       ? cell->value->Identifier : "?"),
                            ctx->module ? ctx->module : "?");
                }
            }
            /* the alt payload's own cid: GO_MKID of the chased terminal of
             * the &Value cell (a named message type in this spec) */
            const char *amsg = "";
            {
                asn1p_expr_t *vt_ = cell->value;
                if(vt_->expr_type == A1TC_REFERENCE
                   || vt_->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *t_ =
                        asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, vt_);
                    if(t_) vt_ = t_;
                }
                if(vt_->Identifier) amsg = GO_MKID(vt_);
            }
            int is_env = (strcmp(row_id_member, "procedureCode") == 0);
            /* the unrecognized-shape guard: a column the dispatcher did not
             * name, or an id that never resolved (a dispatch column spelled
             * differently leaves row_id at its -1 sentinel even when each
             * cell DID resolve) — either way the ctor layer cannot be told
             * what to emit; fail the run naming the class, never skip the
             * row and never misemit. */
            if(unknown_col || row_id == -1) {
                fprintf(stderr,
                        "asn1cgo: IOC dispatch row of %s (module %s) has an "
                        "unrecognized object-class shape%s — refusing to "
                        "emit its layer\n",
                        x_go, ctx->module ? ctx->module : "?",
                        unknown_col ? " (unrecognized class field named above)"
                                    : " (no recognizable id column)");
                ctx->bag->failed = 1;
            }
            { char *alt_tok = go_mk_suffix(cell->value);
              go_conv_record_ioc_row(x_cid, row_id_member, row_id, row_crit,
                                     present_val, alt_tok, amsg, is_env,
                                     id_gov ? id_gov : "", crit_gov,
                                     id_literal);
              free(alt_tok); }   /* record copies (cstrdup) — owned transcient */
            free(id_gov);
            free(crit_gov);
        if(dedup_alt) continue;   /* alt already emitted on its first row */

        }
        /* the __value_PR enumerant suffix and the union member decl
         * token are unprefixed member tokens (c_presence_name suffix +
         * MKID_safe; asn1c_naming.c:304, asn1c_C.c:1353). */
        const char *altcid = go_mk_suffix(cell->value);
        char *altgo = go_r2(altcid);
        /* choice-const <X>ValuePr<Alt>; rawCid = <X_cid>__value_PR_<AltCid> (the
         * real asn1c enum-member token). */
        {
            char *raw = str_append(strdup(""), x_cid);
            raw = str_append(raw, "__value_PR_");
            raw = str_append(raw, altcid);
            char *go = str_append(strdup(""), x_go);
            go = str_append(go, "ValuePr");
            go = str_append(go, altgo);
            char *type_go = str_append(strdup(""), x_go);
            type_go = str_append(type_go, "ValuePr");
            char *path = make_path(parent_path, cell->value->Identifier);
            emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
            row_set_const(ctx->bag, asn1p_itoa(++value_seq), type_go);
            free(type_go);
        }
        /* field row: the alt's data pointer, struct-scoped to the union.
         * struct-body stage: the field's Go type is the alt's own named type — a pointer
         * (pointer per alt); cross-module qualification happens post-walk
         * (qualify_field_types, once the whole name table exists). PATH: under
         * the union's own scope (parent_path + "Value" + alt) — same rule as
         * the Present row above: the alt field belongs to the <X>Value union
         * struct, and the dump-side owner attribution (path-keyed
         * projection bucketing) keys a row to the union by the "Value"
         * path segment. A row at <X>.<Alt> would attribute to the envelope
         * IEs struct (or scopeless), desynchronizing dump vs emitted body. */
        {
            char *base = make_path(parent_path, "Value");
            char *path = make_path(base, cell->value->Identifier);
            free(base);
            emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      own(altcid), strdup(altgo));
            char *ft = str_append(strdup(""), "*");
            ft = str_append(ft, altgo);
            row_set_field_type(ctx->bag, ft);
            free(ft);
        }
        /* Flat (path 2 / the open-type mapping row): the open-type value
         * union is ALWAYS INLINE per alt (the IOC dispatch rule: the asn1c union
         * members here are inline structs; no re-synthesis). One inline
         * slot per alt cid under the __value node. */
        {
            char *flat_alt = own(altcid);   /* GO_MKID buffer owner */
            char *flat_slot = own(altcid);  /* the member token */
            go_flat_member_ref_on(-1, flat_alt, flat_slot, 0);
            /* alt slot label = the alt's ASN.1 Identifier (the td
             * union-member name string). */
            go_flat_label_last_member(cell->value->Identifier);
            free(flat_alt); free(flat_slot);
        }
        free(altgo);
        free((char *)altcid);
    }
done_seen:
    for(size_t s = 0; s < n_seen; s++) free(seen[s]);
    free(seen);
    struct_scope_reset(ctx->bag);
}

/* emit_value_pr_nothing: the lone discriminant for a value union with no
 * resolved alternatives (empty / unresolved object set). rawCid uses the real
 * C-ident prefix x_cid (the verbatim <X_cid>__value_PR_NOTHING token). */
static void
emit_value_pr_nothing(struct walk_ctx *ctx, const char *x_go,
                      const char *x_cid, const char *parent_path) {
    char *raw = str_append(strdup(""), x_cid);
    raw = str_append(raw, "__value_PR_NOTHING");
    char *go = str_append(strdup(""), x_go);
    go = str_append(go, "ValuePrNothing");
    char *type_go = str_append(strdup(""), x_go);
    type_go = str_append(type_go, "ValuePr");
    char *path = make_path(parent_path, "ValuePrNothing");
    emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
    row_set_const(ctx->bag, "0", type_go);
    free(type_go);
}

/* member_is_default: asn1c's own DEFAULT-vs-OPTIONAL discriminator
 * (asn1c_C.c:1351-1358): DEFAULT iff (flags & (EM_DEFAULT & ~EM_INDIRECT))
 * == EM_DEFAULT & ~EM_INDIRECT -- an exact-mask test, NOT a bit test
 * (EM_OPTIONAL 0x07 shares bits with EM_DEFAULT 0x0F; the C pass adds
 * bits, so `flags == EM_DEFAULT` would miss). */
static int
member_is_default(const asn1p_expr_t *child) {
    return (child->marker.flags & (EM_DEFAULT & ~EM_INDIRECT))
           == (EM_DEFAULT & ~EM_INDIRECT);
}

/* member_stars: the Go pointer-star rule for a struct member (the struct-body pass).
 * Types.go stars a member iff it is OPTIONAL — nil = absent — with no
 * exception for slice-shaped members (an OPTIONAL SEQUENCE OF is a
 * pointer-to-slice: nil pointer = absent, non-nil pointer to nil/empty slice
 * = present). EM_INDIRECT is deliberately NOT read here: it is the C
 * column's pointer decision (recursion break asn1c_C.c:3520, or
 * -findirect-choice on a CHOICE member :3490-3497); types.go never follows
 * it — the Go side keeps the by-value inline shape there. Pointers come
 * from OPTIONAL only (CHOICE/value-union alt fields are pointers by
 * construction, not via this function).
 *   EM_DEFAULT — a real DEFAULT member the C generator gives default
 *                 callbacks for: a plain value (""); any other DEFAULT
 *                 form fails the run (exit 70) naming the reason.
 * Returns "*" when the member is pointer-shaped, "" otherwise; sets failed on
 * the bag for the DEFAULT case (the caller's -1 return fails the run). */
static const char *
member_stars(struct walk_ctx *ctx, asn1p_expr_t *child, const char *path) {
    /* asn1c's own DEFAULT-vs-OPTIONAL discriminator (asn1c_C.c:1351-1358):
     * DEFAULT iff (flags & (EM_DEFAULT & ~EM_INDIRECT)) == EM_DEFAULT &
     * ~EM_INDIRECT — an exact-mask test, NOT a bit test (EM_OPTIONAL 0x07
     * shares bits with EM_DEFAULT 0x0F; a plain `& EM_DEFAULT` would
     * misread EM_UNRECURSE-composites). A real DEFAULT member is out of
     * model: fail loud, no Go shape is picked. */
    if(member_is_default(child)) {
        /* A supported DEFAULT member (the C generator emits default
         * callbacks for it: the shared predicate) is a PLAIN VALUE in Go --
         * never a pointer; the C runtime fills an absent default on decode.
         * Anything else is out of model: fail loud, naming the reason. */
        arg_t darg;
        const char *why = NULL;
        memset(&darg, 0, sizeof darg);
        darg.asn = ctx->asn;
        darg.ns = ctx->ns;
        darg.expr = child;
        if(!asn1c_default_callbacks_supported(&darg, child, &why)) {
            fprintf(stderr,
                    "asn1cgo: DEFAULT member %s is out of model in "
                    "module %s: %s\n",
                    path ? path : "?", ctx->module ? ctx->module : "?",
                    why ? why : "unsupported DEFAULT form");
            ctx->bag->failed = 1;
        }
        ctx->last_opt_extra = 0;
        return "";
    }
    /* Nested-mask test, NOT a bit test and NOT exact-equality. The marker
     * flags are a NESTED hierarchy (asn1p_expr.h:208-212):
     *   EM_INDIRECT 0x01 < EM_OMITABLE 0x03 < EM_OPTIONAL 0x07 < EM_DEFAULT 0x0F
     * and fixer passes ADD bits to an existing marker rather than replacing
     * it (-findirect-choice sets EM_INDIRECT|EM_UNRECURSE -> 0x11 on a
     * mandatory CHOICE member; expr_break_recursion's back-edge break sets
     * EM_INDIRECT on an OPTIONAL member too, giving 0x17 — OPTIONAL still).
     * So:
     *   FALSE-STAR trap (bit test `f & EM_OPTIONAL`): 0x11 & 0x07 = 0x01 ->
     *     a mandatory recursion-broken member stars (caught: a frozen
     *     RANParameterDefinition by-value RanParameterDefinitionChoice failed
     *     full-tree -cmp as *RANParameterDefinitionChoice).
     *   STAR-LOSS trap (exact equality `== EM_OPTIONAL`): an OPTIONAL member
     *     carrying extra bits (0x17) compares unequal and loses its star
     *     ("OPTIONAL is always *X" — the star must survive).
     * The containment form `(f & EM_OPTIONAL) == EM_OPTIONAL` (the same form
     * go_walk.c:409 and asn1c_C.c:1357 use for the OPTIONAL arm) is correct
     * under nesting: EM_OPTIONAL's bits are ALL present iff the member is
     * OPTIONAL, whatever additional bits the fixer added. EM_DEFAULT was
     * already rejected above, so a 0x1F-style superset cannot reach here.
     * Census: an OPTIONAL member whose flags carry bits
     * BEYOND EM_OPTIONAL is recorded on ctx->last_opt_extra (the caller
     * copies it onto the member's field row) — reported at run end,
     * purely informational. */
    ctx->last_opt_extra = 0;
    if((child->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
        if(child->marker.flags & ~EM_OPTIONAL)
            ctx->last_opt_extra = child->marker.flags & ~EM_OPTIONAL;
        return "*";
    }
    /* An extension ADDITION (a member after the first `...` of an extensible
     * SEQUENCE) without OPTIONAL: the C pass stamps EM_OMITABLE|EM_INDIRECT on
     * every such member (asn1c_C.c:362), because a sender that implements an
     * older version of the spec leaves it out of the encoding (X.691). The C
     * struct member is a pointer and NULL means "absent", so the Go field is a
     * pointer too, exactly as for OPTIONAL. A DEFAULT addition never reaches
     * here (handled above: a plain value). Plain mandatory members carry at
     * most EM_INDIRECT|EM_UNRECURSE, never the EM_OMITABLE bit. */
    if((child->marker.flags & EM_OMITABLE) == EM_OMITABLE)
        return "*";
    return "";
}

/* classfield_declared_type: the declared TYPE of a lowercase class-field
 * reference member (&id, &procedureCode, &criticality — the envelope members
 * of a field-shaped specialization). Resolution is asn1f_class_access_ex —
 * the same resolver the C backend uses for an &field reference
 * (asn1c_C.c:1284 calls the same entry) — over the member's own reference.
 * The result is the class-field's declared type expression (ProtocolIE-ID,
 * ProcedureCode, Criticality — the FIXED type field's child). Returns NULL
 * when the reference does not resolve (the caller leaves the field type
 * unset; go build names it loudly). */
static asn1p_expr_t *
classfield_declared_type(struct walk_ctx *ctx, asn1p_expr_t *mem) {
    if(!mem->reference) return NULL;
    asn1p_expr_t *r = asn1f_class_access_ex(ctx->asn, NULL, ctx->ns, mem, NULL,
                                            mem->reference);
    /* The returned field-type expr is the class-field's declared-type node —
     * an A1TC_REFERENCE (e.g. `ProtocolIE-ID`) with NO Identifier of its own
     * (asn1c_make_identifier would render it "Member", asn1c_misc.c:78).
     * Chase it to the terminal assignment so the Go name is the referenced
     * type's own goName. */
    if(r && (r->expr_type == A1TC_REFERENCE || r->meta_type == AMT_TYPEREF)) {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, r);
        if(t) return t;
    }
    return r;
}

/* The R2 Go name of an IOC COLUMN's declared type. The column's field
 * expr (the class field spec, e.g. `&id ProtocolIE-ID UNIQUE`) carries the
 * declared type as its first child (asn1p: a FixedTypeValueFieldSpec's
 * Type — as parsed at asn1p_y.y's ObjectClassField parse, the child of the
 * field expr). Chase a reference to its terminal assignment and R2 its
 * real C ident (the same naming path the envelope member rows take). */
static char *
column_governing_go(struct walk_ctx *ctx, asn1p_expr_t *field) {
    asn1p_expr_t *ch = TQ_FIRST(&field->members);
    if(!ch) return NULL;
    asn1p_expr_t *t = ch;
    if(ch->expr_type == A1TC_REFERENCE || ch->meta_type == AMT_TYPEREF) {
        asn1p_expr_t *r = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, ch);
        if(r) t = r;
    }
    if(!t->Identifier) return NULL;
    return go_r2(GO_MKID(t));
}

/* Is an id cell's chased value a NUMBER LITERAL (no value assignment
 * behind it)? asn1p mints the literal's own numeric text as the resolved
 * expr's Identifier ("1" for {ID 1}), while a value-assignment reference
 * chases to the assignment node whose Identifier is the assignment's own
 * (id-RICrequestID — a legal ASN.1 identifier always starts with a
 * lowercase letter, never a digit, so a digits-only Identifier is
 * unambiguous). */
static int
cell_id_is_literal(asn1p_expr_t *cv) {
    if(!cv || !cv->Identifier || !cv->Identifier[0]) return 0;
    for(const char *p = cv->Identifier; *p; p++)
        if(*p < '0' || *p > '9') return 0;
    return 1;
}

/* qualify_type: cross-module qualification for a named-type reference.
 * `go_name` is the referenced type's Go name; walks the FULL name table (the
 * walk has completed by the time this runs — qualify_field_types, below).
 * Returns an owned possibly-qualified copy: `pkg.Name` when the name's only
 * type row lives in another module, `Name` when local or unresolvable (go
 * build fails loudly on a truly unresolvable name — better than guessing). */
static char *
qualify_type(struct name_bag *b, const char *module, const char *go_name) {
    const char *tmod = NULL;
    int local = 0;
    for(int j = 0; j < b->n_rows; j++) {
        struct name_row *t = &b->rows[j];
        if(t->goName && strcmp(t->goName, go_name) == 0
           && (t->kind == GK_TYPE || t->kind == GK_INLINE
               || t->kind == GK_SPEC_KEY)) {
            if(t->module == module) { local = 1; break; }
            if(t->kind == GK_TYPE || t->kind == GK_SPEC_KEY) tmod = t->module;
        }
    }
    if(local || !tmod || tmod == module) return own(go_name);
    char *q = module_pkg_go(tmod);
    q = str_append(q, ".");
    q = str_append(q, go_name);
    return q;
}

/* qualify_field_types: post-walk prepass — cross-module qualification of
 * every FIELD row's Go type. The walk stores unqualified names (an assignment
 * may be referenced before the walk reaches its own row, so the bag must be
 * complete first — same reason qualify_foreign_const_types is a prepass).
 * Only a BARE name is rewritten: an already-qualified `pkg.Name` (never stored
 * by the walk today; kept idempotent) and primitives (int64, []byte, string,
 * BitString...) never carry a '.'-prefix match and stay untouched. */
static void
qualify_field_types(struct name_bag *b) {
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *f = &b->rows[i];
        if(f->kind != GK_FIELD || !f->field_type) continue;
        /* Strip one leading optional pointer star for the lookup; keep it in
         * the rewrite. A '*' beyond the first or a "[]" prefix is a
         * slice/array form — those refer to minted inline names or named
         * slice aliases (same-module by construction) and are skipped. */
        const char *t = f->field_type;
        const char *star = "";
        if(t[0] == '*') { star = "*"; t++; }
        if(!*t || strchr(t, '.') || strchr(t, '[')) continue;
        char *q = qualify_type(b, f->module, t);
        if(strchr(q, '.')) {
            char *nf = str_append(strdup(""), star);
            nf = str_append(nf, q);
            free(f->field_type);
            f->field_type = nf;
        }
        free(q);
    }
}

/* qualify_slice_elems: post-walk prepass — the cross-module
 * qualification of every slice-owner row's ELEMENT type (the slice side of
 * qualify_field_types; the same qualify_type lookup over the same table). A
 * `type X []pkg.Y` alias may reference an element assignment its module
 * references across a module boundary (e.g. e2ap_pdu_contents' container
 * slices over the e2ap_pdu_contents-declared ...ItemIEs — same-module there —
 * and a cross-module element in a future spec); the bare stored name is
 * qualified once the bag is complete. Primitives (int64, []byte, string,
 * BitString) never match a type row and stay untouched. */
static void
qualify_slice_elems(struct name_bag *b) {
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        if(r->kind != GK_TYPE && r->kind != GK_INLINE) continue;
        if(!r->slice_elem) continue;
        const char *t = r->slice_elem;
        if(!*t || strchr(t, '.') || strchr(t, '[')) continue;
        char *q = qualify_type(b, r->module, t);
        if(strchr(q, '.')) {
            free(r->slice_elem);
            r->slice_elem = q;
        } else {
            free(q);
        }
    }
}

/* ========================================================================= *
 * Go package import-cycle check (module -> module).
 *
 * Every ASN.1 module becomes one Go package; mutually importing modules would
 * generate packages Go refuses to build ("import cycle not allowed"). The
 * graph is built BEFORE any file is written from the two places a package
 * imports siblings:
 *   - types.go: collect_module_imports (the same helper emission uses),
 *   - glue.go:  the foreign packages of the glue fn registry, via a dry run
 *               of go_glue_emit (go_glue_collect_imports; same helper the
 *               real emission uses).
 * Any SCC of two or more modules is a hard error naming one cycle. Modules
 * are NOT merged; detection only.
 * ========================================================================= */
extern int go_glue_collect_imports(const char *go_module_basename,
                                   const char *go_rt_module,
                                   void (*cb)(const char *mod,
                                              const char *foreign, void *ud),
                                   void *ud);

struct impgraph {
    int n;
    const char **mod;     /* module names (distinct)           */
    char **pkg;           /* Go package dir per module         */
    unsigned char *adj;   /* n*n adjacency                     */
};

static int
impgraph_index(struct impgraph *g, const char *module) {
    for(int i = 0; i < g->n; i++)
        if(strcmp(g->mod[i], module) == 0) return i;
    return -1;
}

static void
impgraph_glue_cb(const char *mod, const char *foreign, void *ud) {
    struct impgraph *g = ud;
    int a = impgraph_index(g, mod), b = impgraph_index(g, foreign);
    if(a >= 0 && b >= 0 && a != b) g->adj[(size_t)a * g->n + b] = 1;
}

struct tj {
    struct impgraph *g;
    int *idx, *low, *on, *stk, sp, counter, *scc, n_scc;
};

static void
tj_visit(struct tj *t, int v) {
    int n = t->g->n;
    t->idx[v] = t->low[v] = t->counter++;
    t->stk[t->sp++] = v; t->on[v] = 1;
    for(int w = 0; w < n; w++) {
        if(!t->g->adj[(size_t)v * n + w]) continue;
        if(t->idx[w] < 0) {
            tj_visit(t, w);
            if(t->low[w] < t->low[v]) t->low[v] = t->low[w];
        } else if(t->on[w] && t->idx[w] < t->low[v]) {
            t->low[v] = t->idx[w];
        }
    }
    if(t->low[v] == t->idx[v]) {
        int w;
        do {
            w = t->stk[--t->sp]; t->on[w] = 0; t->scc[w] = t->n_scc;
        } while(w != v);
        t->n_scc++;
    }
}

/* Find a cycle through `start` staying inside SCC `c`; path[] gets the
 * vertices start..last (last -> start closes it). Returns its length. */
static int
imp_find_cycle(struct impgraph *g, const int *scc, int c, int start,
               int *path, int *seen, int v, int depth) {
    path[depth] = v; seen[v] = 1;
    for(int w = 0; w < g->n; w++) {
        if(!g->adj[(size_t)v * g->n + w] || scc[w] != c) continue;
        if(w == start) return depth + 1;
        if(seen[w]) continue;
        int r = imp_find_cycle(g, scc, c, start, path, seen, w, depth + 1);
        if(r) return r;
    }
    return 0;
}

/* Returns 0 clean, -1 on an import cycle (diagnostic printed). */
static int
check_go_import_cycles(struct name_bag *b) {
    struct impgraph g = {0};
    const char **mods = NULL;
    int n = 0, cap = 0;
    for(int i = 0; i < b->n_rows; i++) {
        const char *m = b->rows[i].module;
        if(!m) continue;
        int seen = 0;
        for(int j = 0; j < n; j++) if(strcmp(mods[j], m) == 0) { seen = 1; break; }
        if(seen) continue;
        if(n == cap) {
            cap = cap ? cap * 2 : 16;
            const char **nm = xrealloc(mods, (size_t)cap * sizeof(char *));
            if(!nm) { free(mods); return 0; }
            mods = nm;
        }
        mods[n++] = m;
    }
    if(n < 2) { free(mods); return 0; }
    g.n = n; g.mod = mods;
    g.pkg = calloc((size_t)n, sizeof(char *));
    g.adj = calloc((size_t)n * (size_t)n, 1);
    if(!g.pkg || !g.adj) { free(g.pkg); free(g.adj); free(mods); return 0; }
    for(int i = 0; i < n; i++) g.pkg[i] = module_pkg_go(mods[i]);

    /* types.go edges */
    for(int i = 0; i < n; i++) {
        char *imps[64];
        int ni = collect_module_imports(b, mods[i], imps, 64);
        for(int k = 0; k < ni; k++) {
            for(int j = 0; j < n; j++)
                if(j != i && strcmp(g.pkg[j], imps[k]) == 0)
                    g.adj[(size_t)i * n + j] = 1;
            free(imps[k]);
        }
    }
    /* glue.go edges (dry run; no files are written) */
    int retval = 0;
    if(go_glue_collect_imports(g_go_module_path, g_go_rt_module_path,
                               impgraph_glue_cb, &g) < 0) {
        fprintf(stderr, "asn1cgo: Go import-cycle check: glue dry run failed\n");
        retval = -1;
    }

    if(retval == 0) {
        struct tj t = {0};
        t.g = &g;
        t.idx = malloc((size_t)n * sizeof(int));
        t.low = malloc((size_t)n * sizeof(int));
        t.on = calloc((size_t)n, sizeof(int));
        t.stk = malloc((size_t)n * sizeof(int));
        t.scc = malloc((size_t)n * sizeof(int));
        int *path = malloc((size_t)n * sizeof(int));
        int *seen = malloc((size_t)n * sizeof(int));
        if(t.idx && t.low && t.on && t.stk && t.scc && path && seen) {
            for(int i = 0; i < n; i++) t.idx[i] = -1;
            for(int i = 0; i < n; i++) if(t.idx[i] < 0) tj_visit(&t, i);
            for(int c = 0; c < t.n_scc; c++) {
                int start = -1, size = 0;
                for(int i = 0; i < n; i++)
                    if(t.scc[i] == c) { if(start < 0) start = i; size++; }
                if(size < 2) continue;
                for(int i = 0; i < n; i++) seen[i] = 0;
                int len = imp_find_cycle(&g, t.scc, c, start, path, seen,
                                         start, 0);
                fprintf(stderr, "asn1cgo: Go package import cycle: ");
                for(int i = 0; i < len; i++)
                    fprintf(stderr, "%s -> ", g.pkg[path[i]]);
                fprintf(stderr, "%s\n", g.pkg[start]);
                retval = -1;
            }
        }
        free(t.idx); free(t.low); free(t.on); free(t.stk); free(t.scc);
        free(path); free(seen);
    }
    for(int i = 0; i < n; i++) free(g.pkg[i]);
    free(g.pkg); free(g.adj); free(mods);
    return retval;
}

/* ========================================================================= *
 * The by-value-cycle check over the EMITTED Go reference graph.
 *
 * Vertices: every package-scoped type row that declares a Go type (GK_TYPE,
 * GK_INLINE, GK_SPEC_KEY, GK_SPEC_VALUE — the kinds whose goName is a Go type
 * the emitter declares; GK_CHOICE_PR and GK_SPEC_PR are discriminants, not
 * type-declaring rows, and GK_HELPER/GK_PKG_DIR emit no struct).
 *
 * Edges: one edge owner -> target whenever an emitted declaration references a
 * named type. Reference sources (the same rows the emitter reads):
 *   - a struct-owner row's FIELD field_type rows (the struct's members; a
 *     field typed `*T` / `*pkg.T` is INDIRECT — the recursion-completion rule's breakers — and a plain
 *     `T` / `pkg.T` is BY VALUE),
 *   - a slice-owner row's slice_elem (`[]Elem`; ALWAYS indirect — the slice is
 *     the seq-of break),
 *   - a scalar/alias `type` row's leaf underlying (a named-alias chain: the
 *     row_set_leaf text; a reference underlying is BY VALUE. None of the 3
 *     pinned specs has a constructed named-alias cycle, but the edge keeps the
 *     graph honest under every-assignment-is-named).
 * The qualifier is stripped before the lookup (the target's module is
 * its declaring row's; a cross-qualified `pkg.T` resolves to the T row).
 *
 * Star/slice stripping: field_type/slice_elem text is pointer-starred /
 * slice-prefixed exactly as emitted; '*'/'[]' ahead of the base name mark the
 * edge indirect, everything else is by value. qualifier stripping is a plain
 * suffix split on the LAST '.', so the base never contains one.
 *
 * Vertex identity is (module, goName): two modules may declare the same Go
 * — a reference resolves against the OWNER row of the field, i.e.
 * the sf_owner's module first, falling back to any single global hit.
 *
 * A non-trivial SCC (or a self-loop) in which EVERY intra-SCC edge is by value
 * is a cycle with no finite Go representation (breakable only by OPTIONAL
 * *X, CHOICE/value-union alt *X, or a slice). Fail loud,
 * naming the cycle members (-> driver EX_SOFTWARE, exit 70). Indirect edges
 * inside the SCC are the legal break and make it pass.
 *
 * Returns 0 clean, -1 on a by-value cycle (bag->failed is set by the caller;
 * the diagnostic is printed here, naming every member of every bad cycle).
 * ========================================================================= */
/* by-value-cycle helpers: strip a field/slice reference text to (base, indirect) and
 * look a vertex up. Shared by the edge collection below so the FIELD, slice
 * and leaf edges cannot disagree on what counts as a named-type reference. */

/* strip_ref: parse one emitted reference text into its base type name +
 * indirectness. '*'/'[]...' ahead of a base name mark the edge indirect (the
 * legal breaks: a pointer or a slice). ONE trailing qualifier `pkg.T` is
 * stripped to `T` (the qualifier names the PACKAGE, not the type).
 * Returns NULL (and indirect=0) when the text names no vertex candidate: a
 * mapping-table primitive (int64/string/[]byte/...), the BitString helper, or
 * malformed text the other gates own. The result points INTO ref (no alloc). */
static const char *
strip_ref(const char *ref, int *indirect) {
    *indirect = 0;
    if(!ref) return NULL;
    const char *t = ref;
    while(*t == '*' || *t == '[') {
        if(*t == '[') {
            const char *cl = strchr(t, ']');
            if(!cl) return NULL;
            t = cl + 1;
        } else {
            t++;
        }
        *indirect = 1;
    }
    if(!*t || !(isalpha((unsigned char)*t) || *t == '_')) return NULL;
    const char *dot = strrchr(t, '.');
    const char *base = dot ? dot + 1 : t;
    return *base ? base : NULL;
}

/* vtx_lookup: resolve a base name to a vertex under (module, goName) keys.
 * Same-module rows win; a same-module miss falls
 * back to the FIRST cross-module hit. -1 when the name is not a vertex. */
static int
vtx_lookup(const char *const *vmod, char *const *vname, int n,
           const char *module, const char *base) {
    int fallback = -1;
    for(int j = 0; j < n; j++) {
        if(strcmp(vname[j], base) != 0) continue;
        if(vmod[j] == module) return j;
        if(fallback < 0) fallback = j;
    }
    return fallback;
}

typedef struct {
    int src, dst;    /* vertex indices                                  */
    int indirect;    /* 1 = pointer/slice edge (a legal break)     */
} goedge;

static int
check_go_cycles(struct name_bag *b) {
    if(b->n_rows <= 0) return 0;

    /* Vertex table: every type-declaring row, keyed (module, goName). The
     * same (module, goName) twice is a collision; keep the first here. */
    int n = 0, cap = 0;
    int *vrow = NULL;
    const char **vmod = NULL;
    char **vname = NULL;
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        if(r->kind != GK_TYPE && r->kind != GK_INLINE
           && r->kind != GK_SPEC_KEY && r->kind != GK_SPEC_VALUE)
            continue;
        if(!r->goName || !*r->goName || !r->module) continue;
        if(vtx_lookup(vmod, vname, n, r->module, r->goName) >= 0) continue;
        if(n == cap) {
            int nc = cap ? cap * 2 : 64;
            int *nr = xrealloc(vrow, (size_t)nc * sizeof(int));
            if(!nr) { free(vrow); free(vmod); free(vname); return 0; }
            vrow = nr;
            const char **nm = xrealloc(vmod, (size_t)nc * sizeof(char *));
            if(!nm) { free(vrow); free(vmod); free(vname); return 0; }
            vmod = nm;
            char **nn2 = xrealloc(vname, (size_t)nc * sizeof(char *));
            if(!nn2) { free(vrow); free(vmod); free(vname); return 0; }
            vname = nn2;
            cap = nc;
        }
        vrow[n] = i; vmod[n] = r->module; vname[n] = r->goName; n++;
    }
    if(n == 0) { free(vrow); free(vmod); free(vname); return 0; }

    /* Edge collection. One edge (src,dst,indirect) per distinct reference
     * (dedup on the triple: an indirect edge anywhere in an SCC is the legal
     * break, so a by-value and an indirect edge between the same pair are
     * DISTINCT facts, not duplicates of one another).
     *   FIELD rows: owner = the sf_owner struct's vertex (same module).
     *   slice-owner rows: the element reference (always indirect — the slice
     *   is a slice break).
     *   GK_TYPE leaf rows: a named-alias underlying (`type X Y` with Y a
     *   named type) is not retained per-row as text — the leaf edge source is
     *   intentionally omitted (no pinned spec has a constructed alias cycle;
     *   FIELD+slice edges cover every cycle the specs contain). */
    goedge *edg = NULL;
    int n_e = 0, cap_e = 0;
    int *owner_vtx = NULL;   /* per-row ephemeral: the field row's owner vertex */
    owner_vtx = calloc((size_t)b->n_rows, sizeof(int));
    if(!owner_vtx) { free(vrow); free(vmod); free(vname); return 0; }
    /* Pre-resolve each FIELD row's owner vertex once (sf_owner + module). */
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        owner_vtx[i] = -1;
        if(r->kind != GK_FIELD || !r->field_type || !*r->field_type) continue;
        if(!r->sf_owner || !*r->sf_owner) continue;
        owner_vtx[i] = vtx_lookup(vmod, vname, n, r->module, r->sf_owner);
    }
#define GOEDGE_PUSH(s, d, ind) do {                                     \
        int _dup = 0;                                                   \
        for(int _j = 0; _j < n_e; _j++)                                 \
            if(edg[_j].src == (s) && edg[_j].dst == (d)                 \
               && edg[_j].indirect == (ind)) { _dup = 1; break; }       \
        if(!_dup) {                                                     \
            if(n_e == cap_e) {                                          \
                int _nc = cap_e ? cap_e * 2 : 128;                      \
                goedge *_ne = xrealloc(edg, (size_t)_nc * sizeof(goedge)); \
                if(!_ne) { free(edg); edg = NULL; n_e = cap_e = 0; break; } \
                edg = _ne; cap_e = _nc;                                 \
            }                                                           \
            edg[n_e].src = (s); edg[n_e].dst = (d);                     \
            edg[n_e].indirect = (ind); n_e++;                           \
        }                                                               \
    } while(0)
    /* FIELD edges. */
    for(int i = 0; i < b->n_rows; i++) {
        if(owner_vtx[i] < 0) continue;
        int indirect = 0;
        const char *base = strip_ref(b->rows[i].field_type, &indirect);
        if(!base) continue;
        int dst = vtx_lookup(vmod, vname, n, b->rows[i].module, base);
        if(dst < 0) continue;
        GOEDGE_PUSH(owner_vtx[i], dst, indirect);
    }
    /* Slice-element edges (always indirect). */
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        if((r->kind != GK_TYPE && r->kind != GK_INLINE) || !r->slice_elem)
            continue;
        if(!*r->slice_elem) continue;
        int src = -1;
        for(int v = 0; v < n; v++)
            if(vmod[v] == r->module && strcmp(vname[v], r->goName) == 0) {
                src = v; break;
            }
        if(src < 0) continue;
        int indirect = 0;
        const char *base = strip_ref(r->slice_elem, &indirect);
        if(!base) continue;
        int dst = vtx_lookup(vmod, vname, n, r->module, base);
        if(dst < 0) continue;
        GOEDGE_PUSH(src, dst, 1 /* the slice itself is the break */);
    }
#undef GOEDGE_PUSH

    int retval = 0;
    if(n_e > 0) {
        /* Iterative Tarjan over the vertex graph (mirrors go_walk.c
         * tarjan_scc; adjacency scanned linearly per frame — edge counts are
         * small). */
        int *vidx = malloc((size_t)n * sizeof(int));
        int *vlow = malloc((size_t)n * sizeof(int));
        int *vscc = malloc((size_t)n * sizeof(int));
        int *von  = calloc((size_t)n, sizeof(int));
        int *stk  = malloc((size_t)n * sizeof(int));
        int *wrk  = malloc((size_t)n * sizeof(int));
        int *wcur = malloc((size_t)n * sizeof(int));
        if(vidx && vlow && vscc && von && stk && wrk && wcur) {
            for(int v = 0; v < n; v++) { vidx[v] = -1; vscc[v] = -1; }
            int sp = 0, wtop = 0, scc_count = 0, counter = 0;
            for(int root = 0; root < n; root++) {
                if(vidx[root] != -1) continue;
                wrk[wtop] = root; wcur[wtop] = 0; wtop++;
                while(wtop > 0) {
                    int v = wrk[wtop - 1];
                    if(vidx[v] == -1) {
                        vidx[v] = vlow[v] = counter++;
                        stk[sp++] = v; von[v] = 1;
                    }
                    int advanced = 0;
                    for(int j = wcur[wtop - 1]; j < n_e; j++) {
                        if(edg[j].src != v) continue;
                        wcur[wtop - 1] = j + 1;
                        int w = edg[j].dst;
                        if(vidx[w] == -1) {
                            wrk[wtop] = w; wcur[wtop] = 0; wtop++;
                        } else if(von[w]) {
                            if(vidx[w] < vlow[v]) vlow[v] = vidx[w];
                        }
                        advanced = 1;
                        break;
                    }
                    if(advanced) continue;
                    wtop--;
                    if(vlow[v] == vidx[v]) {
                        int w;
                        do {
                            w = stk[--sp];
                            von[w] = 0;
                            vscc[w] = scc_count;
                        } while(w != v);
                        scc_count++;
                    }
                    if(wtop > 0) {
                        int p = wrk[wtop - 1];
                        if(vlow[v] < vlow[p]) vlow[p] = vlow[v];
                    }
                }
            }
            /* Classification: an SCC passes iff it has NO intra-SCC
             * edge at all (a trivial singleton with no self-loop) or at least
             * one INDIRECT intra-SCC edge (the legal break). BAD = has intra-
             * SCC edges and every one of them is by value. */
            int *scc_size   = calloc((size_t)scc_count, sizeof(int));
            int *scc_edges  = calloc((size_t)scc_count, sizeof(int));
            int *scc_ind    = calloc((size_t)scc_count, sizeof(int));
            if(scc_size && scc_edges && scc_ind) {
                for(int v = 0; v < n; v++)
                    if(vscc[v] >= 0) scc_size[vscc[v]]++;
                for(int j = 0; j < n_e; j++) {
                    if(vscc[edg[j].src] < 0) continue;
                    if(vscc[edg[j].src] != vscc[edg[j].dst]) continue;
                    scc_edges[vscc[edg[j].src]]++;
                    if(edg[j].indirect) scc_ind[vscc[edg[j].src]] = 1;
                }
                for(int s = 0; s < scc_count; s++) {
                    if(scc_size[s] < 2 && scc_edges[s] == 0) continue;
                    if(scc_edges[s] > 0 && !scc_ind[s]) {
                        fprintf(stderr, "asn1cgo: type cycle with no indirect "
                                "(pointer or slice) edge — every edge is by "
                                "value (no OPTIONAL *X, CHOICE alt *X, or "
                                "SEQUENCE OF slice):");
                        for(int v = 0; v < n; v++) {
                            if(vscc[v] != s) continue;
                            fprintf(stderr, " %s.%s",
                                    vmod[v] ? vmod[v] : "?", vname[v]);
                        }
                        fprintf(stderr, "\n");
                        retval = -1;
                    }
                }
            }
            free(scc_size); free(scc_edges); free(scc_ind);
        }
        free(vidx); free(vlow); free(vscc); free(von); free(stk);
        free(wrk); free(wcur);
    }
    free(edg);
    free(owner_vtx);
    free(vrow); free(vmod); free(vname);
    return retval;
}
/* slice_element_type (slice stage): the ELEMENT type text of a named slice alias
 * `type X []Elem`, for every one of the three slice-owner shapes — a
 * SEQUENCE-OF type assignment (`type` row), an anonymous inline SEQ-OF at a
 * member (`inline` row), and a param-container specialization use (`inline`
 * row). The three shapes share ONE resolver so the element rule cannot drift
 * between them:
 *   a REFERENCE element — the referenced assignment's own goName
 *     (R2(MKID(chased terminal)); stored UNQUALIFIED, the post-walk prepass
 *     qualify_slice_elems applies cross-module qualification). A
 *     field-shaped specialization element (a container's ProtocolIE-Field
 *     {{X}} payload) resolves to the SAME R2(X) name: X IS the
 *     chased terminal's own Identifier by the time the chase lands on the
 *     field-shaped clone, and go_r2(MKID(terminal)) is R2(X) — exactly the
 *     spec-key name emit_spec mints in X's module.
 *   an inline LEAF element — the mapping-table Go text via classify_leaf, the SAME
 *     table the decl emission uses (go_types_leaf_underlying; one table, no
 *     drift).
 *   an inline CONSTRUCTED element (SEQ/CHOICE/ENUM/SEQ-OF literal body at the
 *     element position) never reaches this function: mint_inline_seqof_elem
 *     (below) names it <Owner>Member first and hands back the element text.
 * Returns an owned string, or NULL after setting bag->failed (fail loud). */
static char *
slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                   const char *path_for_diag);

/* Is the element of a SEQUENCE OF an inline (anonymous) type rather than a
 * reference to a named one? */
static int
seqof_elem_is_inline(asn1p_expr_t *elem) {
    return elem && !(elem->expr_type == A1TC_REFERENCE
                     || elem->meta_type == AMT_TYPEREF);
}

/* mint_inline_seqof_elem: the element of a SEQUENCE OF that is an inline
 * (anonymous) type — `SEQUENCE OF INTEGER (0..3)`, `SEQUENCE OF SEQUENCE
 * {..}`, ... — mirrors the C backend, which synthesizes the element "Member":
 * the C element cid is <OwnerCid>__Member and the Go name <OwnerGo>Member
 * (the member / alt inline rule, so under a member `a` of T it is T__a__Member
 * / TAMember; elements nest: T__Member__Member / TMemberMember).
 *
 * The element is minted as an ordinary package-scoped Flat node of that cid
 * (flagged inline_elem: the C tree has no `_t` typedef / asn_DEF for it):
 *   a plain leaf  (INTEGER BOOLEAN REAL NULL OCTET/BIT/PrintableString,
 *                  named-bit BIT STRING) — a hidden leaf node, NO Go type row:
 *                  the Go element is the unnamed leaf mapping ([]int64 ...),
 *                  from the same table classify_leaf/go_types use;
 *   ENUMERATED    — `type <Owner>Member int32` + value consts (emit_enum);
 *   SEQUENCE / CHOICE — a struct / CHOICE type <Owner>Member with its own
 *                  members, exactly as the member / alt inline rule;
 *   SEQUENCE OF   — the named slice `type <Owner>Member []Elem`, recursing.
 * A named-bit BIT STRING element is the plain BitString plus bit constants
 * <Owner>Member<Bit> (emit_bit_names; the member / alt precedent).
 * On success: *go_elem = the Go element type text, *flat_cid = the Flat
 * element cid (both owned). Returns -1 (bag->failed) on failure. The Flat
 * cur register is restored. */
static int
mint_inline_seqof_elem(struct walk_ctx *ctx, asn1p_expr_t *elem,
                       const char *owner_path, const char *owner_go,
                       const char *owner_cid, char **go_elem,
                       char **flat_cid) {
    char *inline_go = str_append(strdup(""), owner_go ? owner_go : "");
    inline_go = str_append(inline_go, "Member");
    char *inline_cid = go_cid_compound(owner_cid ? owner_cid : "", "__",
                                       "Member");
    char *path = make_path(owner_path, "Member");
    int save_fcur = go_flat_cur_get();
    int rc = 0;
    *go_elem = NULL;
    *flat_cid = NULL;
    for(int j = 0; j < ctx->bag->n_minted; j++) {
        struct minted_elem *me = &ctx->bag->minted[j];
        if(me->module == ctx->module && strcmp(me->cid, inline_cid) == 0) {
            *go_elem = strdup(me->go_elem);
            *flat_cid = strdup(inline_cid);
            free(inline_go); free(inline_cid); free(path);
            return 0;
        }
    }

    switch(elem->expr_type) {
    case ASN_CONSTR_SEQUENCE: {
        emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        go_flat_struct(inline_cid, ctx->module);
        go_flat_mark_inline_elem(NULL, NULL);
        const char *save_go = ctx->parent_go;
        const char *save_cid = ctx->parent_cid;
        char *save_sf = NULL;
        if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
        ctx->parent_go = inline_go;
        ctx->parent_cid = inline_cid;
        reset_field_scope(ctx->bag);
        row_set_is_struct(ctx->bag);
        struct_scope_open(ctx->bag, inline_go);
        rc = walk_names_members(ctx, elem, path);
        struct_scope_reset(ctx->bag);
        free(bag_sf_restore(ctx->bag, save_sf));
        ctx->parent_go = save_go;
        ctx->parent_cid = save_cid;
        *go_elem = strdup(inline_go);
        break;
    }
    case ASN_CONSTR_CHOICE: {
        emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        char *save_sf = NULL;
        if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
        emit_choice(ctx, inline_go, inline_cid, path, elem);
        free(bag_sf_restore(ctx->bag, save_sf));
        {   /* emit_choice minted the CHOICE node and left it cur */
            go_flat_mark_inline_elem(NULL, NULL);
        }
        *go_elem = strdup(inline_go);
        break;
    }
    case ASN_CONSTR_SEQUENCE_OF: {
        emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        int row_ix = ctx->bag->n_rows - 1;
        asn1p_expr_t *inner = TQ_FIRST(&elem->members);
        char *ig = NULL, *ic = NULL;
        if(!inner) { ctx->bag->failed = 1; rc = -1; break; }
        if(seqof_elem_is_inline(inner)) {
            rc = mint_inline_seqof_elem(ctx, inner, path, inline_go,
                                        inline_cid, &ig, &ic);
        } else {
            ig = slice_element_type(ctx, inner, path);
            if(ctx->bag->failed) { rc = -1; break; }
            asn1p_expr_t *et = inner;
            asn1p_expr_t *t2 = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns,
                                                           inner);
            if(t2) et = t2;
            ic = own(GO_MKID(et));
            if(go_construct_classify(et) == GO_CONSTR_BIT_STRING)
                mark_bitstring_module(ctx->bag, ctx->module);
        }
        if(rc < 0 || ctx->bag->failed) { free(ig); free(ic); rc = -1; break; }
        row_set_slice_elem_at(ctx->bag, row_ix, ig);
        (void)go_flat_seqof(inline_cid, ic, 0, ctx->module);
        go_flat_mark_inline_elem(NULL, NULL);
        free(ig); free(ic);
        *go_elem = strdup(inline_go);
        break;
    }
    default: {
        /* a plain leaf (or ENUMERATED / named-bit BIT STRING) */
        int is_enum = elem->expr_type == ASN_BASIC_ENUMERATED;
        int named_bits = elem->expr_type == ASN_BASIC_BIT_STRING
                         && TQ_FIRST(&elem->members);
        ctx->wide_cid = inline_cid;
        ctx->wide_hit = 0;
        int lk = classify_leaf(ctx, elem, path);
        int wide = ctx->wide_hit;
        ctx->wide_cid = NULL;
        ctx->wide_hit = 0;
        if(ctx->bag->failed) { rc = -1; break; }
        if(lk == GLEAF_BITSTRING) mark_bitstring_module(ctx->bag, ctx->module);
        const char *under = go_types_leaf_underlying(lk);
        const char *ctype = NULL;
        switch(lk) {
        case GLEAF_INT64:  ctype = wide ? "INTEGER_t" : "long"; break;
        case GLEAF_UINT64: ctype = wide ? "INTEGER_t" : "unsigned long"; break;
        case GLEAF_BOOL:   ctype = "BOOLEAN_t"; break;
        case GLEAF_NULL:   ctype = "NULL_t"; break;
        case GLEAF_REAL:   ctype = "double"; break;
        case GLEAF_OCTETS: ctype = "OCTET_STRING_t"; break;
        case GLEAF_STRING: ctype = "PrintableString_t"; break;
        case GLEAF_BITSTRING: ctype = "BIT_STRING_t"; break;
        case GLEAF_ENUM:   ctype = "long"; break;
        default: break;
        }
        if(!ctype || !under) {
            fprintf(stderr,
                    "asn1cgo: SEQUENCE OF element of unsupported kind in "
                    "module %s: %s\n",
                    ctx->module ? ctx->module : "?", path);
            ctx->bag->failed = 1; rc = -1; break;
        }
        if(is_enum) {
            emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                      strdup(inline_cid), strdup(inline_go));
            row_set_leaf(ctx->bag, lk);
            (void)go_flat_leaf_gleaf(inline_cid, lk, ctx->module);
            go_flat_mark_inline_elem(ctype, NULL);
            emit_enum(ctx, inline_go, inline_cid, path, elem);
            *go_elem = strdup(inline_go);
            break;
        }
        /* Reserve <Owner>Member as a name (no declaration: the row carries no
         * leaf kind, struct or slice body): the glue helpers are named after
         * it, so another type of that name must collide. */
        emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        if(lk == GLEAF_NULL)
            (void)go_flat_leaf(inline_cid, "int32_t", ctx->module);
        else
            (void)go_flat_leaf_gleaf(inline_cid, lk, ctx->module);
        go_flat_mark_inline_elem(ctype, under);
        if(named_bits) emit_bit_names(ctx, inline_go, inline_cid, path, elem);
        *go_elem = strdup(under);
        break;
    }
    }
    go_flat_cur_restore(save_fcur);
    if(rc == 0 && ctx->bag->failed) rc = -1;
    if(rc == 0) *flat_cid = strdup(inline_cid);
    if(rc == 0) {
        struct name_bag *b = ctx->bag;
        if(b->n_minted + 1 > b->cap_minted) {
            int nc = b->cap_minted ? b->cap_minted * 2 : 16;
            struct minted_elem *nm = realloc(b->minted, (size_t)nc * sizeof *nm);
            if(!nm) { b->failed = 1; rc = -1; }
            else { b->minted = nm; b->cap_minted = nc; }
        }
        if(rc == 0) {
            b->minted[b->n_minted].module = ctx->module;
            b->minted[b->n_minted].cid = strdup(inline_cid);
            b->minted[b->n_minted].go_elem = strdup(*go_elem);
            b->n_minted++;
        }
    }
    if(rc < 0) { free(*go_elem); *go_elem = NULL; free(*flat_cid); *flat_cid = NULL; }
    free(inline_go); free(inline_cid); free(path);
    return rc;
}

static char *
slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                   const char *path_for_diag) {
    if(!elem) return own("");
    /* Inline plain leaf: the mapping-table Go text (the same table). */
    if(!(elem->expr_type == A1TC_REFERENCE || elem->meta_type == AMT_TYPEREF)) {
        int lk = classify_leaf(ctx, elem, path_for_diag);
        if(ctx->bag->failed) return NULL;
        const char *under = go_types_leaf_underlying(lk);
        return own(under ? under : "");
    }
    /* Reference element: the chased terminal assignment's own goName;
     * a field-shaped spec terminal IS named R2(X) — see the block comment). */
    asn1p_expr_t *terminal = elem;
    {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, elem);
        if(t) terminal = t;
    }
    return go_r2(GO_MKID(terminal));
}

/* go_quote: a Go interpreted string literal for arbitrary bytes. */
static char *
go_quote(const unsigned char *b, size_t n) {
    char *o = strdup("\"");
    for(size_t i = 0; i < n; i++) {
        char t[8];
        if(b[i] == '"' || b[i] == '\\') snprintf(t, sizeof t, "\\%c", b[i]);
        else if(b[i] >= 0x20 && b[i] < 0x7f) snprintf(t, sizeof t, "%c", b[i]);
        else snprintf(t, sizeof t, "\\x%02x", b[i]);
        o = str_append(o, t);
    }
    return str_append(o, "\"");
}

/* note_default_value: record the exported Go declaration of one supported
 * DEFAULT member's value (a GK_DEFAULT_VALUE row, package-scoped so a clash
 * with any other name fails the run like every other collision). The
 * member's Go type is the field row's own (read at emit time). The row is
 * named <OwnerStruct><Field>Default. */
static void
note_default_value(struct walk_ctx *ctx, asn1p_expr_t *child,
                   const char *member_path, int field_row_ix) {
    asn1p_value_t *dv = child->marker.default_value;
    asn1p_expr_t *term = child;
    int form = 1;
    char *lit = NULL;
    if(!dv) return;
    if(child->expr_type == A1TC_REFERENCE || child->meta_type == AMT_TYPEREF) {
        term = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child);
        if(!term) term = child;
    }
    switch(term->expr_type) {
    case ASN_BASIC_BOOLEAN:
        lit = strdup(dv->type == ATV_TRUE ? "true"
                     : dv->type == ATV_FALSE ? "false"
                     : dv->value.v_integer ? "true" : "false");
        break;
    case ASN_BASIC_INTEGER:
    case ASN_BASIC_ENUMERATED:
        lit = strdup(asn1p_itoa(dv->value.v_integer));
        break;
    case ASN_BASIC_OCTET_STRING:
    case ASN_BASIC_BIT_STRING: {
        int bits = dv->value.binary_vector.size_in_bits;
        int nb = (bits + 7) / 8, is_bit = term->expr_type == ASN_BASIC_BIT_STRING;
        int unused = (8 - bits % 8) % 8;
        char t[64];
        form = 2;
        lit = strdup(is_bit ? "Bytes: []byte{" : "");
        for(int i = 0; i < nb; i++) {
            unsigned v = dv->value.binary_vector.bits[i];
            if(is_bit && i == nb - 1) v &= (0xffu << unused) & 0xffu;
            snprintf(t, sizeof t, "%s0x%02x", i ? ", " : "", v);
            lit = str_append(lit, t);
        }
        if(is_bit) {
            snprintf(t, sizeof t, "}, BitsUnused: %d", unused);
            lit = str_append(lit, t);
        }
        break;
    }
    default:
        if(term->expr_type & ASN_STRING_KM_MASK) {
            lit = go_quote(dv->value.string.buf, (size_t)dv->value.string.size);
            break;
        }
        return;
    }
    if(!lit) { ctx->bag->failed = 1; return; }
    const char *owner = ctx->bag->rows[field_row_ix].sf_owner;
    const char *fgo = ctx->bag->rows[field_row_ix].goName;
    if(!owner) { free(lit); return; }
    char *name = str_append(str_append(strdup(owner), fgo), "Default");
    char *raw = str_append(str_append(strdup(owner), "_"),
                           child->Identifier ? child->Identifier : "?");
    char *mpath = make_path(member_path, child->Identifier);
    char *path = make_path(mpath, "DEFAULT");
    free(mpath);
    emit_name(ctx->bag, ctx->module, path, GK_DEFAULT_VALUE, raw, name);
    struct name_row *r = &ctx->bag->rows[ctx->bag->n_rows - 1];
    r->dflt_form = form;
    r->dflt_lit = lit;
    r->dflt_owner = strdup(owner);
    r->dflt_field = strdup(fgo);
}

/* Walk one child member of a struct at path `parent_path` (dotted path that
 * already includes this member's name) under enclosing goName `parent_go` and
 * real C-ident prefix `parent_cid` (the latter from ctx->parent_cid at the call
 * site). */
static int
walk_names_child_inner(struct walk_ctx *ctx, asn1p_expr_t *child,
                       const char *parent_path, const char *parent_go,
                       const char *parent_cid) {
    /* Defense-in-depth: the canonical ext-marker skip is in
     * walk_names_members (the SEQUENCE loop), but reject an A1TC_EXTENSIBLE
     * child here too so a future direct caller can't leak a blank-goName row. */
    if(child->expr_type == A1TC_EXTENSIBLE) return 0;
    const char *cid = child->Identifier ? child->Identifier : "?";
    /* Pointer-star FIRST: member_stars also rejects DEFAULT — before
     * any row is emitted, so a failed run writes nothing for the member. */
    ctx->last_opt_extra = 0;
    const char *stars = member_stars(ctx, child, parent_path);
    if(ctx->bag->failed) return -1;
    /* Field row (struct-scoped). rawCid = GO_MKID(child). The census
     * out-param rides along: non-zero iff OPTIONAL carried
     * marker bits beyond EM_OPTIONAL. The row INDEX is retained: the SEQ-OF
     * mint below emits its own inline row AFTER this one, and the field's
     * field_type must land on THIS row (row_set_field_type writes n_rows-1,
     * which by then is the inline row — the param-container bug that left
     * RICsubscriptionRequest's emitted body empty). */
    int field_row_ix;
    {
        char *path = make_path(parent_path, cid);
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  go_mk_member(child), go_r2(GO_MKID(child)));
        field_row_ix = ctx->bag->n_rows - 1;
        ctx->bag->rows[field_row_ix].opt_extra_bits = ctx->last_opt_extra;
    }
    /* A supported DEFAULT member is a plain Go value; its Flat slot is by
     * value too (the C tree slot is a pointer iff the C pass left
     * EM_INDIRECT set: tree_ptr, handled by the conv arms). */
    const int is_dflt = member_is_default(child);
    const int tree_ptr = is_dflt && (child->marker.flags & EM_INDIRECT);

    /* Recurse into the child's OWN inline children only (mirrors go_walk.c
     * walk_child:420-425 plus inline ENUMERATED — see below). A reference child
     * has none. An anonymous inline SEQUENCE/CHOICE/ENUMERATED at a member mints
     * a named Go type <Parent><Member> (the anonymous-inline naming rule)
     * that then parents its own
     * members/enumerators. */
    if(child->expr_type == ASN_CONSTR_SEQUENCE
       || child->expr_type == ASN_CONSTR_CHOICE
       || child->expr_type == ASN_CONSTR_SEQUENCE_OF
       || child->expr_type == ASN_BASIC_ENUMERATED) {

        /* inline record goName = <Parent><Member> (the anonymous-inline
         * naming rule). The real C-ident
         * compounds as asn1c does: <parent_cid> + "__" + <child cid> (the nested
         * tag form <StructCid>__<memberCid>, underscore-preserving on both
         * sides). goName collapses underscores; cid keeps them. */
        char *child_field_go = go_r2(GO_MKID(child));
        /* struct-body stage: the field's Go type is the inline name (the field is typed by
         * the minted named type <Parent><Member>), pointer-starred by the
         * marker rule (member_stars, computed above). Same-module by
         * construction (the name is minted in the parent's own module). Set
         * before the recursion may emit more rows. */
        {
            char *ft = str_append(strdup(""), stars);
            ft = str_append(ft, parent_go);
            ft = str_append(ft, child_field_go);
            row_set_field_type(ctx->bag, ft);
            free(ft);
        }
        char *child_cid = own_mkid(child);
        char *inline_go = str_append(strdup(""), parent_go);
        inline_go = str_append(inline_go, child_field_go);
        free(child_field_go);
        /* an inline tag is an aggregate name — prefix once, parts
         * unprefixed (go_cid_compound strips each part's prefix and puts the
         * run prefix back once at the front; asn1c's nested tag form). */
        char *inline_cid = go_cid_compound(parent_cid ? parent_cid : "", "__",
                                           child_cid);
        free(child_cid);
        char *inline_path = strdup(parent_path);   /* <Parent>.<this member> */

        /* inline row: a named Go type for the anonymous construct. rawCid = the
         * real compounded nested C-ident (e.g. Interface_MessageID__messageType),
         * NOT the _-collapsed Go name. */
        {
            char *raw = strdup(inline_cid);
            char *go = strdup(inline_go);
            char *path = strdup(inline_path);
            emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
            /* leaf-stage body data: an inline LEAF construct's declaration is the
             * same named-type form as a top-level leaf (the anonymous-inline
             * naming rule: the
             * anonymous inline SEQUENCE/CHOICE/ENUMERATED/SEQ-OF at a member
             * is a named Go type <Parent><Member>; an inline ENUMERATED is
             * `type X int32` + consts — the plain-sequence frozen unit's
             * RICIntegratedReportStyleItemRicMultipleIndividualReportingSupport).
             * SEQUENCE/CHOICE/SEQ-OF inline rows carry GLEAF_NONE (bodies are
             * struct-body); a SEQ-OF of a plain leaf is a slice-stage alias. */
            if(child->expr_type == ASN_BASIC_ENUMERATED) {
                row_set_leaf(ctx->bag, GLEAF_ENUM);
                /* Flat: NO leaf typedef mint — an inline ENUM member
                 * is the bare int32 slot only (the frozen units author no
                 * <P>__<m>_flat leaf; the .h's e_<P>__<m> enum tag is not a
                 * scalar alias the mapping table's Flat column maps). Caught red by
                 * flatemit-check (flat-name) before this fix. */
            }
        }

        if(go_construct_classify(child) == GO_CONSTR_BIT_STRING)
            mark_bitstring_module(ctx->bag, ctx->module);

        /* Flat: an inline construct member nests an ANONYMOUS struct in
         * the enclosing Flat exactly as the .h nests `struct <P>__<m> {...}` —
         * mint the nested node, attach it under the member token, then re-target
         * the member-population calls at it for the whole recursion below (the
         * ENUM/CHOICE/SEQ-OF bodies below mint on the node via cur re-binding:
         * go_flat_struct[_nested] sets cur to the new node; on entry here the
         * enclosing struct is cur, so the nested mint + member attach happen on
         * it, and the nested mint re-binds cur to the node for its members). */
        int flat_nest_ix = -2;   /* -2: enum (bare int32 slot below) */
        if(child->expr_type == ASN_BASIC_ENUMERATED) {
            /* an inline ENUM member is a bare int32 slot (the .h typedef enum
             * collapses to long; the ENUMERATED mapping row); no nested node. */
            {
                char *m = go_mk_member(child);
                go_flat_member_prim("int32_t", m, stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                if(is_dflt) go_flat_last_member_default(tree_ptr);
                free(m);
            }
        } else if(child->expr_type == ASN_CONSTR_SEQUENCE_OF) {
            /* the SEQ OF tail attaches the ONE member row itself (a nested
             * {items,count} behind the member star) — no pre-mint attach here
             * (a second attach duplicated the member token). */
            flat_nest_ix = -3;
        } else if(stars && *stars == '*') {
            /* OPTIONAL inline SEQUENCE / CHOICE: the tree slot is a pointer
             * to `struct <cid>` (a tag only, no typedef), the same shape as
             * a CHOICE alt. A pointer slot to an anonymous nested struct has
             * no layout of its own to address, so — exactly as for an alt —
             * the construct is a package-scoped Flat node and the member a
             * starred ref to it (minted below; the conv file aliases
             * `<cid>_t` to the struct tag). A by-value slot stays nested. */
            flat_nest_ix = -4;
            {
                char *m = go_mk_member(child);
                go_flat_member_ref(inline_cid, m, 1);
                go_flat_label_last_member(child->Identifier);
                free(m);
            }
        } else {
            flat_nest_ix = go_flat_struct_nested(inline_cid, ctx->module);
            {
                char *m = go_mk_member(child);
                go_flat_member_nested(flat_nest_ix, m, stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                free(m);
            }
            /* re-bind cur to the nested node: every member the recursion below
             * emits for this construct lands on it. CHOICE mints its own node
             * again below — flat_new_type dedups by (cid, module), so the
             * pre-mint node IS the one the recursion populates. */
        }

        /* inline ENUMERATED: its enumerators become enum-const rows under the
         * inline name (the real .h: `typedef enum <P>__<member> { <P>__<member>_
         * <enumerator> }`). asn1c compounds the parent cIdent into both the enum
         * and every enumerator cIdent, so R2 of the compounded enumerator is the
         * full `<P><Member><Enumerator>` const the frozen units declare. Go_walk does
         * NOT descend here (it classifies the member terminal without recursing),
         * but ENUMERATED IS a supported terminal — naming it stays within the
         * supported-construct set. The real cid prefix (inline_cid) reproduces
         * the verbatim enumerator tokens <P>__<member>_<enumerator>. */
        if(child->expr_type == ASN_BASIC_ENUMERATED) {
            emit_enum(ctx, inline_go, inline_cid, inline_path, child);
            free(inline_go); free(inline_cid); free(inline_path);
            return 0;
        }

        if(child->expr_type == ASN_CONSTR_CHOICE) {
            /* emit_choice toggles the struct-owner scope (open under the
             * inline CHOICE, reset at its end); a member AFTER the inline
             * CHOICE belongs to the OUTER struct again (e.g. RRC-MessageID's
             * messageID after rrcType), so SAVE/RESTORE the outer scope
             * around the call — struct_scope_reset leaves none open, and the
             * outer struct's remaining members would else attach to no owner
             * (and emit nothing). The FLAT cur
             * register needs the same save/restore: emit_choice rebinds it to
             * the inline CHOICE's node (dedup finds the pre-minted node). */
            char *save_sf = NULL;
            if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
            int save_fcur = go_flat_cur_get();
            emit_choice(ctx, inline_go, inline_cid, inline_path, child);
            if(flat_nest_ix == -4) go_flat_mark_inline_elem("struct", NULL);
            go_flat_cur_restore(save_fcur);
            free(bag_sf_restore(ctx->bag, save_sf));
            free(inline_go); free(inline_cid); free(inline_path);
            return 0;
        }
        if(child->expr_type == ASN_CONSTR_SEQUENCE) {
            const char *save_go = ctx->parent_go;
            const char *save_cid = ctx->parent_cid;
            char *save_sf = NULL;
            if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
            ctx->parent_go = inline_go;
            ctx->parent_cid = inline_cid;
            reset_field_scope(ctx->bag);
            /* struct-body stage: the inline SEQUENCE declares a Go struct; its member
             * fields (the rows walk_names_members emits next) attach to it.
             * FLAT cur save/restore as for the CHOICE branch above. */
            row_set_is_struct(ctx->bag);
            struct_scope_open(ctx->bag, inline_go);
            int save_fcur = go_flat_cur_get();
            /* bind cur to the construct's own node (the nested node minted
             * above, or the package-scoped one of a pointer slot): the
             * SEQUENCE branch has no emit_choice-style re-mint to do it, so
             * without this the inline SEQUENCE's members landed on the
             * ENCLOSING struct. */
            if(flat_nest_ix == -4) {
                go_flat_struct(inline_cid, ctx->module);
                go_flat_label_cur(child->Identifier);   /* td->name label */
                go_flat_mark_inline_elem("struct", NULL);
            } else {
                go_flat_cur_restore(flat_nest_ix);
            }
            int rc = walk_names_members(ctx, child, inline_path);
            go_flat_cur_restore(save_fcur);
            struct_scope_reset(ctx->bag);
            free(bag_sf_restore(ctx->bag, save_sf));
            ctx->parent_go = save_go;
            ctx->parent_cid = save_cid;
            free(inline_go); free(inline_cid); free(inline_path);
            return rc;
        }
        /* ASN_CONSTR_SEQUENCE_OF (slice stage): the anonymous inline SEQ-OF
         * at a member mints the named slice alias `type <Parent><Member>
         * []Elem` — the inline ROW was already emitted above (the same
         * walk SEQUENCE/CHOICE/ENUM take); attach the ELEMENT type
         * to it now. No row is appended between the inline emit and here, so
         * the n_rows-1 form targets the inline row. Element rule: ONE
         * resolver for all three slice shapes (slice_element_type) — a
         * reference element is the assignment's own goName, a leaf
         * element is the mapping-table column, an inline element is minted
         * as <Parent><Member>Member by mint_inline_seqof_elem. The
         * member's own field row was typed by the minted name in the block
         * above (stars + parent_go + child name) — never a bare []Elem.
         * A BIT STRING
         * element marks this module for the helper (same membership as a
         * plain member; the element resolve itself keeps one path). */
        char *inl_flat_cid = NULL;   /* the minted Flat element cid */
        {
            asn1p_expr_t *elem = TQ_FIRST(&child->members);
            if(elem && elem->expr_type == ASN_BASIC_BIT_STRING)
                mark_bitstring_module(ctx->bag, ctx->module);
            char *selem;
            if(seqof_elem_is_inline(elem)) {
                int inl_row = ctx->bag->n_rows - 1;
                if(mint_inline_seqof_elem(ctx, elem, inline_path, inline_go,
                                          inline_cid, &selem,
                                          &inl_flat_cid) < 0) {
                    free(selem);
                    free(inline_go); free(inline_cid); free(inline_path);
                    return -1;
                }
                row_set_slice_elem_at(ctx->bag, inl_row, selem);
            } else {
                selem = slice_element_type(ctx, elem, inline_path);
                if(ctx->bag->failed) {
                    free(selem);
                    free(inline_go); free(inline_cid); free(inline_path);
                    return -1;
                }
                row_set_slice_elem(ctx->bag, selem);
            }
            free(selem);
        }
        /* Flat: the inline SEQ OF member rides the nested node minted above
         * (flat_nest_ix): A2 {items,count} nested, behind the member
         * star when OPTIONAL. go_flat_member_seqof re-mints the {items,count}
         * shape into that node (the node's FLT_STRUCT rep is replaced at
         * layout by the seqof shape: nested seqof nodes lay out 16/8). */
        {
            asn1p_expr_t *selem_expr = TQ_FIRST(&child->members);
            asn1p_expr_t *se_ = selem_expr;
            if(selem_expr
               && (selem_expr->expr_type == A1TC_REFERENCE
                   || selem_expr->meta_type == AMT_TYPEREF)) {
                asn1p_expr_t *st = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, selem_expr);
                if(st) se_ = st;
            }
            if(flat_nest_ix == -3) {
                char *flat_selem = inl_flat_cid ? strdup(inl_flat_cid)
                                   : se_ ? own(GO_MKID(se_)) : strdup("");
                char *flat_mtok = go_mk_member(child);
                go_flat_member_seqof(flat_selem, 0, flat_mtok,
                                     stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                free(flat_selem); free(flat_mtok);
            }
        }
        free(inl_flat_cid);
        free(inline_go); free(inline_cid); free(inline_path);
        return 0;
    }

    /* Plain (reference) member: chase the terminal to detect BIT STRING
     * (helper) and a container specialization (a ProtocolIE-Container /
     * SingleContainer / ContainerList {{X}} reference — the asn1c C type is a
     * `ProtocolIE_Container_<N>P<slot>_t`), exactly as go_walk.c walk_child:330-
     * 346 chases the terminal. A container specialization at a member is the
     * named slice: it mints a Go type <Parent><Member> (the comparison unit's
     * `<Msg>ProtocolIEs`), emitted as an `inline` row. */
    asn1p_expr_t *terminal = child;
    if(child->expr_type == A1TC_REFERENCE
       || child->meta_type == AMT_TYPEREF) {
        terminal = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child);
        if(!terminal) terminal = child;
    }
    go_construct_e tk = go_construct_classify(terminal);
    if(tk == GO_CONSTR_BIT_STRING)
        mark_bitstring_module(ctx->bag, ctx->module);
    if(tk == GO_CONSTR_SEQUENCE_OF) {
        /* Only a param-container specialization (a SEQUENCE OF whose element is
         * itself a field-shaped specialization — a `ProtocolIE-Field {{...}}`,
         * the asn1c `ProtocolIE_Container_<N>P<slot>_t`) mints the
         * named slice <Parent><Member> (the comparison unit's `<Msg>ProtocolIEs`). A
         * plain reference to a NAMED top-level SEQUENCE-OF does not (that type
         * already has its own `type` row, walked as a top-level assignment);
         * the chase landing on a hand-authored assignment is detected by
         * lhs_params==NULL && spec_index==-1 (a clone carries spec_index>=0 —
         * the same marker walk_names_expr gates the template walk on). Caught
         * by the full-tree -cmp: RICsubscriptionDetails.ricAction-ToBe-Setup-
         * List (a reference to the named RICactions-ToBe-Setup-List := SEQUENCE
         * OF ProtocolIE-SingleContainer {{...}}) minted
         * RICsubscriptionDetailsRicActionToBeSetupList where the named-type rule names the
         * field by the assignment's own RICactionsToBeSetupList. */
        asn1p_expr_t *elem = TQ_FIRST(&terminal->members);
        int named_top_level_seqof =
            terminal != child
            && !(terminal->lhs_params || terminal->spec_index >= 0);
        if(elem && !named_top_level_seqof
           && (go_construct_is_open_type(elem)
               || (elem->meta_type == AMT_TYPEREF
                   && elem->expr_type == A1TC_REFERENCE
                   && field_shaped_element(ctx, elem)))) {
            char *member_go = go_r2(GO_MKID(child));
            char *inline_go = str_append(strdup(""), parent_go);
            inline_go = str_append(inline_go, member_go);
            free(member_go);
            char *raw = strdup(inline_go);
            char *go = strdup(inline_go);
            char *path = strdup(parent_path);
            emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
            /* slice stage (container element resolution): the container slice's ELEMENT is
             * R2(X) — the field-shaped payload the container holds — which
             * slice_element_type resolves to exactly (the chased terminal
             * IS the field-shaped clone named R2(X); same one-resolver rule
             * as every slice shape). Attached to the inline row just
             * emitted (no row between it and here). */
            {
                char *selem = slice_element_type(ctx, elem, parent_path);
                if(ctx->bag->failed) {
                    free(selem);
                    free(inline_go);
                    return -1;
                }
                row_set_slice_elem(ctx->bag, selem);
                free(selem);
            }
            /* struct-body stage: the field is typed by the minted named slice
             * (<Parent><Member>), same-module. NOT the assignment's own name
             * (the container clone never surfaces in Go). BY INDEX: the inline
             * row was just emitted ABOVE this point, so the n_rows-1 form
             * would type the inline row and leave the FIELD row untyped. */
            {
                char *ft = str_append(strdup(""), stars);
                ft = str_append(ft, inline_go);
                row_set_field_type_at(ctx->bag, field_row_ix, ft);
                free(ft);
            }
            /* Flat (A2 collapse): the container CLONE is a
             * struct Flat named by the clone's own cid (the asn1c
             * <ProtocolIE_Container_85P0> id, GO_MKID of the clone expr
             * carries the _<N>P<n> suffix), holding {<ItemIEs>_flat *items;
             * size_t count;}; the MESSAGE's member row references it by
             * that name (the frozen `ProtocolIE_Container_85P0_flat
             * protocolIEs` shape — a BARE name, no run prefix on clone
             * family names). The ItemIEs element cid:
             * slice_element_type's chase target == the field-shaped clone
             * (R2(X)); the C id is that clone's own GO_MKID. */
            {
                asn1p_expr_t *fterm = elem;
                if(elem->expr_type == A1TC_REFERENCE
                   || elem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *ft_ = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, elem);
                    if(ft_) fterm = ft_;
                }
                char *flat_cname = own(GO_MKID(terminal));
                char *flat_ieid = own(GO_MKID(fterm));
                (void)go_flat_seqof_container(flat_cname, flat_ieid,
                                              ctx->module);
                char *flat_mtok3 = go_mk_member(child);
                go_flat_member_ref(flat_cname, flat_mtok3,
                                   stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                free(flat_cname); free(flat_ieid); free(flat_mtok3);
            }
            free(inline_go);
            return 0;
        }
    }
    /* A param-container clone member (the branch above) returned early; the
     * plain-member Flat rows ride the two tails below. The FLAT star is
     * member_stars (OPTIONAL) OR the asn1c cycle-break/recursion marker
     * (EM_INDIRECT/EM_UNRECURSE, the recursion Flat-pointer rule: Flat pointer placement mirrors
     * asn1c's cycle-break, masked tests per the the marker-reading rule amendment) — the walk
     * prints it once here. */
    int flat_star = !is_dflt && ((stars && *stars == '*')
                    || (child->marker.flags & (EM_INDIRECT | EM_UNRECURSE)));
    /* struct-body stage: the field's Go type for a plain member, keyed on whether the
     * member is a REFERENCE (a member whose type references an
     * assignment — leaf OR constructed — is typed by that assignment's named
     * Go type) or the inline construct itself (mapping-table Go column):
     *   a REFERENCE member — the chased terminal assignment's own Go name
     *     (R2(MKID(terminal)); a field-shaped specialization is named R2(X)
     *     — the spec-key — the same form: X IS the clone's Identifier by the
     *     time the chase lands on it). Stored UNQUALIFIED; the post-walk
     *     prepass (qualify_field_types) applies cross-module
     *     qualification once the whole name table exists (a member may
     *     reference an assignment its module defines LATER in the walk).
     *   an inline leaf (INTEGER/BOOLEAN/string/OCTET STRING/BIT STRING/...)
     *     — the mapping-table Go column via classify_leaf, the SAME table the decl
     *     emission uses (go_types_leaf_underlying — one table, no drift). */
    if(child->expr_type == A1TC_REFERENCE || child->meta_type == AMT_TYPEREF
       || terminal != child) {
        /* `terminal != child` covers the post-fix AST where asn1fix resolved
         * a member's type reference IN PLACE (the member expr itself now
         * carries the terminal's expr_type with meta AMT_TYPE — the
         * A1TC_REFERENCE form is gone). The chase resolving to a DIFFERENT
         * expr than the member is the reliable "was a reference" signal. */
        char *tgo = go_r2(GO_MKID(terminal));
        char *ft = str_append(strdup(""), stars);
        ft = str_append(ft, tgo);
        row_set_field_type(ctx->bag, ft);
        /* Flat: a named-ref member slot (tk SEQ OF with no container clone =
         * the nested {items,count} A2 form; anything else = the terminal's
         * own <X>_flat, starred as decided). */
        if(tk == GO_CONSTR_SEQUENCE_OF && terminal->spec_index >= 0) {
            /* a param-container CLONE: the Flat is the nested
             * {items,count} A2 form (the clone never surfaces as a named
             * Flat of its own). */
            asn1p_expr_t *selem = TQ_FIRST(&terminal->members);
            asn1p_expr_t *sterm = selem;
            if(selem && (selem->expr_type == A1TC_REFERENCE
                         || selem->meta_type == AMT_TYPEREF)) {
                asn1p_expr_t *st = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, selem);
                if(st) sterm = st;
            }
            char *flat_selem = own(GO_MKID(sterm));
            char *flat_mtok = go_mk_member(child);
            go_flat_member_seqof(flat_selem, 0, flat_mtok, flat_star);
            go_flat_label_last_member(child->Identifier);
            free(flat_selem); free(flat_mtok);
        } else if(tk == GO_CONSTR_SEQUENCE_OF) {
            /* a reference to a NAMED top-level SEQUENCE OF: the
             * member is typed by the assignment's own named {items,count}
             * typedef (the frozen KPM_BinRangeList_flat binRangeListX
             * shape); never a re-nested wrapper. */
            char *flat_tcid = own(GO_MKID(terminal));
            char *flat_mtok = go_mk_member(child);
            go_flat_member_ref(flat_tcid, flat_mtok, flat_star);
            go_flat_label_last_member(child->Identifier);
            free(flat_tcid); free(flat_mtok);
        } else {
            char *flat_tcid = own(GO_MKID(terminal));
            char *flat_mtok2 = go_mk_member(child);
            go_flat_member_ref(flat_tcid, flat_mtok2, flat_star);
            go_flat_label_last_member(child->Identifier);
            if(is_dflt) go_flat_last_member_default(tree_ptr);
            free(flat_tcid); free(flat_mtok2);
        }
        free(tgo); free(ft);
    } else {
        /* An inline leaf terminal (the member IS the construct): the
         * mapping-table Go column (classify_leaf — INTEGER via asn1c's own
         * asn1c_type_fits_long). GLEAF_ENUM has no bare primitive here: a
         * member that is an inline ENUMERATED took the inline-construct
         * branch at the top of this function (the minted named type), so
         * the NULL return leaves the row unset only for genuinely
         * unclassifiable terminals (classify_leaf already failed those). */
        ctx->wide_nr = 1; ctx->wide_hit = 0;
        int lk = classify_leaf(ctx, terminal, parent_path);
        int mwide = ctx->wide_hit;
        ctx->wide_nr = 0; ctx->wide_hit = 0;
        if(ctx->bag->failed) return -1;
        const char *under = go_types_leaf_underlying(lk);
        if(under) {
            char *ft = str_append(strdup(""), stars);
            ft = str_append(ft, under);
            row_set_field_type(ctx->bag, ft);
            /* Flat: the same classification -> the mapping-table Flat prim column. */
            {
                static const struct { int k; const char *p; } lk2p[] = {
                    {1, "int64_t"}, {2, "uint64_t"}, {3, "_bool32"},
                    {5, "double"}, {6, "asn1cgo_bytes_flat"},
                    {7, "asn1cgo_bytes_flat"}, {8, "asn1cgo_bytes_flat"},
                    {9, "asn1cgo_bits_flat"}, {10, "int32_t"},
                };
                const char *fprim = NULL;
                for(size_t qi = 0; qi < sizeof lk2p / sizeof lk2p[0]; qi++)
                    if(lk == lk2p[qi].k) { fprim = lk2p[qi].p; break; }
                if(fprim) {
                    char *fpm = go_mk_member(child);
                    go_flat_member_prim(fprim, fpm, flat_star);
                    if(mwide) go_flat_last_member_wide();
                    go_flat_label_last_member(child->Identifier);
                    if(is_dflt) go_flat_last_member_default(tree_ptr);
                    free(fpm);
                }
            }
            free(ft);
        }
    }
    return 0;
}

/* walk_names_child: the member walk, then (for a supported DEFAULT member) the
 * exported default-value row. The row is emitted AFTER the member's rows are
 * complete: row_set_field_type and friends address the last row appended, so
 * nothing may be interleaved with them. The member's field row is the first
 * row the inner walk appends. */
static int
walk_names_child(struct walk_ctx *ctx, asn1p_expr_t *child,
                 const char *parent_path, const char *parent_go,
                 const char *parent_cid) {
    int first_row = ctx->bag->n_rows;
    int rc = walk_names_child_inner(ctx, child, parent_path, parent_go,
                                    parent_cid);
    /* An inline named-bit BIT STRING member: a plain BitString field (typed
     * by the inner walk); the bit positions are named as an inline
     * ENUMERATED member's type would be (<Parent><Member>). Emitted here, after
     * the member's own rows are complete (row_set_field_type addresses the
     * last row). parent_path already ends in this member's name. */
    if(rc == 0 && child->expr_type == ASN_BASIC_BIT_STRING
       && child->meta_type != AMT_TYPEREF && TQ_FIRST(&child->members)
       && asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child) == child) {
        char *mgo = go_r2(GO_MKID(child));
        char *bit_go = str_append(str_append(strdup(""), parent_go), mgo);
        char *mcid = own_mkid(child);
        char *bit_cid = go_cid_compound(parent_cid ? parent_cid : "", "__",
                                        mcid);
        emit_bit_names(ctx, bit_go, bit_cid, parent_path, child);
        free(mgo); free(bit_go); free(mcid); free(bit_cid);
        if(ctx->bag->failed) return -1;
    }
    if(rc == 0 && child->expr_type != A1TC_EXTENSIBLE
       && member_is_default(child) && ctx->bag->n_rows > first_row) {
        note_default_value(ctx, child, parent_path, first_row);
        if(ctx->bag->failed) return -1;
    }
    return rc;
}

/* field_shaped_element: a SEQ-OF element whose chased terminal is a SEQUENCE
 * with an open-type &Value member — i.e. a ProtocolIE-Field specialization
 * clone (the element a param-container holds). Used to distinguish a
 * param-container specialization from a plain SEQ-OF-of-named-type. */
static int
field_shaped_element(struct walk_ctx *ctx, asn1p_expr_t *elem) {
    asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, elem);
    return t && is_field_shaped_spec(t) != NULL;
}

/* Iterate one struct's members. The member path passed to walk_names_child is
 * parent_path + "." + child name (the ASN.1 dotted path). */
static int
walk_names_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
                   const char *parent_path) {
    reset_field_scope(ctx->bag);
    asn1p_expr_t *child;
    TQ_FOR(child, &(parent->members), next) {
        /* Extension marker "..." (A1TC_EXTENSIBLE, Identifier "...") carries no
         * Go name — GO_MKID collapses it to "_" and go_r2 to "" — and it is not a
         * real struct member. emit_choice (go_names.c) and emit_enum skip it in
         * their alt loops; the SEQUENCE-member walk must too, or every extensible
         * SEQUENCE leaks a blank-goName field row that no name check legitimately
         * compares (docs/questions.md). */
        if(child->expr_type == A1TC_EXTENSIBLE) continue;
        char *cp = make_path(parent_path,
                             child->Identifier ? child->Identifier : "?");
        int rc = walk_names_child(ctx, child, cp, ctx->parent_go, ctx->parent_cid);
        free(cp);
        if(rc < 0) return -1;
    }
    return 0;
}

/* Walk one top-level assignment (mirror go_walk.c walk_expr). */
static int
walk_names_expr(struct walk_ctx *ctx, asn1p_expr_t *expr) {
    /* Parameterized template: walk specializations, not the template
     * (go_walk.c walk_expr:446-454; asn1compiler.c:116-130). */
    if(expr->lhs_params && expr->spec_index == -1) {
        for(int i = 0; i < expr->specializations.pspecs_count; i++) {
            asn1p_expr_t *clone = expr->specializations.pspec[i].my_clone;
            if(clone && walk_names_expr(ctx, clone) < 0) return -1;
        }
        return 0;
    }

    /* Value assignment: typed value-const only (asn1c_C.c
     * asn1c_lang_C_type_REFERENCE_Value:1259-1265). The discriminator is the
     * AMT_VALUE's OWN expr_type: a named-reference value assign resolves to a
     * governing terminal; INTEGER/ENUMERATED -> the typed
     *   #define <T>_id_<X> ((<T>_t)<n>)
     * A bare INTEGER value assign (`X INTEGER ::= n`) emits the UNTYPED
     * `#define X (n)` (asn1c_save.c:976) and is NOT a value-const. */
    if(expr->meta_type == AMT_VALUE) {
        asn1p_expr_t *governing = NULL;
        if(expr->expr_type == A1TC_REFERENCE
           || expr->meta_type == AMT_TYPEREF)
            governing = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, expr);
        if(governing
           && (governing->expr_type == ASN_BASIC_INTEGER
               || governing->expr_type == ASN_BASIC_ENUMERATED)) {
            /* the #define token is an aggregate — prefix once, parts
             * unprefixed (the .h: E2AP_ProcedureCode_id_E2setup, never
             * ..._id_E2AP_E2setup). own() each part into a named local BEFORE
             * the second GO_MKID: GO_MKID returns the SHARED static buffer
             * (asn1c_misc.c:60), so passing two live GO_MKID returns aliases
             * one buffer (both parts read the same last-computed string).
             * go_cid_compound does not free its args; free the owned parts
             * after the call. */
            char *gov_cid = own(GO_MKID(governing));
            char *val_cid = own(GO_MKID(expr));
            char *raw = go_cid_compound(gov_cid, "_", val_cid);
            free(gov_cid); free(val_cid);
            char *go = go_r2(raw);
            char *path = make_path("", expr->Identifier
                                       ? expr->Identifier : "?");
            emit_name(ctx->bag, ctx->module, path, GK_VALUE_CONST, raw, go);
            /* leaf-stage body data: const value = the value assignment's own
             * integer (expr->value->value.v_integer — the exact field
             * asn1c_C.c:1264 prints), typed by the GOVERNING named type
             * (the ENUMERATED-governed form is the same numeric path —
             * asn1c emits a number for both INTEGER- and ENUM-governed,
             * asn1c_C.c:1257-1263, no enumerator symbol). */
            if(expr->value) {
                char *gov_go = go_r2(GO_MKID(governing));
                row_set_const(ctx->bag,
                              asn1p_itoa(expr->value->value.v_integer), gov_go);
                free(gov_go);
            }
        }
        return 0;
    }

    /* Class / object / set defs have no Go name; their specializations mint
     * clones walked above (go_walk.c walk_expr:460-467). */
    if(expr->meta_type == AMT_OBJECTCLASS
       || expr->meta_type == AMT_OBJECT
       || expr->meta_type == AMT_VALUESET)
        return 0;

    /* Type assignment: one `type` row. goName = R2(MKID(expr)) (a reference
     * assignment mints its OWN named Go type — not chased to terminal). */
    char *type_go = go_r2(GO_MKID(expr));
    char *type_cid = own_mkid(expr);   /* real asn1c C-ident of this assignment */
    const char *ident = expr->Identifier ? expr->Identifier : "?";
    char *type_path = make_path("", ident);

    asn1p_expr_t *terminal = expr;
    if(expr->expr_type == A1TC_REFERENCE || expr->meta_type == AMT_TYPEREF) {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, expr);
        if(t) terminal = t;
    }
    go_construct_e k = go_construct_classify(terminal);

    /* a parameterized-type TEMPLATE emits nothing in Go. A parameterized
     * type's clones are reached via the specialization-recursion loop above
     * (lhs_params && spec_index==-1); asn1c attaches each clone's module back-
     * pointer to the TEMPLATE's module (e.g. E2AP-Containers for every
     * ProtocolIE-Container specialization), so a .h-banner module attribution
     * would wrongly place a swarm of names in the clone-header module. The Go
     * placement is instead: a container/template clone that is NOT field-shaped
     * emits no name at all (the clone's args — the bound ItemIEs / list element
     * — mint their own names in their defining module during their own walks),
     * and a field-shaped clone mints R2(X) in X's module (see emit_spec below).
     * `spec_index >= 0` marks a clone (a hand-authored top-level assignment keeps
     * spec_index == -1 via the lhs_params check). Refuse here so a container clone
     * (ProtocolIE-Container / -ContainerPair specializations — a SEQUENCE OF
     * field-element) does not leak a `type` row + member `field` rows into the
     * template's module. */
    if(expr->spec_index >= 0 && !(k == GO_CONSTR_SEQUENCE && is_field_shaped_spec(terminal))) {
        free(type_cid);
        free(type_path);
        free(type_go);
        return 0;
    }

    /* a field-shaped specialization (SEQUENCE with an open-type &Value
     * member) is named as R2(X)+Value+ValuePr, NOT as a plain struct. It
     * carries no ordinary top-level type name of its own in the index (the
     * spec-key row IS its "type" name). Handle before the generic SEQUENCE walk
     * so the spec rows (not a colliding `type` + member `field` rows) win. */
    if(k == GO_CONSTR_SEQUENCE && is_field_shaped_spec(terminal)) {
        /* alias collapse: a field-shaped specialization whose ASSIGNMENT is a
         * type-reference alias (AMT_TYPEREF — e.g. ProtocolIE-SingleContainer
         * {{X}} ::= ProtocolIE-Field {{X}},asn1c emits the alias as a bare
         * `typedef <resolved_clone>_t <alias>_t;`) resolves to the SAME field-
         * shaped clone as the referenced parameterized type. That resolved clone
         * is named independently (the referenced type's own specialization walk
         * emits its spec-key, e.g. RICactionToBeSetupItemIEs). The alias mints no
         * new name — collapse (emit nothing) so the two don't double-name one
         * C type. Same shape, not a collision. A directly-defined field-
         * shaped SEQUENCE has AMT_TYPE; only an alias-to-parameterized-type is
         * AMT_TYPEREF. */
        if(expr->meta_type == AMT_TYPEREF) {
            /* Flat (alias collapse): the alias clone emits a Flat
             * ALIAS of the resolved clone's Flat (the frozen
             * `typedef E2AP_RICaction_ToBeSetup_ItemIEs_flat
             * ProtocolIE_SingleContainer_88P0_flat;`). The alias cid is the
             * clone's own ACE id (BARE name, no run prefix on clone family
             * names); the target is the resolved field-shaped clone's cid. */
            char *resolved_cid = NULL;
            const char *resolved_module = ctx->module;
            {
                asn1p_expr_t *rt = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, expr);
                if(rt) {
                    resolved_cid = own(GO_MKID(rt));
                    /* the alias lives in X's module — the
                     * module that DEFINES the bound object set — resolved
                     * the same way emit_spec does (asn1c_get_ioc_table's
                     * objset->module; the clone's own ->module back-pointer
                     * names the TEMPLATE's module (E2AP-Containers), which
                     * would strand the alias in a header that never
                     * includes its target). */
                    arg_t a2;
                    memset(&a2, 0, sizeof a2);
                    a2.asn = ctx->asn;
                    a2.ns = ctx->ns;
                    a2.expr = rt;
                    asn1c_ioc_table_and_objset_t ioc2 =
                        asn1c_get_ioc_table(&a2);
                    if(ioc2.objset && ioc2.objset->module
                       && ioc2.objset->module->ModuleName)
                        resolved_module = ioc2.objset->module->ModuleName;
                }
            }
            if(resolved_cid) {
                (void)go_flat_alias_bare(type_cid, resolved_cid,
                                         resolved_module);
                free(resolved_cid);
            }
            free(type_cid);
            free(type_path);
            free(type_go);
            return 0;
        }
        emit_spec(ctx, type_go, type_cid, ident, terminal);
        free(type_cid);
        free(type_path);
        free(type_go);
        return 0;
    }

    /* For a SEQUENCE/CHOICE/ENUM the type row's goName both goes in the dump
     * and parents the member names; emit it after computing k so a failed
     * classify doesn't leave a half-name. The member path root is `ident`. The
     * type row's rawCid (= type_cid) is the verbatim asn1c C-struct identifier;
     * the value is handed off (owned) to emit_name here. */
    emit_name(ctx->bag, ctx->module, type_path, GK_TYPE,
              type_cid ? type_cid : strdup(""), type_go);
    /* Conv (the entry-point rule): record a PDU root — mirror asn1c's own membership rule
     * (include_type_to_pdu_collection, asn1c_save.c:936): included iff a
     * type_cb exists for the (meta_type, expr_type) — a constructed type we
     * emitted a row for — AND not AMT_VALUE AND no lhs_params AND
     * (A1C_PDU_ALL or (A1C_PDU_AUTO and !expr->_type_referenced)). The run
     * is -pdu=auto (CFLAGS_FORK). */
    {
        int lang_cb = (k == GO_CONSTR_SEQUENCE || k == GO_CONSTR_CHOICE
                       || k == GO_CONSTR_SEQUENCE_OF
                       || k == GO_CONSTR_INTEGER || k == GO_CONSTR_BOOLEAN
                       || k == GO_CONSTR_NULL || k == GO_CONSTR_REAL
                       || k == GO_CONSTR_OCTET_STRING
                       || k == GO_CONSTR_BIT_STRING
                       || k == GO_CONSTR_PRINTABLE
                       || k == GO_CONSTR_ENUMERATED);
        if(lang_cb && !expr->lhs_params
           && (go_compiler_flags & A1C_PDU_ALL
               || ((go_compiler_flags & A1C_PDU_AUTO)
                   && !expr->_type_referenced))) {
            go_conv_record_pdu(GO_MKID(terminal));
        }
    }
    /* leaf-stage body data: a LEAF type assignment's declaration is
     * `type <goName> <underlying>` (every type assignment is a named Go
     * type; only inline constructs use the mapping-table type directly — a plain or
     * reference leaf assignment is named). classify_leaf resolves the
     * underlying via asn1c's own machinery (asn1c_type_fits_long for INTEGER,
     * asn1c_misc.c:408; the frozen classifier for the rest). Constructed
     * kinds (SEQUENCE/CHOICE/SEQ-OF) carry GLEAF_NONE — their bodies are
     * the struct-body stage; ENUMERATED classifies GLEAF_ENUM and pairs with the emit_enum
     * const values below. */
    if(k != GO_CONSTR_SEQUENCE && k != GO_CONSTR_CHOICE
       && k != GO_CONSTR_SEQUENCE_OF) {
        int lk = classify_leaf(ctx, terminal, ident);
        row_set_leaf(ctx->bag, lk);
        /* Flat: the leaf mint rides the SAME classification (one decision,
         * both columns; leaf = bare typedef of the mapping-table Flat prim). */
        go_flat_leaf_gleaf(type_cid, lk, ctx->module);
        go_flat_label_cur(terminal->Identifier);   /* td->name label */
    }

    if(k == GO_CONSTR_BIT_STRING)
        mark_bitstring_module(ctx->bag, ctx->module);
    /* A named-bit BIT STRING assignment: `type X BitString` plus the bit
     * positions as int constants. Only the defining assignment gets them (an
     * alias `Y ::= X` does not redeclare X's bits). */
    if(k == GO_CONSTR_BIT_STRING && terminal == expr
       && expr->expr_type == ASN_BASIC_BIT_STRING
       && expr->meta_type != AMT_TYPEREF && TQ_FIRST(&expr->members))
        emit_bit_names(ctx, type_go, type_cid, ident, expr);

    int rc = 0;
    if(k == GO_CONSTR_SEQUENCE) {
        /* Flat: struct mint before the member walk (members land on it).
         * display label: the td->name of this typedef = the asn_DEF-owning
         * entity's ASN.1 name (the reference-chased terminal for a
         * reference assignment; the assignment itself otherwise). */
        (void)go_flat_struct(type_cid, ctx->module);
        go_flat_label_cur(terminal->Identifier);
        const char *save_go = ctx->parent_go;
        const char *save_cid = ctx->parent_cid;
        ctx->parent_go = type_go;
        ctx->parent_cid = type_cid;   /* borrowed for the duration of this walk */
        reset_field_scope(ctx->bag);
        /* struct-body stage: SEQUENCE type rows declare Go structs; their member fields
         * attach to the struct scope opened here. */
        row_set_is_struct(ctx->bag);
        struct_scope_open(ctx->bag, type_go);
        rc = walk_names_members(ctx, expr, ident);
        struct_scope_reset(ctx->bag);
        ctx->parent_go = save_go;
        ctx->parent_cid = save_cid;
    } else if(k == GO_CONSTR_CHOICE) {
        emit_choice(ctx, type_go, type_cid, ident, terminal);
    } else if(k == GO_CONSTR_ENUMERATED) {
        emit_enum(ctx, type_go, type_cid, ident, terminal);
    } else if(k == GO_CONSTR_SEQUENCE_OF) {
        /* slice stage (the slice-alias naming rule): a SEQUENCE-OF type assignment declares
         * the named slice alias `type X []Elem` right at its own `type` row
         * (emitted above; no row appended between it and here). SIZE
         * constraints and a `...` do not change the shape (the frozen
         * BinRangeList / MeasurementInfoList forms). The ELEMENT carries
         * the same one-resolver rule as every slice shape
         * (slice_element_type): a reference element is the assignment's
         * own goName (qualified by the prepass), an inline
         * leaf is the mapping-table column, an inline element is minted as
         * <Type>Member by mint_inline_seqof_elem (below). */
        asn1p_expr_t *elem = TQ_FIRST(&terminal->members);
        if(elem && elem->expr_type == ASN_BASIC_BIT_STRING)
            mark_bitstring_module(ctx->bag, ctx->module);
        if(seqof_elem_is_inline(elem)) {
            /* an inline element is named after the assignment that DECLARES
             * the SEQUENCE OF (the terminal): its own for a plain assignment,
             * the chased one for an alias `U ::= T` (the element is reused
             * by the minted-element table). */
            int owner_row = ctx->bag->n_rows - 1;
            char *ogo, *ocid;
            const char *opath;
            if(terminal == expr) {
                ogo = strdup(type_go); ocid = strdup(type_cid); opath = ident;
            } else {
                const char *tmod = terminal->module
                    ? terminal->module->ModuleName : NULL;
                if(!tmod || !ctx->module || strcmp(tmod, ctx->module) != 0) {
                    fprintf(stderr,
                            "asn1cgo: SEQUENCE OF with an inline element "
                            "type reached through a type assignment of "
                            "another module is not supported in module "
                            "%s: %s\n",
                            ctx->module ? ctx->module : "?", ident);
                    ctx->bag->failed = 1;
                    return -1;
                }
                ogo = go_r2(GO_MKID(terminal));
                ocid = own_mkid(terminal);
                opath = terminal->Identifier ? terminal->Identifier : ident;
            }
            char *ge = NULL, *fc = NULL;
            int mrc = mint_inline_seqof_elem(ctx, elem, opath, ogo, ocid,
                                             &ge, &fc);
            free(ogo); free(ocid);
            if(mrc < 0) { free(ge); free(fc); return -1; }
            row_set_slice_elem_at(ctx->bag, owner_row, ge);
            (void)go_flat_seqof(type_cid, fc, 0, ctx->module);
            go_flat_label_cur(terminal->Identifier);
            free(ge); free(fc);
            return 0;
        }
        {
            char *selem = slice_element_type(ctx, elem, ident);
            if(ctx->bag->failed) {
                free(selem);
                return -1;
            }
            row_set_slice_elem(ctx->bag, selem);
            /* Flat: the named SEQ OF — the element cid is the
             * chased terminal's own cid (a reference element; an inline
             * leaf element already failed loud above). A SingleContainer
             * clone element takes its BARE clone id (frozen units: the
             * 88P0 list's items read ProtocolIE_SingleContainer_88P0_flat,
             * the alias of the ItemIEs Flat). */
            {
                asn1p_expr_t *eterm = elem;
                if(elem->expr_type == A1TC_REFERENCE
                   || elem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *et = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, elem);
                    if(et) eterm = et;
                }
                char *flat_eterm = own(GO_MKID(eterm));
                if(eterm->spec_index >= 0
                   && eterm->expr_type == ASN_CONSTR_SEQUENCE
                   && is_field_shaped_spec(eterm)) {
                    /* the SingleContainer clone: elem = the bare clone id
                     * (the alias node of the resolved ItemIEs Flat — minted
                     * once; the alias's target resolve is by cid). */
                    char *bare = own(GO_MKID(eterm));
                    /* keep the _<N>P<n> slot suffix GO_MKID appended */
                    const char *pfx = asn1c_prefix();
                    size_t pl = pfx ? strlen(pfx) : 0;
                    if(pl && strncmp(bare, pfx, pl) == 0) {
                        memmove(bare, bare + pl, strlen(bare + pl) + 1);
                    }
                    /* GUARD: mint the 88P0 alias ONLY when the clone id and
                     * the resolved ItemIEs id DIFFER — an in-place-resolved
                     * chase (post-fix AST) gives eterm == the ItemIEs and
                     * would mint a self-alias whose cid hijacks the ItemIEs
                     * STRUCT node by dedup (the bare-name ItemIEs bug). */
                    const char *of_bare = flat_eterm;
                    if(pl && strncmp(of_bare, pfx, pl) == 0)
                        of_bare += pl;
                    (void)go_flat_seqof(type_cid, bare, 0, ctx->module);
                    go_flat_label_cur(terminal->Identifier);
                    if(strcmp(bare, of_bare) != 0) {
                        char *alias_cid = own(bare);
                        (void)go_flat_alias_bare(alias_cid, flat_eterm,
                                                 ctx->module);
                        free(alias_cid);
                    }
                    free(bare);
                } else {
                    (void)go_flat_seqof(type_cid, flat_eterm, 0,
                                        ctx->module);
                    go_flat_label_cur(terminal->Identifier);
                }
                free(flat_eterm);
            }
            free(selem);
        }
    }
    return rc;
}

/* ========================================================================= *
 * (App. G): the name-row surface the glue emitter reads. The bag
 * is file-static; these accessors hand go_glue.c a read-only view (the bag
 * outlives the glue emit — torn down in go_generate's epilogue). Row order
 * here is WALK order (rows[]), not dump order; the glue walks it once.
 * ========================================================================= */
int go_names_rows_n(void) { return g_emit_bag ? g_emit_bag->n_rows : 0; }

/* go_ctor.c's pkg-dir lookup (constructors.go placement): the same
 * module_pkg_go rule types.go uses. malloc'd. */
char *go_ctor_pkg_of(const char *module) { return module_pkg_go(module); }

/* go_ctor.c's module-path head for its import lines: the same live value
 * go_emit_module_imports formats with (set_go_module_paths set it). */
const char *go_ctor_module_path(void) { return g_go_module_path; }

/* Row facts (NULL/0 for absent). Borrowed pointers — valid until go_generate
 * returns; the glue copies whatever it keeps. */
const char *go_names_row_module(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].module : NULL;
}
const char *go_names_row_goname(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].goName : NULL;
}
const char *go_names_row_rawcid(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].rawCid : NULL;
}
/* kind: "type" "field" "choice-pr" "choice-const" "enum-const" "value-const"
 * "inline" "spec-key" "spec-value" "spec-pr" "helper" (g_kind_tag order). */
const char *go_names_row_kind(int i) {
    if(!g_emit_bag || i < 0 || i >= g_emit_bag->n_rows) return NULL;
    go_kind_e k = g_emit_bag->rows[i].kind;
    if(k < 0 || k >= GK__COUNT) return NULL;
    return g_kind_tag[k];
}
/* A field row's Go type text (qualified by qualify_field_types —
 * the glue emit runs after the prepass) + its owning struct's goName. */
const char *go_names_row_field_type(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].field_type : NULL;
}
const char *go_names_row_sf_owner(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].sf_owner : NULL;
}
/* A slice-owner row's element type text (qualified; NULL = not a slice). */
const char *go_names_row_slice_elem(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].slice_elem : NULL;
}
/* A const row's decimal value text + its declared Go type owner. */
const char *go_names_row_intval(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].intval : NULL;
}
const char *go_names_row_gotype(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].goType : NULL;
}
/* is_struct: the row declares a Go struct body (its fields attach by
 * sf_owner == this goName). */
int go_names_row_is_struct(int i) {
    return (g_emit_bag && i >= 0 && i < g_emit_bag->n_rows)
               ? g_emit_bag->rows[i].is_struct : 0;
}
/* A leaf row's mapping-table underlying Go view, as the DECLARED text emits it
 * (go_types.c's table; NULL = GLEAF_NONE / not a leaf). */
const char *go_names_row_leaf_underlying(int i) {
    if(!g_emit_bag || i < 0 || i >= g_emit_bag->n_rows) return NULL;
    int lk = g_emit_bag->rows[i].leaf_kind;
    return lk ? go_types_leaf_underlying(lk) : NULL;
}
