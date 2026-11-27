/*
 * go_names.c — Go-name generator pass.
 *
 * Produces every package-level Go identifier the backend will emit, plus the
 * published name set consumed by the name-distribution check (dump compare).
 * It owns its OWN AST walk, separate from the (classify-only) walk in
 * go_walk.c. The two must agree on which (module, path) nodes carry a Go name
 * — the dump is cross-referenced against the real asn1c .h index — but they
 * serve different purposes:
 * go_walk classifies (support gate), go_names resolves (naming).
 *
 * What is named here (each row cites the asn1c path
 * that makes the rawCid authoritative):
 *
 *   type        one Go type per top-level type assignment (the GoName transform,
 *               the naming rule base).
 *               rawCid = GO_MKID(expr); goName = GoName(rawCid). A reference
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
 *   value-const GoName of a typed value-assignment #define symbol
 *               `#define <T>_id_<X> ((<T>_t)<n>)` — emitted only when the value
 *               assignment's governing type is INTEGER or ENUMERATED
 *               (asn1c_C.c asn1c_lang_C_type_REFERENCE_Value). rawCid =
 *               GO_MKID(governing-type) + "_" + GO_MKID(value-expr). Bare
 *               INTEGER value assigns (`maxno-X INTEGER ::= n`) emit the
 *               UNTYPED `#define X (n)` (asn1c_save.c generate_constant_
 *               collection) and are NOT value-consts: excluded.
 *   spec-*      field-shaped specialization (ProtocolIE-Field /
 *               SingleContainer {{X}} whose clone is a SEQUENCE with an
 *               open-type &Value member): GoName(X), GoName(X)+Value, GoName(X)+ValuePr,
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
 *
 * Source layout (the go_names*.c files share go_names_internal.h):
 *   go_names.c         go_generate (the pass driver), -pdu selection, leaf
 *                      classification, the -Fgo output-dir checks, and the
 *                      name-row accessors go_glue.c / go_ctor.c read
 *   go_names_rows.c    the name bag: rows, name scopes, collisions, the
 *                      alt-spelling registry
 *   go_names_decls.c   Go module paths, imports, types.go declarations
 *   go_names_choice.c  CHOICE, ENUMERATED and BIT STRING names
 *   go_names_spec.c    field-shaped specializations (value unions), member
 *                      pointer stars, IOC class columns
 *   go_names_check.c   post-walk qualification, the import-cycle and
 *                      by-value-cycle checks, New<T>() marking
 *   go_names_dflt.c    SEQUENCE OF elements and DEFAULT values
 *   go_names_walk.c    the recursive walkers
 */
#include "go_names_internal.h"


/* Build a dotted ASN.1 path. parent may be NULL/empty. malloc'd, never NULL. */
char *
go_make_path(const char *parent, const char *leaf) {
    char *p = parent && *parent
        ? go_str_append(strdup(""), parent) : strdup("");
    if(p && *p) p = go_str_append(p, ".");
    return go_str_append(p, leaf ? leaf : "?");
}

/* Deterministic dump order: by module, then path, then kind, then goName. */
static int
row_cmp(const void *pa, const void *pb) {
    const struct name_row *a = pa, *b = pb;
    int c = strcmp(a->module ? a->module : "?", b->module ? b->module : "?");
    if(c) return c;
    c = strcmp(a->path ? a->path : "?", b->path ? b->path : "?");
    if(c) return c;
    c = strcmp(g_go_kind_tag[a->kind], g_go_kind_tag[b->kind]);
    if(c) return c;
    return strcmp(a->goName ? a->goName : "", b->goName ? b->goName : "");
}

/* Mark that `module` owns a BIT-STRING member (so go_generate emits one helper
 * row for it). Called from the member walk when a member's terminal is BIT
 * STRING. Idempotent. */
void
go_mark_bitstring_module(struct name_bag *b, const char *module) {
    for(int j = 0; j < b->n_bs; j++)
        if(b->bs_modules[j] == module) return;
    if(b->n_bs + 1 > b->cap_bs) {
        int nc = b->cap_bs ? b->cap_bs * 2 : 8;
        const char **np = go_xrealloc(b->bs_modules, (size_t)nc * sizeof(char *));
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

/* go_jer_enabled: nonzero when this run was started with -gen-JER
 * (A1C_GEN_JER set). Only then does each PDU get the two JER C entry points
 * and the Go EncodeJER / DecodeJER<T> wrappers; without it the generated
 * files are exactly what they were before JER existed in the Go backend. */
int go_jer_enabled(void);
int go_jer_enabled(void) { return (go_compiler_flags & A1C_GEN_JER) != 0; }

/* go_open_type_unknown: nonzero when this run was started with
 * -fopen-type-unknown (A1C_OPEN_TYPE_UNKNOWN): the value union of an open
 * type over an extensible object set then has the Unknown alternative
 * (*rt.OpenTypeRaw), as the C union has <T>_PR_unknown. */
int go_open_type_unknown(void);
int go_open_type_unknown(void) {
    return (go_compiler_flags & A1C_OPEN_TYPE_UNKNOWN) != 0;
}

/* -pdu=<Type> names, handed over by the driver (asn1c.c) as it parses them:
 * the C pass frees its own list (asn1c_save.c) before the Go pass runs. */
static struct go_pdu_name {
    char *name;
    char *cid;          /* the PDU root recorded for it, NULL = none */
} *go_pdu_names;
static size_t go_n_pdu_names;

void asn1cgo_add_pdu_type(const char *name);
void
asn1cgo_add_pdu_type(const char *name) {
    struct go_pdu_name *n = realloc(go_pdu_names,
                                    (go_n_pdu_names + 1) * sizeof(*n));
    assert(n);
    go_pdu_names = n;
    n[go_n_pdu_names].name = strdup(name);
    assert(n[go_n_pdu_names].name);
    n[go_n_pdu_names].cid = NULL;
    go_n_pdu_names++;
}

/* go_pdu_named: nonzero when a -pdu=<Type> names this hand-written
 * assignment. */
static int
go_pdu_named(const asn1p_expr_t *expr) {
    if(expr->spec_index >= 0 || !expr->Identifier) return 0;
    for(size_t i = 0; i < go_n_pdu_names; i++)
        if(strcmp(go_pdu_names[i].name, expr->Identifier) == 0) return 1;
    return 0;
}

/* go_pdu_selected: asn1c's own PDU rule (include_type_to_pdu_collection,
 * asn1c_save.c) for a top-level type assignment the caller has already
 * found usable as a PDU: -pdu=all takes every type, -pdu=auto (and no -pdu
 * option at all, as in C) every type no other type refers to, and each
 * -pdu=<Type> the hand-written assignments of that name. */
int
go_pdu_selected(const asn1p_expr_t *expr) {
    if(go_compiler_flags & A1C_PDU_ALL) return 1;
    if(!expr->_type_referenced
       && ((go_compiler_flags & A1C_PDU_AUTO)
           || !(go_compiler_flags & A1C_PDU_TYPE)))
        return 1;
    return go_pdu_named(expr);
}

/* go_pdu_record: record cid as a PDU root for expr, and remember it for
 * each -pdu=<Type> that names expr (go_pdu_check). */
void
go_pdu_record(const asn1p_expr_t *expr, const char *cid) {
    go_conv_record_pdu(cid);
    if(!go_pdu_named(expr)) return;
    for(size_t i = 0; i < go_n_pdu_names; i++)
        if(!go_pdu_names[i].cid
           && strcmp(go_pdu_names[i].name, expr->Identifier) == 0) {
            go_pdu_names[i].cid = strdup(cid);
            assert(go_pdu_names[i].cid);
        }
}

/* go_pdu_record_alias: record a type assignment that only renames another
 * (Alias ::= Msg, also tagged, also of an instance of a parameterized type)
 * as a PDU of its own: entry points on its own descriptor asn_DEF_<alias_cid>
 * over the converters of the type it renames (target_cid), Go API on its
 * own Go type alias_go. */
void
go_pdu_record_alias(const asn1p_expr_t *expr, const char *alias_cid,
                    const char *target_cid, const char *alias_go,
                    const char *module) {
    go_conv_record_pdu_alias(target_cid, alias_cid, alias_go,
                             expr->Identifier, module);
    if(!go_pdu_named(expr)) return;
    for(size_t i = 0; i < go_n_pdu_names; i++)
        if(!go_pdu_names[i].cid
           && strcmp(go_pdu_names[i].name, expr->Identifier) == 0) {
            go_pdu_names[i].cid = strdup(target_cid);
            assert(go_pdu_names[i].cid);
        }
}

/* go_pdu_check: every -pdu=<Type> must end up with Go Encode/Decode
 * functions (the glue skips a PDU root without a Go type of its own); names
 * each one that does not and returns how many. Run after the Flat layout. */
static int
go_pdu_check(void) {
    int bad = 0;
    for(size_t i = 0; i < go_n_pdu_names; i++) {
        const char *cid = go_pdu_names[i].cid;
        flat_type *t = cid ? go_flat_ir_ref_resolve(cid) : NULL;
        const char *mod = t ? go_flat_ir_module(t) : NULL;
        if(mod && *mod) continue;
        fprintf(stderr, "asn1cgo: -pdu=%s: the Go backend gives this type no "
                "Encode/Decode functions (%s)\n", go_pdu_names[i].name,
                cid ? "a parameterized type instance is not supported as a PDU"
                    : "not a type the Go backend emits");
        bad++;
    }
    return bad;
}

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
 *           []byte fallback until a real instance exists" (none in
 *           scope today).
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
         * unconstrained INTEGER like `Format-Type ::= INTEGER` — asn1c emits
         * `typedef long` (Format-Type.h), so the Go type is int64. FL_PRESUMED is the native branch;
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
     * with open extension still fits uint64 (treat an
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

/* go_classify_leaf: the GLEAF_* kind of a non-INTEGER leaf terminal. INTEGER
 * goes through classify_integer_leaf (asn1c's own decision function). */
int
go_classify_leaf(struct walk_ctx *ctx, asn1p_expr_t *terminal,
              const char *path_for_diag) {
    switch(go_construct_classify(terminal)) {
    case GO_CONSTR_INTEGER:
        return classify_integer_leaf(ctx, terminal, path_for_diag);
    case GO_CONSTR_BOOLEAN:  return GLEAF_BOOL;
    case GO_CONSTR_NULL:     return GLEAF_NULL;
    case GO_CONSTR_REAL: {
        /* a REAL asn1c stores as a C float (a WITH COMPONENTS constraint
         * narrows it, asn1c_misc.c asn1c_REAL_fits) is float32 in Go */
        arg_t a;
        memset(&a, 0, sizeof a);
        a.asn = ctx->asn;
        a.ns = ctx->ns;
        a.expr = terminal;
        a.flags = go_compiler_flags;
        return asn1c_REAL_fits(&a, terminal) == RL_FITS_FLOAT32
               ? GLEAF_REAL32 : GLEAF_REAL;
    }
    case GO_CONSTR_OCTET_STRING: return GLEAF_OCTETS;
    case GO_CONSTR_BIT_STRING:   return GLEAF_BITSTRING;
    case GO_CONSTR_OID:
        return go_oid_is_relative(terminal) ? GLEAF_ROID : GLEAF_OID;
    case GO_CONSTR_STRING:
        switch(go_string_subkind(terminal)) {
        case GO_STR_BMP:       return GLEAF_STRING_BMP;
        case GO_STR_UNIVERSAL: return GLEAF_STRING_UNIV;
        default:
            return GLEAF_STRING_Z;
        }
    case GO_CONSTR_ENUMERATED:   return GLEAF_ENUM;
    default: break;
    }
    /* An unsupported leaf (the classification walk already rejects them
     * loudly) reaching here is an internal ordering bug: record it as a
     * failure named by path. */
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
    char *gm = go_path_join2(dir, "go.mod");
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
        if(pfx && *pfx && go_check_module_prefix(pfx) < 0)
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
    go_clash_reset();
    go_alt_reset();
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
            if(go_walk_names_expr(&ctx, expr) < 0) {
                asn1_namespace_free(ctx.ns);
                /* best-effort teardown */
                goto done;
            }
        }

        /* pkg-dir: one per real module, package dir = module id lowercased. The
         * row doubles as the across-module collision probe (record_pkg_dir). */
        {
            char *pkg = go_module_pkg_name(mod->ModuleName);
            char *path = strdup(mod->ModuleName ? mod->ModuleName : "?");
            go_emit_name(&bag, mod->ModuleName, path, GK_PKG_DIR,
                      strdup(pkg), pkg);   /* rawCid=goName=the dir itself */
        }

        /* helper BitString: one row per module that owns a BIT-STRING member. */
        for(int j = 0; j < bag.n_bs; j++)
            if(bag.bs_modules[j] == mod->ModuleName) {
                go_emit_name(&bag, mod->ModuleName,
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
     * Slice-stage: go_qualify_slice_elems runs beside it — the same lookup over the
     * same table, applied to every slice-owner row's ELEMENT type. */
    go_qualify_field_types(&bag);
    go_qualify_slice_elems(&bag);
    /* by-value-cycle check: a type cycle in which every edge is by
     * value (no OPTIONAL *T, no CHOICE/value-union alt *T, no slice) has no
     * finite Go representation — as flat types the SCC would expand forever.
     * Computed over the EMITTED Go reference graph (the rows themselves), so
     * specialty mint sites (spec unions, inline slices) are covered by
     * construction. Sets bag->failed + names the cycle (-> exit 70). */
    if(go_check_cycles(&bag))
        bag.failed = 1;
    /* New<T> constructors of the structs with DEFAULT members (after the
     * field types are qualified: a member's type may be in another module). */
    if(!bag.failed && go_mark_ctors(&bag))
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
                        g_go_kind_tag[r->kind]);
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
                            g_go_kind_tag[r->kind],
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
            g_go_emit_bag = &bag;   /* go_emit_module_decls reads this */
            go_set_module_paths(go_outdir);
            /* Go package import cycles are detected BEFORE any file is
             * written (the glue dry run needs the layout). */
            go_flat_layout_all();
            if(go_pdu_check() != 0) {
                bag.failed = 1;
                rc = -1;
            }
            if(rc == 0 && go_check_import_cycles(&bag) != 0) {
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
            g_go_emit_bag = NULL;
            /* Flat: compute every size/align/offset under
             * the LP64 layout rule (no compiler), then write the per-package
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
                g_go_emit_bag = &bag;   /* go_conv_emit reads the Default funcs */
                rc = go_conv_emit(stage, g_go_rt_module_path);
                g_go_emit_bag = NULL;
                if(rc < 0) bag.failed = 1;
            }
            /* Glue: emit the per-package glue.go
             * (Encode/Decode/xer per PDU root, the size/fill/read triples,
             * the arena/error bridge) + the layout.go init() probe. Reads
             * the name rows through the go_names_rows_* surface below (the
             * bag is still alive here; torn down below). */
            if(rc == 0) {
                g_go_emit_bag = &bag;   /* go_glue_emit reads this */
                rc = go_glue_emit(stage, g_go_module_path,
                                  g_go_rt_module_path);
                g_go_emit_bag = NULL;
                if(rc < 0) bag.failed = 1;
            }
            /* one constructor per IOC row into <pkg>/
             * constructors.go (reads the name rows through the same
             * surface + the go_ioc tables; no hook change). */
            if(rc == 0) {
                g_go_emit_bag = &bag;   /* go_ctor_emit reads this */
                rc = go_ctor_emit(stage);
                g_go_emit_bag = NULL;
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
            go_clear_module_paths();
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
            free(bag.rows[j].slice_elem);   /* owned copy (go_row_set_slice_elem) */
            free(bag.rows[j].alias_of);
            free(bag.rows[j].dflt_lit);
            free(bag.rows[j].dflt_owner);
            free(bag.rows[j].dflt_field);
            go_dflt_fn_free(bag.rows[j].dfn);
            free(bag.rows[j].bit_type);
        }
        free(bag.rows);
        for(int j = 0; j < bag.n_ps; j++) {
            for(int k = 0; k < bag.ps_n[j]; k++) {
                free(bag.ps_owners[j][k].goName);
                free(bag.ps_owners[j][k].path);
            }
            gsmap_free(&bag.ps_ix[j]);
            free(bag.ps_owners[j]);
        }
        free(bag.ps_module); free(bag.ps_owners); free(bag.ps_ix);
        free(bag.ps_n); free(bag.ps_cap);
        for(int j = 0; j < bag.n_fields; j++) {
            free(bag.fields[j].goName); free(bag.fields[j].path);
        }
        free(bag.fields);
        free(bag.fs_stack);
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
 * The name-row surface the glue emitter reads. The bag
 * is file-static; these accessors hand go_glue.c a read-only view (the bag
 * outlives the glue emit — torn down in go_generate's epilogue). Row order
 * here is WALK order (rows[]), not dump order; the glue walks it once.
 * ========================================================================= */
int go_names_rows_n(void) { return g_go_emit_bag ? g_go_emit_bag->n_rows : 0; }

/* go_ctor.c's pkg-dir lookup (constructors.go placement): the same
 * go_module_pkg_name rule types.go uses. malloc'd. */
char *go_ctor_pkg_of(const char *module) { return go_module_pkg_name(module); }

/* go_ctor.c's module-path head for its import lines: the same live value
 * go_emit_module_imports formats with (go_set_module_paths set it). */
const char *go_ctor_module_path(void) { return g_go_module_path; }

/* Row facts (NULL/0 for absent). Borrowed pointers — valid until go_generate
 * returns; the glue copies whatever it keeps. */
const char *go_names_row_module(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].module : NULL;
}
const char *go_names_row_goname(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].goName : NULL;
}
const char *go_names_row_rawcid(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].rawCid : NULL;
}
/* kind: "type" "field" "choice-pr" "choice-const" "enum-const" "value-const"
 * "inline" "spec-key" "spec-value" "spec-pr" "helper" (g_go_kind_tag order). */
const char *go_names_row_kind(int i) {
    if(!g_go_emit_bag || i < 0 || i >= g_go_emit_bag->n_rows) return NULL;
    go_kind_e k = g_go_emit_bag->rows[i].kind;
    if(k < 0 || k >= GK__COUNT) return NULL;
    return g_go_kind_tag[k];
}
/* A field row's Go type text (qualified by go_qualify_field_types —
 * the glue emit runs after the prepass) + its owning struct's goName. */
const char *go_names_row_field_type(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].field_type : NULL;
}
const char *go_names_row_sf_owner(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].sf_owner : NULL;
}
/* A slice-owner row's element type text (qualified; NULL = not a slice). */
const char *go_names_row_slice_elem(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].slice_elem : NULL;
}
/* A const row's decimal value text + its declared Go type owner. */
const char *go_names_row_intval(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].intval : NULL;
}
const char *go_names_row_gotype(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].goType : NULL;
}
/* is_struct: the row declares a Go struct body (its fields attach by
 * sf_owner == this goName). */
int go_names_row_is_struct(int i) {
    return (g_go_emit_bag && i >= 0 && i < g_go_emit_bag->n_rows)
               ? g_go_emit_bag->rows[i].is_struct : 0;
}
/* A leaf row's mapping-table underlying Go view, as the DECLARED text emits it
 * (go_types.c's table; NULL = GLEAF_NONE / not a leaf). */
const char *go_names_row_leaf_underlying(int i) {
    if(!g_go_emit_bag || i < 0 || i >= g_go_emit_bag->n_rows) return NULL;
    int lk = g_go_emit_bag->rows[i].leaf_kind;
    return lk ? go_types_leaf_underlying(lk) : NULL;
}
