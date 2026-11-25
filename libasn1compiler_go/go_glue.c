/*
 * go_glue.c — the Go<->Flat glue emission: one glue.go per package
 * that OWNS a PDU root, plus the layout.go init() cross-check (the
 * layout-guard rule: the generator's literals
 * against the live cgo compiler, via the <P><pkg>_layout_probe.h accessor
 * header written beside the flat headers in internal/cspec/).
 *
 * The glue is the only code touching both Go values and Flat memory.
 * glue.go is SELF-CONTAINED per package: size/fill/read functions for every
 * type transitively reachable from this package's PDU roots, including
 * foreign-package types (referenced by their package-qualified names; the
 * camel fn bases are unique across one spec's packages, so the local
 * unexported fns never collide).
 *
 * Per PDU root (the entry set, IR order) the public API:
 *     func (p *<T>) Encode() ([]byte, error)          (method)
 *     func Decode<T>(b []byte) (*<T>, error)          (free fn)
 *     func xer(p *<T>) ([]byte, error)                (unexported)
 *     func (p *<T>) EncodeUPER() ([]byte, error)      (method, BASIC-UPER)
 *     func DecodeUPER<T>(b []byte) (*<T>, error)      (free fn)
 * and, with -gen-JER only:
 *     func (p *<T>) EncodeJER() ([]byte, error)       (method, minified JER)
 *     func DecodeJER<T>(b []byte) (*<T>, error)       (free fn)
 *
 * Per reachable STRUCT/CHOICE node G:
 *     sizeG(v *G) (fixed, payload uintptr, err error) [+depth on SCC types]
 *     fillG(fa *blockArena, slot unsafe.Pointer, v *G) error
 *     readG(slot unsafe.Pointer) *G
 * Nested-only nodes (an inline CHOICE wrapper / the open-type value union)
 * are INLINED at their host member: their members' offsets are composite
 * consts off<Host><Mem><Inner> (go_flat.c's go_off_const2 form), and their
 * Go value rides the host's field (V.<Alt> where V's type is the minted
 * union struct).
 *
 * Ownership (the Go<->Flat ownership rule): Encode = one asn1cgo_block_alloc block -> fill through
 * the two-region bump allocator (fixed structs from the front, variable
 * payloads from the rear) -> the C entry point -> C.GoBytes copy ->
 * asn1cgo_buf_free + asn1cgo_block_free, deferred on every path; no Go pointer is
 * stored in C memory, no runtime.Pinner. Decode = the C entry point (arena
 * owned C-side, handed to Go) -> read (every []byte/string a fresh Go
 * allocation; nothing aliases the arena) -> asn1cgo_arena_free on every
 * path including error returns. No package-level C state; each call owns
 * its arena -> safe for concurrent use.
 *
 * Mapping (App. G.2) — ONE member walk per node emits size+fill+read in
 * parallel so the three cannot drift:
 *   prim int32_t/int64_t/uint64_t/double: inline scalar copy.
 *   prim _bool32: v != 0 <-> bool.
 *   prim asn1cgo_bytes_flat: writeBytesField/readBytesField (a `string` Go
 *     field bridges through string()/[]byte conversions).
 *   prim asn1cgo_bits_flat: writeBitsField/readBitsField. A foreign
 *     package's BitString field type is a distinct Go type — the bridges
 *     convert field-wise.
 *   starred member (OPTIONAL *T, or a by-value-in-Go recursion break whose
 *     Flat slot is a pointer): nil -> the slot stays NULL; else allocStruct
 *     + fill. A NON-optional starred slot decoding to NULL is E_INTERNAL
 *     (App. G.2 last row).
 *   unstarred ref/nested: fill in place at the slot.
 *   a SEQ-OF-shaped target (FLT_SEQOF node or nested seqof member): the
 *     {items,count} header is inline; the item array is one allocStruct
 *     (n * item size); nil and empty slices both count 0.
 *   CHOICE (present-first node): write present + switch; a selected data
 *     alt whose Go pointer is nil -> E_CHOICE_BAD (before any cgo call);
 *     a NULL alt (no Go field, no slot) only validates present;
 *     PrNothing -> E_CHOICE_NOTHING; unknown -> E_CHOICE_BAD. Non-selected
 *     alts are ignored (not read, not validated).
 *
 * Depth: types in a recursion SCC thread a depth counter through
 * size + fill; depth > ASN1CGO_MAX_DEPTH (64) -> E_DEPTH before any C
 * call. read does not thread depth: the C decoder's recursion is bounded
 * by the ASN1CGO_C_STACK_MAX byte budget (asn1c's stack guard, armed in the
 * decode entry), sized so any input within ASN1CGO_MAX_DEPTH fits; deeper
 * input either trips that guard (E_DECODE) or is rejected by the depth check
 * in *_from_tree (E_DEPTH) before any Go-side read.
 *
 * Errors: every returned error is *rt.Error (asn1cgo-rt/rt/errors.go
 * — the ONE Go error surface). Glue-originated errors construct rt.Error
 * directly; C-originated ones goErr-copy the C struct through this
 * package's err.h-typed cgo preamble (the C struct type identity is by
 * declaration — the same C header the rt package includes).
 *
 * Cgo budget: Encode = asn1cgo_block_alloc(1) + entry(1) +
 * asn1cgo_buf_free(1) + asn1cgo_block_free(1) = 4; Decode = entry(1) + asn1cgo_arena_free(1) = 2. The
 * sizing/filling pass and C.GoBytes/GoStringN are Go-side only (GoBytes
 * linknames to runtime.gobytes on the pinned toolchain — not a cgocall).
 *
 * Naming: fn bases and layout-const references are camel-mangled from flat
 * IR node names by the SAME two-strip rule go_flat.c applies to layout.go
 * consts, so `sizeof<Camel>Flat`/`off<Camel><Tok>` spell exactly layout.go's
 * declared names; Go type/field names come from the name rows
 * (go_names_rows_*), never re-derived from ASN.1 here.
 *
 * Source layout (the go_glue*.c files share go_glue_internal.h):
 *   go_glue.c         go_glue_emit (the driver) and the import dry run
 *   go_glue_util.c    string / file helpers, layout-const names and asserts,
 *                     the name-row index, the fn registry, Go type text
 *   go_glue_prim.c    BMPString / UniversalString helpers, emit_prim
 *   go_glue_ref.c     emit_ref (a named-type member)
 *   go_glue_member.c  nested members, CHOICE bodies, emit_member
 *   go_glue_fn.c      SEQUENCE OF item helpers, emit_type_fn
 *   go_glue_pkg.c     the PDU API, the shared glue text, the package header
 */
#include "go_glue_internal.h"

/* display labels of IR nodes/members (go_flat.c accessors already
 * declared via go_conv.h's fwd block). */

int glue_failed = 0;
int g_tmpseq = 0;   /* unique temp names per fn (reset in emit_type_fn) */

/* go_glue_emit — the driver (called by go_generate after go_conv_emit).
 * go_module_basename = the go.mod module path (basename or
 * <prefix>/<basename>); go_rt_module = the runtime module's path. */
/* Dry-run support: when g_dry_cb is set, go_glue_emit builds each package's
 * glue exactly as for real but writes nothing, and reports every foreign
 * package that glue.go would import through the callback. */
static void (*g_dry_cb)(const char *mod, const char *foreign, void *ud) = NULL;
static void *g_dry_ud = NULL;

/* glue_foreign_modules — the ONE place that decides which sibling packages
 * a package's glue.go imports: every module (other than `mod`) owning a
 * type the registry holds a fn for. Returns the count; *out is a malloc'd
 * array of borrowed names (caller frees the array), NULL when none. */
static int glue_foreign_modules(const char *mod, const char ***out) {
    const char **fmods = NULL;
    int n_fm = 0, cap_fm = 0;
    for(int i = 0; i < g_n_fns; i++) {
        flat_type *ft_ = go_flat_ir_type(g_fns[i]->ix);
        const char *fm = ft_ ? go_flat_ir_module(ft_) : NULL;
        if(!fm || !*fm || strcmp(fm, mod) == 0) continue;
        int seen = 0;
        for(int j = 0; j < n_fm; j++)
            if(strcmp(fmods[j], fm) == 0) { seen = 1; break; }
        if(seen) continue;
        if(n_fm == cap_fm) {
            cap_fm = cap_fm ? cap_fm * 2 : 8;
            const char **nf = realloc(fmods, (size_t)cap_fm * sizeof(char *));
            if(!nf) { free(fmods); *out = NULL; return 0; }
            fmods = nf;
        }
        fmods[n_fm++] = fm;
    }
    *out = fmods;
    return n_fm;
}

typedef struct {
    const char *module; const char *pkg; flat_type *root;
    const conv_pdu *alias;   /* an alias PDU (Alias ::= Msg), or NULL */
} pdu_ent;

/* kinds whose Go name lives at package level (go_names.c kind_is_package_scoped) */
static int row_kind_package_scoped(const char *k) {
    static const char *const ks[] = { "type", "inline", "choice-pr",
        "choice-const", "enum-const", "value-const", "spec-key", "spec-value",
        "spec-pr", "helper", "default-value" };
    for(size_t i = 0; k && i < sizeof ks / sizeof *ks; i++)
        if(strcmp(k, ks[i]) == 0) return 1;
    return 0;
}

/* pdu_api_clashes — every PDU's Decode<T> / DecodeUPER<T> (and, with
 * -gen-JER, DecodeJER<T>) func must differ from the other package-level names
 * and the other PDUs' API names, and its Encode / EncodeUPER / EncodeJER
 * method from the fields of T's struct. Reports every clash; returns the
 * count. */
static int pdu_api_clashes(const pdu_ent *pdus, int n_pdu) {
    /* the codec infixes of the API names, in emission order: "" (APER),
     * "UPER", "JER" (the last only with -gen-JER) */
    static const char *const codec[] = { "", "UPER", "JER" };
    int bad = 0, ncodec = go_jer_enabled() ? 3 : 2;
    int nrows = go_names_rows_n();
    char **go = calloc((size_t)(n_pdu ? n_pdu : 1), sizeof *go);
    if(!go) return 0;
    for(int i = 0; i < n_pdu; i++)
        go[i] = pdus[i].alias ? strdup(pdus[i].alias->alias_go)
                              : gcamel_flat(go_flat_ir_name(pdus[i].root));
    for(int i = 0; i < n_pdu; i++) {
        const char *mod = pdus[i].module;
        for(int v = 0; v < ncodec; v++) {
            char *fn = gfmt("Decode%s%s", codec[v], go[i]);
            for(int r = 0; r < nrows; r++) {
                const char *rm = go_names_row_module(r), *rn = go_names_row_goname(r);
                const char *rk = go_names_row_kind(r);
                if(!rm || !rn || strcmp(rm, mod) != 0 || strcmp(rn, fn) != 0
                   || !row_kind_package_scoped(rk)) continue;
                fprintf(stderr, "asn1cgo: collision in module %s: %s <- %s (pdu-func) and %s (%s)\n",
                        mod, fn, go[i], rn, rk);
                bad++;
            }
            for(int j = i + 1; j < n_pdu; j++) {
                if(strcmp(pdus[j].module, mod) != 0) continue;
                for(int w = 0; w < ncodec; w++) {
                    char *f2 = gfmt("Decode%s%s", codec[w], go[j]);
                    if(strcmp(fn, f2) == 0) {
                        fprintf(stderr, "asn1cgo: collision in module %s: %s <- %s (pdu-func) and %s (pdu-func)\n",
                                mod, fn, go[i], go[j]);
                        bad++;
                    }
                    free(f2);
                }
            }
            free(fn);
        }
        for(int v = 0; v < ncodec; v++) {
            char *m = gfmt("Encode%s", codec[v]);
            for(int r = 0; r < nrows; r++) {
                const char *rm = go_names_row_module(r), *rn = go_names_row_goname(r);
                const char *rk = go_names_row_kind(r), *ro = go_names_row_sf_owner(r);
                if(!rm || !rn || !rk || !ro || strcmp(rk, "field") != 0
                   || strcmp(rm, mod) != 0 || strcmp(ro, go[i]) != 0
                   || strcmp(rn, m) != 0) continue;
                fprintf(stderr, "asn1cgo: collision in module %s: %s.%s <- method and field %s\n",
                        mod, go[i], m, rn);
                bad++;
            }
            free(m);
        }
    }
    for(int i = 0; i < n_pdu; i++) free(go[i]);
    free(go);
    return bad;
}

int go_glue_emit(const char *go_outdir, const char *go_module_basename,
                 const char *go_rt_module);
int
go_glue_emit(const char *go_outdir, const char *go_module_basename,
             const char *go_rt_module) {
    if(!go_outdir || !*go_outdir) return 0;
    if(glue_failed) return -1;

    /* reset the registry (a second -Fgo process reuse never sees stale) */
    for(int i = 0; i < g_n_fns; i++) {
        free(g_fns[i]->sz); free(g_fns[i]->fill); free(g_fns[i]->read);
        free(g_fns[i]);
    }
    free(g_fns); g_fns = NULL; g_n_fns = g_cap_fns = 0;
    glue_failed = 0;

    /* group the PDU roots per package (module), mirroring go_conv_emit's
     * package derivation (go_flat_ir_module of the resolved root). */
    int n = go_flat_ir_n_types();
    int n_pdus = 0;
    for(int p = 0; p < /* g_conv_n_pdus */ 0 + g_conv_n_pdus; p++) n_pdus++;
    /* (n_pdus via the table below) */

    pdu_ent *pdus = NULL;
    int n_pdu_e = 0, cap_pdu_e = 0;
    for(int p = 0; p < g_conv_n_pdus; p++) {
        flat_type *rt_ = go_flat_ir_ref_resolve(g_conv_pdus[p].cid);
        if(!rt_) continue;
        const char *mod = go_flat_ir_module(rt_);
        if(!mod || !*mod) continue;
        /* an alias PDU's API lives in the alias's own package */
        if(g_conv_pdus[p].alias_cid) mod = g_conv_pdus[p].alias_module;
        if(n_pdu_e == cap_pdu_e) {
            cap_pdu_e = cap_pdu_e ? cap_pdu_e * 2 : 16;
            pdus = realloc(pdus, (size_t)cap_pdu_e * sizeof(pdu_ent));
            if(!pdus) { GFAIL("oom"); return -1; }
        }
        pdus[n_pdu_e].module = mod;
        pdus[n_pdu_e].pkg = NULL;
        pdus[n_pdu_e].root = rt_;
        pdus[n_pdu_e].alias = g_conv_pdus[p].alias_cid ? &g_conv_pdus[p] : NULL;
        n_pdu_e++;
    }
    (void)n; (void)n_pdus;

    /* PDU API name clashes (not in the dry run: it would print twice) */
    if(!g_dry_cb && pdu_api_clashes(pdus, n_pdu_e)) {
        free(pdus);
        glue_failed = 1;
        return -1;
    }

    /* distinct owning modules, first-seen order */
    const char **mods = NULL;
    int n_mods = 0, cap_mods = 0;
    for(int i = 0; i < n_pdu_e; i++) {
        int seen = 0;
        for(int j = 0; j < n_mods; j++)
            if(strcmp(mods[j], pdus[i].module) == 0) { seen = 1; break; }
        if(seen) continue;
        if(n_mods == cap_mods) {
            cap_mods = cap_mods ? cap_mods * 2 : 8;
            mods = realloc(mods, (size_t)cap_mods * sizeof(char *));
            if(!mods) { GFAIL("oom"); return -1; }
        }
        mods[n_mods++] = pdus[i].module;
    }
    /* a module that owns a Default func gets a package too, PDU or not */
    for(int k = 0, nd = go_names_dflt_n(); k < nd; k++) {
        const struct go_dflt_fn *df = go_names_dflt_at(k);
        if(!df || !df->module || !*df->module
           || !go_flat_ir_ref_resolve(df->root_cid)) continue;
        int seen = 0;
        for(int j = 0; j < n_mods; j++)
            if(strcmp(mods[j], df->module) == 0) { seen = 1; break; }
        if(seen) continue;
        if(n_mods == cap_mods) {
            cap_mods = cap_mods ? cap_mods * 2 : 8;
            mods = realloc(mods, (size_t)cap_mods * sizeof(char *));
            if(!mods) { GFAIL("oom"); return -1; }
        }
        mods[n_mods++] = df->module;
    }

    int rc = 0;
    for(int m = 0; m < n_mods && rc == 0; m++) {
        const char *mod = mods[m];
        char *pkg = gmodule_pkg(mod);
        g_emit_mod = mod;

        /* fresh fn registry per package (local unexported fns per package) */
        for(int i = 0; i < g_n_fns; i++) {
            free(g_fns[i]->sz); free(g_fns[i]->fill); free(g_fns[i]->read);
            free(g_fns[i]);
        }
        free(g_fns); g_fns = NULL; g_n_fns = g_cap_fns = 0;
        item_helpers_reset();
        for(int i = 0; i < g_n_loconsts; i++) free(g_loconsts[i].name);
        free(g_loconsts); g_loconsts = NULL; g_n_loconsts = g_cap_loconsts = 0;
        gsmap_free(&g_loconst_seen);
        asserts_reset();   /* fresh assert block per package */
        glue_failed = 0;

        const char *module_name = go_module_basename ? go_module_basename : "";

        /* the flat header name for this package */
        const char *pfx = asn1c_prefix(); if(!pfx) pfx = "";
        char *flat_hdr = gfmt("%s%s_flat.h", pfx, pkg);
        /* foreign flat headers this package's members reference (mirror
         * go_conv_emit's include derivation: refs + seqof elems + nested) */

        /* the PDU entry-point extern decls of THIS package's roots. The
         * Flat arg type is spelled via this preamble's own flat-header
         * include (cgo typedefs don't cross packages — the C names come
         * straight from the included headers). */
        char *pdu_ext = strdup("");
        for(int i = 0; i < n_pdu_e; i++) {
            if(strcmp(pdus[i].module, mod) != 0) continue;
            flat_type *rt2 = pdus[i].root;
            char *tb = pdus[i].alias
                ? gfmt("%s%s", asn1c_prefix() ? asn1c_prefix() : "", pdus[i].alias->alias_cid)
                : conv_tree_base(rt2);
            char *flatn = gown(go_flat_ir_name(rt2));
            if(!tb || !*tb || !*flatn) { free(tb); free(flatn); continue; }
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_encode_%s(const %s *in, asn1cgo_buf *out, asn1cgo_err *err);\n",
                tb, flatn));
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_decode_%s(const uint8_t *buf, size_t len, struct asn1cgo_arena **arena_out, %s **out, asn1cgo_err *err);\n",
                tb, flatn));
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_xer_%s(const %s *in, asn1cgo_buf *xer_out, asn1cgo_err *err);\n",
                tb, flatn));
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_uperenc_%s(const %s *in, asn1cgo_buf *out, asn1cgo_err *err);\n",
                tb, flatn));
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_uperdec_%s(const uint8_t *buf, size_t len, struct asn1cgo_arena **arena_out, %s **out, asn1cgo_err *err);\n",
                tb, flatn));
            if(go_jer_enabled()) {
                pdu_ext = gam(pdu_ext, gfmt(
                    "extern int asn1cgo_jerenc_%s(const %s *in, asn1cgo_buf *out, asn1cgo_err *err);\n",
                    tb, flatn));
                pdu_ext = gam(pdu_ext, gfmt(
                    "extern int asn1cgo_jerdec_%s(const uint8_t *buf, size_t len, struct asn1cgo_arena **arena_out, %s **out, asn1cgo_err *err);\n",
                    tb, flatn));
            }
            free(tb); free(flatn);
        }
        /* the Default helpers' externs (SEQUENCE / SET / SEQUENCE OF / SET OF
         * DEFAULT members of this package) */
        for(int k = 0, nd = go_names_dflt_n(); k < nd; k++) {
            const struct go_dflt_fn *df = go_names_dflt_at(k);
            flat_type *dr = df && df->module && strcmp(df->module, mod) == 0
                                ? go_flat_ir_ref_resolve(df->root_cid) : NULL;
            if(!dr) continue;
            char *flatn = gown(go_flat_ir_name(dr));
            pdu_ext = gam(pdu_ext, gfmt(
                "extern int asn1cgo_dflt_%s(struct asn1cgo_arena **arena_out, %s **out, asn1cgo_err *err);\n",
                df->cname, flatn));
            free(flatn);
        }
        /* the package flat header (all fn signatures' Flat types) */
        /* a package of aliases only (AlX ::= AlSeq) has no Flat nodes and
         * so no flat header of its own */
        int own_flat = 0;
        for(int i = 0; i < go_flat_ir_n_types() && !own_flat; i++) {
            const char *tm = go_flat_ir_module(go_flat_ir_type(i));
            if(tm && strcmp(tm, mod) == 0) own_flat = 1;
        }
        char *flat_incs2 = own_flat ? gfmt("#include \"%s\"\n", flat_hdr)
                                    : strdup("");
        /* the flat header of the target of an alias PDU of this package
         * defined in another package (its Flat type types the externs) */
        for(int i = 0; i < n_pdu_e; i++) {
            if(!pdus[i].alias || strcmp(pdus[i].module, mod) != 0) continue;
            const char *tm = go_flat_ir_module(pdus[i].root);
            if(!tm || strcmp(tm, mod) == 0) continue;
            char *tpk = gmodule_pkg(tm);
            char *th = gfmt("#include \"%s%s_flat.h\"\n", pfx, tpk);
            free(tpk);
            if(!strstr(flat_incs2, th)) flat_incs2 = gam(flat_incs2, th);
            else free(th);
        }
        gsb sb = {0};
        sb_set(&sb, pkg_header(module_name, pkg, flat_hdr, flat_incs2, pdu_ext,
                               go_rt_module));
        sb_a(&sb, "\n");
        sb_a(&sb, GLUE_STATICS);
        /* (the BITSTR substitution moved below: it now runs where the bits
         * helpers are conditionally appended, after the fn bodies exist) */
        sb_a(&sb, "\n");

        /* queue every PDU root's fns + API (fn queueing fills the registry
         * transitively) */
        for(int i = 0; i < n_pdu_e && !glue_failed; i++) {
            if(strcmp(pdus[i].module, mod) != 0) continue;
            emit_pdu_api(pdus[i].root, pdus[i].alias, &sb);
        }
        /* the owners' readers the Default funcs call */
        for(int k = 0, nd = go_names_dflt_n(); k < nd && !glue_failed; k++) {
            const struct go_dflt_fn *df = go_names_dflt_at(k);
            flat_type *dr = df && df->module && strcmp(df->module, mod) == 0
                                ? go_flat_ir_ref_resolve(df->root_cid) : NULL;
            if(dr) emit_type_fn(dr);
        }
        /* the fns, reverse queue order (callees first) */
        for(int i = g_n_fns - 1; i >= 0 && !glue_failed; i--)
            emit_fn_text(g_fns[i], &sb);

        /* the exported Default funcs */
        for(int k = 0, nd = go_names_dflt_n(); k < nd && !glue_failed; k++) {
            const struct go_dflt_fn *df = go_names_dflt_at(k);
            flat_type *dr = df && df->module && strcmp(df->module, mod) == 0
                                ? go_flat_ir_ref_resolve(df->root_cid) : NULL;
            if(!dr) continue;
            if(!df->field_type || !*df->field_type) { GFAIL("DEFAULT member without a Go type"); break; }
            char *cam = gcamel_flat(go_flat_ir_name(dr));
            char *flatn = gown(go_flat_ir_name(dr));
            char *path = strdup("");
            for(int q = 0; q < df->ngo; q++)
                path = gam(path, gfmt(".%s", df->gopath[q]));
            sb_am(&sb, gfmt(
                "// %s returns the ASN.1 DEFAULT of %s (a new value on each call).\n"
                "// The Go zero value is not the DEFAULT: set the field explicitly.\n"
                "func %s() %s {\n"
                "\tvar cerr C.asn1cgo_err\n"
                "\tvar arena *C.asn1cgo_arena\n"
                "\tvar flat *C.%s\n"
                "\tif rc := C.asn1cgo_dflt_%s(&arena, &flat, &cerr); rc != 0 {\n"
                "\t\tpanic(\"asn1c: DEFAULT of %s (%s): \" + goErr(&cerr).Error())\n"
                "\t}\n"
                "\tv, err := read%s(unsafe.Pointer(flat))\n"
                "\tC.asn1cgo_arena_free(arena)\n"
                "\tif err != nil {\n"
                "\t\tpanic(\"asn1c: DEFAULT of %s (%s): \" + err.Error())\n"
                "\t}\n"
                "\treturn v%s\n"
                "}\n\n",
                df->goname, df->label, df->goname, df->field_type, flatn,
                df->cname, df->label, df->field_type, cam, df->label,
                df->field_type, path));
            free(cam); free(flatn); free(path);
        }

        /* the SEQ-OF item helper triples (first-reference order; the fns
         * they call are already emitted above) */
        for(int i = 0; i < g_n_items && !glue_failed; i++) {
            sb_a(&sb, g_items[i].sz);
            sb_a(&sb, g_items[i].fill);
            sb_a(&sb, g_items[i].read);
        }

        /* the bits helpers, only when this package's emitted bodies use
         * them (a package with no BIT STRING would otherwise carry two
         * helpers typed at an undefined name): resolve the STATICS marker
         * IN PLACE — the historical slot next to the bytes/string pair, so
         * bits-carrying packages stay byte-identical — substituted with
         * GLUE_BITS when the assembled fn text references the pair,
         * deleted otherwise. The chunk's BITSTR placeholder resolves here
         * too, with the fn bodies already present. */
        {
            /* emit time: substitute BITSTR only when used — freeing bsname
             * otherwise would be the only alloc; keep it simple, both paths
             * free it at scope end */
            int use_bits = strstr(sb.p, "writeBitsField(") != NULL
                        || strstr(sb.p, "readBitsField(") != NULL;
            char *bsname = local_bitstring();
            char *out = strdup("");
            const char *p2 = sb.p, *q;
            const char *m1 = "//__GLUE_WRITEBITS__\n";
            const char *m2 = "//__GLUE_READBITS__\n";
            size_t l1 = strlen(m1), l2 = strlen(m2);
            while((q = strstr(p2, m1)) != NULL) {
                char *seg = malloc((size_t)(q - p2) + 1);
                if(seg) {
                    memcpy(seg, p2, (size_t)(q - p2));
                    seg[q - p2] = 0;
                    out = ga(out, seg);
                    free(seg);
                }
                if(use_bits)
                    out = ga(out, GLUE_WRITE_BITS);
                p2 = q + l1;
            }
            while((q = strstr(p2, m2)) != NULL) {
                char *seg = malloc((size_t)(q - p2) + 1);
                if(seg) {
                    memcpy(seg, p2, (size_t)(q - p2));
                    seg[q - p2] = 0;
                    out = ga(out, seg);
                    free(seg);
                }
                if(use_bits)
                    out = ga(out, GLUE_READ_BITS);
                p2 = q + l2;
            }
            out = ga(out, p2);
            if(use_bits) {
                /* substitute BITSTR across the WHOLE package text (the
                 * chunk + any fn bodies that still carry the placeholder) */
                char *sub = strdup("");
                const char *needle = "BITSTR";
                const char *r = out, *q2;
                size_t nl = strlen(needle);
                while((q2 = strstr(r, needle)) != NULL) {
                    /* whole identifiers only: a generated name that merely
                     * contains the text (a type BITSTRING-Count, a value
                     * union alt BIT_STRING -> BITSTRING) stays intact */
                    int whole = !glue_ident_char(q2[nl])
                                && (q2 == out || !glue_ident_char(q2[-1]));
                    size_t keep = (size_t)(q2 - r) + (whole ? 0 : nl);
                    char *seg = malloc(keep + 1);
                    if(seg) {
                        memcpy(seg, r, keep);
                        seg[keep] = 0;
                        sub = ga(sub, seg);
                        free(seg);
                    }
                    if(whole) sub = ga(sub, bsname);
                    r = q2 + nl;
                }
                sub = ga(sub, r);
                free(out); out = sub;
            }
            sb_set(&sb, out);
            free(bsname);
        }

        /* BMPString / UniversalString conversion helpers, only when this
         * package's bodies use them (appended after the bodies, so a package
         * without such a type is unchanged). */
        {
            int use_bmp = strstr(sb.p, "bmpLen(") != NULL
                       || strstr(sb.p, "BMPField(") != NULL;
            int use_univ = strstr(sb.p, "univLen(") != NULL
                        || strstr(sb.p, "UnivField(") != NULL;
            int use_oid = strstr(sb.p, "oidLen(") != NULL
                       || strstr(sb.p, "OIDField(") != NULL;
            if(use_bmp || use_univ || use_oid) {
                sb_a(&sb, GLUE_STRCONV_COMMON);
                if(use_bmp) sb_a(&sb, GLUE_STRCONV_BMP);
                if(use_univ) sb_a(&sb, GLUE_STRCONV_UNIV);
                if(use_oid) sb_a(&sb, GLUE_STRCONV_OID);
            }
        }

        /* sweep: assert EVERY own-package node's const set, not only
         * the ones this package's fns dereference (qconst's first-touch
         * recording below the fn bodies covers only the used subset — an
         * own layout.go declares all its package's nodes; a package whose
         * fns touch just a few of them left the rest unasserted, and the
         * exactly one assert per layout const, keyed to its Go-side
         * value). Foreign nodes stay
         * usage-keyed: their consts reach THIS glue.go only through fn
         * copies that use them, so the sweep would assert foreign nodes
         * whose const set this package never re-declared. */
        for(int i = 0; i < go_flat_ir_n_types(); i++) {
            flat_type *t = go_flat_ir_type(i);
            const char *tm = go_flat_ir_module(t);
            const char *tn = go_flat_ir_name(t);
            if(!tm || !tn || !*tn || strcmp(tm, mod) != 0) continue;
            /* nested_only dotted nodes declare NO consts of their own in
             * layout.go (their offsets exist only as the host's composite
             * consts, asserted by the host's own node_asserts row) —
             * asserting them here would emit inner-relative asserts whose
             * generated names collide with the host's composite spellings
             * at different values. */
            if(go_flat_ir_is_nested_only(t)) continue;
            node_asserts(t);
        }

        /* the glue-local layout consts for FOREIGN nodes this package emits
         * fn copies of (App. G keeps layout.go consts unexported; the
         * self-contained glue re-declares them locally; colloquial names:
         * same const spelling, local package scope — no collision because
         * the owning decl never crosses packages). */
        if(g_n_loconsts > 0) {
            sb_a(&sb,
                "// glue-local layout consts of foreign-package nodes whose fn\n"
                "// copies live here (the glue is self-contained per package; the\n"
                "// owning package's layout.go consts are unexported).\n");
            for(int i = 0; i < g_n_loconsts; i++)
                sb_am(&sb, gfmt("const %s = %ld\n",
                                   g_loconsts[i].name, g_loconsts[i].value));
            sb_a(&sb, "\n");
        }

        /* close the layout-const verification gap at COMPILE time.
         * qconst recorded (during fn emission above) one _Static_assert per
         * layout const this glue.go's arms dereference — own layout.go
         * consts AND the glue-local foreign re-declarations just emitted —
         * keyed to the cspec flat headers this preamble already includes
         * (a foreign node's asserts read the same header its consts were
         * re-declared from). Splice <stddef.h> + the asserts into the
         * preamble just before its closing comment marker; the fn bodies
         * above then reference consts the C compiler has verified against
         * the very headers the Flat memory layout comes from. The fixed
         * rt/shared asserts (asn1cgo_bytes_flat / asn1cgo_bits_flat,
         * rt/types.h) cover the GLUE_STATICS const block's rt consts the
         * same way, and the align* consts (allocator alignment facts with
         * no Flat host of their own) each get an _Alignof assert against
         * the C type they size (void star, int64_t, int32_t; stdint.h comes with
         * rt/types.h). */
        {
            char *blob = gfmt(
                "#include <stddef.h>\n"
                "// compile-time layout-const checks (own layout.go consts\n"
                "// + glue-local foreign re-declarations; a wrong const fails the\n"
                "// build naming the const).\n"
                "_Static_assert(sizeof(asn1cgo_bytes_flat) == 16, \"sizeofBytesFlat\");\n"
                "_Static_assert(offsetof(asn1cgo_bytes_flat, buf) == 0, \"offBytesFlatBuf\");\n"
                "_Static_assert(offsetof(asn1cgo_bytes_flat, len) == 8, \"offBytesFlatLen\");\n"
                "_Static_assert(sizeof(asn1cgo_bits_flat) == 24, \"sizeofBitsFlat\");\n"
                "_Static_assert(offsetof(asn1cgo_bits_flat, buf) == 0, \"offBitsFlatBuf\");\n"
                "_Static_assert(offsetof(asn1cgo_bits_flat, len) == 8, \"offBitsFlatLen\");\n"
                "_Static_assert(offsetof(asn1cgo_bits_flat, bits_unused) == 16, \"offBitsFlatBitsUnused\");\n"
                "_Static_assert(_Alignof(void *) == 8, \"alignPtr\");\n"
                "_Static_assert(_Alignof(int64_t) == 8, \"alignInt64\");\n"
                "_Static_assert(_Alignof(int32_t) == 4, \"alignInt32\");\n"
                "%s",
                g_asserts ? g_asserts : "");
            /* splice before the preamble's closing comment marker + import */
            char *mark = strstr(sb.p, "*/\nimport \"C\"");
            if(mark) {
                size_t off = (size_t)(mark - sb.p);
                size_t tl = strlen(sb.p), il = strlen(blob);
                char *ns = malloc(tl + il + 1);
                if(ns) {
                    memcpy(ns, sb.p, off);
                    memcpy(ns + off, blob, il);
                    memcpy(ns + off + il, sb.p + off, tl - off + 1);
                    sb_set(&sb, ns);
                }
            }
            free(blob);
        }

        /* the sibling-package imports this package's fns qualified through
         * every registry entry whose module is foreign needs its
         * package in the import block. Appended to the header's import
         * block by tracking the distinct foreign modules of the registry
         * and splicing one import line each before the final ")" of the
         * import block pkg_header emitted. */
        {
            const char **fmods = NULL;
            int n_fm = glue_foreign_modules(mod, &fmods);
            if(g_dry_cb)
                for(int j = 0; j < n_fm; j++)
                    g_dry_cb(mod, fmods[j], g_dry_ud);
            if(n_fm > 0 && fmods) {
                /* splice INTO the import block at the gofmt-sorted
                 * position: the block's lines come from pkg_header
                 * (rt-alias first, then math/runtime/strconv/unsafe) — insert
                 * each foreign line before the first existing line that
                 * sorts AFTER it (gofmt order), else before the closing
                 * paren. */
                char *blk = strstr(sb.p, "import (");
                char *bend = blk ? strchr(blk + 8, ')') : NULL;
                if(blk && bend) {
                    for(int j = 0; j < n_fm; j++) {
                        char *fp = gmodule_pkg(fmods[j]);
                        char *line = gfmt("\t\"%s/%s\"\n", module_name, fp);
                        const char *lcmp = line + 2;   /* skip \t" */
                        size_t ll2 = strlen(lcmp) - 1; /* minus \n */
                        char *ins = blk + 8;
                        while(ins < bend) {
                            char *le = strchr(ins, '\n');
                            if(!le || le > bend) le = bend;
                            if(le > ins + 2 && ins[0] == '\t' && ins[1] == '"') {
                                size_t el = (size_t)(le - ins) - 2;
                                if(strncmp(ins + 2, lcmp, el > ll2 ? ll2 : el) > 0)
                                    break;
                            }
                            ins = le + 1;
                        }
                        if(ins > bend) ins = bend;
                        size_t off = (size_t)(ins - sb.p);
                        size_t tl = strlen(sb.p), il = strlen(line);
                        char *ns = malloc(tl + il + 1);
                        if(ns) {
                            memcpy(ns, sb.p, off);
                            memcpy(ns + off, line, il);
                            memcpy(ns + off + il, sb.p + off, tl - off + 1);
                            sb_set(&sb, ns);
                        }
                        /* re-anchor: the splice moved everything after ins */
                        blk = strstr(sb.p, "import (");
                        bend = blk ? strchr(blk + 8, ')') : NULL;
                        free(line); free(fp);
                        if(!blk || !bend) break;
                    }
                } else {
                    /* no import block found (shouldn't happen): old
                     * behavior — append before the close. */
                    char *ip = strstr(sb.p, "\t\"unsafe\"\n)\n");
                    if(ip) {
                        char *ins = strdup("");
                        for(int j = 0; j < n_fm; j++) {
                            char *fp = gmodule_pkg(fmods[j]);
                            ins = gam(ins, gfmt("\t\"%s/%s\"\n", module_name, fp));
                            free(fp);
                        }
                        size_t off = (size_t)(ip - sb.p) + strlen("\t\"unsafe\"\n");
                        size_t tl = strlen(sb.p), il = strlen(ins);
                        char *ns = malloc(tl + il + 1);
                        if(ns) {
                            memcpy(ns, sb.p, off);
                            memcpy(ns + off, ins, il);
                            memcpy(ns + off + il, sb.p + off, tl - off + 1);
                            sb_set(&sb, ns);
                        }
                        free(ins);
                    }
                }
            }
            free(fmods);
        }

        if(glue_failed) { rc = -1; }
        else if(g_dry_cb) {
            /* dry run: nothing is written */
        } else {
            /* gofmt normalization: expand one-line ifs, then trailing
             * newline count. */
            sb_set(&sb, expand_oneline_ifs(reindent_case_blocks(gsb_take(&sb))));
            /* a package without a PDU (only Default funcs) may use none of
             * the optional std imports: drop the unused ones */
            {
                int has_pdu = 0;
                for(int i = 0; i < n_pdu_e; i++)
                    if(strcmp(pdus[i].module, mod) == 0) { has_pdu = 1; break; }
                static const char *const opt[] = { "math", "runtime", "strconv" };
                for(int o = 0; !has_pdu && o < 3; o++) {
                    char *ln = gfmt("\t\"%s\"\n", opt[o]);
                    char *use = gfmt("%s.", opt[o]);
                    char *at = strstr(sb.p, ln);
                    char *endimp = strstr(sb.p, "\n)\n");
                    if(at && endimp && at < endimp && !strstr(endimp, use))
                        memmove(at, at + strlen(ln), strlen(at + strlen(ln)) + 1);
                    free(ln); free(use);
                }
            }
            while(strlen(sb.p) > 1 && sb.p[strlen(sb.p)-1] == '\n'
                  && sb.p[strlen(sb.p)-2] == '\n')
                sb.p[strlen(sb.p)-1] = '\0';
            char *pkgdir = gjoin(go_outdir, pkg);
            if(gmkdir_p(pkgdir) < 0) rc = -1;
            char *path = gjoin(pkgdir, "glue.go");
            if(rc == 0 && gfwrite_all(path, sb.p) < 0) rc = -1;
            free(pkgdir); free(path);
        }
        free(sb.p); free(flat_hdr); free(flat_incs2); free(pdu_ext);
        free(pkg);
        g_emit_mod = NULL;
    }

    for(int i = 0; i < g_n_fns; i++) {
        free(g_fns[i]->sz); free(g_fns[i]->fill); free(g_fns[i]->read);
        free(g_fns[i]);
    }
    free(g_fns); g_fns = NULL; g_n_fns = g_cap_fns = 0;
    asserts_reset();
    free(pdus); free(mods);
    return glue_failed ? -1 : rc;
}

/* go_glue_collect_imports — dry-run the glue emission for every package and
 * report each (module, foreign module) glue.go import through cb, without
 * writing any file. Used by the import-cycle check before emission starts.
 * Returns 0/-1. */
int go_glue_collect_imports(const char *go_module_basename,
                            const char *go_rt_module,
                            void (*cb)(const char *mod, const char *foreign,
                                       void *ud),
                            void *ud);
int
go_glue_collect_imports(const char *go_module_basename,
                        const char *go_rt_module,
                        void (*cb)(const char *mod, const char *foreign,
                                   void *ud),
                        void *ud) {
    g_dry_cb = cb; g_dry_ud = ud;
    int rc = go_glue_emit(".", go_module_basename, go_rt_module);
    g_dry_cb = NULL; g_dry_ud = NULL;
    return rc;
}
