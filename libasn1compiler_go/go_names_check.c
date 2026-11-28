/*
 * go_names_check.c — the steps after the walk: cross-module
 * qualification of field and slice-element types, the Go import-cycle
 * check, New<T>() constructor marking and the by-value cycle check.
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"
#include <asn1_portable.h>     /* Windows: strndup */

/* qualify_type: cross-module qualification for a named-type reference.
 * `go_name` is the referenced type's Go name; walks the FULL name table (the
 * walk has completed by the time this runs — go_qualify_field_types, below).
 * Returns an owned possibly-qualified copy: `pkg.Name` when the name's only
 * type row lives in another module, `Name` when local or unresolvable (go
 * build fails loudly on a truly unresolvable name — better than guessing). */
static char *
qualify_type(struct name_bag *b, const char *module, const char *go_name) {
    const char *tmod = NULL;
    int local = 0;
    /* the rows named go_name, in row order (indexed once per table size) */
    static gsmulti byname;
    static int byname_rows = -1;
    static struct name_bag *byname_bag;
    if(byname_rows != b->n_rows || byname_bag != b) {
        gsmulti_free(&byname);
        for(int j = 0; j < b->n_rows; j++) {
            struct name_row *t = &b->rows[j];
            if(t->goName && (t->kind == GK_TYPE || t->kind == GK_INLINE
                             || t->kind == GK_SPEC_KEY))
                gsmulti_add(&byname, t->goName, j);
        }
        byname_rows = b->n_rows; byname_bag = b;
    }
    int nj;
    const int *js = gsmulti_get(&byname, go_name, &nj);
    for(int q = 0; q < nj; q++) {
        struct name_row *t = &b->rows[js[q]];
        if(t->module == module) { local = 1; break; }
        if(t->kind == GK_TYPE || t->kind == GK_SPEC_KEY) tmod = t->module;
    }
    if(local || !tmod || tmod == module) return go_own(go_name);
    char *q = go_module_pkg_name(tmod);
    q = go_str_append(q, ".");
    q = go_str_append(q, go_name);
    return q;
}

/* go_qualify_field_types: post-walk prepass — cross-module qualification of
 * every FIELD row's Go type. The walk stores unqualified names (an assignment
 * may be referenced before the walk reaches its own row, so the bag must be
 * complete first — same reason qualify_foreign_const_types is a prepass).
 * Only a BARE name is rewritten: an already-qualified `pkg.Name` (never stored
 * by the walk today; kept idempotent) and primitives (int64, []byte, string,
 * BitString...) never carry a '.'-prefix match and stay untouched. */
void
go_qualify_field_types(struct name_bag *b) {
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
            char *nf = go_str_append(strdup(""), star);
            nf = go_str_append(nf, q);
            free(f->field_type);
            f->field_type = nf;
        }
        free(q);
    }
}

/* go_qualify_slice_elems: post-walk prepass — the cross-module
 * qualification of every slice-owner row's ELEMENT type (the slice side of
 * go_qualify_field_types; the same qualify_type lookup over the same table). A
 * `type X []pkg.Y` alias may reference an element assignment its module
 * references across a module boundary (e.g. a container module's
 * slices over the ...ItemIEs it declares itself — same-module there —
 * and a cross-module element in a future spec); the bare stored name is
 * qualified once the bag is complete. Primitives (int64, []byte, string,
 * BitString) never match a type row and stay untouched. */
void
go_qualify_slice_elems(struct name_bag *b) {
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        /* the target of an alias of a constructed type (type Alias Msg) */
        if(r->kind == GK_TYPE && r->alias_of && *r->alias_of
           && !strchr(r->alias_of, '.')) {
            char *q = qualify_type(b, r->module, r->alias_of);
            free(r->alias_of);
            r->alias_of = q;
        }
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
 *   - types.go: go_collect_module_imports (the same helper emission uses),
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
int
go_check_import_cycles(struct name_bag *b) {
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
            const char **nm = go_xrealloc(mods, (size_t)cap * sizeof(char *));
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
    for(int i = 0; i < n; i++) g.pkg[i] = go_module_pkg_name(mods[i]);

    /* types.go edges */
    for(int i = 0; i < n; i++) {
        char *imps[64];
        int ni = go_collect_module_imports(b, mods[i], imps, 64);
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
 *     go_row_set_leaf text; a reference underlying is BY VALUE. None of the 3
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

/* ctor_key: "<a>\x01<b>[\x01<c>]" (owned). */
static char *
ctor_key(const char *a, const char *b2, const char *c) {
    char *k = go_str_append(strdup(""), a ? a : "");
    k = go_str_append(k, "\x01");
    k = go_str_append(k, b2 ? b2 : "");
    if(c) {
        k = go_str_append(k, "\x01");
        k = go_str_append(k, c);
    }
    return k;
}

static int
ctor_struct_kind(const struct name_row *r) {
    return r->is_struct
        && (r->kind == GK_TYPE || r->kind == GK_INLINE || r->kind == GK_SPEC_KEY);
}

/* go_mark_ctors: decide which structs get a `func New<T>() *T` in types.go:
 * a struct with a DEFAULT member, and (to a fixed point) a struct with a
 * mandatory member (no pointer, no slice, no DEFAULT) whose type is a struct
 * that gets one. Records on each field row what its key in the composite
 * literal is set to (ctor_dflt / ctor_type, as ords). New<T> must not be
 * another package-level name of the module: a clash is reported and fails
 * the run. */
int
go_mark_ctors(struct name_bag *b) {
    gsmulti by_mod, by_pkg, fields, dflts, names;
    memset(&by_mod, 0, sizeof by_mod);
    memset(&by_pkg, 0, sizeof by_pkg);
    memset(&fields, 0, sizeof fields);
    memset(&dflts, 0, sizeof dflts);
    memset(&names, 0, sizeof names);
    int bad = 0;
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        r->has_ctor = 0;
        r->ctor_dflt = r->ctor_type = -1;
        char *k;
        if(ctor_struct_kind(r) && r->goName) {
            k = ctor_key(r->module, r->goName, NULL);
            gsmulti_add(&by_mod, k, i);
            free(k);
            char *pkg = go_module_pkg_name(r->module);
            k = ctor_key(pkg, r->goName, NULL);
            gsmulti_add(&by_pkg, k, i);
            free(k);
            free(pkg);
        }
        if(r->kind == GK_FIELD && r->sf_owner && r->goName) {
            k = ctor_key(r->module, r->sf_owner, NULL);
            gsmulti_add(&fields, k, i);
            free(k);
        }
        if(r->kind == GK_DEFAULT_VALUE && r->dflt_owner && r->dflt_field) {
            k = ctor_key(r->module, r->dflt_owner, r->dflt_field);
            gsmulti_add(&dflts, k, i);
            free(k);
        }
        if(go_kind_is_package_scoped(r->kind) && r->goName) {
            k = ctor_key(r->module, r->goName, NULL);
            gsmulti_add(&names, k, i);
            free(k);
        }
    }
    /* field rows: the DEFAULT row, or the struct row of the member's type */
    int *target = malloc(((size_t)b->n_rows + 1) * sizeof(int));
    if(!target) goto out;
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *f = &b->rows[i];
        target[i] = -1;
        if(f->kind != GK_FIELD || !f->sf_owner || !f->goName) continue;
        char *k = ctor_key(f->module, f->sf_owner, f->goName);
        int n;
        const int *d = gsmulti_get(&dflts, k, &n);
        free(k);
        if(n) {
            f->ctor_dflt = b->rows[d[0]].ord;
            continue;
        }
        const char *t = f->field_type;
        if(!t || !*t || t[0] == '*' || strchr(t, '[')) continue;
        const char *dot = strrchr(t, '.');
        const int *c;
        if(dot) {
            char *pkg = strndup(t, (size_t)(dot - t));
            k = ctor_key(pkg, dot + 1, NULL);
            free(pkg);
            c = gsmulti_get(&by_pkg, k, &n);
        } else {
            k = ctor_key(f->module, t, NULL);
            c = gsmulti_get(&by_mod, k, &n);
        }
        free(k);
        if(n == 1) target[i] = c[0];
    }
    /* the structs with a DEFAULT member */
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *d = &b->rows[i];
        if(d->kind != GK_DEFAULT_VALUE || !d->dflt_owner) continue;
        char *k = ctor_key(d->module, d->dflt_owner, NULL);
        int n;
        const int *o = gsmulti_get(&by_mod, k, &n);
        free(k);
        for(int j = 0; j < n; j++) b->rows[o[j]].has_ctor = 1;
    }
    /* ... and those holding one by value, to a fixed point */
    for(int changed = 1; changed;) {
        changed = 0;
        for(int i = 0; i < b->n_rows; i++) {
            struct name_row *f = &b->rows[i];
            if(target[i] < 0 || !b->rows[target[i]].has_ctor) continue;
            char *k = ctor_key(f->module, f->sf_owner, NULL);
            int n;
            const int *o = gsmulti_get(&by_mod, k, &n);
            free(k);
            for(int j = 0; j < n; j++)
                if(!b->rows[o[j]].has_ctor) {
                    b->rows[o[j]].has_ctor = 1;
                    changed = 1;
                }
        }
    }
    for(int i = 0; i < b->n_rows; i++)
        if(target[i] >= 0 && b->rows[target[i]].has_ctor)
            b->rows[i].ctor_type = b->rows[target[i]].ord;
    /* New<T> is a package-level name of its own */
    for(int i = 0; i < b->n_rows; i++) {
        struct name_row *r = &b->rows[i];
        if(!r->has_ctor) continue;
        char *fn = go_str_append(strdup("New"), r->goName);
        char *k = ctor_key(r->module, fn, NULL);
        int n;
        const int *o = gsmulti_get(&names, k, &n);
        for(int j = 0; j < n; j++) {
            struct name_row *q = &b->rows[o[j]];
            fprintf(stderr, "asn1cgo: collision in module %s: %s <- %s "
                    "(constructor) and %s (%s)\n", r->module, fn, r->path,
                    q->path, g_go_kind_tag[q->kind]);
            bad++;
        }
        free(k);
        free(fn);
    }
    free(target);
out:
    gsmulti_free(&by_mod);
    gsmulti_free(&by_pkg);
    gsmulti_free(&fields);
    gsmulti_free(&dflts);
    gsmulti_free(&names);
    return bad ? -1 : 0;
}

int
go_check_cycles(struct name_bag *b) {
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
            int *nr = go_xrealloc(vrow, (size_t)nc * sizeof(int));
            if(!nr) { free(vrow); free(vmod); free(vname); return 0; }
            vrow = nr;
            const char **nm = go_xrealloc(vmod, (size_t)nc * sizeof(char *));
            if(!nm) { free(vrow); free(vmod); free(vname); return 0; }
            vmod = nm;
            char **nn2 = go_xrealloc(vname, (size_t)nc * sizeof(char *));
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
                goedge *_ne = go_xrealloc(edg, (size_t)_nc * sizeof(goedge)); \
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
