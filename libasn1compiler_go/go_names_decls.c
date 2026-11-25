/*
 * go_names_decls.c — Go module paths, the import set of each package
 * and the types.go declarations (go_emit.c calls go_emit_module_imports
 * and go_emit_module_decls).
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

/* ------------------------------------------------------------------------- */
/* leaf-declaration emission. go_emit.c calls go_emit_module_decls once per
 * module (it owns the FILE); this side owns the row data (name_bag — no
 * struct mirroring across TUs). Although the dump is sorted (module, path,
 * kind, goName), DECLARATION order must be the ASN.1 WALK order (ord) — the
 * emitted code pairs each `type X int32` with ITS const block in ASN.1 order
 * (PrNothing heads its block; alts follow in spec order; a top-level PDU Pr
 * precedes the envelope ValuePr chain it introduces) and a sorted-by-path
 * order would interleave foreign blocks between a decl and its consts. */

struct name_bag *g_emit_bag;

/* g_go_module_path: the go.mod module path — `module <path>` and the
 * qualifier of every generated import line. Unset env: the path IS
 * basename(go_outdir). With ASN1CGO_GO_MODULE_PREFIX set (validated in
 * go_generate), the path is `<prefix>/<basename>`. go_conv/go_glue receive
 * this composed string through their go_module_basename params (every use
 * they make of it is import-path composition). The rt import lines compose
 * from g_go_rt_module_path the same way. Owned by this TU, freed via
 * clear_go_module_paths after the emit chain. */
char *g_go_module_path;
char *g_go_rt_module_path;   /* the rt module path (ASN1CGO_RT_MODULE) */

/* Prefix validation, per Go module-path rules: each '/'-separated segment is
 * a valid path element (same char class + dot rules the basename uses), and
 * the whole value has no leading/trailing '/'. Returns 0 valid, -1 invalid
 * (diagnostic already printed). Same failure route as the basename check. */
int
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
char *path_join2(const char *a, const char *b) {
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

void
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

void
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
 * (helper rows are per-module; go_types_emit_bitstring writes the
 * fixed helper text), and const blocks.
 *
 * Emission order (within one module; fixed order):
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
 * value consts group by governing type across the module (one const block
 * per governing type, e.g. a ProtocolIEID block), which the same per-goType grouping
 * produces: their "owner row" is the governing type's own `type` row.
 */
/* collect_module_imports — the ONE place that decides which sibling
 * packages a module's types.go imports (used by go_emit_module_imports for
 * emission and by the import-cycle check, so they cannot drift). Fills
 * imps[] (sorted, malloc'd package-dir names; caller frees) and returns the
 * count. */
int
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
        } else if(c->kind == GK_TYPE && c->alias_of) {
            /* type AlX pkg.AlSeq */
            const char *dot = strchr(c->alias_of, '.');
            if(dot)
                NOTE_IMPORT(c->alias_of, (size_t)(dot - c->alias_of));
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

/* gfmt_names: printf into a new string (NULL on failure). */
static char *
gfmt_names(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if(n < 0) return NULL;
    char *p = malloc((size_t)n + 1);
    if(!p) return NULL;
    va_start(ap, fmt);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return p;
}

/* emit_ctor: `func New<T>() *T` for a struct row with has_ctor (mark_ctors):
 * a composite literal setting each DEFAULT member to its DEFAULT (a fresh
 * copy for a slice or BitString value, a call for a constructed one) and
 * each mandatory member whose type has a constructor to *New<Type>(). The
 * keys are aligned the way gofmt aligns them. */
static int
emit_ctor(FILE *out, struct name_bag *b, const struct name_row *r,
          const char *module, const int *ordx) {
    int key_w = 0;
    for(int s = 0; s < b->n_rows; s++) {
        const struct name_row *f = &b->rows[ordx[s]];
        if(f->kind != GK_FIELD || f->module != module || !f->sf_owner
           || strcmp(f->sf_owner, r->goName) != 0
           || (f->ctor_dflt < 0 && f->ctor_type < 0))
            continue;
        int w = (int)strlen(f->goName) + 1;
        if(w > key_w) key_w = w;
    }
    if(fprintf(out,
               "\n// New%s returns a new %s holding the ASN.1 DEFAULT of each DEFAULT\n"
               "// member (and of the DEFAULT members of its mandatory members).\n"
               "func New%s() *%s {\n\treturn &%s{\n",
               r->goName, r->goName, r->goName, r->goName, r->goName) < 0)
        return -1;
    for(int s = 0; s < b->n_rows; s++) {
        const struct name_row *f = &b->rows[ordx[s]];
        if(f->kind != GK_FIELD || f->module != module || !f->sf_owner
           || strcmp(f->sf_owner, r->goName) != 0)
            continue;
        char *val = NULL;
        if(f->ctor_dflt >= 0) {
            const struct name_row *d = &b->rows[ordx[f->ctor_dflt]];
            if(d->dflt_form == 2)
                val = gfmt_names("%s{%s}", f->field_type, d->dflt_lit);
            else if(d->dflt_form >= 4)
                val = gfmt_names("%s()", d->goName);
            else
                val = strdup(d->goName);
        } else if(f->ctor_type >= 0) {
            const struct name_row *t = &b->rows[ordx[f->ctor_type]];
            const char *dot = strrchr(f->field_type, '.');
            if(dot)
                val = gfmt_names("*%.*sNew%s()", (int)(dot - f->field_type + 1),
                                 f->field_type, t->goName);
            else
                val = gfmt_names("*New%s()", t->goName);
        } else {
            continue;
        }
        if(!val) return -1;
        int rc = fprintf(out, "\t\t%s:%*s%s,\n", f->goName,
                         key_w - (int)strlen(f->goName), "", val);
        free(val);
        if(rc < 0) return -1;
    }
    return fputs("\t}\n}\n", out) < 0 ? -1 : 0;
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
    /* const rows of this module by the type name they attach to (the part of
     * goType after the last '.'), in walk order: the per-type const blocks
     * below used to rescan every row for each type. */
    gsmulti cidx;
    memset(&cidx, 0, sizeof cidx);
    for(int y = 0; y < b->n_rows; y++) {
        struct name_row *c = &b->rows[ordx[y]];
        if(c->module != module) continue;
        if(c->kind != GK_ENUM_CONST && c->kind != GK_CHOICE_CONST
           && c->kind != GK_VALUE_CONST)
            continue;
        if(c->bit_group || !c->goType) continue;
        const char *dot = strrchr(c->goType, '.');
        gsmulti_add(&cidx, dot ? dot + 1 : c->goType, y);
    }

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
                    if(dr->dflt_form >= 4) continue;   /* a func in glue.go */
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
                    else if(dr->dflt_form == 3)
                        rc = fprintf(out, "var %s %s = %s(%s)\n", dr->goName,
                                     ft, ft, dr->dflt_lit) < 0 ? -1 : 0;
                    else
                        rc = fprintf(out, "var %s = %s{%s}\n", dr->goName, ft,
                                     dr->dflt_lit) < 0 ? -1 : 0;
                }
                if(rc == 0 && r->has_ctor) {
                    rc = emit_ctor(out, b, r, module, ordx);
                    emitted_default = 1;
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
                if(r->alias_of && *r->alias_of) {
                    /* Alias ::= Msg: a defined type over the target */
                    if((prev_block || !wrote_any) && fputs("\n", out) < 0) {
                        rc = -1;
                        break;
                    }
                    if(fprintf(out, "type %s %s\n", r->goName, r->alias_of) < 0)
                        rc = -1;
                    prev_block = 0;
                    wrote_any = 1;
                    break;
                }
                if(r->leaf_kind == GLEAF_NONE) break;  /* constructed, not a struct
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
                 * int32` — each decl is paired with its const block. */
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
                int ncy;
                const int *cys = gsmulti_get(&cidx, r->goName, &ncy);
                for(int q = 0; q < ncy; q++) {
                    struct name_row *c = &b->rows[ordx[cys[q]]];
                    int nw = (int)strlen(c->goName) + 1;
                    int tw = (int)strlen(c->goType) + 1;
                    if(nw > name_w) name_w = nw;
                    if(tw > type_w) type_w = tw;
                    nblk++;
                }
                if(nblk > 0) {
                    if(go_types_emit_const_open(out) < 0) { rc = -1; break; }
                    for(int q = 0; q < ncy && rc == 0; q++) {
                        struct name_row *c = &b->rows[ordx[cys[q]]];
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
     * a constants module: the const lives HERE, its governing type is foreign).
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

    gsmulti_free(&cidx);
    free(ordx);
    return rc;
}
