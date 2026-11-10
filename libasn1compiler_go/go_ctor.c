/*
 * go_ctor.c — one E2AP IE constructor per IOC row.
 *
 * Emitted into <go_outdir>/<X's module pkg>/constructors.go, one function
 * per row of every id-dispatch PROTOCOL-IES object set (procedure-dispatch envelope rows carry
 * no &Value alt payload and get none):
 *
 *   func New<R2(X)><A>(v T) R2(X) {
 *       return R2(X){
 *           Id:          <id value-const goName>,
 *           Criticality: <Criticality enum const goName>,
 *           Value: R2(X)Value{
 *               Present: R2(X)ValuePr<A>,
 *               A:       &v,
 *           },
 *       }
 *   }
 *
 * Names are NOT derived here: every identifier is looked up from the
 * already-computed name rows (the same rows types.go prints — the dump's
 * goName column) or the recorded IOC facts (go_ioc.c: id/criticality as
 * numeric values, plus each column's GOVERNING declared type). The name
 * surfaces used:
 *   X's goName  — the spec-key row whose rawCid == the run-prefixed
 *                 <X_cid> (emit_spec's GK_SPEC_KEY row)
 *   A           — the value-union alt FIELD row under <X>.Value.<alt>
 *                 (goName; alt naming, same token as the Pr const)
 *   T           — that field row's field_type minus the pointer star
 *                 (the alt payload type, a named type)
 *   Id const    — the value-const row whose intval == the IOC row's id
 *                 AND whose goType == the id column's governing declared
 *                 type (the row's id_gov fact — e.g. ProtocolIEID under
 *                 E2AP; never a name shape)
 *   Criticality — the ENUM const whose intval == the row's criticality
 *                 AND whose goType == the criticality column's governing
 *                 type (row's crit_gov), when the class HAS a criticality
 *                 column; a class without one (crit_gov NULL) emits
 *                 constructors WITHOUT the field — that shape is
 *                 supported, not an error
 *
 * Collision rule: two rows minting the same constructor name
 * in one module fails the generator with the standard diagnostic.
 *
 * Which modules: conv_ioc rows with is_envelope == 0 only, attributed to
 * X's module via the spec-key row's module (placement rule — the row table
 * key cid is prefix-stripped; the row lookup finds the module directly).
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asn1c_internal.h"     /* asn1c_prefix (the per-spec prefix rule) */
#include "asn1c_misc.h"

#include "go_conv.h"
#include "go_conv_internal.h"

/* The name-row surface (go_names.c: the same read-only view go_glue.c
 * uses; rows are WALK order here, dump order after the qsort — both are
 * complete by emit time). */
extern int go_names_rows_n(void);
extern const char *go_names_row_module(int i);
extern const char *go_names_row_goname(int i);
extern const char *go_names_row_rawcid(int i);
extern const char *go_names_row_kind(int i);
extern const char *go_names_row_field_type(int i);
extern const char *go_names_row_sf_owner(int i);
extern const char *go_names_row_intval(int i);
extern const char *go_names_row_gotype(int i);

/* module pkg dir + import-path head (go_names.c surfaces, flat-extern). */
extern char *go_ctor_pkg_of(const char *module);
extern const char *go_ctor_module_path(void);

/* path join under go_outdir (go_names.c's mkpath/join are private; local
 * copies keep this TU flat). */
static char *
join_path(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *r = malloc(la + lb + 2);
    if(!r) return NULL;
    memcpy(r, a, la);
    r[la] = '/';
    memcpy(r + la + 1, b, lb + 1);
    return r;
}

/* strip the run prefix off a rawCid for table matching against the
 * prefix-stripped conv spec_cid tokens. */
static const char *
unprefixed(const char *cid) {
    const char *pfx = asn1c_prefix();
    if(cid && pfx && *pfx && strncmp(cid, pfx, strlen(pfx)) == 0)
        return cid + strlen(pfx);
    return cid ? cid : "";
}

/* ---- one constructor's material ------------------------------------------ */

typedef struct {
    char *fn;          /* New<X><A> */
    char *x_go;        /* R2(X) */
    char *module;      /* X's module (the spec-key row's module) */
    char *id_const;    /* value-const goName */
    char *crit_const;  /* Criticality const goName (NULL: class has none) */
    char *id_ref;      /* id const as referenced from X's pkg (qualified if foreign) */
    char *crit_ref;    /* criticality const as referenced (qualified iff foreign) */
    char *present;     /* R2(X)ValuePr<A> goName */
    char *alt_field;   /* A (union field goName) */
    char *alt_type;    /* T (payload type, star stripped) */
    long id;           /* the IOC row's id (wire value, documentation) */
    long crit;         /* the IOC row's criticality (-1 = class has none) */
} ctor_info;

/* goType equality under cross-module qualification: a const's goType may
 * carry its defining package prefix (e2ap_commondatatypes.ProtocolIEID —
 * qualify_foreign_const_types); the recorded governing name is the
 * unqualified R2 form. Equal iff equal OR the qualified suffix matches. */
static int
gotype_is(const char *gt, const char *gov);

/* The criticality enumerand's const goName by ASN.1 value under the row's
 * GOVERNING enum type: the ENUM const rows (kind "enum-const") whose goType
 * == crit_gov and intval matches. The consts live in the module that owns
 * the governing type — scan all rows (module-agnostic) and fail on
 * ambiguity. */
/* (fn, module) pair outputs: malloc'd, freed by caller. */
static char *
criticality_const2(long crit, const char *crit_gov, char **out_mod) {
    char want[32];
    snprintf(want, sizeof want, "%ld", crit);
    char *found = NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        if(strcmp(go_names_row_kind(i) ? go_names_row_kind(i) : "",
                  "enum-const") != 0)
            continue;
        const char *gt = go_names_row_gotype(i);
        if(!gotype_is(gt, crit_gov)) continue;
        const char *iv = go_names_row_intval(i);
        if(!iv || strcmp(iv, want) != 0) continue;
        const char *gn = go_names_row_goname(i);
        if(!gn) continue;
        if(found && strcmp(found, gn) != 0) {
            fprintf(stderr,
                    "asn1cgo: ctor: ambiguous %s const for value %s: %s "
                    "and %s\n", crit_gov, want, found, gn);
            free(found);
            return NULL;
        }
        if(!found) {
            found = strdup(gn);
            if(out_mod) {
                const char *m_ = go_names_row_module(i);
                *out_mod = strdup(m_ ? m_ : "");
            }
        }
    }
    return found;
}

/* goType equality under cross-module qualification: a const's goType may
 * carry its defining package prefix (e2ap_commondatatypes.ProtocolIEID —
 * qualify_foreign_const_types); the recorded governing name is the
 * unqualified R2 form. Equal iff equal OR the qualified suffix matches. */
static int
gotype_is(const char *gt, const char *gov) {
    if(!gt || !gov) return 0;
    if(strcmp(gt, gov) == 0) return 1;
    const char *dot = strrchr(gt, '.');
    return dot && strcmp(dot + 1, gov) == 0;
}

/* The id value-const by numeric id under the row's GOVERNING scalar type:
 * kind "value-const" rows whose intval == id AND goType == id_gov (the
 * id-* assignments are the value consts typed by the class's id column
 * type; distinct values make the pair unique). */
static char *
id_const_by_value2(long id, const char *id_gov, char **out_mod) {
    char want[32];
    snprintf(want, sizeof want, "%ld", id);
    char *found = NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        if(strcmp(go_names_row_kind(i) ? go_names_row_kind(i) : "",
                  "value-const") != 0)
            continue;
        const char *iv = go_names_row_intval(i);
        const char *gn = go_names_row_goname(i);
        const char *gt = go_names_row_gotype(i);
        if(!iv || !gn || strcmp(iv, want) != 0) continue;
        if(!gotype_is(gt, id_gov)) continue;
        if(found && strcmp(found, gn) != 0) {
            fprintf(stderr,
                    "asn1cgo: ctor: ambiguous %s const %ld: %s and %s\n",
                    id_gov, id, found, gn);
            free(found);
            return NULL;
        }
        if(!found) {
            found = strdup(gn);
            if(out_mod) {
                const char *m_ = go_names_row_module(i);
                *out_mod = strdup(m_ ? m_ : "");
            }
        }
    }
    return found;
}

/* printf into a fresh malloc'd string (OOM -> NULL). */
static char *
cfmt2(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if(n < 0) { va_end(ap2); return NULL; }
    char *s = malloc((size_t)n + 1);
    if(s) vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

/* A NAME's defining module's pkg prefix as seen from X's module: "" when
 * the name's declaring module == sk_module ("<pkg>." otherwise); "" too
 * when no declaring row is found (go build fails loudly on a truly
 * foreign name). Malloc'd; caller frees. */
static char *
go_ctor_qualify(const char *name, const char *sk_module, int *qualified) {
    const char *nmod = NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *k = go_names_row_kind(i) ? go_names_row_kind(i) : "";
        if(strcmp(k, "type") != 0 && strcmp(k, "spec-key") != 0
           && strcmp(k, "inline") != 0)
            continue;
        const char *gn = go_names_row_goname(i);
        if(!gn || strcmp(gn, name) != 0) continue;
        nmod = go_names_row_module(i);
        break;
    }
    if(qualified) *qualified = 0;
    if(!nmod || strcmp(nmod, sk_module) == 0)
        return strdup("");
    char *pkg = go_ctor_pkg_of(nmod);
    if(!pkg || !*pkg) { free(pkg); return strdup(""); }
    if(qualified) *qualified = 1;
    char *r = cfmt2("%s.", pkg);
    free(pkg);
    return r;
}

/* Self-prototype (the flat-extern convention the sibling emitters use;
 * the extern in go_names.c is the same spelling). */
int go_ctor_emit(const char *go_outdir);

int
go_ctor_emit(const char *go_outdir) {
    int rc = 0;
    ctor_info *ct = NULL;
    int n_ct = 0;

    for(int i = 0; i < g_conv_n_iocs; i++) {
        const conv_ioc_row *row = &g_conv_iocs[i];
        if(row->is_envelope) continue;   /* procedure-dispatch: no &Value payload ctor */

        /* X's spec-key row: rawCid == <pfx><spec_cid> (the run-prefixed
         * clone tag; emit_spec emitted rawCid=own(x_cid) and the conv row
         * stored the stripped form). */
        const char *sk_module = NULL, *x_go = NULL;
        for(int j = 0; j < go_names_rows_n(); j++) {
            if(strcmp(go_names_row_kind(j) ? go_names_row_kind(j) : "",
                      "spec-key") != 0)
                continue;
            const char *raw = go_names_row_rawcid(j);
            if(!raw || strcmp(unprefixed(raw), row->spec_cid) != 0) continue;
            sk_module = go_names_row_module(j);
            x_go = go_names_row_goname(j);
            break;
        }
        if(!x_go) {
            fprintf(stderr,
                    "asn1cgo: ctor: no spec-key row for IOC table %s — "
                    "cannot emit its constructors\n", row->spec_cid);
            conv_failed_set();
            rc = -1;
            goto out;
        }

        /* A + T: the union alt FIELD row under X's Value union whose
         * path ends .Value.<altIdentifier>. The conv row's alt_token is
         * the union member CID token (go_mk_suffix of the cell value);
         * row_set_field_type recorded "*<AltGo>" on that row. Match by
         * sf_owner == <X>Value and rawCid == alt_token. */
        char *val_owner = NULL;
        {
            size_t n = strlen(x_go) + 6;
            val_owner = malloc(n);
            if(!val_owner) { rc = -1; goto out; }
            snprintf(val_owner, n, "%sValue", x_go);
        }
        const char *alt_go = NULL, *alt_ty = NULL;
        for(int j = 0; j < go_names_rows_n(); j++) {
            if(strcmp(go_names_row_kind(j) ? go_names_row_kind(j) : "",
                      "field") != 0)
                continue;
            const char *own_ = go_names_row_sf_owner(j);
            if(!own_ || strcmp(own_, val_owner) != 0) continue;
            const char *raw = go_names_row_rawcid(j);
            if(!raw || strcmp(unprefixed(raw), row->alt_token) != 0) continue;
            alt_go = go_names_row_goname(j);
            alt_ty = go_names_row_field_type(j);
            break;
        }
        free(val_owner);
        if(!alt_go || !alt_ty || !alt_ty[0]) {
            fprintf(stderr,
                    "asn1cgo: ctor: no union field row for %s alt %s\n",
                    row->spec_cid, row->alt_token);
            conv_failed_set();
            rc = -1;
            goto out;
        }
        const char *star = *alt_ty == '*' ? alt_ty + 1 : alt_ty;

        /* Present const: the choice-const whose rawCid is
         * <X_cid>__value_PR_<AltCid> — its goName is <X>ValuePr<A>. Built
         * from the found pieces (same spelling the walker minted). */
        char *present = NULL;
        {
            size_t n = strlen(x_go) + strlen("ValuePr") + strlen(alt_go) + 1;
            present = malloc(n);
            if(!present) { rc = -1; goto out; }
            snprintf(present, n, "%sValuePr%s", x_go, alt_go);
        }

        /* Id value + Criticality const, each with its
         * DEFINING module (the reference from X's package qualifies a
         * foreign const: e2ap_constants.Id..., e2ap_commondatatypes.-).
         * Both resolve BY GOVERNING TYPE + value — the class's own
         * declared column types, never an E2AP name shape. Two id forms:
         * a REFERENCE cell resolves the governing-typed value const; a
         * LITERAL cell (no value assignment exists) carries the governing
         * type's own conversion of the decimal. A class with no
         * &criticality column (crit_gov NULL) has no Criticality member
         * at all: no lookup, and the constructor omits the field. */
        char *id_mod = NULL, *crit_mod = NULL;
        if(!row->id_gov || !*row->id_gov) {
            /* the walker records the governing name only when the column's
             * declared type resolves; an unresolvable id column must not
             * reach a silently-wrong const. */
            fprintf(stderr,
                    "asn1cgo: ctor: id column of %s has no resolvable "
                    "governing type (row id %ld)\n", row->spec_cid,
                    row->id);
            conv_failed_set();
            rc = -1;
            goto out;
        }
        char *idc = NULL;
        if(!row->id_literal) {
            idc = id_const_by_value2(row->id, row->id_gov, &id_mod);
            if(!idc) {
                fprintf(stderr,
                        "asn1cgo: ctor: no %s-typed const for id %ld "
                        "(row %s)\n", row->id_gov, row->id, row->spec_cid);
                conv_failed_set();
                rc = -1;
                goto out;
            }
        }
        char *critc = NULL;
        if(row->crit_gov) {
            critc = criticality_const2(row->criticality, row->crit_gov,
                                       &crit_mod);
            if(!critc) {
                free(id_mod);
                fprintf(stderr,
                        "asn1cgo: ctor: no %s const for value %ld (row %s)\n",
                        row->crit_gov, row->criticality, row->spec_cid);
                free(idc);
                conv_failed_set();
                rc = -1;
                goto out;
            }
        }

        /* Qualified reference texts (a const defined in another
         * module than X references <pkg>.<Name> from X's package). A
         * literal id has no const: the expression is <Gov>(<decimal>),
         * with <Gov> qualified like a const when its module differs. */
        char *id_ref = NULL, *crit_ref = NULL;
        {
            char *ipkg = NULL, *cpkg = NULL;
            if(row->id_literal) {
                char *q = go_ctor_qualify(row->id_gov, sk_module, NULL);
                if(q) {
                    id_ref = cfmt2("%s%s(%ld)", q, row->id_gov, row->id);
                    free(q);
                }
            } else {
                if(id_mod && strcmp(id_mod, sk_module) != 0)
                    ipkg = go_ctor_pkg_of(id_mod);
                size_t n1 = (ipkg ? strlen(ipkg) + 1 : 0) + strlen(idc) + 1;
                id_ref = malloc(n1);
                if(id_ref) {
                    if(ipkg) snprintf(id_ref, n1, "%s.%s", ipkg, idc);
                    else snprintf(id_ref, n1, "%s", idc);
                }
            }
            if(crit_mod && critc && strcmp(crit_mod, sk_module) != 0)
                cpkg = go_ctor_pkg_of(crit_mod);
            if(critc) {
                size_t n2 = (cpkg ? strlen(cpkg) + 1 : 0) + strlen(critc) + 1;
                crit_ref = malloc(n2);
                if(crit_ref) {
                    if(cpkg) snprintf(crit_ref, n2, "%s.%s", cpkg, critc);
                    else snprintf(crit_ref, n2, "%s", critc);
                }
            } else {
                crit_ref = strdup("");   /* class without a criticality column */
            }
            free(ipkg); free(cpkg);
            if(!id_ref || !crit_ref) {
                free(id_ref); free(crit_ref); free(idc); free(critc);
                free(id_mod); free(crit_mod); free(present);
                rc = -1;
                goto out;
            }
        }
        free(id_mod);
        free(crit_mod);

        /* Name: New + R2(X) + R2(I), where
         * I = the asn1c C ident of the row's ID value reference (dump-borne:
         * the id-const goName = "ProtocolIEID" + R2(I)); a LITERAL id cell
         * has no reference, so I = Id + the decimal itself. */
        char *r2i = NULL;
        {
            if(row->id_literal) {
                size_t n = 24;
                r2i = malloc(n);
                if(r2i) snprintf(r2i, n, "Id%ld", row->id);
            } else {
                /* the const name is <Gov> + R2(I); strip the governing
                 * head — no re-derivation, the length IS the gov's. */
                size_t hl = strlen(row->id_gov);
                if(strncmp(idc, row->id_gov, hl) != 0) {
                    fprintf(stderr,
                            "asn1cgo: ctor: id const %s does not carry the "
                            "%s governing head (row %s id %ld)\n",
                            idc, row->id_gov, row->spec_cid, row->id);
                    free(idc); free(critc); free(id_ref); free(crit_ref);
                    free(present);
                    conv_failed_set();
                    rc = -1;
                    goto out;
                }
                r2i = strdup(idc + hl);
            }
            if(!r2i || !*r2i) {
                fprintf(stderr,
                        "asn1cgo: ctor: empty R2(I) for row %s id %ld\n",
                        row->spec_cid, row->id);
                free(r2i); free(idc); free(critc); free(id_ref); free(crit_ref); free(present);
                conv_failed_set();
                rc = -1;
                goto out;
            }
        }

        /* Collision check + append (unique constructor name per module;
         * two rows minting one name is a generator failure). */
        {
            size_t n = strlen("New") + strlen(x_go) + strlen(r2i) + 1;
            char *fn = malloc(n);
            if(!fn) { free(r2i); free(idc); free(critc); free(id_ref);
                      free(crit_ref); free(present);
                      rc = -1; goto out; }
            snprintf(fn, n, "New%s%s", x_go, r2i);
            free(r2i);
            int dup = 0;
            for(int k = 0; k < n_ct; k++) {
                if(strcmp(ct[k].module, sk_module) == 0
                   && strcmp(ct[k].fn, fn) == 0) { dup = 1; break; }
            }
            if(dup) {
                fprintf(stderr,
                        "asn1cgo: ctor collision in %s: %s (two rows mint "
                        "one name)\n", sk_module, fn);
                free(fn); free(idc); free(critc); free(id_ref);
                free(crit_ref); free(present);
                conv_failed_set();
                rc = -1;
                goto out;
            }
            ctor_info *nc =
                realloc(ct, (size_t)(n_ct + 1) * sizeof(ctor_info));
            if(!nc) { free(fn); free(idc); free(critc); free(id_ref);
                      free(crit_ref); free(present);
                      rc = -1; goto out; }
            ct = nc;
            ct[n_ct].fn = fn;
            ct[n_ct].x_go = strdup(x_go);
            ct[n_ct].module = strdup(sk_module);
            ct[n_ct].id_const = idc;
            ct[n_ct].id_ref = id_ref;
            ct[n_ct].crit_const = critc;
            ct[n_ct].crit_ref = crit_ref;
            ct[n_ct].present = present;
            ct[n_ct].alt_field = strdup(alt_go);
            ct[n_ct].alt_type = strdup(star);
            ct[n_ct].id = row->id;
            ct[n_ct++].crit = row->criticality;
        }
    }

    /* ---- write, grouped by module, one constructors.go per pkg --------- */
    /* Deterministic file order: modules in first-appearance order; fns in
     * table order (IOC row order), which is stable per spec. */
    for(int k = 0; k < n_ct; k++) {
        int earlier = 0;
        for(int j = 0; j < k; j++)
            if(strcmp(ct[j].module, ct[k].module) == 0) { earlier = 1; break; }
        if(earlier) continue;   /* module file already written */

        char *pkg = go_ctor_pkg_of(ct[k].module);
        if(!pkg || !*pkg) { free(pkg); rc = -1; goto out; }
        char *pkgdir = join_path(go_outdir, pkg);
        if(!pkgdir) { free(pkg); rc = -1; goto out; }
        char *fpath = join_path(pkgdir, "constructors.go");
        free(pkgdir);
        if(!fpath) { free(pkg); rc = -1; goto out; }
        FILE *f = fopen(fpath, "w");
        if(!f) {
            fprintf(stderr, "asn1cgo: ctor: cannot write '%s'\n", fpath);
            free(fpath); free(pkg);
            rc = -1;
            goto out;
        }
        free(fpath);
        /* every generated package file opens with the generated-file
         * banner, then carries the amd64 build tag (the emitted-tree
         * convention; a missing tag breaks the build on non-amd64 hosts,
         * so it is mandatory on every file). */
        if(fputs(GO_GENERATED_BANNER, f) < 0
           || fputs("//go:build amd64\n\n", f) < 0
           || fprintf(f, "package %s\n", pkg) < 0) { fclose(f); free(pkg); rc = -1; goto out; }
        /* Cross-module payload types (alt T defined in another package)
         * arrive package-qualified in field_type (qualification ran before
         * the emit passes); the constructor file mirrors types.go's
         * import for every distinct qualifier used here. Import PATH
         * needs the module-path head, supplied by the caller's surface
         * (same rule as go_emit_module_imports: <module path>/<pkg>). */
        {
            const char *mpath = go_ctor_module_path();
            char *imps[64];
            int n_imps = 0;
            for(int j = k; j < n_ct; j++) {
                if(strcmp(ct[j].module, ct[k].module) != 0) continue;
                /* collect over every qualified reference this file makes:
                 * the alt payload type, the Id const, the Criticality const */
                const char *cands[3];
                cands[0] = ct[j].alt_type;
                cands[1] = ct[j].id_ref;
                cands[2] = ct[j].crit_ref;
                for(int ci = 0; ci < 3; ci++) {
                const char *ft = cands[ci];
                const char *dot = ft ? strchr(ft, '.') : NULL;
                if(!dot) continue;
                int seen = 0;
                for(int q = 0; q < n_imps; q++)
                    if(strncmp(imps[q], ft, (size_t)(dot - ft)) == 0
                       && strlen(imps[q]) == (size_t)(dot - ft))
                        { seen = 1; break; }
                if(seen || n_imps >= 64) continue;
                char *p = malloc((size_t)(dot - ft) + 1);
                if(!p) continue;
                memcpy(p, ft, (size_t)(dot - ft));
                p[dot - ft] = '\0';
                /* insertion sort (deterministic, matches go_names.c) */
                int q2 = n_imps;
                while(q2 > 0 && strcmp(imps[q2 - 1], p) > 0) {
                    imps[q2] = imps[q2 - 1];
                    q2--;
                }
                imps[q2] = p;
                n_imps++;
                }
            }
            if(n_imps > 0) {
                if(fputs("\nimport (\n", f) < 0) {
                    for(int q = 0; q < n_imps; q++) free(imps[q]);
                    fclose(f); free(pkg); rc = -1; goto out;
                }
                for(int q = 0; q < n_imps; q++) {
                    if(fprintf(f, "\t\"%s/%s\"\n",
                               mpath ? mpath : "", imps[q]) < 0) {
                        for(int q2 = q; q2 < n_imps; q2++) free(imps[q2]);
                        fclose(f); free(pkg); rc = -1; goto out;
                    }
                    free(imps[q]);
                }
                if(fputs(")\n", f) < 0) { fclose(f); free(pkg); rc = -1; goto out; }
            }
        }
        int first = 1;
        for(int j = k; j < n_ct; j++) {
            if(strcmp(ct[j].module, ct[k].module) != 0) continue;
            if(first && fputs("\n", f) < 0) { fclose(f); free(pkg); rc = -1; goto out; }
            first = 0;
            int crit_on = (ct[j].crit_const != NULL);
            if(crit_on) {
              if(fprintf(f,
                       "// %s constructs a %s carrying %s (IOC row "
                       "id=%ld crit=%ld).\n"
                       "func %s(v %s) %s {\n"
                       "\treturn %s{\n"
                       "\t\tId:          %s,\n"
                       "\t\tCriticality: %s,\n"
                       "\t\tValue: %sValue{\n"
                       "\t\t\tPresent: %s,\n"
                       "\t\t\t%s:       &v,\n"
                       "\t\t},\n"
                       "\t}\n"
                       "}\n\n",
                       ct[j].fn,
                       ct[j].x_go, ct[j].alt_field,
                       ct[j].id, ct[j].crit,
                       ct[j].fn,
                       ct[j].alt_type, ct[j].x_go,
                       ct[j].x_go,
                       ct[j].id_ref,
                       ct[j].crit_ref,
                       ct[j].x_go,
                       ct[j].present,
                       ct[j].alt_field) < 0) {
                fclose(f);
                free(pkg);
                rc = -1;
                goto out;
              }
            } else {
              /* criticality-free class: the record the spec gives is
               * id+value; the literal emits exactly those members. */
              if(fprintf(f,
                       "// %s constructs a %s carrying %s (IOC row "
                       "id=%ld).\n"
                       "func %s(v %s) %s {\n"
                       "\treturn %s{\n"
                       "\t\tId:    %s,\n"
                       "\t\tValue: %sValue{\n"
                       "\t\t\tPresent: %s,\n"
                       "\t\t\t%s:       &v,\n"
                       "\t\t},\n"
                       "\t}\n"
                       "}\n\n",
                       ct[j].fn,
                       ct[j].x_go, ct[j].alt_field,
                       ct[j].id,
                       ct[j].fn,
                       ct[j].alt_type, ct[j].x_go,
                       ct[j].x_go,
                       ct[j].id_ref,
                       ct[j].x_go,
                       ct[j].present,
                       ct[j].alt_field) < 0) {
                fclose(f);
                free(pkg);
                rc = -1;
                goto out;
              }
            }
        }
        fclose(f);
        free(pkg);
    }

out:
    for(int k = 0; k < n_ct; k++) {
        free(ct[k].fn); free(ct[k].x_go); free(ct[k].module);
        free(ct[k].id_const); free(ct[k].id_ref);
        free(ct[k].crit_const); free(ct[k].crit_ref); free(ct[k].present);
        free(ct[k].alt_field); free(ct[k].alt_type);
    }
    free(ct);
    return rc;
}
