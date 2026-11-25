/*
 * go_names_rows.c — the name bag: name rows, the package, struct and
 * package-dir name scopes with their collision checks, the C-identifier
 * clash sets and the alt-spelling registry.
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

const char *const g_go_kind_tag[GK__COUNT] = {
    "type", "field", "choice-pr", "choice-const", "enum-const", "value-const",
    "inline", "spec-key", "spec-value", "spec-pr", "helper", "pkg-dir",
    "default-value",
};

/* Kinds whose goName is package-scoped (collide within one module). field is
 * struct-scoped (a fresh per-struct table); pkg-dir collides across modules
 * (its own table). */
int
go_kind_is_package_scoped(go_kind_e k) {
    return k == GK_TYPE || k == GK_INLINE || k == GK_CHOICE_PR
        || k == GK_CHOICE_CONST || k == GK_ENUM_CONST || k == GK_VALUE_CONST
        || k == GK_SPEC_KEY || k == GK_SPEC_VALUE || k == GK_SPEC_PR
        || k == GK_HELPER || k == GK_DEFAULT_VALUE;
}

/* ------------------------------------------------------------------------- */
/* R2 transform: split the C identifier on '_', upper-case the first
 * char of each segment, join. Everything else passes through verbatim. Mirrors
 * the name-distribution check — no curation, no aliasing.
 *
 *   shortName_Field          -> ShortNameField
 *   ProtocolIE_ID_id_Cause   -> ProtocolIEIDIdCause
 *   Item_Name                -> ItemName
 *   ProcedureCode_id_Setup   -> ProcedureCodeIdSetup
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
char *
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
char *
go_str_append(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0;
    size_t lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;            /* leave a unchanged on OOM */
    memcpy(r + la, b ? b : "", lb);
    r[la + lb] = '\0';
    return r;
}

/* Borrowed strdup: strdup the C-identifier return of GO_MKID (which returns a
 * pointer into an asn1c static buffer reused on the next call) into an owned
 * copy. Never returns NULL (returns "" on OOM). */
char *
go_own(const char *s) {
    char *r = strdup(s ? s : "");
    return r ? r : strdup("");
}
char *go_own_mkid(asn1p_expr_t *e) { return go_own(GO_MKID(e)); }

/* prefix-free identifier forms. Under ASN1C_PREFIX=<P>_ asn1c does NOT
 * stamp the prefix on every identifier uniformly; the real .h rules are:
 *   - struct-member declaration tokens: make_identifier WITHOUT prefix
 *     (MKID_safe at asn1c_C.c:98 — AMI_CHECK_RESERVED, no AMI_USE_PREFIX; the
 *     member emit at asn1c_C.c:1353): `beam_ID`, never `PFX_beam_ID`;
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
 * All return owned strings (go_own() semantics: "" on OOM). */
char *go_mk_member(asn1p_expr_t *e) {
    return go_own(asn1c_make_identifier(AMI_CHECK_RESERVED, (e), 0));
}
char *go_mk_suffix(asn1p_expr_t *e) {
    return go_own(asn1c_make_identifier(0, (e), 0));
}
char *go_cid_compound(const char *a, const char *sep, const char *b) {
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
    if(!r) return go_own("");
    snprintf(r, n, "%s%s%s%s", pfx ? pfx : "", as ? as : "", sep ? sep : "",
             bs ? bs : "");
    return r;
}

/* ------------------------------------------------------------------------- */
/* Hyphen-clash spelling (the rule of go_list_suffix, applied to the sibling
 * lists of SEQUENCE fields / CHOICE alternatives, to the type names of one
 * module and to the value names of one module). go_r2 drops every '_', so
 * `a1` and `a-1` (C tokens `a1`, `a_1`) would both become `A1`. Only a
 * member that clashes AND has a '_' directly followed by a digit uses the
 * alternative spelling, which keeps that '_' (`A_1`); every other name is
 * the plain go_r2 spelling, byte for byte. */

/* alt spelling of a C token: go_r2, but a '_' directly before a digit stays */
char *
go_alt_spell(const char *cid) {
    const char *prefix = asn1c_prefix();
    size_t plen = prefix ? strlen(prefix) : 0;
    if(cid && plen && strncmp(cid, prefix, plen) == 0) cid += plen;
    size_t n = cid ? strlen(cid) : 0;
    char *out = malloc(n + 1);
    if(!out) return strdup("");
    size_t j = 0;
    int cap = 1;
    for(size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)cid[i];
        if(c == '_' && isdigit((unsigned char)cid[i + 1])) {
            out[j++] = '_';
            cap = 0;
            continue;
        }
        if(c == '_') { cap = 1; continue; }
        out[j++] = (cap && isalpha(c)) ? (char)toupper(c) : (char)c;
        cap = 0;
    }
    out[j] = '\0';
    return out;
}

static int
go_has_us_digit(const char *cid) {
    for(; cid && *cid; cid++)
        if(*cid == '_' && isdigit((unsigned char)cid[1])) return 1;
    return 0;
}

/* A sorted multiset of keys per (module, kind): answers "does another
 * entry of this module normalise to the same name?". Built once per module. */
struct clash_set {
    asn1p_module_t *mod;
    int kind;                   /* 0 type names, 1 value names */
    char **keys;
    size_t n;
};
static struct clash_set *g_clash;
static size_t g_clash_n;

static int
clash_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void
go_clash_reset(void) {
    for(size_t i = 0; i < g_clash_n; i++) {
        for(size_t k = 0; k < g_clash[i].n; k++) free(g_clash[i].keys[k]);
        free(g_clash[i].keys);
    }
    free(g_clash);
    g_clash = NULL;
    g_clash_n = 0;
}

static const char *
value_type_ref_name(asn1p_expr_t *v) {
    if(v->reference && v->reference->comp_count && v->reference->components)
        return v->reference->components[0].name;
    return "";
}

/* key of a top-level type (kind 0) or value (kind 1) assignment */
static char *
clash_key(asn1p_expr_t *m, int kind) {
    char *cid = go_own(GO_MKID(m));
    char *r = go_r2(cid);
    free(cid);
    if(kind == 1) {
        r = go_str_append(r, "\x01");
        r = go_str_append(r, value_type_ref_name(m));
    }
    return r;
}

static int
clash_member(asn1p_expr_t *m, int kind) {
    if(!m->Identifier || m->expr_type == A1TC_EXTENSIBLE) return 0;
    if(kind == 0)
        return (m->meta_type == AMT_TYPE || m->meta_type == AMT_TYPEREF)
            && !m->lhs_params && m->spec_index < 0;
    return m->meta_type == AMT_VALUE;
}

static struct clash_set *
clash_get(asn1p_module_t *mod, int kind) {
    for(size_t i = 0; i < g_clash_n; i++)
        if(g_clash[i].mod == mod && g_clash[i].kind == kind) return &g_clash[i];
    struct clash_set *ng = realloc(g_clash, (g_clash_n + 1) * sizeof *ng);
    if(!ng) return NULL;
    g_clash = ng;
    struct clash_set *cs = &g_clash[g_clash_n++];
    cs->mod = mod;
    cs->kind = kind;
    cs->keys = NULL;
    cs->n = 0;
    size_t cap = 0;
    asn1p_expr_t *m;
    TQ_FOR(m, &(mod->members), next) {
        if(!clash_member(m, kind)) continue;
        if(cs->n == cap) {
            cap = cap ? cap * 2 : 64;
            char **nk = realloc(cs->keys, cap * sizeof *nk);
            if(!nk) break;
            cs->keys = nk;
        }
        cs->keys[cs->n++] = clash_key(m, kind);
    }
    if(cs->n) qsort(cs->keys, cs->n, sizeof *cs->keys, clash_cmp);
    return cs;
}

static int
clash_has_other(struct clash_set *cs, const char *key) {
    if(!cs || !cs->n) return 0;
    size_t lo = 0, hi = cs->n;
    while(lo < hi) {
        size_t mid = (lo + hi) / 2;
        if(strcmp(cs->keys[mid], key) < 0) lo = mid + 1; else hi = mid;
    }
    return lo + 1 < cs->n && strcmp(cs->keys[lo], key) == 0
        && strcmp(cs->keys[lo + 1], key) == 0;
}

/* Go name of a top-level type assignment: go_r2(MKID(t)), or the alt
 * spelling when it clashes with another type of its module (`T1`/`T-1`). */
char *
go_type_go(asn1p_expr_t *t) {
    char *cid = go_own(GO_MKID(t));
    char *norm = go_r2(cid);
    if(go_has_us_digit(cid) && !t->parent_expr && t->module
       && clash_member(t, 0)
       && clash_has_other(clash_get(t->module, 0), norm)) {
        free(norm);
        norm = go_alt_spell(cid);
    }
    free(cid);
    return norm;
}

/* Go name of the value-const `#define <Gov>_<val>`: go_type_go(Gov) plus
 * the value segment, which takes the alt spelling when the value clashes
 * with a sibling value of its module of the same type reference. */
char *
go_value_go(asn1p_expr_t *gov, asn1p_expr_t *val) {
    char *head = go_type_go(gov);
    char *vc = go_own(GO_MKID(val));
    char *seg = NULL;
    if(go_has_us_digit(vc) && !val->parent_expr && val->module
       && clash_member(val, 1)) {
        char *key = clash_key(val, 1);
        if(clash_has_other(clash_get(val->module, 1), key))
            seg = go_alt_spell(vc);
        free(key);
    }
    if(!seg) seg = go_r2(vc);
    head = go_str_append(head, seg);
    free(seg);
    free(vc);
    return head;
}

/* module_pkg: module identifier lowercased, '-' -> '_'. malloc'd, never NULL.
 * (package dir = this. Mirrors go_emit.c's same-named helper.) */
char *
go_module_pkg_name(const char *module_name) {
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

void *
go_xrealloc(void *p, size_t n) {
    void *r = realloc(p, n);
    return r;   /* caller handles NULL */
}

static int
ps_grow(struct name_bag *b) {
    if(b->n_ps + 1 <= b->cap_ps) return 1;
    int nc = b->cap_ps ? b->cap_ps * 2 : 16;
    const char **nm = go_xrealloc(b->ps_module, (size_t)nc * sizeof(char *));
    if(!nm) return 0;
    b->ps_module = nm;
    struct pkg_owner **no = go_xrealloc(b->ps_owners, (size_t)nc * sizeof(*no));
    if(!no) return 0;
    b->ps_owners = no;
    int *nn = go_xrealloc(b->ps_n, (size_t)nc * sizeof(int));
    if(!nn) return 0;
    b->ps_n = nn;
    int *ncp = go_xrealloc(b->ps_cap, (size_t)nc * sizeof(int));
    if(!ncp) return 0;
    b->ps_cap = ncp;
    gsmap *nix = go_xrealloc(b->ps_ix, (size_t)nc * sizeof(gsmap));
    if(!nix) return 0;
    b->ps_ix = nix;
    for(int i = b->cap_ps; i < nc; i++) {
        memset(&b->ps_ix[i], 0, sizeof(gsmap));
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
        struct pkg_owner *np = go_xrealloc(b->ps_owners[i],
                                        (size_t)nc * sizeof(struct pkg_owner));
        if(!np) return 0;
        b->ps_owners[i] = np; b->ps_cap[i] = nc;
    }
    gsmap_put_first(&b->ps_ix[i], o.goName, b->ps_n[i]);
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
    {
        int j;
        struct pkg_owner *o;
        if(gsmap_get(&b->ps_ix[i], goName, &j)) {
            o = &b->ps_owners[i][j];
            /* Same (path, kind) row meaning a re-visit: idempotent, no row. */
            if(strcmp(o->path, path) == 0 && o->kind == kind)
                return;
            fprintf(stderr,
                    "asn1cgo: collision in module %s: %s <- %s (%s) and %s (%s)\n",
                    module ? module : "?", goName,
                    o->path, g_go_kind_tag[o->kind],
                    path, g_go_kind_tag[kind]);
            b->failed = 1;
            return;
        }
    }
    struct pkg_owner o = { strdup(goName), strdup(path), kind };
    ps_append(i, b, o);
}

/* field_diag_path: strip the doubled last component of a field row's path
 * ("T.a.x.x" -> "T.a.x"). Owned copy. */
static char *
field_diag_path(const char *path) {
    char *c = strdup(path);
    char *last = strrchr(c, '.');
    if(last) {
        char *prev = last;
        while(prev > c && prev[-1] != '.') prev--;
        if((size_t)(last - prev) == strlen(last + 1)
           && strncmp(prev, last + 1, (size_t)(last - prev)) == 0)
            *last = '\0';
    }
    return c;
}

/* Record a struct-scoped field name in the CURRENT struct's field table. */
static void
record_field(struct name_bag *b, const char *module,
             const char *path, char *rawCid, char *goName) {
    (void)rawCid;
    for(int j = 0; j < b->n_fields; j++) {
        if(strcmp(b->fields[j].goName, goName) == 0) {
            /* a field row's path is <member path>.<member>: the last
             * component is doubled; print it once. */
            char *p1 = field_diag_path(b->fields[j].path);
            char *p2 = field_diag_path(path);
            fprintf(stderr,
                    "asn1cgo: collision in module %s: %s <- %s (field) and %s (field)\n",
                    module ? module : "?", goName, p1, p2);
            free(p1); free(p2);
            b->failed = 1;
            return;
        }
    }
    if(b->n_fields + 1 > b->cap_fields) {
        int nc = b->cap_fields ? b->cap_fields * 2 : 16;
        struct field_owner *np = go_xrealloc(b->fields,
                                          (size_t)nc * sizeof(struct field_owner));
        if(!np) { b->failed = 1; return; }
        b->fields = np; b->cap_fields = nc;
    }
    b->fields[b->n_fields].goName = strdup(goName);
    b->fields[b->n_fields].path = strdup(path);
    b->n_fields++;
}

void
go_reset_field_scope(struct name_bag *b) {
    for(int j = 0; j < b->n_fields; j++) {
        free(b->fields[j].goName); free(b->fields[j].path);
    }
    b->n_fields = 0;
}

/* go_field_scope_push / go_field_scope_pop: give a struct that becomes its own Go
 * type (inline SEQUENCE/CHOICE, SEQUENCE OF inline element, [[ ]] group) its
 * own field scope. push parks the enclosing table and starts an empty one;
 * pop discards the inner table and restores the enclosing one. */
void
go_field_scope_push(struct name_bag *b) {
    if(b->n_fs + 1 > b->cap_fs) {
        int nc = b->cap_fs ? b->cap_fs * 2 : 8;
        struct field_scope_save *np = go_xrealloc(b->fs_stack,
                                  (size_t)nc * sizeof(struct field_scope_save));
        if(!np) { b->failed = 1; return; }
        b->fs_stack = np; b->cap_fs = nc;
    }
    b->fs_stack[b->n_fs].fields = b->fields;
    b->fs_stack[b->n_fs].n_fields = b->n_fields;
    b->fs_stack[b->n_fs].cap_fields = b->cap_fields;
    b->n_fs++;
    b->fields = NULL; b->n_fields = 0; b->cap_fields = 0;
}

void
go_field_scope_pop(struct name_bag *b) {
    if(b->n_fs <= 0) return;
    go_reset_field_scope(b);
    free(b->fields);
    b->n_fs--;
    b->fields = b->fs_stack[b->n_fs].fields;
    b->n_fields = b->fs_stack[b->n_fs].n_fields;
    b->cap_fields = b->fs_stack[b->n_fs].cap_fields;
}

/* ---- struct-body recording ------------------------------------ */

/* go_struct_scope_open: open a struct-owner scope named `owner_go` (the struct's
 * goName). Every GK_FIELD row emitted while the scope is open (until the next
 * open/reset) records `owner_go` in its sf_owner — exactly the scope
 * discipline the field collision table uses (go_reset_field_scope), now retained
 * for emission. Owner by NAME: the emit matches fields to their struct by
 * goName (ord-order interleaving across structs is harmless; within one
 * match, ord order is the walk order = AST member order). */
void
go_struct_scope_open(struct name_bag *b, const char *owner_go) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = strdup(owner_go ? owner_go : "");
}

/* go_struct_scope_reset: close the open scope (fields emitted after this attach
 * to no struct — e.g. a leftover guard between top-level assignments). */
void
go_struct_scope_reset(struct name_bag *b) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = NULL;
}

/* go_bag_sf_restore: reopen a SAVED struct-owner scope after a nested struct's
 * walk finished with go_struct_scope_reset (an inline CHOICE/SEQUENCE member
 * walk). Returns the saved pointer it consumed (free() it), NULL- and
 * strdup-safe. The member walk of an OUTER struct continues after a nested
 * construct; without the restore, every later member of the outer struct
 * lands scopeless (emit skips fields with no sf_owner — RRC-MessageID's
 * messageID after the inline rrcType CHOICE). */
char *
go_bag_sf_restore(struct name_bag *b, char *saved) {
    free(b->sf_cur_owner);
    b->sf_cur_owner = saved ? strdup(saved) : NULL;
    return saved;
}

/* struct_field_note: stamp the open struct scope's owner onto the row just
 * appended (a GK_FIELD row). Called from go_emit_name right after add_row. */
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
        struct pkgdir_owner *np = go_xrealloc(b->dirs,
                                           (size_t)nc * sizeof(struct pkgdir_owner));
        if(!np) { b->failed = 1; return; }
        b->dirs = np; b->cap_dirs = nc;
    }
    b->dirs[b->n_dirs].dir = strdup(dir);
    b->dirs[b->n_dirs].module = module;
    b->n_dirs++;
}

/* ---- alt-spelling registry ------------------------------------------------
 * go_flat.c / go_glue.c derive layout-const and fn names, and look up a node's
 * Go type, by camel-casing the C names (which drops every '_'). A name that
 * took the alt spelling above keeps a '_' there, so the camel of its C name
 * is not its Go name. The registry maps the C name (node cid, or node cid +
 * member token) to the exact Go spelling, for those names only; every other
 * name is camel-cased as before. */
struct alt_ent { char *key; char *val; };
static struct alt_ent *g_alt;
static size_t g_alt_n, g_alt_cap;
static int g_alt_sorted;

static char *
alt_norm(const char *name, const char *tok) {
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *s0 = name ? name : "";
    if(pl && strncmp(s0, pfx, pl) == 0) s0 += pl;
    size_t n = strlen(s0);
    if(n > 5 && strcmp(s0 + n - 5, "_flat") == 0) n -= 5;
    size_t tl = tok ? strlen(tok) : 0;
    char *k = malloc(n + tl + 2);
    if(!k) return NULL;
    memcpy(k, s0, n);
    k[n] = '\0';
    if(tok) { k[n] = '\x01'; memcpy(k + n + 1, tok, tl); k[n + 1 + tl] = '\0'; }
    return k;
}

void
go_alt_register(const char *name, const char *tok, const char *go) {
    if(!go || !strchr(go, '_')) return;      /* only alt spellings */
    char *k = alt_norm(name, tok);
    if(!k) return;
    if(g_alt_n == g_alt_cap) {
        size_t nc = g_alt_cap ? g_alt_cap * 2 : 64;
        struct alt_ent *ng = realloc(g_alt, nc * sizeof *ng);
        if(!ng) { free(k); return; }
        g_alt = ng;
        g_alt_cap = nc;
    }
    g_alt[g_alt_n].key = k;
    g_alt[g_alt_n].val = strdup(go);
    g_alt_n++;
    g_alt_sorted = 0;
}

static int
alt_cmp(const void *a, const void *b) {
    return strcmp(((const struct alt_ent *)a)->key,
                  ((const struct alt_ent *)b)->key);
}

static const char *
alt_find(const char *name, const char *tok) {
    if(!g_alt_n) return NULL;
    if(!g_alt_sorted) {
        qsort(g_alt, g_alt_n, sizeof *g_alt, alt_cmp);
        g_alt_sorted = 1;
    }
    char *k = alt_norm(name, tok);
    if(!k) return NULL;
    struct alt_ent key = { k, NULL };
    struct alt_ent *r = bsearch(&key, g_alt, g_alt_n, sizeof *g_alt, alt_cmp);
    free(k);
    return r ? r->val : NULL;
}

/* The exact Go spelling of node `node_name` / of its member `tok` when it
 * took the alt spelling; NULL otherwise (camel-case as before). */
const char *go_alt_node(const char *node_name);
const char *go_alt_tok(const char *node_name, const char *tok);
const char *go_alt_node(const char *node_name) { return alt_find(node_name, NULL); }
const char *go_alt_tok(const char *node_name, const char *tok) {
    return alt_find(node_name, tok);
}

void
go_alt_reset(void) {
    for(size_t i = 0; i < g_alt_n; i++) { free(g_alt[i].key); free(g_alt[i].val); }
    free(g_alt);
    g_alt = NULL;
    g_alt_n = g_alt_cap = 0;
    g_alt_sorted = 0;
}

/* Append a retained row. module is borrowed; path/rawCid/goName owned. */
static void
add_row(struct name_bag *b, const char *module,
        char *path, go_kind_e kind, char *rawCid, char *goName) {
    if(b->n_rows + 1 > b->cap_rows) {
        int nc = b->cap_rows ? b->cap_rows * 2 : 128;
        struct name_row *nr = go_xrealloc(b->rows,
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
    b->rows[b->n_rows].dfn = NULL;
    b->rows[b->n_rows].dflt_field_row = -1;
    b->rows[b->n_rows].bit_group = 0;
    b->rows[b->n_rows].bit_type = NULL;
    b->rows[b->n_rows].has_ctor = 0;
    b->rows[b->n_rows].alias_of = NULL;
    b->rows[b->n_rows].ctor_dflt = -1;
    b->rows[b->n_rows].ctor_type = -1;
    b->rows[b->n_rows].ord = b->n_rows;
    b->n_rows++;
}

/* Attach leaf-stage const body data to the row just appended (the LAST row).
 * value is the decimal const value text (asn1p_itoa output, owned copy);
 * go_type the const's declared Go type name (owned copy; "" if none). */
void
go_row_set_const(struct name_bag *b, const char *value, const char *go_type) {
    struct name_row *r = &b->rows[b->n_rows - 1];
    r->intval = go_own(value);
    r->goType = go_own(go_type ? go_type : "");
}

/* Attach a leaf-stage kind (GLEAF_*) to the row just appended. */
void
go_row_set_leaf(struct name_bag *b, int leaf_kind) {
    b->rows[b->n_rows - 1].leaf_kind = leaf_kind;
}

/* Attach a slice-stage ELEMENT type text to the row just appended (a
 * slice-owner row: the SEQUENCE-OF type assignment's `type` row or the
 * minted anonymous/container `inline` row). Owned copy. */
void
go_row_set_slice_elem(struct name_bag *b, const char *elem) {
    b->rows[b->n_rows - 1].slice_elem = go_own(elem);
}

/* the same, by row index (an inline element's rows are appended after the
 * slice owner's own row). */
void
go_row_set_slice_elem_at(struct name_bag *b, int ix, const char *elem) {
    b->rows[ix].slice_elem = go_own(elem);
}

/* One name, fully recorded into BOTH the right collision scope and the dump
 * rows. Routes on kind, then hands path/rawCid/goName to the scope recorder.
 * path/rawCid/goName ownership is taken on all paths (freed at teardown).
 * leaf-stage body data (leaf_kind/intval/goType) attaches AFTER this call via
 * go_row_set_leaf/go_row_set_const (rows are address-stable between add_row calls:
 * the walker sets the fields immediately, before the next go_emit_name). */
void
go_emit_name(struct name_bag *b, const char *module,
          char *path, go_kind_e kind, char *rawCid, char *goName) {
    if(kind == GK_TYPE || kind == GK_INLINE)
        go_alt_register(rawCid, NULL, goName);
    if(go_kind_is_package_scoped(kind))
        record_package(b, module, path, kind, rawCid, goName);
    else if(kind == GK_FIELD)
        record_field(b, module, path, rawCid, goName);
    else if(kind == GK_PKG_DIR)
        record_pkg_dir(b, module, goName, path);
    add_row(b, module, path, kind, rawCid, goName);
    if(kind == GK_FIELD)
        struct_field_note(b);   /* struct-body pass: retain per-owner, in walk order */
}

/* go_row_set_field_type: attach a struct-body field's Go TYPE text to the row just
 * appended (a GK_FIELD row). Owned copy; pointer-star and cross-module
 * qualification are the caller's (computed by field_go_type below). */
void
go_row_set_field_type(struct name_bag *b, const char *field_type) {
    struct name_row *r = &b->rows[b->n_rows - 1];
    free(r->field_type);
    r->field_type = go_own(field_type ? field_type : "");
}

/* go_row_set_field_type_at: the by-INDEX form for the one site that emits rows
 * BETWEEN the field row and its field_type computation (the SEQ-OF mint: the
 * inline row lands after the field row; the n_rows-1 form would type the
 * inline row and leave the field row untyped — the emitted struct body then
 * drops the field entirely). */
void
go_row_set_field_type_at(struct name_bag *b, int ix, const char *field_type) {
    struct name_row *r = &b->rows[ix];
    free(r->field_type);
    r->field_type = go_own(field_type ? field_type : "");
}

/* go_row_set_is_struct: mark the row just appended as a STRUCT-OWNER row (its
 * declaration is `type X struct {...}` over the recorded field rows).
 * go_row_set_is_struct_at: the by-INDEX form for go_emit_choice, which appends its
 * choice-pr row between the owner row and the call (the owner row is a GK_TYPE
 * or GK_INLINE row emitted by the caller). */
void
go_row_set_is_struct_at(struct name_bag *b, int ix) {
    b->rows[ix].is_struct = 1;
}

void
go_row_set_is_struct(struct name_bag *b) {
    go_row_set_is_struct_at(b, b->n_rows - 1);
}
