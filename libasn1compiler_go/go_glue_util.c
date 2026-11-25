/*
 * go_glue_util.c — the helpers of the glue emitters: strings and
 * files, layout-const names and their asserts, primitive slot tables, the
 * name-row index, the fn registry and Go type text.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

/* ---- string / fs helpers ----------------------------------------------- */

char *go_ga(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0, lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;
    memcpy(r + la, b ? b : "", lb + 1);
    return r;
}

/* go_ga() over an OWNED second argument (the go_gfmt results; genasan g17 class:
 * go_ga() doesn't free b, so every go_gam(x, go_gfmt(...)) leaked the go_gfmt return —
 * now every such site goes through gam). */
char *go_gam(char *a, char *b) {
    char *r = go_ga(a, b);
    free(b);
    return r;
}

/* length-tracking buffer helpers (go_strmap.h gsb): appends are O(len(b)). */
void go_sb_a(gsb *b, const char *s) { if(s) gsb_adds(b, s); }
void go_sb_am(gsb *b, char *s) { go_sb_a(b, s); free(s); }
void go_sb_set(gsb *b, char *s) {
    free(b->p); b->p = s; b->len = s ? strlen(s) : 0; b->cap = b->len + 1;
}

/* substring copy (length-based; NUL-terminated). */
static char *gown2_len(const char *p, size_t n) {
    char *r = malloc(n + 1);
    if(!r) return strdup("");
    memcpy(r, p, n);
    r[n] = 0;
    return r;
}

__attribute__((format(printf, 1, 2)))
char *go_gfmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if(n < 0) return strdup("");
    char *s = malloc((size_t)n + 1);
    if(!s) return strdup("");
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

/* free a const char* owned copy (no -Wcast-qual noise). */
void go_free_const(const void *p) { free((void *)(uintptr_t)p); }

char *go_gown(const char *s) {
    char *r = strdup(s ? s : "");
    return r ? r : strdup("");
}

/* the composite const prefix of member `tok` under prefix `pre` ("" = at the
 * node top): one "_<tok>" segment per nesting level (g_offconst2 camel-cases
 * the separators away). Malloc'd. */
char *go_cpre_chain(const char *pre, const char *tok, const char *tnode);

char *go_gjoin(const char *dir, const char *leaf) {
    char *p = malloc(strlen(dir) + 1 + strlen(leaf) + 1);
    if(!p) return strdup("");
    sprintf(p, "%s/%s", dir, leaf);
    return p;
}

int go_gmkdir_p(const char *path) {
    char buf[4096];
    size_t n = strlen(path);
    if(n == 0 || n >= sizeof buf) {
        fprintf(stderr, "asn1cgo: glue: bad directory path (empty or too long): '%s'\n", path);
        return -1;
    }
    memcpy(buf, path, n + 1);
    for(size_t i = 1; i < n; i++) {
        if(buf[i] == '/') {
            buf[i] = '\0';
            if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: glue: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
            buf[i] = '/';
        }
    }
    if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: glue: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
    return 0;
}

/* gofmt normalizer: single-line `if cond { stmt }` forms expand to the
 * 3-line form (gofmt never keeps them when the body is a statement pair).
 * Scans line-wise; the indent of the `if` keys the expansion. Applied to
 * the fully assembled package source so every emitter depth is handled
 * uniformly. */
char *go_expand_oneline_ifs(char *src) {
    if(!src) return src;
    const char *q = src;
    gsb obuf = {0};
    while(*q) {
        const char *eol = strchr(q, '\n');
        size_t ll = eol ? (size_t)(eol - q) : strlen(q);
        /* match: (tabs) if ... { ... }  — with the whole if+body on this line */
        size_t ti = 0;
        while(ti < ll && q[ti] == '\t') ti++;
        if(ll > ti + 4 && strncmp(q + ti, "if ", 3) == 0) {
            const char *ob = NULL, *cb = NULL;
            /* find the LAST " { " opening and matching " }" at line end */
            for(size_t k = ti; k < ll; k++) {
                if(q[k] == '{' && k > ti + 3 && q[k-1] == ' ') { ob = q + k; }
            }
            if(ob) {
                /* closing brace must end the line: " }" or "}" right before EOL */
                if(ll >= 2 && q[ll-1] == '}') {
                    /* body = between ob+1 and cb */
                    cb = q + ll - 1;
                    /* reject nested braces in the body (compound body) */
                    int nested = 0;
                    for(const char *c2 = ob + 1; c2 < cb; c2++)
                        if(*c2 == '{' || *c2 == '}') nested = 1;
                    if(!nested) {
                        char *indent = malloc(ti + 1);
                        for(size_t k = 0; k < ti; k++) indent[k] = '\t';
                        indent[ti] = 0;
                        char *cond = malloc((size_t)(ob - (q + ti)) + 1);
                        memcpy(cond, q + ti, (size_t)(ob - (q + ti)));
                        cond[ob - (q + ti)] = 0;
                        /* trim " {" from cond end */
                        size_t cl = strlen(cond);
                        if(cl >= 2 && cond[cl-1] == ' ') cond[cl-1] = 0;
                        char *body = malloc((size_t)(cb - (ob + 1)) + 1);
                        memcpy(body, ob + 1, (size_t)(cb - (ob + 1)));
                        body[cb - (ob + 1)] = 0;
                        /* trim body edges */
                        char *b2 = body; while(*b2 == ' ') b2++;
                        char *b3 = b2 + strlen(b2); while(b3 > b2 && b3[-1] == ' ') b3--;
                        *b3 = 0;
                        if(*b2 && strcmp(cond, "if") != 0) {
                            go_sb_am(&obuf, go_gfmt("%s%s {\n%s\t%s\n%s}\n",
                                                indent, cond, indent, b2, indent));
                            free(indent); free(cond); free(body);
                            if(!eol) break;
                            q = eol + 1;
                            continue;
                        }
                        free(indent); free(cond); free(body);
                    }
                }
            }
        }
        /* pass the line through */
        if(eol) {
            char *seg = gown2_len(q, ll);
            go_sb_a(&obuf, seg);
            free(seg);
            go_sb_a(&obuf, "\n");
            q = eol + 1;
        } else {
            go_sb_a(&obuf, q);
            break;
        }
    }
    free(src);
    return gsb_take(&obuf);
}

/* gofmt normalizer 2: a switch case body wrapped in a brace block
 * (`\tcase X:` then a line exactly "\t{") is formatted by gofmt one level
 * deeper (case bodies live at case+1). Adds one tab to every line of the
 * block through its matching line-exactly-"\t}" close. Line-exact at BOTH
 * ends so nested \t\t{ blocks stay put. */
char *go_reindent_case_blocks(char *src) {
    if(!src) return src;
    gsb obuf = {0};
    const char *q = src;
    while(*q) {
        const char *eol = strchr(q, '\n');
        if(!eol) { go_sb_a(&obuf, q); break; }
        size_t ll = (size_t)(eol - q);
        { char *sg = gown2_len(q, ll);
          go_sb_a(&obuf, sg); free(sg); }
        go_sb_a(&obuf, "\n");
        int is_case = (ll >= 6 && q[0] == '\t' && strncmp(q + 1, "case ", 5) == 0)
                      || (ll >= 9 && q[0] == '\t'
                          && strncmp(q + 1, "default:", 8) == 0);
        if(is_case) {
            const char *nxt = eol + 1;
            if(nxt[0] == '\t' && nxt[1] == '{'
               && (nxt[2] == '\n' || nxt[2] == 0)) {
                const char *body = nxt + 3;
                /* find line-exactly-"\t}" */
                const char *p2 = body;
                const char *close = NULL;
                while(*p2) {
                    if(p2[0] == '\t' && p2[1] == '}'
                       && (p2[2] == '\n' || p2[2] == 0)) {
                        close = p2;
                        break;
                    }
                    const char *e2 = strchr(p2, '\n');
                    if(!e2) break;
                    p2 = e2 + 1;
                }
                if(close && close >= body) {
                    go_sb_a(&obuf, "\t\t{\n");
                    for(const char *b = body; b < close; ) {
                        const char *e2 = strchr(b, '\n');
                        if(!e2 || e2 > close) e2 = close;
                        go_sb_a(&obuf, "\t");
                        { char *sg = gown2_len(b, (size_t)(e2 - b));
                          go_sb_a(&obuf, sg); free(sg); }
                        go_sb_a(&obuf, "\n");
                        if(e2 >= close) break;
                        b = e2 + 1;
                    }
                    go_sb_a(&obuf, "\t\t}\n");
                    q = close + 2;
                    if(*q == '\n') { q++; }
                    else { /* close had no newline (EOF) */ }
                    continue;
                }
            }
        }
        q = eol + 1;
    }
    free(src);
    return gsb_take(&obuf);
}

int go_gfwrite_all(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if(!f) {
        fprintf(stderr, "asn1cgo: glue: cannot write '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    size_t n = strlen(text);
    int ok = fwrite(text, 1, n, f) == n;
    if(fclose(f) != 0) ok = 0;
    if(!ok) {
        fprintf(stderr, "asn1cgo: glue: short write '%s'\n", path);
        return -1;
    }
    return 0;
}

/* module_pkg — the same rule go_emit.c applies (lowercase, '-'->'_'). */
char *go_gmodule_pkg(const char *module_name) {
    const char *s = module_name ? module_name : "_";
    char *out = malloc(strlen(s) + 1);
    if(!out) return strdup("");
    size_t j = 0;
    for(size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        out[j++] = (char)(c == '-' ? '_' : tolower(c));
    }
    out[j] = '\0';
    return out;
}

/* ---- camel mangling (lockstep with go_flat.c's layout.go const names) -- */

char *go_gcamel(const char *s) {
    s = s ? s : "";
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if(!out) return strdup("");
    size_t j = 0;
    int cap = 1;
    for(size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if(c == '_' || c == '-') { cap = 1; continue; }
        if(cap && islower(c)) c = (unsigned char)toupper(c);
        out[j++] = (char)c;
        cap = 0;
    }
    out[j] = '\0';
    return out;
}

/* camel of a flat NODE name: run prefix + trailing `_flat` stripped, then
 * camel — the same input go_flat.c::go_sizeof_const mangles, so const
 * references below spell exactly layout.go's declared names. */
const char *go_alt_node(const char *node_name);
const char *go_alt_tok(const char *node_name, const char *tok);

/* camel of member `tok` of node `node_name`: the exact Go spelling when the
 * member took the alt spelling (hyphen clash), else go_gcamel. */
char *go_gcamel_tok_in(const char *node_name, const char *tok) {
    const char *alt = go_alt_tok(node_name, tok);
    return alt ? strdup(alt) : go_gcamel(tok);
}

char *go_gcamel_flat(const char *node_name) {
    {
        const char *alt = go_alt_node(node_name);
        if(alt) return strdup(alt);
    }
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *s = node_name ? node_name : "";
    if(pl && strncmp(s, pfx, pl) == 0) s += pl;
    char *c = go_gcamel(s);
    size_t n = strlen(c);
    if(n > 4 && strcmp(c + n - 4, "Flat") == 0) c[n - 4] = '\0';
    return c;
}

/* the emit-module (set per go_glue_emit; package qualification qualification anchor) —
 * forward-declared here for go_qconst (defined with its comment block below
 * the ectx). */
const char *g_go_emit_mod = NULL;

char *g_go_szconst(const char *node_name) {
    char *c = go_gcamel_flat(node_name);
    char *o = go_gfmt("sizeof%s", c);
    free(c);
    return o;
}

/* gconst — a layout const reference from a fn emitted in THIS package for
 * a node: layout.go of THIS package declares consts for ITS OWN nodes, so
 * a local node's const passes through unchanged. A FOREIGN node's const is
 * unexported in the owning package (unreachable cross-package — App. G has
 * no cross-package const form); the glue's fn copies are SELF-CONTAINED per
 * package, so a foreign const is re-declared LOCALLY under the same const
 * name (the camel space is per-package; the owning package's own layout.go
 * never leaks here), and the (name, value) pair is collected for the
 * glue-local const block. node lookup by name (first module hit; same-group
 * cross-module homonyms = 0, verified per scope check). */
static char *g_offconst(const char *node_name, const char *tok) {
    char *c = go_gcamel_flat(node_name);
    char *t = go_gcamel_tok_in(node_name, tok);
    char *o = go_gfmt("off%s%s", c, t);
    free(c); free(t);
    return o;
}
/* composite const for an INNER member of a nested-by-value host member:
 * go_flat.c's go_off_const2 spelling off<Host><Mem><Inner>. */
static char *g_offconst2(const char *node_name, const char *tok1,
                         const char *tok2) {
    /* tok1 (the chain) and tok2 are already camel-cased by the caller */
    char *c = go_gcamel_flat(node_name);
    char *o = go_gfmt("off%s%s%s", c, tok1, tok2);
    free(c);
    return o;
}
/* member off const honoring a composite prefix ("" = plain form). */
char *g_go_offconst_pfx(const char *node_name, const char *pre,
                     const char *tok, const char *tnode) {
    if(*pre) {
        char *tc = go_gcamel_tok_in(tnode, tok);
        char *o = g_offconst2(node_name, pre, tc);
        free(tc);
        return o;
    }
    return g_offconst(node_name, tok);
}
/* the composite const prefix: the camel-cased member tokens of the nesting
 * levels concatenated (pre-camelled for g_offconst2). Malloc'd. */
char *go_cpre_chain(const char *pre, const char *tok, const char *tnode) {
    char *t = go_gcamel_tok_in(tnode, tok);
    char *o = (pre && *pre) ? go_gfmt("%s%s", pre, t) : go_gown(t);
    free(t);
    return o;
}
goneconst *g_go_loconsts = NULL;
int g_go_n_loconsts = 0, g_go_cap_loconsts = 0;

gsmap g_go_loconst_seen;   /* names in g_go_loconsts (reset with it) */

static void loconst_add(char *name, long value) {
    { int v; if(gsmap_get(&g_go_loconst_seen, name, &v)) { free(name); return; } }
    if(g_go_n_loconsts == g_go_cap_loconsts) {
        int nc = g_go_cap_loconsts ? g_go_cap_loconsts * 2 : 64;
        goneconst *nl = realloc(g_go_loconsts, (size_t)nc * sizeof(goneconst));
        if(!nl) { free(name); return; }
        g_go_loconsts = nl; g_go_cap_loconsts = nc;
    }
    gsmap_put_first(&g_go_loconst_seen, name, 1);
    g_go_loconsts[g_go_n_loconsts].name = name;
    g_go_loconsts[g_go_n_loconsts].value = value;
    g_go_n_loconsts++;
}

/* every layout const this glue.go uses (own layout.go consts + the
 * glue-local foreign re-declarations) carries a matching C _Static_assert
 * in this glue.go's cgo preamble, so a wrong const fails `go build` naming
 * the const. Assert text per const is recorded once (first touch), keyed
 * by the const spelling — the failures of the two-touch paths (own const +
 * a foreign re-declaration of the same node under go_qconst) collapse to one
 * assert per name, and the name <-> value pairs are non-contradictory
 * because both touches derive from the same IR node. */
gsb g_go_asserts_sb;         /* the package's assert block (owned) */
static gsmap g_asserts_seen;     /* its lines, for the once-per-line rule */

/* append an assert line unless the block already has it */
static void assert_line(const char *line) {
    int v;
    if(gsmap_get(&g_asserts_seen, line, &v)) return;
    gsmap_put_first(&g_asserts_seen, line, 1);
    gsb_adds(&g_go_asserts_sb, line);
}
void go_asserts_reset(void) {
    free(g_go_asserts_sb.p);
    memset(&g_go_asserts_sb, 0, sizeof g_go_asserts_sb);
    gsmap_free(&g_asserts_seen);
}

/* one assert line, appended under its const name as the failure message */
static void assert_add(const char *kind, const char *node_name,
                       const char *designator, const char *const_name,
                       long value) {
    char *line = designator
        ? go_gfmt("_Static_assert(%s(%s, %s) == %ld, \"%s\");\n",
               kind, node_name, designator, value, const_name)
        : go_gfmt("_Static_assert(%s(%s) == %ld, \"%s\");\n",
               kind, node_name, value, const_name);
    assert_line(line);
    free(line);
}

/* The composite consts of the by-value nested wrapper member `m` of node
 * `nm`, recursing through wrappers nested inside wrappers (the chain token
 * grows by one "_<tok>" segment per level; g_offconst2's camel-casing drops
 * the separators, so layout.go's spelling is reproduced). With `emit_assert`
 * each const's typeof-sum _Static_assert is recorded; otherwise the const is
 * re-declared glue-locally (a foreign node's set). `lhs`/`acc`: the C offset
 * expression / member path of the wrapper under node `nm`; `abs`: the
 * wrapper's offset from the node top. */
static void nested_consts(const char *nm, const char *node_id,
                          flat_member *m, const char *chain, const char *lhs,
                          const char *acc, long abs, int emit_assert) {
    int nix = go_flat_ir_member_nested_ix(m);
    flat_type *n = nix >= 0 ? go_flat_ir_type(nix) : NULL;
    if(!n) return;
    for(int j = 0; j < go_flat_ir_members(n); j++) {
        flat_member *im = go_flat_ir_member(n, j);
        const char *itok = go_flat_ir_member_token(im);
        if(!itok || !*itok) continue;
        char *itc = go_gcamel_tok_in(go_flat_ir_name(n), itok);
        char *oc2 = g_offconst2(nm, chain, itc);
        long ioff = abs + go_flat_ir_member_offset(im);
        char *sub = go_gfmt("%s + offsetof(typeof(((%s *)0)->%s), %s)",
                         lhs, node_id, acc, itok);
        if(emit_assert) {
            /* the typeof-sum designator form (offsetof(T,a) +
             * offsetof(typeof(((T*)0)->a),b) == host+inner) */
            char *line = go_gfmt("_Static_assert(%s == %ld, \"%s\");\n",
                              sub, ioff, oc2);
            assert_line(line);
            free(line);
            free(oc2);
        } else {
            loconst_add(oc2, ioff);
        }
        if(go_flat_ir_member_is_nested(im) && !go_flat_ir_member_stars(im)) {
            char *nchain = go_gfmt("%s%s", chain, itc);
            char *nacc = go_gfmt("%s.%s", acc, itok);
            nested_consts(nm, node_id, im, nchain, sub, nacc, ioff,
                          emit_assert);
            free(nchain); free(nacc);
        }
        free(sub);
        free(itc);
    }
}

/* the assert block of one node's whole const set (sizeof + every member
 * offset + every nested composite offset), mirroring the local-const set
 * go_qconst declares for a foreign node and layout.go declares for an own
 * node; the assert designators use the render_node_asserts grammar (the
 * nested composite asserts spell the typeof-sum form). The failure message
 * of every assert is the CONST NAME (a failure must name the failing
 * build names the const). */
void go_node_asserts(flat_type *t) {
    if(!t) return;
    const char *nm = go_flat_ir_name(t);
    if(!nm || !*nm) return;
    char *node_id = go_gown(go_flat_ir_name(t));   /* the C _flat typedef */
    char *szc = g_go_szconst(nm);
    assert_add("sizeof", node_id, NULL, szc, go_flat_ir_node_size(t));
    free(szc);
    for(int i = 0; i < go_flat_ir_members(t); i++) {
        flat_member *m = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(m);
        if(!tok || !*tok) continue;
        char *oc = g_offconst(nm, tok);
        assert_add("offsetof", node_id, tok, oc,
                   go_flat_ir_member_offset(m));
        free(oc);
        if(!go_flat_ir_member_is_nested(m) || go_flat_ir_member_stars(m))
            continue;
        {
            char *lhs = go_gfmt("offsetof(%s, %s)", node_id, tok);
            char *chain0 = go_gcamel_tok_in(nm, tok);
            nested_consts(nm, node_id, m, chain0, lhs, tok,
                          go_flat_ir_member_offset(m), 1);
            free(lhs);
            free(chain0);
        }
    }
    free(node_id);
}

static flat_type *ir_find_by_name(const char *node_name) {
    if(!node_name) return NULL;
    for(int i = 0; i < go_flat_ir_n_types(); i++) {
        flat_type *t = go_flat_ir_type(i);
        const char *nm = go_flat_ir_name(t);
        if(nm && strcmp(nm, node_name) == 0) return t;
    }
    return NULL;
}

char *go_qconst(const char *node_name, char *o) {
    if(!node_name || !o) return o;
    flat_type *t = ir_find_by_name(node_name);
    if(!t) return o;
    const char *tm = go_flat_ir_module(t);
    if(!tm || !g_go_emit_mod || strcmp(tm, g_go_emit_mod) == 0) {
        /* an OWN node's const (declared in THIS package's layout.go)
         * is recorded here too — the preamble asserts cover own consts as
         * much as the foreign re-declarations. */
        go_node_asserts(t);
        return o;
    }
    /* a FOREIGN node's re-declared const set (the glue-local block,
     * below) gets its asserts the same way. */
    go_node_asserts(t);
    /* foreign node: re-declare `sizeof<Node>` + every member offset here */
    char *sc = g_go_szconst(node_name);
    loconst_add(go_gown(sc), go_flat_ir_node_size(t));
    free(sc);
    for(int i = 0; i < go_flat_ir_members(t); i++) {
        flat_member *m = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(m);
        if(!tok) continue;
        char *oc = g_offconst(node_name, tok);
        loconst_add(oc, go_flat_ir_member_offset(m));
    }
    /* nested inner offsets (the composite const form), at every depth */
    {
        char *node_id = go_gown(go_flat_ir_name(t));
        for(int i = 0; i < go_flat_ir_members(t); i++) {
            flat_member *m = go_flat_ir_member(t, i);
            if(!go_flat_ir_member_is_nested(m) || go_flat_ir_member_stars(m))
                continue;
            const char *mtok = go_flat_ir_member_token(m);
            char *lhs = go_gfmt("offsetof(%s, %s)", node_id, mtok);
            char *chain0 = go_gcamel_tok_in(node_name, mtok);
            nested_consts(node_name, node_id, m, chain0, lhs, mtok,
                          go_flat_ir_member_offset(m), 0);
            free(lhs);
            free(chain0);
        }
        free(node_id);
    }
    return o;
}

int go_gprim_width(const char *prim) {
    if(!prim) return 0;
    if(strcmp(prim, "int64_t") == 0) return 8;
    if(strcmp(prim, "uint64_t") == 0) return 8;
    if(strcmp(prim, "double") == 0) return 8;
    if(strcmp(prim, "float") == 0) return 4;
    if(strcmp(prim, "int32_t") == 0) return 4;
    if(strcmp(prim, "_bool32") == 0) return 4;
    if(strcmp(prim, "asn1cgo_bytes_flat") == 0) return 16;
    if(strcmp(prim, "asn1cgo_bits_flat") == 0) return 24;
    return 0;
}

/* canonical Go cast type of a prim token ("" when not scalar). */
const char *go_gprim_go(const char *prim) {
    if(!prim) return "";
    if(strcmp(prim, "int32_t") == 0) return "int32";
    if(strcmp(prim, "int64_t") == 0) return "int64";
    if(strcmp(prim, "uint64_t") == 0) return "uint64";
    if(strcmp(prim, "double") == 0) return "float64";
    if(strcmp(prim, "float") == 0) return "float32";
    return "";
}

/* Go cast type of a prim for a NAMED-LEAF slot access: _bool32 is an int32
 * in the flat layout (the Go side is a bool). */
const char *go_gprim_slot(const char *prim) {
    if(prim && strcmp(prim, "_bool32") == 0) return "int32";
    return go_gprim_go(prim);
}

/* the Go-side (member's own) type spelling of a prim: bool for _bool32. */
const char *go_gprim_own(const char *prim) {
    if(prim && strcmp(prim, "_bool32") == 0) return "bool";
    return go_gprim_go(prim);
}

/* Go expression storing VAL (a Go value of the member's own type) into a
 * slot of raw type GT: _bool32 goes bool -> 0/1, everything else is a plain
 * conversion to the RAW prim. Caller frees. */
char *go_gconv_store(const char *prim, const char *gt, const char *val) {
    if(prim && strcmp(prim, "_bool32") == 0)
        return go_gfmt("b32FromBool(bool(%s))", val);
    return go_gfmt("%s(%s)", gt, val);
}

/* Go expression reading RAW (a slot of raw type GT) into the member's own
 * type CAST: _bool32 goes int32 != 0 -> bool. Caller frees. */
char *go_gconv_load(const char *prim, const char *cast, const char *raw) {
    if(prim && strcmp(prim, "_bool32") == 0)
        return go_gfmt("%s(%s != 0)", cast, raw);
    return go_gfmt("%s(%s)", cast, raw);
}

/* ---- name-row lookups ------------------------------------------------- */

/* First-hit indexes over the name rows, rebuilt when the row count changes:
 * the lookups below used to scan every row per call (quadratic in the type
 * count). Each index returns the FIRST row the old scan would have hit. */
static gsmap g_ix_type, g_ix_field, g_ix_present, g_ix_fgo;
static gsmap g_ix_ownty;   /* (module, goName) of a type/inline row     */
static gsmap g_ix_alias;   /* goName -> first type-ish row (go_qualify_alias) */
static int g_ix_rows = -1;

static char *ix_key2(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *k = malloc(la + lb + 2);
    if(!k) return NULL;
    memcpy(k, a, la); k[la] = '\x01'; memcpy(k + la + 1, b, lb + 1);
    return k;
}

static void rows_index(void) {
    int n = go_names_rows_n();
    if(n == g_ix_rows) return;
    gsmap_free(&g_ix_type); gsmap_free(&g_ix_field); gsmap_free(&g_ix_present);
    gsmap_free(&g_ix_fgo); gsmap_free(&g_ix_ownty); gsmap_free(&g_ix_alias);
    g_ix_rows = n;
    for(int i = 0; i < n; i++) {
        const char *k = go_names_row_kind(i);
        const char *mod = go_names_row_module(i);
        const char *gn = go_names_row_goname(i);
        if(mod && k && gn && *gn
           && (strcmp(k, "type") == 0 || strcmp(k, "inline") == 0
               || strcmp(k, "spec-key") == 0 || strcmp(k, "spec-value") == 0)) {
            char *key = ix_key2(mod, gn);
            if(key) { gsmap_put_first(&g_ix_type, key, i); free(key); }
        }
        if(mod && k && gn && (strcmp(k, "type") == 0 || strcmp(k, "inline") == 0)) {
            char *key = ix_key2(mod, gn);
            if(key) { gsmap_put_first(&g_ix_ownty, key, i); free(key); }
        }
        if(k && gn && (strcmp(k, "type") == 0 || strcmp(k, "inline") == 0
                       || strcmp(k, "spec-key") == 0
                       || strcmp(k, "spec-value") == 0
                       || strcmp(k, "spec-pr") == 0
                       || strcmp(k, "choice-pr") == 0))
            gsmap_put_first(&g_ix_alias, gn, i);
        const char *so = go_names_row_sf_owner(i);
        if(!so) continue;
        if(k && strcmp(k, "field") == 0) {
            const char *rc = go_names_row_rawcid(i);
            if(rc) {
                char *key = ix_key2(so, rc);
                if(key) { gsmap_put_first(&g_ix_field, key, i); free(key); }
            }
            const char *ft = go_names_row_field_type(i);
            if(gn && ft && *ft) {
                char *key = ix_key2(so, gn);
                if(key) { gsmap_put_first(&g_ix_fgo, key, i); free(key); }
            }
        }
        if(gn && strcmp(gn, "Present") == 0)
            gsmap_put_first(&g_ix_present, so, i);
    }
}

/* The Go type name of a package-scoped node: the row (type/inline/spec-key/
 * spec-value) of this node's module whose goName == camel(node). Borrowed;
 * NULL when no row (a nested-only node). */
const char *go_gf_goname(flat_type *t) {
    const char *tname = t ? go_flat_ir_name(t) : NULL;
    const char *tmod = t ? go_flat_ir_module(t) : NULL;
    if(!tname || !*tname || !tmod) return NULL;
    char *c = go_gcamel_flat(tname);
    const char *r = NULL;
    rows_index();
    char *key = ix_key2(tmod, c);
    int v;
    if(key && gsmap_get(&g_ix_type, key, &v)) r = go_names_row_goname(v);
    free(key);
    free(c);
    return r;
}

static int gf_field_row(const char *owner, const char *token) {
    if(!owner || !token) return -1;
    rows_index();
    char *key = ix_key2(owner, token);
    int v = -1;
    if(!key || !gsmap_get(&g_ix_field, key, &v)) v = -1;
    free(key);
    return v;
}

/* A FIELD row goName by (owner goName, rawCid == member token). Borrowed.
 * NULL = no row (a NULL alt's suppressed row — callers key on the
 * null-alt record). */
const char *go_gf_field_goname(const char *owner, const char *token) {
    int i = gf_field_row(owner, token);
    return i < 0 ? NULL : go_names_row_goname(i);
}

/* A FIELD row's field_type text by the same key (package-qualified). */
const char *go_gf_field_type(const char *owner, const char *token) {
    int i = gf_field_row(owner, token);
    return i < 0 ? NULL : go_names_row_field_type(i);
}

/* The <owner>.Present discriminant's TYPE text (field row `Present`). */
const char *go_gf_present_type(const char *owner) {
    int v;
    if(!owner) return NULL;
    rows_index();
    return gsmap_get(&g_ix_present, owner, &v) ? go_names_row_field_type(v) : NULL;
}

/* the unqualified base of a possibly qualified name */
const char *go_unqual(const char *n) {
    const char *d = strrchr(n ? n : "", '.');
    return d ? d + 1 : n;
}

gluefn **g_go_fns = NULL;   /* array of stable heap ptrs (realloc-safe) */
int g_go_n_fns = 0, g_go_cap_fns = 0;

int go_fn_ix(flat_type *t) {
    for(int i = 0; i < go_flat_ir_n_types(); i++)
        if(go_flat_ir_type(i) == t) return i;
    return -1;
}

static gluefn *fn_find(int ix) {
    for(int i = 0; i < g_go_n_fns; i++)
        if(g_go_fns[i]->ix == ix) return g_go_fns[i];
    return NULL;
}

gluefn *go_fn_queue(int ix) {
    gluefn *f = fn_find(ix);
    if(f) { f->queued = 1; return f; }
    if(g_go_n_fns == g_go_cap_fns) {
        int nc = g_go_cap_fns ? g_go_cap_fns * 2 : 64;
        gluefn **nf = realloc(g_go_fns, (size_t)nc * sizeof(gluefn *));
        if(!nf) { GFAIL("oom"); return NULL; }
        g_go_fns = nf; g_go_cap_fns = nc;
    }
    f = calloc(1, sizeof(gluefn));
    if(!f) { GFAIL("oom"); return NULL; }
    g_go_fns[g_go_n_fns++] = f;
    f->ix = ix;
    f->sz = strdup("");
    f->fill = strdup("");
    f->read = strdup("");
    f->queued = 1;
    f->active = 0;
    f->done = 0;
    return f;
}

/* local fn-name base for node t (unique per spec: camel node name). */
char *go_fnbase(flat_type *t) { return go_gcamel_flat(go_flat_ir_name(t)); }

/* ---------------------------------------------------------------------------
 * Body emission. ONE walk of a node's member rows fills all body strings
 * concurrently (size/fill/read) so the three cannot drift.
 *
 * IR access is strictly through the go_flat_ir_* surface (the IR struct is
 * private to go_flat.c); kind tags come from the enum's numeric order —
 * mirrored here as GK_* local constants (FT_PRIM=0, FT_REF=1, FT_NESTED=2;
 * FLT_STRUCT=0, FLT_LEAF=1, FLT_SEQOF=2, FLT_ALIAS=3) with a compile-time
 * cross-check below (kinds.h is deliberately not shared: go_flat.h keeps
 * the IR opaque by design).
 * ------------------------------------------------------------------------- */
/* Node/member kind predicates: ONLY the go_flat_ir_is_* accessors are used
 * (is_seqof/is_alias/is_choice/is_struct/is_leaf on nodes; member_is_prim/
 * member_is_ref/member_is_nested on member rows). The IR's numeric kind
 * tags are private to go_flat.c and never compared here. */
int go_n_is_seqof(flat_type *t) { return go_flat_ir_is_seqof(t); }
int go_n_is_leaf(flat_type *t) { return go_flat_ir_is_leaf(t); }

/* go_gtype_q — the package-qualified Go type spelling of node t's own type from
 * the CURRENT emit module's view (g_go_emit_mod, forward-declared near go_qconst):
 * "T" when t's module == g_go_emit_mod, else "<pkg>.T" (the local fns are
 * per-package; the sibling packages of one go.mod are importable by their
 * module path "<mod>/<pkg>"). Malloc'd. */
/* For each node, the (host, member) pairs whose REF member resolves to it, in
 * (host, member) scan order: go_gtype_q's container-clone search used to rescan
 * every member of every node per call. Rebuilt when the node count changes. */
static int *g_rh_start, *g_rh_host, *g_rh_mem;
static int g_rh_n = -1;

static void refhost_index(void) {
    int n = go_flat_ir_n_types();
    if(n < 0) n = 0;
    if(n == g_rh_n) return;
    free(g_rh_start); free(g_rh_host); free(g_rh_mem);
    g_rh_start = calloc((size_t)n + 2, sizeof(int));
    int tot = 0;
    for(int pass = 0; pass < 2; pass++) {
        if(pass == 1) {
            for(int i = 0; i <= n; i++) {
                int c = g_rh_start[i]; g_rh_start[i] = tot; tot += c;
            }
            g_rh_host = malloc(((size_t)tot + 1) * sizeof(int));
            g_rh_mem = malloc(((size_t)tot + 1) * sizeof(int));
            tot = 0;
        }
        int *fill = pass ? calloc((size_t)n + 1, sizeof(int)) : NULL;
        for(int hi = 0; hi < n; hi++) {
            flat_type *host = go_flat_ir_type(hi);
            for(int mi = 0; mi < go_flat_ir_members(host); mi++) {
                flat_member *m = go_flat_ir_member(host, mi);
                if(!m || !go_flat_ir_member_is_ref(m)) continue;
                const char *rf = go_flat_ir_member_ref(m);
                flat_type *rr = rf ? go_flat_ir_ref_resolve(rf) : NULL;
                if(!rr || rr == host) continue;
                int ri = go_flat_ir_index(rr);
                if(ri < 0) continue;
                if(!pass) g_rh_start[ri]++;
                else {
                    int at = g_rh_start[ri] + fill[ri]++;
                    g_rh_host[at] = hi; g_rh_mem[at] = mi;
                }
            }
        }
        free(fill);
    }
    g_rh_n = n;
}

char *go_local_bitstring(void);
char *go_owner_bitstring(const char *mod);
char *go_gtype_q(flat_type *t) {
    /* a hidden inline-element leaf (`SEQUENCE OF INTEGER`...) has no Go type
     * row: its Go type IS the unnamed leaf mapping text. */
    if(t && go_flat_ir_go_type(t)) {
        const char *gt = go_flat_ir_go_type(t);
        return strcmp(gt, "BitString") == 0
            ? go_owner_bitstring(go_flat_ir_module(t)) : go_gown(gt);
    }
    /* a SEQ-OF CONTAINER CLONE node (asn1c's ProtocolIE-Container 85Px
     * instantiations) has NO Go type row of its own — its Go spelling is
     * the referencing field's slice alias (<Msg>ProtocolIEs). Find
     * any IR member whose ref resolves to t, then that member's field
     * row's field_type IS the alias Go name. */
    if(t && go_flat_ir_is_seqof(t)) {
        /* NOTE: borrow-only scan — NO owned strings held across the row
         * hit (the loop frees its per-iteration temps on every path). */
        refhost_index();
        int tix = go_flat_ir_index(t);
        for(int ci = 0; tix >= 0 && tix < g_rh_n
                && ci < g_rh_start[tix + 1] - g_rh_start[tix]; ci++) {
            int cj = g_rh_start[tix] + ci;
            flat_type *host = go_flat_ir_type(g_rh_host[cj]);
            {
                flat_member *m = go_flat_ir_member(host, g_rh_mem[cj]);
                const char *nown = go_flat_ir_name(host);
                const char *tokraw = go_flat_ir_member_token(m);
                char *hostcam = go_gcamel_flat(nown ? nown : "");
                char *tokcam = go_gcamel_tok_in(nown ? nown : "", tokraw ? tokraw : "");
                int ri = -1;
                { char *fk = ix_key2(hostcam, tokcam);
                  rows_index();
                  if(!fk || !gsmap_get(&g_ix_fgo, fk, &ri)) ri = -1;
                  free(fk); }
                if(ri >= 0) {
                    const char *ft_v = go_names_row_field_type(ri);
                    {
                        /* the field row's spelling may already carry the
                         * REFERENCING module's package qualifier; it is
                         * re-qualified below from g_go_emit_mod's view. */
                        const char *alias = go_unqual((*ft_v == '*') ? ft_v + 1 : ft_v);
                        const char *rtm = go_flat_ir_module(t);
                        char *out;
                        if(rtm && g_go_emit_mod && strcmp(rtm, g_go_emit_mod) != 0) {
                            char *pk = go_gmodule_pkg(rtm);
                            out = go_gfmt("%s.%s", pk, alias);
                            free(pk);
                        } else {
                            out = go_gown(alias);
                        }
                        free(hostcam); free(tokcam);
                        return out;
                    }
                }
                free(hostcam); free(tokcam);
            }
        }
    }
    char *cam = go_gcamel_flat(go_flat_ir_name(t));
    const char *tm = t ? go_flat_ir_module(t) : NULL;
    if(!tm || !g_go_emit_mod || strcmp(tm, g_go_emit_mod) == 0) return cam;
    char *pkg = go_gmodule_pkg(tm);
    char *q = go_gfmt("%s.%s", pkg, cam);
    free(pkg); free(cam);
    return q;
}

int go_dep_is_scc(flat_type *t) { return go_conv_is_scc(t); }

/* rt.Error literal text (TypeName from the display label, cid fallback). */
char *
go_errlit(flat_type *t, const char *mfield, const char *code, const char *msg) {
    char *tl;
    { const char *lb = go_flat_ir_type_label(t);
      const char *tc = go_flat_ir_cid(t);
      const char *nm = go_flat_ir_name(t);
      tl = go_gown(lb && *lb ? lb : (tc ? tc : (nm ? nm : "")));
    }
    char *s = go_gfmt("rt.Error{Code: rt.%s, TypeName: \"%s\"", code, tl);
    if(mfield && *mfield) {
        s = go_ga(s, ", Field: \"");
        s = go_ga(s, mfield);
        s = go_ga(s, "\"");
    }
    if(msg && *msg) {
        s = go_ga(s, ", Message: \"");
        s = go_ga(s, msg);
        s = go_ga(s, "\"");
    }
    s = go_ga(s, "}");
    free(tl);
    return s;
}

/* Is `ft` (a field's Go type text) a bare primitive view? */
/* a Go identifier character (the BITSTR placeholder match boundary) */
int
go_glue_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '_';
}

/* this package's BitString spelling: the local type when THIS package
 * declares one, else the OWNER's qualified name (used by the static bits
 * helpers' parameterization + every literal BitString bridge the glue
 * emits). */
char *go_local_bitstring(void) {
    char *bsname = go_gown("BitString");
    const char *foreign = NULL, *used = NULL;
    for(int bi = 0; bi < go_names_rows_n(); bi++) {
        const char *bk = go_names_row_kind(bi);
        if(!bk || (strcmp(bk, "type") != 0 && strcmp(bk, "helper") != 0))
            continue;
        const char *bg = go_names_row_goname(bi);
        if(!bg || strcmp(bg, "BitString") != 0) continue;
        const char *bm = go_names_row_module(bi);
        if(bm && g_go_emit_mod && strcmp(bm, g_go_emit_mod) == 0)
            return bsname;   /* ours: bare, wherever its row sits */
        if(bm && g_go_emit_mod && strcmp(bm, g_go_emit_mod) != 0) {
            /* prefer a foreign owner this package's own field types
             * reference (its types.go imports that package, so the name is
             * bound); a package it never imports would be undefined here. */
            if(!foreign) foreign = bm;
            if(!used) {
                char *pk = go_gmodule_pkg(bm);
                char *pre = go_gfmt("%s.", pk);
                size_t pl = strlen(pre);
                for(int ri = 0; ri < go_names_rows_n() && !used; ri++) {
                    const char *rm = go_names_row_module(ri);
                    const char *rf = go_names_row_field_type(ri);
                    if(!rm || strcmp(rm, g_go_emit_mod) != 0 || !rf) continue;
                    while(*rf == '*') rf++;
                    if(strncmp(rf, pre, pl) == 0) used = bm;
                }
                free(pk); free(pre);
            }
        }
    }
    if(used) foreign = used;
    if(foreign) {
        char *pk = go_gmodule_pkg(foreign);
        free(bsname);
        bsname = go_gfmt("%s.BitString", pk);
        free(pk);
    }
    return bsname;
}

/* the Go spelling of a BitString VALUE owned by module `mod`: bare when that
 * is the module being emitted, else qualified with the owner's package (a
 * value's type is its owner's, whatever this package's helpers take). */
char *go_owner_bitstring(const char *mod) {
    if(!mod || !g_go_emit_mod || strcmp(mod, g_go_emit_mod) == 0)
        return go_gown("BitString");
    char *pk = go_gmodule_pkg(mod);
    char *r = go_gfmt("%s.BitString", pk);
    free(pk);
    return r;
}

/* wrap/unwrap a scalar BitString value `expr` of the owner `mod` for the
 * helpers: "<local>(expr)" when the owner's and the local spelling differ,
 * `expr` unchanged otherwise (so unaffected output stays byte-identical).
 * `to_local` selects the direction. Malloc'd. */
char *go_bits_bridge(const char *mod, const char *expr, int to_local) {
    char *ow = go_owner_bitstring(mod), *lo = go_local_bitstring();
    char *r = strcmp(ow, lo) == 0 ? go_gown(expr)
            : go_gfmt("%s(%s)", to_local ? lo : ow, expr);
    free(ow); free(lo);
    return r;
}

int go_is_prim_view(const char *ft) {
    static const char *P[] = { "int32", "int64", "uint64", "float64", "float32", "bool",
                               "string", "[]byte", "BitString", "struct{}", "" };
    if(!ft) return 1;
    const char *u = go_unqual(ft);
    for(int i = 0; P[i][0]; i++)
        if(strcmp(u, P[i]) == 0) return 1;
    return 0;
}

/* The Go cast type of a member field: its row field_type base (a named
 * alias), falling back to the prim's canonical Go view. The caller strips
 * the pointer star. Always non-NULL. */
char *go_qualify_alias(const char *alias);

char *
go_field_cast(flat_type *t, const char *owner_go, const char *tok,
           const char *prim) {
    const char *ft = go_gf_field_type(owner_go, tok);
    if(ft && *ft) {
        /* the alias may be FOREIGN (the field row's type text names a type
         * of another package bare): qualify through its names row. */
        return go_qualify_alias(ft);
    }
    return go_gown(prim ? go_gprim_own(prim) : "");
}

/* go_qualify_alias — package-qualify a possibly-foreign alias spelling: find its
 * names row (type/inline kinds) by goName; when its module is foreign to
 * g_go_emit_mod, spell "<pkg>.<alias>" (star and pointee preserved). */
char *
go_qualify_alias(const char *alias_in) {
    if(!alias_in || !*alias_in) return go_gown(alias_in ? alias_in : "");
    const char *st = alias_in;
    int star = 0;
    while(*st == '*') { star++; st++; }
    const char *base = go_unqual(st);
    /* a name this package declares itself wins over a same-named row of
     * another module (BitString: every module that owns BIT STRING members
     * declares one) — never qualify it by the first match. */
    rows_index();
    if(g_go_emit_mod) {
        char *lk = ix_key2(g_go_emit_mod, base);
        int lv;
        int go_own = lk && gsmap_get(&g_ix_ownty, lk, &lv);
        free(lk);
        if(go_own) return go_gown(alias_in);
    }
    {
        int i;
        if(gsmap_get(&g_ix_alias, base, &i)) {
            const char *mrow = go_names_row_module(i);
            if(mrow && g_go_emit_mod && strcmp(mrow, g_go_emit_mod) != 0) {
                char *pk = go_gmodule_pkg(mrow);
                char pre[8];
                int si;
                for(si = 0; si < star && si < 7; si++) pre[si] = '*';
                pre[si] = 0;
                char *q = go_gfmt("%s%s.%s", pre, pk, base);
                free(pk);
                return q;
            }
        }
    }
    /* local or unresolvable: keep the original spelling (star preserved) */
    return go_gown(alias_in);
}
