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
 * Ownership (the Go<->Flat ownership rule): Encode = one C.malloc'd block -> fill through
 * the two-region bump allocator (fixed structs from the front, variable
 * payloads from the rear) -> the C entry point -> C.GoBytes copy ->
 * asn1cgo_buf_free + C.free, deferred on every path; no Go pointer is
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
 * call. read does not thread depth (decoded data cannot exceed the C-side
 * guard the decoder already enforced).
 *
 * Errors: every returned error is *rt.Error (asn1cgo-rt/rt/errors.go
 * — the ONE Go error surface). Glue-originated errors construct rt.Error
 * directly; C-originated ones goErr-copy the C struct through this
 * package's err.h-typed cgo preamble (the C struct type identity is by
 * declaration — the same C header the rt package includes).
 *
 * Cgo budget: Encode = C.malloc(1) + entry(1) + asn1cgo_buf_free(1)
 * + C.free(1) = 4; Decode = entry(1) + asn1cgo_arena_free(1) = 2. The
 * sizing/filling pass and C.GoBytes/GoStringN are Go-side only (GoBytes
 * linknames to runtime.gobytes on the pinned toolchain — not a cgocall).
 *
 * Naming: fn bases and layout-const references are camel-mangled from flat
 * IR node names by the SAME two-strip rule go_flat.c applies to layout.go
 * consts, so `sizeof<Camel>Flat`/`off<Camel><Tok>` spell exactly layout.go's
 * declared names; Go type/field names come from the name rows
 * (go_names_rows_*), never re-derived from ASN.1 here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asn1c_internal.h"      /* arg_t + asn1p_expr_t before asn1c_misc.h
                                 * (the go_entry.c include discipline) */
#include "asn1c_misc.h"          /* asn1c_prefix */
#include "go_conv.h"             /* flat IR surface + conv facts (PDU roots) */
#include "go_conv_internal.h"    /* g_conv_pdus, conv_* helpers */

/* The name-row surface (go_names.c — the bag outlives the glue emit;
 * extern decls here keep -Wmissing-prototypes quiet in both TUs). */
int go_names_rows_n(void);
const char *go_names_row_module(int i);
const char *go_names_row_goname(int i);
const char *go_names_row_rawcid(int i);
const char *go_names_row_kind(int i);
const char *go_names_row_field_type(int i);
const char *go_names_row_sf_owner(int i);
const char *go_names_row_slice_elem(int i);
const char *go_names_row_intval(int i);
const char *go_names_row_gotype(int i);
int go_names_row_is_struct(int i);
const char *go_names_row_leaf_underlying(int i);

/* display labels of IR nodes/members (go_flat.c accessors already
 * declared via go_conv.h's fwd block). */

static int glue_failed = 0;
static int g_tmpseq = 0;   /* unique temp names per fn (reset in emit_type_fn) */
#define GFAIL(msg) do { fprintf(stderr, "asn1cgo: glue: %s\n", (msg)); \
                        glue_failed = 1; } while(0)

/* ---- string / fs helpers ----------------------------------------------- */

static char *ga(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0, lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;
    memcpy(r + la, b ? b : "", lb + 1);
    return r;
}

/* ga() over an OWNED second argument (the gfmt results; genasan g17 class:
 * ga() doesn't free b, so every gam(x, gfmt(...)) leaked the gfmt return —
 * now every such site goes through gam). */
static char *gam(char *a, char *b) {
    char *r = ga(a, b);
    free(b);
    return r;
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
static char *gfmt(const char *fmt, ...) {
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
static void free_const(const void *p) { free((void *)(uintptr_t)p); }

static char *gown(const char *s) {
    char *r = strdup(s ? s : "");
    return r ? r : strdup("");
}

static char *gjoin(const char *dir, const char *leaf) {
    char *p = malloc(strlen(dir) + 1 + strlen(leaf) + 1);
    if(!p) return strdup("");
    sprintf(p, "%s/%s", dir, leaf);
    return p;
}


static int gmkdir_p(const char *path) {
    char buf[4096];
    size_t n = strlen(path);
    if(n == 0 || n >= sizeof buf) return -1;
    memcpy(buf, path, n + 1);
    for(size_t i = 1; i < n; i++) {
        if(buf[i] == '/') {
            buf[i] = '\0';
            if(mkdir(buf, 0777) < 0 && errno != EEXIST) return -1;
            buf[i] = '/';
        }
    }
    if(mkdir(buf, 0777) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* gofmt normalizer: single-line `if cond { stmt }` forms expand to the
 * 3-line form (gofmt never keeps them when the body is a statement pair).
 * Scans line-wise; the indent of the `if` keys the expansion. Applied to
 * the fully assembled package source so every emitter depth is handled
 * uniformly. */
static char *expand_oneline_ifs(char *src) {
    if(!src) return src;
    const char *q = src;
    char *out = strdup("");
    while(*q) {
        const char *eol = strchr(q, '\n');
        size_t ll = eol ? (size_t)(eol - q) : strlen(q);
        /* match: (tabs) if ... { ... }  — with the whole if+body on this line */
        size_t ti = 0;
        while(ti < ll && q[ti] == '\t') ti++;
        if(ll > ti + 4 && strncmp(q + ti, "if ", 3) == 0) {
            const char *ob = NULL, *cb = NULL, *semi = NULL;
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
                            out = gam(out, gfmt("%s%s {\n%s\t%s\n%s}\n",
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
            out = ga(out, seg);
            free(seg);
            out = ga(out, "\n");
            q = eol + 1;
        } else {
            out = ga(out, q);
            break;
        }
    }
    free(src);
    return out;
}

/* gofmt normalizer 2: a switch case body wrapped in a brace block
 * (`\tcase X:` then a line exactly "\t{") is formatted by gofmt one level
 * deeper (case bodies live at case+1). Adds one tab to every line of the
 * block through its matching line-exactly-"\t}" close. Line-exact at BOTH
 * ends so nested \t\t{ blocks stay put. */
static char *reindent_case_blocks(char *src) {
    if(!src) return src;
    char *out = strdup("");
    const char *q = src;
    while(*q) {
        const char *eol = strchr(q, '\n');
        if(!eol) { out = ga(out, q); break; }
        size_t ll = (size_t)(eol - q);
        { char *sg = gown2_len(q, ll);
          out = ga(out, sg); free(sg); }
        out = ga(out, "\n");
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
                    out = ga(out, "\t\t{\n");
                    for(const char *b = body; b < close; ) {
                        const char *e2 = strchr(b, '\n');
                        if(!e2 || e2 > close) e2 = close;
                        out = ga(out, "\t");
                        { char *sg = gown2_len(b, (size_t)(e2 - b));
                          out = ga(out, sg); free(sg); }
                        out = ga(out, "\n");
                        if(e2 >= close) break;
                        b = e2 + 1;
                    }
                    out = ga(out, "\t\t}\n");
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
    return out;
}

static int gfwrite_all(const char *path, const char *text) {
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
static char *gmodule_pkg(const char *module_name) {
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

static char *gcamel(const char *s) {
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
static char *gcamel_flat(const char *node_name) {
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *s = node_name ? node_name : "";
    if(pl && strncmp(s, pfx, pl) == 0) s += pl;
    char *c = gcamel(s);
    size_t n = strlen(c);
    if(n > 4 && strcmp(c + n - 4, "Flat") == 0) c[n - 4] = '\0';
    return c;
}

/* the emit-module (set per go_glue_emit; package qualification qualification anchor) —
 * forward-declared here for qconst (defined with its comment block below
 * the ectx). */
static const char *g_emit_mod = NULL;

static char *g_szconst(const char *node_name) {
    char *c = gcamel_flat(node_name);
    char *o = gfmt("sizeof%s", c);
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
    char *c = gcamel_flat(node_name);
    char *t = gcamel(tok);
    char *o = gfmt("off%s%s", c, t);
    free(c); free(t);
    return o;
}
/* composite const for an INNER member of a nested-by-value host member:
 * go_flat.c's go_off_const2 spelling off<Host><Mem><Inner>. */
static char *g_offconst2(const char *node_name, const char *tok1,
                         const char *tok2) {
    char *c = gcamel_flat(node_name);
    char *t1 = gcamel(tok1);
    char *t2 = gcamel(tok2);
    char *o = gfmt("off%s%s%s", c, t1, t2);
    free(c); free(t1); free(t2);
    return o;
}
/* member off const honoring a composite prefix ("" = plain form). */
static char *g_offconst_pfx(const char *node_name, const char *pre,
                            const char *tok) {
    return (*pre && strcmp(pre, "") != 0)
               ? g_offconst2(node_name, pre, tok)
               : g_offconst(node_name, tok);
}
typedef struct { char *name; long value; } goneconst;
static goneconst *g_loconsts = NULL;
static int g_n_loconsts = 0, g_cap_loconsts = 0;

static void loconst_add(char *name, long value) {
    for(int i = 0; i < g_n_loconsts; i++)
        if(strcmp(g_loconsts[i].name, name) == 0) { free(name); return; }
    if(g_n_loconsts == g_cap_loconsts) {
        int nc = g_cap_loconsts ? g_cap_loconsts * 2 : 64;
        goneconst *nl = realloc(g_loconsts, (size_t)nc * sizeof(goneconst));
        if(!nl) { free(name); return; }
        g_loconsts = nl; g_cap_loconsts = nc;
    }
    g_loconsts[g_n_loconsts].name = name;
    g_loconsts[g_n_loconsts].value = value;
    g_n_loconsts++;
}

/* every layout const this glue.go uses (own layout.go consts + the
 * glue-local foreign re-declarations) carries a matching C _Static_assert
 * in this glue.go's cgo preamble, so a wrong const fails `go build` naming
 * the const. Assert text per const is recorded once (first touch), keyed
 * by the const spelling — the failures of the two-touch paths (own const +
 * a foreign re-declaration of the same node under qconst) collapse to one
 * assert per name, and the name <-> value pairs are non-contradictory
 * because both touches derive from the same IR node. */
static char *g_asserts = NULL;   /* the package's assert block (owned) */

/* one assert line, appended under its const name as the failure message */
static void assert_add(const char *kind, const char *node_name,
                       const char *designator, const char *const_name,
                       long value) {
    char *line = designator
        ? gfmt("_Static_assert(%s(%s, %s) == %ld, \"%s\");\n",
               kind, node_name, designator, value, const_name)
        : gfmt("_Static_assert(%s(%s) == %ld, \"%s\");\n",
               kind, node_name, value, const_name);
    if(strstr(g_asserts ? g_asserts : "", line)) { free(line); return; }
    g_asserts = ga(g_asserts, line);
    free(line);
}

/* the assert block of one node's whole const set (sizeof + every member
 * offset + every nested composite offset), mirroring the local-const set
 * qconst declares for a foreign node and layout.go declares for an own
 * node; the assert designators use the render_node_asserts grammar (the
 * nested composite asserts spell the typeof-sum form). The failure message
 * of every assert is the CONST NAME (a failure must name the failing
 * build names the const). */
static void node_asserts(flat_type *t) {
    if(!t) return;
    const char *nm = go_flat_ir_name(t);
    if(!nm || !*nm) return;
    char *node_id = gown(go_flat_ir_name(t));   /* the C _flat typedef */
    char *szc = g_szconst(nm);
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
        flat_type *n = go_flat_ir_member_nested_ix(m) >= 0
            ? go_flat_ir_type(go_flat_ir_member_nested_ix(m)) : NULL;
        if(!n) continue;
        for(int j = 0; j < go_flat_ir_members(n); j++) {
            flat_member *im = go_flat_ir_member(n, j);
            const char *itok = go_flat_ir_member_token(im);
            if(!itok || !*itok) continue;
            /* the composite const's assert: the typeof-sum designator form
             * (offsetof(T,a)+offsetof(typeof(((T*)0)->a),b) == host+inner) */
            char *oc2 = g_offconst2(nm, tok, itok);
            char *line = gfmt(
                "_Static_assert(offsetof(%s, %s) + "
                "offsetof(typeof(((%s *)0)->%s), %s) == %ld, \"%s\");\n",
                node_id, tok, node_id, tok, itok,
                go_flat_ir_member_offset(m) + go_flat_ir_member_offset(im),
                oc2);
            if(!strstr(g_asserts ? g_asserts : "", line))
                g_asserts = ga(g_asserts, line);
            free(oc2);
            free(line);
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

static char *qconst(const char *node_name, char *o) {
    if(!node_name || !o) return o;
    flat_type *t = ir_find_by_name(node_name);
    if(!t) return o;
    const char *tm = go_flat_ir_module(t);
    if(!tm || !g_emit_mod || strcmp(tm, g_emit_mod) == 0) {
        /* an OWN node's const (declared in THIS package's layout.go)
         * is recorded here too — the preamble asserts cover own consts as
         * much as the foreign re-declarations. */
        node_asserts(t);
        return o;
    }
    /* a FOREIGN node's re-declared const set (the glue-local block,
     * below) gets its asserts the same way. */
    node_asserts(t);
    /* foreign node: re-declare `sizeof<Node>` + every member offset here */
    char *sc = g_szconst(node_name);
    loconst_add(gown(sc), go_flat_ir_node_size(t));
    free(sc);
    for(int i = 0; i < go_flat_ir_members(t); i++) {
        flat_member *m = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(m);
        if(!tok) continue;
        char *oc = g_offconst(node_name, tok);
        loconst_add(oc, go_flat_ir_member_offset(m));
    }
    /* nested inner offsets (the composite const form) */
    for(int i = 0; i < go_flat_ir_members(t); i++) {
        flat_member *m = go_flat_ir_member(t, i);
        if(!go_flat_ir_member_is_nested(m) || go_flat_ir_member_stars(m))
            continue;
        flat_type *n = go_flat_ir_member_nested_ix(m) >= 0
            ? go_flat_ir_type(go_flat_ir_member_nested_ix(m)) : NULL;
        if(!n) continue;
        for(int j = 0; j < go_flat_ir_members(n); j++) {
            flat_member *im = go_flat_ir_member(n, j);
            const char *itok = go_flat_ir_member_token(im);
            if(!itok) continue;
            char *oc2 = g_offconst2(node_name, go_flat_ir_member_token(m), itok);
            loconst_add(oc2, go_flat_ir_member_offset(m)
                              + go_flat_ir_member_offset(im));
        }
    }
    return o;
}



static const char *g_alignconst(const char *prim) {
    if(prim && (strcmp(prim, "int32_t") == 0 || strcmp(prim, "_bool32") == 0))
        return "alignInt32";
    return "alignInt64";
}

static int gprim_width(const char *prim) {
    if(!prim) return 0;
    if(strcmp(prim, "int64_t") == 0) return 8;
    if(strcmp(prim, "uint64_t") == 0) return 8;
    if(strcmp(prim, "double") == 0) return 8;
    if(strcmp(prim, "int32_t") == 0) return 4;
    if(strcmp(prim, "_bool32") == 0) return 4;
    if(strcmp(prim, "asn1cgo_bytes_flat") == 0) return 16;
    if(strcmp(prim, "asn1cgo_bits_flat") == 0) return 24;
    return 0;
}


/* canonical Go cast type of a prim token ("" when not scalar). */
static const char *gprim_go(const char *prim) {
    if(!prim) return "";
    if(strcmp(prim, "int32_t") == 0) return "int32";
    if(strcmp(prim, "int64_t") == 0) return "int64";
    if(strcmp(prim, "uint64_t") == 0) return "uint64";
    if(strcmp(prim, "double") == 0) return "float64";
    return "";
}

/* ---- name-row lookups ------------------------------------------------- */

/* The Go type name of a package-scoped node: the row (type/inline/spec-key/
 * spec-value) of this node's module whose goName == camel(node). Borrowed;
 * NULL when no row (a nested-only node). */
static const char *gf_goname(flat_type *t) {
    const char *tname = t ? go_flat_ir_name(t) : NULL;
    const char *tmod = t ? go_flat_ir_module(t) : NULL;
    if(!tname || !*tname) return NULL;
    char *c = gcamel_flat(tname);
    const char *r = NULL;
    for(int i = 0; i < go_names_rows_n() && !r; i++) {
        const char *mod = go_names_row_module(i);
        if(!mod || !tmod || strcmp(mod, tmod) != 0) continue;
        const char *k = go_names_row_kind(i);
        if(!k || (strcmp(k, "type") != 0 && strcmp(k, "inline") != 0
                  && strcmp(k, "spec-key") != 0
                  && strcmp(k, "spec-value") != 0)) continue;
        const char *gn = go_names_row_goname(i);
        if(gn && *gn && strcmp(gn, c) == 0) r = gn;
    }
    free(c);
    return r;
}



/* A FIELD row goName by (owner goName, rawCid == member token). Borrowed.
 * NULL = no row (a NULL alt's suppressed row — callers key on the
 * null-alt record). */
static const char *gf_field_goname(const char *owner, const char *token) {
    if(!owner || !token) return NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *so = go_names_row_sf_owner(i);
        if(!so || strcmp(so, owner) != 0) continue;
        const char *k = go_names_row_kind(i);
        if(!k || strcmp(k, "field") != 0) continue;
        const char *rc = go_names_row_rawcid(i);
        if(rc && strcmp(rc, token) == 0) return go_names_row_goname(i);
    }
    return NULL;
}

/* A FIELD row's field_type text by the same key (package-qualified). */
static const char *gf_field_type(const char *owner, const char *token) {
    if(!owner || !token) return NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *so = go_names_row_sf_owner(i);
        if(!so || strcmp(so, owner) != 0) continue;
        const char *k = go_names_row_kind(i);
        if(!k || strcmp(k, "field") != 0) continue;
        const char *rc = go_names_row_rawcid(i);
        if(rc && strcmp(rc, token) == 0) return go_names_row_field_type(i);
    }
    return NULL;
}

/* The <owner>.Present discriminant's TYPE text (field row `Present`). */
static const char *gf_present_type(const char *owner) {
    if(!owner) return NULL;
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *so = go_names_row_sf_owner(i);
        if(!so || strcmp(so, owner) != 0) continue;
        const char *gn = go_names_row_goname(i);
        if(gn && strcmp(gn, "Present") == 0)
            return go_names_row_field_type(i);
    }
    return NULL;
}

/* the unqualified base of a possibly qualified name */
static const char *unqual(const char *n) {
    const char *d = strrchr(n ? n : "", '.');
    return d ? d + 1 : n;
}

/* ---- the fn registry ----------------------------------------------------
 * One entry per emitted local fn (keyed by flat IR node index). Nested-only
 * nodes are INLINED, not registered. The registry dedups a diamond (two
 * members referencing the same type) and orders emission by first need. */

typedef struct {
    int ix;                    /* flat index of the node (the fn's type)  */
    char *sz, *fill, *read;    /* body lines (indent embedded)            */
    int queued, active, done;
    int leaf_pdu;              /* a scalar-alias leaf PDU (no &T{} read)  */
} gluefn;

static gluefn **g_fns = NULL;   /* array of stable heap ptrs (realloc-safe) */
static int g_n_fns = 0, g_cap_fns = 0;

static int fn_ix(flat_type *t) {
    for(int i = 0; i < go_flat_ir_n_types(); i++)
        if(go_flat_ir_type(i) == t) return i;
    return -1;
}

static gluefn *fn_find(int ix) {
    for(int i = 0; i < g_n_fns; i++)
        if(g_fns[i]->ix == ix) return g_fns[i];
    return NULL;
}

static gluefn *fn_queue(int ix) {
    gluefn *f = fn_find(ix);
    if(f) { f->queued = 1; return f; }
    if(g_n_fns == g_cap_fns) {
        int nc = g_cap_fns ? g_cap_fns * 2 : 64;
        gluefn **nf = realloc(g_fns, (size_t)nc * sizeof(gluefn *));
        if(!nf) { GFAIL("oom"); return NULL; }
        g_fns = nf; g_cap_fns = nc;
    }
    f = calloc(1, sizeof(gluefn));
    if(!f) { GFAIL("oom"); return NULL; }
    g_fns[g_n_fns++] = f;
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
static char *fnbase(flat_type *t) { return gcamel_flat(go_flat_ir_name(t)); }

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
static int n_is_seqof(flat_type *t) { return go_flat_ir_is_seqof(t); }
static int n_is_leaf(flat_type *t) { return go_flat_ir_is_leaf(t); }

/* ectx: one node's emission context (nested walks chain host bases). */
typedef struct {
    flat_type *t;          /* the node being walked                       */
    const char *owner_go;  /* its Go struct-owner name (row anchor;
                            * UNQUALIFIED — row keys are unqualified)    */
    const char *cbase;     /* C-address base expr for its member slots    */
    const char *cnode;     /* the flat NODE NAME its off consts key on
                            * (a nested walk keeps the HOST package node;
                            * composite consts carry the inner tokens)   */
    const char *cpre;      /* the composite const token prefix: "" at a
                            * package node, "<M>" inside one nested level
                            * (off<Node><M><Inner> = off<Node> + cpre<I>) */
    const char *val;       /* the Go value expr (borrowed; a *T or &F)    */
    char **szt, **fill, **read;  /* body-accumulator SLOTS (shared by ctx
                             * copies: ga moves the buffer, the slot
                             * stays; a copied ctx always sees the
                             * current string)                              */
    const char *depth;     /* the depth arg expr ("depth") or NULL        */
    int depth_on;          /* the walked node threads depth        */
} ectx;

/* gtype_q — the package-qualified Go type spelling of node t's own type from
 * the CURRENT emit module's view (g_emit_mod, forward-declared near qconst):
 * "T" when t's module == g_emit_mod, else "<pkg>.T" (the local fns are
 * per-package; the sibling packages of one go.mod are importable by their
 * module path "<mod>/<pkg>"). Malloc'd. */
static char *gtype_q(flat_type *t) {
    /* a SEQ-OF CONTAINER CLONE node (asn1c's ProtocolIE-Container 85Px
     * instantiations) has NO Go type row of its own — its Go spelling is
     * the referencing field's slice alias (<Msg>ProtocolIEs). Find
     * any IR member whose ref resolves to t, then that member's field
     * row's field_type IS the alias Go name. */
    if(t && go_flat_ir_is_seqof(t)) {
        /* NOTE: borrow-only scan — NO owned strings held across the row
         * hit (the loop frees its per-iteration temps on every path). */
        for(int ti = 0; ti < go_flat_ir_n_types(); ti++) {
            flat_type *host = go_flat_ir_type(ti);
            if(!host || host == t) continue;
            for(int mi = 0; mi < go_flat_ir_members(host); mi++) {
                flat_member *m = go_flat_ir_member(host, mi);
                if(!m || !go_flat_ir_member_is_ref(m)) continue;
                const char *rf = go_flat_ir_member_ref(m);
                flat_type *rr = rf ? go_flat_ir_ref_resolve(rf) : NULL;
                if(rr != t) continue;
                const char *nown = go_flat_ir_name(host);
                const char *tokraw = go_flat_ir_member_token(m);
                char *hostcam = gcamel_flat(nown ? nown : "");
                char *tokcam = gcamel(tokraw ? tokraw : "");
                for(int ri = 0; ri < go_names_rows_n(); ri++) {
                    const char *rk = go_names_row_kind(ri);
                    if(!rk || strcmp(rk, "field") != 0) continue;
                    const char *rwn = go_names_row_goname(ri);
                    if(!rwn || strcmp(rwn, tokcam) != 0) continue;
                    const char *rowner = go_names_row_sf_owner(ri);
                    if(!rowner || strcmp(rowner, hostcam) != 0) continue;
                    const char *ft_v = go_names_row_field_type(ri);
                    if(ft_v && *ft_v) {
                        const char *alias = (*ft_v == '*') ? ft_v + 1 : ft_v;
                        const char *rtm = go_flat_ir_module(t);
                        char *out;
                        if(rtm && g_emit_mod && strcmp(rtm, g_emit_mod) != 0) {
                            char *pk = gmodule_pkg(rtm);
                            out = gfmt("%s.%s", pk, alias);
                            free(pk);
                        } else {
                            out = gown(alias);
                        }
                        free(hostcam); free(tokcam);
                        return out;
                    }
                }
                free(hostcam); free(tokcam);
            }
        }
    }
    char *cam = gcamel_flat(go_flat_ir_name(t));
    const char *tm = t ? go_flat_ir_module(t) : NULL;
    if(!tm || !g_emit_mod || strcmp(tm, g_emit_mod) == 0) return cam;
    char *pkg = gmodule_pkg(tm);
    char *q = gfmt("%s.%s", pkg, cam);
    free(pkg); free(cam);
    return q;
}

static int dep_is_scc(flat_type *t) { return conv_is_scc(t); }

/* rt.Error literal text (TypeName from the display label, cid fallback). */
static char *
errlit(flat_type *t, const char *mfield, const char *code, const char *msg) {
    char *tl;
    { const char *lb = go_flat_ir_type_label(t);
      const char *tc = go_flat_ir_cid(t);
      const char *nm = go_flat_ir_name(t);
      tl = gown(lb && *lb ? lb : (tc ? tc : (nm ? nm : "")));
    }
    char *s = gfmt("rt.Error{Code: rt.%s, TypeName: \"%s\"", code, tl);
    if(mfield && *mfield) {
        s = ga(s, ", Field: \"");
        s = ga(s, mfield);
        s = ga(s, "\"");
    }
    if(msg && *msg) {
        s = ga(s, ", Message: \"");
        s = ga(s, msg);
        s = ga(s, "\"");
    }
    s = ga(s, "}");
    free(tl);
    return s;
}

/* Is `ft` (a field's Go type text) a bare primitive view? */
/* this package's BitString spelling: the local type when THIS package
 * declares one, else the OWNER's qualified name (used by the static bits
 * helpers' parameterization + every literal BitString bridge the glue
 * emits). */
static char *local_bitstring(void) {
    char *bsname = gown("BitString");
    for(int bi = 0; bi < go_names_rows_n(); bi++) {
        const char *bk = go_names_row_kind(bi);
        if(!bk || (strcmp(bk, "type") != 0 && strcmp(bk, "helper") != 0))
            continue;
        const char *bg = go_names_row_goname(bi);
        if(!bg || strcmp(bg, "BitString") != 0) continue;
        const char *bm = go_names_row_module(bi);
        if(bm && g_emit_mod && strcmp(bm, g_emit_mod) == 0)
            break;   /* ours: bare */
        if(bm) {
            char *pk = gmodule_pkg(bm);
            free(bsname);
            bsname = gfmt("%s.BitString", pk);
            free(pk);
        }
        break;
    }
    return bsname;
}

static int is_prim_view(const char *ft) {
    static const char *P[] = { "int32", "int64", "uint64", "float64", "bool",
                               "string", "[]byte", "BitString", "struct{}", "" };
    if(!ft) return 1;
    const char *u = unqual(ft);
    for(int i = 0; P[i][0]; i++)
        if(strcmp(u, P[i]) == 0) return 1;
    return 0;
}

/* The Go cast type of a member field: its row field_type base (a named
 * alias), falling back to the prim's canonical Go view. The caller strips
 * the pointer star. Always non-NULL. */
static char *qualify_alias(const char *alias);

static char *
field_cast(flat_type *t, const char *owner_go, const char *tok,
           const char *prim) {
    const char *ft = gf_field_type(owner_go, tok);
    if(ft && *ft) {
        /* the alias may be FOREIGN (the field row's type text names a type
         * of another package bare): qualify through its names row. */
        return qualify_alias(ft);
    }
    return gown(prim ? gprim_go(prim) : "");
}

/* qualify_alias — package-qualify a possibly-foreign alias spelling: find its
 * names row (type/inline kinds) by goName; when its module is foreign to
 * g_emit_mod, spell "<pkg>.<alias>" (star and pointee preserved). */
static char *
qualify_alias(const char *alias_in) {
    if(!alias_in || !*alias_in) return gown(alias_in ? alias_in : "");
    const char *st = alias_in;
    int star = 0;
    while(*st == '*') { star++; st++; }
    const char *base = unqual(st);
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *k = go_names_row_kind(i);
        if(!k || (strcmp(k, "type") != 0 && strcmp(k, "inline") != 0
                  && strcmp(k, "spec-key") != 0
                  && strcmp(k, "spec-value") != 0
                  && strcmp(k, "spec-pr") != 0
                  && strcmp(k, "choice-pr") != 0)) continue;
        const char *gn = go_names_row_goname(i);
        if(!gn || strcmp(gn, base) != 0) continue;
        const char *mrow = go_names_row_module(i);
        if(mrow && g_emit_mod && strcmp(mrow, g_emit_mod) != 0) {
            char *pk = gmodule_pkg(mrow);
            char pre[8];
            int si;
            for(si = 0; si < star && si < 7; si++) pre[si] = '*';
            pre[si] = 0;
            char *q = gfmt("%s%s.%s", pre, pk, base);
            free(pk);
            return q;
        }
        break;
    }
    /* local or unresolvable: keep the original spelling (star preserved) */
    return gown(alias_in);
}

/* ---------------------------------------------------------------------------
 * emit_prim — one scalar / bytes / bits member.
 * ------------------------------------------------------------------------- */
static void
emit_prim(ectx *E, flat_member *m) {
    const char *tok = go_flat_ir_member_token(m);
    const char *prim = go_flat_ir_member_prim(m);
    char *offc = qconst(E->cnode, g_offconst_pfx(E->cnode, E->cpre, tok));
    char *slot = gfmt("unsafe.Pointer(uintptr(%s) + uintptr(%s))", E->cbase, offc);
    const char *fgo = gf_field_goname(E->owner_go, tok);
    char *acc;
    {
        char *gtokA = fgo ? gown(fgo) : gcamel(tok);
        acc = gfmt("%s.%s", E->val, gtokA);
        free(gtokA);
    }
    const char *ft = gf_field_type(E->owner_go, tok);
    char *cast = field_cast(E->t, E->owner_go, tok, prim);
    int starred = *cast == '*';
    const char *cast0 = starred ? cast + 1 : cast;

    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
        const char *uel0 = unqual(ft);          /* may carry one leading '*' */
        const char *uel = (uel0 && uel0[0] == '*') ? uel0 + 1 : uel0;
        int is_str = uel && strcmp(uel, "string") == 0;
        int named_alias = ft && *ft && !is_str && !is_prim_view(ft);
        int ptr_ft = ft && *ft == '*';
        /* the SLOT's shape rules the pointer forms: a Go *[]byte/*string
         * field whose Flat member is an INLINE bytes_flat (a value-union
         * alt: asn1cgo_bytes_flat valueOctS) has NO pointer slot to test —
         * the record rides at slot+offset itself. Only a STARRED Flat
         * member (OPTIONAL bytes: asn1cgo_bytes_flat *x) takes the
         * p != nil + alloc/storePtr form. */
        int slot_ptr = ptr_ft && go_flat_ir_member_stars(m);
        if(is_str && !ptr_ft) {
            (*E->fill) = gam((*E->fill), gfmt("\twriteStringField(fa, %s, %s)\n", slot, acc));
            (*E->szt) = gam((*E->szt), gfmt("\tpayload += uintptr(len(%s))\n", acc));
        } else if(named_alias && !ptr_ft) {
            (*E->fill) = gam((*E->fill), gfmt("\twriteBytesField(fa, %s, []byte(%s))\n", slot, acc));
            (*E->szt) = gam((*E->szt), gfmt("\tpayload += uintptr(len([]byte(%s)))\n", acc));
        } else if(slot_ptr) {
            /* an OPTIONAL bytes field whose Go type is *[]byte / *string
             * AND whose Flat slot is a pointer: nil = absent (a non-nil
             * pointer slot is allocated + filled). BOTH twins allocate the
             * record and store the pointer — the bytes twin historically
             * wrote the {buf,len} record AT the pointer slot (16B into an
             * 8B slot, clobbering the next member); same shape as the
             * string twin now. */
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n\t\trec%d := fa.allocStruct(sizeofBytesFlat, alignInt64)\n"
                "\t\twrite%sField(fa, rec%d, %s*%s))\n\t\tstorePtr(%s, rec%d)\n\t}\n",
                acc, g_tmpseq, is_str ? "String" : "Bytes", g_tmpseq,
                is_str ? "string(" : "[]byte(", acc, slot, g_tmpseq));
            if(is_str) {
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := readStringField(unsafe.Pointer(p))\n\t\t%s = &sd\n\t}\n",
                    slot, acc));
            } else {
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := readBytesField(unsafe.Pointer(p))\n\t\t%s = &sd\n\t}\n",
                    slot, acc));
            }
            /* the fill allocates the bytes record in the FIXED region: the
             * size pass must add it under the same guard (payload-only
             * sizing undercounted — the same class as the leaf arm). */
            if(is_str) {
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBytesFlat)\n\t\tpayload += uintptr(len(string(*%s)))\n\t}\n",
                    acc, acc));
            } else {
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBytesFlat)\n\t\tpayload += uintptr(len([]byte(*%s)))\n\t}\n",
                    acc, acc));
            }
            g_tmpseq++;
        } else if(ptr_ft) {
            /* a value-union alt: the Go field is *[]byte/*string but the
             * Flat member is INLINE bytes_flat — no pointer slot, no nil
             * test; write/read the record at the slot itself. The union
             * alt is always present when selected, so unconditionally
             * deref the Go pointer (decode wrote it; a nil Go pointer at
             * encode means an unselected alt slot filled with zeros). */
            char *sdn2 = gfmt("sd%d", g_tmpseq++);
            if(is_str) {
                (*E->fill) = gam((*E->fill), gfmt("\twriteStringField(fa, %s, *%s)\n", slot, acc));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len(string(*%s)))\n", acc));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s := readStringField(%s)\n\t%s = &%s\n", sdn2, slot, acc, sdn2));
            } else {
                (*E->fill) = gam((*E->fill), gfmt("\twriteBytesField(fa, %s, *%s)\n", slot, acc));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len([]byte(*%s)))\n", acc));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s := readBytesField(%s)\n\t%s = &%s\n", sdn2, slot, acc, sdn2));
            }
            free(sdn2);
        } else {
            (*E->fill) = gam((*E->fill), gfmt("\twriteBytesField(fa, %s, %s)\n", slot, acc));
            /* sizing: the plain []byte (non-alias, non-ptr, non-str) member
             * allocs its byte slice in the payload region — reserve it
             * (the tail form after TNLinformation's starred one). */
            (*E->szt) = gam((*E->szt), gfmt("\tpayload += uintptr(len(%s))\n", acc));
        }
        /* read: a named []byte alias / plain []byte / string (ptr handled
         * above). SIZING NOTE: every fill-site
         * branch above ALREADY emitted its own szt line — the tail must
         * emit NONE. The old tail `payload += len(...)` for is_str was a
         * SECOND count of the same member (RANfunction-Name: payload
         * over-reserved by exactly the sum of its string lengths — the
         * exact-consumption invariant's first find). */
        if(!ptr_ft) {
            if(is_str) {
                (*E->read) = gam((*E->read), gfmt("\t%s = readStringField(%s)\n", acc, slot));
            } else if(named_alias) {
                (*E->read) = gam((*E->read), gfmt("\t%s = %s(readBytesField(%s))\n", acc, cast0, slot));
            } else {
                (*E->read) = gam((*E->read), gfmt("\t%s = readBytesField(%s)\n", acc, slot));
            }
        }
    } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
        if(ft && *ft == '*') {
            /* the pointee: the star-stripped field-type spelling; a BARE
             * foreign-field BitString needs the OWNING node's package's
             * helper form (the helper is per-package). */
            char *bst2 = NULL;
            {
                const char *uelb = ft + 1;
                if(strcmp(unqual(uelb), "BitString") == 0) {
                    const char *tm = go_flat_ir_module(E->t);
                    if(tm && g_emit_mod && strcmp(tm, g_emit_mod) != 0) {
                        char *pk = gmodule_pkg(tm);
                        bst2 = gfmt("%s.BitString", pk);
                        free(pk);
                    }
                }
            }
            if(!bst2) bst2 = gown(ft + 1);
            char *sdn = gfmt("sd%d", g_tmpseq++);
            char *lbs3 = local_bitstring();
            if(go_flat_ir_member_stars(m)) {
                /* a STARRED Flat slot (OPTIONAL BIT STRING): pointer test. */
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n\t\twriteBitsField(fa, %s, %s(*%s))\n\t}\n",
                    acc, slot, lbs3, acc));
                /* sizing (the e2connectionUpdate catch): the
                 * fill's writeBitsField allocs payload for the byte slice —
                 * the size fn MUST reserve it (same rule as the bytes member
                 * path; the undercount panicked blockArena.allocPayload on
                 * the first BitsField-bearing struct the corpus ever drove). */
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tpayload += uintptr(len((*%s).Bytes))\n\t}\n",
                    acc, acc));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\t%s := %s(readBitsField(unsafe.Pointer(p)))\n"
                    "\t\t%s = &%s\n\t}\n",
                    slot, sdn, bst2, acc, sdn));
            } else {
                /* a value-union alt: Go *BitString over an INLINE bits
                 * flat — the record rides at the slot itself. */
                (*E->fill) = gam((*E->fill), gfmt(
                    "\twriteBitsField(fa, %s, %s(*%s))\n", slot, lbs3, acc));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len((*%s).Bytes))\n", acc));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s := %s(readBitsField(%s))\n\t%s = &%s\n",
                    sdn, bst2, slot, acc, sdn));
            }
            free(sdn);
            free(lbs3);
            free(bst2);
        } else {
        (*E->fill) = gam((*E->fill), gfmt("\twriteBitsField(fa, %s, %s)\n", slot, acc));
        /* sizing: the plain (non-star, non-alias) member's bytes payload
         * (same rule as the starred form above). */
        (*E->szt) = gam((*E->szt), gfmt("\tpayload += uintptr(len(%s.Bytes))\n", acc));
        (*E->read) = gam((*E->read), gfmt("\t%s = readBitsField(%s)\n", acc, slot));
        }
    } else if(prim && strcmp(prim, "_bool32") == 0) {
        /* a starred bool view (an OPTIONAL BOOLEAN whose Go field is *bool
         * or a named *int32 alias): deref for truth; read wraps a temp.
         * A plain bool: store 0/1, read back != 0.
         * A STARRED FLAT SLOT (OPTIONAL member, int32_t *x in the .h) is a
         * pointer slot: alloc the leaf, write through it, storePtr — never
         * the value inline into the pointer field (the KPM noLabel/SUM
         * class caught by -asan item 2: value-in-slot made to_tree deref a
         * garbage/1 "pointer"). */
        if(go_flat_ir_member_stars(m)) {
            /* the leaf carves its slot from the 8-aligned fixed region:
             * allocate the PADDED width (8) so the region's alignment
             * invariant holds — a 4-byte int32 alloc between int64 allocs
             * forces 4 bytes of padding the width-summed sizing pass never
             * counts (measured live: undercount by 8 for two bools). C
             * reads the int32 through the stored pointer; bytes 4..7 stay
             * zero. */
            char *bn = gfmt("b%d", g_tmpseq++);
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n\t\t%s := fa.allocStruct(uintptr(8), alignInt64)\n"
                "\t\tif *%s {\n\t\t\t*(*int32)(unsafe.Pointer(%s)) = 1\n\t\t}\n"
                "\t\tstorePtr(%s, %s)\n\t}\n",
                acc, bn, acc, bn, slot, bn));
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif %s != nil {\n\t\tfixed += uintptr(8)\n\t}\n", acc));
            /* read: through the stored pointer slot */
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := *(*int32)(unsafe.Pointer(p)) != 0\n\t\t%s = &sd\n\t}\n",
                slot, acc));
            free(bn);
        } else if(ft && *ft == '*') {
            /* strip the pointer star + any package qualifier: the pointee's
             * own spelling (bool or a named scalar alias). */
            const char *st = ft + 1;
            const char *uel = unqual(st);
            if(strcmp(uel, "bool") == 0) {
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil && *%s {\n\t\t*(*int32)(%s) = 1\n\t}\n",
                    acc, acc, slot));
                /* read: a value-union alt is SELECTED whenever the switch
                 * dispatched here — a false wire value (int32==0) must
                 * still materialize the *bool alt (pointing at false), or
                 * Encode's selected-alt nil guard fires on it
                 * (KPM-TestCond-valueBool-false). */
                (*E->read) = gam((*E->read), gfmt(
                    "\tsd := *(*int32)(%s) != 0\n\t%s = &sd\n",
                    slot, acc));
            } else {
                char *tn = gfmt("b%d", g_tmpseq++);
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil && *(*%s)(%s) != 0 {\n\t\t*(*int32)(%s) = 1\n\t}\n",
                    acc, uel, acc, slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s := %s(*(*int32)(%s) != 0)\n\t%s = &%s\n",
                    tn, uel, slot, acc, tn));
                free(tn);
            }
        } else {
            (*E->fill) = gam((*E->fill), gfmt("\tif %s {\n\t\t*(*int32)(%s) = 1\n\t}\n", acc, slot));
            (*E->read) = gam((*E->read), gfmt("\t%s = *(*int32)(%s) != 0\n", acc, slot));
        }
    } else if(prim) {
        const char *gt = gprim_go(prim);
        if(gt && *gt) {
            if(go_flat_ir_member_stars(m)) {
                /* a STARRED FLAT SLOT over a prim leaf (OPTIONAL scalar
                 * member — int64_t *x in the .h): alloc the leaf, store the
                 * converted value through it, storePtr; size adds the leaf
                 * under the same guard (same class as _bool32 above). */
                char *pn = gfmt("p%d", g_tmpseq++);
                int gw = gprim_width(prim);
                if(gw < 8) gw = 8;   /* padded width: keep the fixed region
                                      * 8-aligned (see the _bool32 arm) */
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n\t\t%s := fa.allocStruct(uintptr(%d), alignInt64)\n"
                    "\t\t*(*%s)(unsafe.Pointer(%s)) = %s(*%s)\n\t\tstorePtr(%s, %s)\n\t}\n",
                    acc, pn, gw,
                    gt, pn, gt, acc, slot, pn));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := %s(*(*%s)(unsafe.Pointer(p)))\n\t\t%s = &sd\n\t}\n",
                    slot, cast0, gt, acc));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(%d)\n\t}\n", acc, gw));
                free(pn);
            } else if(ft && *ft == '*') {
                /* a POINTER field over a prim slot (an OPTIONAL ENUMERATED
                 * whose Go field is the *Named PR form): store deref'd (via
                 * the RAW prim conversion — named-alias assignability trap);
                 * read wraps the named conversion in a temp. */
                char *tn = gfmt("sd%d", g_tmpseq++);
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n\t\t*(*%s)(%s) = %s(*%s)\n\t}\n",
                    acc, gt, slot, gt, acc));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s := %s(*(*%s)(%s))\n\t%s = &%s\n",
                    tn, cast0, gt, slot, acc, tn));
                free(tn);
            } else {
            /* the STORE conversion goes to the RAW prim (gt): the LHS is
             * *gt and Go's assignability exemption needs a non-named side —
             * predeclared uint64/int64 ARE named, so a named-alias
             * conversion result is NOT assignable to *uint64 (repro'd). The
             * READ conversion keeps the FIELD's own type (cast0: the field
             * is the alias; raw -> named is always a legal conversion). */
            (*E->fill) = gam((*E->fill), gfmt("\t*(*%s)(%s) = %s(%s)\n", gt, slot, gt, acc));
            (*E->read) = gam((*E->read), gfmt("\t%s = %s(*(*%s)(%s))\n", acc, cast0, gt, slot));
            }
        } else {
            char *m2 = gfmt("member %s of %s: unmapped prim %s", tok, go_flat_ir_name(E->t), prim);
            GFAIL(m2); free(m2);
        }
    }
    free(offc); free(slot); free(acc); free(cast);
}

/* ---------------------------------------------------------------------------
 * Forward decls of the recursive emitters.
 * ------------------------------------------------------------------------- */


/* the depth ARG EXPRESSIONS at ref/fill/size call sites: "" when the target
 * takes no depth param; ", <expr>" else. Depth parity: Go counts
 * EXACTLY like the C converter — one increment per entry into an SCC-type
 * CONVERSION, and the C ++ sites sit on the SCC-INTERNAL arms only
 * (go_conv's choice-arm/seq-of hops). The ENTRY edge from a non-SCC host
 * into an SCC target costs ZERO in C (the counter is still 0 at cycle
 * entry), so a non-SCC host passes literal 0
 * PLAIN; only an SCC host (threads depth) charges +1 crossing into the
 * next cycle member. The old ", 0+1" form double-counted the entry and
 * made the Go pre-check trip one turn early (the 16-turn row red at the
 * leaf ValueType #17). */
static const char *hdf_fill(ectx *E, flat_type *target) {
    static char buf[32];
    if(!conv_is_scc(target)) return "";
    snprintf(buf, sizeof buf, ", %s",
             (E->depth && *E->depth) ? "depth+1" : "0");
    return buf;
}
static const char *hdf_size(ectx *E, flat_type *target) {
    static char buf[32];
    if(!conv_is_scc(target)) return "";
    /* MIRRORS hdf_fill (one increment per SCC edge, the seq-of Items hop
     * included): the size walk must trip at the same depth the fill walk
     * does — a flat ", depth" never incremented, so a cyclic value
     * stack-overflowed the size pass instead of tripping the depth guard (caught by
     * item-3's E_DEPTH test). Same parity form: non-SCC host = plain 0. */
    snprintf(buf, sizeof buf, ", %s",
             (E->depth && *E->depth) ? "depth+1" : "0");
    return buf;
}
static void emit_member(ectx *E, flat_member *m);
static void emit_ref(ectx *E, flat_member *m, flat_type *r);
static void emit_type_fn(flat_type *t);
static void emit_items_helper(flat_type *er);
static void emit_choice_at(ectx *E, flat_type *ch, const char *body_base,
                           const char *pv);
static void emit_nested(ectx *E, flat_member *m);
static const char *gf_pr_nothing(const char *prtype_q);

/* ---------------------------------------------------------------------------
 * emit_ref — one named-type member (FT_REF).
 *   r = resolved target node. Stars on the member row = the Flat slot is a
 *   pointer (an OPTIONAL *T whose Go field is *T, or by-value-in-Go with a
 *   pointer Flat slot); unstarred = the target is inline in the host.
 * A SEQ-OF target (named slice or container clone) emits through its
 * {items,count} header — via_ptr says whether the HEADER itself sits behind
 * the member's pointer slot.
 * ------------------------------------------------------------------------- */
static void
emit_ref(ectx *E, flat_member *m, flat_type *r) {
    /* queue the target's own fns first (leaf scalar triples included: a
     * LEAF-typedef target called by name needs its size/fill/read triple;
     * send_type-fn skips non-PDU leaves elsewhere). Not for nested_only
     * targets (they inline). */
    if(r && !go_flat_ir_is_nested_only(r)) emit_type_fn(r);
    const char *tok = go_flat_ir_member_token(m);
    int stars = go_flat_ir_member_stars(m);
    char *offc = qconst(E->cnode, g_offconst_pfx(E->cnode, E->cpre, tok));
    char *slot = gfmt("unsafe.Pointer(uintptr(%s) + uintptr(%s))", E->cbase, offc);
    const char *fgo = gf_field_goname(E->owner_go, tok);
    char *acc;
    {
        char *gtokA = fgo ? gown(fgo) : gcamel(tok);
        acc = gfmt("%s.%s", E->val, gtokA);
        free(gtokA);
    }
    char *rb = fnbase(r);
    char *tsz = qconst(go_flat_ir_name(r), g_szconst(go_flat_ir_name(r)));
    int scc = dep_is_scc(r);
    const char *dinc = scc ? ", depth+1" : "";   /* the target's own depth
                                                    arg inherits host depth */
    char *darg_t = dep_is_scc(r) ? gown(", depth") : gown("");
    /* the target's size/fill signature's depth arg when CALLED from host h:
     * the target threads depth iff IT is an SCC member; the host passes its
     * own depth expression (E's `depth`), or the literal 0 from a non-SCC
     * host into an SCC target. */
    const char *host_depth = dep_is_scc(E->t) ? "depth" : "0";

    if(go_flat_ir_is_seqof(r)) {
        /* {items,count}: ONE unified helper triple per element type:
         *   size<E>Items(&f, &p, slice)                    (nil/empty => 0)
         *   fill<E>Items(fa, hdrPtr, stride, slice) error  (hdr = the 16B
         *     {items,count} header, wherever it lives)
         *   read<E>Items(hdrPtr, stride) []E
         * unstarred: the header rides INLINE at the slot; starred (an
         * OPTIONAL named slice *X member): nil = absent (the slot
         * stays NULL); else the caller allocates one 16B header in the
         * fixed region, fills it, and stores its pointer at the slot. */
        const char *elem0 = go_flat_ir_elem(r);
        flat_type *er = elem0 ? go_flat_ir_ref_resolve(elem0) : NULL;
        {
            if(er) {
                emit_items_helper(er);
                /* the helper TRIPLE is keyed to the ELEMENT's name — a
                 * call site must spell the element camel too (rb is the
                 * SEQ-OF node's own name; the dedup table + the fill/read
                 * arms all key on the element). */
                char *erbn = fnbase(er);
                free(rb);
                rb = erbn;
            }
        }
        char *stride = NULL;
        { flat_type *ert = go_flat_ir_ref_resolve(go_flat_ir_elem(r));
          char *strv = ert ? g_szconst(go_flat_ir_name(ert)) : g_szconst("");
          stride = ert ? qconst(go_flat_ir_name(ert), strv) : strv; }
        /* the starred-vs-inline form keys on the FIELD TYPE's Go star
         * (a *NamedSlice member is a Go pointer EVEN when the Flat
         * member is an unstarred inline {items,count} header — C stars and
         * Go stars diverge exactly here). The POINTER form additionally
         * requires the Flat slot to BE a pointer slot (member stars): the
         * C flat writes an inline header THROUGH the address (e.g.
         * RANfunctionsID_List rides inline inside the ItemIEs value union,
         * &out->value.RANfunctionsID_List) — the disjunctive form emitted
         * storePtr(hdr) / *(**byte)(slot) on an inline slot (the pointer
         * test read the items FIELD as a header; live crash on the
         * RICserviceQuery row). Same conjunction the nested arm uses
         * (emit_nested's go_starred). */
        const char *sft = gf_field_type(E->owner_go, tok);
        /* four star-combination cases, keyed on (Go field star, Flat member
         * star) — the C slot's pointer-ness and the Go field's
         * pointer-ness vary INDEPENDENTLY:
         *   A sft* + stars: OPTIONAL named slice, pointer slot
         *   B value + stars: by-value slice behind a pointer slot
         *     (recursion break + the ChoiceList-ptr shape)
         *   C sft* + !stars: INLINE header at the slot, Go *NamedSlice
         *     (the value-union ALT lists)
         *   D value + !stars: plain inline header
         * The historical single `go_starred` disjunction (sft*)||(stars)
         * conflated A with C: C-shaped slots got storePtr/`(**byte)` forms
         * on an inline slot (live crash: RICserviceQuery read the items
         * FIELD as a header). */
        int go_starred = sft && *sft == '*' && stars;   /* case A only */
        if(go_starred && sft && *sft == '*') {
            /* the starred member's Go field is the *NamedSlice: pass
             * *acc (the deref'd slice) to the fill/size; read goes through a
             * temp (cannot &assign a []E into *NamedSlice directly). */
            char *dacc = gfmt("*%s", acc);
            char *tn = gfmt("sl%d", g_tmpseq++);
            /* the read conversion target: the star-stripped FIELD type,
             * package-QUALIFIED when the slice alias is foreign (the helper
             * returns the OWNING package's alias spelling). */
            char *nname = gtype_q(r);
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n"
                "\t\thdr := fa.allocStruct(16, alignPtr)\n"
                "\t\tif err := fill%sItems(fa, hdr, uintptr(%s), %s%s); err != nil {\n"
                "\t\t\treturn err\n\t\t}\n\t\tstorePtr(%s, hdr)\n\t}\n",
                acc, rb, stride, dacc, hdf_fill(E, er ? er : r), slot));
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n"
                "\t\t%s := read%sItems(unsafe.Pointer(p), uintptr(%s))\n"
                "\t\t%s = (*%s)(&%s)\n\t}\n",
                slot, tn, rb, stride, acc, nname, tn));
            /* sizing: the starred header itself is one 16B fixed-region
             * struct; nil/empty both count 0 via size<Seq>Items (App. G.2) */
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif %s != nil {\n\t\tfixed += uintptr(16)\n\t\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\t\treturn 0, 0, err\n\t\t}\n\t}\n",
                acc, rb, dacc, hdf_size(E, er ? er : r)));
            free(dacc); free(tn); free(nname);
            (void)0;
        } else if(sft && *sft == '*' && !stars) {
            /* case C — an INLINE {items,count} header at the slot whose Go
             * field is a *NamedSlice (the value-union ALT lists, e.g.
             * RICservice-Query-IEs value.RANfunctionsID_List: the C flat
             * writes the list INLINE at &out->value.RANfunctionsID_List).
             * fill: the nil guard selects absent-vs-present; the header is
             * written AT the slot (no allocStruct/storePtr — the slot is
             * not a pointer). read: temp + (*T)(&tmp) (a []E cannot be
             * assigned to *NamedSlice directly). sizing: the inline header
             * is PART OF THE PARENT STRUCT (its 16B ride the parent's own
             * sizeof<Parent>, already counted by the owner) — NO +16 here.
             * The old `fixed += 16` reserved 16B nothing ever allocated
             * (every E2AP wire with a param-container IE under-consumed by
             * exactly 16 per inline arm — the exact-consumption
             * invariant catches it). */
            char *dacc = gfmt("*%s", acc);
            char *tn = gfmt("sl%d", g_tmpseq++);
            char *nname = gtype_q(r);
            (void)go_starred;
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n"
                "\t\tif err := fill%sItems(fa, %s, uintptr(%s), %s%s); err != nil {\n"
                "\t\t\treturn err\n\t\t}\n\t}\n",
                acc, rb, slot, stride, dacc, hdf_fill(E, er ? er : r)));
            (*E->read) = gam((*E->read), gfmt(
                "\t%s := read%sItems(%s, uintptr(%s))\n"
                "\t%s = (*%s)(&%s)\n",
                tn, rb, slot, stride, acc, nname, tn));
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif %s != nil {\n\t\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\t\treturn 0, 0, err\n\t\t}\n\t}\n",
                acc, rb, dacc, hdf_size(E, er ? er : r)));
            free(dacc); free(tn); free(nname);
        } else if(stars) {
            /* case B — a by-value slice field behind a STARRED Flat header
             * slot (the by-value recursion-break shape, e.g. ChoiceList.
             * ranParameter_List: the flat slot holds a pointer to the
             * {items,count} header). No Go pointer, no nil guard: allocate
             * one header in the fixed region, fill it, store the pointer. */
            (*E->fill) = gam((*E->fill), gfmt(
                "\thdr := fa.allocStruct(16, alignPtr)\n"
                "\tif err := fill%sItems(fa, hdr, uintptr(%s), %s%s); err != nil {\n"
                "\t\treturn err\n\t}\n"
                "\tstorePtr(%s, hdr)\n",
                rb, stride, acc, hdf_fill(E, er ? er : r), slot));
            {
                char *tn = gfmt("sl%d", g_tmpseq++);
                char *nname = gtype_q(r);
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\t%s := read%sItems(unsafe.Pointer(p), uintptr(%s))\n"
                    "\t\t%s = %s(%s)\n\t}\n",
                    slot, tn, rb, stride, acc, nname, tn));
                free(tn); free(nname);
            }
            (*E->szt) = gam((*E->szt), gfmt(
                "\tfixed += uintptr(16)\n\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\treturn 0, 0, err\n\t}\n",
                rb, acc, hdf_size(E, er ? er : r)));
        } else {
            (*E->fill) = gam((*E->fill), gfmt("\tif err := fill%sItems(fa, %s, uintptr(%s), %s%s); err != nil {\n\t\treturn err\n\t}\n", rb, slot, stride, acc, hdf_fill(E, er ? er : r)));
            (*E->read) = gam((*E->read), gfmt("\t%s = read%sItems(%s, uintptr(%s))\n", acc, rb, slot, stride));
            (*E->szt) = gam((*E->szt), gfmt("\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\treturn 0, 0, err\n\t}\n", rb, acc, hdf_size(E, er ? er : r)));
        }
        free(stride);
        free(offc); free(slot); free(acc); free(rb); free(tsz); free(darg_t);
        return;
    }
    if(go_flat_ir_is_choice(r)) {
        /* a CHOICE reference member: struct-or-pointer per stars; the
         * choice switch runs at the slot (inline) or the pointed target.
         * A by-VALUE Go field behind a pointer Flat slot (the by-value recursion
         * break) always allocates + &field and derefs on read. */
        if(stars) {
            const char *sftc = gf_field_type(E->owner_go, tok);
            if(sftc && *sftc != '*') {
            (*E->fill) = gam((*E->fill), gfmt(
                "\ttgt := fa.allocStruct(uintptr(%s), alignInt64)\n"
                "\tif err := fill%s(fa, tgt, &%s%s); err != nil {\n\t\treturn err\n\t}\n"
                "\tstorePtr(%s, tgt)\n",
                tsz, rb, acc, hdf_fill(E, r), slot));
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n\t\trr, err := read%s(unsafe.Pointer(p))\n"
                "\t\tif err != nil { return nil, err }\n\t\t%s = *rr\n\t}\n",
                slot, rb, acc));
            (*E->szt) = gam((*E->szt), gfmt(
                "\t{\n\t\tf0, p0, err := size%s(&%s%s)\n"
                "\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += uintptr(%s)\n\t\tfixed += f0; payload += p0\n\t}\n",
                rb, acc, hdf_size(E, r), tsz));
            } else {
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n\t\ttgt := fa.allocStruct(uintptr(%s), alignInt64)\n"
                "\t\tif err := fill%s(fa, tgt, %s%s); err != nil {\n\t\t\treturn err\n\t\t}\n"
                "\t\tstorePtr(%s, tgt)\n\t\t}\n",
                acc, tsz, rb, acc, hdf_fill(E, r), slot));
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n\t\trr, err := read%s(unsafe.Pointer(p))\n"
                "\t\tif err != nil { return nil, err }\n\t\t%s = rr\n\t}\n",
                slot, rb, acc));
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif %s != nil {\n\t\tf0, p0, err := size%s(%s%s)\n"
                "\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += uintptr(%s)\n\t\tfixed += f0; payload += p0\n\t}\n",
                acc, rb, acc, hdf_size(E, r), tsz));
            }
        } else {
            /* inline target: &field for fill/size; non-shadowing read temp.
             * A VALUE-UNION ALT (Go *T field over an INLINE choice slot):
             * the field row's star (dotted <IE>.Value owner fallback) keys
             * the bare-pointer pass — the alt pass nil-guarded already. */
            const char *sfC = gf_field_type(E->owner_go, tok);
            int alt_ptrC = sfC && *sfC == '*';
            if(!sfC || !*sfC) {
                char *dottedC = gfmt("%s.Value", E->owner_go);
                const char *sfC3 = gf_field_type(dottedC, tok);
                if(sfC3 && *sfC3) sfC = sfC3;
                alt_ptrC = sfC && *sfC == '*';
                free(dottedC);
            }
            if(alt_ptrC) {
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif err := fill%s(fa, %s, %s%s); err != nil {\n\t\treturn err\n\t}\n",
                rb, slot, acc, hdf_fill(E, r)));
            {
                char *tn3 = gfmt("rd%d", g_tmpseq++);
                (*E->read) = gam((*E->read), gfmt(
                    "\t{\n\t\t%s, err := read%s(%s)\n\t\tif err != nil { return nil, err }\n\t\t%s = %s\n\t}\n",
                    tn3, rb, slot, acc, tn3));
                free(tn3);
            }
            (*E->szt) = gam((*E->szt), gfmt(
                "\t{\n\t\tf0, p0, err := size%s(%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += f0; payload += p0\n\t}\n", rb, acc, hdf_size(E, r)));
            } else {
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif err := fill%s(fa, %s, &%s%s); err != nil {\n\t\treturn err\n\t}\n",
                rb, slot, acc, hdf_fill(E, r)));
            {
                char *tn3 = gfmt("rd%d", g_tmpseq++);
                (*E->read) = gam((*E->read), gfmt(
                    "\t{\n\t\t%s, err := read%s(%s)\n\t\tif err != nil { return nil, err }\n\t\t%s = *%s\n\t}\n",
                    tn3, rb, slot, acc, tn3));
                free(tn3);
            }
            (*E->szt) = gam((*E->szt), gfmt(
                "\t{\n\t\tf0, p0, err := size%s(&%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += f0; payload += p0\n\t}\n", rb, acc, hdf_size(E, r)));
            }
        }
        free(offc); free(slot); free(acc); free(rb); free(tsz); free(darg_t);
        return;
    }
    /* A LEAF-typedef target (bytes/bits/scalar behind a named assignment):
     * the member row is FT_REF but the payload is a prim — bridge by the
     * prim's shape. The Go field's type text (the named alias) drives
     * the casts; the size const is the prim's fixed width (bytes/bits = the
     * shared Flat structs; scalars = the native width). */
    if(n_is_leaf(r)) {
        const char *prim = go_flat_ir_prim(r);
        const char *ft = gf_field_type(E->owner_go, tok);
        char *castbase = NULL;
        if(ft && *ft) castbase = gown(ft);
        else castbase = gown(prim ? gprim_go(prim) : "");
        char *cast = *castbase == '*' ? castbase + 1 : castbase;
        /* the cast's alias may be FOREIGN (a leaf PDU named in another
         * package): re-spell it via the target's own module (gtype_q —
         * local spelling when local, qualified when foreign). */
        {
            char *qct = gtype_q(r);
            if(qct && *qct && strcmp(qct, cast) != 0 && !strchr(cast, '.')) {
                /* keep the alias spelling the FIELD row gave (may be an
                 * alias of the leaf, not the leaf type itself) — only
                 * qualify when the name IS the target's own type name. */
                char *lcam = gcamel_flat(go_flat_ir_name(r));
                if(strcmp(cast, lcam) == 0) {
                    /* cast may be an INTERIOR pointer (castbase + 1) —
                     * replace by assignment, never free. */
                    cast = qct; qct = NULL;
                }
                free(lcam);
            }
            free(qct);
        }
        char *szc = NULL;
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) szc = gown("sizeofBytesFlat");
        else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) szc = gown("sizeofBitsFlat");
        else {
            /* PADDED width: a STARRED leaf's
             * alloc below uses alignInt32/Int64 bump-pointer placement — a
             * 4-byte alloc between 8-aligned neighbors forces 4B of struct
             * padding the narrow size never reserves (RICSsubscriptionAudit
             * undercounted by exactly 4). Reserve the padded 8 like every
             * sibling emitter (the _bool32 arm, the generic prim-star arm). */
            int gw0 = gprim_width(prim);
            if(gw0 < 8) gw0 = 8;
            szc = gfmt("uintptr(%d)", gw0);
        }
        const char *szexpr = szc;
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            /* the union-ALT form: a Go star-string / star-byte-slice /
             * star-alias field whose
             * Flat member is an INLINE bytes_flat record (no pointer slot) —
             * the p != nil / allocStruct / storePtr machinery below is for
             * a STARRED Flat slot only (an OPTIONAL bytes member). */
            int is_str = ft && strcmp(unqual(ft), "string") == 0;
            int ft_ptr = ft && *ft == '*';
            if(ft_ptr && !stars) {
                char *rrn = gfmt("rr%d", g_tmpseq++);
                if(is_str || !is_prim_view(cast)) {
                    const char *acast = is_str ? "string" : cast;
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBytesField(fa, %s, []byte(*%s))\n", slot, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s := %s(readBytesField(%s))\n\t%s = &%s\n",
                        rrn, acast, slot, acc, rrn));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tpayload += uintptr(len([]byte(*%s)))\n", acc));
                } else {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBytesField(fa, %s, []byte(*%s))\n", slot, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s := readBytesField(%s)\n\t%s = &%s\n", rrn, slot, acc, rrn));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tpayload += uintptr(len([]byte(*%s)))\n", acc));
                }
                free(rrn);
            } else if(stars) {
                /* the fill allocates the bytes/bits RECORD (sizeofBytesFlat
                 * / sizeofBitsFlat / the prim width) in the FIXED region
                 * behind the pointer slot — the sizing pass MUST add the
                 * same fixed footprint under the same nil-guard (the
                 * historical payload-only sizing undercounted the fixed
                 * region by exactly the record size; live panic:
                 * "fixed-region undercounted by 8/16" on RICaction-ToBe-
                 * Setup-Item.ric-Action-Definition). */
                if(is_str) {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\tif %s != nil {\n"
                        "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                        "\t\twriteStringField(fa, wv, string(*%s))\n"
                        "\t\tstorePtr(%s, wv)\n\t}\n",
                        acc, szexpr, acc, slot));
                    (*E->read) = gam((*E->read), gfmt(
                        "\tif p := *(**byte)(%s); p != nil {\n"
                        "\t\trr2 := %s(readStringField(unsafe.Pointer(p)))\n"
                        "\t\t%s = &rr2\n\t}\n", slot, cast, acc));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tif %s != nil {\n\t\tfixed += uintptr(%s)\n\t\tpayload += uintptr(len(string(*%s)))\n\t}\n",
                        acc, szexpr, acc));
                } else {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\tif %s != nil {\n"
                        "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                        "\t\twriteBytesField(fa, wv, []byte(*%s))\n"
                        "\t\tstorePtr(%s, wv)\n\t}\n",
                        acc, szexpr, acc, slot));
                    (*E->read) = gam((*E->read), gfmt(
                        "\tif p := *(**byte)(%s); p != nil {\n"
                        "\t\trr2 := %s(readBytesField(unsafe.Pointer(p)))\n"
                        "\t\t%s = &rr2\n\t}\n", slot, cast, acc));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tif %s != nil {\n\t\tfixed += uintptr(%s)\n\t\tpayload += uintptr(len([]byte(*%s)))\n\t}\n",
                        acc, szexpr, acc));
                }
            } else {
                if(is_str) {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteStringField(fa, %s, string(%s))\n", slot, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = %s(readStringField(%s))\n", acc, cast, slot));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tpayload += uintptr(len(string(%s)))\n", acc));
                } else {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBytesField(fa, %s, []byte(%s))\n", slot, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = %s(readBytesField(%s))\n", acc, cast, slot));
                }
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len([]byte(%s)))\n", acc));
            }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            if(stars) {
                /* the pointee's type: the star-stripped field-type spelling,
                 * or — for a bare foreign-field BitString — the OWNING
                 * node's package's helper form (the helper is per-package;
                 * the field lives in another package's type). */
                char *bst = NULL;
                if(ft && *ft == '*') {
                    bst = qualify_alias(ft);
                } else {
                    const char *tm = go_flat_ir_module(E->t);
                    if(tm && g_emit_mod && strcmp(tm, g_emit_mod) != 0) {
                        char *pk = gmodule_pkg(tm);
                        bst = gfmt("%s.BitString", pk);
                        free(pk);
                    } else {
                        bst = gown("BitString");
                    }
                }
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                    "\t\twriteBitsField(fa, wv, BitString(%s(*%s)))\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n", acc, szexpr, bst, acc, slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\tbs := %s(readBitsField(unsafe.Pointer(p)))\n"
                    "\t\t%s = &bs\n\t}\n", slot, bst, acc));
                free(bst);
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(%s)\n\t\tpayload += uintptr(len((*%s).Bytes))\n\t}\n",
                    acc, szexpr, acc));
            } else {
                /* a BitString-alias member (a distinct named type): bridge
                 * field-wise both directions. */
                const char *ub = unqual(ft);
                int alias_bs = ub && strcmp(ub, "BitString") != 0
                               && strcmp(ub, "struct{}") != 0;
                if(alias_bs) {
                    /* the alias may be FOREIGN (declared in another
                     * package): spell it package-qualified (qualify_alias);
                     * the BitString side of the bridge is THIS package's
                     * helper spelling (a foreign alias bridges to the
                     * owner's BitString — the helper takes the local
                     * parameterized type). */
                    char *qa = ft ? qualify_alias(ft) : gown(ub);
                    char *local_bs = local_bitstring();
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBitsField(fa, %s, %s{Bytes: %s.Bytes, BitsUnused: %s.BitsUnused})\n",
                        slot, local_bs, acc, acc));
                    free(local_bs);
                    char *tn = gfmt("bs%d", g_tmpseq++);
                    /* a UNION-ALT field is a Go POINTER (*Alias): assign
                     * the composite's address; a by-value field (a plain
                     * member) takes the value form. */
                    const char *sfB = gf_field_type(E->owner_go, tok);
                    int ptr_field_b = sfB && *sfB == '*';
                    if(!sfB || !*sfB) {
                        char *dottedB = gfmt("%s.Value", E->owner_go);
                        const char *sfB3 = gf_field_type(dottedB, tok);
                        if(sfB3 && *sfB3) ptr_field_b = *sfB3 == '*';
                        free(dottedB);
                    }
                    if(ptr_field_b) {
                        const char *qa0 = qa;
                        while(*qa0 == '*') qa0++;   /* the & literal wants the bare type */
                        (*E->read) = gam((*E->read), gfmt(
                            "\t%s := readBitsField(%s)\n"
                            "\t%s = &%s{Bytes: %s.Bytes, BitsUnused: %s.BitsUnused}\n",
                            tn, slot, acc, qa0, tn, tn));
                    } else {
                        (*E->read) = gam((*E->read), gfmt(
                            "\t%s := readBitsField(%s)\n"
                            "\t%s = %s{Bytes: %s.Bytes, BitsUnused: %s.BitsUnused}\n",
                            tn, slot, acc, qa, tn, tn));
                    }
                    free(tn); free(qa);
                } else {
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBitsField(fa, %s, %s)\n", slot, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = readBitsField(%s)\n", acc, slot));
                }
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len(%s.Bytes))\n", acc));
            }
        } else {
            const char *gt = gprim_go(prim);
            if(!gt || !*gt) {
                char *m2 = gfmt("leaf ref %s.%s: prim %s unmapped",
                                go_flat_ir_name(E->t), tok, prim ? prim : "?");
                GFAIL(m2); free(m2);
            } else if(stars) {
                /* the STORE converts to the RAW prim (the named-alias trap:
                 * predeclared int64/uint64 are named — see emit_prim).
                 * The alloc takes the PADDED width at alignInt64:
                 * a 4-byte leaf alloc between 8-aligned neighbors pads the
                 * next alloc by 4 — size now reserves the same 8). */
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                    "\t\t*(*%s)(wv) = %s(*%s)\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n",
                    acc, szexpr, gt, gt, acc, slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\tsd := %s(*(*%s)(unsafe.Pointer(p)))\n"
                    "\t\t%s = &sd\n\t}\n", slot, cast, gt, acc));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += %s\n\t}\n", acc, szexpr));
            } else {
                int ptr_ft = ft && *ft == '*';
                char *ival_o = ptr_ft ? gfmt("(*%s)", acc) : NULL;
                const char *ival = ptr_ft ? ival_o : acc;
                const char *fcast = ptr_ft ? gt : cast;
                /* the STORE converts to the RAW prim (gt): assignability
                 * exemption needs a non-named side and predeclared
                 * uint64/int64 are NAMED (same trap as emit_prim). */
                (void)fcast;
                (*E->fill) = gam((*E->fill), gfmt(
                    "\t*(*%s)(%s) = %s(%s)\n", gt, slot, gt, ival));
                if(ptr_ft) {
                    char *tn = gfmt("sd%d", g_tmpseq++);
                    char *sdv = gfmt("\t%s := %s(*(*%s)(%s))\n\t%s = &%s\n",
                                     tn, cast, gt, slot, acc, tn);
                    (*E->read) = ga((*E->read), sdv);
                    free(sdv); free(tn);
                } else {
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = %s(*(*%s)(%s))\n", acc, cast, gt, slot));
                }
                free(ival_o);
            }
        }
        /* cast may have been REASSIGNED to gtype_q's result (the qualify
         * block above steals it with qct = NULL) — free its OWN copy when
         * it no longer points into castbase. */
        if(cast != castbase && cast != castbase + 1) free(cast);
        free(castbase); free(szc);
        free(offc); free(slot); free(acc); free(rb); free(tsz); free(darg_t);
        return;
    }

    /* plain STRUCT target. */
    if(stars) {
        /* OPTIONAL *T / recursion break: nil = absent; non-nil = one
         * target struct in the fixed region. E_INTERNAL is NOT raised here
         * on encode (nil is the caller's absence statement); decode NULL
         * on a NON-OPTIONAL starred slot raises E_INTERNAL in read. */
        /* by-value recursion break: the Flat slot is a pointer but the
         * Go field carries the value (no Go pointer, no nil guard — always
         * allocate + &field; read derefs). A *T Go field: nil = absent. */
        const char *sftv = gf_field_type(E->owner_go, tok);
        int value_field = !(sftv && *sftv == '*');
        if(value_field) {
            (*E->fill) = gam((*E->fill), gfmt(
                "\ttgt := fa.allocStruct(uintptr(%s), alignInt64)\n"
                "\tif err := fill%s(fa, tgt, &%s%s); err != nil {\n\t\treturn err\n\t}\n"
                "\tstorePtr(%s, tgt)\n",
                tsz, rb, acc, hdf_fill(E, r), slot));
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n\t\trr, err := read%s(unsafe.Pointer(p))\n"
                "\t\tif err != nil { return nil, err }\n\t\t%s = *rr\n\t}\n",
                slot, rb, acc));
            (*E->szt) = gam((*E->szt), gfmt(
                "\t{\n\t\tf0, p0, err := size%s(&%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += uintptr(%s) + f0; payload += p0\n\t}\n",
                rb, acc, hdf_size(E, r), tsz));
        } else {
        (*E->fill) = gam((*E->fill), gfmt(
            "\tif %s != nil {\n\t\ttgt := fa.allocStruct(uintptr(%s), alignInt64)\n"
            "\t\tif err := fill%s(fa, tgt, %s%s); err != nil {\n\t\t\treturn err\n\t\t}\n"
            "\t\tstorePtr(%s, tgt)\n\t\t}\n",
            acc, tsz, rb, acc, hdf_fill(E, r), slot));
        (*E->read) = gam((*E->read), gfmt(
            "\tif p := *(**byte)(%s); p != nil {\n\t\trr, err := read%s(unsafe.Pointer(p))\n"
            "\t\tif err != nil { return nil, err }\n\t\t%s = rr\n\t}\n",
            slot, rb, acc));
        (*E->szt) = gam((*E->szt), gfmt(
            "\tif %s != nil {\n\t\tf0, p0, err := size%s(%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
            "\t\tfixed += uintptr(%s) + f0; payload += p0\n\t}\n",
            acc, rb, acc, hdf_size(E, r), tsz));
        }
    } else {
        /* inline (unstarred) target: the fn takes *T — pass &field for
         * fill/size; read assigns through a NON-SHADOWING temp (a temp
         * named `v` shadows the receiver and self-assigns — the anchor's
         * recorded read-side accessor bug, now fixed here).
         * A VALUE-UNION ALT: the Go field is *T (the union's alt slots are
         * pointers in Go) while the Flat alt rides INLINE — the alt pass
         * above already nil-guarded, so pass the bare pointer (no &)
         * fill/size and assign the read result pointer directly. */
        const char *sf2 = gf_field_type(E->owner_go, tok);
        int alt_ptr = sf2 && *sf2 == '*';
        {
            FILE *tf = fopen("/tmp/inl_trace.txt", "a");
            if(tf) {
                fprintf(tf, "inline-ref owner=%s tok=%s sf2=%s\n",
                        E->owner_go ? E->owner_go : "?",
                        tok ? tok : "?",
                        sf2 ? sf2 : "(null)");
                fclose(tf);
            }
        }
        if(!sf2 || !*sf2) {
            /* value-union inner fields' rows key on the DOTTED owner
             * (<IE>.Value): fall back to that spelling before concluding
             * the Go field is by-value. */
            char *dotted = gfmt("%s.Value", E->owner_go);
            const char *sf3 = gf_field_type(dotted, tok);
            if(sf3 && *sf3) sf2 = sf3;
            alt_ptr = sf2 && *sf2 == '*';
            free(dotted);
        }
        if(alt_ptr) {
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif err := fill%s(fa, %s, %s%s); err != nil {\n\t\treturn err\n\t}\n",
                rb, slot, acc, hdf_fill(E, r)));
            {
                char *tn2 = gfmt("rd%d", g_tmpseq++);
                (*E->read) = gam((*E->read), gfmt(
                    "\t{\n\t\t%s, err := read%s(%s)\n\t\tif err != nil { return nil, err }\n\t\t%s = %s\n\t}\n",
                    tn2, rb, slot, acc, tn2));
                free(tn2);
            }
            (*E->szt) = gam((*E->szt), gfmt(
                "\t{\n\t\tf0, p0, err := size%s(%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
                "\t\tfixed += f0; payload += p0\n\t}\n", rb, acc, hdf_size(E, r)));
        } else {
        /* value-union ALT go-pointer over an INLINE flat: same keying as
         * the CHOICE-branch inline arm (field row star, dotted-owner
         * fallback) — pass the bare pointer, assign the read result. */
        const char *sfS = gf_field_type(E->owner_go, tok);
        int alt_ptrS = sfS && *sfS == '*';
        if(!sfS || !*sfS) {
            char *dottedS = gfmt("%s.Value", E->owner_go);
            const char *sfS3 = gf_field_type(dottedS, tok);
            if(sfS3 && *sfS3) sfS = sfS3;
            alt_ptrS = sfS && *sfS == '*';
            free(dottedS);
        }
        if(alt_ptrS) {
        (*E->fill) = gam((*E->fill), gfmt(
            "\tif err := fill%s(fa, %s, %s%s); err != nil {\n\t\treturn err\n\t}\n",
            rb, slot, acc, hdf_fill(E, r)));
        {
            char *tn2 = gfmt("rd%d", g_tmpseq++);
            (*E->read) = gam((*E->read), gfmt(
                "\t{\n\t\t%s, err := read%s(%s)\n\t\tif err != nil { return nil, err }\n\t\t%s = %s\n\t}\n",
                tn2, rb, slot, acc, tn2));
            free(tn2);
        }
        (*E->szt) = gam((*E->szt), gfmt(
            "\t{\n\t\tf0, p0, err := size%s(%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
            "\t\tfixed += f0; payload += p0\n\t}\n", rb, acc, hdf_size(E, r)));
        } else {
        (*E->fill) = gam((*E->fill), gfmt(
            "\tif err := fill%s(fa, %s, &%s%s); err != nil {\n\t\treturn err\n\t}\n",
            rb, slot, acc, hdf_fill(E, r)));
        {
            char *tn2 = gfmt("rd%d", g_tmpseq++);
            (*E->read) = gam((*E->read), gfmt(
                "\t{\n\t\t%s, err := read%s(%s)\n\t\tif err != nil { return nil, err }\n\t\t%s = *%s\n\t}\n",
                tn2, rb, slot, acc, tn2));
            free(tn2);
        }
        (*E->szt) = gam((*E->szt), gfmt(
            "\t{\n\t\tf0, p0, err := size%s(&%s%s)\n\t\tif err != nil { return 0, 0, err }\n"
            "\t\tfixed += f0; payload += p0\n\t}\n", rb, acc, hdf_size(E, r)));
        }
        }
    }
    free(offc); free(slot); free(acc); free(rb); free(tsz); free(darg_t);
    (void)dinc; (void)host_depth;
}


/* ---------------------------------------------------------------------------
 * Const-address model (KEEPS THE WHOLE EMITTER FLAT): every member slot is
 * addressed as base + <const>, where <const> is a *C expression* string the
 * emitter builds from the node/token pairs along the containment path:
 *    a package-scoped node's member M:            off<Node><M>
 *    a nested node's member I under host member M: off<Host><M><I>
 * (both go_flat.c const spellings — go_off_const / go_off_const2). The base
 * expression chains identically on the C side (a nested inline member's
 * base = the host member's slot) and on the Go side (v.HostM.I).
 * ------------------------------------------------------------------------- */

/* emit_nested — one inline anonymous struct member (FT_NESTED): an inline
 * CHOICE wrapper, the open-type value union ({present,alts}, present-first),
 * or a nested {items,count} SEQ OF. The nested node rides INSIDE the host:
 * inner member slots = hostMemberSlot + off<Host><M><Inner> composite consts
 * (the nested walk re-bases the cbase at the host member's slot); the Go
 * value rides the host field (the minted named type / <X>Value union,
 * always BY VALUE — a field-shaped spec's `Value` field). The owner_go for
 * the nested rows = the nested node's own Go name (its field rows hang
 * under their minted struct-owner name: e.g. RICsubscriptionRequestIEsValue).
 */
static void
emit_nested(ectx *E, flat_member *m) {
    const char *tok = go_flat_ir_member_token(m);
    int nix = go_flat_ir_member_nested_ix(m);
    flat_type *n = (nix >= 0 && nix < go_flat_ir_n_types())
                       ? go_flat_ir_type(nix) : NULL;
    if(!n) {
        char *m2 = gfmt("nested member %s.%s has no node", go_flat_ir_name(E->t), tok);
        GFAIL(m2); free(m2);
        return;
    }
    char *offc = qconst(E->cnode, g_offconst_pfx(E->cnode, E->cpre, tok));
    char *slot = gfmt("unsafe.Pointer(uintptr(%s) + uintptr(%s))", E->cbase, offc);
    const char *fgo = gf_field_goname(E->owner_go, tok);
    char *ft = gf_field_type(E->owner_go, tok) ? gown(gf_field_type(E->owner_go, tok)) : NULL;
    char *acc;
    {
        char *gtok = fgo ? gown(fgo) : gcamel(tok);
        acc = gfmt("%s.%s", E->val, gtok);
        free(gtok);
    }
    char *nb = gcamel_flat(go_flat_ir_name(n));   /* the nested node's Go base name */

    /* the nested node's Go owner name: its field rows live under the
     * minted struct-owner (the <X>Value union / the <Parent><M> inline) —
     * rows are keyed UNQUALIFIED, so strip a package qualifier from the
     * field_type; fall back to the camel node base (same name by mint). */
    char *nowner = NULL;
    {
        const char *obase = ft ? unqual(ft) : nb;
        nowner = gown(obase);
    }

    if(n_is_seqof(n)) {
        /* the nested {items,count} SEQ OF member: header inline under the
         * member token; the item array via the elem node's stride const.
         * Go: the named slice field; nil/empty both count 0. */
        const char *elem = go_flat_ir_elem(n);
        flat_type *er = go_flat_ir_ref_resolve(elem);
        if(!er) {
            char *m2 = gfmt("nested seqof %s.%s: unresolved elem", go_flat_ir_name(E->t), tok);
            GFAIL(m2); free(m2);
            free(offc); free(slot); free(acc); free(ft); free(nowner); free(nb);
            return;
        }
        char *stride = qconst(go_flat_ir_name(er), g_szconst(go_flat_ir_name(er)));
        char *erb = gcamel_flat(go_flat_ir_name(er));
        /* the element's own fill/read call + item sizing (the unified
         * 4-arg/2-arg helper shapes). A *NamedSlice field (Go star)
         * wraps in the nil-guard + temp form even though the Flat header
         * rides inline at the slot here (mirror of emit_ref's starred arm:
         * C stars and Go stars diverge on this exact member class). */
        emit_items_helper(er);
        /* by-value recursion break, the nested-seqof form: the Flat
         * member is a starred {items,count} header pointer, but the Go
         * FIELD may carry the value (RANParameterTestingItemChoiceStructure.
         * RanParameterStructure is a VALUE struct field) — the starred Go
         * arm keys on the FIELD's Go star, not the Flat member's. */
        int go_starred = ft && *ft == '*' && go_flat_ir_member_stars(m);
        if(go_starred) {
            char *dacc = gfmt("*%s", acc);
            char *tn = gfmt("sl%d", g_tmpseq++);
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif %s != nil {\n"
                "\t\thdr := fa.allocStruct(16, alignPtr)\n"
                "\t\tif err := fill%sItems(fa, hdr, uintptr(%s), %s%s); err != nil {\n"
                "\t\t\treturn err\n\t\t}\n"
                "\t\tstorePtr(%s, hdr)\n\t}\n",
                acc, erb, stride, dacc, hdf_fill(E, er), slot));
            (*E->read) = gam((*E->read), gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n"
                "\t\t%s := read%sItems(unsafe.Pointer(p), uintptr(%s))\n"
                "\t\t%s = (*%s)(&%s)\n\t}\n",
                slot, tn, erb, stride, acc, ft && *ft == '*' ? ft + 1 : ft, tn));
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif %s != nil {\n\t\tfixed += uintptr(16)\n\t\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\t\treturn 0, 0, err\n\t\t}\n\t}\n",
                acc, erb, dacc, hdf_size(E, er)));
            free(dacc); free(tn);
        } else {
            (*E->fill) = gam((*E->fill), gfmt(
                "\tif err := fill%sItems(fa, %s, uintptr(%s), %s%s); err != nil {\n\t\treturn err\n\t}\n", erb, slot, stride, acc, hdf_fill(E, er)));
            (*E->read) = gam((*E->read), gfmt(
                "\t%s = read%sItems(%s, uintptr(%s))\n", acc, erb, slot, stride));
            (*E->szt) = gam((*E->szt), gfmt(
                "\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\treturn 0, 0, err\n\t}\n", erb, acc, hdf_size(E, er)));
        }
        free(stride); free(erb);
        free(offc); free(slot); free(acc); free(ft); free(nowner); free(nb);
        return;
    }

    if(go_flat_ir_is_choice(n)) {
        /* inline CHOICE / value union at the slot; the Go value is the host
         * field by value (&field is the value pointer the switch reads).
         * The union's member consts key on the HOST node with THIS member's
         * token chained into cpre (off<Host><M><inner>, go_flat.c's
         * go_off_const2 spelling) — so the walk enters with cpre chained
         * (and the alt walk does NOT chain again: emit_choice_at's package
         * vs nested distinction reads ch != E->t).
         *
         * DOUBLE-ADD FIX (bug 2 class): the composite consts
         * off<Host><M><inner> are ABSOLUTE from the node top (they carry
         * offsetof(host,M) inside them — layout.go m->offset + im->offset,
         * go_flat.c:1614; the C assert's typeof-sum spells the same). The
         * walk base for inner members must therefore stay the NODE base
         * (E->cbase), NOT the member slot: slot + composite would add
         * offsetof(host,M) twice (caught as bug 2: KPM-ActionDefinition
         * read Present = slot+8+8 = the Format1 pointer slot, garbage
         * 0x1dea90e0 / code=8 on re-encode). The member slot itself is
         * still used where the MEMBER is addressed (the SEQ OF header at
         * the slot, below). */
        char *pv = gfmt("&%s", acc);
        ectx A = *E;
        A.t = n;
        A.owner_go = nowner;
        A.cbase = gown(E->cbase);
        const char *host_pre = (E->cpre && *E->cpre) ? E->cpre : "";
        A.cpre = gown(host_pre[0] ? gfmt("%s%s", host_pre, tok) : tok);
        A.val = gown(acc);
        emit_choice_at(&A, n, E->cbase, pv);
        free(pv);
        free_const(A.cbase); free_const(A.cpre); free_const(A.val);
        free(offc); free(slot); free(acc); free(ft); free(nowner); free(nb);
        return;
    }

    /* a nested inline STRUCT wrapper: descend in place — inner members key
     * composite consts off<Host><M><Inner> (ABSOLUTE from the node top, the
     * same double-add rule as the choice arm above), so the walk base stays
     * the NODE base; the Go field descends by value. */
    {
        ectx E2 = *E;              /* shares szt/fill/read + depth */
        E2.t = n;
        E2.owner_go = nowner;      /* rows hang under the minted name */
        E2.cbase = gown(E->cbase); /* NOT slot: composite consts carry off<M> */
        /* the inner member const prefix: composite — off<HostNode><M><I>.
         * Implemented by carrying (host node, inner token-prefix) in the
         * const formatter: cnode stays the HOST node and cpre carries M. */
        E2.cnode = E->cnode;
        E2.cpre = tok;
        E2.val = gown(acc);
        for(int i = 0; i < go_flat_ir_members(n); i++)
            emit_member(&E2, go_flat_ir_member(n, i));
        (*E->szt) = (*E2.szt); (*E->fill) = (*E2.fill); (*E->read) = (*E2.read);   /* ga moved them */
        free_const(E2.cbase); free_const(E2.val);
        /* nowner consumed by E2 (borrowed into rows lookups; still ours) */
        free(ft);
        free(offc); free(slot); free(acc); free(nowner); free(nb);
        return;
    }
}

/* The Go struct-owner name of node t (its field rows' anchor): the
 * package-scoped row's goName, falling back to camel(node) — a nested
 * node's rows hang under its minted owner name (<X>Value / <Parent><M>),
 * which camel(node) reproduces (<X>__value -> <X>Value). */
static const char *
gowner(flat_type *t, char **owned_out) {
    *owned_out = NULL;
    const char *gn = gf_goname(t);
    if(gn) return gn;
    *owned_out = gcamel_flat(go_flat_ir_name(t));
    return *owned_out;
}


/* size line for a prim CHOICE alt: bytes/bits payload only (inline scalar
 * alts ride in the choice body). */
static char *
size_prim_alt(flat_member *m, const char *acc) {
    const char *prim = go_flat_ir_member_prim(m);
    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0)
        return gfmt("\tpayload += uintptr(len(%s))\n", acc);
    if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0)
        return gfmt("\tpayload += uintptr(len(%s.Bytes))\n", acc);
    return strdup("");
}

/* the qualified const identifier of a Pr/enum const from emit module's
 * view (package qualification: a const declared in another module carries its package
 * qualifier). */
static char *qcconst(const char *cbase, const char *suffix) {
    char *want = gfmt("%s%s", cbase, suffix);
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *k = go_names_row_kind(i);
        if(!k || (strcmp(k, "choice-const") != 0
                  && strcmp(k, "enum-const") != 0
                  && strcmp(k, "value-const") != 0)) continue;
        const char *gn = go_names_row_goname(i);
        if(gn && strcmp(gn, want) == 0) {
            const char *mod = go_names_row_module(i);
            if(mod && g_emit_mod && strcmp(mod, g_emit_mod) == 0)
                { free(want); return gfmt("%s%s", cbase, suffix); }
            char *pkg = gmodule_pkg(mod);
            char *q = gfmt("%s.%s%s", pkg, cbase, suffix);
            free(pkg); free(want);
            return q;
        }
    }
    free(want);
    return gfmt("%s%s", cbase, suffix);
}

/* rebalance_switch: the emitted szt switch has bare case arms whose
 * statements share one scope (f0/p0/err redeclarations collide); wrap each
 * arm body in braces and turn repeated ':=' after the first in an arm into
 * '='. In-place edit of the buffer at *slot (realloc'd through ga). */
static void rebalance_switch(char **slot) {
    char *src = *slot;
    if(!src) return;
    /* find the LAST "\tswitch " line; arms follow it */
    char *p = src;
    char *last = NULL;
    while((p = strstr(p, "\tswitch ")) != NULL) { last = p; p++; }
    if(!last) return;
    char *out = strdup("");
    char *rest = gown(last);
    /* iterate lines of rest */
    char *line = strtok(rest, "\n");
    int arm = 0;
    int in_arm = 0;
    while(line) {
        if(strncmp(line, "\tcase ", 6) == 0 || strncmp(line, "\tdefault:", 9) == 0) {
            if(in_arm) out = ga(out, "\n\t}");
            out = ga(out, "\n");
            out = ga(out, line);
            out = ga(out, "\n\t{");
            in_arm = 1;
            arm++;
        } else {
            out = ga(out, "\n");
            out = ga(out, line);
        }
        line = strtok(NULL, "\n");
    }
    if(in_arm) out = ga(out, "\n\t}");
    /* splice: src up to last + rebalanced rest */
    size_t head = (size_t)(last - src);
    char *joined = malloc(head + strlen(out) + 2);
    memcpy(joined, src, head);
    strcpy(joined + head, out);
    free(out); free(rest); free(src);
    *slot = joined;
}
/* emit_choice_at — the CHOICE/union switch of node `ch` (present-first):
 * a package CHOICE node, an inline CHOICE, or the open-type value union.
 *   host_inner   "" = ch sits ON the walked node's own body (a package
 *                 CHOICE / the walked node IS a choice); else the member
 *                 token path prefix (the composite const chain).
 *   body_base    the C expr of ch's body (present + alts)
 *   pv           the Go value pointer expr (*T var or &unionField)
 * The switch cases emit per-alt member emission inline (ch's member rows).
 */
static void
emit_choice_at(ectx *E, flat_type *ch, const char *body_base,
               const char *pv) {
    char *owner_own = NULL;
    const char *ch_owner = gowner(ch, &owner_own);
    const char *prtype_q = gf_present_type(ch_owner);   /* may be qualified */
    /* a foreign Pr type's package qualifier: the row of the Present field's
     * TYPE (a type row named <PrBase>); when its module is foreign, spell
     * the Pr type through its package (mirror of qcconst for type names). */
    char *prtype_own = NULL;
    {
        const char *pb = unqual(prtype_q);
        for(int i = 0; i < go_names_rows_n(); i++) {
            const char *k = go_names_row_kind(i);
            if(!k || (strcmp(k, "type") != 0 && strcmp(k, "choice-pr") != 0
                      && strcmp(k, "choice-const") != 0
                      && strcmp(k, "spec-pr") != 0)) continue;
            const char *gn = go_names_row_goname(i);
            if(!gn || strcmp(gn, pb) != 0) continue;
            const char *mrow = go_names_row_module(i);
            if(mrow && g_emit_mod && strcmp(mrow, g_emit_mod) != 0) {
                char *pk = gmodule_pkg(mrow);
                prtype_own = gfmt("%s.%s", pk, pb);
                free(pk);
            }
            break;
        }
    }
    if(prtype_own) prtype_q = prtype_own;   /* borrowed swap; freed at return */
    if(!prtype_q) {
        char *m2 = gfmt("choice %s has no Present field row", go_flat_ir_name(ch));
        GFAIL(m2); free(m2); free((char *)owner_own);
        return;
    }

    /* present write/read (composite const chain honors E->cpre). The value
     * pointer is deref'd ONCE up front (c) — every later expression reads c.
     * The READ side binds the pointed VALUE (pv minus one '&' — a nested
     * union reads its present off the host field, not the receiver). */
    (*E->fill) = gam((*E->fill), gfmt("\tc := *%s\n", pv));
    {
        char *poffc = qconst(E->cnode, g_offconst_pfx(E->cnode, E->cpre, "present"));
        const char *pvv = (pv[0] == '&') ? pv + 1 : pv;
        (*E->fill) = gam((*E->fill), gfmt(
            "\t*(*int32)(unsafe.Pointer(uintptr(%s) + uintptr(%s))) = int32(c.Present)\n",
            body_base, poffc));
        (*E->read) = gam((*E->read), gfmt(
            "\t%s.Present = %s(*(*int32)(unsafe.Pointer(uintptr(%s) + uintptr(%s))))\n",
            pvv, prtype_q, body_base, poffc));
        (*E->read) = gam((*E->read), gfmt("\tswitch %s.Present {\n", pvv));
        free(poffc);
    }

    (*E->fill) = gam((*E->fill), gfmt("\tswitch c.Present {\n"));
    (*E->szt) = gam((*E->szt), gfmt("\tcs := *%s\n", pv));
    (*E->szt) = gam((*E->szt), gfmt("\tswitch cs.Present {\n"));

    for(int i = 0; i < go_flat_ir_members(ch); i++) {
        flat_member *m = go_flat_ir_member(ch, i);
        const char *tok = go_flat_ir_member_token(m);
        if(!tok || strcmp(tok, "present") == 0) continue;

        /* NULL alts never reach this loop: the walk records them in the
         * null-alt registry and skips the member row entirely (a NULL alt
         * has no Go field and no Flat slot), so their arms come from the
         * registry loop below, exactly once. */

        const char *alt_field = gf_field_goname(ch_owner, tok);
        if(!alt_field) {
            char *m2 = gfmt("choice %s alt %s has no field row", go_flat_ir_name(ch), tok);
            GFAIL(m2); free(m2);
            continue;
        }
        char *gu1 = gown(unqual(prtype_q));
        char *gu2 = gown(alt_field);
        char *cstname = qcconst(gu1, gu2);
        free(gu1); free(gu2);
        (*E->fill) = gam((*E->fill), gfmt("\tcase %s:\n", cstname));
        (*E->read) = gam((*E->read), gfmt("\tcase %s:\n", cstname));
        (*E->szt) = gam((*E->szt), gfmt("\tcase %s:\n", cstname));

        /* per-alt, per-accumulator: the threearms bind the choice value
         * DIFFERENTLY — fill derefs `c`, read reads the receiver `v`, size
         * derefs `cs` (the c := *pv / cs := *pv forms above). ONE emission
         * pass per accumulator, its val set to that arm's binding and the
         * other two accumulators redirected to scratch (one shared emitter
         * cannot know which accumulator a line targets). The composite-off
         * chains the choice's own host token; rows key on the CHOICE owner. */
        {
            /* the READ binding descends the value path: pv is the value
             * POINTER expr (&v.field for a nested union, v for a package
             * CHOICE read via its own &v receiver); the read pass binds
             * the pointed VALUE (strip one leading '&' of the pv form). */
            const char *pvv = (pv[0] == '&') ? pv + 1 : pv;
            char *rd_v = gfmt("%s%s", pvv, "");
            struct { const char *val; char **dst; } passes[3] = {
                { "c",  E->fill },
                { rd_v, E->read },
                { "cs", E->szt  },
            };
            for(int pass = 0; pass < 3; pass++) {
                char *scratch1 = strdup(""), *scratch2 = strdup("");
                ectx A = *E;
                A.t = ch;
                A.owner_go = ch_owner;
                A.cbase = gown(body_base);
                /* the alt slot const is off<cnode><cpre><alt>: the CALLER
                 * already chained the host path into cpre (the nested-union
                 * walk chains its member token at entry); the alt token
                 * alone appends here. Fresh gown copies per pass (freed
                 * below; the host's own strings stay borrowed). */
                A.cpre = gown((E->cpre && *E->cpre) ? E->cpre : "");
                A.val = gown(passes[pass].val);
                if(passes[pass].dst == E->fill) { A.read = &scratch1; A.szt = &scratch2; }
                else if(passes[pass].dst == E->read) { A.fill = &scratch1; A.szt = &scratch2; }
                else { A.fill = &scratch1; A.read = &scratch2; }

                /* nil-selected-alt guard (before any cgo call; the
                 * nil-alt error rule) — the
                 * READ pass needs no guard (decode sets only the selected
                 * alt); fill returns the error, size returns (0, 0, err). */
                if(passes[pass].dst != E->read) {
                    char *accG = gfmt("%s.%s", passes[pass].val, alt_field);
                    char *el = errlit(ch, tok, "CodeChoiceBad",
                                      "selected alternative is nil");
                    if(passes[pass].dst == E->szt) {
                        *(passes[pass].dst) = gam(*(passes[pass].dst), gfmt(
                            "\t\tif %s == nil {\n\t\t\treturn 0, 0, &%s\n\t\t}\n", accG, el));
                    } else {
                        *(passes[pass].dst) = gam(*(passes[pass].dst), gfmt(
                            "\t\tif %s == nil {\n\t\t\treturn &%s\n\t\t}\n", accG, el));
                    }
                    free(accG); free(el);
                }

                if(go_flat_ir_member_is_prim(m)) {
                    emit_prim(&A, m);
                    /* prim alt sizing: emit_prim's OWN member
                     * branches emit the szt lines (bytes/bits payload,
                     * guarded/padded fixed; scalars 0 by construction) —
                     * the old size_prim_alt call DUPLICATED them (GNB-ID-
                     * Choice gnb_ID: payload += len(Bytes) twice; the
                     * exact-consumption invariant's find #3). The alt
                     * nil-guard above already ran; nothing more to add. */
                } else if(go_flat_ir_member_is_ref(m)) {
                    flat_type *r = go_flat_ir_ref_resolve(go_flat_ir_member_ref(m));
                    if(!r) {
                        char *m2 = gfmt("choice %s alt %s: unresolved ref",
                                        go_flat_ir_name(ch), tok);
                        GFAIL(m2); free(m2);
                    } else {
                        if(!go_flat_ir_is_nested_only(r)) emit_type_fn(r);
                        emit_ref(&A, m, r);
                    }
                } else {
                    emit_nested(&A, m);
                }
                /* A.cbase/A.cpre/A.val are owned (gown copies); the HOST's
                 * cpre (E->cpre) stays borrowed, never freed here. */
                free_const(A.cbase); free_const(A.cpre); free_const(A.val);
                free(scratch1); free(scratch2);
            }
            free(rd_v);
        }
        free(cstname);
    }

    /* NULL-alt arms (both directions): a NULL alt carries no Flat slot and
     * no Go field, so its member never rides the flat IR — the member loop
     * above cannot see it. The conv registry (the same source the C switch
     * emits its bare-break arms from) carries every (node, alt) pair;
     * emit each arm here as present-only, in recorded order, BEFORE the
     * NOTHING/default arms. A selected NULL alt must reach the C entry
     * (encode) / decode clean (read), never E_CHOICE_BAD. */
    for(int i = 0; i < g_conv_n_nullalts; i++) {
        const char *ch_cid = go_flat_ir_cid(ch);
        if(!conv_cid_eq(g_conv_nullalts[i].node_cid, ch_cid ? ch_cid : ""))
            continue;
        char *gu = gown(unqual(prtype_q));
        char *ag = gcamel(g_conv_nullalts[i].alt_token);
        char *cst = qcconst(gu, ag);
        free(gu);
        (*E->fill) = gam((*E->fill), gfmt("\tcase %s:\n", cst));
        (*E->fill) = ga((*E->fill), "\t\t// NULL alternative carries no data slot.\n");
        (*E->read) = gam((*E->read), gfmt("\tcase %s:\n", cst));
        free(ag); free(cst);
    }

    /* NOTHING + BAD arms (fill only; read ignores unknown present — a
     * codec-decoded tree always carries a known present, and the from_tree
     * side raises its own error before the glue reads). */
    /* PrNothing arm: E_CHOICE_NOTHING (the CHOICE to_tree template's
     * NOTHING handling). */
    {
        const char *nothing = gf_pr_nothing(prtype_q);
        if(nothing) {
            (*E->fill) = gam((*E->fill), gfmt("\tcase %s:\n", nothing));
            {
                char *el = errlit(ch, "", "CodeChoiceNothing",
                                  "present == NOTHING");
                (*E->fill) = gam((*E->fill), gfmt(
                    "\t\treturn &%s\n", el));
                free(el);
            }
        }
        /* the choice's PrNothing const (name = <PrBase>Nothing, the base
         * already ends in "Pr"): lookup via gf_pr_const falls flat because
         * the row name pattern differs — handled by gf_pr_nothing. */
    }
    /* default arm: E_CHOICE_BAD (present out of range). */
    {
        char *el = errlit(ch, "", "CodeChoiceBad", "present out of range");
        (*E->fill) = gam((*E->fill), gfmt(
            "\tdefault:\n\t\treturn &%s\n", el));
        free(el);
    }
    (*E->fill) = ga((*E->fill), "\t}\n");
    (*E->read) = ga((*E->read), "\t}\n");
    rebalance_switch(E->szt);
    (*E->szt) = ga((*E->szt), "\t}\n");
    free(prtype_own);
    free((char *)owner_own);
}

/* The qualified PrNothing const of a Pr type (row goType == base): the row
 * named <base>Nothing. */
static const char *gf_pr_nothing(const char *prtype_q) {
    const char *base = unqual(prtype_q);
    static char buf[512];
    if(strlen(base) + 8 >= sizeof buf) return NULL;
    sprintf(buf, "%sNothing", base);
    /* the PR type itself may be foreign-qualified: find its row & requalify */
    char *want = buf;
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *k = go_names_row_kind(i);
        if(!k || strcmp(k, "choice-const") != 0) continue;
        const char *gn = go_names_row_goname(i);
        if(gn && strcmp(gn, want) == 0) {
            const char *mod = go_names_row_module(i);
            const char *emit_mod = g_emit_mod;
            if(mod && emit_mod && strcmp(mod, emit_mod) == 0)
                return want;
            char *pkgS = gmodule_pkg(mod);
            static char q[600];
            snprintf(q, sizeof q, "%s.%s", pkgS, want);
            free(pkgS);
            return q;
        }
    }
    return NULL;
}

/* emit_member — dispatch one member row of the walked node. */
static void
emit_member(ectx *E, flat_member *m) {
    if(go_flat_ir_member_is_prim(m)) {
        emit_prim(E, m);
        return;
    }
    if(go_flat_ir_member_is_ref(m)) {
        flat_type *r = go_flat_ir_ref_resolve(go_flat_ir_member_ref(m));
        if(!r) {
            const char *tok = go_flat_ir_member_token(m);
            char *m2 = gfmt("unresolved member ref %s.%s", go_flat_ir_name(E->t),
                            tok ? tok : "?");
            GFAIL(m2); free(m2);
            return;
        }
        emit_ref(E, m, r);
        return;
    }
    emit_nested(E, m);
}

/* ---------------------------------------------------------------------------
 * SEQ-OF item helpers — one shared triple per element type:
 *   size<E>Items(&f, &p, slice)     — no error (a slice walk cannot fail:
 *                                      E_DEPTH checked at the RECURSIVE step)
 *   fill<E>Items(fa, hdr, stride, slice) error
 *   read<E>Items(hdr, stride) []E
 * The slice parameter arrives as its underlying []<E> form (a named slice
 * the slice assign targets []E implicitly). A prim element uses the prim stride +
 * a direct store (no per-item call).
 * ------------------------------------------------------------------------- */
static void emit_type_fn(flat_type *t);

/* the per-package item-helper text list (order = first reference; the
 * emit_items_helper dedup table is reset with it per package). */
typedef struct { char *sz, *fill, *read; } itemh;
static itemh *g_items = NULL;
static int g_n_items = 0, g_cap_items = 0;

static void
item_helpers_append(char *sz, char *fill, char *read) {
    if(g_n_items == g_cap_items) {
        int nc = g_cap_items ? g_cap_items * 2 : 32;
        itemh *ni = realloc(g_items, (size_t)nc * sizeof(itemh));
        if(!ni) { GFAIL("oom"); free(sz); free(fill); free(read); return; }
        g_items = ni; g_cap_items = nc;
    }
    g_items[g_n_items].sz = sz;
    g_items[g_n_items].fill = fill;
    g_items[g_n_items].read = read;
    g_n_items++;
}

static void emit_items_helper(flat_type *er);

/* the per-element dedup table of emit_items_helper (reset per package). */
static flat_type **g_done_elems = NULL;
static int g_n_done = 0, g_cap_done = 0;

static void
item_helpers_reset(void) {
    for(int i = 0; i < g_n_items; i++) {
        free(g_items[i].sz); free(g_items[i].fill); free(g_items[i].read);
    }
    free(g_items); g_items = NULL; g_n_items = g_cap_items = 0;
    free(g_done_elems); g_done_elems = NULL; g_n_done = g_cap_done = 0;
}
static void
emit_items_helper(flat_type *er) {
    if(glue_failed) return;
    for(int i = 0; i < g_n_done; i++)
        if(g_done_elems[i] == er) return;
    if(g_n_done == g_cap_done) {
        int nc = g_cap_done ? g_cap_done * 2 : 32;
        flat_type **nd = realloc(g_done_elems, (size_t)nc * sizeof(flat_type *));
        if(!nd) { GFAIL("oom"); return; }
        g_done_elems = nd; g_cap_done = nc;
    }
    g_done_elems[g_n_done++] = er;

    /* the element's own fns (a node element's fill/read/size trio) */
    int prim_elem = go_flat_ir_elem_prim(er);
    if(!prim_elem && !go_flat_ir_is_nested_only(er)) emit_type_fn(er);

    char *cam = gcamel_flat(go_flat_ir_name(er));
    char *qt = gtype_q(er);
    char *stride = qconst(go_flat_ir_name(er), g_szconst(go_flat_ir_name(er)));
    const char *prim = go_flat_ir_prim(er);
    const char *gt = prim ? gprim_go(prim) : NULL;

    /* ---- size<E>Items(&f, &p, items): nil/empty => nothing ----
     * A NODE element's per-item fn allocates BEYOND the stride (nested
     * CHOICE-struct copies, sub-list headers, ...): the size helper must
     * CALL the element's size fn per item and add both its fixed and
     * payload, not just n*stride (the fill helper's loop is the mirror).
     * A prim element is exactly one stride slot, no sub-allocation. */
    int scc_elem = conv_is_scc(er);
    char *s = gfmt(
        "func size%sItems(f *uintptr, p *uintptr, items []%s%s) error {\n"
        "\tif items == nil {\n\t\treturn nil\n\t}\n"
        "\tn := uintptr(len(items))\n"
        "\t*f += n * uintptr(%s)\n",
        cam, qt, scc_elem ? ", depth int" : "", stride);
    if(!prim_elem) {
        /* an SCC element must observe the HOST's depth (each item
         * sizes at host depth; the element's own guard+threading carries
         * the increment from there). The old literal 0 reset the chain at
         * every named SEQ-OF boundary — the Go depth guard could never
         * trip through a SEQ-OF cycle (caught by item-3's E_DEPTH test).
         * A NON-SCC element takes no depth arg at all. */
        if(scc_elem) {
            s = gam(s, gfmt(
                "\tfor j := range items {\n"
                "\t\tf0, p0, err := size%s(&items[j], depth)\n"
                "\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n"
                "\t\t*f += f0; *p += p0\n\t\t}\n"
                "\treturn nil\n",
                cam));
        } else {
            s = gam(s, gfmt(
                "\tfor j := range items {\n"
                "\t\tf0, p0, err := size%s(&items[j])\n"
                "\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n"
                "\t\t*f += f0; *p += p0\n\t\t}\n"
                "\treturn nil\n",
                cam));
        }
    }
    s = ga(s, "}\n\n");

    /* ---- fill<E>Items(fa, hdr, stride, items): header + one flat array ---- */
    char *fl = gfmt(
        "func fill%sItems(fa *blockArena, hdr unsafe.Pointer, stride uintptr, items []%s%s) error {\n"
        "\tn := len(items)\n"
        "\t*(*uintptr)(unsafe.Pointer(uintptr(hdr) + 8)) = uintptr(n)\n"
        "\tif n == 0 {\n"
        "\t\tstorePtr(hdr, nil)\n"
        "\t\treturn nil\n"
        "\t}\n"
        "\tarr := fa.allocStruct(uintptr(n)*stride, alignInt64)\n"
        "\tstorePtr(hdr, arr)\n",
        cam, qt, scc_elem ? ", depth int" : "");
    if(prim_elem) {
        fl = gam(fl, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\t*(*%s)(s2) = %s(items[j])\n"
            "\t}\n",
            gt ? gt : "int64", gt ? gt : "int64"));
    } else {
        /* the element fn's depth arg when it threads depth (an SCC element):
        the helper is called from a host already holding depth; pass 0 at
        this layer only when the HELPER itself takes no depth — keep the
        same hdf_fill spelling the direct call sites use. */
        /* thread the host depth into every item (see size twin). */
        const char *hdp = scc_elem ? ", depth" : "";
        fl = gam(fl, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\tif err := fill%s(fa, s2, &items[j]%s); err != nil {\n"
            "\t\t\treturn err\n\t\t}\n"
            "\t}\n",
            cam, hdp));
    }
    fl = ga(fl, "\treturn nil\n}\n\n");

    /* ---- read<E>Items(hdr, stride) <slice> ---- */
    char *rd = gfmt(
        "func read%sItems(hdr unsafe.Pointer, stride uintptr) []%s {\n"
        "\tn := int(*(*uintptr)(unsafe.Pointer(uintptr(hdr) + 8)))\n"
        "\tarr := unsafe.Pointer(*(**byte)(hdr))\n"
        "\tif arr == nil || n == 0 {\n"
        "\t\treturn nil\n\t}\n"
        "\tout := make([]%s, n, n)\n",
        cam, qt, qt);
    if(prim_elem) {
        rd = gam(rd, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\tout[j] = %s(*(*%s)(s2))\n\t}\n",
            gt ? gt : "int64", gt ? gt : "int64"));
    } else {
        rd = gam(rd, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\tit, err := read%s(s2)\n"
            "\t\tif err != nil {\n\t\t\treturn nil\n\t\t}\n"
            "\t\tout[j] = *it\n\t}\n",
            cam));
    }
    rd = ga(rd, "\treturn out\n}\n\n");

    item_helpers_append(s, fl, rd);
    free(cam); free(qt); free(stride);
}

/* ---------------------------------------------------------------------------
 * emit_type_fn — one package-scoped node's size/fill/read triple, queued
 * into the registry (cycles close on the fn call; nested nodes inline).
 * ------------------------------------------------------------------------- */
static void
emit_type_fn(flat_type *t) {
    if(glue_failed) return;
    int ix = fn_ix(t);
    if(ix < 0) return;
    gluefn *f = fn_queue(ix);
    if(!f || f->active || f->done) return;
    f->active = 1;

    char *cam = gcamel_flat(go_flat_ir_name(t));
    char *owner_own = NULL;
    const char *owner_go = gowner(t, &owner_own);

    ectx E = {0};
    E.t = t;
    E.owner_go = owner_go;
    E.cbase = gown("slot");
    E.cnode = go_flat_ir_name(t);
    E.cpre = "";
    E.val = "v";
    /* the accumulators ARE the registry's strings (ga returns the moved
     * buffer; every emitter writes through E and syncs back below — one
     * aliasing rule, no local reassign: the registry never holds a freed
     * pre-ga pointer). */
    /* fresh accumulators per emission (fn_queue's placeholders freed —
     * every fn was queued before its first emission began). */
    free(f->sz); free(f->fill); free(f->read);
    f->sz = strdup(""); f->fill = strdup(""); f->read = strdup("");
    E.szt = &f->sz; E.fill = &f->fill; E.read = &f->read;
    E.depth = conv_is_scc(t) ? "depth" : NULL;
    E.depth_on = conv_is_scc(t);

    /* the depth guard first, before any size/fill walk. */
    if(conv_is_scc(t)) {
        char *el = errlit(t, "", "CodeDepth", "depth > maxEncodeDepth (Go-side pre-check)");
        f->sz = gam(f->sz, gfmt("\tif depth > maxEncodeDepth {\n\t\treturn 0, 0, &%s\n\t}\n", el));
        f->fill = gam(f->fill, gfmt("\tif depth > maxEncodeDepth {\n\t\treturn &%s\n\t}\n", el));
        free(el);
    }

    if(go_flat_ir_is_choice(t)) {
        char *slotb = gown("slot");
        emit_choice_at(&E, t, slotb, "v");
        free_const(slotb);   /* emit_choice_at copies what it needs */
    } else if(n_is_seqof(t)) {
        /* a NAMED SEQ-OF type (a type assignment whose Flat is a {items,count}
         * header node): the fn bodies delegate to the element's Items helper
         * (ONE filler of the 16B header at the slot itself). */
        {
            const char *elem = go_flat_ir_elem(t);
            flat_type *er = elem ? go_flat_ir_ref_resolve(elem) : NULL;
            if(er) {
                emit_items_helper(er);
                char *stride = qconst(go_flat_ir_name(er), g_szconst(go_flat_ir_name(er)));
                char *erb = gcamel_flat(go_flat_ir_name(er));
                {
                    char *qer = gtype_q(er);
                    /* an SCC element's Items helper threads depth —
                     * the root call enters at 0 (hdf idiom). */
                    f->sz = gam(f->sz, gfmt(
                        "\tif err := size%sItems(&fixed, &payload, []%s(*v)%s); err != nil {\n\t\treturn 0, 0, err\n\t}\n",
                        erb, qer, conv_is_scc(er) ? ", 0" : ""));
                    f->fill = gam(f->fill, gfmt(
                        "\treturn fill%sItems(fa, slot, uintptr(%s), []%s(*v)%s)\n",
                        erb, stride, qer, conv_is_scc(er) ? ", 0" : ""));
                    free(qer);
                }
                char *tn = gfmt("sl%d", g_tmpseq++);
                char *qt2 = gtype_q(t);   /* the qualified return spelling */
                f->read = gam(f->read, gfmt(
                    "\t%s := read%sItems(slot, uintptr(%s))\n"
                    "\treturn (*%s)(&%s), nil\n",
                    tn, erb, stride, qt2, tn));
                free(qt2); free(tn); free(stride); free(erb);
            }
        }
    } else if(n_is_leaf(t) && go_flat_ir_members(t) == 0) {
        f->leaf_pdu = 1;
        /* a scalar-alias leaf PDU root (the entry set includes named INTEGER/bytes
         * leaves): one prim store at slot+0. Encode/Decode call the entry
         * point with the Flat's own single value. */
        const char *prim = go_flat_ir_prim(t);
        char *cast = gown(prim ? prim : "");
        const char *al0 = gf_goname(t);   /* the leaf's own named alias, if any */
        char *alq = NULL;                 /* package-qualified alias spelling */
        if(al0 && *al0) {
            const char *tm = go_flat_ir_module(t);
            if(tm && g_emit_mod && strcmp(tm, g_emit_mod) == 0) alq = gown(al0);
            else { char *pk = gmodule_pkg(tm); alq = gfmt("%s.%s", pk, al0); free(pk); }
        }
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            (*E.fill) = ga((*E.fill), "\twriteBytesField(fa, slot, []byte(*v))\n");
            {
                char *lv = alq && *alq
                    ? gfmt("\t*v = %s([]byte(readBytesField(slot)))\n", alq)
                    : strdup("\t*v = []byte(readBytesField(slot))\n");
                (*E.read) = gam((*E.read), lv);
            }
            (*E.szt) = ga((*E.szt), "\tpayload += uintptr(len([]byte(*v)))\n");
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            /* a BitString-alias leaf (a distinct named type): bridge
             * field-wise — BitString{Bytes, BitsUnused} both ways; the
             * BitString side of the bridge is THIS package's spelling. */
            char *lbs = local_bitstring();
            (*E.fill) = gam((*E.fill), gfmt(
                "\twriteBitsField(fa, slot, %s{Bytes: (*v).Bytes, BitsUnused: (*v).BitsUnused})\n", lbs));
            (*E.read) = gam((*E.read), gfmt(
                "\tbs := %s(readBitsField(slot))\n"
                "\t*v = %s{Bytes: bs.Bytes, BitsUnused: bs.BitsUnused}\n",
                lbs, (alq && *alq) ? alq : lbs));
            free(lbs);
            (*E.szt) = ga((*E.szt), "\tpayload += uintptr(len((*v).Bytes))\n");
        } else {
            const char *gt = gprim_go(prim);
            (*E.fill) = gam((*E.fill), gfmt(
                "\t*(*%s)(slot) = %s(*v)\n", gt, gt));
            (*E.read) = gam((*E.read), gfmt(
                "\tsd := %s(*(*%s)(slot))\n\t*v = sd\n",
                (alq && *alq) ? alq : gt, gt));
        }
        free(cast); free(alq);
    } else {
        for(int i = 0; i < go_flat_ir_members(t) && !glue_failed; i++)
            emit_member(&E, go_flat_ir_member(t, i));
    }

    /* the registry strings ARE the accumulators (slots point at them). */
    f->active = 0;
    f->done = 1;
    free_const(E.cbase);   /* the ctx's own gown("slot") copy */
    free(cam); free((char *)owner_own);
}

/* ---------------------------------------------------------------------------
 * The package file assembly + PDU API emission + the go_glue_emit driver.
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * The PDU API + per-package file assembly + the go_glue_emit driver.
 * ------------------------------------------------------------------------- */

/* the ONE emitter of the Encode/xer wrapper bodies — the
 * PDU-root arena reservation (budget += sizeof(root), root allocStruct'd
 * before any child alloc) lives HERE and nowhere else on the Go side.
 * Before this, emit_pdu_api carried two inline gfmt blocks, one per
 * wrapper, with the reservation text duplicated — the exact shape of the
 * an earlier sizing bug (Encode got the +sizeof(root) budget + reservation,
 * xer silently didn't; e2removal-init xer -> present=13). `kind` switches
 * only the decl line and the C entry-point name; every other line — size,
 * two-region budget WITH sizeof(root), allocStruct reserve, fill, entry
 * call, KeepAlive, GoBytes copy — is emitted from this single template for
 * BOTH wrappers of EVERY PDU root. Decode's root reservation is likewise
 * one path, on the C side: entry_decode's asn1cgo_arena_alloc(flat)
 * (go_entry.c). */
static char *
entry_go_wrapper(const char *kind, const char *go, const char *label,
                 const char *tb, const char *fna, const char *root_sz,
                 const char *d0) {
    char *s;
    if(strcmp(kind, "encode") == 0)
        s = cfmt("func (p *%s) Encode() ([]byte, error) {\n", go);
    else
        s = cfmt("func xer%s(p *%s) ([]byte, error) {\n", go, go);
    { char *_cf = cfmt(
        "\tif p == nil {\n\t\treturn nil, &rt.Error{Code: rt.CodeArg, TypeName: \"%s\"}\n\t}\n"
        "\tfixed, payload, err := size%s(p%s)\n"
        "\tif err != nil { return nil, err }\n"
        "\tfa, base := newBlockArena(fixed+uintptr(%s), payload)\n"
        "\tif fa == nil {\n\t\treturn nil, &rt.Error{Code: rt.CodeAlloc, TypeName: \"%s\"}\n\t}\n"
        "\tdefer C.free(base)\n"
        "\troot := fa.allocStruct(uintptr(%s), alignInt64)\n"
        "\tif err := fill%s(fa, root, p%s); err != nil {\n\t\treturn nil, err\n\t}\n"
        "\tfa.exact(\"%s\")   /* consumed == reserved, exactly */\n"
        "\tvar cerr C.asn1cgo_err\n"
        "\tvar cbuf C.asn1cgo_buf\n"
        "\trc := C.asn1cgo_%s_%s((*C.%s)(root), &cbuf, &cerr)\n"
        "\truntime.KeepAlive(fa)\n\truntime.KeepAlive(p)\n"
        "\tif rc != 0 {\n\t\tC.asn1cgo_buf_free(&cbuf)\n\t\treturn nil, goErr(&cerr)\n\t}\n"
        "\tout := C.GoBytes(unsafe.Pointer(cbuf.buf), C.int(cbuf.len))\n"
        "\tC.asn1cgo_buf_free(&cbuf)\n"
        "\treturn append([]byte(nil), out...), nil\n"
        "}\n\n",
        label, go, d0, root_sz, label, root_sz, go, d0, label, kind, tb, fna);
      s = ca(s, _cf); free(_cf); }
    return s;
}

/* one PDU root's API surface + its type fn queueing. `tb` = the
 * tree base (<P><cid>, the entry-point name suffix), `go` = the Go type. */
static void
emit_pdu_api(flat_type *rt_, char **src) {
    char *tb = conv_tree_base(rt_);
    char *go = gcamel_flat(go_flat_ir_name(rt_));
    char *label = conv_type_label(rt_);
    if(!tb || !*tb) {
        char *m2 = gfmt("PDU node %s has no tree base", go_flat_ir_name(rt_));
        GFAIL(m2); free(m2); free(go); free(label);
        return;
    }
    emit_type_fn(rt_);
    char *fna = gown(go_flat_ir_name(rt_));   /* the C Flat typedef name */
    const char *d0 = conv_is_scc(rt_) ? ", 0" : "";   /* the root call's depth arg */

    *src = gam(*src, gfmt("// %s — the public API (Encode/Decode entry points; xer unexported).\n", go));
    /* the ROOT's own struct: the size fns count only CHILD allocations
     * (every nested caller allocs the child slot via allocStruct and so
     * counts it), but the PDU root's Flat sits at the block base for
     * free — its sizeof must be added to the arena budget AND the base
     * reserved via allocStruct, or the first child alloc lands at offset
     * 0 ON TOP of the root (the choice-present overwritten bug class).
     * BOTH Encode and xer fill the root Flat; BOTH reserve it — via the
     * ONE shared body template (entry_go_wrapper). */
    char *root_sz = g_szconst(go_flat_ir_name(rt_));
    {
        char *wb = entry_go_wrapper("encode", go, label, tb, fna, root_sz, d0);
        *src = gam(*src, wb);   /* gam frees wb */
    }
    *src = gam(*src, gfmt(
        "func Decode%s(b []byte) (*%s, error) {\n"
        "\tif len(b) == 0 {\n\t\treturn nil, &rt.Error{Code: rt.CodeArg, TypeName: \"%s\"}\n\t}\n"
        "\tvar cerr C.asn1cgo_err\n"
        "\tvar arena *C.asn1cgo_arena\n"
        "\tvar flat *C.%s\n"
        "\trc := C.asn1cgo_decode_%s((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &arena, &flat, &cerr)\n"
        "\truntime.KeepAlive(b)\n"
        "\tif rc != 0 {\n"
        "\t\tif arena != nil {\n\t\t\tC.asn1cgo_arena_free(arena)\n\t\t}\n"
        "\t\treturn nil, goErr(&cerr)\n\t}\n"
        "\tv, err := read%s(unsafe.Pointer(flat))\n"
        "\tC.asn1cgo_arena_free(arena)\n"
        "\tif err != nil { return nil, err }\n"
        "\treturn v, nil\n"
        "}\n\n",
        go, go, label, fna, tb, go));
    {
        char *wb = entry_go_wrapper("xer", go, label, tb, fna, root_sz, d0);
        *src = gam(*src, wb);   /* gam frees wb */
    }
    free(root_sz);
    free(tb); free(go); free(label); free(fna);
}

/* The shared glue statics (blockArena + field helpers + goErr) — emitted
 * once per package (byte-stable text). */
static const char *GLUE_STATICS =
    "// rt/shared Flat layout consts (asn1cgo_bytes_flat/asn1cgo_bits_flat,\n"
"// rt/types.h; x86-64 SysV). The layout.go init() probe cross-checks these\n"
"// against cgo's C compiler view (rt/types.h include below).\n"
"const (\n"
"\tsizeofBytesFlat       = 16\n"
"\toffBytesFlatBuf       = 0\n"
"\toffBytesFlatLen       = 8\n"
"\tsizeofBitsFlat        = 24\n"
"\toffBitsFlatBuf        = 0\n"
"\toffBitsFlatLen        = 8\n"
"\toffBitsFlatBitsUnused = 16\n"
"\talignPtr              = 8\n"
"\talignInt64            = 8\n"
"\talignInt32            = 4\n"
")\n"
"\n"
"// ---- the Go-side bump allocator over one C block ----\n"
    "\n"
    "type blockArena struct {\n"
    "\tmem        []byte\n"
    "\tfixedEnd   uintptr\n"
    "\tstructCur  uintptr\n"
    "\tpayloadCur uintptr\n"
    "}\n"
    "\n"
    "// newBlockArena: fixed structs from the front, variable payloads from the\n"
    "// rear — a payload can never overlap a fixed struct's footprint (the\n"
    "// two-region split).\n"
    "func newBlockArena(fixedSize, payloadSize uintptr) (*blockArena, unsafe.Pointer) {\n"
    "\tn := fixedSize + payloadSize\n"
    "\tif n == 0 {\n\t\tn = 1\n\t}\n"
    "\tp := C.malloc(C.size_t(n))\n"
    "\tif p == nil {\n\t\treturn nil, nil\n\t}\n"
    "\tmem := unsafe.Slice((*byte)(p), int(n))\n"
    "\tfor i := range mem {\n\t\tmem[i] = 0\n\t}\n"
    "\treturn &blockArena{mem: mem, fixedEnd: fixedSize, structCur: 0, payloadCur: fixedSize}, p\n"
    "}\n"
    "\n"
    "func (a *blockArena) allocStruct(n, align uintptr) unsafe.Pointer {\n"
    "\ta.structCur = alignUp(a.structCur, align)\n"
    "\tend := a.structCur + n\n"
    "\tif end > a.fixedEnd {\n\t\tpanic(\"asn1cgo: fixed-region undercounted by \" + strconv.Itoa(int(end-a.fixedEnd)))\n\t}\n"
    "\taddr := unsafe.Pointer(&a.mem[a.structCur])\n"
    "\ta.structCur = end\n"
    "\treturn addr\n"
    "}\n"
    "\n"
    "func (a *blockArena) allocPayload(n uintptr) unsafe.Pointer {\n"
    "\tend := a.payloadCur + n\n"
    "\tif end > uintptr(len(a.mem)) {\n\t\tpanic(\"asn1cgo: payload-region undercounted by \" + strconv.Itoa(int(end-uintptr(len(a.mem)))))\n\t}\n"
    "\taddr := unsafe.Pointer(&a.mem[a.payloadCur])\n"
    "\ta.payloadCur = end\n"
    "\treturn addr\n"
    "}\n"
    "\n"
    "// exact invariant: after a fill, what the\n"
    "// arena CONSUMED must equal what the size pass RESERVED — exactly, not\n"
    "// <=. structCur reaches fixedEnd only if every sized struct was\n"
    "// allocated; payloadCur reaches len(mem) only if every sized payload\n"
    "// byte was written. An over-reserving size fn (consumed < reserved)\n"
    "// wastes budget and hides fill/size drift; an under-reserving one\n"
    "// already panics in the alloc guards above. Names the type + both\n"
    "// deltas so the offending size fn is identifiable from the panic.\n"
    "func (a *blockArena) exact(typeName string) {\n"
    "\tif a.structCur != a.fixedEnd || a.payloadCur != uintptr(len(a.mem)) {\n"
    "\t\tpanic(\"asn1cgo: arena budget not exactly consumed for \" + typeName +\n"
    "\t\t\t\": struct \" + strconv.Itoa(int(a.structCur)) + \"/\" + strconv.Itoa(int(a.fixedEnd)) +\n"
    "\t\t\t\", payload \" + strconv.Itoa(int(a.payloadCur)) + \"/\" + strconv.Itoa(int(len(a.mem))))\n"
    "\t}\n"
    "}\n"
    "\n"
    "func storePtr(slot, val unsafe.Pointer) {\n\t*(**byte)(slot) = (*byte)(val)\n}\n"
    "\n"
    "func alignUp(n, a uintptr) uintptr { return (n + a - 1) &^ (a - 1) }\n"
    "\n"
    "// maxEncodeDepth mirrors ASN1CGO_MAX_DEPTH (the rt err.h) on the\n"
    "// Go side: a cyclic Go value fails E_DEPTH before any C call.\n"
    "const maxEncodeDepth = 64\n"
    "\n"
    "func writeBytesField(fa *blockArena, recAddr unsafe.Pointer, b []byte) {\n"
    "\tif len(b) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(b)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(b)), b)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = uintptr(len(b))\n"
    "}\n"
    "\n"
    "func writeStringField(fa *blockArena, recAddr unsafe.Pointer, s string) {\n"
    "\tif len(s) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(s)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(s)), s)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = uintptr(len(s))\n"
    "}\n"
    "\n"
    /* the bits helpers ride behind their own markers (__GLUE_WRITEBITS__
     * / __GLUE_READBITS__): a package with no BIT STRING anywhere never
     * emits them, so the BITSTR placeholder never resolves to an undefined
     * type; a bits-carrying package gets them at their historical slots. */
    "//__GLUE_WRITEBITS__\n"
    "\n"
    "func readBytesField(recAddr unsafe.Pointer) []byte {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn nil\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\treturn append([]byte(nil), unsafe.Slice(bufPtr, int(n))...)\n"
    "}\n"
    "\n"
    "func readStringField(recAddr unsafe.Pointer) string {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn \"\"\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\treturn string(append([]byte(nil), unsafe.Slice(bufPtr, int(n))...))\n"
    "}\n"
    "\n"
    /* position marker: replaced by the bits-helpers chunk (GLUE_BITS) when
     * the package's emitted bodies reference them, deleted otherwise — the
     * helpers keep their historical slot next to the bytes/string pair so
     * bits-carrying packages stay byte-identical. */
    "//__GLUE_READBITS__\n"
    "\n"
    "// goErr copies a C asn1cgo_err (this preamble's err.h = the rt err.h) into\n"
    "// a *rt.Error; the copy is the caller's only stable handle (the ONE\n"
    "// Go error surface lives in rt).\n"
    "func goErr(cerr *C.asn1cgo_err) error {\n"
    "\tif cerr == nil || cerr.code == 0 {\n\t\treturn nil\n\t}\n"
    "\te := &rt.Error{Code: rt.Code(cerr.code)}\n"
    "\tif cerr.type_name != nil {\n\t\te.TypeName = C.GoString(cerr.type_name)\n\t}\n"
    "\tif cerr.field != nil {\n\t\te.Field = C.GoString(cerr.field)\n\t}\n"
    "\te.Message = C.GoStringN(&cerr.msg[0], C.int(C.asn1cgo_err_msg_len(cerr)))\n"
    "\treturn e\n"
    "}\n";

/* the bits helpers, appended to a package's glue ONLY when its emitted
 * bodies reference them (every O-RAN package does; a spec with no BIT
 * STRING omits the pair and never resolves the BITSTR placeholder). The
 * chunk text is carved verbatim from the static block above. */
static const char *GLUE_WRITE_BITS =
    "func writeBitsField(fa *blockArena, recAddr unsafe.Pointer, bs BITSTR) {\n"
    "\t*(*int32)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatBitsUnused)) = bs.BitsUnused\n"
    "\tif len(bs.Bytes) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(bs.Bytes)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(bs.Bytes)), bs.Bytes)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatLen)) = uintptr(len(bs.Bytes))\n"
    "}\n"
    "\n";

static const char *GLUE_READ_BITS =
    "func readBitsField(recAddr unsafe.Pointer) BITSTR {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatLen))\n"
    "\tbs := BITSTR{BitsUnused: *(*int32)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatBitsUnused))}\n"
    "\tif n == 0 {\n\t\treturn bs\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\tbs.Bytes = append([]byte(nil), unsafe.Slice(bufPtr, int(n))...)\n"
    "\treturn bs\n"
    "}\n"
    "\n";

/* the alignment consts go to layout.go (already emitted there by go_flat.c
 * as const alignPtr/alignInt64/alignInt32? — go_flat.c emits per-type consts
 * only; the alignment consts + alignUp + must were skeleton-stage glue-scope items,
 * so the glue package header declares align* + gofmts them itself. */

/* the per-package file header. `module` = the go.mod module path (basename
 * or <prefix>/<basename>), `pkg` the package dir/name, `flat_hdr` the
 * package flat header, `pdu_externs` the entry-point extern decls text,
 * `flat_externs` extra flat includes, `rt_module` the runtime module's path
 * (asn1cgo-rt or <prefix>/asn1cgo-rt). */
static char *
pkg_header(const char *module, const char *pkg, const char *flat_hdr,
           const char *flat_includes, const char *pdu_externs,
           const char *rt_module) {
    char *s = strdup(GO_GENERATED_BANNER "//go:build amd64\n\n");
    s = ga(s, "// glue.go — generated Go<->Flat glue.\n");
    s = ga(s, "// Encode: one C block -> fill via the Go-side bump allocator -> the C\n");
    s = ga(s, "// entry point -> C.GoBytes copy -> buf_free + free (deferred, every\n");
    s = ga(s, "// path). Decode: the C entry point -> a deep copy into Go values\n");
    s = ga(s, "// (nothing aliases the arena) -> arena_free (every path). No Go pointer\n");
    s = ga(s, "// is stored in C memory; no package-level C state; each call owns its\n");
    s = ga(s, "// own arena, so the API is safe for concurrent use.\n");
    s = ga(s, "package ");
    s = ga(s, pkg);
    s = ga(s, "\n\n/*\n");
    s = ga(s, "#cgo CFLAGS: -I${SRCDIR}/../internal/cspec -I${SRCDIR}/../internal/cspec/rt\n");
    s = ga(s, "#include \"rt/arena.h\"\n");
    s = ga(s, "#include \"rt/err.h\"\n");
    s = ga(s, "#include \"rt/types.h\"\n");
    s = ga(s, "#include <stdlib.h>\n");
    s = ga(s, flat_includes);
    s = ga(s, "\ntypedef struct { uint8_t *buf; size_t len; } asn1cgo_buf;\n");
    s = ga(s, "extern void asn1cgo_buf_free(asn1cgo_buf *b);\n");
    s = ga(s, pdu_externs);
    s = ga(s, "*/\nimport \"C\"\n\n");
    s = ga(s, "// the C world (the asn1c tree copy + conv/entry C) lives in internal/\n");
    s = ga(s, "// cspec; the import links its objects into every build of this package\n");
    s = ga(s, "// (process-global externs under Go static linking).\n");
    s = ga(s, "import _ \"");
    s = ga(s, module);
    s = ga(s, "/internal/cspec\"\n\n");
    s = ga(s, "import (\n");
    s = ga(s, "\trt \"");
    s = ga(s, rt_module ? rt_module : "asn1cgo-rt");
    s = ga(s, "/rt\"\n");
    s = ga(s, "\t\"runtime\"\n");
    s = ga(s, "\t\"strconv\"\n");
    s = ga(s, "\t\"unsafe\"\n");
    s = ga(s, ")\n");
    return s;
}

/* fmt the fns of one queued registry entry into the package source. The
 * entries were emitted in dependency order (queue order; a fn's callees are
 * queued before it completes — actually callees queue DURING body emission,
 * so reverse the registry for emission: callees first). */
static void
emit_fn_text(gluefn *f, char **src) {
    if(!f || !f->done) return;
    flat_type *t = go_flat_ir_type(f->ix);
    if(!t) return;
    char *cam = gcamel_flat(go_flat_ir_name(t));
    char *qt = gtype_q(t);   /* the package-qualified type spelling */
    const char *dp = conv_is_scc(t) ? ", depth int" : "";

    *src = gam(*src, gfmt(
        "func size%s(v *%s%s) (fixed, payload uintptr, err error) {\n",
        cam, qt, dp));
    *src = ga(*src, f->sz);
    *src = ga(*src, "\treturn\n}\n\n");
    *src = gam(*src, gfmt(
        "func fill%s(fa *blockArena, slot unsafe.Pointer, v *%s%s) error {\n",
        cam, qt, dp));
    *src = ga(*src, f->fill);
    /* a fill body that already returns (a delegation) must not get the
     * trailer `return nil` — unreachable. Mirror of the read side. */
    {
        const char *fb = f->fill ? f->fill : "";
        int fill_returns = 0;
        for(const char *q = fb; *q; ) {
            const char *eol = strchr(q, '\n');
            size_t ll = eol ? (size_t)(eol - q) : strlen(q);
            if(ll > 8 && strncmp(q, "\treturn ", 8) == 0) fill_returns = 1;
            if(!eol) break;
            q = eol + 1;
        }
        *src = ga(*src, fill_returns ? "}\n\n" : "\treturn nil\n}\n\n");
    }
    if(f->leaf_pdu) {
        *src = gam(*src, gfmt(
            "func read%s(slot unsafe.Pointer) (*%s, error) {\n\tv := new(%s)\n",
            cam, qt, qt));
    } else {
    *src = gam(*src, gfmt(
        "func read%s(slot unsafe.Pointer) (*%s, error) {\n\tv := &%s{}\n",
        cam, qt, qt));
    }
    {
        const char *rb = f->read ? f->read : "";
        int has_return = 0, uses_v = 0;
        for(const char *q = rb; *q; ) {
            const char *eol = strchr(q, '\n');
            size_t ll = eol ? (size_t)(eol - q) : strlen(q);
            if(ll > 8 && strncmp(q, "\treturn ", 8) == 0) has_return = 1;
            if(!eol) break;
            q = eol + 1;
        }
        if(strstr(rb, "v.") || strstr(rb, "= v") || strstr(rb, "(v)") || strstr(rb, "[v]"))
            uses_v = 1;
        size_t rbl = 0;
        while(rb[rbl] == ' ' || rb[rbl] == '\t' || rb[rbl] == '\n') rbl++;
        if(rb[rbl] == 0) has_return = 0;
        /* a returning, v-free body: blank the decl by hoisting `var _ =` —
         * simplest legal form: emit `_ = v` BEFORE the body (still used),
         * then the body, then just the close. */
        if(has_return && !uses_v)
            *src = ga(*src, "\t_ = v\n");
        *src = ga(*src, f->read);
        if(has_return) {
            *src = ga(*src, "}\n\n");
        } else {
            *src = ga(*src, "\tvar err error\n\t_ = err\n\treturn v, nil\n}\n\n");
        }
    }
    free(cam); free(qt);
}

/* go_glue_emit — the driver (called by go_generate after go_conv_emit).
 * go_module_basename = the go.mod module path (basename or
 * <prefix>/<basename>); go_rt_module = the runtime module's path. */
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

    typedef struct { const char *module; const char *pkg; flat_type *root; } pdu_ent;
    pdu_ent *pdus = NULL;
    int n_pdu_e = 0, cap_pdu_e = 0;
    for(int p = 0; p < g_conv_n_pdus; p++) {
        flat_type *rt_ = go_flat_ir_ref_resolve(g_conv_pdus[p].cid);
        if(!rt_) continue;
        const char *mod = go_flat_ir_module(rt_);
        if(!mod || !*mod) continue;
        if(n_pdu_e == cap_pdu_e) {
            cap_pdu_e = cap_pdu_e ? cap_pdu_e * 2 : 16;
            pdus = realloc(pdus, (size_t)cap_pdu_e * sizeof(pdu_ent));
            if(!pdus) { GFAIL("oom"); return -1; }
        }
        pdus[n_pdu_e].module = mod;
        pdus[n_pdu_e].pkg = NULL;
        pdus[n_pdu_e].root = rt_;
        n_pdu_e++;
    }
    (void)n; (void)n_pdus;

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
        free(g_asserts); g_asserts = NULL;   /* fresh assert block per package */
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
            char *tb = conv_tree_base(rt2);
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
            free(tb); free(flatn);
        }
        /* the package flat header (all fn signatures' Flat types) */
        char *flat_incs2 = gfmt("#include \"%s\"\n", flat_hdr);
        char *src = pkg_header(module_name, pkg, flat_hdr, flat_incs2, pdu_ext,
                               go_rt_module);
        src = ga(src, "\n");
        src = ga(src, GLUE_STATICS);
        /* (the BITSTR substitution moved below: it now runs where the bits
         * helpers are conditionally appended, after the fn bodies exist) */
        src = ga(src, "\n");

        /* queue every PDU root's fns + API (fn queueing fills the registry
         * transitively) */
        for(int i = 0; i < n_pdu_e && !glue_failed; i++) {
            if(strcmp(pdus[i].module, mod) != 0) continue;
            emit_pdu_api(pdus[i].root, &src);
        }
        /* the fns, reverse queue order (callees first) */
        for(int i = g_n_fns - 1; i >= 0 && !glue_failed; i--)
            emit_fn_text(g_fns[i], &src);

        /* the SEQ-OF item helper triples (first-reference order; the fns
         * they call are already emitted above) */
        for(int i = 0; i < g_n_items && !glue_failed; i++) {
            src = ga(src, g_items[i].sz);
            src = ga(src, g_items[i].fill);
            src = ga(src, g_items[i].read);
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
            int use_bits = strstr(src, "writeBitsField(") != NULL
                        || strstr(src, "readBitsField(") != NULL;
            char *bsname = local_bitstring();
            char *out = strdup("");
            const char *p2 = src, *q;
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
                    char *seg = malloc((size_t)(q2 - r) + 1);
                    if(seg) {
                        memcpy(seg, r, (size_t)(q2 - r));
                        seg[q2 - r] = 0;
                        sub = ga(sub, seg);
                        free(seg);
                    }
                    sub = ga(sub, bsname);
                    r = q2 + nl;
                }
                sub = ga(sub, r);
                free(out); out = sub;
            }
            free(src); src = out;
            free(bsname);
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
            src = ga(src,
                "// glue-local layout consts of foreign-package nodes whose fn\n"
                "// copies live here (the glue is self-contained per package; the\n"
                "// owning package's layout.go consts are unexported).\n");
            for(int i = 0; i < g_n_loconsts; i++)
                src = gam(src, gfmt("const %s = %ld\n",
                                   g_loconsts[i].name, g_loconsts[i].value));
            src = ga(src, "\n");
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
            char *mark = strstr(src, "*/\nimport \"C\"");
            if(mark) {
                size_t off = (size_t)(mark - src);
                size_t tl = strlen(src), il = strlen(blob);
                char *ns = malloc(tl + il + 1);
                if(ns) {
                    memcpy(ns, src, off);
                    memcpy(ns + off, blob, il);
                    memcpy(ns + off + il, src + off, tl - off + 1);
                    free(src); src = ns;
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
                    if(!nf) { free(fmods); fmods = NULL; n_fm = cap_fm = 0; break; }
                    fmods = nf;
                }
                fmods[n_fm++] = fm;
            }
            if(n_fm > 0 && fmods) {
                /* splice INTO the import block at the gofmt-sorted
                 * position: the block's lines come from pkg_header
                 * (rt-alias first, then runtime/strconv/unsafe) — insert
                 * each foreign line before the first existing line that
                 * sorts AFTER it (gofmt order), else before the closing
                 * paren. */
                char *blk = strstr(src, "import (");
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
                        size_t off = (size_t)(ins - src);
                        size_t tl = strlen(src), il = strlen(line);
                        char *ns = malloc(tl + il + 1);
                        if(ns) {
                            memcpy(ns, src, off);
                            memcpy(ns + off, line, il);
                            memcpy(ns + off + il, src + off, tl - off + 1);
                            free(src); src = ns;
                        }
                        /* re-anchor: the splice moved everything after ins */
                        blk = strstr(src, "import (");
                        bend = blk ? strchr(blk + 8, ')') : NULL;
                        free(line); free(fp);
                        if(!blk || !bend) break;
                    }
                } else {
                    /* no import block found (shouldn't happen): old
                     * behavior — append before the close. */
                    char *ip = strstr(src, "\t\"unsafe\"\n)\n");
                    if(ip) {
                        char *ins = strdup("");
                        for(int j = 0; j < n_fm; j++) {
                            char *fp = gmodule_pkg(fmods[j]);
                            ins = gam(ins, gfmt("\t\"%s/%s\"\n", module_name, fp));
                            free(fp);
                        }
                        size_t off = (size_t)(ip - src) + strlen("\t\"unsafe\"\n");
                        size_t tl = strlen(src), il = strlen(ins);
                        char *ns = malloc(tl + il + 1);
                        if(ns) {
                            memcpy(ns, src, off);
                            memcpy(ns + off, ins, il);
                            memcpy(ns + off + il, src + off, tl - off + 1);
                            free(src); src = ns;
                        }
                        free(ins);
                    }
                }
            }
            free(fmods);
        }

        if(glue_failed) { rc = -1; }
        else {
            /* gofmt normalization: expand one-line ifs, then trailing
             * newline count. */
            src = reindent_case_blocks(src);
            src = expand_oneline_ifs(src);
            while(strlen(src) > 1 && src[strlen(src)-1] == '\n'
                  && src[strlen(src)-2] == '\n')
                src[strlen(src)-1] = '\0';
            char *pkgdir = gjoin(go_outdir, pkg);
            if(gmkdir_p(pkgdir) < 0) rc = -1;
            char *path = gjoin(pkgdir, "glue.go");
            if(rc == 0 && gfwrite_all(path, src) < 0) rc = -1;
            free(pkgdir); free(path);
        }
        free(src); free(flat_hdr); free(flat_incs2); free(pdu_ext);
        free(pkg);
        g_emit_mod = NULL;
    }

    for(int i = 0; i < g_n_fns; i++) {
        free(g_fns[i]->sz); free(g_fns[i]->fill); free(g_fns[i]->read);
        free(g_fns[i]);
    }
    free(g_fns); g_fns = NULL; g_n_fns = g_cap_fns = 0;
    free(g_asserts); g_asserts = NULL;
    free(pdus); free(mods);
    return glue_failed ? -1 : rc;
}
