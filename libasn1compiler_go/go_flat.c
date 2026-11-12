/*
 * go_flat.c — Flat C emission (the leaf-kind-to-Flat-C mapping table; the
 * x86-64 SysV Flat layout rule).
 *
 * Scope of this TU:
 *   - the Flat IR: one flat_type per ASN.1 type the walk visits, shaped per
 *     Flat naming (verbatim member tokens; leaf = bare typedef; named SEQ OF =
 *     {items,count}; inline SEQ OF / SEQUENCE / CHOICE nested exactly as the
 *     .h nests them; CHOICE slot pointer iff asn1c's union member is one
 *     (Flat CHOICE layout, masked marker tests per the marker-reading rule); no slot for a NULL
 *     alt (NULL-alt refinement); native-width INTEGER Flat members);
 *   - the x86-64 SysV layout engine: every size/align/offset computed HERE
 *     from the ABI rule table + member placement (the layout rule: the
 *     generator never asks the compiler);
 *   - the three file writers: per-package <P><pkg>_flat.h (run-prefixed,
 *     dependency order, forward declarations for recursion), the matching
 *     <P><pkg>_layout_check.c (_Static_asserts on the computed literals),
 *     and each Go package's layout.go (the same literals + the init() guard).
 *
 * IR capture: NOT a second walk. go_names.c calls the go_flat_* hooks below
 * at the exact points where it has already made each structural decision
 * (chased terminal, member_stars star, minted inline name, value-union
 * membership); the Flat tree and the Go name tree are therefore captured by
 * construction, never re-derived. The hooks are declared in go_flat.h.
 *
 * Cross-module member types: a Flat member whose referenced type lives in
 * another module's package emits `#include "<P><other_pkg>_flat.h"` into the
 * referencing package's header (quoted include, one per foreign package,
 * sorted; both headers sit in the same c/ dir per the generated-module
 * layout rule, resolved by the
 * cgo -I flag — the comparison units' quoted-include discipline at generator scale).
 *
 * Shared primitives (asn1cgo_bytes_flat / asn1cgo_bits_flat) and the rt
 * files (arena/err/types) are copied once per module into c/rt/ by
 * go_flat_copy_rt; every <P><pkg>_flat.h includes "rt/types.h".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>

#include "asn1c_internal.h"     /* arg_t (required before asn1c_misc.h) */
#include "asn1c_misc.h"         /* asn1c_prefix (per-spec prefix; asn1c_misc.h:55) */

#include "go_flat.h"

#include <stdarg.h>
#include "go_conv.h"

/* ---------------------------------------------------------------------------
 * Small helpers (this TU's own; go_names.c's equivalents are file-static).
 * `failed` lives in the bag defined below; a one-bit out-of-line cell keeps
 * the helpers_compilable before the bag's definition.
 * ------------------------------------------------------------------------ */
extern int go_oer_disabled(void);

static int g_flat_failed_;

#define g_flat_failed_set() do { g_flat_failed_ = 1; } while(0)

/* Append b to a (malloc growth; on OOM a is returned unchanged). */
static char *
fa(char *a, const char *b);

static char *
fap(char *a, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return fa(a, buf);
}

static char *
fa(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0;
    size_t lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;
    memcpy(r + la, b ? b : "", lb);
    r[la + lb] = '\0';
    return r;
}

static char *
fstrdup(const char *s) {
    char *r = strdup(s ? s : "");
    if(!r) g_flat_failed_set();
    return r;
}

static void *
fxrealloc(void *p, size_t n) {
    void *r = realloc(p, n);
    if(!r) g_flat_failed_set();
    return r;
}

/* module_pkg of a module name (lowercase, '-' -> '_'; the output-root rule). */
static char *
flat_module_pkg(const char *module_name) {
    const char *s = module_name ? module_name : "_";
    char *out = malloc(strlen(s) + 1);
    if(!out) { g_flat_failed_set(); return strdup(""); }
    size_t j = 0;
    for(size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        out[j++] = (char)(c == '-' ? '_' : tolower(c));
    }
    out[j] = '\0';
    return out;
}

/* ---------------------------------------------------------------------------
 * IR construction (called by go_names.c through go_flat.h).
 * ------------------------------------------------------------------------ */

/* A Flat member's type: a primitive token (FT_PRIM), a named <X>_flat
 * reference (FT_REF — stars=1 for a pointer slot), or a nested anonymous
 * struct (FT_NESTED — an inline SEQ OF {items,count}, an inline CHOICE, or
 * the open-type value union; stars=1 behind a pointer member). */
typedef enum {
    FT_PRIM,
    FT_REF,
    FT_NESTED
} flat_member_kind_e;

typedef struct flat_member flat_member;
typedef struct flat_type flat_type;

struct flat_member {
    flat_member_kind_e kind;
    char *prim;        /* FT_PRIM: the C type token                        */
    char *ref;         /* FT_REF: the referenced type's cid                */
    int nested_ix;     /* FT_NESTED: the nested node's INDEX (the types
                        * array reallocs on every mint, so NO node pointer
                        * is ever held across hook calls)                  */
    char *token;       /* the member token, verbatim                */
    char *label;       /* display label: the ASN.1 member Identifier
                        * verbatim (asn1c_C.c:3119 emits expr->Identifier
                        * as the member's td-name string, hyphens kept);
                        * NULL = unrecorded (emission uses the token).     */
    int stars;         /* 1 = a pointer slot                                */
    int is_default;    /* DEFAULT member: Flat slot by value (stars=0)      */
    int tree_ptr;      /* DEFAULT member: the C tree slot is a pointer      */
    char *tree_token;  /* CHOICE alt: the C tree's member name when it differs
                        * from token (an alt `present`); NULL = same         */
    int strk;          /* bytes_flat member holding a BMPString (1) or
                        * UniversalString (2): the glue converts UTF-8 <->
                        * UCS-2/UCS-4; 0 = bytes as-is                      */
    int strz;          /* bytes_flat member of a restricted string / time type
                        * other than PrintableString: the tree buffer is
                        * allocated even when empty (the C constraint
                        * functions reject a NULL buf, "value not given")   */
    int wide;          /* INTEGER_t-backed int64/uint64 member (the tree slot
                        * is an INTEGER_t, not a native long)               */
    unsigned long offset;  /* computed (x86-64 SysV layout rule)              */
};

typedef enum {
    FLT_STRUCT,   /* SEQUENCE / CHOICE / field-shaped spec envelope        */
    FLT_LEAF,     /* `typedef <prim> X_flat;`                              */
    FLT_SEQOF,    /* `typedef struct { elem *items; size_t count; } */
    FLT_ALIAS     /* `typedef of_flat X_flat;` (SingleContainer clone)     */
} flat_type_kind_e;

struct flat_type {
    flat_type_kind_e kind;
    char *name;         /* <P><CIdent>_flat (run prefix, _flat suffix)     */
    char *cid;          /* <CIdent> (prefix-stripped normalized form)      */
    char *label;        /* display label: the asn1c td->name string
                         * — the ASN.1 expr->Identifier verbatim, hyphens
                         * kept, run prefix NEVER applied (td->name is a
                         * display name; the oracle carries it unprefixed
                         * even under ASN1C_PREFIX — E2SM-KPM-RANfunction-
                         * Description.c:308). NULL = unrecorded (falls back
                         * to the C-ident form at emission).                */
    const char *module; /* owning module name (borrowed)                    */
    flat_member *members;
    int n_members, cap_members;
    char *prim;         /* FLT_LEAF                                        */
    int strk;           /* FLT_LEAF bytes: 1 BMPString, 2 UniversalString   */
    int strz;           /* FLT_LEAF bytes: see flat_member.strz             */
    char *elem;         /* FLT_SEQOF element cid (or prim token)            */
    int elem_prim;      /* 1 = elem is a primitive token                    */
    char *alias_of;     /* FLT_ALIAS target cid                             */
    char *tree_base;    /* tree typedef base override (a bare-
                         * named FLAT whose ORACLE typedef is prefixed —
                         * the container clones: Flat ProtocolIE_Container_
                         * 85P0_flat, tree E2AP_ProtocolIE_Container_85P0).
                         * NULL = derive from name (strip _flat).           */
    int nested_only;    /* 1 = rides inside a parent member (no typedef)    */
    int inline_elem;    /* 1 = an inline (anonymous) element/alt type: the C
                         * tree type has no `<cid>_t` typedef and no exported
                         * asn_DEF_<cid>; the conv file declares the _t alias
                         * from tree_ctype and frees through the owning tree */
    char *tree_ctype;   /* inline_elem: the C spelling of the tree type     */
    char *go_type;      /* inline_elem leaf: the Go element type text (the
                         * unnamed leaf mapping, e.g. int64); NULL = a named
                         * Go type (the camel of the Flat name)             */
    int is_choice;      /* 1 = a CHOICE layout (present first)              */
    unsigned long size, align;
    int laid_out, in_progress;
};

/* The per-run Flat bag. */
typedef struct {
    flat_type *types;
    int n_types, cap_types;
    int cur_ix;         /* the struct members currently land on (-1 none);
                         * an INDEX — the array reallocs on every mint      */
    int failed;
} flat_bag;

flat_bag g_flat;

/* The most-recent go_flat_struct_nested mint index (the value-union
 * register: emit_spec mints the __value node, then the alt rows attach
 * onto it from emit_spec_value_alts). An INDEX register, not a pointer:
 * the types array reallocs between the mint and the rows. */
static int g_flat_last_nest = -1;

/* The node whose member row landed LAST (cur, or the _on hook's resolved
 * target) — the target of go_flat_label_last_member, set by every member
 * hook right before the row lands. */
static int g_flat_last_member_owner = -1;

/* Node pointer valid only WITHIN one go_flat call (never across mints). */
static flat_type *
flat_at(int ix) { return ix >= 0 && ix < g_flat.n_types ? &g_flat.types[ix] : NULL; }

static flat_type *flat_new_type(flat_type_kind_e kind, const char *cid,
                                const char *module);

static flat_type *
flat_new_type(flat_type_kind_e kind, const char *cid, const char *module) {
    /* dedup by (cid, module): the walk may reach one construct twice — an
     * inline CHOICE pre-minted as a nested member node, then emit_choice's
     * own owner mint for the same construct (the node is then completed as
     * cur). Same node, one IR entry; second mint returns the first. */
    {
        const char *pfx = asn1c_prefix();
        size_t pl = pfx ? strlen(pfx) : 0;
        const char *cs = cid ? cid : "";
        if(pl && strncmp(cs, pfx, pl) == 0) cs += pl;
        if(!*cs) goto no_dedup;   /* anonymous nested nodes: NEVER dedup on
                        * an empty cid (every {items,count} wrapper would
                        * collapse into ONE shared node — the wrong-elem
                        * bug: all nested seqofs rendered the last mint's
                        * element). */
        for(int i = 0; i < g_flat.n_types; i++) {
            flat_type *t = &g_flat.types[i];
            if(t->cid && strcmp(t->cid, cs) == 0
               && (t->module == module
                   || (t->module && module
                       && strcmp(t->module, module) == 0))) {
                /* a nested_only pre-mint being re-minted package-scoped
                 * (or re-bound): adopt it — the walk is entering the
                 * construct now; keep nested_only until the caller emits
                 * it as part of its parent member (the CHOICE case: the
                 * pre-minted member attach stays; emit_choice's cur re-bind
                 * populates THIS node either way). */
                return t;
            }
        }
    }
no_dedup:
    ;
    if(g_flat.n_types + 1 > g_flat.cap_types) {
        int nc = g_flat.cap_types ? g_flat.cap_types * 2 : 64;
        flat_type *nt = fxrealloc(g_flat.types,
                                  (size_t)nc * sizeof(flat_type));
        if(!nt) return NULL;
        g_flat.types = nt;
        g_flat.cap_types = nc;
    }
    flat_type *t = &g_flat.types[g_flat.n_types++];
    memset(t, 0, sizeof *t);
    t->kind = kind;
    /* the node NAME is <P><cid>_flat where P is the run prefix and
     * cid arrives already compound-prefixed for aggregates; strip any
     * prefix cid carries, then put the run prefix back ONCE — the same
     * prefix-once rule as go_cid_compound (a cid may arrive prefixed from
     * GO_MKID or bare from a minted inline compound; normalize both). */
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *cs = cid ? cid : "";
    if(pl && strncmp(cs, pfx, pl) == 0) cs += pl;
    char *nm = malloc(pl + strlen(cs) + 6 + 1);
    if(nm) {
        if(pl) memcpy(nm, pfx, pl);
        strcpy(nm + pl, cs);
        strcat(nm + pl, "_flat");
        t->name = nm;
    } else {
        t->name = fstrdup("");
        g_flat_failed_set();
    }
    t->cid = fstrdup(cs);
    t->module = module;
    return t;
}


static void
flat_add_member(flat_type *t, flat_member_kind_e kind, const char *prim,
                const char *ref, int nested_ix, const char *token,
                int stars) {
    if(!t) return;
    if(t->n_members + 1 > t->cap_members) {
        int nc = t->cap_members ? t->cap_members * 2 : 8;
        flat_member *nm = fxrealloc(t->members,
                                    (size_t)nc * sizeof(flat_member));
        if(!nm) return;
        t->members = nm;
        t->cap_members = nc;
    }
    flat_member *m = &t->members[t->n_members++];
    memset(m, 0, sizeof *m);
    m->kind = kind;
    m->prim = prim ? fstrdup(prim) : NULL;
    m->ref = ref ? fstrdup(ref) : NULL;
    m->nested_ix = nested_ix;
    m->token = token ? fstrdup(token) : fstrdup("");
    m->stars = stars;
}

void
go_flat_struct(const char *cid, const char *module) {
    if(getenv("ASN1CGO_FLATDBG"))
        fprintf(stderr, "asn1cgo: flatdbg: struct cid=%s\n", cid ? cid : "?");
    flat_type *t = flat_new_type(FLT_STRUCT, cid, module);
    g_flat.cur_ix = t ? (int)(t - g_flat.types) : -1;
}

void
go_flat_choice(const char *cid, const char *module) {
    flat_type *t = flat_new_type(FLT_STRUCT, cid, module);
    if(t) t->is_choice = 1;
    g_flat.cur_ix = t ? (int)(t - g_flat.types) : -1;
}

int
go_flat_struct_nested(const char *cid, const char *module) {
    ;
    /* a nested anonymous construct with a cid (an inline CHOICE / the
     * open-type value union): a struct that is NOT a package-scoped typedef
     * of its own — it rides inside its parent's member. Returns the node's
     * INDEX (stable across mints); the caller populates it via the
     * _on handle member calls, then attaches it under its parent token. */
    flat_type *t = flat_new_type(FLT_STRUCT, cid, module);
    if(!t) return -1;
    t->nested_only = 1;
    g_flat_last_nest = (int)(t - g_flat.types);
    /* cur stays at the ENCLOSING struct: the caller adds the wrapper member
     * itself via go_flat_member_nested. */
    return g_flat_last_nest;
}

int
go_flat_cur_get(void) {
    return g_flat.cur_ix;
}

void
go_flat_cur_restore(int ix) {
    /* after an inline construct's member recursion (emit_choice /
     * walk_names_members), cur must return to the ENCLOSING struct: a member
     * AFTER the inline construct belongs to the parent again (e.g.
     * EventParameterItem's nextMathOp after the paramType inline CHOICE,
     * which would otherwise land inside paramType). */
    if(ix >= 0 && ix < g_flat.n_types) g_flat.cur_ix = ix;
}

int
go_flat_leaf(const char *cid, const char *prim, const char *module) {
    flat_type *t = flat_new_type(FLT_LEAF, cid, module);
    if(!t) return -1;
    t->prim = fstrdup(prim);
    /* bind cur: the caller's go_flat_label_cur (td->name label, right
     * after the leaf mint at go_names.c:3829) must land on THIS node. The
     * real td->name of a leaf typedef'd onto a NativeInteger scalar is the
     * C identifier spelling (asn1c_C.c:3194 uses expr->Identifier — for a
     * scalar leaf that is the C ident, e.g. "RANfunctionID", no hyphens). */
    g_flat.cur_ix = (int)(t - g_flat.types);
    return g_flat.cur_ix;
}

/* The GLEAF kinds as go_names.c/go_types.c number them (go_types.c:74-76;
 * the int ABI is stable across the TUs). Maps each to the mapping-table Flat-column
 * C prim token. NULL for GLEAF_NONE and GLEAF_NULL — a NULL TYPE assignment
 * mints no Flat leaf (an OPTIONAL NULL member is an int32 prim row below). */
static const char *
gleaf_prim(int gleaf) {
    static const int order[] = {
        1 /* GLEAF_INT64 */, 2 /* GLEAF_UINT64 */, 3 /* GLEAF_BOOL */,
        4 /* GLEAF_NULL */, 5 /* GLEAF_REAL */, 6 /* GLEAF_OCTETS */,
        7 /* GLEAF_OID */, 8 /* GLEAF_STRING */, 9 /* GLEAF_BITSTRING */,
        10 /* GLEAF_ENUM */, 11 /* GLEAF_STRING_BMP */, 12 /* GLEAF_STRING_UNIV */,
        13 /* GLEAF_STRING_Z */
    };
    static const char *const prim[] = {
        "int64_t", "uint64_t", "_bool32",
        NULL, "double", "asn1cgo_bytes_flat",
        "asn1cgo_bytes_flat", "asn1cgo_bytes_flat", "asn1cgo_bits_flat",
        "int32_t", "asn1cgo_bytes_flat", "asn1cgo_bytes_flat",
        "asn1cgo_bytes_flat"
    };
    for(size_t i = 0; i < sizeof order / sizeof order[0]; i++)
        if(gleaf == order[i]) return prim[i];
    return NULL;
}

int
go_flat_leaf_gleaf(const char *cid, int gleaf, const char *module) {
    const char *p = gleaf_prim(gleaf);
    if(!p) return -1;
    int ix = go_flat_leaf(cid, p, module);
    /* 11 = GLEAF_STRING_BMP, 12 = GLEAF_STRING_UNIV, 13 = GLEAF_STRING_Z */
    if(ix >= 0 && gleaf >= 11 && gleaf <= 13) {
        flat_at(ix)->strk = gleaf == 11 ? 1 : gleaf == 12 ? 2 : 0;
        flat_at(ix)->strz = 1;
    }
    return ix;
}

/* Mark the CUR node (just minted) as an inline element/alt type: see the
 * inline_elem field. tree_ctype is the C spelling of the tree type; go_type
 * the unnamed Go element type (NULL when the Go type is a named one). */
void
go_flat_mark_inline_elem(const char *tree_ctype, const char *go_type) {
    flat_type *t = flat_at(g_flat.cur_ix);
    if(!t) return;
    t->inline_elem = 1;
    free(t->tree_ctype);
    t->tree_ctype = tree_ctype ? fstrdup(tree_ctype) : NULL;
    free(t->go_type);
    t->go_type = go_type ? fstrdup(go_type) : NULL;
}

int
go_flat_seqof(const char *cid, const char *elem_cid_or_prim, int elem_is_prim,
              const char *module) {
    flat_type *t = flat_new_type(FLT_SEQOF, cid, module);
    if(!t) return -1;
    t->elem = fstrdup(elem_cid_or_prim);
    t->elem_prim = elem_is_prim;
    if(t->nested_only) t->nested_only = 0;   /* named SEQ OF typedef */
    /* bind cur: the caller's go_flat_label_cur (td->name label) must
     * land on THIS node (go_names.c:3916/3927 call it immediately after). */
    g_flat.cur_ix = (int)(t - g_flat.types);
    return g_flat.cur_ix;
}

int
go_flat_alias_bare(const char *cid, const char *of_cid, const char *module) {
    if(getenv("ASN1CGO_FLATDBG"))
        fprintf(stderr, "asn1cgo: flatdbg: alias_bare cid=%s of=%s\n",
                cid ? cid : "?", of_cid ? of_cid : "?");
    /* mint under the ALIAS's own cid (the clone ACE id, e.g.
     * ProtocolIE_SingleContainer_88P0) — NOT a dedup collision with the
     * resolved ItemIEs node — then carry the target cid in alias_of (the
     * resolution key for emit/layout). The name = <cid>_flat, bare (no run
     * prefix; flat_new_type_bare keeps it). */
    /* <P><CIdent>_flat — the standard mint (flat_new_type prefixes
     * once, dedups on the stripped cid). The name is ALWAYS prefixed;
     * a bare mint is drift. */
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *cs = cid ? cid : "";
    if(pl && strncmp(cs, pfx, pl) == 0) cs += pl;
    char *base = malloc(pl + strlen(cs) + 1);
    if(!base) return -1;
    if(pl) memcpy(base, pfx, pl);
    strcpy(base + pl, cs);
    flat_type *t = flat_new_type(FLT_ALIAS, base, module);
    free(base);
    if(!t) return -1;
    t->alias_of = strdup(of_cid ? of_cid : "");
    t->nested_only = 0;
    return (int)(t - g_flat.types);
}

int
go_flat_seqof_container(const char *cid, const char *elem_cid,
                        const char *module) {
    if(getenv("ASN1CGO_FLATDBG"))
        fprintf(stderr, "asn1cgo: flatdbg: seqof_container cid=%s elem=%s\n",
                cid ? cid : "?", elem_cid ? elem_cid : "?");
    /* the Flat type name is <P><CIdent>_flat — same as every other
     * node; flat_new_type normalizes (strip the prefix cid may carry from
     * GO_MKID, put it back ONCE) and composes the _flat itself. ALWAYS
     * prefixed here too; a bare mint is drift. */
    {
        const char *pfx = asn1c_prefix();
        size_t pl = pfx ? strlen(pfx) : 0;
        const char *cs = cid ? cid : "";
        if(pl && strncmp(cs, pfx, pl) == 0) cs += pl;
        char *base = malloc(pl + strlen(cs) + 1);
        if(!base) return -1;
        if(pl) memcpy(base, pfx, pl);
        strcpy(base + pl, cs);
        flat_type *t = flat_new_type(FLT_SEQOF, base, module);
        free(base);
        if(!t) return -1;
        t->elem = strdup(elem_cid ? elem_cid : "");
        t->elem_prim = 0;
        return (int)(t - g_flat.types);
    }
}

int
go_flat_alias(const char *cid, const char *of_cid, const char *module) {
    flat_type *t = flat_new_type(FLT_ALIAS, cid, module);
    if(!t) return -1;
    t->alias_of = fstrdup(of_cid);
    return (int)(t - g_flat.types);
}


/* Members are added to g_flat.cur (the struct the walk most recently opened
 * for itself — go_flat_struct sets it; nested wrappers are populated via
 * their returned handle, then attached). */
void
go_flat_member_prim(const char *prim, const char *token, int stars) {
    g_flat_last_member_owner = g_flat.cur_ix;
    flat_add_member(flat_at(g_flat.cur_ix), FT_PRIM, prim, NULL, -1, token, stars);
}

void
go_flat_member_ref(const char *cid, const char *token, int stars) {
    g_flat_last_member_owner = g_flat.cur_ix;
    flat_add_member(flat_at(g_flat.cur_ix), FT_REF, NULL, cid, -1, token, stars);
}

/* label recording: set the CUR node's type display label (the td->name
 * string — expr->Identifier verbatim, prefix-free). Call right after the
 * mint that binds cur to the node. Re-binding cur record order matches the
 * walk's mint order; a node minted by dedup keeps its first label. */
void
go_flat_label_cur(const char *label) {
    flat_type *t = flat_at(g_flat.cur_ix);
    if(!t || !label) return;
    if(!t->label) t->label = fstrdup(label);
}

/* Set the LAST-ADDED member's display label on the node the members most
 * recently landed on: cur, or the last _on-target (g_flat_last_nest when the
 * _on hook's ix was < 0). Call immediately after the member mint it labels.
 * NULL label = leave unset (emission falls back to the token). */
void
go_flat_label_last_member(const char *label) {
    flat_type *t = flat_at(g_flat_last_member_owner);
    if(!t || !label || t->n_members <= 0) return;
    flat_member *m = &t->members[t->n_members - 1];
    if(!m->label) m->label = fstrdup(label);
}

void
go_flat_last_member_default(int tree_ptr) {
    flat_type *t = flat_at(g_flat_last_member_owner);
    if(!t || t->n_members <= 0) return;
    t->members[t->n_members - 1].is_default = 1;
    t->members[t->n_members - 1].tree_ptr = tree_ptr ? 1 : 0;
}

void
go_flat_last_member_tree_token(const char *tree_token) {
    flat_type *t = flat_at(g_flat_last_member_owner);
    if(!t || t->n_members <= 0 || !tree_token) return;
    t->members[t->n_members - 1].tree_token = fstrdup(tree_token);
}

void
go_flat_last_member_wide(void) {
    flat_type *t = flat_at(g_flat_last_member_owner);
    if(!t || t->n_members <= 0) return;
    t->members[t->n_members - 1].wide = 1;
}

void
go_flat_last_member_gleaf(int gleaf) {
    flat_type *t = flat_at(g_flat_last_member_owner);
    if(!t || t->n_members <= 0 || gleaf < 11 || gleaf > 13) return;
    t->members[t->n_members - 1].strk = gleaf == 11 ? 1 : gleaf == 12 ? 2 : 0;
    t->members[t->n_members - 1].strz = 1;
}

void
go_flat_member_prim_on(int ix, const char *prim, const char *token, int stars) {
    if(ix < 0) ix = g_flat_last_nest;
    g_flat_last_member_owner = ix;
    flat_add_member(flat_at(ix), FT_PRIM, prim, NULL, -1, token, stars);
}

void
go_flat_member_ref_on(int ix, const char *cid, const char *token, int stars) {
    if(ix < 0) ix = g_flat_last_nest;
    g_flat_last_member_owner = ix;
    flat_add_member(flat_at(ix), FT_REF, NULL, cid, -1, token, stars);
}

void
go_flat_member_nested(int nested_ix, const char *token, int stars) {
    g_flat_last_member_owner = g_flat.cur_ix;
    flat_add_member(flat_at(g_flat.cur_ix), FT_NESTED, NULL, NULL,
                    nested_ix, token, stars);
}

void
go_flat_member_nested_on(int on_ix, int nested_ix, const char *token,
                         int stars) {
    if(on_ix < 0) on_ix = g_flat_last_nest;
    g_flat_last_member_owner = on_ix;
    flat_add_member(flat_at(on_ix), FT_NESTED, NULL, NULL,
                    nested_ix, token, stars);
}

/* A SEQ OF member nested-inline in the CURRENT struct ({items,count} by
 * value, or * behind a star): mint the nested seqof node on the fly. */
static void
flat_member_seqof_at(int tgt_ix, const char *elem_cid, int elem_is_prim,
                     const char *token, int stars) {
    /* MINT the node FIRST (g_flat.types reallocs inside), and only then
     * resolve the target pointer — a pointer taken before the mint would
     * dangle after the realloc (the heap-corruption bug this comment
     * replaces: malloc_consolidate invalid chunk). */
    flat_type *n = flat_new_type(FLT_SEQOF, "", NULL);
    if(!n) return;
    n->elem = fstrdup(elem_cid);
    n->elem_prim = elem_is_prim;
    n->nested_only = 1;
    flat_add_member(flat_at(tgt_ix), FT_NESTED, NULL, NULL,
                    (int)(n - g_flat.types), token, stars);
    g_flat_last_member_owner = tgt_ix;
}

void
go_flat_member_seqof(const char *elem_cid, int elem_is_prim, const char *token,
                     int stars) {
    flat_member_seqof_at(g_flat.cur_ix, elem_cid, elem_is_prim,
                         token, stars);
}

void
go_flat_member_seqof_on(int nest_ix, const char *elem_cid,
                        int elem_is_prim, const char *token, int stars) {
    /* the member ROW lands on the ENCLOSING struct (cur) pointing at the new
     * {items,count} node; nest_ix (a pre-minted FLT_STRUCT for the same
     * construct, whose members instead ride the seqof node) stays empty —
     * empty nested nodes emit nothing. */
    flat_member_seqof_at(g_flat.cur_ix, elem_cid, elem_is_prim,
                         token, stars);
    (void)nest_ix;
}

/* ---------------------------------------------------------------------------
 * IR accessors for the conv emitter (go_conv.c; the conv/entry emission reads the
 * SAME IR — one structural decision, both file families).
 * Called only after the walk completes (no mints interleave); indices and
 * short-lived pointers are safe under that contract.
 * ------------------------------------------------------------------------ */
int go_flat_ir_n_types(void) { return g_flat.n_types; }
flat_type *go_flat_ir_type(int ix) { return flat_at(ix); }
int go_flat_ir_members(flat_type *t) { return t ? t->n_members : 0; }
flat_member *go_flat_ir_member(flat_type *t, int i) {
    return (t && i >= 0 && i < t->n_members) ? &t->members[i] : NULL;
}
/* flat_ref_resolve is defined below (the layout section); this forward decl
 * keeps the IR accessor usable above it. */
static flat_type *flat_ref_resolve(const char *ref);
flat_type *go_flat_ir_ref_resolve(const char *ref) {
    return flat_ref_resolve(ref);
}
int go_flat_ir_is_choice(flat_type *t) { return t ? t->is_choice : 0; }
int go_flat_ir_is_nested_only(flat_type *t) { return t ? t->nested_only : 0; }
int go_flat_ir_is_alias(flat_type *t) { return t && t->kind == FLT_ALIAS; }
int go_flat_ir_is_seqof(flat_type *t) { return t && t->kind == FLT_SEQOF; }
int go_flat_ir_is_struct(flat_type *t) { return t && t->kind == FLT_STRUCT; }
int go_flat_ir_is_leaf(flat_type *t) { return t && t->kind == FLT_LEAF; }
const char *go_flat_ir_name(flat_type *t) { return t ? t->name : NULL; }
const char *go_flat_ir_cid(flat_type *t) { return t ? t->cid : NULL; }
const char *go_flat_ir_module(flat_type *t) { return t ? t->module : NULL; }
const char *go_flat_ir_prim(flat_type *t) { return t ? t->prim : NULL; }
int go_flat_ir_member_is_prim(flat_member *m) {
    return m && m->kind == FT_PRIM;
}
int go_flat_ir_member_is_ref(flat_member *m) {
    return m && m->kind == FT_REF;
}
int go_flat_ir_member_is_nested(flat_member *m) {
    return m && m->kind == FT_NESTED;
}
const char *go_flat_ir_member_prim(flat_member *m) { return m ? m->prim : NULL; }
const char *go_flat_ir_member_ref(flat_member *m) { return m ? m->ref : NULL; }
const char *go_flat_ir_member_token(flat_member *m) { return m ? m->token : NULL; }
/* display label (recorded Identifier); NULL = unrecorded. */
const char *go_flat_ir_member_label(flat_member *m) { return m ? m->label : NULL; }
const char *go_flat_ir_type_label(flat_type *t) { return t ? t->label : NULL; }
int go_flat_ir_member_stars(flat_member *m) { return m ? m->stars : 0; }
int go_flat_ir_member_is_default(flat_member *m) { return m ? m->is_default : 0; }
int go_flat_ir_member_tree_ptr(flat_member *m) { return m ? m->tree_ptr : 0; }
int go_flat_ir_member_wide(flat_member *m) { return m ? m->wide : 0; }
int go_flat_ir_member_strk(flat_member *m) { return m ? m->strk : 0; }
int go_flat_ir_strk(flat_type *t) { return t ? t->strk : 0; }
int go_flat_ir_member_strz(flat_member *m) { return m ? m->strz : 0; }
int go_flat_ir_strz(flat_type *t) { return t ? t->strz : 0; }
const char *go_flat_ir_member_tree_token(flat_member *m) {
    return m ? (m->tree_token ? m->tree_token : m->token) : NULL;
}
int go_flat_ir_member_nested_ix(flat_member *m) { return m ? m->nested_ix : -1; }
/* Glue scope: the computed layout VALUES behind the layout.go consts
 * (the glue's self-contained local copies of FOREIGN-type fns need the
 * foreign offsets, which layout.go declares only in the OWNING package —
 * unexported, so cross-package const references cannot compile). The glue
 * emits its own local const decl for a foreign offset, spelled by its own
 * rule (the <P><pkg>-collision-safe local alias; go_glue.c gconst_glue). */
long go_flat_ir_member_offset(flat_member *m) { return m ? (long)m->offset : -1; }
long go_flat_ir_node_size(flat_type *t) { return t ? (long)t->size : -1; }
const char *go_flat_ir_elem(flat_type *t) { return t ? t->elem : NULL; }
int go_flat_ir_elem_prim(flat_type *t) { return t ? t->elem_prim : 0; }
int go_flat_ir_inline_elem(flat_type *t) { return t ? t->inline_elem : 0; }
const char *go_flat_ir_tree_ctype(flat_type *t) { return t ? t->tree_ctype : NULL; }
const char *go_flat_ir_go_type(flat_type *t) { return t ? t->go_type : NULL; }
const char *go_flat_ir_alias_of(flat_type *t) { return t ? t->alias_of : NULL; }

/* Tree type name of a node: <P><cid>_t (the real prefixed asn1c typedef).
 * the Flat name derives from the same cid, so the tree name is the Flat
 * name with _flat -> _t. A node without a cid (anonymous nested wrapper)
 * has no converter of its own — NULL. (Prototype: declared in go_conv.h.) */
const char *
go_conv_tree_typename(flat_type *t) {
    static char buf[512];
    if(!t || !t->name || !t->cid || !*t->cid) return NULL;
    size_t n = strlen(t->name);
    if(n < 5 || strcmp(t->name + n - 5, "_flat") != 0) return NULL;
    if(n - 5 + 2 >= sizeof buf) return NULL;
    memcpy(buf, t->name, n - 5);
    buf[n - 5] = '_';
    buf[n - 5 + 1] = 't';
    buf[n - 5 + 2] = '\0';
    return buf;
}

/* ---------------------------------------------------------------------------
 * x86-64 SysV layout engine (the Flat layout rule) — no compiler involved.
 * ------------------------------------------------------------------------ */
static int
flat_prim_layout(const char *prim, unsigned long *size, unsigned long *align) {
    static const struct { const char *tok; unsigned long s, a; } tab[] = {
        {"int8_t", 1, 1},   {"uint8_t", 1, 1},
        {"int16_t", 2, 2},  {"uint16_t", 2, 2},
        {"int32_t", 4, 4},  {"uint32_t", 4, 4},  {"_bool32", 4, 4},
        {"int64_t", 8, 8},  {"uint64_t", 8, 8},
        {"size_t", 8, 8},
        {"double", 8, 8},
        /* shared rt primitives (c/rt/types.h; their own members never change
         * — sizes restated here once): {ptr,len}=16/8, {ptr,len,i32}=24/8 */
        {"asn1cgo_bytes_flat", 16, 8},
        {"asn1cgo_bits_flat", 24, 8},
    };
    for(size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if(strcmp(tab[i].tok, prim) == 0) {
            *size = tab[i].s;
            *align = tab[i].a;
            return 1;
        }
    return 0;
}

static void flat_layout(flat_type *t);

/* Resolve a member's REF target cid to a node: an exact name, else the cid
 * set is prefixed (the per-spec prefix rule) — the walk records refs by the terminal's GO_MKID
 * (prefixed aggregate), while a node minted from an inline compound may have
 * stored its cid unprefixed; try the run prefix in both directions. */
static const char *cid_strip_static(const char *cid);
static const char *
cid_strip_static(const char *cid) {
    const char *pfx = asn1c_prefix();
    if(pfx && *pfx && cid && strncmp(cid, pfx, strlen(pfx)) == 0)
        return cid + strlen(pfx);
    return cid;
}
static flat_type *
flat_ref_resolve(const char *ref) {
    /* nodes are named <P><cid>_flat and store the PREFIX-STRIPPED cid
     * (flat_new_type strips once); refs arrive in both spellings — GO_MKID
     * output (prefix included, the member walk) and already-stripped cids
     * (go_conv_record_pdu stores via cid_dup). Normalize ONE strip, then
     * match; on a miss where a strip happened, the input may have been an
     * already-stripped cid whose own text starts with the run prefix
     * (E2AP-PDU -> stored cid "E2AP_PDU" under prefix "E2AP_") — the second
     * strip then ate a legitimate part of the cid. In that case the ORIGINAL
     * input spelling left intact IS the stored cid: match it directly
     * (never recursively — P_PDU strips back to PDU and loops forever). */
    const char *orig = ref;
    int was_stripped = (cid_strip_static(ref) != ref);
    ref = cid_strip_static(ref);
    /* strip a _flat suffix if present (name-keyed call sites) */
    {
        size_t n = strlen(ref);
        if(n > 5 && strcmp(ref + n - 5, "_flat") == 0) {
            char *b = malloc(n - 5 + 1);
            if(b) {
                memcpy(b, ref, n - 5);
                b[n - 5] = 0;
                flat_type *r = NULL;
                for(int i = 0; i < g_flat.n_types && !r; i++)
                    if(g_flat.types[i].cid && strcmp(g_flat.types[i].cid, b) == 0)
                        r = &g_flat.types[i];
                free(b);
                if(r) return r;
            }
        }
    }
    for(int i = 0; i < g_flat.n_types; i++)
        if(g_flat.types[i].cid
           && strcmp(g_flat.types[i].cid, ref) == 0)
            return &g_flat.types[i];
    if(was_stripped) {
        for(int i = 0; i < g_flat.n_types; i++)
            if(g_flat.types[i].cid
               && strcmp(g_flat.types[i].cid, orig) == 0)
                return &g_flat.types[i];
    }
    return NULL;
}

static void
flat_member_layout(flat_member *m, unsigned long *size, unsigned long *align) {
    switch(m->kind) {
    case FT_PRIM:
        if(m->stars) { *size = 8; *align = 8; return; }   /* pointer slot */
        if(!flat_prim_layout(m->prim, size, align)) {
            fprintf(stderr, "asn1cgo: flat: unknown primitive %s\n",
                    m->prim ? m->prim : "?");
            g_flat_failed_set();
            *size = 0; *align = 1;
        }
        return;
    case FT_REF:
        if(m->stars) { *size = 8; *align = 8; return; }
        {
            flat_type *r = flat_ref_resolve(m->ref);
            if(!r) {
                fprintf(stderr, "asn1cgo: flat: unresolved ref %s\n",
                        m->ref ? m->ref : "?");
                g_flat_failed_set();
                *size = 0; *align = 1;
                return;
            }
            flat_layout(r);
            *size = r->size;
            *align = r->align;
        }
        return;
    case FT_NESTED: {
        flat_type *n = flat_at(m->nested_ix);
        if(m->stars || !n) { *size = 8; *align = 8; return; }
        flat_layout(n);
        *size = n->size;
        *align = n->align;
        return;
    }
    }
}

/* Recursion termination: every by-value edge in a Flat IR forms a DAG
 * (the by-value-cycle gate runs upstream on the same walk); a cycle
 * would recurse forever, so an in-progress guard fails loud instead. */
static void
flat_layout(flat_type *t) {
    if(t->laid_out) return;
    if(t->kind == FLT_LEAF) {
        if(!flat_prim_layout(t->prim, &t->size, &t->align)) {
            fprintf(stderr, "asn1cgo: flat: bad leaf primitive %s\n",
                    t->prim ? t->prim : "?");
            g_flat_failed_set();
            t->size = 0; t->align = 1;
        }
        t->laid_out = 1;
        return;
    }
    if(t->kind == FLT_SEQOF) {
        t->size = 16; t->align = 8; t->laid_out = 1;
        return;
    }
    if(t->kind == FLT_ALIAS) {
        flat_type *r = flat_ref_resolve(t->alias_of);
        if(!r) {
            fprintf(stderr, "asn1cgo: flat: alias %s of unresolved %s\n",
                    t->name, t->alias_of);
            g_flat_failed_set();
            t->size = 0; t->align = 1;
        } else {
            flat_layout(r);
            t->size = r->size;
            t->align = r->align;
        }
        t->laid_out = 1;
        return;
    }
    if(t->in_progress) {
        fprintf(stderr, "asn1cgo: flat: by-value cycle at %s\n", t->name);
        g_flat_failed_set();
        return;
    }
    t->in_progress = 1;
    unsigned long off = 0, maxa = 1;
    for(int i = 0; i < t->n_members; i++) {
        flat_member *m = &t->members[i];
        unsigned long ms = 0, ma = 1;
        flat_member_layout(m, &ms, &ma);
        off = (off + ma - 1) / ma * ma;
        m->offset = off;
        off += ms;
        if(ma > maxa) maxa = ma;
    }
    t->size = (off + maxa - 1) / maxa * maxa;
    t->align = maxa;
    t->in_progress = 0;
    t->laid_out = 1;
}

void
go_flat_layout_all(void) {
    for(int i = 0; i < g_flat.n_types; i++)
        flat_layout(&g_flat.types[i]);
}

/* ---------------------------------------------------------------------------
 * Emission.
 * ------------------------------------------------------------------------ */


static int
flat_mkdir_p(const char *path) {
    char buf[4096];
    size_t n = strlen(path);
    if(n == 0 || n >= sizeof buf) {
        fprintf(stderr, "asn1cgo: flat: bad directory path (empty or too long): '%s'\n", path);
        return -1;
    }
    memcpy(buf, path, n + 1);
    for(size_t i = 1; i < n; i++) {
        if(buf[i] == '/') {
            buf[i] = '\0';
            if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: flat: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
            buf[i] = '/';
        }
    }
    if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: flat: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
    return 0;
}

static char *
fpath(const char *dir, const char *leaf) {
    size_t a = strlen(dir), b = strlen(leaf);
    char *p = malloc(a + 1 + b + 1);
    if(!p) { g_flat_failed_set(); return strdup(""); }
    memcpy(p, dir, a); p[a] = '/'; memcpy(p + a + 1, leaf, b); p[a + 1 + b] = 0;
    return p;
}

/* Write one whole file (returns 0/-1). */
static int
fwrite_all(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if(!f) {
        fprintf(stderr, "asn1cgo: flat: cannot write '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    size_t n = strlen(text);
    int ok = fwrite(text, 1, n, f) == n;
    if(fclose(f) != 0) ok = 0;
    if(!ok) {
        fprintf(stderr, "asn1cgo: flat: write failed under '%s'\n", path);
        return -1;
    }
    return 0;
}

/* Copy one rt file from <fork>/libasn1compiler_go/rt/ into c/rt/. The rt
 * files live beside this source in the build tree; resolved relative to the
 * compiled-in go-flat source dir is not possible portably, so the rt text
 * is EMBEDDED in the generator (self-contained output; a generated tree
 * never depends on the fork's build state). See rt blob table below. */
struct rt_blob { const char *name, *text; };

/* The package's header file name: <P><pkg>_flat.h. */
static char *
pkg_flat_h(const char *prefix, const char *pkg) {
    char *r = malloc(strlen(prefix) + strlen(pkg) + 10 + 1);
    if(!r) { g_flat_failed_set(); return strdup(""); }
    sprintf(r, "%s%s_flat.h", prefix, pkg);
    return r;
}

/* ---- dependency order -----------------------------------------------------
 * A package header emits its OWN nodes in dependency order: a node may be
 * defined only after every node it references BY VALUE (a star never needs
 * the definition — an incomplete forward decl suffices). SCC-free by the
 * by-value-cycle gate (every cycle rides a pointer), so a post-order DFS over by-value
 * edges lands every node after its by-value deps; a recursive by-value edge
 * cannot occur (that is the by-value-cycle gate), so the DFS terminates.
 * Forwarddeclarations: every multi-member-capable node referenced by a
 * POINTER before its definition gets `typedef struct X_flat X_flat;` up top
 * (including self-reference: a pointer member to the enclosing type).
 */

/* Pre-pass over a package's nodes: collect foreign-package refs (module
 * differs) as include lines. */
typedef struct { char *pkg, *sample; } flat_inc;

/* ---- node emission ------------------------------------------------------- */

/* Render ONE node's member lines (igits: members with type tokens) into s. */
static void
render_struct_body(flat_type *t, char **s, int indent) {
    /* the {items,count} shape (a SEQ OF node, or a minted nested seqof) */
    if(t->kind == FLT_SEQOF) {
        for(int i = 0; i < indent; i++) *s = fa(*s, " ");
        if(t->elem_prim) {
            *s = fa(*s, t->elem);
        } else {
            flat_type *r = flat_ref_resolve(t->elem);
            *s = fa(*s, r ? r->name : t->elem);
        }
        *s = fa(*s, " *items;\n");
        for(int i = 0; i < indent; i++) *s = fa(*s, " ");
        *s = fa(*s, "size_t count;\n");
        return;
    }
    for(int i = 0; i < t->n_members; i++) {
        flat_member *m = &t->members[i];
        for(int k = 0; k < indent; k++) *s = fa(*s, " ");
        flat_type *nest = m->kind == FT_NESTED ? flat_at(m->nested_ix) : NULL;
        if(m->kind == FT_NESTED) {
            /* an anonymous nested struct, exactly as the .h nests it
             * (the Flat naming rule): `struct {` ... `} token;` (a leading `*` for a
             * pointer slot member). */
            if(m->stars) *s = fa(*s, "struct {   /* ptr-to-nested */\n");
            else *s = fa(*s, "struct {\n");
            render_struct_body(nest, s, indent + 4);
            for(int k = 0; k < indent; k++) *s = fa(*s, " ");
            *s = fa(*s, "} ");
            if(m->stars) *s = fa(*s, "*");
            *s = fa(*s, m->token);
            *s = fa(*s, ";\n");
            continue;
        }
        if(m->kind == FT_PRIM) *s = fa(*s, strcmp(m->prim, "_bool32") == 0 ? "int32_t" : m->prim);
        else {   /* FT_REF */
            flat_type *r = flat_ref_resolve(m->ref);
            *s = fa(*s, r ? r->name : m->ref);
        }
        if(m->stars) *s = fa(*s, " *"); else *s = fa(*s, " ");
        *s = fa(*s, m->token);
        *s = fa(*s, ";\n");
    }
}

/* The full package-scoped typedef of one node (NULL when nested-only). */
static char *
render_node(flat_type *t) {
    if(t->nested_only) return NULL;
    char *s = strdup("");
    switch(t->kind) {
    case FLT_LEAF:
        s = fa(s, "typedef ");
        /* _bool32 is a Go-side marker (bool <-> 0/1); the C layout is int32_t */
        s = fa(s, strcmp(t->prim, "_bool32") == 0 ? "int32_t" : t->prim);
        s = fa(s, " ");
        s = fa(s, t->name);
        s = fa(s, ";\n");
        break;
    case FLT_SEQOF:
        s = fa(s, "typedef struct {\n");
        render_struct_body(t, &s, 4);
        s = fa(s, "} ");
        s = fa(s, t->name);
        s = fa(s, ";\n");
        break;
    case FLT_ALIAS: {
        flat_type *r = flat_ref_resolve(t->alias_of);
        s = fa(s, "typedef ");
        s = fa(s, r ? r->name : t->alias_of);
        s = fa(s, " ");
        s = fa(s, t->name);
        s = fa(s, ";\n");
        break;
    }
    case FLT_STRUCT:
        s = fa(s, "typedef struct ");
        s = fa(s, t->name);
        s = fa(s, " {\n");
        render_struct_body(t, &s, 4);
        s = fa(s, "} ");
        s = fa(s, t->name);
        s = fa(s, ";\n");
        break;
    }
    return s;
}

/* Forward-declaration line for one node (before its full definition). */
static char *
render_fwd(flat_type *t) {
    char *s = strdup("typedef struct ");
    s = fa(s, t->name);
    s = fa(s, " ");
    s = fa(s, t->name);
    s = fa(s, ";\n");
    return s;
}

/* Does t reference d at member level (ANY ref: a starred pointer ref needs
 * the typedef NAME declared before use, just like a by-value ref — only the
 * STRUCT-kind targets can bridge via a `typedef struct X X;` fwd instead)?
 * Depth-limited (cycles are excluded by the upstream by-value-cycle gate: every cycle
 * rides a pointer edge, which still counts as an edge here — the ORDERER
 * just ignores edges that close a cycle among already-ordered nodes). */
static int
value_ref_to(flat_type *t, flat_type *d, int depth) {
    if(depth > 64) return 0;
    for(int i = 0; i < t->n_members; i++) {
        flat_member *m = &t->members[i];
        if(m->kind == FT_NESTED) {
            flat_type *n = flat_at(m->nested_ix);
            if(!m->stars && n == d) return 1;
            if(n && value_ref_to(n, d, depth + 1)) return 1;
            /* a nested seqof's items element references its elem */
            if(n && n->kind == FLT_SEQOF && !n->elem_prim
               && flat_ref_resolve(n->elem) == d)
                return 1;
        } else if(m->kind == FT_REF) {
            flat_type *r = flat_ref_resolve(m->ref);
            if(r == d) return 1;
            if(r && value_ref_to(r, d, depth + 1)) return 1;
        }
    }
    if(t->kind == FLT_SEQOF && !t->elem_prim
       && flat_ref_resolve(t->elem) == d)
        return 1;
    if(t->kind == FLT_ALIAS && flat_ref_resolve(t->alias_of) == d)
        return 1;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Per-package emission: <P><pkg>_flat.h + <P><pkg>_layout_check.c under
 * <go_outdir>/c/, and layout.go under <go_outdir>/<pkg>/.
 * ------------------------------------------------------------------------ */

/* rstrip an owned string in place. */
static char *
rtrim(char *s) {
    size_t n = strlen(s);
    while(n && (s[n-1] == '\n' || s[n-1] == ' ')) s[--n] = '\0';
    return s;
}

/* The inner-offset asserts of the by-value nested wrapper member `m` of node
 * `t`, recursing through wrappers nested inside wrappers. `lhs` = the C
 * offset expression of the wrapper from the top of t ("offsetof(T, a)", then
 * "offsetof(T, a) + offsetof(typeof(((T *)0)->a), c)"); `acc` = its member
 * access path ("a", "a.c"); `label` = the assert message prefix; `abs` = the
 * wrapper's offset from the top of t. */
static void
render_nested_asserts(flat_type *t, flat_member *m, const char *lhs,
                      const char *acc, const char *label, unsigned long abs,
                      char **s) {
    flat_type *n = flat_at(m->nested_ix);
    if(!n) return;
    for(int j = 0; j < n->n_members; j++) {
        flat_member *im = &n->members[j];
        char *sub = fstrdup(lhs);
        sub = fa(sub, " + offsetof(typeof(((");
        sub = fa(sub, t->name);
        sub = fa(sub, " *)0)->");
        sub = fa(sub, acc);
        sub = fa(sub, "), ");
        sub = fa(sub, im->token);
        sub = fa(sub, ")");
        char num[32];
        *s = fa(*s, "_Static_assert(");
        *s = fa(*s, sub);
        snprintf(num, sizeof num, " == %lu, \"", abs + im->offset);
        *s = fa(*s, num);
        *s = fa(*s, label);
        *s = fa(*s, ".");
        *s = fa(*s, im->token);
        snprintf(num, sizeof num, "@%lu", im->offset);
        *s = fa(*s, num);
        *s = fa(*s, "\");\n");
        if(im->kind == FT_NESTED && !im->stars) {
            char *nacc = fstrdup(acc);
            nacc = fa(nacc, ".");
            nacc = fa(nacc, im->token);
            char *nlabel = fstrdup(label);
            nlabel = fa(nlabel, ".");
            nlabel = fa(nlabel, im->token);
            render_nested_asserts(t, im, sub, nacc, nlabel,
                                  abs + im->offset, s);
            free(nacc); free(nlabel);
        }
        free(sub);
    }
}

static char *go_off_const2(const char *node_name, const char *tok1,
                           const char *tok2);

/* layout.go consts + cgo probes of the inner members of the by-value nested
 * wrapper member `m` of node `t`, recursing through wrappers nested inside
 * wrappers. `chain` = the const-name token chain ("a", "a_c": the camel-casing
 * of go_off_const2 drops the separators); `lhs`/`acc` = the C offset
 * expression and member-access path of the wrapper under t (as in
 * render_nested_asserts); `label` = the probe message path; `abs` = the
 * wrapper's offset from the top of t. */
static void
layout_nested_consts(flat_type *t, flat_member *m, const char *chain,
                     const char *lhs, const char *acc, const char *label,
                     unsigned long abs, char **lconsts, char **probe_c,
                     char **probe_go, size_t *probe_n) {
    flat_type *n = flat_at(m->nested_ix);
    if(!n) return;
    for(int j = 0; j < n->n_members; j++) {
        flat_member *im = &n->members[j];
        char ob[32];
        snprintf(ob, sizeof ob, "%lu", abs + im->offset);
        char *oc = go_off_const2(t->name, chain, im->token);
        *lconsts = fa(*lconsts, "const ");
        *lconsts = fa(*lconsts, oc);
        *lconsts = fa(*lconsts, " = ");
        *lconsts = fa(*lconsts, ob);
        *lconsts = fa(*lconsts, "\n");
        /* probe: the composite accessor uses the typeof-sum form (an
         * anonymous inline struct member has no named inner typedef to
         * offsetof directly). */
        char *sub = fstrdup(lhs);
        sub = fa(sub, " + offsetof(typeof(((");
        sub = fa(sub, t->name);
        sub = fa(sub, " *)0)->");
        sub = fa(sub, acc);
        sub = fa(sub, "), ");
        sub = fa(sub, im->token);
        sub = fa(sub, ")");
        char acs[64];
        snprintf(acs, sizeof acs, "probe_%zu", (*probe_n)++);
        *probe_c = fap(*probe_c,
            "static inline unsigned long %s(void) "
            "{ return (unsigned long)(%s); }\n", acs, sub);
        *probe_go = fap(*probe_go,
            "\tmust(\"off %s.%s.%s\", uintptr(%s), uintptr(C.%s()))\n",
            t->name, label, im->token, oc, acs);
        if(im->kind == FT_NESTED && !im->stars) {
            char *nchain = fstrdup(chain);
            nchain = fa(nchain, "_");
            nchain = fa(nchain, im->token);
            char *nacc = fstrdup(acc);
            nacc = fa(nacc, ".");
            nacc = fa(nacc, im->token);
            char *nlabel = fstrdup(label);
            nlabel = fa(nlabel, ".");
            nlabel = fa(nlabel, im->token);
            layout_nested_consts(t, im, nchain, sub, nacc, nlabel,
                                 abs + im->offset, lconsts, probe_c,
                                 probe_go, probe_n);
            free(nchain); free(nacc); free(nlabel);
        }
        free(sub);
        free(oc);
    }
}

/* The asserts of one node (the sizeof + one offsetof per member, in member
 * order) appended to layout_check.c text. Nested members use the frozen units
 * typeof-sum forms: offsetof(T, tok) + offsetof(typeof(((T*)0)->tok), m). */
static void
render_node_asserts(flat_type *t, char **s) {
    if(t->nested_only) return;
    /* the sizeof assert (leaf/seqof/alias included) */
    *s = fa(*s, "_Static_assert(sizeof(");
    *s = fa(*s, t->name);
    *s = fa(*s, ") == ");
    {
        char buf[32];
        snprintf(buf, sizeof buf, "%lu", t->size);
        *s = fa(*s, buf);
    }
    *s = fa(*s, ", \"");
    *s = fa(*s, t->name);
    *s = fa(*s, "\");\n");
    for(int i = 0; i < t->n_members; i++) {
        flat_member *m = &t->members[i];
        char off[32], moff[32], msize[32];
        snprintf(off, sizeof off, "%lu", m->offset);
        *s = fa(*s, "_Static_assert(offsetof(");
        *s = fa(*s, t->name);
        *s = fa(*s, ", ");
        *s = fa(*s, m->token);
        *s = fa(*s, ") == ");
        *s = fa(*s, off);
        *s = fa(*s, ", \"");
        *s = fa(*s, m->token);
        *s = fa(*s, "@");
        *s = fa(*s, off);
        *s = fa(*s, "\");\n");
        (void)msize; (void)moff;
        /* a nested-by-value wrapper: also assert its inner offsets via the
         * typeof-sum form (the frozen units' nested-assert grammar), at every
         * nesting depth */
        if(m->kind == FT_NESTED && !m->stars) {
            {
                char *off = fstrdup("offsetof(");
                off = fa(off, t->name);
                off = fa(off, ", ");
                off = fa(off, m->token);
                off = fa(off, ")");
                render_nested_asserts(t, m, off, m->token, m->token,
                                      m->offset, s);
                free(off);
            }
            /* the nested wrapper's own sizeof via typeof */
            flat_type *n = flat_at(m->nested_ix);
            *s = fa(*s, "_Static_assert(sizeof(typeof(((");
            *s = fa(*s, t->name);
            *s = fa(*s, " *)0)->");
            *s = fa(*s, m->token);
            *s = fa(*s, ")) == ");
            {
                char nb[32];
                snprintf(nb, sizeof nb, "%lu", n->size);
                *s = fa(*s, nb);
            }
            *s = fa(*s, ", \"");
            *s = fa(*s, m->token);
            *s = fa(*s, " size");
            *s = fa(*s, "\");\n");
        }
    }
}


/* One module's emission unit: its package name, its nodes, ordered. */
typedef struct {
    const char *module;
    char *pkg;
    int *order;         /* node indices, dependency order                    */
    int n_order;
    flat_inc *incs;         /* foreign packages to include                     */
    int n_incs;
} pkg_unit;

/* fwd_note: add `typedef struct X_flat X_flat;` for target r (same package,
 * FLT_STRUCT, defined later-or-self than the user at order position oi). */
static void
fwd_note(flat_type *r, const char *user_module, pkg_unit *pu, int oi,
         char **fwd) {
    if(!r || r->nested_only || r->kind != FLT_STRUCT) return;
    if(!r->module || !user_module) return;
    if(strcmp(r->module, user_module) != 0) return;
    int rpos = -1;
    for(int q = 0; q < pu->n_order; q++)
        if(pu->order[q] == (int)(r - g_flat.types)) { rpos = q; break; }
    if(rpos < 0) return;                 /* not a package node of this pkg */
    if(rpos <= oi && &g_flat.types[pu->order[oi]] != r) return;  /* earlier */
    char *line = render_fwd(r);
    if(!strstr(*fwd, line)) *fwd = fa(*fwd, line);
    free(line);
}

/* Dependency order of one package's package-scoped nodes: a node is emitted
 * after every SAME-package node it references by value (a starred ref never
 * delays). O(n^2) sweep (n = per-package node count, hundreds max): repeat
 * passes; each pass appends every node whose by-value same-package deps are
 * all already placed; a full pass with no placement = an unorderable cycle
 * (fail loud — the by-value-cycle gate upstream should have caught it). */
static int
order_pkg_nodes(int *ix, int n, int **order_out, int *n_order_out) {
    int *order = calloc((size_t)n ? (size_t)n : 1, sizeof(int));
    int n_order = 0;
    char *done = calloc((size_t)n ? (size_t)n : 1, 1);
    if(!order || !done) { free(order); free(done); g_flat_failed_set(); return -1; }
    for(int pass = 0; pass <= n; pass++) {
        int placed = 0;
        for(int i = 0; i < n; i++) {
            if(done[i]) continue;
            flat_type *t = &g_flat.types[ix[i]];
            int ready = 1;
            for(int j = 0; j < n && ready; j++) {
                if(done[j] || i == j) continue;
                flat_type *d = &g_flat.types[ix[j]];
                int same = d->module && t->module
                           && strcmp(d->module, t->module) == 0;
                if(!same || !value_ref_to(t, d, 0)) continue;
                /* unsatisfied dep; it is a BREAKABLE back edge iff d also
                 * (transitively) references t — the fwd decl covers t's use
                 * inside d, and d's use inside t is the pointer the cycle
                 * rides a recursion pointer. Otherwise a true forward dep: not ready. */
                if(!value_ref_to(d, t, 0)) ready = 0;
            }
            if(ready) {
                order[n_order++] = ix[i];
                done[i] = 1;
                placed = 1;
            }
        }
        if(n_order == n) break;
        if(!placed) {
            fprintf(stderr, "asn1cgo: flat: by-value cycle among package "
                            "nodes (unorderable; by-value cycle upstream?)\n");
            free(order); free(done);
            g_flat_failed_set();
            return -1;
        }
    }
    free(done);
    *order_out = order;
    *n_order_out = n_order;
    return 0;
}

/* uniqueness helper: node index appears once per module in pkgs. */
static int
pkg_of(const char *module, pkg_unit *pkgs, int n_pkgs) {
    for(int i = 0; i < n_pkgs; i++)
        if(pkgs[i].module == module
           || (module && pkgs[i].module
               && strcmp(pkgs[i].module, module) == 0))
            return i;
    return -1;
}


/* Go const-name mangling: the node cid (prefix + _flat stripped) CamelCased,
 * e.g. RICrequestID_flat -> RicrequestIDFlat; the frozen units' sizeof<...> /
 * off<...> const forms (unexported: off-lowercased first letter). */
static char *
camel_flat(const char *node_name) {
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    const char *s = node_name ? node_name : "";
    if(pl && strncmp(s, pfx, pl) == 0) s += pl;
    size_t n = strlen(s);
    if(n > 5 && strcmp(s + n - 5, "_flat") == 0) n -= 5;
    char *out = malloc(n + 1);
    if(!out) { g_flat_failed_set(); return strdup(""); }
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

static char *
camel_tok(const char *token) {
    const char *s = token ? token : "";
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if(!out) { g_flat_failed_set(); return strdup(""); }
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

static char *
go_sizeof_const(const char *node_name) {
    char *c = camel_flat(node_name);
    char *out = malloc(strlen(c) + 8);
    if(!out) { free(c); g_flat_failed_set(); return strdup(""); }
    sprintf(out, "sizeof%s", c);
    free(c);
    return out;
}

static char *
go_off_const(const char *node_name, const char *token) {
    char *c = camel_flat(node_name);
    char *t = camel_tok(token);
    char *out = malloc(strlen(c) + strlen(t) + 8);
    if(!out) { free(c); free(t); g_flat_failed_set(); return strdup(""); }
    sprintf(out, "off%s%s", c, t);
    free(c); free(t);
    return out;
}

static char *
go_off_const2(const char *node_name, const char *tok1, const char *tok2) {
    char *c = camel_flat(node_name);
    char *t1 = camel_tok(tok1);
    char *t2 = camel_tok(tok2);
    char *out = malloc(strlen(c) + strlen(t1) + strlen(t2) + 8);
    if(!out) { free(c); free(t1); free(t2); g_flat_failed_set(); return strdup(""); }
    sprintf(out, "off%s%s%s", c, t1, t2);
    free(c); free(t1); free(t2);
    return out;
}

int
go_flat_emit(const char *go_outdir, const char *go_module_basename) {
    (void)go_module_basename;
    if(!go_outdir || !*go_outdir) return 0;
    if(g_flat_failed_) return -1;

    const char *prefix = asn1c_prefix();
    if(!prefix) prefix = "";

    /* group nodes into per-module packages (walk order = module order) */
    pkg_unit *pkgs = NULL;
    int n_pkgs = 0, cap_pkgs = 0;
    int *by_pkg = malloc((size_t)(g_flat.n_types ? g_flat.n_types : 1)
                         * sizeof(int));
    if(!by_pkg) { g_flat_failed_set(); return -1; }
    int *pkg_start = malloc((size_t)(g_flat.n_types + 1) * sizeof(int));
    if(!pkg_start) { free(by_pkg); g_flat_failed_set(); return -1; }
    /* nodes were created in walk order; module changes mark boundaries only
     * if contiguous — sweep all nodes per module instead (modules may
     * interleave by owning module). */
    for(int i = 0; i < g_flat.n_types; i++) {
        const char *mod = g_flat.types[i].module;
        if(!mod || !*mod) {
            /* a package-scoped node minted without a module (defensive:
             * every mint site passes the owning module) — fail loud, never
             * a silent empty-name package header. */
            if(!g_flat.types[i].nested_only) {
                fprintf(stderr, "asn1cgo: flat: node %s has no owning module\n",
                        g_flat.types[i].name);
                g_flat_failed_set();
            }
            continue;
        }
        int pi = pkg_of(mod, pkgs, n_pkgs);
        if(pi < 0) {
            if(n_pkgs + 1 > cap_pkgs) {
                cap_pkgs = cap_pkgs ? cap_pkgs * 2 : 8;
                pkgs = realloc(pkgs, (size_t)cap_pkgs * sizeof(pkg_unit));
                if(!pkgs) { free(by_pkg); free(pkg_start);
                            g_flat_failed_set(); return -1; }
            }
            pkgs[n_pkgs].module = mod;
            pkgs[n_pkgs].pkg = flat_module_pkg(mod);
            pkgs[n_pkgs].order = NULL;
            pkgs[n_pkgs].n_order = 0;
            pkgs[n_pkgs].incs = NULL;
            pkgs[n_pkgs].n_incs = 0;
            pi = n_pkgs++;
        }
    }
    /* per-package node index lists */
    for(int p = 0; p < n_pkgs; p++) {
        int n = 0;
        for(int i = 0; i < g_flat.n_types; i++)
            if(pkg_of(g_flat.types[i].module, pkgs, n_pkgs) == p
               && !g_flat.types[i].nested_only)
                by_pkg[n++] = i;
        if(order_pkg_nodes(by_pkg, n, &pkgs[p].order, &pkgs[p].n_order) < 0) {
            free(by_pkg); free(pkg_start); free(pkgs);
            return -1;
        }
    }

    if(getenv("ASN1CGO_FLATDBG"))
        fprintf(stderr, "asn1cgo: flatdbg: n_types=%d n_pkgs=%d failed=%d\n",
                g_flat.n_types, n_pkgs, g_flat_failed_);
    /* output dirs */
    char *cdir = fpath(go_outdir, "c");
    if(flat_mkdir_p(cdir) < 0) g_flat_failed_set();   /* diag printed; fail below */

    int rc = -1;
    char *hdr = NULL, *lc = NULL, *fwd = NULL;

    for(int p = 0; p < n_pkgs && !g_flat_failed_; p++) {
        pkg_unit *pu = &pkgs[p];
        /* includes: foreign packages referenced by this package's nodes */
        pu->incs = malloc(32 * sizeof(*pu->incs));   /* 32 foreign pkgs cap */
        if(!pu->incs) { g_flat_failed_set(); break; }
        int n_inc = 0;
        for(int oi = 0; oi < pu->n_order; oi++) {
            flat_type *t = &g_flat.types[pu->order[oi]];
            /* every ref edge of the node: direct members, nested wrapper
             * members (a value union's alt rows), and a nested seqof's
             * element — a foreign target means one quoted include of its
             * package. */
            for(int i = 0; i < t->n_members; i++) {
                flat_member *m = &t->members[i];
                flat_type *cand[8];
                int n_cand = 0;
                if(m->kind == FT_REF) {
                    flat_type *r = flat_ref_resolve(m->ref);
                    if(r) cand[n_cand++] = r;
                } else if(m->kind == FT_NESTED) {
                    flat_type *n = flat_at(m->nested_ix);
                    if(n) {
                        for(int j = 0; j < n->n_members && n_cand < 8; j++)
                            if(n->members[j].kind == FT_REF) {
                                flat_type *r =
                                    flat_ref_resolve(n->members[j].ref);
                                if(r) cand[n_cand++] = r;
                            }
                        if(n->kind == FLT_SEQOF && !n->elem_prim) {
                            flat_type *e = flat_ref_resolve(n->elem);
                            if(e) cand[n_cand++] = e;
                        }
                    }
                }
                for(int c = 0; c < n_cand; c++) {
                    flat_type *r = cand[c];
                    if(!r->module || !t->module) continue;
                    if(strcmp(r->module, t->module) == 0) continue;
                    char *pkg = flat_module_pkg(r->module);
                    int seen = 0;
                    for(int q = 0; q < n_inc; q++)
                        if(strcmp(pu->incs[q].pkg, pkg) == 0) { seen = 1; break; }
                    if(!seen && n_inc < 32) {
                        pu->incs[n_inc].pkg = pkg;
                        pu->incs[n_inc].sample = r->name;
                        n_inc++;
                    } else free(pkg);
                }
            }
            if(t->kind == FLT_SEQOF && !t->elem_prim) {
                flat_type *e = flat_ref_resolve(t->elem);
                if(e && e->module && t->module
                   && strcmp(e->module, t->module) != 0) {
                    char *pkg = flat_module_pkg(e->module);
                    int seen = 0;
                    for(int q = 0; q < n_inc; q++)
                        if(strcmp(pu->incs[q].pkg, pkg) == 0) { seen = 1; break; }
                    if(!seen && n_inc < 32) {
                        pu->incs[n_inc].pkg = pkg;
                        pu->incs[n_inc].sample = e->name;
                        n_inc++;
                    } else free(pkg);
                }
            }
        }
        pu->n_incs = n_inc;

        /* forward decls (the layout rule): every STRUCT node of THIS package
         * named by a POINTER-holding reference â a starred ref
         * member OR the items-element of any seqof ({ Elem *items; } holds a
         * pointer too, direct or nested) â whose full definition
         * comes LATER in this package's order (or names the user itself:
         * recursion) gets `typedef struct X_flat X_flat;` before the bodies.
         * Leaf/seqof/alias targets need no fwd (an incomplete pointer target
         * needs the struct tag only). */
        fwd = strdup("");
        for(int oi = 0; oi < pu->n_order; oi++) {
            flat_type *t = &g_flat.types[pu->order[oi]];
            for(int i = 0; i < t->n_members; i++) {
                flat_member *m = &t->members[i];
                if(m->kind == FT_REF && m->stars) {
                    flat_type *r = flat_ref_resolve(m->ref);
                    fwd_note(r, t->module, pu, oi, &fwd);
                } else if(m->kind == FT_NESTED) {
                    flat_type *n = flat_at(m->nested_ix);
                    if(n && n->kind == FLT_SEQOF && !n->elem_prim) {
                        flat_type *e = flat_ref_resolve(n->elem);
                        fwd_note(e, t->module, pu, oi, &fwd);
                    }
                    for(int j = 0; n && j < n->n_members; j++) {
                        flat_member *nm = &n->members[j];
                        if(nm->kind == FT_REF && nm->stars)
                            fwd_note(flat_ref_resolve(nm->ref),
                                     t->module, pu, oi, &fwd);
                    }
                }
            }
            if(t->kind == FLT_SEQOF && !t->elem_prim) {
                flat_type *e = flat_ref_resolve(t->elem);
                fwd_note(e, t->module, pu, oi, &fwd);
            }
        }

        /* header */
        hdr = strdup("/* Generated Flat structs. */\n");
        {
            char *guard = malloc(strlen(prefix) + strlen(pu->pkg) + 32);
            sprintf(guard, "ASN1CGO_%s%s_FLAT_H", prefix, pu->pkg);
            for(char *g = guard; *g; g++)
                *g = (char)toupper((unsigned char)*g);
            char *line = malloc(2 * strlen(guard) + 24);
            sprintf(line, "#ifndef %s\n#define %s\n\n", guard, guard);
            hdr = fa(hdr, line);
            hdr = fa(hdr, "#include \"rt/types.h\"\n");
            /* sort foreign includes by pkg for determinism */
            for(int q = 0; q < n_inc; q++)
                for(int w = q + 1; w < n_inc; w++)
                    if(strcmp(pu->incs[q].pkg, pu->incs[w].pkg) > 0) {
                        char *a = pu->incs[q].pkg, *b = pu->incs[q].sample;
                        pu->incs[q].pkg = pu->incs[w].pkg;
                        pu->incs[q].sample = pu->incs[w].sample;
                        pu->incs[w].pkg = a; pu->incs[w].sample = b;
                    }
            for(int q = 0; q < n_inc; q++) {
                char *fh = pkg_flat_h(prefix, pu->incs[q].pkg);
                char *line2 = malloc(strlen(fh) + 16);
                sprintf(line2, "#include \"%s\"\n", fh);
                hdr = fa(hdr, line2);
                free(line2); free(fh);
            }
            hdr = fa(hdr, "\n");
            hdr = fa(hdr, fwd);
            hdr = fa(hdr, "\n");
            free(line); free(guard); free(fwd); fwd = NULL;
        }
        for(int oi = 0; oi < pu->n_order; oi++) {
            char *body = render_node(&g_flat.types[pu->order[oi]]);
            if(body) {
                hdr = fa(hdr, body);
                hdr = fa(hdr, "\n");
                free(body);
            }
        }
        hdr = fa(hdr, "#endif\n");
        if(getenv("ASN1CGO_FLATDBG"))
            fprintf(stderr, "asn1cgo: flatdbg: pkg=%s n_order=%d writing hdr len=%zu\n",
                    pu->pkg, pu->n_order, strlen(hdr));
        char *hname = pkg_flat_h(prefix, pu->pkg);
        char *hpath = fpath(cdir, hname);
        if(fwrite_all(hpath, hdr) < 0) { free(hpath); free(hname); goto out; }
        free(hpath); free(hname);
        free(hdr); hdr = NULL;

        /* layout_check.c */
        lc = strdup("/* Generated layout asserts. */\n");
        lc = fa(lc, "#include <stddef.h>\n");
        {
            char *hname = pkg_flat_h(prefix, pu->pkg);
            char *line = malloc(strlen(hname) + 16);
            sprintf(line, "#include \"%s\"\n", hname);
            lc = fa(lc, line);
            free(line); free(hname);
        }
        lc = fa(lc, "\n");
        for(int oi = 0; oi < pu->n_order; oi++)
            render_node_asserts(&g_flat.types[pu->order[oi]], &lc);
        rtrim(lc);
        lc = fa(lc, "\n");
        {
            char *lname = malloc(strlen(prefix) + strlen(pu->pkg) + 24);
            sprintf(lname, "%s%s_layout_check.c", prefix, pu->pkg);
            char *lpath = fpath(cdir, lname);
            if(fwrite_all(lpath, lc) < 0) { free(lpath); free(lname); goto out; }
            free(lpath); free(lname);
        }
        free(lc); lc = NULL;

        /* layout.go: the SAME computed literals + the init() cgo probe
         * (the layout rule + its Go-side guard): every own-package layout const
         * is compared at init() against the LIVE C compiler via cgo —
         * static inline accessors in the preamble return sizeof/offsetof
         * over the cspec <P><pkg>_flat.h definitions; a mismatch panics
         * naming struct + member (must()). This is the Go-side twin of the
         * glue asserts (which check the consts the GLUE uses, incl.
         * foreign re-declarations, at build time); this one checks the
         * layout.go consts the OWNING package declares, at init time. */
        {
            char *lg = strdup("");       /* assembled LAST (see below) */
            char *lconsts = strdup("");  /* the const declarations */
            char *probe_c = strdup("");   /* static inline accessor bodies */
            char *probe_go = strdup("");  /* must() lines */
            size_t probe_n = 0;
            for(int oi = 0; oi < pu->n_order; oi++) {
                flat_type *t = &g_flat.types[pu->order[oi]];
                if(t->nested_only) continue;
                char nb[32];
                snprintf(nb, sizeof nb, "%lu", t->size);
                char *sz = go_sizeof_const(t->name);
                lconsts = fa(lconsts, "const ");
                lconsts = fa(lconsts, sz);
                lconsts = fa(lconsts, " = ");
                lconsts = fa(lconsts, nb);
                lconsts = fa(lconsts, "\n");
                free(sz);
                /* probe: sizeof accessor + must line */
                {
                    char acc[64];
                    snprintf(acc, sizeof acc, "probe_%zu", probe_n++);
                    probe_c = fap(probe_c,
                        "static inline unsigned long %s(void) { return (unsigned long)sizeof(%s); }\n",
                        acc, t->name);
                    {
                        char *cf = camel_flat(t->name);
                        probe_go = fap(probe_go, "\tmust(\"sizeof %s\", uintptr(sizeof%s), uintptr(C.%s()))\n",
                                      t->name, cf ? cf : "", acc);
                        free(cf);
                    }
                }
                for(int i = 0; i < t->n_members; i++) {
                    flat_member *m = &t->members[i];
                    char ob[32];
                    snprintf(ob, sizeof ob, "%lu", m->offset);
                    char *oc = go_off_const(t->name, m->token);
                    lconsts = fa(lconsts, "const ");
                    lconsts = fa(lconsts, oc);
                    lconsts = fa(lconsts, " = ");
                    lconsts = fa(lconsts, ob);
                    lconsts = fa(lconsts, "\n");
                    /* probe: offsetof accessor */
                    {
                        char acc[64];
                        snprintf(acc, sizeof acc, "probe_%zu", probe_n++);
                        probe_c = fap(probe_c,
                            "static inline unsigned long %s(void) { return (unsigned long)offsetof(%s, %s); }\n",
                            acc, t->name, m->token);
                        char *cf = camel_flat(t->name);
                        char *ct = camel_tok(m->token);
                        probe_go = fap(probe_go, "\tmust(\"off %s.%s\", uintptr(off%s%s), uintptr(C.%s()))\n",
                                      t->name, m->token, cf ? cf : "", ct ? ct : "", acc);
                        free(cf); free(ct);
                    }
                    free(oc);
                }
                /* nested member offsets: off<Type><tok><inner>, and one name
                 * segment per level for a wrapper nested in a wrapper */
                for(int i = 0; i < t->n_members; i++) {
                    flat_member *m = &t->members[i];
                    if(m->kind != FT_NESTED || m->stars) continue;
                    char *lhs = fstrdup("offsetof(");
                    lhs = fa(lhs, t->name);
                    lhs = fa(lhs, ", ");
                    lhs = fa(lhs, m->token);
                    lhs = fa(lhs, ")");
                    layout_nested_consts(t, m, m->token, lhs, m->token,
                                         m->token, m->offset, &lconsts,
                                         &probe_c, &probe_go, &probe_n);
                    free(lhs);
                }
                lconsts = fa(lconsts, "\n");
            }
            /* assemble: banner + build tag + doc + package, cgo preamble
             * (import C MUST precede the const declarations), consts,
             * init, helpers */
            {
                lg = fa(lg, GO_GENERATED_BANNER);
                lg = fa(lg, "//go:build amd64\n\n");
                lg = fa(lg, "// layout.go - Flat struct sizeof/offsetof constants.\n");
                lg = fa(lg, "// Values computed by the generator under x86-64 SysV; cross-checked\n");
                lg = fa(lg, "// by <P><pkg>_layout_check.c (_Static_asserts) and the init() cgo\n");
                lg = fa(lg, "// probe below (live sizeof/offsetof, G.4).\n");
                lg = fa(lg, "package ");
                lg = fa(lg, pu->pkg);
                lg = fa(lg, "\n\n");
                char *fh = malloc(strlen(prefix) + strlen(pu->pkg) + 16);
                sprintf(fh, "%s%s_flat.h", prefix, pu->pkg);
                lg = fa(lg, "/*\n#cgo CFLAGS: -I${SRCDIR}/../internal/cspec -I${SRCDIR}/../internal/cspec/rt");
                if(go_oer_disabled()) lg = fa(lg, " -DASN_DISABLE_OER_SUPPORT");
                lg = fa(lg, "\n");
                lg = fa(lg, "#include \"");
                lg = fa(lg, fh);
                lg = fa(lg, "\"\n#include <stddef.h>\n");
                lg = fa(lg, probe_c);
                lg = fa(lg, "*/\nimport \"C\"\n\n");
                lg = fa(lg, lconsts);
                free(fh);
            }
            free(lconsts);
            lg = fa(lg, "func init() {\n");
            lg = fa(lg, probe_go);
            lg = fa(lg, "}\n\n");
            lg = fa(lg, "func must(name string, goVal, cVal uintptr) {\n"
                        "\tif goVal != cVal {\n"
                        "\t\tpanic(\"asn1cgo layout drift: \" + name + \": go=\" + itoa(goVal) + \" c=\" + itoa(cVal))\n"
                        "\t}\n"
                        "}\n\n");
            lg = fa(lg, "func itoa(v uintptr) string {\n"
                        "\tif v == 0 {\n"
                        "\t\treturn \"0\"\n"
                        "\t}\n"
                        "\tvar b [20]byte\n"
                        "\ti := len(b)\n"
                        "\tfor v > 0 {\n"
                        "\t\ti--\n"
                        "\t\td := byte('0') + byte(v%10)\n"
                        "\t\tb[i] = d\n"
                        "\t\tv /= 10\n"
                        "\t}\n"
                        "\treturn string(b[i:])\n"
                        "}\n");
            free(probe_c); free(probe_go);
            char *lname = malloc(strlen(pu->pkg) + 12);
            sprintf(lname, "%s/layout.go", pu->pkg);
            char *pkgdir = fpath(go_outdir, pu->pkg);
            if(flat_mkdir_p(pkgdir) < 0) g_flat_failed_set();
            while(strlen(lg) > 1 && lg[strlen(lg)-1] == '\n' && lg[strlen(lg)-2] == '\n')
                lg[strlen(lg)-1] = '\0';   /* gofmt: exactly one trailing \n */
            char *lpath2 = fpath(pkgdir, "layout.go");
            if(fwrite_all(lpath2, lg) < 0) {
                free(pkgdir); free(lpath2); free(lname); free(lg);
                goto out;
            }
            free(pkgdir); free(lpath2); free(lname); free(lg);
        }
    }
    rc = 0;
out:
    free(hdr); free(lc); free(fwd);
    for(int p = 0; p < n_pkgs; p++) {
        free(pkgs[p].pkg);
        free(pkgs[p].order);
        for(int q = 0; q < pkgs[p].n_incs; q++) free(pkgs[p].incs[q].pkg);
        free(pkgs[p].incs);
    }
    free(pkgs);
    free(pkg_start);
    free(by_pkg);
    free(cdir);
    if(g_flat_failed_) return -1;
    return rc;
}

/* void*-typed wrappers over the IR accessors for the conv TUs (go_conv.h's
 * shared surface; the flat_type* forms above stay this-file-only). */
const char *go_conv_ir_name(const void *t) {
    return t ? ((const flat_type *)t)->name : NULL;
}
const char *go_conv_ir_tree_base_override(const void *t) {
    return t ? ((const flat_type *)t)->tree_base : NULL;
}
const char *go_conv_ir_type_label(const void *t) {
    return t ? ((const flat_type *)t)->label : NULL;
}
const char *go_conv_ir_member_label(const void *m) {
    return m ? ((const flat_member *)m)->label : NULL;
}
void *go_conv_ir_ref_resolve(const char *ref) {
    return flat_ref_resolve(ref);
}
int go_conv_ir_is_choice(const void *t) {
    return t ? ((const flat_type *)t)->is_choice : 0;
}
