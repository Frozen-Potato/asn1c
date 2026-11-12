/*
 * go_conv_to.c — the `_to_tree` emission (Flat -> tree; per-type comparison,
 * Flat CHOICE layout and native-width INTEGER Flat/
 * per-SCC depth, NULL-alt and Flat naming) and the go_conv_emit driver (the cspec layout rule cspec package layout).
 *
 * The Flat IR (go_flat.c) is the single structural source: each IR node
 * emits ONE converter pair, its body driven by node kind + member kinds.
 * The tree-side accessor paths come from the SAME member tokens the Flat
 * carries (the Flat nests exactly as the asn1c .h nests):
 *   prim/ref member       in-><tok>            out-><tok>
 *   {items,count} member  in-><tok>.items/.count   out-><tok>.list
 *   nested wrapper member in-><tok>.<inner>    out-><tok>.<inner>
 *   CHOICE node           in->present / in-><alt>   out->present /
 *                         out->choice.<alt> (pointer alt: calloc first)
 *   leaf node             bare typedef value mirror
 *
 * SCC membership is computed HERE from the IR: a node is
 * recursion-SCC iff it can reach itself through ref edges (self-reachability
 * DFS over one-hop edges — ref members, seqof elements, alias targets,
 * nested-wrapper members; equivalent to Tarjan membership for "in a cycle").
 * SCC nodes get the depth guard at converter entry/exit; nothing else does.
 *
 * Naming: all identifiers derive from the IR cid (= the walk's GO_MKID
 * output, run prefix included per the per-spec prefix rule) via conv_tree_base
 * (go_conv_internal.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>

#include "asn1c_internal.h"     /* arg_t (required before asn1c_misc.h) */
#include "asn1c_misc.h"         /* asn1c_prefix (per-spec prefix) */

#include "go_conv.h"
#include "go_conv_internal.h"

/* The IR surface (go_flat.c, post-walk contract) is declared in go_conv.h
 * (the flat_type and flat_member prototypes; go_conv_internal.h includes it). */


/* go_conv_from.c per-node body emitter (this TU's mirror partner). */
extern char *conv_from_node(void *t, int scc);

/* ---------------------------------------------------------------------------
 * IR index helpers (indices are stable post-walk; pointer identity too).
 * ------------------------------------------------------------------------- */
static int
ir_ix_of(const void *t) {
    for(int i = 0; i < go_flat_ir_n_types(); i++)
        if(go_flat_ir_type(i) == (flat_type *)t) return i;
    return -1;
}

static void *
ir_resolve_ix(const char *ref) {
    void *r = go_conv_ir_ref_resolve(ref);
    return r;
}

/* ---------------------------------------------------------------------------
 * SCC: self-reachability over one-hop ref edges.
 * One-hop edges of a node:
 *   - alias: its alias_of target
 *   - named seqof: its element target (when a ref)
 *   - members: a REF member's resolved target; a NESTED member points at a
 *     wrapper node — a seqof wrapper contributes its element target, a
 *     struct/choice wrapper (inline CHOICE, value union) contributes ITS
 *     members' edges recursively (nested_only nodes have no independent
 *     lifetime; recursion through them is still unbounded).
 * A node is in a recursion SCC iff it reaches itself by >=1 edge.
 * ------------------------------------------------------------------------- */

/* add-target accumulator for ir_neighbors (NO nested functions in this TU:
 * clang-13 — the sanitizer build's compiler — rejects nested function
 * definitions, a GNU extension; a static helper + ctx struct keeps the same
 * shape portable). */
typedef struct {
    int *out;
    int n;      /* the IR type count (index bound)    */
    int cap;    /* out[] capacity                     */
    int c;      /* neighbors written so far           */
} ir_nb_ctx;

static void
ir_nb_add(ir_nb_ctx *nb, const char *ref) {
    void *r = ir_resolve_ix(ref);
    if(r) {
        int ix = ir_ix_of(r);
        if(ix >= 0 && ix < nb->n && nb->c < nb->cap) nb->out[nb->c++] = ix;
    }
}

/* emit neighbor indices of node t into out (cap n); returns count */
static int
ir_neighbors(void *t, int *out, int cap) {
    int n = go_flat_ir_n_types();
    ir_nb_ctx nb = { out, n, cap, 0 };
    if(go_flat_ir_is_alias(t)) {
        ir_nb_add(&nb, go_flat_ir_alias_of(t));
        return nb.c;
    }
    if(go_flat_ir_is_seqof(t)) {
        if(!go_flat_ir_elem_prim(t))
            ir_nb_add(&nb, go_flat_ir_elem(t));
        return nb.c;
    }
    if(go_flat_ir_is_leaf(t)) return nb.c;
    int nm = go_flat_ir_members(t);
    for(int i = 0; i < nm; i++) {
        void *m = go_flat_ir_member(t, i);
        if(go_flat_ir_member_is_ref(m)) {
            ir_nb_add(&nb, go_flat_ir_member_ref(m));
        } else if(go_flat_ir_member_is_nested(m)) {
            int nix = go_flat_ir_member_nested_ix(m);
            void *nw = (nix >= 0 && nix < n) ? go_flat_ir_type(nix) : NULL;
            if(!nw) continue;
            /* the nested-wrapper edge itself: the OWNER converter runs the
             * wrapper's conversion inline (an SCC edge owner→wrapper; without
             * it a wrapper embedded in a cycle looks acyclic — the
             * ranParameter-Testing inline CHOICE case found by convconf) */
            if(nb.c < nb.cap) nb.out[nb.c++] = nix;
            if(go_flat_ir_is_seqof(nw)) {
                if(!go_flat_ir_elem_prim(nw))
                    ir_nb_add(&nb, go_flat_ir_elem(nw));
            } else {
                /* wrapper: recurse on its member shape inline (depth 2 is
                 * the deepest the walk mints: value-union alt rows and the
                 * inline-CHOICE under a wrapper; each wrapper member is
                 * ref/prim/nested-seqof only) */
                int wnm = go_flat_ir_members(nw);
                for(int wi = 0; wi < wnm; wi++) {
                    void *wm = go_flat_ir_member(nw, wi);
                    if(go_flat_ir_member_is_ref(wm)) {
                        ir_nb_add(&nb, go_flat_ir_member_ref(wm));
                    } else if(go_flat_ir_member_is_nested(wm)) {
                        int wx = go_flat_ir_member_nested_ix(wm);
                        void *ww = (wx >= 0 && wx < n) ? go_flat_ir_type(wx) : NULL;
                        if(ww && go_flat_ir_is_seqof(ww)
                           && !go_flat_ir_elem_prim(ww))
                            ir_nb_add(&nb, go_flat_ir_elem(ww));
                    }
                }
            }
        }
    }
    return nb.c;
}

/* DFS: does `from` reach `target` through >=1 edge? (visited[] guards) */
static int
 reaches(int from, int target, char *visited, int depth) {
    if(depth > 512) return 0;   /* cycle through non-target nodes: no gain */
    int n = go_flat_ir_n_types();
    int *nb = malloc((size_t)(n > 0 ? n : 1) * sizeof(int));
    if(!nb) { conv_failed_set(); return 0; }
    int c = ir_neighbors(go_flat_ir_type(from), nb, n);
    int hit = 0;
    for(int i = 0; i < c && !hit; i++) {
        int w = nb[i];
        if(w == target) { hit = 1; break; }
        if(visited[w]) continue;
        visited[w] = 1;
        hit = reaches(w, target, visited, depth + 1);
    }
    free(nb);
    return hit;
}

int
conv_is_scc(const void *t) {
    static char *scc_flag = NULL;
    static int *scc_ix = NULL;
    static int scc_n = 0;
    int n = go_flat_ir_n_types();
    if(n != scc_n || !scc_flag) {
        free(scc_flag); free(scc_ix);
        scc_flag = calloc((size_t)(n > 0 ? n : 1), 1);
        scc_ix = calloc((size_t)(n > 0 ? n : 1), sizeof(int));
        if(!scc_flag || !scc_ix) { conv_failed_set(); return 0; }
        scc_n = n;
        /* a node is SCC iff it reaches itself (>=1 edge). Do it once,
         * memoized per IR index. */
        for(int v = 0; v < n; v++) {
            char *visited = calloc((size_t)(n > 0 ? n : 1), 1);
            if(!visited) { conv_failed_set(); return 0; }
            visited[v] = 1;   /* the target itself may be re-entered; the
                                 neighbor loop checks w==target first */
            scc_ix[v] = reaches(v, v, visited, 0);
            free(visited);
        }
    }
    int ix = -1;
    for(int i = 0; i < n; i++)
        if(go_flat_ir_type(i) == (flat_type *)t) { ix = i; break; }
    if(ix < 0) return 0;
    return scc_ix[ix];
}

/* ---------------------------------------------------------------------------
 * Per-node body emission: _to_tree (this TU) — continued below.
 * ------------------------------------------------------------------------- */

/* tree-side scalar ctype of a Flat prim token, as the emitted casts need it:
 * int64/int32 (NativeInteger/ENUM) -> long; uint64 -> unsigned long/long per
 * the comparison set' member casts; double -> double. */
static const char *
tree_scalar(const char *prim) {
    if(prim && strcmp(prim, "double") == 0) return "double";
    if(prim && strcmp(prim, "_bool32") == 0) return "BOOLEAN_t";
    if(prim && strcmp(prim, "uint64_t") == 0) return "unsigned long";
    /* BOOLEAN mapping row: the tree member is BOOLEAN_t (int), not long. An
     * INT32 prim here is a BOOLEAN leaf or an ENUM inline member; ENUM tree
     * members are long (NativeInteger) — distinguish by the FLAT-vs-tree
     * context at the call sites (this helper only serves BOOLEAN leaves). */
    return "long";
}

/* FT_NESTED member arm: the member's nested node under token <tok>.
 *   seqof wrapper       -> SEQ OF loop (to_tree template): items calloc + ASN_SEQUENCE_ADD
 *                          onto out-><tok>.list, ASN_STRUCT_FREE on both
 *                          failure paths (comparison shape)
 *   struct/choice w.    -> descend one accessor level (in-><tok> / out-><tok>)
 *                          over the wrapper's members; a CHOICE wrapper emits
 *                          its own switch (nested CHOICE under a member)
 * Wrapper slots are never starred on the Flat side except the inline
 * SEQ OF/CHOICE under OPTIONAL (stars=1 -> calloc wrapper first). */
static char *
arm_nested_to(void *t, void *m, const char *in_acc, const char *out_acc);

/* CHOICE body switch emitter (a CHOICE node OR a nested CHOICE wrapper with
 * is_choice). `in_sel`/`out_sel` = accessor of the CHOICE holder ("in" for
 * a node; "in-><tok>" for a nested wrapper). PR token base = the CHOICE
 * node's tree base. */
static char *choice_switch_to_deref(void *t, const char *in_sel,
                                    const char *out_sel, const char *deref);
static char *
choice_switch_to(void *t, const char *in_sel, const char *out_sel) {
    return choice_switch_to_deref(t, in_sel, out_sel, "->");
}

/* deref = the accessor suffix for descending INTO the CHOICE holder: "."
 * for an inline (by-value) wrapper slot, "->" for the node level and a
 * calloc'd (starred) wrapper slot (the comparison set: a node's in->present /
 * an inline wrapper's in->value.present). */
static char *
choice_switch_to_deref(void *t, const char *in_sel, const char *out_sel,
                       const char *deref) {
    char *label = conv_type_label(t);   /* td->name display label */
    char *prbase = conv_tree_base(t);   /* <P><X>_PR enum base (prefixed) */
    char *s = cstrdup("");
    /* present assignments */
    { char *_cf = cfmt("    %s%spresent = (%s_PR)%s%spresent;\n", out_sel, deref, prbase, in_sel, deref); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    switch (%s%spresent) {\n", in_sel, deref); s = ca(s, _cf); free(_cf); }
    int nm = go_flat_ir_members(t);
    for(int i = 0; i < nm; i++) {
        void *mtmp = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(mtmp);
        char *mlab = conv_member_label(mtmp);   /* display label */
        if(strcmp(tok, "present") == 0) { free(mlab); continue; }
        char *pr = cfmt("%s_PR_%s", prbase, tok);
        int stars = go_flat_ir_member_stars(mtmp);
        /* NULL alt carries no slot, no arm work — bare break. */
        if(conv_is_null_alt(go_flat_ir_cid(t), tok)) {
            { char *_cf = cfmt("    case %s:\n", pr); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        break;   /* NULL alt carries no slot */\n");
            free(pr); free(mlab);
            continue;
        }
        if(go_flat_ir_member_is_prim(mtmp)) {
            const char *prim = go_flat_ir_member_prim(mtmp);
            { char *_cf = cfmt("    case %s:\n", pr); s = ca(s, _cf); free(_cf); }
            if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
                { char *_cf = cfmt("        if (%s%s%s.len) {\n", in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s%schoice.%s.buf = (uint8_t *)asn1cgo_calloc(1, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s%schoice.%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s%schoice.%s.buf, %s%s%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        }\n");
                { char *_cf = cfmt("        %s%schoice.%s.size = (int)%s%s%s.len;\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
                { char *_cf = cfmt("        if (%s%s%s.len) {\n", in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s%schoice.%s.buf = (uint8_t *)asn1cgo_calloc(1, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s%schoice.%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s%schoice.%s.buf, %s%s%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        }\n");
                { char *_cf = cfmt("        %s%schoice.%s.size = (int)%s%s%s.len;\n        %s%schoice.%s.bits_unused = (int)%s%s%s.bits_unused;\n", out_sel, deref, tok, in_sel, deref, tok, out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            } else {
                /* inline scalar alt slot: by value (leaf CHOICEs are all
                 * inline; long/int32/double) */
                const char *ct = tree_scalar(prim);
                { char *_cf = cfmt("        %s%schoice.%s = (%s)%s%s%s;\n", out_sel, deref, tok, ct, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            }
            s = ca(s, "        break;\n");
            free(pr); free(mlab);
            continue;
        }
        /* ref alt (or nested alt): an inline slot carries the alt by value;
         * a pointer slot callocs (the to_tree CHOICE pointer-alt rule =
         * OPTIONAL alloc). */
        const char *ref = go_flat_ir_member_ref(mtmp);
        void *r = go_flat_ir_member_is_ref(mtmp) && ref
                       ? ir_resolve_ix(ref) : NULL;
        if(!r && !go_flat_ir_member_is_nested(mtmp)) {
            fprintf(stderr, "asn1cgo: conv: choice alt %s of %s unresolved\n",
                    tok, label);
            conv_failed_set();
            free(pr); free(mlab);
            continue;
        }
        char *rb = r ? conv_tree_base(r) : cstrdup("");
        { char *_cf = cfmt("    case %s:\n", pr); s = ca(s, _cf); free(_cf); }
        if(stars) {
            if(!r || !*rb) {
                { char *_cf = cfmt("        if (!%s%s%s) return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"alt NULL\");\n", in_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
            }
            { char *_cf = cfmt("        %s%schoice.%s = asn1cgo_calloc(1, sizeof(*%s%schoice.%s));\n", out_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s%schoice.%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && r && conv_is_scc(r)) {
                /* the arm declares no local (an unbraced switch arm cannot:
                 * a second guarded arm in the same switch would redeclare);
                 * guard, call, decrement, test inline */
                s = ca(s, "        if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s_to_tree(%s%s%s, %s%schoice.%s, err)) { err->depth--; return err->code; }\n", rb, in_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        err->depth--;\n");
            } else {
                { char *_cf = cfmt("        if (%s_to_tree(%s%s%s, %s%schoice.%s, err)) return err->code;\n", rb, in_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            }
        } else {
            if(r && conv_is_wide(go_flat_ir_cid(r))) {
                /* wide-INTEGER inline alt (native Flat width) */
                { char *_cf = cfmt("        if (asn_umax2INTEGER((INTEGER_t *)&%s%schoice.%s, (uintmax_t)%s%s%s) != 0)\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", \"asn_umax2INTEGER failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
            } else if(r && go_flat_ir_is_leaf(r)) {
                /* an inline leaf alt reference (scalar leaf): by value */
                const char *prim = go_flat_ir_prim(r);
                const char *ct = tree_scalar(prim);
                if(prim && strcmp(prim, "uint64_t") == 0) ct = "unsigned long";
                if(prim && (strcmp(prim, "asn1cgo_bytes_flat") == 0
                            || strcmp(prim, "asn1cgo_bits_flat") == 0)) {
                    { char *_cf = cfmt("        if (%s%s%s.len) {\n", in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            %s%schoice.%s.buf = (uint8_t *)asn1cgo_calloc(1, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            if (!%s%schoice.%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            memcpy(%s%schoice.%s.buf, %s%s%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    s = ca(s, "        }\n");
                    if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0)
                        { char *_cf = cfmt("        %s%schoice.%s.bits_unused = (int)%s%s%s.bits_unused;\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("        %s%schoice.%s.size = (int)%s%s%s.len;\n", out_sel, deref, tok, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                } else {
                    { char *_cf = cfmt("        %s%schoice.%s = (%s)%s%s%s;\n", out_sel, deref, tok, ct, in_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                }
            } else {
                if(r && conv_is_scc(t) && conv_is_scc(r)) {
                    /* depth guard: a by-value CHOICE alt into a recursion-SCC type
                     * (the whole E2SM-RC ranParameter-Testing graph); guard
                     * the entry, call, decrement, test inline. */
                    { char *_cf = cfmt("        if (++err->depth > ASN1CGO_MAX_DEPTH) return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("        int itrc = %s_to_tree(&%s%s%s, &%s%schoice.%s, err);\n", rb, in_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    s = ca(s, "        err->depth--;\n");
                    s = ca(s, "        if (itrc) return err->code;\n");
                } else {
                    { char *_cf = cfmt("        if (%s_to_tree(&%s%s%s, &%s%schoice.%s, err)) return err->code;\n", rb, in_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                }
            }
        }
        s = ca(s, "        break;\n");
        free(rb); free(pr); free(mlab);
    }
    /* NULL alts carry no union slot and thus no IR member row: emit
     * their bare-break arms from the recorded null-alt list, in walk order,
     * after every slot-bearing arm and before the NOTHING arm (a selected
     * NULL alt must not fall to BAD). */
    {
        extern conv_null_alt *g_conv_nullalts;
        extern int g_conv_n_nullalts;
        for(int i = 0; i < g_conv_n_nullalts; i++) {
            if(!conv_cid_eq(g_conv_nullalts[i].node_cid, go_flat_ir_cid(t))) continue;
            { char *_cf = cfmt("    case %s_PR_%s:\n", prbase,
                           g_conv_nullalts[i].alt_token); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        break;\n");
        }
    }
    { char *_cf = cfmt("    case %s_PR_NOTHING:\n", prbase); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    default:\n");
    { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_CHOICE_BAD, \"%s\", NULL, \"present=%%d\", (int)%s%spresent);\n", label, in_sel, deref); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    }\n");
    free(prbase); free(label);
    return s;
}

/* The child converter fn base of a REF member: the resolved target's tree
 * base; when the target is unresolvable (should never happen — the layout
 * pass fails first), fall back to the ref text. */
static char *
ref_conv_fn(const char *ref, const char *label, const char *tok) {
    void *r = ir_resolve_ix(ref);
    char *b = r ? conv_tree_base(r) : NULL;
    if(!b || !*b) {
        fprintf(stderr, "asn1cgo: conv: unresolved ref %s at %s.%s\n",
                ref ? ref : "?", label ? label : "?", tok ? tok : "?");
        conv_failed_set();
        return cstrdup("");
    }
    return b;
}

/* struct_members_to (defined after arm_nested_to — they nest into each
 * other through wrapper members). */
static char *struct_members_to(void *t, const char *in_acc, const char *out_acc);

/* IOC dispatch node body (the IOC rule; defined after node_to_body's section). */
static char *ioc_node_to_body(void *t);

/* ---- leaf node ------------------------------------------------------------ */
static char *
leaf_to_body(void *t, const char *label) {
    const char *prim = go_flat_ir_prim(t);
    if(conv_is_wide(go_flat_ir_cid(t))) {
        /* wide INTEGER: bare INTEGER_t leaf (uint64/int64 native). */
        char *s = cfmt(
            "    if (asn_umax2INTEGER((INTEGER_t *)out, (uintmax_t)*in) != 0)\n"
            "        return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, \"asn_umax2INTEGER failed\");\n", label);
        return s;
    }
    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
        return cfmt(
            "    {\n"
            "        const asn1cgo_bytes_flat *b = (const asn1cgo_bytes_flat *)in;\n"
            "        OCTET_STRING_t *o = (OCTET_STRING_t *)out;\n"
            "        if (b->len) {\n"
            "            o->buf = (uint8_t *)asn1cgo_calloc(1, b->len);\n"
            "            if (!o->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, \"calloc bytes (%%zu)\", b->len);\n"
            "            memcpy(o->buf, b->buf, b->len);\n"
            "        }\n"
            "        o->size = (int)b->len;\n"
            "    }\n", label);
    }
    if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
        return cfmt(
            "    {\n"
            "        const asn1cgo_bits_flat *b = (const asn1cgo_bits_flat *)in;\n"
            "        BIT_STRING_t *o = (BIT_STRING_t *)out;\n"
            "        if (b->len) {\n"
            "            o->buf = (uint8_t *)asn1cgo_calloc(1, b->len);\n"
            "            if (!o->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, \"calloc bits (%%zu)\", b->len);\n"
            "            memcpy(o->buf, b->buf, b->len);\n"
            "        }\n"
            "        o->size = (int)b->len;\n"
            "        o->bits_unused = (int)b->bits_unused;\n"
            "    }\n", label);
    }
    /* an inline SEQUENCE OF element leaf knows its exact C tree type (long,
     * unsigned long, BOOLEAN_t, NULL_t, double): store through it, so a
     * 4-byte BOOLEAN_t / NULL_t slot is never written as a long. */
    if(go_flat_ir_inline_elem(t) && go_flat_ir_tree_ctype(t)) {
        const char *ct = go_flat_ir_tree_ctype(t);
        if(strcmp(ct, "NULL_t") == 0)
            return cstrdup("    (void)in;\n    *(NULL_t *)out = 0;\n");
        return cfmt("    *(%s *)out = (%s)*in;\n", ct, ct);
    }
    /* native scalar leaf (bare typedef): int64/uint64 -> long, int32
     * (enum) -> long, double -> double. */
    if(prim && strcmp(prim, "double") == 0)
        return cstrdup("    *(double *)out = (double)*in;\n");
    return cstrdup("    *(long *)out = (long)*in;\n");
}

/* ---- struct member arms --------------------------------------------------- */

/* Receiver contract — one comment per arm kind, stated once
 * here for this family): every receiver operand the arms emit is an LVALUE
 * ACCESS expression ("in->tok", "out->tok", "in->tok.inner" — the Flat-side
 * verbatim member tokens). Address-of (&) attaches at CALL BOUNDARIES only (a child
 * converter's by-value args, "&in->tok, &out->tok"); storage access within
 * an arm dereferences through the access expression itself. Pointer-slot
 * members (stars=1) pass the pointer VALUE — never &-of-pointer. */

/* FT_PRIM member arm — accessor strings are precomposed by the caller
 * (in_acc/out_acc, e.g. "in->tok" / "out->tok" or a nested-wrapper path). */
static char *
arm_prim_to(void *t, void *m, const char *in_acc, const char *out_acc) {
    const char *prim = go_flat_ir_member_prim(m);
    char *mlab = conv_member_label(m);   /* display label (fail args;
                                          * token accessors go through
                                          * in_acc/out_acc — no tok needed) */
    int stars = go_flat_ir_member_stars(m);
    char *label = conv_type_label(t);
    char *s = cstrdup("");
    if(stars) {
        /* OPTIONAL scalar member (the to_tree OPTIONAL rule): calloc then
         * copy. An
         * OPTIONAL OCTET/BIT STRING member's Flat slot is a pointer to the
         * bytes/bits struct (NULL = absent) — calloc the tree's
         * OCTET_STRING_t/BIT_STRING_t slot and copy (the to_tree OCTET
         * STRING rule). */
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s->len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            %s->buf = (uint8_t *)asn1cgo_calloc(1, %s->len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!%s->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            memcpy(%s->buf, %s->buf, %s->len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        }\n        %s->size = (int)%s->len;\n    }\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s->len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            %s->buf = (uint8_t *)asn1cgo_calloc(1, %s->len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!%s->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            memcpy(%s->buf, %s->buf, %s->len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        }\n        %s->size = (int)%s->len;\n        %s->bits_unused = (int)%s->bits_unused;\n    }\n", out_acc, in_acc, out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "uint64_t") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        *%s = (unsigned long)*%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "    }\n");
        } else {
            const char *ct = tree_scalar(prim);
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        *%s = (%s)*%s;\n", out_acc, ct, in_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "    }\n");
        }
        free(mlab); free(label);
        return s;
    }
    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
        { char *_cf = cfmt("    if (%s.len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_calloc(1, %s.len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    }\n");
        { char *_cf = cfmt("    %s.size = (int)%s.len;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
        { char *_cf = cfmt("    if (%s.len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_calloc(1, %s.len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    }\n");
        { char *_cf = cfmt("    %s.size = (int)%s.len;\n    %s.bits_unused = (int)%s.bits_unused;\n", out_acc, in_acc, out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "double") == 0) {
        { char *_cf = cfmt("    %s = (double)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "uint64_t") == 0) {
        { char *_cf = cfmt("    %s = (unsigned long)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else {
        { char *_cf = cfmt("    %s = (%s)%s;\n", out_acc, tree_scalar(prim), in_acc); s = ca(s, _cf); free(_cf); }
    }
    free(mlab); free(label);
    return s;
}

/* FT_REF member arm. The target drives the shape:
 *   wide leaf  -> wide-INTEGER verb pair (calloc ptr if OPTIONAL)
 *   bytes/bits leaf -> inline copy (to_tree OCTET/BIT STRING rule) (+ ptr OPTIONAL)
 *   scalar leaf -> scalar copy (+ ptr OPTIONAL)
 *   constructed (struct/choice/seqof/alias) -> child call
 *       pointer slot (stars)  : OPTIONAL-template calloc + call
 *       inline slot (no stars): direct byvalue call
 * Depth guard: when the EDGE target is an SCC member and the caller
 * node is an SCC member, the call carries the guard (the comparison set's call-site
 * form). */
static char *
arm_ref_to(void *t, void *m, const char *in_acc, const char *out_acc) {
    char *mlab = conv_member_label(m);   /* display label (fail args) */
    const char *ref = go_flat_ir_member_ref(m);
    int stars = go_flat_ir_member_stars(m);
    void *r = ir_resolve_ix(ref);
    char *label = conv_type_label(t);
    char *s = cstrdup("");
    if(!r) {
        fprintf(stderr, "asn1cgo: conv: unresolved ref %s at %s\n",
                ref ? ref : "?", label);
        conv_failed_set();
        free(mlab); free(label);
        return s;
    }
    char *rb = conv_tree_base(r);
    char *rflat = conv_flat_name(r);
    int t_scc = conv_is_scc(t);
    int r_scc = conv_is_scc(r);

    if(go_flat_ir_is_leaf(r)) {
        const char *prim = go_flat_ir_prim(r);
        if(conv_is_wide(go_flat_ir_cid(r))) {
            /* wide INTEGER ref (leaf INTEGER_t; OPTIONAL = ptr star) */
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (asn_umax2INTEGER((INTEGER_t *)%s, (uintmax_t)*%s) != 0)\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", \"asn_umax2INTEGER failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
            } else {
                { char *_cf = cfmt("    if (asn_umax2INTEGER((INTEGER_t *)&%s, (uintmax_t)%s) != 0)\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", \"asn_umax2INTEGER failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
            }
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            /* inline bytes leaf reference: the tree member IS an
             * OCTET_STRING_t; copy in place (a starred slot callocs it). */
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s->len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s->buf = (uint8_t *)asn1cgo_calloc(1, %s->len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s->buf, %s->buf, %s->len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        }\n");
                { char *_cf = cfmt("        %s->size = (int)%s->len;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
            } else {
                { char *_cf = cfmt("    if (%s.len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_calloc(1, %s.len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
                { char *_cf = cfmt("    %s.size = (int)%s.len;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s->len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s->buf = (uint8_t *)asn1cgo_calloc(1, %s->len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s->buf, %s->buf, %s->len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        }\n");
                { char *_cf = cfmt("        %s->size = (int)%s->len;\n        %s->bits_unused = (int)%s->bits_unused;\n", out_acc, in_acc, out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
            } else {
                { char *_cf = cfmt("    if (%s.len) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_calloc(1, %s.len);\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
                { char *_cf = cfmt("    %s.size = (int)%s.len;\n    %s.bits_unused = (int)%s.bits_unused;\n", out_acc, in_acc, out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            }
        } else {
            /* scalar leaf reference: the tree member is the scalar itself
             * (long/int32/double); a named leaf typedef on the Flat side. */
            if(stars) {
                const char *ct = tree_scalar(prim);
                if(prim && strcmp(prim, "uint64_t") == 0) ct = "unsigned long";
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        *%s = (%s)*%s;\n", out_acc, ct, in_acc); s = ca(s, _cf); free(_cf); }
                s = ca(s, "    }\n");
            } else {
                const char *ct = tree_scalar(prim);
                if(prim && strcmp(prim, "uint64_t") == 0) ct = "unsigned long";
                { char *_cf = cfmt("    %s = (%s)%s;\n", out_acc, ct, in_acc); s = ca(s, _cf); free(_cf); }
            }
        }
        free(mlab); free(rb); free(rflat); free(label);
        return s;
    }

    /* constructed target: a NAMED SEQUENCE OF reference member delegates
     * to the named type's own converter (the to_tree nested-member template:
     * X_to_tree(&in->m, &out->m, err) — the reference names a top-level
     * type assignment whose conv pair is emitted; inlining its loop here
     * would duplicate that converter). ANONYMOUS inline SEQ-OF members ride
     * arm_nested_to's inline loop instead (no named conv exists for them).
     * The generic child-call tail below handles this case unchanged. */

    /* constructed target: child converter call */
    int guarded = t_scc && r_scc;   /* an edge inside the recursion SCC */
    if(stars) {
        { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        if(guarded) {
            s = ca(s, "        if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
            { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        int rc = %s_to_tree(%s, %s, err);\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        err->depth--;\n");
            s = ca(s, "        if (rc) return err->code;\n");
        } else {
            { char *_cf = cfmt("        if (%s_to_tree(%s, %s, err)) return err->code;\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        }
        s = ca(s, "    }\n");
    } else {
        /* inline slot: NON-OPTIONAL but possibly a POINTER tree member
         * (EXPLICIT-tag recursion break — in->tok is a pointer; out->tok is
         * calloc'd by this arm) is carried as stars=1 above; a true inline
         * by-value call needs no alloc. But a NON-OPTIONAL EXPLICIT member
         * whose Flat slot is a POINTER (in->%s non-NULL when present —
         * always) is stars=1. Here: plain by-value child call — receivers
         * are lvalue accesses ("in->tok"/"out->tok"); & attaches at this
         * call boundary only. */
        if(guarded) {
            char *root_label = label;
            /* the guard labels the SCC root (the comparison units label the ROOT
             * type, not the member owner, when the edge returns to it) */
            s = ca(s, "    if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
            { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", root_label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("    int rc = %s_to_tree(&%s, &%s, err);\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "    err->depth--;\n");
            s = ca(s, "    if (rc) return err->code;\n");
        } else {
            { char *_cf = cfmt("    if (%s_to_tree(&%s, &%s, err)) return err->code;\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        }
    }
    free(mlab); free(rb); free(rflat); free(label);
    return s;
}

/* FT_NESTED member arm implementation (declared above choice_switch_to).
 * struct_members_to is defined below (mutual recursion via prototype). */
static char *
arm_nested_to(void *t, void *m, const char *in_acc, const char *out_acc) {
    const char *tok = go_flat_ir_member_token(m);
    char *mlab = conv_member_label(m);   /* display label (fail args) */
    int stars = go_flat_ir_member_stars(m);
    int nix = go_flat_ir_member_nested_ix(m);
    void *n = (nix >= 0 && nix < go_flat_ir_n_types())
                  ? go_flat_ir_type(nix) : NULL;
    char *label = conv_type_label(t);
    char *s = cstrdup("");
    if(!n) {
        fprintf(stderr, "asn1cgo: conv: bad nested ix at %s.%s\n", label, mlab);
        conv_failed_set();
        free(mlab); free(label);
        return s;
    }
    char *in_sel = cfmt("%s%s", in_acc, tok);
    char *out_sel = cfmt("%s%s", out_acc, tok);
    if(go_flat_ir_is_seqof(n)) {
        /* {items,count} wrapper: SEQ-OF loop onto the .h's nested list. The
         * tree list accessor: out_sel->list (the .h nests an anonymous
         * A_SEQUENCE_OF wrapper under the same token). */
        const char *elem = go_flat_ir_elem(n);
        if(go_flat_ir_elem_prim(n)) {
            fprintf(stderr,
                    "asn1cgo: conv: SEQUENCE (OF primitive %s) at %s.%s has "
                    "no authored template (fail loud)\n",
                    elem ? elem : "?", label, mlab);
            conv_failed_set();
        }
        void *rt = ir_resolve_ix(elem);
        char *rb = rt ? conv_tree_base(rt) : NULL;
        char *rflat = rt ? conv_flat_name(rt) : NULL;
        if(!rb || !*rb) {
            fprintf(stderr, "asn1cgo: conv: unresolved seqof elem %s at %s\n",
                    elem ? elem : "?", label);
            conv_failed_set();
            free(mlab); free(label); free(in_sel); free(out_sel);
            return s;
        }
        const int inl = rt && go_flat_ir_inline_elem(rt);
        char *frs = inl ? cstrdup("") : cfmt("ASN_STRUCT_FREE(asn_DEF_%s, item); ", rb);
        if(stars) {
            /* OPTIONAL inline SEQ OF: the Flat side carries *{items,count};
             * calloc the tree wrapper, loop into it. */
            { char *_cf = cfmt("    if (%s) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_sel, out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        for (size_t i = 0; i < %s->count; i++) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            %s_t *item = asn1cgo_calloc(1, sizeof(*item));\n", rb); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!item) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            if(inl) { char *_cf = cfmt("            if (ASN_SEQUENCE_ADD(&%s->list, item) != 0) { free(item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL); }\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt)) {
                /* depth guard: guard, call, decrement, test inline (the depth must
                 * NOT leak past the loop iteration) */
                { char *_cf = cfmt("            if (++err->depth > ASN1CGO_MAX_DEPTH) { %sreturn asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH); }\n", frs, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            int itrc = %s_to_tree(&%s->items[i], item, err);\n", rb, in_sel); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (itrc) { %sreturn err->code; }\n", frs); s = ca(s, _cf); free(_cf); }
            } else {
                { char *_cf = cfmt("            if (%s_to_tree(&%s->items[i], item, err)) { %sreturn err->code; }\n", rb, in_sel, frs); s = ca(s, _cf); free(_cf); }
            }
            if(!inl) { char *_cf = cfmt("            if (ASN_SEQUENCE_ADD(&%s->list, item) != 0) { ASN_STRUCT_FREE(asn_DEF_%s, item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL); }\n", out_sel, rb, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt))
                s = ca(s, "            err->depth--;\n");
            s = ca(s, "        }\n    }\n");
        } else {
            { char *_cf = cfmt("    for (size_t i = 0; i < %s.count; i++) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s_t *item = asn1cgo_calloc(1, sizeof(*item));\n", rb); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!item) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            if(inl) { char *_cf = cfmt("        if (ASN_SEQUENCE_ADD(&%s.list, item) != 0) { free(item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL); }\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt)) {
                /* depth guard: guard, call, decrement, test inline (mirror of the
                 * starred form; no depth leak past the iteration) */
                { char *_cf = cfmt("        if (++err->depth > ASN1CGO_MAX_DEPTH) { %sreturn asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH); }\n", frs, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        int itrc = %s_to_tree(&%s.items[i], item, err);\n", rb, in_sel); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (itrc) { %sreturn err->code; }\n", frs); s = ca(s, _cf); free(_cf); }
            } else {
                { char *_cf = cfmt("        if (%s_to_tree(&%s.items[i], item, err)) { %sreturn err->code; }\n", rb, in_sel, frs); s = ca(s, _cf); free(_cf); }
            }
            if(!inl) { char *_cf = cfmt("        if (ASN_SEQUENCE_ADD(&%s.list, item) != 0) { ASN_STRUCT_FREE(asn_DEF_%s, item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL); }\n", out_sel, rb, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt))
                s = ca(s, "        err->depth--;\n");
            s = ca(s, "    }\n");
        }
        free(frs);
        free(rb); free(rflat);
    } else if(go_conv_ir_is_choice(n)) {
        /* nested CHOICE wrapper: present + inline alt slots under <tok>.
         * in_sel/out_sel are accessors ending in the token (e.g.
         * "in->tok"); the switch composes "%s->..." on them — pass the
         * pointer-deref form (an extra deref level: the wrapper rides a
         * pointer in the tree). For a starred wrapper the Flat operand is
         * the pointer itself. */
        if(stars) {
            /* OPTIONAL nested CHOICE (Flat carries *wrapper): calloc the
             * tree wrapper, then switch through both pointers. */
            { char *_cf = cfmt("    if (%s) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_sel, out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            {
                char *sw = choice_switch_to(n, in_sel, out_sel);
                s = ca(s, sw);
                free(sw);
            }
            s = ca(s, "    }\n");
        } else {
            /* INLINE wrapper: the slot is the wrapper VALUE — accessors
             * compose '.' into it (the comparison units' in->value.present form). */
            char *sw = choice_switch_to_deref(n, in_sel, out_sel, ".");
            s = ca(s, sw);
            free(sw);
        }
    } else {
        /* nested struct wrapper (an inline SEQUENCE / the open-type value
         * union's struct): descend accessor level over its members. */
        if(stars) {
            { char *_cf = cfmt("    if (%s) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = asn1cgo_calloc(1, sizeof(*%s));\n", out_sel, out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            /* the calloc'd slot is a POINTER — descend with '->' */
            char *in_pfx = cfmt("%s->", in_sel);
            char *out_pfx = cfmt("%s->", out_sel);
            char *body = struct_members_to(n, in_pfx, out_pfx);
            s = ca(s, body);
            free(body); free(in_pfx); free(out_pfx);
            s = ca(s, "    }\n");
        } else {
            /* INLINE wrapper: descend with '.' (the comparison units' in->value.id
             * form — the tree nests the wrapper by value). */
            char *in_pfx = cfmt("%s.", in_sel);
            char *out_pfx = cfmt("%s.", out_sel);
            char *body = struct_members_to(n, in_pfx, out_pfx);
            s = ca(s, body);
            free(body); free(in_pfx); free(out_pfx);
        }
    }
    free(mlab); free(label); free(in_sel); free(out_sel);
    return s;
}

/* Walk one struct-like node's members, emitting an arm per member with the
 * given accessor prefixes ("" = node-level "in"/"out"). */
static char *
struct_members_to(void *t, const char *in_acc, const char *out_acc) {
    char *s = cstrdup("");
    int nm = go_flat_ir_members(t);
    for(int i = 0; i < nm; i++) {
        void *m = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(m);
        char *ia = cfmt("%s%s", in_acc, tok);
        char *oa = cfmt("%s%s", out_acc, tok);
        char *body = NULL;
        if(go_flat_ir_member_is_default(m) && go_flat_ir_member_tree_ptr(m)) {
            /* DEFAULT member whose C tree slot is a pointer: the Flat slot
             * is by value, so allocate the tree slot and fill it through the
             * dereference (the decoder/encoder callbacks expect the pointer
             * form; the C encoder decides whether to omit it). */
            char *ml = conv_member_label(m), *tl = conv_type_label(t);
            char *pre = cfmt(
                "    %s = asn1cgo_calloc(1, sizeof(*%s));\n"
                "    if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n",
                oa, oa, oa, tl, ml);
            free(oa);
            oa = cfmt("(*%s%s)", out_acc, tok);
            body = go_flat_ir_member_is_prim(m) ? arm_prim_to(t, m, ia, oa)
                                                : arm_ref_to(t, m, ia, oa);
            { char *j = ca(pre, body); free(body); body = j; }
            free(ml); free(tl);
        } else if(go_flat_ir_member_is_prim(m)) {
            body = arm_prim_to(t, m, ia, oa);
        } else if(go_flat_ir_member_is_ref(m)) {
            body = arm_ref_to(t, m, ia, oa);
        } else {
            body = arm_nested_to(t, m, in_acc, out_acc);
        }
        s = ca(s, body);
        free(body); free(ia); free(oa);
    }
    return s;
}

/* ---------------------------------------------------------------------------
 * Node-level to_tree body: kind dispatch (leaf/alias/seqof/struct/choice).
 * ------------------------------------------------------------------------- */
static char *
node_to_body(void *t);

/* The public per-node to_body entry (go_entry.c's emit driver uses it). */
char *
node_to_body_pub(void *t) { return node_to_body(t); }

static char *
node_to_body(void *t) {
    char *label = conv_type_label(t);   /* td->name display label */
    char *s = cstrdup("");
    if(go_flat_ir_is_leaf(t)) {
        char *b = leaf_to_body(t, label);
        s = ca(s, b);
        free(b);
        free(label);
        return s;
    }
    if(go_flat_ir_is_alias(t)) {
        /* SingleContainer clone: call the target's converter on the same
         * value (the Flat alias is a bare typedef — same memory shape). */
        char *rb = ref_conv_fn(go_flat_ir_alias_of(t), label, "(alias)");
        { char *_cf = cfmt("    return %s_to_tree((const %s_flat *)in, (%s_t *)out, err);\n",
                       rb, rb, rb); s = ca(s, _cf); free(_cf); }
        free(rb);
        free(label);
        return s;
    }
    if(go_flat_ir_is_seqof(t)) {
        /* named SEQUENCE OF node: loop over in->items onto out->list */
        const char *elem = go_flat_ir_elem(t);
        if(go_flat_ir_elem_prim(t)) {
            fprintf(stderr,
                    "asn1cgo: conv: named SEQUENCE (OF primitive %s) %s has "
                    "no authored template (fail loud)\n",
                    elem ? elem : "?", label);
            conv_failed_set();
        }
        void *rt = ir_resolve_ix(elem);
        char *rb = rt ? conv_tree_base(rt) : NULL;
        if(!rb || !*rb) {
            fprintf(stderr, "asn1cgo: conv: unresolved seqof elem %s (%s)\n",
                    elem ? elem : "?", label);
            conv_failed_set();
            free(label);
            return s;
        }
        int scc_edge = rt && conv_is_scc(rt);
        /* an inline element type has no asn_DEF to free the item with: it is
         * attached to the list first, and an error leaves it to the tree's
         * own free (the caller frees the whole tree on failure). */
        const int inl = rt && go_flat_ir_inline_elem(rt);
        char *frs = inl ? cstrdup("") : cfmt("ASN_STRUCT_FREE(asn_DEF_%s, item); ", rb);
        { char *_cf = cfmt("    for (size_t i = 0; i < in->count; i++) {\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s_t *item = asn1cgo_calloc(1, sizeof(*item));\n", rb); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!item) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
        if(inl) { char *_cf = cfmt("        if (ASN_SEQUENCE_ADD(&out->list, item) != 0) { free(item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL); }\n", label); s = ca(s, _cf); free(_cf); }
        if(scc_edge) {
            /* depth guard: the loop edge re-enters the recursion SCC (the list's
             * element type is itself an SCC member) — guard each item. */
            { char *_cf = cfmt("        if (++err->depth > ASN1CGO_MAX_DEPTH) { %sreturn asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", NULL, \"depth > %%d\", ASN1CGO_MAX_DEPTH); }\n", frs, label); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        int itrc = %s_to_tree(&in->items[i], item, err);\n", rb); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        err->depth--;\n");
            { char *_cf = cfmt("        if (itrc) { %sreturn err->code; }\n", frs); s = ca(s, _cf); free(_cf); }
        } else {
            { char *_cf = cfmt("        if (%s_to_tree(&in->items[i], item, err)) { %sreturn err->code; }\n", rb, frs); s = ca(s, _cf); free(_cf); }
        }
        if(!inl) { char *_cf = cfmt("        if (ASN_SEQUENCE_ADD(&out->list, item) != 0) { ASN_STRUCT_FREE(asn_DEF_%s, item); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL); }\n", rb, label); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    }\n");
        free(frs);
        free(rb);
        free(label);
        return s;
    }
    /* struct/choice node */
    if(go_conv_ir_is_choice(t)) {
        char *sw = choice_switch_to(t, "in", "out");
        s = ca(s, sw);
        free(sw);
    } else if(conv_ioc_has(go_flat_ir_cid(t))) {
        /* IOC spec node: the value-union converter body (the IOC rule; the recorded
         * rows drive it; declared above (prototype not needed — defined
         * earlier in this TU than its use? no: it is defined BELOW; hoisted
         * via the prototype at the top of this emitter section). */
        char *b = ioc_node_to_body(t);
        s = ca(s, b);
        free(b);
    } else {
        char *b = struct_members_to(t, "in->", "out->");
        s = ca(s, b);
        free(b);
    }
    free(label);
    return s;
}

/* ---------------------------------------------------------------------------
 * IOC dispatch node body (the IOC rule; both dispatch forms). The recorded rows carry (id,
 * criticality, present, alt_token, alt_msg). One-to-one (no two rows share
 * alt_token) => present-authoritative (procedure-dispatch form); many-to-one (two ids
 * share an alt present slot) => id-authoritative (id-dispatch form, the IOC
 * dispatch rule).
 * ------------------------------------------------------------------------- */
static char *
ioc_node_to_body(void *t) {
    const char *cid = go_flat_ir_cid(t);
    char *label = conv_type_label(t);   /* td->name display label */
    char *s = cstrdup("");
    /* collect this spec node's rows */
    const conv_ioc_row *rows[256];
    int nrows = 0;
    for(int i = 0; i < g_conv_n_iocs && nrows < 256; i++)
        if(conv_cid_eq(g_conv_iocs[i].spec_cid, cid))
            rows[nrows++] = &g_conv_iocs[i];
    if(nrows == 0) {
        fprintf(stderr, "asn1cgo: conv: IOC node %s has no rows\n", label);
        conv_failed_set();
        free(label);
        return s;
    }
    /* one-to-one iff no two rows share alt_token (same present slot) */
    int one_to_one = 1;
    for(int i = 0; i < nrows && one_to_one; i++)
        for(int j = i + 1; j < nrows; j++)
            if(strcmp(rows[i]->alt_token, rows[j]->alt_token) == 0) {
                one_to_one = 0;
                break;
            }
    int is_env = rows[0]->is_envelope;
    const char *id_member = rows[0]->id_member;
    int has_crit = (rows[0]->crit_gov != NULL);   /* a class without a
                                                   * &criticality column has
                                                   * no criticality member
                                                   * on either side */
    char *tb_ = conv_tree_base(t);   /* prefixed base for the PR enum */
    char *prbase = cfmt("%s__value", tb_);   /* the __value PR enum base */

    /*
     * Flat shape of a spec node: {id/procedureCode, criticality, value{present, alts}}.
     * The flat value union wrapper is the member token "value" carrying the
     * nested value-union node; the tree nests struct <X>__value under
     * out->value with present + choice.<alt>.
     */
    if(one_to_one) {
        /* present-authoritative lookup: present -> (id/crit, alt) */
        { char *_cf = cfmt("    {\n"); s = ca(s, _cf); free(_cf); }
        /* an id outside the object set is IOC_UNKNOWN — checked BEFORE the
         * id-vs-present comparison, which reports IOC_MISMATCH (known id,
         * wrong alternative) */
        { char *_cf = cfmt("        switch (in->%s) {\n", id_member); s = ca(s, _cf); free(_cf); }
        for(int i = 0; i < nrows; i++) {
            int dupid = 0;
            for(int j = 0; j < i; j++)
                if(rows[j]->id == rows[i]->id) { dupid = 1; break; }
            if(dupid) continue;
            { char *_cf = cfmt("        case %ld:\n", rows[i]->id); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("            break;\n        default:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_IOC_UNKNOWN, \"%s\", \"%s\", \"unknown IE id=%%lld\", (long long)in->%s);\n        }\n",
                       label, id_member, id_member); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        int64_t want_id = 0;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        switch (in->value.present) {\n"); s = ca(s, _cf); free(_cf); }
        for(int i = 0; i < nrows; i++) {
            const conv_ioc_row *r = rows[i];
            { char *_cf = cfmt("        case (int32_t)%s_PR_%s:\n", prbase, r->alt_token); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            want_id = %ld; break;\n", r->id); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("        case 0:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        default:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_BAD, \"%s\", \"value\", \"present=%%d\", (int)in->value.present);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        }\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (in->%s != want_id)\n", id_member); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_IOC_MISMATCH, \"%s\", \"%s\", \"Flat=%%lld derived(from present)=%%lld\", (long long)in->%s, (long long)want_id);\n",
                       label, id_member, id_member); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        out->%s = (%s)want_id;\n", id_member, is_env ? "long" : "long"); s = ca(s, _cf); free(_cf); }
        if(has_crit)
        { char *_cf = cfmt("        out->criticality = (long)in->criticality;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        out->value.present = (%s_PR)in->value.present;\n", prbase); s = ca(s, _cf); free(_cf); }
        /* alt switch: build the selected alt into the union slot. The alt
         * payload's converter base is the PREFIXED cid (alt_msg, run-prefixed);
         * the flat member + tree union member carry the unprefixed token. */
        { char *_cf = cfmt("        switch (in->value.present) {\n"); s = ca(s, _cf); free(_cf); }
        for(int i = 0; i < nrows; i++) {
            const conv_ioc_row *r = rows[i];
            /* dedup alt arms (id-dispatch many-to-one: several ids share one alt —
             * one arm per present slot, not per row) */
            int dup = 0;
            for(int j = 0; j < i; j++)
                if(strcmp(rows[j]->alt_token, r->alt_token) == 0) { dup = 1; break; }
            if(dup) continue;
            const char *pfx = asn1c_prefix();
            const char *amsg = (r->alt_msg && *r->alt_msg) ? r->alt_msg
                                                           : r->alt_token;
            { char *_cf = cfmt("        case (int32_t)%s_PR_%s:\n", prbase, r->alt_token); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (%s%s_to_tree(&in->value.%s, &out->value.choice.%s, err)) return err->code;\n",
                           pfx ? pfx : "", amsg, r->alt_token, r->alt_token); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            break;\n"); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("        case (int32_t)%s_PR_NOTHING:\n", prbase); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        default:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_BAD, \"%s\", \"value\", \"present=%%d\", (int)in->value.present);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        }\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    }\n"); s = ca(s, _cf); free(_cf); }
    } else {
        /* many-to-one: id-authoritative (id-dispatch). */
        { char *_cf = cfmt("    {\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        int32_t want_pr = 0;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        switch (in->%s) {\n", id_member); s = ca(s, _cf); free(_cf); }
        for(int i = 0; i < nrows; i++) {
            const conv_ioc_row *r = rows[i];
            { char *_cf = cfmt("        case %ld:\n", r->id); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            want_pr = (int32_t)%s_PR_%s; break;\n",
                           prbase, r->alt_token); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("        default:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_IOC_UNKNOWN, \"%s\", \"%s\", \"unknown IE id=%%lld\", (long long)in->%s);\n",
                       label, id_member, id_member); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        }\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        out->%s = (long)in->%s;\n", id_member, id_member); s = ca(s, _cf); free(_cf); }
        if(has_crit)
        { char *_cf = cfmt("        out->criticality = (long)in->criticality;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (in->value.present == 0)\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (in->value.present != want_pr)\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_IOC_MISMATCH, \"%s\", \"value\", \"%s=%%lld present=%%d want pr=%%d\", (long long)in->%s, (int)in->value.present, (int)want_pr);\n",
                       label, id_member, id_member); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        out->value.present = (%s_PR)in->value.present;\n", prbase); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        switch (in->value.present) {\n"); s = ca(s, _cf); free(_cf); }
        for(int i = 0; i < nrows; i++) {
            const conv_ioc_row *r = rows[i];
            /* dedup alt arms (many-to-one rows: one arm per present slot) */
            int dup = 0;
            for(int j = 0; j < i; j++)
                if(strcmp(rows[j]->alt_token, r->alt_token) == 0) { dup = 1; break; }
            if(dup) continue;
            const char *pfx = asn1c_prefix();
            const char *amsg = (r->alt_msg && *r->alt_msg) ? r->alt_msg
                                                           : r->alt_token;
            { char *_cf = cfmt("        case (int32_t)%s_PR_%s:\n", prbase, r->alt_token); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (%s%s_to_tree(&in->value.%s, &out->value.choice.%s, err)) return err->code;\n",
                           pfx ? pfx : "", amsg, r->alt_token, r->alt_token); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            break;\n"); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("        case (int32_t)%s_PR_NOTHING:\n", prbase); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        default:\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_BAD, \"%s\", \"value\", \"present=%%d\", (int)in->value.present);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        }\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    }\n"); s = ca(s, _cf); free(_cf); }
    }
    free(prbase); free(tb_); free(label);
    return s;
}
