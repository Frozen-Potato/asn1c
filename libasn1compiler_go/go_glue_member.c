/*
 * go_glue_member.c — nested (inline) members, CHOICE bodies
 * and go_emit_member, the per-member dispatch.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

static const char *gf_pr_nothing(const char *prtype_q);

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
 * under their minted struct-owner name: e.g. MsgIEsValue).
 */
static void
emit_nested(ectx *E, flat_member *m) {
    const char *tok = go_flat_ir_member_token(m);
    int nix = go_flat_ir_member_nested_ix(m);
    flat_type *n = (nix >= 0 && nix < go_flat_ir_n_types())
                       ? go_flat_ir_type(nix) : NULL;
    if(!n) {
        char *m2 = go_gfmt("nested member %s.%s has no node", go_flat_ir_name(E->t), tok);
        GFAIL(m2); free(m2);
        return;
    }
    char *offc = go_qconst(E->cnode, g_go_offconst_pfx(E->cnode, E->cpre, tok, go_flat_ir_name(E->t)));
    char *slot = go_gfmt("unsafe.Pointer(uintptr(%s) + uintptr(%s))", E->cbase, offc);
    const char *fgo = go_gf_field_goname(E->owner_go, tok);
    char *ft = go_gf_field_type(E->owner_go, tok) ? go_gown(go_gf_field_type(E->owner_go, tok)) : NULL;
    char *acc;
    {
        char *gtok = fgo ? go_gown(fgo) : go_gcamel(tok);
        acc = go_gfmt("%s.%s", E->val, gtok);
        free(gtok);
    }
    char *nb = go_gcamel_flat(go_flat_ir_name(n));   /* the nested node's Go base name */

    /* the nested node's Go owner name: its field rows live under the
     * minted struct-owner (the <X>Value union / the <Parent><M> inline) —
     * rows are keyed UNQUALIFIED, so strip a package qualifier from the
     * field_type; fall back to the camel node base (same name by mint). */
    char *nowner = NULL;
    {
        const char *obase = ft ? go_unqual(ft) : nb;
        nowner = go_gown(obase);
    }

    if(go_n_is_seqof(n)) {
        /* the nested {items,count} SEQ OF member: header inline under the
         * member token; the item array via the elem node's stride const.
         * Go: the named slice field; nil/empty both count 0. */
        const char *elem = go_flat_ir_elem(n);
        flat_type *er = go_flat_ir_ref_resolve(elem);
        if(!er) {
            char *m2 = go_gfmt("nested seqof %s.%s: unresolved elem", go_flat_ir_name(E->t), tok);
            GFAIL(m2); free(m2);
            free(offc); free(slot); free(acc); free(ft); free(nowner); free(nb);
            return;
        }
        char *stride = go_qconst(go_flat_ir_name(er), g_go_szconst(go_flat_ir_name(er)));
        char *erb = go_gcamel_flat(go_flat_ir_name(er));
        /* the element's own fill/read call + item sizing (the unified
         * 4-arg/2-arg helper shapes). A *NamedSlice field (Go star)
         * wraps in the nil-guard + temp form even though the Flat header
         * rides inline at the slot here (mirror of go_emit_ref's starred arm:
         * C stars and Go stars diverge on this exact member class). */
        go_emit_items_helper(er);
        /* by-value recursion break, the nested-seqof form: the Flat
         * member is a starred {items,count} header pointer, but the Go
         * FIELD may carry the value (a nested-structure member
         * of a recursive CHOICE is a VALUE struct field) — the starred Go
         * arm keys on the FIELD's Go star, not the Flat member's. */
        int go_starred = ft && *ft == '*' && go_flat_ir_member_stars(m);
        if(go_starred) {
            char *dacc = go_gfmt("*%s", acc);
            char *tn = go_gfmt("sl%d", g_go_tmpseq++);
            (*E->fill) = go_gam((*E->fill), go_gfmt(
                "\tif %s != nil {\n"
                "\t\thdr := fa.allocStruct(16, alignPtr)\n"
                "\t\tif err := fill%sItems(fa, hdr, uintptr(%s), %s%s); err != nil {\n"
                "\t\t\treturn err\n\t\t}\n"
                "\t\tstorePtr(%s, hdr)\n\t}\n",
                acc, erb, stride, dacc, go_hdf_fill(E, er), slot));
            char *sqa = go_qualify_alias(ft + 1);
            (*E->read) = go_gam((*E->read), go_gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n"
                "\t\t%s := read%sItems(unsafe.Pointer(p), uintptr(%s))\n"
                "\t\t%s = (*%s)(&%s)\n\t}\n",
                slot, tn, erb, stride, acc, sqa, tn));
            (*E->szt) = go_gam((*E->szt), go_gfmt(
                "\tif %s != nil {\n\t\tfixed += uintptr(16)\n\t\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\t\treturn 0, 0, err\n\t\t}\n\t}\n",
                acc, erb, dacc, go_hdf_size(E, er)));
            free(dacc); free(tn); free(sqa);
        } else {
            (*E->fill) = go_gam((*E->fill), go_gfmt(
                "\tif err := fill%sItems(fa, %s, uintptr(%s), %s%s); err != nil {\n\t\treturn err\n\t}\n", erb, slot, stride, acc, go_hdf_fill(E, er)));
            (*E->read) = go_gam((*E->read), go_gfmt(
                "\t%s = read%sItems(%s, uintptr(%s))\n", acc, erb, slot, stride));
            (*E->szt) = go_gam((*E->szt), go_gfmt(
                "\tif err := size%sItems(&fixed, &payload, %s%s); err != nil {\n\t\treturn 0, 0, err\n\t}\n", erb, acc, go_hdf_size(E, er)));
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
         * (and the alt walk does NOT chain again: go_emit_choice_at's package
         * vs nested distinction reads ch != E->t).
         *
         * No double-add: the composite consts
         * off<Host><M><inner> are ABSOLUTE from the node top (they carry
         * offsetof(host,M) inside them — layout.go m->offset + im->offset,
         * go_flat.c:1614; the C assert's typeof-sum spells the same). The
         * walk base for inner members must therefore stay the NODE base
         * (E->cbase), NOT the member slot: slot + composite would add
         * offsetof(host,M) twice (Present would be read from
         * slot+8+8, the pointer slot of a nested member, giving garbage). The member slot itself is
         * still used where the MEMBER is addressed (the SEQ OF header at
         * the slot, below). */
        char *pv = go_gfmt("&%s", acc);
        ectx A = *E;
        A.t = n;
        A.owner_go = nowner;
        A.cbase = go_gown(E->cbase);
        A.cpre = go_cpre_chain(E->cpre, tok, go_flat_ir_name(E->t));
        A.val = go_gown(acc);
        go_emit_choice_at(&A, n, E->cbase, pv);
        free(pv);
        go_free_const(A.cbase); go_free_const(A.cpre); go_free_const(A.val);
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
        E2.cbase = go_gown(E->cbase); /* NOT slot: composite consts carry off<M> */
        /* the inner member const prefix: composite — off<HostNode><M><I>.
         * Implemented by carrying (host node, inner token-prefix) in the
         * const formatter: cnode stays the HOST node and cpre carries M. */
        E2.cnode = E->cnode;
        E2.cpre = go_cpre_chain(E->cpre, tok, go_flat_ir_name(E->t));
        E2.val = go_gown(acc);
        for(int i = 0; i < go_flat_ir_members(n); i++)
            go_emit_member(&E2, go_flat_ir_member(n, i));
        (*E->szt) = (*E2.szt); (*E->fill) = (*E2.fill); (*E->read) = (*E2.read);   /* ga moved them */
        go_free_const(E2.cbase); go_free_const(E2.cpre); go_free_const(E2.val);
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
const char *
go_gowner(flat_type *t, char **owned_out) {
    *owned_out = NULL;
    const char *gn = go_gf_goname(t);
    if(gn) return gn;
    *owned_out = go_gcamel_flat(go_flat_ir_name(t));
    return *owned_out;
}

/* the qualified const identifier of a Pr/enum const from emit module's
 * view (package qualification: a const declared in another module carries its package
 * qualifier). */
static char *qcconst(const char *cbase, const char *suffix) {
    char *want = go_gfmt("%s%s", cbase, suffix);
    for(int i = 0; i < go_names_rows_n(); i++) {
        const char *k = go_names_row_kind(i);
        if(!k || (strcmp(k, "choice-const") != 0
                  && strcmp(k, "enum-const") != 0
                  && strcmp(k, "value-const") != 0)) continue;
        const char *gn = go_names_row_goname(i);
        if(gn && strcmp(gn, want) == 0) {
            const char *mod = go_names_row_module(i);
            if(mod && g_go_emit_mod && strcmp(mod, g_go_emit_mod) == 0)
                { free(want); return go_gfmt("%s%s", cbase, suffix); }
            char *pkg = go_gmodule_pkg(mod);
            char *q = go_gfmt("%s.%s%s", pkg, cbase, suffix);
            free(pkg); free(want);
            return q;
        }
    }
    free(want);
    return go_gfmt("%s%s", cbase, suffix);
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
    char *rest = go_gown(last);
    /* iterate lines of rest */
    char *line = strtok(rest, "\n");
    int in_arm = 0;
    while(line) {
        if(strncmp(line, "\tcase ", 6) == 0 || strncmp(line, "\tdefault:", 9) == 0) {
            if(in_arm) out = go_ga(out, "\n\t}");
            out = go_ga(out, "\n");
            out = go_ga(out, line);
            out = go_ga(out, "\n\t{");
            in_arm = 1;
        } else {
            out = go_ga(out, "\n");
            out = go_ga(out, line);
        }
        line = strtok(NULL, "\n");
    }
    if(in_arm) out = go_ga(out, "\n\t}");
    /* splice: src up to last + rebalanced rest */
    size_t head = (size_t)(last - src);
    char *joined = malloc(head + strlen(out) + 2);
    memcpy(joined, src, head);
    strcpy(joined + head, out);
    free(out); free(rest); free(src);
    *slot = joined;
}
/* go_emit_choice_at — the CHOICE/union switch of node `ch` (present-first):
 * a package CHOICE node, an inline CHOICE, or the open-type value union.
 *   host_inner   "" = ch sits ON the walked node's own body (a package
 *                 CHOICE / the walked node IS a choice); else the member
 *                 token path prefix (the composite const chain).
 *   body_base    the C expr of ch's body (present + alts)
 *   pv           the Go value pointer expr (*T var or &unionField)
 * The switch cases emit per-alt member emission inline (ch's member rows).
 */
void
go_emit_choice_at(ectx *E, flat_type *ch, const char *body_base,
               const char *pv) {
    char *owner_own = NULL;
    const char *ch_owner = go_gowner(ch, &owner_own);
    const char *prtype_q = go_gf_present_type(ch_owner);   /* may be qualified */
    /* a foreign Pr type's package qualifier: the row of the Present field's
     * TYPE (a type row named <PrBase>); when its module is foreign, spell
     * the Pr type through its package (mirror of qcconst for type names). */
    char *prtype_own = NULL;
    {
        const char *pb = go_unqual(prtype_q);
        for(int i = 0; i < go_names_rows_n(); i++) {
            const char *k = go_names_row_kind(i);
            if(!k || (strcmp(k, "type") != 0 && strcmp(k, "choice-pr") != 0
                      && strcmp(k, "choice-const") != 0
                      && strcmp(k, "spec-pr") != 0)) continue;
            const char *gn = go_names_row_goname(i);
            if(!gn || strcmp(gn, pb) != 0) continue;
            const char *mrow = go_names_row_module(i);
            if(mrow && g_go_emit_mod && strcmp(mrow, g_go_emit_mod) != 0) {
                char *pk = go_gmodule_pkg(mrow);
                prtype_own = go_gfmt("%s.%s", pk, pb);
                free(pk);
            }
            break;
        }
    }
    if(prtype_own) prtype_q = prtype_own;   /* borrowed swap; freed at return */
    if(!prtype_q) {
        char *m2 = go_gfmt("choice %s has no Present field row", go_flat_ir_name(ch));
        GFAIL(m2); free(m2); free((char *)owner_own);
        return;
    }

    /* present write/read (composite const chain honors E->cpre). The value
     * pointer is deref'd ONCE up front (c) — every later expression reads c.
     * The READ side binds the pointed VALUE (pv minus one '&' — a nested
     * union reads its present off the host field, not the receiver). */
    /* Each inline union gets its own block scope in the fill and size
     * bodies: a SEQUENCE with two inline CHOICE members would otherwise
     * declare c / cs twice at function scope. The read body declares no
     * variable at this level (it switches on the receiver's field). */
    (*E->fill) = go_ga((*E->fill), "\t{\n");
    (*E->fill) = go_gam((*E->fill), go_gfmt("\tc := *%s\n", pv));
    {
        char *poffc = go_qconst(E->cnode, g_go_offconst_pfx(E->cnode, E->cpre, "present", go_flat_ir_name(E->t)));
        const char *pvv = (pv[0] == '&') ? pv + 1 : pv;
        (*E->fill) = go_gam((*E->fill), go_gfmt(
            "\t*(*int32)(unsafe.Pointer(uintptr(%s) + uintptr(%s))) = int32(c.Present)\n",
            body_base, poffc));
        (*E->read) = go_gam((*E->read), go_gfmt(
            "\t%s.Present = %s(*(*int32)(unsafe.Pointer(uintptr(%s) + uintptr(%s))))\n",
            pvv, prtype_q, body_base, poffc));
        (*E->read) = go_gam((*E->read), go_gfmt("\tswitch %s.Present {\n", pvv));
        free(poffc);
    }

    size_t fill_sw = strlen(*E->fill);   /* start of the fill switch */
    (*E->fill) = go_gam((*E->fill), go_gfmt("\tswitch c.Present {\n"));
    (*E->szt) = go_ga((*E->szt), "\t{\n");
    (*E->szt) = go_gam((*E->szt), go_gfmt("\tcs := *%s\n", pv));
    (*E->szt) = go_gam((*E->szt), go_gfmt("\tswitch cs.Present {\n"));

    for(int i = 0; i < go_flat_ir_members(ch); i++) {
        flat_member *m = go_flat_ir_member(ch, i);
        const char *tok = go_flat_ir_member_token(m);
        if(!tok || strcmp(tok, "present") == 0) continue;

        /* NULL alts never reach this loop: the walk records them in the
         * null-alt registry and skips the member row entirely (a NULL alt
         * has no Go field and no Flat slot), so their arms come from the
         * registry loop below, exactly once. */

        const char *alt_field = go_gf_field_goname(ch_owner, tok);
        if(!alt_field) {
            char *m2 = go_gfmt("choice %s alt %s has no field row", go_flat_ir_name(ch), tok);
            GFAIL(m2); free(m2);
            continue;
        }
        char *gu1 = go_gown(go_unqual(prtype_q));
        /* the <Choice>Pr<Alt> constant is named after the alt's C/ASN.1 name,
         * not its Go field: an alt `present` has the field PresentAlt but
         * the constant TPrPresent. */
        const char *ttok_alt = go_flat_ir_member_tree_token(m);
        /* ... except the Unknown alternative of an open type, whose
         * constant follows its field (<X>ValuePrUnknownRaw beside an
         * alternative of a type named Unknown) */
        const char *mprim = go_flat_ir_member_is_prim(m)
                                ? go_flat_ir_member_prim(m) : NULL;
        int is_raw = mprim && strcmp(mprim, "asn1cgo_raw_flat") == 0;
        char *gu2 = (!is_raw && ttok_alt && strcmp(ttok_alt, tok) != 0)
                        ? go_gown(go_gcamel_tok_in(go_flat_ir_name(ch), ttok_alt)) : go_gown(alt_field);
        char *cstname = qcconst(gu1, gu2);
        free(gu1); free(gu2);
        (*E->fill) = go_gam((*E->fill), go_gfmt("\tcase %s:\n", cstname));
        (*E->read) = go_gam((*E->read), go_gfmt("\tcase %s:\n", cstname));
        (*E->szt) = go_gam((*E->szt), go_gfmt("\tcase %s:\n", cstname));

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
            char *rd_v = go_gfmt("%s%s", pvv, "");
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
                A.cbase = go_gown(body_base);
                /* the alt slot const is off<cnode><cpre><alt>: the CALLER
                 * already chained the host path into cpre (the nested-union
                 * walk chains its member token at entry); the alt token
                 * alone appends here. Fresh go_gown copies per pass (freed
                 * below; the host's own strings stay borrowed). */
                A.cpre = go_gown((E->cpre && *E->cpre) ? E->cpre : "");
                A.val = go_gown(passes[pass].val);
                if(passes[pass].dst == E->fill) { A.read = &scratch1; A.szt = &scratch2; }
                else if(passes[pass].dst == E->read) { A.fill = &scratch1; A.szt = &scratch2; }
                else { A.fill = &scratch1; A.read = &scratch2; }

                /* nil-selected-alt guard (before any cgo call; the
                 * nil-alt error rule) — the
                 * READ pass needs no guard (decode sets only the selected
                 * alt); fill returns the error, size returns (0, 0, err). */
                if(passes[pass].dst != E->read) {
                    char *accG = go_gfmt("%s.%s", passes[pass].val, alt_field);
                    char *el = go_errlit(ch, tok, "CodeChoiceBad",
                                      "selected alternative is nil");
                    if(passes[pass].dst == E->szt) {
                        *(passes[pass].dst) = go_gam(*(passes[pass].dst), go_gfmt(
                            "\t\tif %s == nil {\n\t\t\treturn 0, 0, &%s\n\t\t}\n", accG, el));
                    } else {
                        *(passes[pass].dst) = go_gam(*(passes[pass].dst), go_gfmt(
                            "\t\tif %s == nil {\n\t\t\treturn &%s\n\t\t}\n", accG, el));
                    }
                    free(accG); free(el);
                }

                if(go_flat_ir_member_is_prim(m)) {
                    go_emit_prim(&A, m);
                    /* prim alt sizing: go_emit_prim's OWN member
                     * branches emit the szt lines (bytes/bits payload,
                     * guarded/padded fixed; scalars 0 by construction) —
                     * an extra alt size line DUPLICATED them (GNB-ID-
                     * Choice gnb_ID: payload += len(Bytes) twice; the
                     * exact-consumption invariant's find #3). The alt
                     * nil-guard above already ran; nothing more to add. */
                } else if(go_flat_ir_member_is_ref(m)) {
                    flat_type *r = go_flat_ir_ref_resolve(go_flat_ir_member_ref(m));
                    if(!r) {
                        char *m2 = go_gfmt("choice %s alt %s: unresolved ref",
                                        go_flat_ir_name(ch), tok);
                        GFAIL(m2); free(m2);
                    } else {
                        if(!go_flat_ir_is_nested_only(r)) go_emit_type_fn(r);
                        go_emit_ref(&A, m, r);
                    }
                } else {
                    emit_nested(&A, m);
                }
                /* A.cbase/A.cpre/A.val are owned (go_gown copies); the HOST's
                 * cpre (E->cpre) stays borrowed, never freed here. */
                go_free_const(A.cbase); go_free_const(A.cpre); go_free_const(A.val);
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
    for(int i = 0; i < g_go_conv_n_nullalts; i++) {
        const char *ch_cid = go_flat_ir_cid(ch);
        if(!go_conv_cid_eq(g_go_conv_nullalts[i].node_cid, ch_cid ? ch_cid : ""))
            continue;
        char *gu = go_gown(go_unqual(prtype_q));
        char *ag = go_gcamel_tok_in(go_flat_ir_name(ch), g_go_conv_nullalts[i].alt_token);
        char *cst = qcconst(gu, ag);
        free(gu);
        (*E->fill) = go_gam((*E->fill), go_gfmt("\tcase %s:\n", cst));
        (*E->fill) = go_ga((*E->fill), "\t\t// NULL alternative carries no data slot.\n");
        (*E->read) = go_gam((*E->read), go_gfmt("\tcase %s:\n", cst));
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
            (*E->fill) = go_gam((*E->fill), go_gfmt("\tcase %s:\n", nothing));
            {
                char *el = go_errlit(ch, "", "CodeChoiceNothing",
                                  "present == NOTHING");
                (*E->fill) = go_gam((*E->fill), go_gfmt(
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
        char *el = go_errlit(ch, "", "CodeChoiceBad", "present out of range");
        (*E->fill) = go_gam((*E->fill), go_gfmt(
            "\tdefault:\n\t\treturn &%s\n", el));
        free(el);
    }
    (*E->fill) = go_ga((*E->fill), "\t}\n\t}\n");
    /* No alternative at all (the value union of an empty object set,
     * `{ ... }`): every arm of that switch returns, which makes the
     * members after it unreachable (go vet). Spell the same two errors as
     * two plain ifs instead. */
    int n_arms = 0;
    for(const char *q = strstr(*E->fill + fill_sw, "\tcase "); q;
        q = strstr(q + 1, "\tcase "))
        n_arms++;
    const char *nothing = gf_pr_nothing(prtype_q);
    if(n_arms <= (nothing ? 1 : 0)) {
        char *eln = go_errlit(ch, "", "CodeChoiceNothing", "present == NOTHING");
        char *elb = go_errlit(ch, "", "CodeChoiceBad", "present out of range");
        (*E->fill)[fill_sw] = '\0';
        (*E->fill) = go_gam((*E->fill), go_gfmt(
            "\tif c.Present == %s {\n\t\treturn &%s\n\t}\n"
            "\tif c.Present != %s {\n\t\treturn &%s\n\t}\n\t}\n",
            nothing ? nothing : "0", eln, nothing ? nothing : "0", elb));
        free(eln); free(elb);
    }
    (*E->read) = go_ga((*E->read), "\t}\n");
    rebalance_switch(E->szt);
    (*E->szt) = go_ga((*E->szt), "\t}\n\t}\n");
    free(prtype_own);
    free((char *)owner_own);
}

/* The qualified PrNothing const of a Pr type (row goType == base): the row
 * named <base>Nothing. */
static const char *gf_pr_nothing(const char *prtype_q) {
    const char *base = go_unqual(prtype_q);
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
            const char *emit_mod = g_go_emit_mod;
            if(mod && emit_mod && strcmp(mod, emit_mod) == 0)
                return want;
            char *pkgS = go_gmodule_pkg(mod);
            static char q[600];
            snprintf(q, sizeof q, "%s.%s", pkgS, want);
            free(pkgS);
            return q;
        }
    }
    return NULL;
}

/* go_emit_member — dispatch one member row of the walked node. */
void
go_emit_member(ectx *E, flat_member *m) {
    if(go_flat_ir_member_is_prim(m)) {
        go_emit_prim(E, m);
        return;
    }
    if(go_flat_ir_member_is_ref(m)) {
        flat_type *r = go_flat_ir_ref_resolve(go_flat_ir_member_ref(m));
        if(!r) {
            const char *tok = go_flat_ir_member_token(m);
            char *m2 = go_gfmt("unresolved member ref %s.%s", go_flat_ir_name(E->t),
                            tok ? tok : "?");
            GFAIL(m2); free(m2);
            return;
        }
        go_emit_ref(E, m, r);
        return;
    }
    emit_nested(E, m);
}
