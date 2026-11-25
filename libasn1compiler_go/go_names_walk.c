/*
 * go_names_walk.c — the recursive walkers: one member
 * (walk_names_child), a member list (go_walk_names_members) and a top-level
 * assignment (go_walk_names_expr).
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

static int field_shaped_element(struct walk_ctx *ctx, asn1p_expr_t *elem);
static int plain_clone(struct walk_ctx *ctx, asn1p_expr_t *t);

/* Walk one child member of a struct at path `parent_path` (dotted path that
 * already includes this member's name) under enclosing goName `parent_go` and
 * real C-ident prefix `parent_cid` (the latter from ctx->parent_cid at the call
 * site). */
static int
walk_names_child_inner(struct walk_ctx *ctx, asn1p_expr_t *child,
                       const char *parent_path, const char *parent_go,
                       const char *parent_cid) {
    /* Defense-in-depth: the canonical ext-marker skip is in
     * go_walk_names_members (the SEQUENCE loop), but reject an A1TC_EXTENSIBLE
     * child here too so a future direct caller can't leak a blank-goName row. */
    if(child->expr_type == A1TC_EXTENSIBLE) return 0;
    const char *cid = child->Identifier ? child->Identifier : "?";
    /* Pointer-star FIRST: go_member_stars also rejects DEFAULT — before
     * any row is emitted, so a failed run writes nothing for the member. */
    ctx->last_opt_extra = 0;
    const char *stars = go_member_stars(ctx, child, parent_path);
    if(ctx->bag->failed) return -1;
    /* Field row (struct-scoped). rawCid = GO_MKID(child). The census
     * out-param rides along: non-zero iff OPTIONAL carried
     * marker bits beyond EM_OPTIONAL. The row INDEX is retained: the SEQ-OF
     * mint below emits its own inline row AFTER this one, and the field's
     * field_type must land on THIS row (go_row_set_field_type writes n_rows-1,
     * which by then is the inline row; a mismatch left the
     * emitted body of a parameterized container empty). */
    int field_row_ix;
    {
        char *path = go_make_path(parent_path, cid);
        char *mgo_ = go_member_go(child);
        char *mtok_ = go_mk_member(child);
        go_alt_register(parent_cid ? parent_cid : "", mtok_, mgo_);
        free(mtok_);
        go_emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  go_mk_member(child), mgo_);
        field_row_ix = ctx->bag->n_rows - 1;
        ctx->bag->rows[field_row_ix].opt_extra_bits = ctx->last_opt_extra;
    }
    /* A supported DEFAULT member is a plain Go value; its Flat slot is by
     * value too (the C tree slot is a pointer iff the C pass left
     * EM_INDIRECT set: tree_ptr, handled by the conv arms). */
    const int is_dflt = go_member_is_default(child);
    const int tree_ptr = is_dflt && (child->marker.flags & EM_INDIRECT);

    /* Recurse into the child's OWN inline children only (mirrors go_walk.c
     * walk_child:420-425 plus inline ENUMERATED — see below). A reference child
     * has none. An anonymous inline SEQUENCE/CHOICE/ENUMERATED at a member mints
     * a named Go type <Parent><Member> (the anonymous-inline naming rule)
     * that then parents its own
     * members/enumerators. */
    if(go_is_struct_kind(child->expr_type)
       || child->expr_type == ASN_CONSTR_CHOICE
       || go_is_list_kind(child->expr_type)
       || child->expr_type == ASN_BASIC_ENUMERATED) {

        /* inline record goName = <Parent><Member> (the anonymous-inline
         * naming rule). The real C-ident
         * compounds as asn1c does: <parent_cid> + "__" + <child cid> (the nested
         * tag form <StructCid>__<memberCid>, underscore-preserving on both
         * sides). goName collapses underscores; cid keeps them. */
        char *child_field_go = go_member_go(child);
        /* struct-body stage: the field's Go type is the inline name (the field is typed by
         * the minted named type <Parent><Member>), pointer-starred by the
         * marker rule (go_member_stars, computed above). Same-module by
         * construction (the name is minted in the parent's own module). Set
         * before the recursion may emit more rows. */
        {
            char *ft = go_str_append(strdup(""), stars);
            ft = go_str_append(ft, parent_go);
            ft = go_str_append(ft, child_field_go);
            go_row_set_field_type(ctx->bag, ft);
            free(ft);
        }
        char *child_cid = go_own_mkid(child);
        char *inline_go = go_str_append(strdup(""), parent_go);
        inline_go = go_str_append(inline_go, child_field_go);
        free(child_field_go);
        /* an inline tag is an aggregate name — prefix once, parts
         * unprefixed (go_cid_compound strips each part's prefix and puts the
         * run prefix back once at the front; asn1c's nested tag form). */
        char *inline_cid = go_cid_compound(parent_cid ? parent_cid : "", "__",
                                           child_cid);
        free(child_cid);
        char *inline_path = strdup(parent_path);   /* <Parent>.<this member> */

        /* inline row: a named Go type for the anonymous construct. rawCid = the
         * real compounded nested C-ident (e.g. Interface_MessageID__messageType),
         * NOT the _-collapsed Go name. */
        {
            char *raw = strdup(inline_cid);
            char *go = strdup(inline_go);
            char *path = strdup(inline_path);
            go_emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
            /* leaf-stage body data: an inline LEAF construct's declaration is the
             * same named-type form as a top-level leaf (the anonymous-inline
             * naming rule: the
             * anonymous inline SEQUENCE/CHOICE/ENUMERATED/SEQ-OF at a member
             * is a named Go type <Parent><Member>; an inline ENUMERATED is
             * `type X int32` + consts — e.g. a SEQUENCE member
             * `ReportingSupport` becomes `ItemReportingSupport`).
             * SEQUENCE/CHOICE/SEQ-OF inline rows carry GLEAF_NONE (bodies are
             * struct-body); a SEQ-OF of a plain leaf is a slice-stage alias. */
            if(child->expr_type == ASN_BASIC_ENUMERATED) {
                go_row_set_leaf(ctx->bag, GLEAF_ENUM);
                /* Flat: NO leaf typedef mint — an inline ENUM member
                 * is the bare int32 slot only (no
                 * <P>__<m>_flat leaf is authored; the .h's e_<P>__<m> enum tag is not a
                 * scalar alias the mapping table's Flat column maps). */
            }
        }

        if(go_construct_classify(child) == GO_CONSTR_BIT_STRING)
            go_mark_bitstring_module(ctx->bag, ctx->module);

        /* Flat: an inline construct member nests an ANONYMOUS struct in
         * the enclosing Flat exactly as the .h nests `struct <P>__<m> {...}` —
         * mint the nested node, attach it under the member token, then re-target
         * the member-population calls at it for the whole recursion below (the
         * ENUM/CHOICE/SEQ-OF bodies below mint on the node via cur re-binding:
         * go_flat_struct[_nested] sets cur to the new node; on entry here the
         * enclosing struct is cur, so the nested mint + member attach happen on
         * it, and the nested mint re-binds cur to the node for its members). */
        int flat_nest_ix = -2;   /* -2: enum (bare int32 slot below) */
        if(child->expr_type == ASN_BASIC_ENUMERATED) {
            /* an inline ENUM member is a bare int32 slot (the .h typedef enum
             * collapses to long; the ENUMERATED mapping row); no nested node. */
            {
                char *m = go_mk_member(child);
                go_flat_member_prim("int32_t", m, stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                if(is_dflt) go_flat_last_member_default(tree_ptr);
                free(m);
            }
        } else if(go_is_list_kind(child->expr_type)) {
            /* the SEQ OF tail attaches the ONE member row itself (a nested
             * {items,count} behind the member star) — no pre-mint attach here
             * (a second attach duplicated the member token). */
            flat_nest_ix = -3;
        } else if(stars && *stars == '*') {
            /* OPTIONAL inline SEQUENCE / CHOICE: the tree slot is a pointer
             * to `struct <cid>` (a tag only, no typedef), the same shape as
             * a CHOICE alt. A pointer slot to an anonymous nested struct has
             * no layout of its own to address, so — exactly as for an alt —
             * the construct is a package-scoped Flat node and the member a
             * starred ref to it (minted below; the conv file aliases
             * `<cid>_t` to the struct tag). A by-value slot stays nested. */
            flat_nest_ix = -4;
            {
                char *m = go_mk_member(child);
                go_flat_member_ref(inline_cid, m, 1);
                go_flat_label_last_member(child->Identifier);
                free(m);
            }
        } else {
            flat_nest_ix = go_flat_struct_nested(inline_cid, ctx->module);
            {
                char *m = go_mk_member(child);
                go_flat_member_nested(flat_nest_ix, m, stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                if(is_dflt) go_flat_last_member_default(tree_ptr);
                free(m);
            }
            /* re-bind cur to the nested node: every member the recursion below
             * emits for this construct lands on it. CHOICE mints its own node
             * again below — flat_new_type dedups by (cid, module), so the
             * pre-mint node IS the one the recursion populates. */
        }

        /* inline ENUMERATED: its enumerators become enum-const rows under the
         * inline name (the real .h: `typedef enum <P>__<member> { <P>__<member>_
         * <enumerator> }`). asn1c compounds the parent cIdent into both the enum
         * and every enumerator cIdent, so R2 of the compounded enumerator is the
         * full `<P><Member><Enumerator>` const declared. Go_walk does
         * NOT descend here (it classifies the member terminal without recursing),
         * but ENUMERATED IS a supported terminal — naming it stays within the
         * supported-construct set. The real cid prefix (inline_cid) reproduces
         * the verbatim enumerator tokens <P>__<member>_<enumerator>. */
        if(child->expr_type == ASN_BASIC_ENUMERATED) {
            go_emit_enum(ctx, inline_go, inline_cid, inline_path, child);
            free(inline_go); free(inline_cid); free(inline_path);
            return 0;
        }

        if(child->expr_type == ASN_CONSTR_CHOICE) {
            /* go_emit_choice toggles the struct-owner scope (open under the
             * inline CHOICE, reset at its end); a member AFTER the inline
             * CHOICE belongs to the OUTER struct again (e.g. RRC-MessageID's
             * messageID after rrcType), so SAVE/RESTORE the outer scope
             * around the call — go_struct_scope_reset leaves none open, and the
             * outer struct's remaining members would else attach to no owner
             * (and emit nothing). The FLAT cur
             * register needs the same save/restore: go_emit_choice rebinds it to
             * the inline CHOICE's node (dedup finds the pre-minted node). */
            char *save_sf = NULL;
            if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
            int save_fcur = go_flat_cur_get();
            go_field_scope_push(ctx->bag);
            go_emit_choice(ctx, inline_go, inline_cid, inline_path, child);
            go_field_scope_pop(ctx->bag);
            if(flat_nest_ix == -4) go_flat_mark_inline_elem("struct", NULL);
            go_flat_cur_restore(save_fcur);
            free(go_bag_sf_restore(ctx->bag, save_sf));
            free(inline_go); free(inline_cid); free(inline_path);
            return 0;
        }
        if(go_is_struct_kind(child->expr_type)) {
            const char *save_go = ctx->parent_go;
            const char *save_cid = ctx->parent_cid;
            char *save_sf = NULL;
            if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
            ctx->parent_go = inline_go;
            ctx->parent_cid = inline_cid;
            go_field_scope_push(ctx->bag);
            /* struct-body stage: the inline SEQUENCE declares a Go struct; its member
             * fields (the rows go_walk_names_members emits next) attach to it.
             * FLAT cur save/restore as for the CHOICE branch above. */
            go_row_set_is_struct(ctx->bag);
            go_struct_scope_open(ctx->bag, inline_go);
            int save_fcur = go_flat_cur_get();
            /* bind cur to the construct's own node (the nested node minted
             * above, or the package-scoped one of a pointer slot): the
             * SEQUENCE branch has no go_emit_choice-style re-mint to do it, so
             * without this the inline SEQUENCE's members landed on the
             * ENCLOSING struct. */
            if(flat_nest_ix == -4) {
                go_flat_struct(inline_cid, ctx->module);
                go_flat_label_cur(child->Identifier);   /* td->name label */
                go_flat_mark_inline_elem("struct", NULL);
            } else {
                go_flat_cur_restore(flat_nest_ix);
            }
            int rc = go_walk_names_members(ctx, child, inline_path);
            go_flat_cur_restore(save_fcur);
            go_struct_scope_reset(ctx->bag);
            go_field_scope_pop(ctx->bag);
            free(go_bag_sf_restore(ctx->bag, save_sf));
            ctx->parent_go = save_go;
            ctx->parent_cid = save_cid;
            free(inline_go); free(inline_cid); free(inline_path);
            return rc;
        }
        /* ASN_CONSTR_SEQUENCE_OF (slice stage): the anonymous inline SEQ-OF
         * at a member mints the named slice alias `type <Parent><Member>
         * []Elem` — the inline ROW was already emitted above (the same
         * walk SEQUENCE/CHOICE/ENUM take); attach the ELEMENT type
         * to it now. No row is appended between the inline emit and here, so
         * the n_rows-1 form targets the inline row. Element rule: ONE
         * resolver for all three slice shapes (go_slice_element_type) — a
         * reference element is the assignment's own goName, a leaf
         * element is the mapping-table column, an inline element is minted
         * as <Parent><Member>Member by go_mint_inline_seqof_elem. The
         * member's own field row was typed by the minted name in the block
         * above (stars + parent_go + child name) — never a bare []Elem.
         * A BIT STRING
         * element marks this module for the helper (same membership as a
         * plain member; the element resolve itself keeps one path). */
        char *inl_flat_cid = NULL;   /* the minted Flat element cid */
        {
            asn1p_expr_t *elem = TQ_FIRST(&child->members);
            if(elem && elem->expr_type == ASN_BASIC_BIT_STRING)
                go_mark_bitstring_module(ctx->bag, ctx->module);
            char *selem;
            if(go_seqof_elem_is_inline(elem)) {
                int inl_row = ctx->bag->n_rows - 1;
                if(go_mint_inline_seqof_elem(ctx, elem, inline_path, inline_go,
                                          inline_cid, &selem,
                                          &inl_flat_cid) < 0) {
                    free(selem);
                    free(inline_go); free(inline_cid); free(inline_path);
                    return -1;
                }
                go_row_set_slice_elem_at(ctx->bag, inl_row, selem);
            } else {
                selem = go_slice_element_type(ctx, elem, inline_path);
                if(ctx->bag->failed) {
                    free(selem);
                    free(inline_go); free(inline_cid); free(inline_path);
                    return -1;
                }
                go_row_set_slice_elem(ctx->bag, selem);
            }
            free(selem);
        }
        /* Flat: the inline SEQ OF member rides the nested node minted above
         * (flat_nest_ix): A2 {items,count} nested, behind the member
         * star when OPTIONAL. go_flat_member_seqof re-mints the {items,count}
         * shape into that node (the node's FLT_STRUCT rep is replaced at
         * layout by the seqof shape: nested seqof nodes lay out 16/8). */
        {
            asn1p_expr_t *selem_expr = TQ_FIRST(&child->members);
            asn1p_expr_t *se_ = selem_expr;
            if(selem_expr
               && (selem_expr->expr_type == A1TC_REFERENCE
                   || selem_expr->meta_type == AMT_TYPEREF)) {
                asn1p_expr_t *st = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, selem_expr);
                if(st) se_ = st;
            }
            if(flat_nest_ix == -3) {
                char *flat_selem = inl_flat_cid ? strdup(inl_flat_cid)
                                   : se_ ? go_own(GO_MKID(se_)) : strdup("");
                char *flat_mtok = go_mk_member(child);
                go_flat_member_seqof(flat_selem, 0,
                                     child->expr_type == ASN_CONSTR_SET_OF,
                                     flat_mtok, stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                if(is_dflt) go_flat_last_member_default(tree_ptr);
                free(flat_selem); free(flat_mtok);
            }
        }
        free(inl_flat_cid);
        free(inline_go); free(inline_cid); free(inline_path);
        return 0;
    }

    /* Plain (reference) member: chase the terminal to detect BIT STRING
     * (helper) and a container specialization (a ProtocolIE-Container /
     * SingleContainer / ContainerList {{X}} reference — the asn1c C type is a
     * `ProtocolIE_Container_<N>P<slot>_t`), exactly as go_walk.c walk_child:330-
     * 346 chases the terminal. A container specialization at a member is the
     * named slice: it mints a Go type <Parent><Member> (e.g.
     * `<Msg>ProtocolIEs`), emitted as an `inline` row. */
    asn1p_expr_t *terminal = child;
    if(child->expr_type == A1TC_REFERENCE
       || child->meta_type == AMT_TYPEREF) {
        terminal = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child);
        if(!terminal) terminal = child;
    }
    go_construct_e tk = go_construct_classify(terminal);
    if(tk == GO_CONSTR_BIT_STRING)
        go_mark_bitstring_module(ctx->bag, ctx->module);
    if(tk == GO_CONSTR_SEQUENCE_OF) {
        /* Only a param-container specialization (a SEQUENCE OF whose element is
         * itself a field-shaped specialization — a `ProtocolIE-Field {{...}}`,
         * the asn1c `ProtocolIE_Container_<N>P<slot>_t`) mints the
         * named slice <Parent><Member> (e.g. `<Msg>ProtocolIEs`). A
         * plain reference to a NAMED top-level SEQUENCE-OF does not (that type
         * already has its own `type` row, walked as a top-level assignment);
         * the chase landing on a hand-authored assignment is detected by
         * lhs_params==NULL && spec_index==-1 (a clone carries spec_index>=0 —
         * the same marker go_walk_names_expr gates the template walk on). A
         * member `Details.items-List` referencing the named
         * `Items-List ::= SEQUENCE OF ProtocolIE-SingleContainer {{...}}`
         * must not mint DetailsItemsList; the named-type rule names the
         * field by the assignment's own ItemsList. */
        asn1p_expr_t *elem = TQ_FIRST(&terminal->members);
        int named_top_level_seqof =
            terminal != child
            && (!(terminal->lhs_params || terminal->spec_index >= 0)
                || plain_clone(ctx, terminal));
        if(elem && !named_top_level_seqof
           && (go_construct_is_open_type(elem)
               || (elem->meta_type == AMT_TYPEREF
                   && elem->expr_type == A1TC_REFERENCE
                   && field_shaped_element(ctx, elem)))) {
            char *member_go = go_member_go(child);
            char *inline_go = go_str_append(strdup(""), parent_go);
            inline_go = go_str_append(inline_go, member_go);
            free(member_go);
            char *raw = strdup(inline_go);
            char *go = strdup(inline_go);
            char *path = strdup(parent_path);
            go_emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
            /* slice stage (container element resolution): the container slice's ELEMENT is
             * R2(X) — the field-shaped payload the container holds — which
             * go_slice_element_type resolves to exactly (the chased terminal
             * IS the field-shaped clone named R2(X); same one-resolver rule
             * as every slice shape). Attached to the inline row just
             * emitted (no row between it and here). */
            {
                char *selem = go_slice_element_type(ctx, elem, parent_path);
                if(ctx->bag->failed) {
                    free(selem);
                    free(inline_go);
                    return -1;
                }
                go_row_set_slice_elem(ctx->bag, selem);
                free(selem);
            }
            /* struct-body stage: the field is typed by the minted named slice
             * (<Parent><Member>), same-module. NOT the assignment's own name
             * (the container clone never surfaces in Go). BY INDEX: the inline
             * row was just emitted ABOVE this point, so the n_rows-1 form
             * would type the inline row and leave the FIELD row untyped. */
            {
                char *ft = go_str_append(strdup(""), stars);
                ft = go_str_append(ft, inline_go);
                go_row_set_field_type_at(ctx->bag, field_row_ix, ft);
                free(ft);
            }
            /* Flat (A2 collapse): the container CLONE is a
             * struct Flat named by the clone's own cid (the asn1c
             * <ProtocolIE_Container_85P0> id, GO_MKID of the clone expr
             * carries the _<N>P<n> suffix), holding {<ItemIEs>_flat *items;
             * size_t count;}; the MESSAGE's member row references it by
             * that name (the `ProtocolIE_Container_85P0_flat
             * protocolIEs` shape — a BARE name, no run prefix on clone
             * family names). The ItemIEs element cid:
             * go_slice_element_type's chase target == the field-shaped clone
             * (R2(X)); the C id is that clone's own GO_MKID. */
            {
                asn1p_expr_t *fterm = elem;
                if(elem->expr_type == A1TC_REFERENCE
                   || elem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *ft_ = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, elem);
                    if(ft_) fterm = ft_;
                }
                char *flat_cname = go_own(GO_MKID(terminal));
                char *flat_ieid = go_own(GO_MKID(fterm));
                (void)go_flat_seqof_container(flat_cname, flat_ieid,
                                              ctx->module);
                char *flat_mtok3 = go_mk_member(child);
                go_flat_member_ref(flat_cname, flat_mtok3,
                                   stars && *stars == '*');
                go_flat_label_last_member(child->Identifier);
                free(flat_cname); free(flat_ieid); free(flat_mtok3);
            }
            free(inline_go);
            return 0;
        }
    }
    /* A param-container clone member (the branch above) returned early; the
     * plain-member Flat rows ride the two tails below. The FLAT star is
     * go_member_stars (OPTIONAL) OR the asn1c cycle-break/recursion marker
     * (EM_INDIRECT/EM_UNRECURSE, the recursion Flat-pointer rule: Flat pointer placement mirrors
     * asn1c's cycle-break, masked tests per the the marker-reading rule amendment) — the walk
     * prints it once here. */
    int flat_star = !is_dflt && ((stars && *stars == '*')
                    || (child->marker.flags & (EM_INDIRECT | EM_UNRECURSE)));
    /* struct-body stage: the field's Go type for a plain member, keyed on whether the
     * member is a REFERENCE (a member whose type references an
     * assignment — leaf OR constructed — is typed by that assignment's named
     * Go type) or the inline construct itself (mapping-table Go column):
     *   a REFERENCE member — the chased terminal assignment's own Go name
     *     (R2(MKID(terminal)); a field-shaped specialization is named R2(X)
     *     — the spec-key — the same form: X IS the clone's Identifier by the
     *     time the chase lands on it). Stored UNQUALIFIED; the post-walk
     *     prepass (go_qualify_field_types) applies cross-module
     *     qualification once the whole name table exists (a member may
     *     reference an assignment its module defines LATER in the walk).
     *   an inline leaf (INTEGER/BOOLEAN/string/OCTET STRING/BIT STRING/...)
     *     — the mapping-table Go column via go_classify_leaf, the SAME table the decl
     *     emission uses (go_types_leaf_underlying — one table, no drift). */
    if(child->expr_type == A1TC_REFERENCE || child->meta_type == AMT_TYPEREF
       || terminal != child) {
        /* `terminal != child` covers the post-fix AST where asn1fix resolved
         * a member's type reference IN PLACE (the member expr itself now
         * carries the terminal's expr_type with meta AMT_TYPE — the
         * A1TC_REFERENCE form is gone). The chase resolving to a DIFFERENT
         * expr than the member is the reliable "was a reference" signal. */
        char *tgo = go_type_go(terminal);
        char *ft = go_str_append(strdup(""), stars);
        ft = go_str_append(ft, tgo);
        go_row_set_field_type(ctx->bag, ft);
        /* Flat: a named-ref member slot (tk SEQ OF with no container clone =
         * the nested {items,count} A2 form; anything else = the terminal's
         * own <X>_flat, starred as decided). */
        if(tk == GO_CONSTR_SEQUENCE_OF && terminal->spec_index >= 0
           && !plain_clone(ctx, terminal)) {
            /* a param-container CLONE: the Flat is the nested
             * {items,count} A2 form (the clone never surfaces as a named
             * Flat of its own). */
            asn1p_expr_t *selem = TQ_FIRST(&terminal->members);
            asn1p_expr_t *sterm = selem;
            if(selem && (selem->expr_type == A1TC_REFERENCE
                         || selem->meta_type == AMT_TYPEREF)) {
                asn1p_expr_t *st = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, selem);
                if(st) sterm = st;
            }
            char *flat_selem = go_own(GO_MKID(sterm));
            char *flat_mtok = go_mk_member(child);
            go_flat_member_seqof(flat_selem, 0,
                                 terminal->expr_type == ASN_CONSTR_SET_OF,
                                 flat_mtok, flat_star);
            go_flat_label_last_member(child->Identifier);
            free(flat_selem); free(flat_mtok);
        } else if(tk == GO_CONSTR_SEQUENCE_OF) {
            /* a reference to a NAMED top-level SEQUENCE OF: the
             * member is typed by the assignment's own named {items,count}
             * typedef (a `PFX_BinRangeList_flat` member
             * shape); never a re-nested wrapper. */
            char *flat_tcid = go_own(GO_MKID(terminal));
            char *flat_mtok = go_mk_member(child);
            go_flat_member_ref(flat_tcid, flat_mtok, flat_star);
            go_flat_label_last_member(child->Identifier);
            if(is_dflt) go_flat_last_member_default(tree_ptr);
            free(flat_tcid); free(flat_mtok);
        } else {
            char *flat_tcid = go_own(GO_MKID(terminal));
            char *flat_mtok2 = go_mk_member(child);
            go_flat_member_ref(flat_tcid, flat_mtok2, flat_star);
            go_flat_label_last_member(child->Identifier);
            if(is_dflt) go_flat_last_member_default(tree_ptr);
            free(flat_tcid); free(flat_mtok2);
        }
        free(tgo); free(ft);
    } else {
        /* An inline leaf terminal (the member IS the construct): the
         * mapping-table Go column (go_classify_leaf — INTEGER via asn1c's own
         * asn1c_type_fits_long). GLEAF_ENUM has no bare primitive here: a
         * member that is an inline ENUMERATED took the inline-construct
         * branch at the top of this function (the minted named type), so
         * the NULL return leaves the row unset only for genuinely
         * unclassifiable terminals (go_classify_leaf already failed those). */
        ctx->wide_nr = 1; ctx->wide_hit = 0;
        int lk = go_classify_leaf(ctx, terminal, parent_path);
        int mwide = ctx->wide_hit;
        ctx->wide_nr = 0; ctx->wide_hit = 0;
        if(ctx->bag->failed) return -1;
        const char *under = go_types_leaf_underlying(lk);
        if(under) {
            char *ft = go_str_append(strdup(""), stars);
            ft = go_str_append(ft, under);
            go_row_set_field_type(ctx->bag, ft);
            /* Flat: the same classification -> the mapping-table Flat prim column. */
            {
                                const char *fprim = go_leaf_flat_prim(lk);
                if(fprim) {
                    char *fpm = go_mk_member(child);
                    go_flat_member_prim(fprim, fpm, flat_star);
                    if(mwide) go_flat_last_member_wide();
                    go_flat_last_member_gleaf(lk);
                    go_flat_label_last_member(child->Identifier);
                    if(is_dflt) go_flat_last_member_default(tree_ptr);
                    free(fpm);
                }
            }
            free(ft);
        }
    }
    return 0;
}

/* walk_names_child: the member walk, then (for a supported DEFAULT member) the
 * exported default-value row. The row is emitted AFTER the member's rows are
 * complete: go_row_set_field_type and friends address the last row appended, so
 * nothing may be interleaved with them. The member's field row is the first
 * row the inner walk appends. */
static int
walk_names_child(struct walk_ctx *ctx, asn1p_expr_t *child,
                 const char *parent_path, const char *parent_go,
                 const char *parent_cid) {
    int first_row = ctx->bag->n_rows;
    int rc = walk_names_child_inner(ctx, child, parent_path, parent_go,
                                    parent_cid);
    /* An inline named-bit BIT STRING member: a plain BitString field (typed
     * by the inner walk); the bit positions are named as an inline
     * ENUMERATED member's type would be (<Parent><Member>). Emitted here, after
     * the member's own rows are complete (go_row_set_field_type addresses the
     * last row). parent_path already ends in this member's name. */
    if(rc == 0 && child->expr_type == ASN_BASIC_BIT_STRING
       && child->meta_type != AMT_TYPEREF && TQ_FIRST(&child->members)
       && asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child) == child) {
        char *mgo = go_member_go(child);
        char *bit_go = go_str_append(go_str_append(strdup(""), parent_go), mgo);
        char *mcid = go_own_mkid(child);
        char *bit_cid = go_cid_compound(parent_cid ? parent_cid : "", "__",
                                        mcid);
        go_emit_bit_names(ctx, bit_go, bit_cid, parent_path, child);
        free(mgo); free(bit_go); free(mcid); free(bit_cid);
        if(ctx->bag->failed) return -1;
    }
    if(rc == 0 && child->expr_type != A1TC_EXTENSIBLE
       && go_member_is_default(child) && ctx->bag->n_rows > first_row) {
        go_note_default_value(ctx, child, parent_path, first_row);
        if(ctx->bag->failed) return -1;
    }
    return rc;
}

/* field_shaped_element: a SEQ-OF element whose chased terminal is a SEQUENCE
 * with an open-type &Value member — i.e. a ProtocolIE-Field specialization
 * clone (the element a param-container holds). Used to distinguish a
 * param-container specialization from a plain SEQ-OF-of-named-type. */
static int
field_shaped_element(struct walk_ctx *ctx, asn1p_expr_t *elem) {
    asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, elem);
    return t && go_is_field_shaped_spec(t) != NULL;
}

/* plain_clone: a specialization of a parameterized type that is not an
 * information object container: a SEQUENCE / CHOICE that is not field-shaped
 * (T{X} ::= SEQUENCE { v X }), or a SEQUENCE OF / SET OF whose element is
 * neither an open type nor a field-shaped specialization (L{X} ::= SEQUENCE
 * OF X). asn1c emits it as an ordinary named C type (T_<N>P<k>_t); the Go
 * side names it like any top-level type assignment (go_type_go of the clone:
 * T<N>P<k>). Container clones keep the inline <Parent><Member> slice. */
static int
plain_clone(struct walk_ctx *ctx, asn1p_expr_t *t) {
    if(!t || t->spec_index < 0) return 0;
    go_construct_e k = go_construct_classify(t);
    if(k == GO_CONSTR_SEQUENCE) return go_is_field_shaped_spec(t) == NULL;
    if(k == GO_CONSTR_CHOICE) return 1;
    if(k == GO_CONSTR_SEQUENCE_OF) {
        asn1p_expr_t *elem = TQ_FIRST(&t->members);
        if(!elem || go_construct_is_open_type(elem)) return 0;
        if(elem->meta_type == AMT_TYPEREF && elem->expr_type == A1TC_REFERENCE
           && field_shaped_element(ctx, elem))
            return 0;
        return 1;
    }
    switch(k) {
    case GO_CONSTR_ENUMERATED: case GO_CONSTR_BIT_STRING:
    case GO_CONSTR_OCTET_STRING: case GO_CONSTR_INTEGER:
    case GO_CONSTR_BOOLEAN: case GO_CONSTR_NULL: case GO_CONSTR_REAL:
    case GO_CONSTR_OID: case GO_CONSTR_STRING:
        return 1;
    default:
        return 0;
    }
}

/* Iterate one struct's members. The member path passed to walk_names_child is
 * parent_path + "." + child name (the ASN.1 dotted path). */
int
go_walk_names_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
                   const char *parent_path) {
    /* the caller opened this struct's (empty) field scope */
    asn1p_expr_t *child;
    TQ_FOR(child, &(parent->members), next) {
        /* Extension marker "..." (A1TC_EXTENSIBLE, Identifier "...") carries no
         * Go name — GO_MKID collapses it to "_" and go_r2 to "" — and it is not a
         * real struct member. go_emit_choice (go_names.c) and go_emit_enum skip it in
         * their alt loops; the SEQUENCE-member walk must too, or every extensible
         * SEQUENCE leaks a blank-goName field row that no name check legitimately
         * compares (docs/questions.md). */
        if(child->expr_type == A1TC_EXTENSIBLE) continue;
        char *cp = go_make_path(parent_path,
                             child->Identifier ? child->Identifier : "?");
        int rc = walk_names_child(ctx, child, cp, ctx->parent_go, ctx->parent_cid);
        free(cp);
        if(rc < 0) return -1;
    }
    return 0;
}

/* Walk one top-level assignment (mirror go_walk.c walk_expr). */
int
go_walk_names_expr(struct walk_ctx *ctx, asn1p_expr_t *expr) {
    /* Parameterized template: walk specializations, not the template
     * (go_walk.c walk_expr:446-454; asn1compiler.c:116-130). */
    if(expr->lhs_params && expr->spec_index == -1) {
        for(int i = 0; i < expr->specializations.pspecs_count; i++) {
            asn1p_expr_t *clone = expr->specializations.pspec[i].my_clone;
            if(clone && go_walk_names_expr(ctx, clone) < 0) return -1;
        }
        return 0;
    }

    /* Value assignment: typed value-const only (asn1c_C.c
     * asn1c_lang_C_type_REFERENCE_Value:1259-1265). The discriminator is the
     * AMT_VALUE's OWN expr_type: a named-reference value assign resolves to a
     * governing terminal; INTEGER/ENUMERATED -> the typed
     *   #define <T>_id_<X> ((<T>_t)<n>)
     * A bare INTEGER value assign (`X INTEGER ::= n`) emits the UNTYPED
     * `#define X (n)` (asn1c_save.c:976) and is NOT a value-const. */
    if(expr->meta_type == AMT_VALUE) {
        asn1p_expr_t *governing = NULL;
        if(expr->expr_type == A1TC_REFERENCE
           || expr->meta_type == AMT_TYPEREF)
            governing = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, expr);
        if(governing
           && (governing->expr_type == ASN_BASIC_INTEGER
               || governing->expr_type == ASN_BASIC_ENUMERATED)) {
            /* the #define token is an aggregate — prefix once, parts
             * unprefixed (the .h: PFX_ProcedureCode_id_Setup, never
             * ..._id_PFX_Setup). go_own() each part into a named local BEFORE
             * the second GO_MKID: GO_MKID returns the SHARED static buffer
             * (asn1c_misc.c:60), so passing two live GO_MKID returns aliases
             * one buffer (both parts read the same last-computed string).
             * go_cid_compound does not free its args; free the owned parts
             * after the call. */
            char *gov_cid = go_own(GO_MKID(governing));
            char *val_cid = go_own(GO_MKID(expr));
            char *raw = go_cid_compound(gov_cid, "_", val_cid);
            free(gov_cid); free(val_cid);
            char *go = go_value_go(governing, expr);
            char *path = go_make_path("", expr->Identifier
                                       ? expr->Identifier : "?");
            go_emit_name(ctx->bag, ctx->module, path, GK_VALUE_CONST, raw, go);
            /* leaf-stage body data: const value = the value assignment's own
             * integer (expr->value->value.v_integer — the exact field
             * asn1c_C.c:1264 prints), typed by the GOVERNING named type
             * (the ENUMERATED-governed form is the same numeric path —
             * asn1c emits a number for both INTEGER- and ENUM-governed,
             * asn1c_C.c:1257-1263, no enumerator symbol). */
            if(expr->value) {
                char *gov_go = go_type_go(governing);
                go_row_set_const(ctx->bag,
                              asn1p_itoa(expr->value->value.v_integer), gov_go);
                free(gov_go);
            }
        }
        return 0;
    }

    /* Class / object / set defs have no Go name; their specializations mint
     * clones walked above (go_walk.c walk_expr:460-467). */
    if(expr->meta_type == AMT_OBJECTCLASS
       || expr->meta_type == AMT_OBJECT
       || expr->meta_type == AMT_VALUESET)
        return 0;

    /* Type assignment: one `type` row. goName = R2(MKID(expr)) (a reference
     * assignment mints its OWN named Go type — not chased to terminal). */
    char *type_go = go_type_go(expr);
    char *type_cid = go_own_mkid(expr);   /* real asn1c C-ident of this assignment */
    const char *ident = expr->Identifier ? expr->Identifier : "?";
    char *type_path = go_make_path("", ident);

    asn1p_expr_t *terminal = expr;
    if(expr->expr_type == A1TC_REFERENCE || expr->meta_type == AMT_TYPEREF) {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, expr);
        if(t) terminal = t;
    }
    go_construct_e k = go_construct_classify(terminal);

    /* a parameterized-type TEMPLATE emits nothing in Go. A parameterized
     * type's clones are reached via the specialization-recursion loop above
     * (lhs_params && spec_index==-1); asn1c attaches each clone's module back-
     * pointer to the TEMPLATE's module (e.g. the container module for every
     * ProtocolIE-Container specialization), so a .h-banner module attribution
     * would wrongly place a swarm of names in the clone-header module. The Go
     * placement is instead: a container/template clone that is NOT field-shaped
     * emits no name at all (the clone's args — the bound ItemIEs / list element
     * — mint their own names in their defining module during their own walks),
     * and a field-shaped clone mints R2(X) in X's module (see go_emit_spec below).
     * `spec_index >= 0` marks a clone (a hand-authored top-level assignment keeps
     * spec_index == -1 via the lhs_params check). A plain_clone (T{X} ::=
     * SEQUENCE { v X } as T{INTEGER}) is the exception: it is named like any
     * top-level type assignment (T<N>P<k>) and walked below, but it is never
     * a PDU (asn1c lists no specialization in pdu_collection.c). Refuse here so a container clone
     * (ProtocolIE-Container / -ContainerPair specializations — a SEQUENCE OF
     * field-element) does not leak a `type` row + member `field` rows into the
     * template's module. */
    if(expr->spec_index >= 0
       && !(k == GO_CONSTR_SEQUENCE && go_is_field_shaped_spec(terminal))
       && !(expr == terminal && plain_clone(ctx, expr))) {
        free(type_cid);
        free(type_path);
        free(type_go);
        return 0;
    }

    /* a field-shaped specialization (SEQUENCE with an open-type &Value
     * member) is named as R2(X)+Value+ValuePr, NOT as a plain struct. It
     * carries no ordinary top-level type name of its own in the index (the
     * spec-key row IS its "type" name). Handle before the generic SEQUENCE walk
     * so the spec rows (not a colliding `type` + member `field` rows) win. */
    if(k == GO_CONSTR_SEQUENCE && go_is_field_shaped_spec(terminal)) {
        /* alias collapse: a field-shaped specialization whose ASSIGNMENT is a
         * type-reference alias (AMT_TYPEREF — e.g. ProtocolIE-SingleContainer
         * {{X}} ::= ProtocolIE-Field {{X}},asn1c emits the alias as a bare
         * `typedef <resolved_clone>_t <alias>_t;`) resolves to the SAME field-
         * shaped clone as the referenced parameterized type. That resolved clone
         * is named independently (the referenced type's own specialization walk
         * emits its spec-key, e.g. ActionToBeSetupItemIEs). The alias mints no
         * new name — collapse (emit nothing) so the two don't double-name one
         * C type. Same shape, not a collision. A directly-defined field-
         * shaped SEQUENCE has AMT_TYPE; only an alias-to-parameterized-type is
         * AMT_TYPEREF. */
        if(expr->meta_type == AMT_TYPEREF) {
            /* Flat (alias collapse): the alias clone emits a Flat
             * ALIAS of the resolved clone's Flat (e.g.
             * `typedef PFX_Action_ToBeSetup_ItemIEs_flat
             * ProtocolIE_SingleContainer_88P0_flat;`). The alias cid is the
             * clone's own ACE id (BARE name, no run prefix on clone family
             * names); the target is the resolved field-shaped clone's cid. */
            char *resolved_cid = NULL;
            const char *resolved_module = ctx->module;
            {
                asn1p_expr_t *rt = asn1f_find_terminal_type_ex(
                    ctx->asn, ctx->ns, expr);
                if(rt) {
                    resolved_cid = go_own(GO_MKID(rt));
                    /* the alias lives in X's module — the
                     * module that DEFINES the bound object set — resolved
                     * the same way go_emit_spec does (asn1c_get_ioc_table's
                     * objset->module; the clone's own ->module back-pointer
                     * names the TEMPLATE's module (the container module), which
                     * would strand the alias in a header that never
                     * includes its target). */
                    arg_t a2;
                    memset(&a2, 0, sizeof a2);
                    a2.asn = ctx->asn;
                    a2.ns = ctx->ns;
                    a2.expr = rt;
                    asn1c_ioc_table_and_objset_t ioc2 =
                        asn1c_get_ioc_table(&a2);
                    if(ioc2.objset && ioc2.objset->module
                       && ioc2.objset->module->ModuleName)
                        resolved_module = ioc2.objset->module->ModuleName;
                }
            }
            if(resolved_cid) {
                (void)go_flat_alias_bare(type_cid, resolved_cid,
                                         resolved_module);
                free(resolved_cid);
            }
            free(type_cid);
            free(type_path);
            free(type_go);
            return 0;
        }
        go_emit_spec(ctx, type_go, type_cid, ident, terminal);
        /* Conv (the entry-point rule, as below): a hand-written field-shaped
         * SEQUENCE (not a parameterized clone) is a PDU root like any other
         * SEQUENCE; asn1c lists it in pdu_collection.c too. */
        if(expr->spec_index < 0 && !expr->lhs_params
           && go_pdu_selected(expr))
            go_pdu_record(expr, GO_MKID(terminal));
        free(type_cid);
        free(type_path);
        free(type_go);
        return 0;
    }

    /* A type assignment that only renames a SEQUENCE, SET or CHOICE
     * (Alias ::= Msg, TAlias ::= [APPLICATION 5] Msg, Inst ::= T{INTEGER}):
     * C has `typedef Msg_t Alias_t;` and its own descriptor asn_DEF_Alias
     * (its own tags, name and constraints). Go declares `type Alias Msg`
     * (no Flat of its own, no member names) and gives it its own
     * Encode/Decode functions on asn_DEF_Alias over Msg's converters. A
     * member of type Alias is a Msg field, as before. */
    if(terminal != expr
       && (k == GO_CONSTR_SEQUENCE || k == GO_CONSTR_CHOICE)) {
        go_emit_name(ctx->bag, ctx->module, type_path, GK_TYPE,
                  type_cid ? strdup(type_cid) : strdup(""), strdup(type_go));
        ctx->bag->rows[ctx->bag->n_rows - 1].alias_of = go_type_go(terminal);
        if(!expr->lhs_params && expr->spec_index < 0 && go_pdu_selected(expr))
            go_pdu_record_alias(expr, type_cid, GO_MKID(terminal), type_go,
                                ctx->module);
        free(type_cid);
        free(type_go);
        return 0;
    }

    /* For a SEQUENCE/CHOICE/ENUM the type row's goName both goes in the dump
     * and parents the member names; emit it after computing k so a failed
     * classify doesn't leave a half-name. The member path root is `ident`. The
     * type row's rawCid (= type_cid) is the verbatim asn1c C-struct identifier;
     * the value is handed off (owned) to go_emit_name here. */
    go_emit_name(ctx->bag, ctx->module, type_path, GK_TYPE,
              type_cid ? type_cid : strdup(""), type_go);
    /* Conv (the entry-point rule): record a PDU root — mirror asn1c's own membership rule
     * (include_type_to_pdu_collection, asn1c_save.c): included iff a
     * type_cb exists for the (meta_type, expr_type) — a constructed type we
     * emitted a row for — AND not AMT_VALUE AND no lhs_params AND the -pdu
     * options select it (go_pdu_selected). */
    {
        int lang_cb = (k == GO_CONSTR_SEQUENCE || k == GO_CONSTR_CHOICE
                       || k == GO_CONSTR_SEQUENCE_OF
                       || k == GO_CONSTR_INTEGER || k == GO_CONSTR_BOOLEAN
                       || k == GO_CONSTR_NULL || k == GO_CONSTR_REAL
                       || k == GO_CONSTR_OCTET_STRING
                       || k == GO_CONSTR_BIT_STRING
                       || k == GO_CONSTR_OID
                       || k == GO_CONSTR_STRING
                       || k == GO_CONSTR_ENUMERATED);
        if(lang_cb && !expr->lhs_params && expr->spec_index < 0
           && go_pdu_selected(expr)) {
            if(terminal != expr)    /* NumA ::= Num: its own descriptor */
                go_pdu_record_alias(expr, type_cid, GO_MKID(terminal),
                                    type_go, ctx->module);
            else
                go_pdu_record(expr, GO_MKID(terminal));
        }
    }
    /* leaf-stage body data: a LEAF type assignment's declaration is
     * `type <goName> <underlying>` (every type assignment is a named Go
     * type; only inline constructs use the mapping-table type directly — a plain or
     * reference leaf assignment is named). go_classify_leaf resolves the
     * underlying via asn1c's own machinery (asn1c_type_fits_long for INTEGER,
     * asn1c_misc.c:408; the leaf classifier for the rest). Constructed
     * kinds (SEQUENCE/CHOICE/SEQ-OF) carry GLEAF_NONE — their bodies are
     * the struct-body stage; ENUMERATED classifies GLEAF_ENUM and pairs with the go_emit_enum
     * const values below. */
    if(k != GO_CONSTR_SEQUENCE && k != GO_CONSTR_CHOICE
       && k != GO_CONSTR_SEQUENCE_OF) {
        int lk = go_classify_leaf(ctx, terminal, ident);
        go_row_set_leaf(ctx->bag, lk);
        /* Flat: the leaf mint rides the SAME classification (one decision,
         * both columns; leaf = bare typedef of the mapping-table Flat prim). */
        if(lk == GLEAF_NULL) {
            /* a NULL type mints a hidden int32 placeholder leaf, only so
             * that a SEQUENCE OF this type has an element to resolve */
            (void)go_flat_leaf(type_cid, "int32_t", ctx->module);
            go_flat_mark_null_leaf();
        } else
            go_flat_leaf_gleaf(type_cid, lk, ctx->module);
        go_flat_label_cur(terminal->Identifier);   /* td->name label */
    }

    if(k == GO_CONSTR_BIT_STRING)
        go_mark_bitstring_module(ctx->bag, ctx->module);
    /* A named-bit BIT STRING assignment: `type X BitString` plus the bit
     * positions as int constants. Only the defining assignment gets them (an
     * alias `Y ::= X` does not redeclare X's bits). */
    if(k == GO_CONSTR_BIT_STRING && terminal == expr
       && expr->expr_type == ASN_BASIC_BIT_STRING
       && expr->meta_type != AMT_TYPEREF && TQ_FIRST(&expr->members))
        go_emit_bit_names(ctx, type_go, type_cid, ident, expr);

    int rc = 0;
    if(k == GO_CONSTR_SEQUENCE) {
        /* Flat: struct mint before the member walk (members land on it).
         * display label: the td->name of this typedef = the asn_DEF-owning
         * entity's ASN.1 name (the reference-chased terminal for a
         * reference assignment; the assignment itself otherwise). */
        (void)go_flat_struct(type_cid, ctx->module);
        go_flat_label_cur(terminal->Identifier);
        const char *save_go = ctx->parent_go;
        const char *save_cid = ctx->parent_cid;
        ctx->parent_go = type_go;
        ctx->parent_cid = type_cid;   /* borrowed for the duration of this walk */
        go_reset_field_scope(ctx->bag);
        /* struct-body stage: SEQUENCE type rows declare Go structs; their member fields
         * attach to the struct scope opened here. */
        go_row_set_is_struct(ctx->bag);
        go_struct_scope_open(ctx->bag, type_go);
        rc = go_walk_names_members(ctx, expr, ident);
        go_struct_scope_reset(ctx->bag);
        ctx->parent_go = save_go;
        ctx->parent_cid = save_cid;
    } else if(k == GO_CONSTR_CHOICE) {
        go_emit_choice(ctx, type_go, type_cid, ident, terminal);
        if(terminal != expr) {
            /* `A ::= B` (B a CHOICE): C has only `typedef B_t A_t;` */
            char *tcid = go_own_mkid(terminal);
            go_flat_mark_c_alias(type_cid, tcid);
            free(tcid);
        }
    } else if(k == GO_CONSTR_ENUMERATED) {
        go_emit_enum(ctx, type_go, type_cid, ident, terminal);
    } else if(k == GO_CONSTR_SEQUENCE_OF) {
        /* slice stage (the slice-alias naming rule): a SEQUENCE-OF type assignment declares
         * the named slice alias `type X []Elem` right at its own `type` row
         * (emitted above; no row appended between it and here). SIZE
         * constraints and a `...` do not change the shape. The ELEMENT carries
         * the same one-resolver rule as every slice shape
         * (go_slice_element_type): a reference element is the assignment's
         * own goName (qualified by the prepass), an inline
         * leaf is the mapping-table column, an inline element is minted as
         * <Type>Member by go_mint_inline_seqof_elem (below). */
        asn1p_expr_t *elem = TQ_FIRST(&terminal->members);
        if(elem && elem->expr_type == ASN_BASIC_BIT_STRING)
            go_mark_bitstring_module(ctx->bag, ctx->module);
        if(go_seqof_elem_is_inline(elem)) {
            /* an inline element is named after the assignment that DECLARES
             * the SEQUENCE OF (the terminal): its own for a plain assignment,
             * the chased one for an alias `U ::= T` (the element is reused
             * by the minted-element table). */
            int owner_row = ctx->bag->n_rows - 1;
            char *ogo, *ocid;
            const char *opath;
            if(terminal == expr) {
                ogo = strdup(type_go); ocid = strdup(type_cid); opath = ident;
            } else {
                const char *tmod = terminal->module
                    ? terminal->module->ModuleName : NULL;
                if(!tmod || !ctx->module || strcmp(tmod, ctx->module) != 0) {
                    fprintf(stderr,
                            "asn1cgo: SEQUENCE OF with an inline element "
                            "type reached through a type assignment of "
                            "another module is not supported in module "
                            "%s: %s\n",
                            ctx->module ? ctx->module : "?", ident);
                    ctx->bag->failed = 1;
                    return -1;
                }
                ogo = go_type_go(terminal);
                ocid = go_own_mkid(terminal);
                opath = terminal->Identifier ? terminal->Identifier : ident;
            }
            char *ge = NULL, *fc = NULL;
            int mrc = go_mint_inline_seqof_elem(ctx, elem, opath, ogo, ocid,
                                             &ge, &fc);
            free(ogo); free(ocid);
            if(mrc < 0) { free(ge); free(fc); return -1; }
            go_row_set_slice_elem_at(ctx->bag, owner_row, ge);
            (void)go_flat_seqof(type_cid, fc, 0,
                               terminal->expr_type == ASN_CONSTR_SET_OF,
                               ctx->module);
            go_flat_label_cur(terminal->Identifier);
            free(ge); free(fc);
            return 0;
        }
        {
            char *selem = go_slice_element_type(ctx, elem, ident);
            if(ctx->bag->failed) {
                free(selem);
                return -1;
            }
            go_row_set_slice_elem(ctx->bag, selem);
            /* Flat: the named SEQ OF — the element cid is the
             * chased terminal's own cid (a reference element; an inline
             * leaf element already failed loud above). A SingleContainer
             * clone element takes its BARE clone id (the
             * 88P0 list's items read ProtocolIE_SingleContainer_88P0_flat,
             * the alias of the ItemIEs Flat). */
            {
                asn1p_expr_t *eterm = elem;
                if(elem->expr_type == A1TC_REFERENCE
                   || elem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *et = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, elem);
                    if(et) eterm = et;
                }
                char *flat_eterm = go_own(GO_MKID(eterm));
                if(eterm->spec_index >= 0
                   && go_is_struct_kind(eterm->expr_type)
                   && go_is_field_shaped_spec(eterm)) {
                    /* the SingleContainer clone: elem = the bare clone id
                     * (the alias node of the resolved ItemIEs Flat — minted
                     * once; the alias's target resolve is by cid). */
                    char *bare = go_own(GO_MKID(eterm));
                    /* keep the _<N>P<n> slot suffix GO_MKID appended */
                    const char *pfx = asn1c_prefix();
                    size_t pl = pfx ? strlen(pfx) : 0;
                    if(pl && strncmp(bare, pfx, pl) == 0) {
                        memmove(bare, bare + pl, strlen(bare + pl) + 1);
                    }
                    /* GUARD: mint the 88P0 alias ONLY when the clone id and
                     * the resolved ItemIEs id DIFFER — an in-place-resolved
                     * chase (post-fix AST) gives eterm == the ItemIEs and
                     * would mint a self-alias whose cid hijacks the ItemIEs
                     * STRUCT node by dedup (the bare-name ItemIEs bug). */
                    const char *of_bare = flat_eterm;
                    if(pl && strncmp(of_bare, pfx, pl) == 0)
                        of_bare += pl;
                    (void)go_flat_seqof(type_cid, bare, 0,
                                       terminal->expr_type == ASN_CONSTR_SET_OF,
                                       ctx->module);
                    go_flat_label_cur(terminal->Identifier);
                    if(strcmp(bare, of_bare) != 0) {
                        char *alias_cid = go_own(bare);
                        (void)go_flat_alias_bare(alias_cid, flat_eterm,
                                                 ctx->module);
                        free(alias_cid);
                    }
                    free(bare);
                } else {
                    (void)go_flat_seqof(type_cid, flat_eterm, 0,
                                        terminal->expr_type == ASN_CONSTR_SET_OF,
                                        ctx->module);
                    go_flat_label_cur(terminal->Identifier);
                }
                free(flat_eterm);
            }
            free(selem);
        }
    }
    return rc;
}
