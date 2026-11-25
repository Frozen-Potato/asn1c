/*
 * go_names_choice.c — the names of a CHOICE (discriminant type,
 * consts, alt fields), an ENUMERATED (consts) and a BIT STRING (named
 * bits).
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

static char *go_list_suffix(asn1p_expr_t *list, asn1p_expr_t *e);

/* ========================================================================= *
 * Walkers — mirror go_walk.c's walk_expr / walk_child / walk_members, but
 * resolve Go names instead of classifying for the support gate. The structural
 * decisions are the SAME (parameterized-specialization iteration; skip
 * OBJECTCLASS / OBJECT / VALUESET; inline-only recursion via the child's own
 * .members; reference resolution via asn1f_find_terminal_type_ex), so the two
 * walks visit the same (module, path) node set. Naming rule invoked per node
 * is cited inline by asn1c path:line. The member path passed down is the
 * ASN.1 dotted path; the parent goName (ctx->parent_go) is the inline prefix.
 * ========================================================================= */

/* go_emit_choice / go_emit_enum are mutually recursive (a CHOICE alt may be an inline
 * CHOICE/ENUM). Both are defined just below; declared here so either may call the
 * other. Both take choice_go/enum_go (the Go name — the dump goName and the parent
 * prefix for nested inline names) AND choice_cid/enum_cid: the REAL asn1c C
 * identifier prefix of this construct, compounded exactly as asn1c does
 * (GO_MKID(expr) at top level; parent-real-cid + "__" + member-real-cid for an
 * inline). rawCid for every discriminant/const row is built FROM the real cid, so
 * it is the verbatim symbol asn1c stamps into the .h (e.g. ENB_ID_PR for the
 * ENB-ID choice, not the _-collapsed ENBID_PR the Go name would yield; an inline
 * choice's tag is <ParentCid>__<memberCid>_PR). goName and path are unaffected. */
void go_emit_choice(struct walk_ctx *ctx, const char *choice_go,
                 const char *choice_cid, const char *parent_path,
                 asn1p_expr_t *choice_expr);
void go_emit_enum(struct walk_ctx *ctx, const char *enum_go,
               const char *enum_cid, const char *parent_path,
               asn1p_expr_t *enum_expr);
void go_emit_bit_names(struct walk_ctx *ctx, const char *type_go,
                    const char *type_cid, const char *type_path,
                    asn1p_expr_t *bs);

/* Emit choice discriminant rows for a CHOICE whose goName is `choice_go` and real
 * C-ident prefix is `choice_cid`, at path prefix `parent_path`. choice_expr is the
 * CHOICE construct whose .members are the alts. Emits one choice-pr, a PrNothing
 * choice-const, one choice-const per alt, AND one field per alt (pointer per alt — the alt
 * data-pointer set, struct-scoped to this CHOICE). rawCids are built from
 * choice_cid (the verbatim asn1c symbol). */
void
go_emit_choice(struct walk_ctx *ctx, const char *choice_go,
            const char *choice_cid, const char *parent_path,
            asn1p_expr_t *choice_expr) {
    /* CHOICE emission: the CHOICE's own type/inline row (emitted by the caller just
     * before this call on ALL three call paths — go_walk_names_expr's top-level
     * GK_TYPE row, walk_names_child's inline GK_INLINE row, and go_emit_choice's
     * own recursion below) is declared `type <Choice> struct {...}` over the
     * Present + alt field rows this function records. Capture the owner row
     * INDEX here — at entry it is n_rows-1, but the choice-pr emit below
     * appends rows, so an n_rows-1 mark after it would stamp the PR row (the
     * live bug: `type BinRangeValuePr struct {}` + a MISSING BinRangeValue). */
    int owner_ix = ctx->bag->n_rows - 1;
    /* Flat: the CHOICE struct rides the owner row above (walk order:
     * members land on the most-recent go_flat_struct). is_choice rides
     * the mint via the go_flat_choice flag hook. */
    go_flat_choice(choice_cid, ctx->module);
    go_flat_label_cur(choice_expr->Identifier);   /* td->name label */
    /* choice-pr: <Choice>Pr (discriminant-type name). rawCid = <Cid>_PR, the
     * verbatim asn1c `<Choice>_PR` enum tag (not the _-collapsed Go name + _PR). */
    {
        char *raw = go_str_append(strdup(""), choice_cid);
        raw = go_str_append(raw, "_PR");
        char *go = go_str_append(strdup(""), choice_go);
        go = go_str_append(go, "Pr");
        char *path = go_make_path(parent_path, "Pr");
        go_emit_name(ctx->bag, ctx->module, path, GK_CHOICE_PR, raw, go);
    }
    go_reset_field_scope(ctx->bag);    /* CHOICE is one struct for field scope */
    go_row_set_is_struct_at(ctx->bag, owner_ix);
    go_struct_scope_open(ctx->bag, choice_go);
    /* choice-const: <Choice>PrNothing. rawCid = <Cid>_PR_NOTHING. Value 0:
     * asn1c's _PR enum lists NOTHING first with no explicit value
     * (asn1c_C.c:984), so the implicit numbering makes NOTHING=0 (the
     * `<T>PrNothing <T>Pr = 0` row, the const-naming rule). The const's TYPE is the
     * discriminant <Choice>Pr (e.g. `MsgPrNothing MsgPr = 0`),
     * not the CHOICE struct itself (the struct body). */
    {
        char *raw = go_str_append(strdup(""), choice_cid);
        raw = go_str_append(raw, "_PR_NOTHING");
        char *go = go_str_append(strdup(""), choice_go);
        go = go_str_append(go, "PrNothing");
        char *type_go = go_str_append(strdup(""), choice_go);
        type_go = go_str_append(type_go, "Pr");
        char *path = go_make_path(parent_path, "PrNothing");
        go_emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
        go_row_set_const(ctx->bag, "0", type_go);
        free(type_go);
    }
    /* The CHOICE Go struct carries a `Present <Choice>Pr` discriminant field
     * (the holder that selects an alt); emit it as a struct-scoped field
     * alongside the alt fields. rawCid = the asn1c `present` member token
     * VERBATIM — a generic CHOICE's discriminant holder is the C member
     * `present` (constr_CHOICE.h: `Present <X>_PR present;`), not a compound
     * <Cid>_present. Storing the literal `present` makes the dump's rawCid a
     * real .h identifier token AND makes goName = R2("present") = "Present" —
     * no special case on either side (token + R2 checks both pass
     * unaided). */
    {
        char *path = go_make_path(parent_path, "Present");
        go_emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  strdup("present"), strdup("Present"));
        /* CHOICE emission: `Present <Choice>Pr` (the discriminant holder;
         * by VALUE, never a pointer: it is the selector, not an alt slot). */
        char *pt = go_str_append(strdup(""), choice_go);
        pt = go_str_append(pt, "Pr");
        go_row_set_field_type(ctx->bag, pt);
        free(pt);
    }
    /* Flat: the present member is the int32 prim row (the CHOICE mapping
     * row: present-first as a prim column). */
    go_flat_member_prim("int32_t", "present", 0);
    asn1p_expr_t *alt;
    int alt_seq = 0;   /* _PR value: sequential over emitted alts (asn1c_C.c
                        * :985-996 lists NOTHING + alts with NO explicit
                        * values, so implicit numbering 0,1,2... follows the
                        * TQ_FOR order; the PrNothing row above consumed 0). */
    TQ_FOR(alt, &(choice_expr->members), next) {
        if(alt->expr_type == A1TC_EXTENSIBLE) continue;       /* "..." */

        /* A BIT.STRING alt marks this module for the BitString helper (the same
         * membership the plain-member chase applies; a CHOICE alt may be a plain
         * inline BIT STRING or a reference to one). */
        {
            asn1p_expr_t *at = alt;
            if(alt->expr_type == A1TC_REFERENCE || alt->meta_type == AMT_TYPEREF) {
                asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt);
                if(t) at = t;
            }
            if(go_construct_classify(at) == GO_CONSTR_BIT_STRING)
                go_mark_bitstring_module(ctx->bag, ctx->module);
        }
        /* An alt that is itself an inline constructed type (plain inline SEQ/
         * CHOICE/ENUM) mints the inline naming + alts, exactly as a struct
         * member does — recurse over it via walk_names_child. Prefix: the alt
         * PART of every _PR_ token is an unprefixed member token
         * (c_presence_name's suffix, asn1c_naming.c:304 — make_identifier
         * flags 0), and the alt's own field row carries the unprefixed
         * member-decl token (MKID_safe, asn1c_C.c:1353). One unprefixed
         * string serves both. */
        char *altcid = go_mk_suffix(alt);
        char *altgo = go_list_suffix(choice_expr, alt);
        {
            /* layout / glue name the alt's slot and constant by camel-casing
             * its token: tell them the alt spelling (also for a NULL alt) */
            char *at_ = go_mk_member(alt);
            go_alt_register(choice_cid, at_, altgo);
            go_alt_register(choice_cid, altcid, altgo);
            free(at_);
        }
        /* choice-const <Choice>Pr<Alt>; rawCid = <Cid>_PR_<AltCid> (the verbatim
         * asn1c enum-member token <Choice>_PR_<AltCid>). <Cid> is the
         * aggregate prefixed form; the alt part is unprefixed. */
        {
            char *raw = go_str_append(strdup(""), choice_cid);
            raw = go_str_append(raw, "_PR_");
            raw = go_str_append(raw, altcid);
            char *go = go_str_append(strdup(""), choice_go);
            go = go_str_append(go, "Pr");
            go = go_str_append(go, altgo);
            char *type_go = go_str_append(strdup(""), choice_go);
            type_go = go_str_append(type_go, "Pr");
            char *path = go_make_path(parent_path, alt->Identifier);
            go_emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
            /* Value: the next sequential _PR slot (PrNothing=0, alt i = i+1;
             * asn1c's _PR enum carries no explicit values — asn1c_C.c:985-996
             * — so the implicit numbering follows the TQ_FOR alt order).
             * asn1p_itoa's ring buffer makes one call per row safe. */
            go_row_set_const(ctx->bag, asn1p_itoa(++alt_seq), type_go);
            free(type_go);
        }
        /* field row: the alt's data pointer. struct-scoped to CHOICE.
         * CHOICE emission: the alt field's TYPE — always a POINTER ("every alt a
         * pointer, leaves included"; the emitted structs carry *BitString for a
         * BIT-STRING alt, *uint64 for an INTEGER alt, and NO field at all for
         * a NULL alt — a NULL alt emits no Go field, only its Pr const
         * (the C union member is NULL_t, a zero-size payload; a CHOICE with
         * NULL alts emits no field for them while
         * still emitting their Pr consts; the glue never raises
         * E_CHOICE_BAD for a selected NULL alt). So NO field row at all is
         * emitted for a NULL alt, keyed on the chased terminal's class ==
         * GO_CONSTR_NULL — and the dump carries no such row either (the
         * index side drops it in lockstep). The pointee follows the
         * member rules: the minted <Choice><Alt> name for an inline alt (the
         * block below mints it in this same iteration), the named
         * assignment's own Go name for a reference alt, the mapping-table Go
         * column for a plain inline leaf alt (go_classify_leaf — the SAME table
         * the decl emission uses; never re-spelled here). The star is NOT the
         * OPTIONAL star (go_member_stars): a CHOICE alt is a pointer by construction
         * whatever its marker — "*" + pointee unconditionally. */
        /* The alt's terminal (the BIT STRING chase above already resolved
         * it, but into a nested scope; re-chase here for the type — and
         * BEFORE the field emit: a NULL terminal suppresses the row ENTIRELY
         * as a NULL alt, not just its type). */
        {
            asn1p_expr_t *aterm = alt;
            if(alt->expr_type == A1TC_REFERENCE || alt->meta_type == AMT_TYPEREF) {
                asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt);
                if(t) aterm = t;
            }
            if(go_construct_classify(aterm) == GO_CONSTR_NULL) {
                /* a NULL alt emits NO Go field, only its Pr const —
                 * the shape of a CHOICE with NULL alts (they carry
                 * consts but no field; the C union member
                 * is NULL_t, a zero-size payload). The dump emits NO field
                 * row for it either (the index side drops it in lockstep) —
                 * NOT an empty-typed row: the dump invariant rejects
                 * blank rows, and Check A expects no such field. Conv: the
                 * generated switch still carries its bare `case ..._PR_<alt>:
                 * break;` (a selected NULL alt must not fall to BAD). */
                go_conv_record_null_alt(choice_cid, altcid);
                free(altgo);
                free(altcid);
                continue;
            }
            char *path = go_make_path(parent_path, alt->Identifier);
            /* An alt whose field name would be `Present` collides with the
             * discriminant field (public API, kept as is): the FIELD gets the
             * deterministic name PresentAlt. The <Choice>Pr<Alt> constant
             * (TPrPresent) and the inline type name keep altgo. The renamed
             * field is registered like any other, so an alt literally named
             * `presentAlt` is still reported as a collision. */
            go_emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      go_own(strcmp(altcid, "present") == 0 ? "presentAlt" : go_mk_member(alt)),
                      strdup(strcmp(altgo, "Present") == 0 ? "PresentAlt" : altgo));
            /* Flat slot: a POINTER iff asn1c's union member for
             * this alt is one — the EM_INDIRECT marker expr_break_recursion
             * stamped (masked test; leaf CHOICEs are
             * all-inline, structured CHOICEs pointer-per-alt under
             * -findirect-choice). The pointee cid: the minted inline
             * compound for an inline-alt (rendered by the same rules below),
             * the terminal's own cid for a reference alt, or a prim for a
             * plain inline leaf alt (none in scope: all data-bearing leaf
             * alts here are BIT STRING / INTEGER / REAL prims — the same
             * go_classify_leaf table). */
            {
                int cstars = 0;
                int cwide = 0, clk = 0;
                char *ccid = NULL;
                const char *cprim = NULL;
                const char *star_tok = go_mk_suffix(alt);
                (void)star_tok;
                if((alt->marker.flags & EM_INDIRECT)) cstars = 1;
                if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                    /* an inline ENUMERATED alt collapses to the bare int32
                     * slot (the ENUMERATED mapping row, the same form used
                     * for inline-enum members; the .h e_<X>__<alt> enum tag
                     * is not a scalar alias) — NO named alt leaf is minted
                     * on the Flat side (a minted leaf would not match the C
                     * flat naming). */
                    cprim = "int32_t";
                } else if(go_is_struct_kind(alt->expr_type)
                          || alt->expr_type == ASN_CONSTR_CHOICE
                          || go_is_list_kind(alt->expr_type)) {
                    /* inline constructed alt: pointee = the __-compound cid
                     * the mint below creates; prim-form slot when inline */
                    char *ac = go_mk_suffix(alt);
                    ccid = go_cid_compound(choice_cid, "__", ac);
                    free(ac);
                    /* an inline CHOICE/SEQ alt under -findirect-choice
                     * carries EM_INDIRECT (constructed terminal) — cstars
                     * already 1; without the flag (leaf alts) EM_INDIRECT
                     * never set: inline slot. */
                } else if(alt->expr_type == A1TC_REFERENCE
                          || alt->meta_type == AMT_TYPEREF || aterm != alt) {
                    ccid = go_own(GO_MKID(aterm));
                } else {
                    /* a plain inline leaf alt: the mapping-table Flat prim slot. */
                    ctx->wide_nr = 1; ctx->wide_hit = 0;
                    int lk = go_classify_leaf(ctx, aterm, parent_path);
                    clk = lk;
                    cwide = ctx->wide_hit;
                    ctx->wide_nr = 0; ctx->wide_hit = 0;
                                        cprim = go_leaf_flat_prim(lk);
                }
                {
                    /* altcid borrows the shared static buffer (go_mk_suffix);
                     * own it before the mint (the same aliasing trap). */
                    char *flat_acid = go_own(altcid);
                    int alt_is_present = strcmp(altcid, "present") == 0;
                    /* the flat slot is a C struct field: a reserved word is
                     * upcased as asn1c does for the union member; the _PR
                     * suffix (tree_token) keeps the lower-case spelling */
                    char *flat_mem = go_mk_member(alt);
                    char *flat_atok = go_own(alt_is_present ? "presentAlt" : flat_mem);
                    if(cprim) {
                        go_flat_member_prim(cprim, flat_atok, cstars);
                        if(cwide) go_flat_last_member_wide();
                        go_flat_last_member_gleaf(clk);
                    } else if(ccid)
                        go_flat_member_ref(ccid, flat_atok, cstars);
                    /* CHOICE alt member label = the alt's own ASN.1
                     * Identifier (the td-member name). */
                    go_flat_label_last_member(alt->Identifier);
                    if(alt_is_present && (cprim || ccid))
                        go_flat_last_member_tree_token("present");
                    if(!alt_is_present && (cprim || ccid)
                       && strcmp(flat_mem, flat_acid) != 0) {
                        go_flat_last_member_tree_token(flat_acid);
                        go_flat_last_member_tree_member(flat_mem);
                    }
                    free(flat_acid); free(flat_atok); free(flat_mem);
                }
                free(ccid);
            }
            {
                char *ft = NULL;
                if(alt->expr_type == ASN_BASIC_ENUMERATED
                   || go_is_struct_kind(alt->expr_type)
                   || alt->expr_type == ASN_CONSTR_CHOICE
                   || go_is_list_kind(alt->expr_type)) {
                    /* An inline constructed alt: typed by its minted
                     * <Choice><Alt> name (the anonymous-inline naming
                     * rule), same-module. */
                    ft = go_str_append(strdup(""), choice_go);
                    ft = go_str_append(ft, altgo);
                } else if(alt->expr_type == A1TC_REFERENCE
                          || alt->meta_type == AMT_TYPEREF || aterm != alt) {
                    /* A reference alt: the terminal assignment's own Go name
                     * (leaf or constructed alike). Stored UNQUALIFIED;
                     * the post-walk prepass (go_qualify_field_types) applies cross-module qualification
                     * cross-module qualification once the bag is complete. */
                    char *tgo = go_type_go(aterm);
                    ft = go_str_append(strdup(""), tgo);
                    free(tgo);
                } else {
                    /* A plain inline leaf alt: the shared mapping table. */
                    ctx->wide_nr = 1;
                    int lk = go_classify_leaf(ctx, aterm, parent_path);
                    ctx->wide_nr = 0; ctx->wide_hit = 0;
                    const char *under = go_types_leaf_underlying(lk);
                    if(under) ft = go_own(under);
                }
                if(ft) {
                    char *sft = go_str_append(strdup(""), "*");
                    sft = go_str_append(sft, ft);
                    go_row_set_field_type(ctx->bag, sft);
                    free(sft); free(ft);
                }
            }
        }
        /* An alt that is an inline ENUMERATED mints the named type
         * <Choice><Alt> + enum-consts under it (e.g. Cond-Type.rate ->
         * CondTypeRate; the real .h compounds the parent into the enum and
         * every enumerator). An inline CHOICE alt mints <Choice><Alt> too and
         * recurses via go_emit_choice (the CHOICE pass: that recursion now marks its own
         * inline row a struct owner + types its alt slots). An inline SEQUENCE
         * alt mints <Choice><Alt> and walks its members (go_walk_names_members —
         * the struct-body machinery; the alt slot's type above points
         * at the minted name). The real C-ident compounds by `__`:
         * <choice_cid>__<altcid>, matching asn1c's nested tag form. An inline
         * SEQUENCE-OF alt mints the slice alias <Choice><Alt> below, with its
         * element named by go_mint_inline_seqof_elem when that is inline too. */
        if(alt->expr_type == ASN_BASIC_ENUMERATED
           || go_is_struct_kind(alt->expr_type)
           || alt->expr_type == ASN_CONSTR_CHOICE) {
            char *inline_go = go_str_append(strdup(""), choice_go);
            inline_go = go_str_append(inline_go, altgo);
            /* an inline tag is an AGGREGATE name — prefix once, parts
             * unprefixed (asn1c's compound tag PFX_X__y, never PFX_X__PFX_y;
             * construct_base_name flag=0, asn1c_naming.c:185-186). */
            char *inline_cid = go_cid_compound(choice_cid, "__", altcid);
            char *alt_path = go_make_path(parent_path, alt->Identifier);
            {
                char *raw = strdup(inline_cid);
                char *go = strdup(inline_go);
                char *path = strdup(alt_path);
                go_emit_name(ctx->bag, ctx->module, path, GK_INLINE, raw, go);
                if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                    go_row_set_leaf(ctx->bag, GLEAF_ENUM);
                    /* Flat: NO leaf typedef mint for an inline-ENUM
                     * alt — the alt slot is the bare int32 prim above; a
                     * minted <P>__<alt>_flat leaf is unresolvable by the
                     * index (flat-name red) and unreferenced. */
                }
            }
            if(alt->expr_type == ASN_BASIC_ENUMERATED) {
                go_emit_enum(ctx, inline_go, inline_cid, alt_path, alt);
            } else {
                /* An inline CHOICE / SEQUENCE alt is a package-scoped Flat
                 * node of its own (the alt slot above is a ref to it; the C
                 * tree has only the struct tag `struct <choice>__<alt>`, so
                 * the conv file aliases `<cid>_t` to it: inline_elem
                 * "struct"). Both the Flat cur register and the Go
                 * struct-field scope belong to the ENCLOSING CHOICE again
                 * once the alt is done — an alt AFTER it must land on this
                 * CHOICE, not inside the inline one. */
                char *save_sf = NULL;
                if(ctx->bag->sf_cur_owner)
                    save_sf = strdup(ctx->bag->sf_cur_owner);
                int save_fcur = go_flat_cur_get();
                if(alt->expr_type == ASN_CONSTR_CHOICE) {
                    go_field_scope_push(ctx->bag);
                    go_emit_choice(ctx, inline_go, inline_cid, alt_path, alt);
                    go_field_scope_pop(ctx->bag);
                    /* go_emit_choice minted the node and left it cur */
                    go_flat_mark_inline_elem("struct", NULL);
                } else {   /* ASN_CONSTR_SEQUENCE: a struct with member fields */
                    const char *save_go = ctx->parent_go;
                    const char *save_cid = ctx->parent_cid;
                    go_flat_struct(inline_cid, ctx->module);
                    go_flat_label_cur(alt->Identifier);   /* td->name label */
                    go_flat_mark_inline_elem("struct", NULL);
                    ctx->parent_go = inline_go;
                    ctx->parent_cid = inline_cid;
                    go_field_scope_push(ctx->bag);
                    go_row_set_is_struct(ctx->bag);
                    go_struct_scope_open(ctx->bag, inline_go);
                    (void)go_walk_names_members(ctx, alt, alt_path);
                    go_struct_scope_reset(ctx->bag);
                    go_field_scope_pop(ctx->bag);
                    ctx->parent_go = save_go;
                    ctx->parent_cid = save_cid;
                }
                go_flat_cur_restore(save_fcur);
                free(go_bag_sf_restore(ctx->bag, save_sf));
            }
            free(inline_go); free(inline_cid); free(alt_path);
        } else if(alt->expr_type == ASN_BASIC_BIT_STRING
                  && TQ_FIRST(&alt->members)
                  && alt->meta_type != AMT_TYPEREF
                  && asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, alt)
                         == alt) {
            /* An inline named-bit BIT STRING alt: the alt is a plain
             * BitString; only the bit positions are named, as an inline
             * ENUMERATED alt would be (<Choice><Alt>). */
            char *bit_go = go_str_append(strdup(""), choice_go);
            bit_go = go_str_append(bit_go, altgo);
            char *bit_cid = go_cid_compound(choice_cid, "__", altcid);
            char *bit_path = go_make_path(parent_path, alt->Identifier);
            go_emit_bit_names(ctx, bit_go, bit_cid, bit_path, alt);
            free(bit_go); free(bit_cid); free(bit_path);
        } else if(go_is_list_kind(alt->expr_type)) {
            /* An inline SEQUENCE OF alt: the named slice `type <Choice><Alt>
             * []Elem`, a package-scoped Flat {items,count} node of the C
             * cid <choice>__<alt> (the alt slot is a pointer to it). The C
             * struct has only a tag (`struct T__a {..} *a`), no typedef. */
            char *sq_go = go_str_append(strdup(""), choice_go);
            sq_go = go_str_append(sq_go, altgo);
            char *sq_cid = go_cid_compound(choice_cid, "__", altcid);
            char *sq_path = go_make_path(parent_path, alt->Identifier);
            go_emit_name(ctx->bag, ctx->module, strdup(sq_path), GK_INLINE,
                      strdup(sq_cid), strdup(sq_go));
            int sq_row = ctx->bag->n_rows - 1;
            asn1p_expr_t *sq_elem = TQ_FIRST(&alt->members);
            int save_fcur = go_flat_cur_get();
            char *ge = NULL, *fc = NULL;
            int mrc = 0;
            if(sq_elem && sq_elem->expr_type == ASN_BASIC_BIT_STRING)
                go_mark_bitstring_module(ctx->bag, ctx->module);
            if(go_seqof_elem_is_inline(sq_elem)) {
                mrc = go_mint_inline_seqof_elem(ctx, sq_elem, sq_path, sq_go,
                                             sq_cid, &ge, &fc);
            } else {
                ge = go_slice_element_type(ctx, sq_elem, sq_path);
                if(ctx->bag->failed) mrc = -1;
                else {
                    asn1p_expr_t *et = sq_elem;
                    asn1p_expr_t *t2 = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, sq_elem);
                    if(t2) et = t2;
                    fc = go_own(GO_MKID(et));
                }
            }
            if(mrc >= 0 && !ctx->bag->failed) {
                go_row_set_slice_elem_at(ctx->bag, sq_row, ge);
                (void)go_flat_seqof(sq_cid, fc, 0,
                                     alt->expr_type == ASN_CONSTR_SET_OF,
                                     ctx->module);
                go_flat_mark_inline_elem("struct", NULL);
                go_flat_cur_restore(save_fcur);
            }
            free(ge); free(fc);
            free(sq_go); free(sq_cid); free(sq_path);
        }
        free(altgo);
        free(altcid);
    }
    go_struct_scope_reset(ctx->bag);
}

/* go_list_suffix: the Go suffix of member `e` of one ENUMERATED enumerator
 * list or one named-bit list `list`. Normally go_r2(go_mk_suffix(e)), which
 * drops every '_' (so `d1` and `d-1`, C suffixes `d1` and `d_1`, would both
 * become `D1`). The rule, local to the one list:
 *   1. compute the normal suffix go_r2(go_mk_suffix(m)) of every member;
 *   2. a member whose normal suffix equals another member's in the same list,
 *      AND whose C suffix has a '_' directly followed by a digit, uses the
 *      alternative form: go_r2, except that a '_' directly followed by a
 *      digit is kept (`d_1` -> `D_1`, `sfnsfndrift_5` -> `Sfnsfndrift_5`);
 *   3. every other member, and every list without such a clash, keeps the
 *      normal suffix, byte for byte;
 *   4. if the alternative names still collide, the usual collision error
 *      stays.
 * The result does not depend on member order. Malloc'd. */
static char *
go_list_suffix(asn1p_expr_t *list, asn1p_expr_t *e) {
    char *cid = go_mk_suffix(e);
    char *norm = go_r2(cid);
    int alt = 0;
    const char *u;
    for(u = cid; *u && !alt; u++)
        if(*u == '_' && isdigit((unsigned char)u[1])) alt = 1;
    if(alt) {
        int clash = 0;
        asn1p_expr_t *m;
        TQ_FOR(m, &(list->members), next) {
            if(m == e || m->expr_type == A1TC_EXTENSIBLE || !m->Identifier)
                continue;
            char *mc = go_mk_suffix(m);
            char *mn = go_r2(mc);
            if(strcmp(mn, norm) == 0) clash = 1;
            free(mc);
            free(mn);
            if(clash) break;
        }
        alt = clash;
    }
    char *out = norm;
    if(alt) {
        out = go_alt_spell(cid);
        free(norm);
    }
    free(cid);
    return out;
}

/* go_member_go: the Go segment of member `e` of a SEQUENCE / CHOICE: the
 * sibling-list rule of go_list_suffix (a hyphen clash between `a1` and `a-1`
 * keeps the '_' before the digit of the clashing one only). Every name built
 * from the member (field, inline type <Parent><Member>, <Choice>Pr<Alt>,
 * <Owner>Member) uses this one segment. Malloc'd. */
char *
go_member_go(asn1p_expr_t *e) {
    if(e->parent_expr && e->Identifier)
        return go_list_suffix(e->parent_expr, e);
    return go_r2(GO_MKID(e));
}

/* Emit enum-const rows for an ENUMERATED whose goName is `enum_go` and real
 * C-ident prefix is `enum_cid`, at path prefix `parent_path`. enumerators off
 * `enum_expr`. rawCid = <EnumCid>_<enumerator> (the verbatim asn1c enumerator
 * token: asn1c compounds the enum's C-ident prefix into every enumerator, so the
 * real token is `<enum_cid>` + "_" + GO_MKID(enumeratorChild)). goName is R2 of
 * that (=<Enum> + R2 of the enumerator suffix); path is unchanged.
 *
 * leaf-stage body data: each enum-const's VALUE is the enumerator's own ASN.1
 * value — e->value->value.v_integer, the exact field asn1c_C.c:152 prints as
 * " = N" (asn1fix_enum.c:97-99 assigns the sequential numbering for implicit
 * enumerators at fix time, so the AST value and the .h value are the same
 * number; asn1p_itoa renders it, asn1p_integer.h:39). goType is the enum's
 * own Go name (consts `<GoType>` + R2(name), typed by the enum type). */
void
go_emit_enum(struct walk_ctx *ctx, const char *enum_go,
          const char *enum_cid, const char *parent_path,
          asn1p_expr_t *enum_expr) {
    asn1p_expr_t *e;
    TQ_FOR(e, &(enum_expr->members), next) {
        if(e->expr_type == A1TC_EXTENSIBLE) continue;
        if(!e->Identifier) continue;
        /* real .h: `typedef enum <Cid> { <Cid>_reject, ... }`; the enumerator
         * child's identifier is the enumerator SUFFIX (asn1c compounds the type
         * prefix at emit, not into the child), so the real token is
         * <enum_cid> + "_" + suffix. For a top-level enum the two prefixes
         * coincide (enum_go == enum_cid); for an inline-or-hyphenated enum they
         * differ, and only the real cid reproduces the .h token verbatim.
         * the per-spec prefix rule: the suffix itself carries NO prefix AND NO reserved-word
         * upcasing (c_member_name's suffix is make_identifier(0, expr, 0),
         * asn1c_naming.c:304 — the real token is `..._true`, lowercase). */
        char *ecid = go_mk_suffix(e);
        char *raw = go_str_append(strdup(""), enum_cid);
        raw = go_str_append(raw, "_");
        raw = go_str_append(raw, ecid);
        char *ego = go_list_suffix(enum_expr, e);
        char *go = go_str_append(strdup(""), enum_go);
        go = go_str_append(go, ego);
        free(ego);
        char *path = go_make_path(parent_path, e->Identifier);
        go_emit_name(ctx->bag, ctx->module, path, GK_ENUM_CONST, raw, go);
        char *etype = go_str_append(strdup(""), enum_go);
        if(e->expr_type == A1TC_UNIVERVAL && e->value)
            go_row_set_const(ctx->bag, asn1p_itoa(e->value->value.v_integer),
                          etype);
        free(etype);
        free(ecid);
    }
}

/* go_emit_bit_names: the bit-position constants of a named-bit BIT STRING
 * (`BIT STRING { a(0), b(1) }`). The value type is a plain BitString; the
 * names only add one `int` constant per named bit, in declaration order:
 * <type_go> + R2(bit) -- the ENUMERATED enumerator scheme (go_emit_enum), with
 * `type_go` the name an ENUMERATED in the same position would get (the type's
 * own Go name at top level, <Parent><Member> for an inline member,
 * <Choice><Alt> for a CHOICE alt). They are package-scoped GK_ENUM_CONST
 * rows, so a clash with a type or another constant fails like every other
 * collision. The values are the C backend's own (v->value->value.v_integer,
 * asn1c_C.c asn1c_lang_C_type_BIT_STRING); the fixer resolved referenced
 * values and rejects non-integer / negative ones, anything else is refused
 * here. */
void
go_emit_bit_names(struct walk_ctx *ctx, const char *type_go,
               const char *type_cid, const char *type_path,
               asn1p_expr_t *bs) {
    asn1p_expr_t *v;
    int group = 0;
    TQ_FOR(v, &(bs->members), next) {
        if(v->expr_type == A1TC_EXTENSIBLE || !v->Identifier) continue;
        if(v->expr_type != A1TC_UNIVERVAL || !v->value
           || v->value->type != ATV_INTEGER || v->value->value.v_integer < 0) {
            fprintf(stderr,
                    "asn1cgo: BIT STRING named bit %s is not a resolved "
                    "non-negative integer in module %s: %s\n",
                    v->Identifier, ctx->module ? ctx->module : "?", type_path);
            ctx->bag->failed = 1;
            return;
        }
        char *bcid = go_mk_suffix(v);
        char *raw = go_str_append(strdup(""), type_cid);
        raw = go_str_append(raw, "_");
        raw = go_str_append(raw, bcid);
        char *bgo = go_list_suffix(bs, v);
        char *go = go_str_append(strdup(""), type_go);
        go = go_str_append(go, bgo);
        free(bgo);
        go_emit_name(ctx->bag, ctx->module, go_make_path(type_path, v->Identifier),
                  GK_ENUM_CONST, raw, go);
        go_row_set_const(ctx->bag, asn1p_itoa(v->value->value.v_integer), "int");
        struct name_row *r = &ctx->bag->rows[ctx->bag->n_rows - 1];
        if(!group) group = r->ord + 1;
        r->bit_group = group;
        r->bit_type = go_own(type_path);
        free(bcid);
    }
}
