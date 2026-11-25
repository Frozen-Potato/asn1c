/*
 * go_names_dflt.c — SEQUENCE OF element types (named and inline
 * elements) and the Go form of DEFAULT values.
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

/* go_slice_element_type (slice stage): the ELEMENT type text of a named slice alias
 * `type X []Elem`, for every one of the three slice-owner shapes — a
 * SEQUENCE-OF type assignment (`type` row), an anonymous inline SEQ-OF at a
 * member (`inline` row), and a param-container specialization use (`inline`
 * row). The three shapes share ONE resolver so the element rule cannot drift
 * between them:
 *   a REFERENCE element — the referenced assignment's own goName
 *     (GoName(MKID(chased terminal)); stored UNQUALIFIED, the post-walk prepass
 *     go_qualify_slice_elems applies cross-module qualification). A
 *     field-shaped specialization element (a container's ProtocolIE-Field
 *     {{X}} payload) resolves to the SAME GoName(X) name: X IS the
 *     chased terminal's own Identifier by the time the chase lands on the
 *     field-shaped clone, and go_cid_to_go_name(MKID(terminal)) is GoName(X) — exactly the
 *     spec-key name go_emit_spec mints in X's module.
 *   an inline LEAF element — the mapping-table Go text via go_classify_leaf, the SAME
 *     table the decl emission uses (go_types_leaf_underlying; one table, no
 *     drift).
 *   an inline CONSTRUCTED element (SEQ/CHOICE/ENUM/SEQ-OF literal body at the
 *     element position) never reaches this function: go_mint_inline_seqof_elem
 *     (below) names it <Owner>Member first and hands back the element text.
 * Returns an owned string, or NULL after setting bag->failed (fail loud). */
char *
go_slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                   const char *path_for_diag);

/* Is the element of a SEQUENCE OF an inline (anonymous) type rather than a
 * reference to a named one? */
int
go_seqof_elem_is_inline(asn1p_expr_t *elem) {
    return elem && !(elem->expr_type == A1TC_REFERENCE
                     || elem->meta_type == AMT_TYPEREF);
}

/* go_mint_inline_seqof_elem: the element of a SEQUENCE OF that is an inline
 * (anonymous) type — `SEQUENCE OF INTEGER (0..3)`, `SEQUENCE OF SEQUENCE
 * {..}`, ... — mirrors the C backend, which synthesizes the element "Member":
 * the C element cid is <OwnerCid>__Member and the Go name <OwnerGo>Member
 * (the member / alt inline rule, so under a member `a` of T it is T__a__Member
 * / TAMember; elements nest: T__Member__Member / TMemberMember).
 *
 * The element is minted as an ordinary package-scoped Flat node of that cid
 * (flagged inline_elem: the C tree has no `_t` typedef / asn_DEF for it):
 *   a plain leaf  (INTEGER BOOLEAN REAL NULL OCTET/BIT/PrintableString,
 *                  named-bit BIT STRING) — a hidden leaf node, NO Go type row:
 *                  the Go element is the unnamed leaf mapping ([]int64 ...),
 *                  from the same table go_classify_leaf/go_types use;
 *   ENUMERATED    — `type <Owner>Member int32` + value consts (go_emit_enum);
 *   SEQUENCE / CHOICE — a struct / CHOICE type <Owner>Member with its own
 *                  members, exactly as the member / alt inline rule;
 *   SEQUENCE OF   — the named slice `type <Owner>Member []Elem`, recursing.
 * A named-bit BIT STRING element is the plain BitString plus bit constants
 * <Owner>Member<Bit> (go_emit_bit_names; the member / alt precedent).
 * On success: *go_elem = the Go element type text, *flat_cid = the Flat
 * element cid (both owned). Returns -1 (bag->failed) on failure. The Flat
 * cur register is restored. */
int
go_mint_inline_seqof_elem(struct walk_ctx *ctx, asn1p_expr_t *elem,
                       const char *owner_path, const char *owner_go,
                       const char *owner_cid, char **go_elem,
                       char **flat_cid) {
    char *inline_go = go_str_append(strdup(""), owner_go ? owner_go : "");
    inline_go = go_str_append(inline_go, "Member");
    char *inline_cid = go_cid_compound(owner_cid ? owner_cid : "", "__",
                                       "Member");
    char *path = go_make_path(owner_path, "Member");
    int save_fcur = go_flat_cur_get();
    int rc = 0;
    *go_elem = NULL;
    *flat_cid = NULL;
    for(int j = 0; j < ctx->bag->n_minted; j++) {
        struct minted_elem *me = &ctx->bag->minted[j];
        if(me->module == ctx->module && strcmp(me->cid, inline_cid) == 0) {
            *go_elem = strdup(me->go_elem);
            *flat_cid = strdup(inline_cid);
            free(inline_go); free(inline_cid); free(path);
            return 0;
        }
    }

    switch(elem->expr_type) {
    case ASN_CONSTR_SEQUENCE:
    case ASN_CONSTR_SET: {
        go_emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        go_flat_struct(inline_cid, ctx->module);
        go_flat_mark_inline_elem(NULL, NULL);
        const char *save_go = ctx->parent_go;
        const char *save_cid = ctx->parent_cid;
        char *save_sf = NULL;
        if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
        ctx->parent_go = inline_go;
        ctx->parent_cid = inline_cid;
        go_field_scope_push(ctx->bag);
        go_row_set_is_struct(ctx->bag);
        go_struct_scope_open(ctx->bag, inline_go);
        rc = go_walk_names_members(ctx, elem, path);
        go_struct_scope_reset(ctx->bag);
        go_field_scope_pop(ctx->bag);
        free(go_bag_sf_restore(ctx->bag, save_sf));
        ctx->parent_go = save_go;
        ctx->parent_cid = save_cid;
        *go_elem = strdup(inline_go);
        break;
    }
    case ASN_CONSTR_CHOICE: {
        go_emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        char *save_sf = NULL;
        if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
        go_field_scope_push(ctx->bag);
        go_emit_choice(ctx, inline_go, inline_cid, path, elem);
        go_field_scope_pop(ctx->bag);
        free(go_bag_sf_restore(ctx->bag, save_sf));
        {   /* go_emit_choice minted the CHOICE node and left it cur */
            go_flat_mark_inline_elem(NULL, NULL);
        }
        *go_elem = strdup(inline_go);
        break;
    }
    case ASN_CONSTR_SEQUENCE_OF:
    case ASN_CONSTR_SET_OF: {
        go_emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        int row_ix = ctx->bag->n_rows - 1;
        asn1p_expr_t *inner = TQ_FIRST(&elem->members);
        char *ig = NULL, *ic = NULL;
        if(!inner) { ctx->bag->failed = 1; rc = -1; break; }
        if(go_seqof_elem_is_inline(inner)) {
            rc = go_mint_inline_seqof_elem(ctx, inner, path, inline_go,
                                        inline_cid, &ig, &ic);
        } else {
            ig = go_slice_element_type(ctx, inner, path);
            if(ctx->bag->failed) { rc = -1; break; }
            asn1p_expr_t *et = inner;
            asn1p_expr_t *t2 = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns,
                                                           inner);
            if(t2) et = t2;
            ic = go_own(GO_MKID(et));
            if(go_construct_classify(et) == GO_CONSTR_BIT_STRING)
                go_mark_bitstring_module(ctx->bag, ctx->module);
        }
        if(rc < 0 || ctx->bag->failed) { free(ig); free(ic); rc = -1; break; }
        go_row_set_slice_elem_at(ctx->bag, row_ix, ig);
        (void)go_flat_seqof(inline_cid, ic, 0,
                           elem->expr_type == ASN_CONSTR_SET_OF, ctx->module);
        go_flat_mark_inline_elem(NULL, NULL);
        free(ig); free(ic);
        *go_elem = strdup(inline_go);
        break;
    }
    default: {
        /* a plain leaf (or ENUMERATED / named-bit BIT STRING) */
        int is_enum = elem->expr_type == ASN_BASIC_ENUMERATED;
        int named_bits = elem->expr_type == ASN_BASIC_BIT_STRING
                         && TQ_FIRST(&elem->members);
        ctx->wide_cid = inline_cid;
        ctx->wide_hit = 0;
        int lk = go_classify_leaf(ctx, elem, path);
        int wide = ctx->wide_hit;
        ctx->wide_cid = NULL;
        ctx->wide_hit = 0;
        if(ctx->bag->failed) { rc = -1; break; }
        if(lk == GLEAF_BITSTRING) go_mark_bitstring_module(ctx->bag, ctx->module);
        const char *under = go_types_leaf_underlying(lk);
        const char *ctype = NULL;
        switch(lk) {
        case GLEAF_INT64:  ctype = wide ? "INTEGER_t" : "long"; break;
        case GLEAF_UINT64: ctype = wide ? "INTEGER_t" : "unsigned long"; break;
        case GLEAF_BOOL:   ctype = "BOOLEAN_t"; break;
        case GLEAF_NULL:   ctype = "NULL_t"; break;
        case GLEAF_REAL:   ctype = "double"; break;
        case GLEAF_REAL32: ctype = "float"; break;
        case GLEAF_OCTETS: ctype = "OCTET_STRING_t"; break;
        case GLEAF_OID:    ctype = "OBJECT_IDENTIFIER_t"; break;
        case GLEAF_ROID:   ctype = "RELATIVE_OID_t"; break;
        case GLEAF_STRING:
        case GLEAF_STRING_Z:
        case GLEAF_STRING_BMP:
        case GLEAF_STRING_UNIV: ctype = go_string_ctype(elem); break;
        case GLEAF_BITSTRING: ctype = "BIT_STRING_t"; break;
        case GLEAF_ENUM:   ctype = "long"; break;
        default: break;
        }
        if(!ctype || !under) {
            fprintf(stderr,
                    "asn1cgo: SEQUENCE OF element of unsupported kind in "
                    "module %s: %s\n",
                    ctx->module ? ctx->module : "?", path);
            ctx->bag->failed = 1; rc = -1; break;
        }
        if(is_enum) {
            go_emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                      strdup(inline_cid), strdup(inline_go));
            go_row_set_leaf(ctx->bag, lk);
            (void)go_flat_leaf_gleaf(inline_cid, lk, ctx->module);
            go_flat_mark_inline_elem(ctype, NULL);
            go_emit_enum(ctx, inline_go, inline_cid, path, elem);
            *go_elem = strdup(inline_go);
            break;
        }
        /* Reserve <Owner>Member as a name (no declaration: the row carries no
         * leaf kind, struct or slice body): the glue helpers are named after
         * it, so another type of that name must collide. */
        go_emit_name(ctx->bag, ctx->module, strdup(path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        if(lk == GLEAF_NULL)
            (void)go_flat_leaf(inline_cid, "int32_t", ctx->module);
        else
            (void)go_flat_leaf_gleaf(inline_cid, lk, ctx->module);
        go_flat_mark_inline_elem(ctype, under);
        if(named_bits) go_emit_bit_names(ctx, inline_go, inline_cid, path, elem);
        *go_elem = strdup(under);
        break;
    }
    }
    go_flat_cur_restore(save_fcur);
    if(rc == 0 && ctx->bag->failed) rc = -1;
    if(rc == 0) *flat_cid = strdup(inline_cid);
    if(rc == 0) {
        struct name_bag *b = ctx->bag;
        if(b->n_minted + 1 > b->cap_minted) {
            int nc = b->cap_minted ? b->cap_minted * 2 : 16;
            struct minted_elem *nm = realloc(b->minted, (size_t)nc * sizeof *nm);
            if(!nm) { b->failed = 1; rc = -1; }
            else { b->minted = nm; b->cap_minted = nc; }
        }
        if(rc == 0) {
            b->minted[b->n_minted].module = ctx->module;
            b->minted[b->n_minted].cid = strdup(inline_cid);
            b->minted[b->n_minted].go_elem = strdup(*go_elem);
            b->n_minted++;
        }
    }
    if(rc < 0) { free(*go_elem); *go_elem = NULL; free(*flat_cid); *flat_cid = NULL; }
    free(inline_go); free(inline_cid); free(path);
    return rc;
}

char *
go_slice_element_type(struct walk_ctx *ctx, asn1p_expr_t *elem,
                   const char *path_for_diag) {
    if(!elem) return go_own("");
    /* Inline plain leaf: the mapping-table Go text (the same table). */
    if(!(elem->expr_type == A1TC_REFERENCE || elem->meta_type == AMT_TYPEREF)) {
        int lk = go_classify_leaf(ctx, elem, path_for_diag);
        if(ctx->bag->failed) return NULL;
        const char *under = go_types_leaf_underlying(lk);
        return go_own(under ? under : "");
    }
    /* Reference element: the chased terminal assignment's own goName;
     * a field-shaped spec terminal IS named GoName(X) — see the block comment). */
    asn1p_expr_t *terminal = elem;
    {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, elem);
        if(t) terminal = t;
    }
    return go_type_go(terminal);
}

/* go_quote: a Go interpreted string literal for arbitrary bytes. */
static char *
go_quote(const unsigned char *b, size_t n) {
    char *o = strdup("\"");
    for(size_t i = 0; i < n; i++) {
        char t[8];
        if(b[i] == '"' || b[i] == '\\') snprintf(t, sizeof t, "\\%c", b[i]);
        else if(b[i] >= 0x20 && b[i] < 0x7f) snprintf(t, sizeof t, "%c", b[i]);
        else snprintf(t, sizeof t, "\\x%02x", b[i]);
        o = go_str_append(o, t);
    }
    return go_str_append(o, "\"");
}

void
go_dflt_fn_free(struct go_dflt_fn *f) {
    if(!f) return;
    free(f->cname); free(f->root_cid); free(f->start_cid); free(f->tree_ctype); free(f->label);
    free(f->member_tok);
    for(int i = 0; i < f->ntok; i++) free(f->toks[i]);
    for(int i = 0; i < f->ndesc; i++) free(f->desc[i]);
    for(int i = 0; i < f->ngo; i++) free(f->gopath[i]);
    free(f->toks); free(f->desc); free(f->gopath);
    free(f);
}

static void
dflt_push(char ***v, int *n, char *s) {
    char **nv = realloc(*v, (size_t)(*n + 1) * sizeof(char *));
    if(!nv) { free(s); return; }
    nv[(*n)++] = s;
    *v = nv;
}

/* dflt_fn_build: how the C helper reaches the member's default_value_set.
 * Inline owner types are static in C, so the helper starts at the descriptor
 * of the nearest top-level type (start_cid) and follows member names (the
 * element of a SEQUENCE OF / SET OF has no name). The Flat side starts at the
 * nearest enclosing node that has a reader of its own (root_cid): the
 * top-level type, an element of an inline SEQUENCE OF, or an inline SEQUENCE
 * that is OPTIONAL; the inline SEQUENCEs the Flat holds by value below it are
 * followed by token (toks) and Go field (gopath). An owner reached through a
 * DEFAULT inline SEQUENCE or a recursion break, or in a parameterized type,
 * has no Default func (NULL). An inline SEQUENCE / SET alternative of a CHOICE
 * is a node with a reader of its own, like an OPTIONAL inline SEQUENCE. */
static struct go_dflt_fn *
dflt_fn_build(struct walk_ctx *ctx, asn1p_expr_t *child, const char *owner,
              const char *fgo) {
    asn1p_expr_t *anc[64];
    int na = 0;
    asn1p_expr_t *e = child->parent_expr;
    for(; e && e->parent_expr; e = e->parent_expr) {
        if(na == 64) return NULL;
        anc[na++] = e;
    }
    asn1p_expr_t *top = e;
    if(!top || top->lhs_params || top->spec_index >= 0
       || !(go_is_struct_kind(top->expr_type) || go_is_list_kind(top->expr_type)
            || top->expr_type == ASN_CONSTR_CHOICE))
        return NULL;
    struct go_dflt_fn *f = calloc(1, sizeof *f);
    if(!f) return NULL;
    f->start_cid = go_own_mkid(top);
    f->root_cid = strdup(f->start_cid);
    char *cid = strdup(f->start_cid);
    asn1p_expr_t *prev = top;
    for(int i = na - 1; i >= 0; i--) {
        asn1p_expr_t *a = anc[i];
        char *mc, *nc;
        if(go_is_list_kind(prev->expr_type)) {
            /* the element of an inline list: a node with its own reader */
            if(!go_is_struct_kind(a->expr_type) || a->meta_type == AMT_TYPEREF
               || a->expr_type == A1TC_REFERENCE) {
                free(cid); go_dflt_fn_free(f);
                return NULL;
            }
            nc = go_cid_compound(cid, "__", "Member");
            free(f->root_cid); f->root_cid = strdup(nc);
            for(int k = 0; k < f->ntok; k++) free(f->toks[k]);
            f->ntok = 0;
            for(int k = 0; k < f->ngo; k++) free(f->gopath[k]);
            f->ngo = 0;
            dflt_push(&f->desc, &f->ndesc, strdup(""));
            free(cid); cid = nc;
            prev = a;
            continue;
        }
        if(prev->expr_type == ASN_CONSTR_CHOICE) {
            /* an inline SEQUENCE / SET alternative: a node with its own
             * reader (the Flat slot may be a pointer to it) */
            if(!go_is_struct_kind(a->expr_type) || a->meta_type == AMT_TYPEREF
               || a->expr_type == A1TC_REFERENCE) {
                free(cid); go_dflt_fn_free(f);
                return NULL;
            }
            mc = go_own_mkid(a);
            nc = go_cid_compound(cid, "__", mc);
            free(mc);
            free(f->root_cid); f->root_cid = strdup(nc);
            for(int k = 0; k < f->ntok; k++) free(f->toks[k]);
            f->ntok = 0;
            for(int k = 0; k < f->ngo; k++) free(f->gopath[k]);
            f->ngo = 0;
            dflt_push(&f->desc, &f->ndesc, strdup(a->Identifier ? a->Identifier : ""));
            free(cid); cid = nc;
            prev = a;
            continue;
        }
        if(a->expr_type == ASN_CONSTR_CHOICE && a->meta_type != AMT_TYPEREF
           && a->expr_type != A1TC_REFERENCE
           && (a->marker.flags & EM_DEFAULT) != EM_DEFAULT
           && i > 0 && go_is_struct_kind(anc[i - 1]->expr_type)) {
            /* an inline CHOICE on the way down: only descended into by an
             * inline SEQUENCE / SET alternative, which restarts the Flat path */
            mc = go_own_mkid(a);
            nc = go_cid_compound(cid, "__", mc);
            free(mc);
            dflt_push(&f->desc, &f->ndesc, strdup(a->Identifier ? a->Identifier : ""));
            free(cid); cid = nc;
            prev = a;
            continue;
        }
        if(!(go_is_struct_kind(a->expr_type) || go_is_list_kind(a->expr_type))
           || a->meta_type == AMT_TYPEREF || a->expr_type == A1TC_REFERENCE
           || (a->marker.flags & EM_DEFAULT) == EM_DEFAULT
           || (a->marker.flags & (EM_DEFAULT & ~EM_INDIRECT) & ~EM_OPTIONAL)) {
            free(cid); go_dflt_fn_free(f);
            return NULL;
        }
        mc = go_own_mkid(a);
        nc = go_cid_compound(cid, "__", mc);
        free(mc);
        dflt_push(&f->desc, &f->ndesc, strdup(a->Identifier ? a->Identifier : ""));
        if(go_is_list_kind(a->expr_type)) {
            /* the next ancestor is the element: no token, no Go field */
        } else if((a->marker.flags & EM_OPTIONAL) == EM_OPTIONAL
                  || (a->marker.flags & EM_OMITABLE) == EM_OMITABLE) {
            /* a starred inline SEQUENCE is a node of its own */
            free(f->root_cid); f->root_cid = strdup(nc);
            for(int k = 0; k < f->ntok; k++) free(f->toks[k]);
            f->ntok = 0;
            for(int k = 0; k < f->ngo; k++) free(f->gopath[k]);
            f->ngo = 0;
        } else if(a->marker.flags & EM_INDIRECT) {
            free(nc); free(cid); go_dflt_fn_free(f);
            return NULL;
        } else {
            dflt_push(&f->toks, &f->ntok, go_mk_member(a));
            dflt_push(&f->gopath, &f->ngo, go_member_go(a));
        }
        free(cid); cid = nc;
        prev = a;
    }
    if(!go_is_struct_kind(prev->expr_type)) { free(cid); go_dflt_fn_free(f); return NULL; }
    f->member_tok = go_mk_member(child);
    dflt_push(&f->desc, &f->ndesc, strdup(child->Identifier ? child->Identifier : ""));
    dflt_push(&f->gopath, &f->ngo, strdup(fgo));
    if(go_is_struct_kind(child->expr_type) || go_is_list_kind(child->expr_type)) {
        /* an inline member: `struct <compound cid>` */
        char *mc = go_own_mkid(child);
        char *nc = go_cid_compound(cid, "__", mc);
        f->tree_ctype = go_str_append(strdup("struct "), nc);
        free(mc); free(nc);
    }
    f->label = go_str_append(go_str_append(strdup(owner), "."), fgo);
    f->cname = strdup(f->root_cid);
    for(int i = 0; i < f->ntok; i++)
        f->cname = go_str_append(go_str_append(f->cname, "_"), f->toks[i]);
    f->cname = go_str_append(go_str_append(f->cname, "_"), f->member_tok);
    free(cid);
    (void)ctx;
    return f;
}

int
go_names_dflt_n(void) {
    int n = 0;
    if(!g_go_emit_bag) return 0;
    for(int i = 0; i < g_go_emit_bag->n_rows; i++)
        if(g_go_emit_bag->rows[i].dfn) n++;
    return n;
}

const struct go_dflt_fn *
go_names_dflt_at(int k) {
    if(!g_go_emit_bag) return NULL;
    for(int i = 0; i < g_go_emit_bag->n_rows; i++) {
        struct name_row *r = &g_go_emit_bag->rows[i];
        if(!r->dfn || k-- > 0) continue;
        r->dfn->module = r->module;
        r->dfn->goname = r->goName;
        r->dfn->field_type = NULL;
        for(int j = 0; j < g_go_emit_bag->n_rows; j++) {
            struct name_row *f = &g_go_emit_bag->rows[j];
            if(f->kind == GK_FIELD && f->sf_owner && f->module == r->module
               && r->dflt_owner && r->dflt_field
               && strcmp(f->sf_owner, r->dflt_owner) == 0
               && strcmp(f->goName, r->dflt_field) == 0) {
                r->dfn->field_type = f->field_type;
                break;
            }
        }
        return r->dfn;
    }
    return NULL;
}

/* go_note_default_value: record the exported Go declaration of one supported
 * DEFAULT member's value (a GK_DEFAULT_VALUE row, package-scoped so a clash
 * with any other name fails the run like every other collision). The
 * member's Go type is the field row's own (read at emit time). The row is
 * named <OwnerStruct><Field>Default. */
void
go_note_default_value(struct walk_ctx *ctx, asn1p_expr_t *child,
                   const char *member_path, int field_row_ix) {
    asn1p_value_t *dv = child->marker.default_value;
    asn1p_expr_t *term = child;
    int form = 1;
    char *lit = NULL;
    if(!dv) return;
    if(child->expr_type == A1TC_REFERENCE || child->meta_type == AMT_TYPEREF) {
        term = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, child);
        if(!term) term = child;
    }
    switch(term->expr_type) {
    case ASN_BASIC_BOOLEAN:
        lit = strdup(dv->type == ATV_TRUE ? "true"
                     : dv->type == ATV_FALSE ? "false"
                     : dv->value.v_integer ? "true" : "false");
        break;
    case ASN_BASIC_INTEGER:
    case ASN_BASIC_ENUMERATED:
        lit = strdup(asn1p_itoa(dv->value.v_integer));
        break;
    case ASN_BASIC_OCTET_STRING: {
        int bits = dv->value.binary_vector.size_in_bits;
        int nb = (bits + 7) / 8;
        char t[64];
        form = 2;
        lit = strdup("");
        for(int i = 0; i < nb; i++) {
            snprintf(t, sizeof t, "%s0x%02x", i ? ", " : "",
                     dv->value.binary_vector.bits[i]);
            lit = go_str_append(lit, t);
        }
        break;
    }
    case ASN_BASIC_BIT_STRING: {
        /* The stored form the C default_value_set installs: for a named-bit
         * type the bits of { a, b }, without trailing 0 bits, padded to the
         * lower bound of a SIZE constraint. */
        arg_t darg;
        uint8_t *bb = NULL;
        int bits = 0;
        char t[64];
        memset(&darg, 0, sizeof darg);
        darg.asn = ctx->asn;
        darg.ns = ctx->ns;
        darg.expr = child;
        if(!asn1c_default_bit_string(&darg, child, &bb, &bits, NULL)) {
            ctx->bag->failed = 1;
            return;
        }
        form = 2;
        lit = strdup("Bytes: []byte{");
        for(int i = 0; i < (bits + 7) / 8; i++) {
            snprintf(t, sizeof t, "%s0x%02x", i ? ", " : "", bb[i]);
            lit = go_str_append(lit, t);
        }
        snprintf(t, sizeof t, "}, BitsUnused: %d", (8 - bits % 8) % 8);
        lit = go_str_append(lit, t);
        free(bb);
        break;
    }
    case ASN_BASIC_OBJECT_IDENTIFIER:
    case ASN_BASIC_RELATIVE_OID: {
        /* []uint64 arcs: `var Name = T{1, 3, 6}` */
        arg_t darg;
        uint32_t *arcs = NULL;
        size_t n = 0;
        char t[32];
        memset(&darg, 0, sizeof darg);
        darg.asn = ctx->asn;
        darg.ns = ctx->ns;
        darg.expr = child;
        if(!asn1c_default_oid_arcs(&darg, child, &arcs, &n, NULL)) {
            ctx->bag->failed = 1;
            return;
        }
        form = 2;
        lit = strdup("");
        for(size_t i = 0; i < n; i++) {
            snprintf(t, sizeof t, "%s%u", i ? ", " : "", (unsigned)arcs[i]);
            lit = go_str_append(lit, t);
        }
        free(arcs);
        break;
    }
    case ASN_BASIC_NULL:
        /* The only value: `var Name = T{}` with T = struct{} (or its name) */
        form = 2;
        lit = strdup("");
        break;
    case ASN_BASIC_REAL: {
        /* A decimal / integer DEFAULT is a Go constant. Infinity and NaN
         * are not constants in Go, and a constant -0.0 is +0: those are
         * computed from a variable at start-up (no "math" import needed:
         * float division by a zero variable yields +-Inf / NaN, negating a
         * zero variable yields -0). */
        double d = dv->type == ATV_REAL ? dv->value.v_double
                                        : (double)dv->value.v_integer;
        if(d != d) {
            form = 3;
            lit = strdup("func() float64 { z := 0.0; return z / z }()");
        } else if(d > 1.7976931348623157e308) {
            form = 3;
            lit = strdup("func() float64 { z := 0.0; return 1 / z }()");
        } else if(d < -1.7976931348623157e308) {
            form = 3;
            lit = strdup("func() float64 { z := 0.0; return -1 / z }()");
        } else if(d == 0.0 && 1.0 / d < 0.0) {
            form = 3;
            lit = strdup("func() float64 { z := 0.0; return -z }()");
        } else {
            asn1p_value_t rv;
            memset(&rv, 0, sizeof rv);
            rv.type = ATV_REAL;
            rv.value.v_double = d;
            /* shortest text that reads back as the same double */
            lit = strdup(asn1f_printable_value(&rv));
        }
        break;
    }
    case ASN_CONSTR_SEQUENCE:
    case ASN_CONSTR_SET:
    case ASN_CONSTR_SEQUENCE_OF:
    case ASN_CONSTR_SET_OF:
        /* A value, not a constant: a func in glue.go (see dflt_fn_build). */
        form = 4;
        lit = strdup("");
        break;
    default:
        if((term->expr_type & ASN_STRING_MASK)
           || term->expr_type == ASN_BASIC_UTCTime
           || term->expr_type == ASN_BASIC_GeneralizedTime) {
            lit = go_quote(dv->value.string.buf, (size_t)dv->value.string.size);
            break;
        }
        return;
    }
    if(!lit) { ctx->bag->failed = 1; return; }
    const char *owner = ctx->bag->rows[field_row_ix].sf_owner;
    const char *fgo = ctx->bag->rows[field_row_ix].goName;
    if(!owner) { free(lit); return; }
    char *name = go_str_append(go_str_append(strdup(owner), fgo), "Default");
    char *raw = go_str_append(go_str_append(strdup(owner), "_"),
                           child->Identifier ? child->Identifier : "?");
    char *mpath = go_make_path(member_path, child->Identifier);
    char *path = go_make_path(mpath, "DEFAULT");
    free(mpath);
    go_emit_name(ctx->bag, ctx->module, path, GK_DEFAULT_VALUE, raw, name);
    struct name_row *r = &ctx->bag->rows[ctx->bag->n_rows - 1];
    r->dflt_form = form;
    r->dflt_lit = lit;
    r->dflt_owner = strdup(owner);
    r->dflt_field = strdup(fgo);
    r->dflt_field_row = field_row_ix;
    if(form == 4) {
        r->dfn = dflt_fn_build(ctx, child, owner, fgo);
        /* An owner the helper cannot reach (see dflt_fn_build) has no Default
         * func; the member itself works. */
        if(!r->dfn) r->dflt_form = 5;
    }
}
