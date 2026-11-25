/*
 * go_names_spec.c — the names of a field-shaped parameterized
 * specialization (the value union, its discriminant and alts), member
 * pointer stars and the IOC class-column helpers.
 *
 * Part of the Go-name generator pass; go_names.c has the overview.
 */
#include "go_names_internal.h"

/* is_field_shaped_spec: a top-level SEQUENCE assignment is a field-shaped
 * parameterized specialization (ProtocolIE-Field / SingleContainer {{X}}, the
 * asn1c `struct <X>__value { ... }` wrapper) iff one of its members is an
 * open-type class-field `&Value` reference (go_construct_is_open_type mirrors
 * is_open_type at asn1c_C.c:305). Returns that open-type member, or NULL. */
asn1p_expr_t *
is_field_shaped_spec(asn1p_expr_t *seq_terminal) {
    if(!seq_terminal) return NULL;
    asn1p_expr_t *child;
    TQ_FOR(child, &(seq_terminal->members), next) {
        if(go_construct_is_open_type(child))
            return child;
    }
    return NULL;
}

/* Forward decl (struct-body field-type resolution): classfield_declared_type
 * resolves a lowercase &field envelope member to its declared type; emit_spec
 * uses it above its definition. */
static asn1p_expr_t *
classfield_declared_type(struct walk_ctx *ctx, asn1p_expr_t *mem);

/* The governing Go type NAME of an IOC class column's declared type (R2 of
 * the column's own type field, e.g. &id -> ProtocolIE-ID -> ProtocolIEID):
 * the name the ctor layer resolves consts BY (value-consts typed it, enum
 * consts owned by it) instead of any name-shape assumption. Malloc'd;
 * NULL when the declared type does not resolve. */
static char *column_governing_go(struct walk_ctx *ctx, asn1p_expr_t *field);
static int column_is_inline(asn1p_expr_t *field);
static int cell_id_is_literal(asn1p_expr_t *cv);

/* Forward decls: emit_spec_value_alts + emit_value_pr_nothing are defined
 * after emit_spec; both are called from it. */
static void emit_spec_value_alts(struct walk_ctx *ctx, const char *x_go,
                                 const char *x_cid, const char *parent_path,
                                 asn1p_expr_t *seq_terminal);
static void emit_value_inline_alt(struct walk_ctx *ctx, asn1p_expr_t *alt,
                                  const char *inline_go,
                                  const char *inline_cid,
                                  const char *parent_path,
                                  const char *altcid);
static void emit_value_pr_nothing(struct walk_ctx *ctx, const char *x_go,
                                  const char *x_cid, const char *parent_path);

/* emit_spec: the specialization names. X is the type's goName; the
 * specialization mints a named value union (R2(X)+Value) with a discriminant
 * (R2(X)+ValuePr), exactly as asn1c emits `struct <X>__value { union {...} }` +
 * `enum <X>__value_PR {...}`. spec-key = the type name itself (R2(X)). The
 * value-union alt fields + their choice-constants come from the object set the
 * &Value resolves to; those are emitted by emit_spec_value_alts when the
 * open-type member is available.
 *
 * A field-shaped specialization is a STRUCT (named R2(X)), so in addition
 * to the spec-key/value/pr + value-union-alts, it carries STRUCT FIELD rows for
 * its envelope members — exactly as a plain SEQUENCE does. The real C
 * struct `typedef struct <X> { <id|procedureCode>; <criticality>; struct <X>
 * __value { ... } value; asn_struct_ctx_t _asn_ctx; }` carries the envelope
 * members and the `value` wrapper; the Go struct is
 * `{ Id|ProcedureCode; Criticality; Value <X>Value }` — the envelope members as
 * fields, the `value` wrapper as ONE `Value` field typed by the union. The
 * discriminant `present` lives on the <X>Value UNION (not on the IEs struct), so
 * it is NOT a field here (it is emitted as a choice-const + union alt field in
 * emit_spec_value_alts). The rule: a field-shaped specialization
 * is a type, so it is emitted as a struct with field rows for its members.
 *
 * Fail loud if the specialization has NO open-type &Value member (the one shape
 * invariant rests on): a field-shaped spec without it is an unforeseen
 * structure (file a Q; do not silently mis-emit). */
void
emit_spec(struct walk_ctx *ctx, const char *x_go, const char *x_cid,
          const char *parent_path, asn1p_expr_t *seq_terminal) {
    /* a field-shaped specialization's names belong in X's module — the
     * module that DEFINES the bound object set — NOT ctx->module (the template's
     * module: asn1c attaches every clone's module back-pointer to the parameter-
     * ized type's home, e.g. the container module for all ProtocolIE-Field clones).
     * Resolve X's module from the IOC objset (the same resolution emit_spec_
     * value_alts makes) and rebind ctx->module to it for the whole spec emit, so
     * every emit_name in this function AND emit_spec_value_alts attributes to X.
     * Falls back to ctx->module if the objset is unresolvable (a degenerate spec
     * with no object rows — emit_spec_value_alts then emits PrNothing only). */
    asn1c_ioc_table_and_objset_t ioc;
    {
        arg_t a;
        memset(&a, 0, sizeof a);
        a.asn = ctx->asn;
        a.ns = ctx->ns;
        a.expr = seq_terminal;
        ioc = asn1c_get_ioc_table(&a);
    }
    const char *save_module = ctx->module;
    if(ioc.objset && ioc.objset->module && ioc.objset->module->ModuleName)
        ctx->module = ioc.objset->module->ModuleName;

    char *path_key = strdup(parent_path);

    /* spec-key: R2(X). rawCid = the real C struct identifier of the clone
     * (asn1c's `typedef struct <X_cid> {...} <X_cid>_t;` — the verbatim tag,
     * underscore-preserving, e.g. Action_ToBeSetup_ItemIEs, NOT the
     * _-collapsed Go name ActionToBeSetupItemIEs). */
    emit_name(ctx->bag, ctx->module, path_key, GK_SPEC_KEY,
              own(x_cid), strdup(x_go));
    /* struct-body stage: the specialization's Go struct (envelope + the Value union
     * holder) — the field rows below attach to this scope. */
    row_set_is_struct(ctx->bag);
    /* Flat: the field-shaped spec IS a Flat struct
     * in X's module ({id/procedureCode, criticality, value{present,alts}}),
     * the PFX_Action_ToBeSetup_ItemIEs_flat / <Msg>_IEs_flat
     * shape. Members land on it through the envelope walk below. */
    (void)go_flat_struct(x_cid, ctx->module);
    go_flat_label_cur(seq_terminal->Identifier);   /* td->name label */

    /* The struct's field scope is this specialization; reset before the envelope
     * member walk so struct-scoped field names collide only with siblings of THIS
     * struct. */
    reset_field_scope(ctx->bag);
    struct_scope_open(ctx->bag, x_go);

    /* Envelope field rows: walk the specialization SEQUENCE's members and emit a
     * `field` for each PLAIN envelope member (id/procedureCode/criticality) AND
     * for the open-type `value` member (which becomes the single `Value` field).
     * The open-type member is itself a member of the SEQUENCE body; detect it
     * with go_construct_is_open_type (the same test the classify walk uses). An
     * open-type member does not carry the envelope; it becomes `Value` (typed by
     * the <X>Value union emitted below). */
    asn1p_expr_t *open_member = NULL;
    asn1p_expr_t *mem;
    TQ_FOR(mem, &(seq_terminal->members), next) {
        if(go_construct_is_open_type(mem)) {
            open_member = mem;
            continue;   /* emitted as the single `Value` field below */
        }
        /* Skip a bare reference/member with no Identifier (defensive; the
         * envelope members all carry one). */
        if(!mem->Identifier) continue;
        char *path = make_path(parent_path, mem->Identifier);
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  go_mk_member(mem), go_r2(GO_MKID(mem)));
        /* Flat: the envelope member's ref row (the class-field-declared
         * type's own cid; integer/enum leaves resolve via the declared
         * type's leaf Flat). */
        {
            char *env_cid = NULL;
            if(go_construct_is_classfield_ref(mem)) {
                asn1p_expr_t *decl = classfield_declared_type(ctx, mem);
                if(decl && !decl->Identifier) {
                    /* an inline class-field type (`&id INTEGER (0..255)`):
                     * no named type behind it; the C member is the bare
                     * leaf (long id), so the Flat row is the leaf prim. */
                    int lk = classify_leaf(ctx, decl, parent_path);
                    const char *fprim = go_leaf_flat_prim(lk);
                    if(fprim) {
                        char *tok = go_mk_member(mem);
                        go_flat_member_prim(fprim, tok, 0);
                        go_flat_last_member_gleaf(lk);
                        go_flat_label_last_member(mem->Identifier);
                        free(tok);
                    }
                } else if(decl) env_cid = own(GO_MKID(decl));
            }
            if(env_cid) {
                char *tok = go_mk_member(mem);
                go_flat_member_ref(env_cid, tok, 0);
                go_flat_label_last_member(mem->Identifier);
                free(env_cid); free(tok);
            }
        }
        /* struct-body stage: envelope member field types — a reference to the class-field
         * declared type (&id -> ProtocolIE-ID, &procedureCode ->
         * ProcedureCode, &criticality -> Criticality): the resolved named
         * type's own name, cross-module qualified. Resolution mirrors asn1c_C.c:
         * 2653-2655/2710-2720 — an &field reference resolves to the class's
         * declared field type (find_column_index + the field's Type). */
        {
            char *ft = NULL;
            if(go_construct_is_classfield_ref(mem)) {
                asn1p_expr_t *decl = classfield_declared_type(ctx, mem);
                if(decl && !decl->Identifier) {
                    int lk = classify_leaf(ctx, decl, parent_path);
                    const char *under = go_types_leaf_underlying(lk);
                    if(under) ft = own(under);
                } else if(decl) {
                    char *tgo = go_type_go(decl);
                    ft = str_append(strdup(""), tgo);
                    free(tgo);
                }
            }
            if(!ft) {
                /* A non-class-field envelope member (a plain typed member of a
                 * directly-defined specialization): the reference target's
                 * named type, or the mapping-table leaf. */
                asn1p_expr_t *t = mem;
                if(mem->expr_type == A1TC_REFERENCE
                   || mem->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *r = asn1f_find_terminal_type_ex(
                        ctx->asn, ctx->ns, mem);
                    if(r) t = r;
                }
                if(go_is_struct_kind(t->expr_type)
                   || t->expr_type == ASN_CONSTR_CHOICE
                   || go_is_list_kind(t->expr_type)
                   || t->expr_type == ASN_BASIC_ENUMERATED) {
                    char *tgo = go_type_go(t);
                    ft = str_append(strdup(""), tgo);
                    free(tgo);
                } else {
                    int lk = classify_leaf(ctx, t, parent_path);
                    const char *under = go_types_leaf_underlying(lk);
                    if(under) ft = own(under);
                }
            }
            if(ft) {
                row_set_field_type(ctx->bag, ft);
                free(ft);
            }
        }
    }

    /* A field-shaped spec without an open-type &Value member is
     * an unforeseen structure — fail loud and file a Q rather than emit a struct
     * with no Value union. is_field_shaped_spec already guaranteed one existed at
     * the call site, so this is a consistency guard. */
    if(!open_member) {
        fprintf(stderr,
                "asn1cgo: field-shaped specialization %s has no open-type &Value "
                "member in module %s: %s\n",
                ctx->module ? ctx->module : "?", ctx->module ? ctx->module : "?",
                parent_path ? parent_path : "?");
        ctx->bag->failed = 1;
        ctx->module = save_module;
        return;
    }
    /* The open-type member becomes the single `Value` field (the union holder).
     * goName = `Value` (the envelope's value slot, i.e. the field
     * `Value <X>Value`); the path leaf is the member's ASN.1 identifier so the
     * dump's provenance reflects the actual member (the index keys the field by
     * goName). struct-body stage: its field TYPE is the <X>Value union (by VALUE — the
     * envelope's value slot is the union struct itself
     * (`Value ActionToBeSetupItemIEsValue`). */
    {
        const char *leaf = open_member->Identifier ? open_member->Identifier
                                                   : "Value";
        char *path = make_path(parent_path, leaf);
        emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                  strdup("Value"), strdup("Value"));
        char *ft = str_append(strdup(""), x_go);
        ft = str_append(ft, "Value");
        row_set_field_type(ctx->bag, ft);
        free(ft);
        /* Flat: the value member nests the open-type
         * union INLINE ({present, alts...}) — the verbatim .h `value`
         * member. Mint the nested node (its cid = <x_cid>__value so the
         * present/alt primes below find it); the alt rows attach under it
         * via the _on handle the enclosing struct records. OWN the cid (the
         * GO_MKID static buffer aliases across the compound call). */
        {
            char *flat_vtok = own("value");
            char *vx_cid = str_append(strdup(""), x_cid);
            vx_cid = str_append(vx_cid, "__value");
            int v_ix = go_flat_struct_nested(vx_cid, ctx->module);
            /* the value union IS a CHOICE layout ({present, alts}, present
             * first, exactly the .h `struct <X>__value` wrapper): the glue's
             * emit_nested dispatches on is_choice — without the flag the
             * union walked LINEARLY (fill/read of EVERY alt slot, nil *T
             * handed to the selected alt's fill, unselected pointer slots
             * deref'd on read: a PDU-envelope round trip faults at
             * decode).
             * flat_new_type dedups by (cid, module), so this mint lands the
             * flag ON the pre-minted node above — but go_flat_choice ALSO
             * re-binds the cur register to it; emit_spec's caller keeps
             * populating the ENCLOSING struct after this, so save/restore
             * cur around the call (the walk_names_child CHOICE arm's own
             * pattern). */
            {
                int save_fcur = go_flat_cur_get();
                go_flat_choice(vx_cid, ctx->module);
                go_flat_cur_restore(save_fcur);
            }
            go_flat_member_nested(v_ix, flat_vtok, 0);
            free(flat_vtok); free(vx_cid);
        }
    }

    /* spec-value: R2(X)+Value — the open-type value union. rawCid = <X_cid>__value
     * (the real asn1c `struct <X_cid>__value {...}` wrapper tag). struct-body stage: the
     * UNION is a struct too (Present + one pointer field per alt — the pointer-per-alt form
     * alt fields emit_spec_value_alts records in the x_go+"Value" scope).
     * emit_name takes ownership of `go` (add_row retains it). */
    {
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "Value");
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value");
        char *path = make_path(parent_path, "Value");
        emit_name(ctx->bag, ctx->module, path, GK_SPEC_VALUE, raw, go);
        row_set_is_struct(ctx->bag);
    }
    /* spec-pr: R2(X)+ValuePr — the union discriminant type. rawCid =
     * <X_cid>__value_PR (the real asn1c `typedef enum <X_cid>__value_PR` tag). */
    {
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "ValuePr");
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value_PR");
        char *path = make_path(parent_path, "ValuePr");
        emit_name(ctx->bag, ctx->module, path, GK_SPEC_PR, raw, go);
    }

    /* value-union alt fields + choice-consts + PrNothing. The alts are the
     * &Value column cells of the object set the specialization binds to, exactly
     * as asn1c_C.c asn1c_lang_C_OpenType:1090-1101 iterates ioct->row[r]->column[
     * col]->value to build the open-type CHOICE. We resolve that object set via
     * asn1c_get_ioc_table (the same call the C backend makes), find the "Value"
     * column (mirroring find_column_index at asn1c_C.c:1049), and emit one
     * choice-const + field per distinct alt. */
    emit_spec_value_alts(ctx, x_go, x_cid, parent_path, seq_terminal);
    ctx->module = save_module;
}

/* emit_spec_value_alts: enumerate the open-type value-union alternatives of a
 * field-shaped specialization and emit their choice-const + field rows, plus the
 * PrNothing discriminant. The alts = the object-set &Value column cells; mirrors
 * asn1c_C.c:1090-1101. The value union's discriminant is <X>+"ValuePr"; the alts
 * are one field each, struct-scoped to the union. rawCids use the real C-ident
 * prefix x_cid (the verbatim <X_cid>__value_PR[_NOTHING|_<AltCid>] tokens). */
static void
emit_spec_value_alts(struct walk_ctx *ctx, const char *x_go,
                     const char *x_cid, const char *parent_path,
                     asn1p_expr_t *seq_terminal) {
    /* Resolve the object set the specialization binds. asn1c_get_ioc_table walks
     * the SEQUENCE's members for a component-relation constraint and returns its
     * IOC table (asn1c_ioc.c:67); it needs a minimal arg_t carrying asn/ns/expr
     * = the specialization SEQUENCE. */
    arg_t arg;
    memset(&arg, 0, sizeof arg);
    arg.asn = ctx->asn;
    arg.ns = ctx->ns;
    arg.expr = seq_terminal;
    asn1c_ioc_table_and_objset_t ioc = asn1c_get_ioc_table(&arg);
    if(!ioc.ioct || ioc.ioct->rows == 0) {
        /* No object rows: emit PrNothing only (matches a value union with no
         * alternatives, e.g. SingleContainer of an empty set). */
        emit_value_pr_nothing(ctx, x_go, x_cid, parent_path);
        return;
    }

    /* The open-type member decides WHICH class-field column holds the alts.
     * ProtocolIE-Field's value member references &Value; an envelope's value
     * member references &InitiatingMessage / &SuccessfulOutcome / ... The field
     * name is component[1] of the member's reference; the IOC row stores each
     * class-field under "&<field>". The union name is <X>+"Value" regardless
     * (cf. InitiatingMessageValuePr<X>). */
    asn1p_expr_t *valmember = is_field_shaped_spec(seq_terminal);
    /* components[1].name already carries the leading '&' ("&Value",
     * "&InitiatingMessage"), exactly as the IOC row's field Identifier does — so
     * use it verbatim (no re-prefixing). */
    char wantcol[128] = "&Value";
    if(valmember && valmember->reference
       && valmember->reference->comp_count >= 2
       && valmember->reference->components[1].name) {
        snprintf(wantcol, sizeof wantcol, "%s",
                 valmember->reference->components[1].name);
    }
    ssize_t col = -1;
    for(size_t c = 0; c < ioc.ioct->row[0]->columns; c++) {
        if(ioc.ioct->row[0]->column[c].field
           && ioc.ioct->row[0]->column[c].field->Identifier
           && strcmp(ioc.ioct->row[0]->column[c].field->Identifier, wantcol) == 0) {
            col = (ssize_t)c;
            break;
        }
    }
    (void)arg;
    if(col < 0) {
        emit_value_pr_nothing(ctx, x_go, x_cid, parent_path);
        return;
    }
    /* The union struct opens its scope right after the PrNothing block below;
     * the early return here leaves no open scope (an empty union's fields are
     * none; emit_value_pr_nothing only writes a const row). */

    /* PrNothing first, then one choice-const + one field per distinct alt
     * (asn1c dedups by Identifier at asn1c_C.c:1096-1097). The field scope is the
     * whole value union, so reset once. The alt's C union-member token is
     * GO_MKID(cell value); its Go field = R2(token). The choice-const is
     * <X>+"ValuePr" + R2(token) (the discriminant-const form for owner
     * <X>Value). rawCids use x_cid (the real <X_cid>__value_PR token).
     *
     * struct-body stage: the union's own fields open a struct scope under <X>Value —
     * the alt fields (and Present, emitted by the first alt's row order below
     * — see emit_choice's Present row; here the union carries ONLY the alt
     * pointers, the discriminant lives on the union's Go struct as `Present`,
     * which emit_name<GK_FIELD> records through the open scope) attach to it. */
    reset_field_scope(ctx->bag);
    {
        char *owner = str_append(strdup(""), x_go);
        owner = str_append(owner, "Value");
        struct_scope_open(ctx->bag, owner);
        free(owner);
        /* The union's `Present` discriminant field (the holder), rawCid
         * the real `present` member token — same rule as emit_choice's. Its
         * PATH leaf keys it under the union's own dump scope (parent_path +
         * "Value" + "Present"), mirroring the index bucketing (the wrapper's
         * `present` member routes to the compounded <X>Value owner); an
         * envelope-scoped path would attribute it to the IEs struct, which
         * carries no Present (the envelope is {Id, Criticality,
         * Value}). */
        {
            char *base = make_path(parent_path, "Value");
            char *path = make_path(base, "Present");
            free(base);
            emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      strdup("present"), strdup("Present"));
            char *pt = str_append(strdup(""), x_go);
            pt = str_append(pt, "ValuePr");
            row_set_field_type(ctx->bag, pt);
            free(pt);
            /* Flat: the union's present member (int32) lands on the
             * nested __value node (the register — cur is the ENCLOSING
             * spec struct here). display label: the open-type VALUE member's
             * td-member name ("value" — the &Value/&InitiatingMessage
             * Identifier names the class FIELD, not this member). */
            go_flat_member_prim_on(-1, "int32_t", "present", 0);
            go_flat_label_last_member("value");
            (void)valmember;
        }
    }
    /* PrNothing discriminant const, value 0, in this module (module already
     * rebound to X's by emit_spec). */
    {
        char *raw = str_append(strdup(""), x_cid);
        raw = str_append(raw, "__value_PR_NOTHING");
        char *go = str_append(strdup(""), x_go);
        go = str_append(go, "ValuePrNothing");
        char *type_go = str_append(strdup(""), x_go);
        type_go = str_append(type_go, "ValuePr");
        char *path = make_path(parent_path, "ValuePrNothing");
        emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
        /* Value 0: NOTHING heads the __value_PR enum (asn1c_C.c:2842-2843,
         * the indexToPresence table: NOTHING first, then one entry per object
         * row — the row ORDER is the numbering, i.e. the same order the alt
         * loop below walks). */
        row_set_const(ctx->bag, "0", type_go);
        free(type_go);
    }
    /* Iterate rows, dedup by the alt's ASN.1 Identifier exactly as asn1c does
     * (asn1c_C.c:1096 asn1p_lookup_child — duplicate &Value rows collapse to one
     * alt). Without this, extensible object sets with repeated Value members
     * produce spurious per-name collisions. */
    char **seen = NULL;
    size_t n_seen = 0, cap_seen = 0;
    /* leaf-stage body data: the __value_PR value is the alt's DEDUPED SEQUENCE
     * position (PrNothing=0 above, then 1,2,...), mirroring asn1c's own
     * numbering (asn1c_C.c:2842-2852 indexToPresence: NOTHING first, then one
     * entry per object row in set order; the open-type CHOICE members are
     * cloned in that same deduped row order — asn1c_lang_C_OpenType:1086-1092
     * — and the _PR enum carries no explicit values, so implicit numbering IS
     * the row order). Verified non-sequential case: InitiatingMessage__value_
     * PR_ErrorIndication = 23 (row 23 of an ELEMENTARY-PROCEDURES set) while
     * procedureCode(id-ErrorIndication) = 2 — InitiatingMessage.h:88-110. */
    int value_seq = 0;
    for(size_t r = 0; r < ioc.ioct->rows; r++) {
        struct asn1p_ioc_cell_s *cell = &ioc.ioct->row[r]->column[col];
        if(!cell->value || !cell->value->Identifier)
            continue;
        size_t s;
        for(s = 0; s < n_seen; s++)
            if(strcmp(seen[s], cell->value->Identifier) == 0) break;
        int dedup_alt = (s < n_seen);
        /* dedupeded alts reuse the alt's original _PR slot (the alt was
         * emitted when first seen); new alts take the next sequence
         * position. Positioned BEFORE the seen[] append so the first
         * occurrence's slot is 1 (row order), matching ++value_seq below. */
        int present_val = dedup_alt ? (int)(s + 1) : (int)(n_seen + 1);
        char *dup = dedup_alt ? NULL : strdup(cell->value->Identifier);
        if(dup) {
            if(n_seen + 1 > cap_seen) {
                size_t nc = cap_seen ? cap_seen * 2 : 8;
                char **np = realloc(seen, nc * sizeof(char *));
                if(np) { seen = np; cap_seen = nc; } else { free(dup); goto done_seen; }
            }
            seen[n_seen++] = dup;
        }
        /* Conv (the IOC rule): record this IOC dispatch row — id/criticality off
         * the row's earlier columns (INTEGER cells: the value via
         * value->value.v_integer; criticality's Criticality numbering
         * reject=0/ignore=1/notify=2 — the enumerand's own ASN.1 value),
         * present = the deduped alt sequence position (1,2,...; the same
         * value ++value_seq renders below), alt_token = the union member
         * token, alt_msg = the payload's own prefixed cid (GO_MKID of the
         * chased terminal). The envelope marker (procedure-dispatch) keys on the id
         * member: column 0 of an ELEMENTARY-PROCEDURES row is
         * &procedureCode, of a PROTOCOL-IES row &id.
         *
         * The recognized dispatch spellings are exactly &id, &procedureCode
         * and &criticality (the constructor rule's shape); a class field
         * spelled any other way that a row cell populates is an
         * unrecognized dispatch shape — fail loud HERE, naming the object
         * class field, rather than let the ctor layer die on an id -1
         * sentinel it cannot attribute. A class that omits &criticality
         * is a SUPPORTED shape (rows carry no criticality; the
         * constructors omit the field). */
        {
            long row_id = -1, row_crit = -1;
            const char *row_id_member = "id";
            char *id_gov = NULL;   /* R2 name of the id column's declared type */
            char *crit_gov = NULL; /* ... of &criticality; NULL = no column */
            int unknown_col = 0;
            int id_literal = 0;    /* the id cell is a bare INTEGER literal */
            /* scan every column EXCEPT the value column — procedure-dispatch rows place
             * &procedureCode/&criticality AFTER the &InitiatingMessage col */
            for(size_t oc = 0; oc < ioc.ioct->row[r]->columns; oc++) {
                if((ssize_t)oc == col) continue;
                struct asn1p_ioc_cell_s *ocell =
                    &ioc.ioct->row[r]->column[oc];
                if(!ocell->field || !ocell->field->Identifier
                   || !ocell->value || !ocell->value->Identifier)
                    continue;
                const char *fid = ocell->field->Identifier;
                /* the cell value: an INTEGER literal (id-dispatch &id rows) or a
                 * REFERENCE to a value assignment (procedure-dispatch: PROCEDURE CODE
                 * id-Subscription — chase the terminal for the integer;
                 * CRITICALITY reject is an ENUMERATED reference likewise). */
                /* VALUE-ASSIGNMENT chase (id-dispatch and procedure-dispatch id cells): the cell
                 * value references a value assignment (id-RequestID ::=
                 * 29 / id-Subscription ::= 8). Resolve by the SAME
                 * read-only lookup chain the C backend's IOC emitter uses
                 * (asn1c_ioc.c:161-171 — asn1f_lookup_symbol_ex loop until
                 * the value is not ATV_REFERENCED); NOT asn1f_find_terminal_
                 * value (it resolves in place and re-fatal'd the C naming
                 * pass on such modules). */
                asn1p_expr_t *cv = ocell->value;
                while(cv && cv->value
                      && cv->value->type == ATV_REFERENCED) {
                    asn1p_expr_t *nx = WITH_MODULE_NAMESPACE(
                        cv->module, cv_ns,
                        asn1f_lookup_symbol_ex(ctx->asn, cv_ns, cv,
                                               cv->value->value.reference));
                    if(!nx)
                        nx = asn1f_lookup_symbol_ex(ctx->asn, ctx->ns, cv,
                                                    cv->value->value.reference);
                    if(!nx) {
                        /* the defining module may not IMPORT the value
                         * assignment (the PROCEDURE CODE row cell sits in
                         * PDU-Descriptions, the value in Constants) —
                         * sweep every module's namespace. */
                        asn1p_module_t *mscan;
                        TQ_FOR(mscan, &(ctx->asn->modules), mod_next) {
                            if(nx) break;
                            nx = WITH_MODULE_NAMESPACE(
                                mscan, ms_ns,
                                asn1f_lookup_symbol_ex(ctx->asn, ms_ns, cv,
                                          cv->value->value.reference));
                        }
                    }
                    if(!nx) break;
                    cv = nx;
                }
                asn1p_value_t *v = cv && cv->value
                                  && cv->value->type != ATV_REFERENCED
                                       ? cv->value : NULL;
                if(strcmp(fid, "&procedureCode") == 0) {
                    row_id_member = "procedureCode";
                    if(v) row_id = (long)v->value.v_integer;
                    free(id_gov);
                    id_gov = column_governing_go(ctx, ocell->field);
                    id_literal = cell_id_is_literal(cv)
                                 || column_is_inline(ocell->field);
                } else if(strcmp(fid, "&id") == 0) {
                    if(v) row_id = (long)v->value.v_integer;
                    free(id_gov);
                    id_gov = column_governing_go(ctx, ocell->field);
                    id_literal = cell_id_is_literal(cv)
                                 || column_is_inline(ocell->field);
                } else if(strcmp(fid, "&criticality") == 0) {
                    if(v) row_crit = (long)v->value.v_integer;
                    free(crit_gov);
                    crit_gov = column_governing_go(ctx, ocell->field);
                } else if(strcmp(fid, "&presence") == 0) {
                    /* a known non-dispatch column of the 3GPP IE classes
                     * (mandatory/optional/conditional): not part of the
                     * constructor's material — the ctor layer never reads
                     * it — but a legitimate class field, not an error. */
                } else if(strcmp(fid, "&InitiatingMessage") == 0
                          || strcmp(fid, "&SuccessfulOutcome") == 0
                          || strcmp(fid, "&UnsuccessfulOutcome") == 0) {
                    /* the procedure-dispatch class's message columns: each
                     * IS the value column of its own envelope spec (only
                     * the column matching this walk's value member is
                     * excluded above); the siblings are known payloads of
                     * the other two envelope specializations. */
                } else {
                    unknown_col = 1;
                    fprintf(stderr,
                            "asn1cgo: object class field %s of object set %s "
                            "is not a recognized dispatch field (recognized: "
                            "&id, &procedureCode, &criticality, &presence, "
                            "the procedure message columns; module %s)\n",
                            fid,
                            ioc.objset && ioc.objset->Identifier
                                ? ioc.objset->Identifier
                                : (cell->value->Identifier
                                       ? cell->value->Identifier : "?"),
                            ctx->module ? ctx->module : "?");
                }
            }
            /* the alt payload's own cid: GO_MKID of the chased terminal of
             * the &Value cell (a named message type in this spec) */
            const char *amsg = "";
            {
                asn1p_expr_t *vt_ = cell->value;
                if(vt_->expr_type == A1TC_REFERENCE
                   || vt_->meta_type == AMT_TYPEREF) {
                    asn1p_expr_t *t_ =
                        asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, vt_);
                    if(t_) vt_ = t_;
                }
                if(vt_->Identifier) amsg = GO_MKID(vt_);
            }
            int is_env = (strcmp(row_id_member, "procedureCode") == 0);
            /* the unrecognized-shape guard: a column the dispatcher did not
             * name, or an id that never resolved (a dispatch column spelled
             * differently leaves row_id at its -1 sentinel even when each
             * cell DID resolve) — either way the ctor layer cannot be told
             * what to emit; fail the run naming the class, never skip the
             * row and never misemit. */
            if(unknown_col || row_id == -1) {
                fprintf(stderr,
                        "asn1cgo: IOC dispatch row of %s (module %s) has an "
                        "unrecognized object-class shape%s — refusing to "
                        "emit its layer\n",
                        x_go, ctx->module ? ctx->module : "?",
                        unknown_col ? " (unrecognized class field named above)"
                                    : " (no recognizable id column)");
                ctx->bag->failed = 1;
            }
            { char *alt_tok = go_mk_suffix(cell->value);
              go_conv_record_ioc_row(x_cid, row_id_member, row_id, row_crit,
                                     present_val, alt_tok, amsg, is_env,
                                     id_gov ? id_gov : "", crit_gov,
                                     id_literal);
              free(alt_tok); }   /* record copies (cstrdup) — owned transcient */
            free(id_gov);
            free(crit_gov);
        if(dedup_alt) continue;   /* alt already emitted on its first row */

        }
        /* the __value_PR enumerant suffix and the union member decl
         * token are unprefixed member tokens (c_presence_name suffix +
         * MKID_safe; asn1c_naming.c:304, asn1c_C.c:1353). */
        /* A built-in type written directly in the object (`TYPE BOOLEAN`,
         * not a reference to a type assignment): asn1c makes the union
         * member the bare leaf. Only unconstrained leaf types reach a
         * compilable C union (asn1c fails on NULL, ENUMERATED, constrained
         * and constructed cells), so anything else is refused here. */
        int alt_lk = -1, alt_wide = 0, alt_null = 0;
        /* a constructed type written in the object (TYPE SEQUENCE {...},
         * SEQUENCE OF ...): an inline alternative, minted like an inline
         * CHOICE alternative (<X>Value<Alt>, C struct <X>__value__<alt>) */
        asn1p_expr_t *alt_inline = NULL;
        if(cell->value->expr_type != A1TC_REFERENCE
           && cell->value->meta_type != AMT_TYPEREF
           && (go_is_struct_kind(cell->value->expr_type)
               || cell->value->expr_type == ASN_CONSTR_CHOICE
               || go_is_list_kind(cell->value->expr_type)
               || cell->value->expr_type == ASN_BASIC_ENUMERATED))
            alt_inline = cell->value;
        if(!alt_inline && cell->value->expr_type != A1TC_REFERENCE
           && cell->value->meta_type != AMT_TYPEREF) {
            asn1p_expr_t *bv = cell->value;
            alt_null = go_construct_classify(bv) == GO_CONSTR_NULL;
            ctx->wide_nr = 1; ctx->wide_hit = 0;
            alt_lk = classify_leaf(ctx, bv, parent_path);
            alt_wide = ctx->wide_hit;
            ctx->wide_nr = 0; ctx->wide_hit = 0;
            if(!go_leaf_flat_prim(alt_lk)) alt_lk = -1;
            /* the BitString helper type lives in the module that uses it */
            if(alt_lk >= 0
               && go_construct_classify(bv) == GO_CONSTR_BIT_STRING)
                mark_bitstring_module(ctx->bag, ctx->module);
        }
        char *altcid = go_mk_suffix(cell->value);
        char *altgo = go_r2(altcid);
        /* A named alternative's own type: the chased terminal. Its C name
         * (and so its Go name) is module-prefixed when the name exists in
         * several modules (ModB_Flag / ModBFlag), while the union member
         * token stays the bare reference (Flag). */
        asn1p_expr_t *alt_term = NULL;
        if(cell->value->expr_type == A1TC_REFERENCE
           || cell->value->meta_type == AMT_TYPEREF) {
            alt_term = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns,
                                                   cell->value);
            if(alt_term && !alt_term->Identifier) alt_term = NULL;
        }
        char *inl_go = NULL, *inl_cid = NULL;
        if(alt_inline) {
            inl_go = str_append(strdup(""), x_go);
            inl_go = str_append(inl_go, "Value");
            inl_go = str_append(inl_go, altgo);
            char *vx = str_append(strdup(""), x_cid);
            vx = str_append(vx, "__value");
            inl_cid = go_cid_compound(vx, "__", altcid);
            free(vx);
        }
        /* choice-const <X>ValuePr<Alt>; rawCid = <X_cid>__value_PR_<AltCid> (the
         * real asn1c enum-member token). */
        {
            char *raw = str_append(strdup(""), x_cid);
            raw = str_append(raw, "__value_PR_");
            raw = str_append(raw, altcid);
            char *go = str_append(strdup(""), x_go);
            go = str_append(go, "ValuePr");
            go = str_append(go, altgo);
            char *type_go = str_append(strdup(""), x_go);
            type_go = str_append(type_go, "ValuePr");
            char *path = make_path(parent_path, cell->value->Identifier);
            emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
            row_set_const(ctx->bag, asn1p_itoa(++value_seq), type_go);
            free(type_go);
        }
        /* A NULL written in the object (TYPE NULL): like a NULL CHOICE
         * alternative, only its Pr const; no Go field and no Flat slot (the
         * C union member NULL_ carries nothing), and the conv switches get
         * a bare case for it. */
        if(alt_null) {
            char *node = str_append(strdup(""), x_cid);
            node = str_append(node, "__value");
            go_conv_record_null_alt(node, altcid);
            free(node);
            goto alt_done;
        }
        /* field row: the alt's data pointer, struct-scoped to the union.
         * struct-body stage: the field's Go type is the alt's own named type — a pointer
         * (pointer per alt); cross-module qualification happens post-walk
         * (qualify_field_types, once the whole name table exists). PATH: under
         * the union's own scope (parent_path + "Value" + alt) — same rule as
         * the Present row above: the alt field belongs to the <X>Value union
         * struct, and the dump-side owner attribution (path-keyed
         * projection bucketing) keys a row to the union by the "Value"
         * path segment. A row at <X>.<Alt> would attribute to the envelope
         * IEs struct (or scopeless), desynchronizing dump vs emitted body. */
        {
            char *base = make_path(parent_path, "Value");
            char *path = make_path(base, cell->value->Identifier);
            free(base);
            emit_name(ctx->bag, ctx->module, path, GK_FIELD,
                      own(altcid), strdup(altgo));
            char *ft = str_append(strdup(""), "*");
            if(alt_lk >= 0) {
                /* a built-in leaf cell (`TYPE BOOLEAN`): no named Go type
                 * exists; the field is the leaf's mapping-table type. */
                const char *under = go_types_leaf_underlying(alt_lk);
                ft = str_append(ft, under ? under : altgo);
            } else if(alt_inline) {
                ft = str_append(ft, inl_go);
            } else if(alt_term) {
                char *tgo = go_type_go(alt_term);
                ft = str_append(ft, tgo);
                free(tgo);
            } else
                ft = str_append(ft, altgo);
            row_set_field_type(ctx->bag, ft);
            free(ft);
        }
        /* Flat (path 2 / the open-type mapping row): the open-type value
         * union is ALWAYS INLINE per alt (the IOC dispatch rule: the asn1c union
         * members here are inline structs; no re-synthesis). One inline
         * slot per alt cid under the __value node. */
        {
            char *flat_alt = own(alt_inline ? inl_cid
                                 : alt_term ? GO_MKID(alt_term) : altcid);
            char *flat_slot = own(altcid);  /* the member token */
            if(alt_inline
               && alt_inline->expr_type == ASN_BASIC_ENUMERATED) {
                /* an ENUMERATED written in the object: the bare int32 slot,
                 * as for an inline ENUMERATED CHOICE alternative */
                go_flat_member_prim_on(-1, "int32_t", flat_slot, 0);
            } else if(alt_lk >= 0) {
                /* built-in leaf cell: the union member is the bare leaf
                 * (`BOOLEAN_t BOOLEAN;`, `long INTEGER;`) — a prim slot */
                go_flat_member_prim_on(-1, go_leaf_flat_prim(alt_lk),
                                       flat_slot, 0);
                if(alt_wide) go_flat_last_member_wide();
                go_flat_last_member_gleaf(alt_lk);
            } else
                go_flat_member_ref_on(-1, flat_alt, flat_slot, 0);
            /* alt slot label = the alt's ASN.1 Identifier (the td
             * union-member name string). */
            go_flat_label_last_member(cell->value->Identifier);
            free(flat_alt); free(flat_slot);
        }
        if(alt_inline)
            emit_value_inline_alt(ctx, alt_inline, inl_go, inl_cid,
                                  parent_path, altcid);
alt_done:
        free(inl_go); free(inl_cid);
        free(altgo);
        free(altcid);
    }
done_seen:
    for(size_t s = 0; s < n_seen; s++) free(seen[s]);
    free(seen);
    struct_scope_reset(ctx->bag);
}

/* emit_value_inline_alt: the Go type of a constructed type written directly
 * in an object (TYPE SEQUENCE { a INTEGER }): asn1c makes it an inline member
 * of the open type's union (`struct <X>__value__<alt> {...} <alt>;`), so it
 * is minted exactly like an inline CHOICE alternative (emit_choice): a
 * package-scoped Flat node <X>__value__<alt> (C struct tag only: inline_elem
 * "struct") and the Go type <X>Value<Alt>. The Flat cur / last-nested
 * registers and the Go field scope belong to the value union again after. */
static void
emit_value_inline_alt(struct walk_ctx *ctx, asn1p_expr_t *alt,
                      const char *inline_go, const char *inline_cid,
                      const char *parent_path, const char *altcid) {
    char *vbase = make_path(parent_path, "Value");
    char *alt_path = make_path(vbase, altcid);
    free(vbase);
    /* the classify walk never visits a type written in an object: note its
     * runtime headers (constr_SET.h) the way that walk does */
    (void)go_construct_classify(alt);
    char *save_sf = NULL;
    if(ctx->bag->sf_cur_owner) save_sf = strdup(ctx->bag->sf_cur_owner);
    int save_fcur = go_flat_cur_get();
    int save_nest = go_flat_last_nest_get();
    if(alt->expr_type == ASN_BASIC_ENUMERATED) {
        /* as emit_choice's inline ENUMERATED alt: `type <X>Value<Alt>
         * int32` plus its constants; no Flat node (the slot is int32) */
        emit_name(ctx->bag, ctx->module, strdup(alt_path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        row_set_leaf(ctx->bag, GLEAF_ENUM);
        emit_enum(ctx, inline_go, inline_cid, alt_path, alt);
    } else if(go_is_list_kind(alt->expr_type)) {
        /* as emit_choice's inline SEQUENCE OF alt: `type <X>Value<Alt>
         * []Elem`, a Flat {items,count} node */
        emit_name(ctx->bag, ctx->module, strdup(alt_path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        int sq_row = ctx->bag->n_rows - 1;
        asn1p_expr_t *sq_elem = TQ_FIRST(&alt->members);
        char *ge = NULL, *fc = NULL;
        int mrc = 0;
        if(sq_elem && sq_elem->expr_type == ASN_BASIC_BIT_STRING)
            mark_bitstring_module(ctx->bag, ctx->module);
        if(seqof_elem_is_inline(sq_elem)) {
            mrc = mint_inline_seqof_elem(ctx, sq_elem, alt_path, inline_go,
                                         inline_cid, &ge, &fc);
        } else {
            ge = slice_element_type(ctx, sq_elem, alt_path);
            if(ctx->bag->failed) mrc = -1;
            else {
                asn1p_expr_t *et = sq_elem;
                asn1p_expr_t *t2 =
                    asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, sq_elem);
                if(t2) et = t2;
                fc = own(GO_MKID(et));
            }
        }
        if(mrc >= 0 && !ctx->bag->failed) {
            row_set_slice_elem_at(ctx->bag, sq_row, ge);
            (void)go_flat_seqof(inline_cid, fc, 0,
                                alt->expr_type == ASN_CONSTR_SET_OF,
                                ctx->module);
            go_flat_mark_inline_elem("struct", NULL);
        }
        free(ge); free(fc);
    } else {
        emit_name(ctx->bag, ctx->module, strdup(alt_path), GK_INLINE,
                  strdup(inline_cid), strdup(inline_go));
        if(alt->expr_type == ASN_CONSTR_CHOICE) {
            field_scope_push(ctx->bag);
            emit_choice(ctx, inline_go, inline_cid, alt_path, alt);
            field_scope_pop(ctx->bag);
            go_flat_mark_inline_elem("struct", NULL);
        } else {   /* SEQUENCE / SET: a struct with member fields */
            const char *save_go = ctx->parent_go;
            const char *save_cid = ctx->parent_cid;
            go_flat_struct(inline_cid, ctx->module);
            go_flat_label_cur(alt->Identifier);
            go_flat_mark_inline_elem("struct", NULL);
            ctx->parent_go = inline_go;
            ctx->parent_cid = inline_cid;
            field_scope_push(ctx->bag);
            row_set_is_struct(ctx->bag);
            struct_scope_open(ctx->bag, inline_go);
            (void)walk_names_members(ctx, alt, alt_path);
            struct_scope_reset(ctx->bag);
            field_scope_pop(ctx->bag);
            ctx->parent_go = save_go;
            ctx->parent_cid = save_cid;
        }
    }
    go_flat_cur_restore(save_fcur);
    go_flat_last_nest_set(save_nest);
    free(bag_sf_restore(ctx->bag, save_sf));
    free(alt_path);
}

/* emit_value_pr_nothing: the lone discriminant for a value union with no
 * resolved alternatives (empty / unresolved object set). rawCid uses the real
 * C-ident prefix x_cid (the verbatim <X_cid>__value_PR_NOTHING token). */
static void
emit_value_pr_nothing(struct walk_ctx *ctx, const char *x_go,
                      const char *x_cid, const char *parent_path) {
    char *raw = str_append(strdup(""), x_cid);
    raw = str_append(raw, "__value_PR_NOTHING");
    char *go = str_append(strdup(""), x_go);
    go = str_append(go, "ValuePrNothing");
    char *type_go = str_append(strdup(""), x_go);
    type_go = str_append(type_go, "ValuePr");
    char *path = make_path(parent_path, "ValuePrNothing");
    emit_name(ctx->bag, ctx->module, path, GK_CHOICE_CONST, raw, go);
    row_set_const(ctx->bag, "0", type_go);
    free(type_go);
}

/* member_is_default: asn1c's own DEFAULT-vs-OPTIONAL discriminator
 * (asn1c_C.c:1351-1358): DEFAULT iff (flags & (EM_DEFAULT & ~EM_INDIRECT))
 * == EM_DEFAULT & ~EM_INDIRECT -- an exact-mask test, NOT a bit test
 * (EM_OPTIONAL 0x07 shares bits with EM_DEFAULT 0x0F; the C pass adds
 * bits, so `flags == EM_DEFAULT` would miss). */
int
member_is_default(const asn1p_expr_t *child) {
    return (child->marker.flags & (EM_DEFAULT & ~EM_INDIRECT))
           == (EM_DEFAULT & ~EM_INDIRECT);
}

/* member_stars: the Go pointer-star rule for a struct member (the struct-body pass).
 * Types.go stars a member iff it is OPTIONAL — nil = absent — with no
 * exception for slice-shaped members (an OPTIONAL SEQUENCE OF is a
 * pointer-to-slice: nil pointer = absent, non-nil pointer to nil/empty slice
 * = present). EM_INDIRECT is deliberately NOT read here: it is the C
 * column's pointer decision (recursion break asn1c_C.c:3520, or
 * -findirect-choice on a CHOICE member :3490-3497); types.go never follows
 * it — the Go side keeps the by-value inline shape there. Pointers come
 * from OPTIONAL only (CHOICE/value-union alt fields are pointers by
 * construction, not via this function).
 *   EM_DEFAULT — a real DEFAULT member the C generator gives default
 *                 callbacks for: a plain value (""); any other DEFAULT
 *                 form fails the run (exit 70) naming the reason.
 * Returns "*" when the member is pointer-shaped, "" otherwise; sets failed on
 * the bag for the DEFAULT case (the caller's -1 return fails the run). */
const char *
member_stars(struct walk_ctx *ctx, asn1p_expr_t *child, const char *path) {
    /* asn1c's own DEFAULT-vs-OPTIONAL discriminator (asn1c_C.c:1351-1358):
     * DEFAULT iff (flags & (EM_DEFAULT & ~EM_INDIRECT)) == EM_DEFAULT &
     * ~EM_INDIRECT — an exact-mask test, NOT a bit test (EM_OPTIONAL 0x07
     * shares bits with EM_DEFAULT 0x0F; a plain `& EM_DEFAULT` would
     * misread EM_UNRECURSE-composites). A real DEFAULT member is out of
     * model: fail loud, no Go shape is picked. */
    if(member_is_default(child)) {
        /* A supported DEFAULT member (the C generator emits default
         * callbacks for it: the shared predicate) is a PLAIN VALUE in Go --
         * never a pointer; the C runtime fills an absent default on decode.
         * Anything else is out of model: fail loud, naming the reason. */
        arg_t darg;
        const char *why = NULL;
        memset(&darg, 0, sizeof darg);
        darg.asn = ctx->asn;
        darg.ns = ctx->ns;
        darg.expr = child;
        int dflt_ok = asn1c_default_callbacks_supported(&darg, child, &why);
        if(!dflt_ok) {
            fprintf(stderr,
                    "asn1cgo: DEFAULT member %s is out of model in "
                    "module %s: %s\n",
                    path ? path : "?", ctx->module ? ctx->module : "?",
                    why ? why : "unsupported DEFAULT form");
            ctx->bag->failed = 1;
        }
        ctx->last_opt_extra = 0;
        return "";
    }
    /* Nested-mask test, NOT a bit test and NOT exact-equality. The marker
     * flags are a NESTED hierarchy (asn1p_expr.h:208-212):
     *   EM_INDIRECT 0x01 < EM_OMITABLE 0x03 < EM_OPTIONAL 0x07 < EM_DEFAULT 0x0F
     * and fixer passes ADD bits to an existing marker rather than replacing
     * it (-findirect-choice sets EM_INDIRECT|EM_UNRECURSE -> 0x11 on a
     * mandatory CHOICE member; expr_break_recursion's back-edge break sets
     * EM_INDIRECT on an OPTIONAL member too, giving 0x17 — OPTIONAL still).
     * So:
     *   FALSE-STAR trap (bit test `f & EM_OPTIONAL`): 0x11 & 0x07 = 0x01 ->
     *     a mandatory recursion-broken member stars (a by-value
     *     member of a recursive CHOICE type would be emitted as a pointer).
     *   STAR-LOSS trap (exact equality `== EM_OPTIONAL`): an OPTIONAL member
     *     carrying extra bits (0x17) compares unequal and loses its star
     *     ("OPTIONAL is always *X" — the star must survive).
     * The containment form `(f & EM_OPTIONAL) == EM_OPTIONAL` (the same form
     * go_walk.c:409 and asn1c_C.c:1357 use for the OPTIONAL arm) is correct
     * under nesting: EM_OPTIONAL's bits are ALL present iff the member is
     * OPTIONAL, whatever additional bits the fixer added. EM_DEFAULT was
     * already rejected above, so a 0x1F-style superset cannot reach here.
     * Census: an OPTIONAL member whose flags carry bits
     * BEYOND EM_OPTIONAL is recorded on ctx->last_opt_extra (the caller
     * copies it onto the member's field row) — reported at run end,
     * purely informational. */
    ctx->last_opt_extra = 0;
    if((child->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
        if(child->marker.flags & ~EM_OPTIONAL)
            ctx->last_opt_extra = child->marker.flags & ~EM_OPTIONAL;
        return "*";
    }
    /* An extension ADDITION (a member after the first `...` of an extensible
     * SEQUENCE) without OPTIONAL: the C pass stamps EM_OMITABLE|EM_INDIRECT on
     * every such member (asn1c_C.c:362), because a sender that implements an
     * older version of the spec leaves it out of the encoding (X.691). The C
     * struct member is a pointer and NULL means "absent", so the Go field is a
     * pointer too, exactly as for OPTIONAL. A DEFAULT addition never reaches
     * here (handled above: a plain value). Plain mandatory members carry at
     * most EM_INDIRECT|EM_UNRECURSE, never the EM_OMITABLE bit. */
    if((child->marker.flags & EM_OMITABLE) == EM_OMITABLE)
        return "*";
    return "";
}

/* classfield_declared_type: the declared TYPE of a lowercase class-field
 * reference member (&id, &procedureCode, &criticality — the envelope members
 * of a field-shaped specialization). Resolution is asn1f_class_access_ex —
 * the same resolver the C backend uses for an &field reference
 * (asn1c_C.c:1284 calls the same entry) — over the member's own reference.
 * The result is the class-field's declared type expression (ProtocolIE-ID,
 * ProcedureCode, Criticality — the FIXED type field's child). Returns NULL
 * when the reference does not resolve (the caller leaves the field type
 * unset; go build names it loudly). */
static asn1p_expr_t *
classfield_declared_type(struct walk_ctx *ctx, asn1p_expr_t *mem) {
    if(!mem->reference) return NULL;
    asn1p_expr_t *r = asn1f_class_access_ex(ctx->asn, NULL, ctx->ns, mem, NULL,
                                            mem->reference);
    /* The returned field-type expr is the class-field's declared-type node —
     * an A1TC_REFERENCE (e.g. `ProtocolIE-ID`) with NO Identifier of its own
     * (asn1c_make_identifier would render it "Member", asn1c_misc.c:78).
     * Chase it to the terminal assignment so the Go name is the referenced
     * type's own goName. */
    if(r && (r->expr_type == A1TC_REFERENCE || r->meta_type == AMT_TYPEREF)) {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, r);
        if(t) return t;
    }
    return r;
}

/* The R2 Go name of an IOC COLUMN's declared type. The column's field
 * expr (the class field spec, e.g. `&id ProtocolIE-ID UNIQUE`) carries the
 * declared type as its first child (asn1p: a FixedTypeValueFieldSpec's
 * Type — as parsed at asn1p_y.y's ObjectClassField parse, the child of the
 * field expr). Chase a reference to its terminal assignment and R2 its
 * real C ident (the same naming path the envelope member rows take). */
static char *
column_governing_go(struct walk_ctx *ctx, asn1p_expr_t *field) {
    asn1p_expr_t *ch = TQ_FIRST(&field->members);
    if(!ch) return NULL;
    asn1p_expr_t *t = ch;
    if(ch->expr_type == A1TC_REFERENCE || ch->meta_type == AMT_TYPEREF) {
        asn1p_expr_t *r = asn1f_find_terminal_type_ex(ctx->asn, ctx->ns, ch);
        if(r) t = r;
    }
    if(!t->Identifier) {
        /* an inline column type (`&id INTEGER (0..255)`): the Go field is
         * the leaf's mapping-table type itself (int64, ...). */
        int lk = classify_leaf(ctx, t, "");
        const char *under = go_types_leaf_underlying(lk);
        return under ? strdup(under) : NULL;
    }
    return go_type_go(t);
}

/* Is an IOC column's declared type an inline (unnamed) type, e.g.
 * `&id INTEGER (0..255)`? Its Go type is a bare leaf (int64) and a value
 * assignment governed by it emits no Go const, so every id of such a
 * column is rendered like a literal (<leaf>(<n>), constructor New<X>Id<n>). */
static int
column_is_inline(asn1p_expr_t *field) {
    asn1p_expr_t *ch = TQ_FIRST(&field->members);
    return ch && ch->expr_type != A1TC_REFERENCE
           && ch->meta_type != AMT_TYPEREF && !ch->Identifier;
}

/* Is an id cell's chased value a NUMBER LITERAL (no value assignment
 * behind it)? asn1p mints the literal's own numeric text as the resolved
 * expr's Identifier ("1" for {ID 1}), while a value-assignment reference
 * chases to the assignment node whose Identifier is the assignment's own
 * (id-RequestID — a legal ASN.1 identifier always starts with a
 * lowercase letter, never a digit, so a digits-only Identifier is
 * unambiguous). */
static int
cell_id_is_literal(asn1p_expr_t *cv) {
    if(!cv || !cv->Identifier || !cv->Identifier[0]) return 0;
    for(const char *p = cv->Identifier; *p; p++)
        if(*p < '0' || *p > '9') return 0;
    return 1;
}
