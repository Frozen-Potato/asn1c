/*
 * go_glue_ref.c — emit_ref, the size / fill / read lines of one
 * named-type member.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

/* ---------------------------------------------------------------------------
 * emit_ref — one named-type member (FT_REF).
 *   r = resolved target node. Stars on the member row = the Flat slot is a
 *   pointer (an OPTIONAL *T whose Go field is *T, or by-value-in-Go with a
 *   pointer Flat slot); unstarred = the target is inline in the host.
 * A SEQ-OF target (named slice or container clone) emits through its
 * {items,count} header — via_ptr says whether the HEADER itself sits behind
 * the member's pointer slot.
 * ------------------------------------------------------------------------- */
void
emit_ref(ectx *E, flat_member *m, flat_type *r) {
    /* queue the target's own fns first (leaf scalar triples included: a
     * LEAF-typedef target called by name needs its size/fill/read triple;
     * send_type-fn skips non-PDU leaves elsewhere). Not for nested_only
     * targets (they inline). */
    if(r && !go_flat_ir_is_nested_only(r)) emit_type_fn(r);
    const char *tok = go_flat_ir_member_token(m);
    int stars = go_flat_ir_member_stars(m);
    char *offc = qconst(E->cnode, g_offconst_pfx(E->cnode, E->cpre, tok, go_flat_ir_name(E->t)));
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
    {
        /* The target struct is allocated behind a pointer slot with
         * alignInt64 bump-pointer placement, so a node whose C size is not a
         * multiple of 8 (a 4-byte SEQUENCE { e ENUMERATED }, an inline
         * SEQUENCE { z BOOLEAN }) forces padding up to the next 8-aligned
         * allocation that the narrow sizeof never reserves ("fixed-region
         * undercounted by 4"). Alloc and size both use the padded footprint
         * (tsz feeds BOTH), so consumption stays exactly the reservation.
         * Sizes that are multiples of 8 keep the const name, so unaffected
         * types emit byte-identical glue. */
        long nsz = go_flat_ir_node_size(r);
        if(nsz % 8) {
            free(tsz);
            tsz = gfmt("%ld", nsz + 8 - nsz % 8);
        }
    }
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
         * an ID list rides inline inside the ItemIEs value union,
         * &out->value.IDList) — the disjunctive form would emit
         * storePtr(hdr) / *(**byte)(slot) on an inline slot (the pointer
         * test would read the items FIELD as a header). Same conjunction the nested arm uses
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
         * A single `go_starred` disjunction (sft*)||(stars)
         * would conflate A with C: C-shaped slots would get storePtr/`(**byte)`
         * forms on an inline slot (reading the items FIELD as a header). */
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
             * Msg-IEs value.IDList: the C flat
             * writes the list INLINE at &out->value.IDList).
             * fill: the nil guard selects absent-vs-present; the header is
             * written AT the slot (no allocStruct/storePtr — the slot is
             * not a pointer). read: temp + (*T)(&tmp) (a []E cannot be
             * assigned to *NamedSlice directly). sizing: the inline header
             * is PART OF THE PARENT STRUCT (its 16B ride the parent's own
             * sizeof<Parent>, already counted by the owner) — NO +16 here.
             * A `fixed += 16` here would reserve 16B nothing ever allocates
             * (under-consuming by exactly 16 per inline arm — the
             * exact-consumption invariant would catch it). */
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
             * paramList: the flat slot holds a pointer to the
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
        else castbase = gown(prim ? gprim_own(prim) : "");
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
             * padding the narrow size never reserves (a struct
             * undercounts by exactly 4). Reserve the padded 8 like every
             * sibling emitter (the _bool32 arm, the generic prim-star arm). */
            int gw0 = gprim_width(prim);
            if(gw0 < 8) gw0 = 8;
            szc = gfmt("uintptr(%d)", gw0);
        }
        const char *szexpr = szc;
        if(go_flat_ir_null_leaf(r)) {
            /* a member of a NULL type: the Flat slot is an int32 placeholder
             * (the Go value carries nothing but its presence). */
            int ft_ptr = ft && *ft == '*';
            if(stars) {
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                    "\t\t*(*int32)(wv) = 0\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n", acc, szexpr, slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\t%s = &%s{}\n\t}\n", slot, acc, cast));
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tif %s != nil {\n\t\tfixed += %s\n\t}\n", acc, szexpr));
            } else {
                (*E->fill) = gam((*E->fill), gfmt(
                    "\t*(*int32)(%s) = 0\n", slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\t%s = %s%s{}\n", acc, ft_ptr ? "&" : "", cast));
            }
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            /* the union-ALT form: a Go star-string / star-byte-slice /
             * star-alias field whose
             * Flat member is an INLINE bytes_flat record (no pointer slot) —
             * the p != nil / allocStruct / storePtr machinery below is for
             * a STARRED Flat slot only (an OPTIONAL bytes member). */
            int is_str = ft && strcmp(unqual(ft), "string") == 0;
            int ft_ptr = ft && *ft == '*';
            const int strk = go_flat_ir_strk(r);
            if(strk) {
                /* a BMPString / UniversalString leaf behind a named type:
                 * UTF-8 <-> UCS-2/UCS-4 at the boundary (cast = the
                 * member's Go type, pointer star stripped). */
                const char *fn = strk_fn(strk);
                const char *gt = strk_gotype(strk);
                if(stars) {
                    char *deref = gfmt("%s(*%s)", gt, acc);
                    char *sz = strk_size(strk, deref, "\t");
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\tif %s != nil {\n"
                        "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                        "\t\twrite%sField(fa, wv, %s(*%s))\n"
                        "\t\tstorePtr(%s, wv)\n\t}\n",
                        acc, szexpr, fn, gt, acc, slot));
                    (*E->read) = gam((*E->read), gfmt(
                        "\tif p := *(**byte)(%s); p != nil {\n"
                        "\t\tucss, err := read%sField(unsafe.Pointer(p))\n"
                        "\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n"
                        "\t\trr2 := %s(ucss)\n\t\t%s = &rr2\n\t}\n",
                        slot, fn, cast, acc));
                    (*E->szt) = gam((*E->szt), gfmt(
                        "\tif %s != nil {\n\t\tfixed += uintptr(%s)\n%s\t}\n",
                        acc, szexpr, sz));
                    free(deref); free(sz);
                } else if(ft_ptr) {
                    char *deref = gfmt("%s(*%s)", gt, acc);
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twrite%sField(fa, %s, %s(*%s))\n", fn, slot, gt, acc));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t{\n\t\tucss, err := read%sField(%s)\n"
                        "\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n"
                        "\t\trr := %s(ucss)\n\t\t%s = &rr\n\t}\n",
                        fn, slot, cast, acc));
                    (*E->szt) = gam((*E->szt), strk_size(strk, deref, ""));
                    free(deref);
                } else {
                    char *deref = gfmt("%s(%s)", gt, acc);
                    char *asg = gfmt("%s = %s(%%s)", acc, cast);
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twrite%sField(fa, %s, %s(%s))\n", fn, slot, gt, acc));
                    (*E->read) = gam((*E->read), strk_read(strk, slot, asg));
                    (*E->szt) = gam((*E->szt), strk_size(strk, deref, ""));
                    free(deref); free(asg);
                }
            } else if(ft_ptr && !stars) {
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
                 * same fixed footprint under the same nil-guard (payload-only
                 * sizing would undercount the fixed region by exactly the
                 * record size: "fixed-region undercounted by 8/16"). */
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
                    /* strip the pointer star BEFORE qualifying: the casts
                     * below spell the pointee type, not a pointer type. */
                    const char *ftp = ft;
                    while(*ftp == '*') ftp++;
                    bst = qualify_alias(ftp);
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
                char *lbsq = local_bitstring();
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                    "\t\twriteBitsField(fa, wv, %s(%s(*%s)))\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n", acc, szexpr, lbsq, bst, acc, slot));
                free(lbsq);
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
                    char *wa = bits_bridge(go_flat_ir_module(E->t), acc, 1);
                    char *rd = gfmt("readBitsField(%s)", slot);
                    char *rb = bits_bridge(go_flat_ir_module(E->t), rd, 0);
                    (*E->fill) = gam((*E->fill), gfmt(
                        "\twriteBitsField(fa, %s, %s)\n", slot, wa));
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = %s\n", acc, rb));
                    free(wa); free(rd); free(rb);
                }
                (*E->szt) = gam((*E->szt), gfmt(
                    "\tpayload += uintptr(len(%s.Bytes))\n", acc));
            }
        } else {
            const char *gt = gprim_slot(prim);
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
                char *sv = gfmt("*%s", acc);
                char *stx = gconv_store(prim, gt, sv);
                char *rawp = gfmt("*(*%s)(unsafe.Pointer(p))", gt);
                char *ldx = gconv_load(prim, cast, rawp);
                (*E->fill) = gam((*E->fill), gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(%s, alignInt64)\n"
                    "\t\t*(*%s)(wv) = %s\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n",
                    acc, szexpr, gt, stx, slot));
                (*E->read) = gam((*E->read), gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\tsd := %s\n"
                    "\t\t%s = &sd\n\t}\n", slot, ldx, acc));
                free(sv); free(stx); free(rawp); free(ldx);
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
                char *stx = gconv_store(prim, gt, ival);
                char *rawv = gfmt("*(*%s)(%s)", gt, slot);
                char *ldx = gconv_load(prim, cast, rawv);
                (*E->fill) = gam((*E->fill), gfmt(
                    "\t*(*%s)(%s) = %s\n", gt, slot, stx));
                if(ptr_ft) {
                    char *tn = gfmt("sd%d", g_tmpseq++);
                    char *sdv = gfmt("\t%s := %s\n\t%s = &%s\n",
                                     tn, ldx, acc, tn);
                    (*E->read) = ga((*E->read), sdv);
                    free(sdv); free(tn);
                } else {
                    (*E->read) = gam((*E->read), gfmt(
                        "\t%s = %s\n", acc, ldx));
                }
                free(stx); free(rawv); free(ldx);
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
