/*
 * go_glue_fn.c — the SEQUENCE OF item helpers and
 * emit_type_fn, the size / fill / read functions of one type.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

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
void emit_type_fn(flat_type *t);
itemh *g_items = NULL;
int g_n_items = 0, g_cap_items = 0;

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

void emit_items_helper(flat_type *er);

/* the per-element dedup table of emit_items_helper (reset per package). */
static flat_type **g_done_elems = NULL;
static int g_n_done = 0, g_cap_done = 0;

void
item_helpers_reset(void) {
    for(int i = 0; i < g_n_items; i++) {
        free(g_items[i].sz); free(g_items[i].fill); free(g_items[i].read);
    }
    free(g_items); g_items = NULL; g_n_items = g_cap_items = 0;
    free(g_done_elems); g_done_elems = NULL; g_n_done = g_cap_done = 0;
}
void
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
    const char *gt = prim ? gprim_slot(prim) : NULL;

    /* ---- size<E>Items(&f, &p, items): nil/empty => nothing ----
     * A NODE element's per-item fn allocates BEYOND the stride (nested
     * CHOICE-struct copies, sub-list headers, ...): the size helper must
     * CALL the element's size fn per item and add both its fixed and
     * payload, not just n*stride (the fill helper's loop is the mirror).
     * A prim element is exactly one stride slot, no sub-allocation. */
    int scc_elem = conv_is_scc(er);
    /* the item array is ONE allocStruct(.., alignInt64): when the element
     * stride is not a multiple of 8, an odd-length array ends mid-word and
     * the next 8-aligned allocation pays the pad. Size and fill both reserve
     * / consume the array rounded up to 8 (only for such strides, so the
     * common helpers stay byte-identical). */
    int arr_pad = go_flat_ir_node_size(er) % 8 != 0;
    char *arr_sz = arr_pad ? gfmt("alignUp(n*uintptr(%s), alignInt64)", stride)
                           : gfmt("n * uintptr(%s)", stride);
    char *s = gfmt(
        "func size%sItems(f *uintptr, p *uintptr, items []%s%s) error {\n"
        "\tif items == nil {\n\t\treturn nil\n\t}\n"
        "\tn := uintptr(len(items))\n"
        "\t*f += %s\n",
        cam, qt, scc_elem ? ", depth int" : "", arr_sz);
    if(!prim_elem) {
        /* an SCC element must observe the HOST's depth (each item
         * sizes at host depth; the element's own guard+threading carries
         * the increment from there). A literal 0 here would reset the chain at
         * every named SEQ-OF boundary — the Go depth guard could never
         * trip through a SEQ-OF cycle (E_DEPTH).
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
        "\tarr := fa.allocStruct(%s, alignInt64)\n"
        "\tstorePtr(hdr, arr)\n",
        cam, qt, scc_elem ? ", depth int" : "",
        arr_pad ? "alignUp(uintptr(n)*stride, alignInt64)" : "uintptr(n)*stride");
    if(prim_elem) {
        char *stx = gconv_store(prim, gt ? gt : "int64", "items[j]");
        fl = gam(fl, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\t*(*%s)(s2) = %s\n"
            "\t}\n",
            gt ? gt : "int64", stx));
        free(stx);
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
        char *rawv = gfmt("*(*%s)(s2)", gt ? gt : "int64");
        char *ldx = gconv_load(prim, prim && strcmp(prim, "_bool32") == 0 ? "bool" : (gt ? gt : "int64"), rawv);
        rd = gam(rd, gfmt(
            "\tfor j := 0; j < n; j++ {\n"
            "\t\ts2 := unsafe.Pointer(uintptr(arr) + uintptr(j)*stride)\n"
            "\t\tout[j] = %s\n\t}\n",
            ldx));
        free(rawv); free(ldx);
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
    free(cam); free(qt); free(stride); free(arr_sz);
}

/* ---------------------------------------------------------------------------
 * emit_type_fn — one package-scoped node's size/fill/read triple, queued
 * into the registry (cycles close on the fn call; nested nodes inline).
 * ------------------------------------------------------------------------- */
void
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
        /* the leaf's own named alias, if any; a hidden inline-element leaf
         * has none — its Go type is the unnamed leaf mapping text */
        const char *al0 = go_flat_ir_go_type(t) ? go_flat_ir_go_type(t)
                                                : gf_goname(t);
        char *alq = NULL;                 /* package-qualified alias spelling */
        if(al0 && *al0) {
            const char *tm = go_flat_ir_module(t);
            if(go_flat_ir_go_type(t) || (tm && g_emit_mod && strcmp(tm, g_emit_mod) == 0)) alq = gown(al0);
            else { char *pk = gmodule_pkg(tm); alq = gfmt("%s.%s", pk, al0); free(pk); }
        }
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0 && go_flat_ir_strk(t)) {
            /* a BMPString / UniversalString leaf root (or hidden element):
             * UTF-8 <-> UCS-2/UCS-4 at the boundary. */
            const int strk = go_flat_ir_strk(t);
            const char *fn = strk_fn(strk);
            const char *gt = strk_gotype(strk);
            char *asg = gfmt("*v = %s(%%s)", (alq && *alq) ? alq : gt);
            char *vexp = gfmt("%s(*v)", gt);
            (*E.fill) = gam((*E.fill), gfmt("\twrite%sField(fa, slot, %s)\n", fn, vexp));
            (*E.read) = gam((*E.read), strk_read(strk, "slot", asg));
            (*E.szt) = gam((*E.szt), strk_size(strk, vexp, ""));
            free(asg); free(vexp);
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
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
            char *obs = owner_bitstring(go_flat_ir_module(t));
            (*E.fill) = gam((*E.fill), gfmt(
                "\twriteBitsField(fa, slot, %s{Bytes: (*v).Bytes, BitsUnused: (*v).BitsUnused})\n", lbs));
            (*E.read) = gam((*E.read), gfmt(
                "\tbs := %s(readBitsField(slot))\n"
                "\t*v = %s{Bytes: bs.Bytes, BitsUnused: bs.BitsUnused}\n",
                lbs, (alq && *alq && strcmp(alq, "BitString") != 0) ? alq : obs));
            free(lbs); free(obs);
            (*E.szt) = ga((*E.szt), "\tpayload += uintptr(len((*v).Bytes))\n");
        } else if(go_flat_ir_null_leaf(t)) {
            /* the hidden leaf of a NULL type assignment, the element of a
             * SEQUENCE OF it: a placeholder slot, the Go value is `alq{}` */
            (*E.fill) = ga((*E.fill), "\t*(*int32)(slot) = 0\n\t_ = v\n");
            (*E.read) = gam((*E.read), gfmt("\t*v = %s{}\n", (alq && *alq) ? alq : "struct{}"));
        } else if(go_flat_ir_go_type(t)
                  && strcmp(go_flat_ir_go_type(t), "struct{}") == 0) {
            /* a hidden NULL element: one int32 placeholder slot per item
             * (the Go value struct{} carries nothing but its presence). */
            (*E.fill) = ga((*E.fill), "\t*(*int32)(slot) = 0\n\t_ = v\n");
            (*E.read) = ga((*E.read), "\t*v = struct{}{}\n");
        } else {
            const char *gt = gprim_slot(prim);
            char *stx = gconv_store(prim, gt, "*v");
            char *rawv = gfmt("*(*%s)(slot)", gt);
            char *ldx = gconv_load(prim,
                (alq && *alq) ? alq : gprim_own(prim), rawv);
            (*E.fill) = gam((*E.fill), gfmt(
                "\t*(*%s)(slot) = %s\n", gt, stx));
            (*E.read) = gam((*E.read), gfmt(
                "\tsd := %s\n\t*v = sd\n", ldx));
            free(stx); free(rawv); free(ldx);
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
