/*
 * go_glue_prim.c — BMPString / UniversalString conversions and
 * go_emit_prim, the size / fill / read lines of one primitive member.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

/* ---------------------------------------------------------------------------
 * BMPString / UniversalString: the C buffer is UCS-2 / UCS-4 big-endian, the
 * Go value UTF-8. strk 1 = BMP, 2 = Universal (the Flat member's / leaf's
 * strk). The helpers (GLUE_STRCONV below) are emitted into a package only
 * when its bodies use them:
 *   bmpLen/univLen(s)      size pass: validates s, returns the C byte length
 *   write<fn>Field(...)    fill, after the size pass accepted s
 *   read<fn>Field(rec)     (string, error): rejects odd lengths / non-scalars
 * ------------------------------------------------------------------------- */
const char *
go_strk_fn(int strk) {
    return strk == 1 ? "BMP" : strk == 2 ? "Univ" : strk == 3 ? "OID" : "ROID";
}

/* The Go type the glue converts through: string for the two UCS types, the
 * []uint64 arcs for OBJECT IDENTIFIER (3) / RELATIVE-OID (4). */
const char *
go_strk_gotype(int strk) { return strk >= 3 ? "[]uint64" : "string"; }

/* The size-pass validation call for the Go expression e. */
static char *
strk_len_call(int strk, const char *e) {
    if(strk == 1) return go_gfmt("bmpLen(%s)", e);
    if(strk == 2) return go_gfmt("univLen(%s)", e);
    return go_gfmt("oidLen(%s, %s)", e, strk == 4 ? "true" : "false");
}

/* size-pass statements adding the converted payload of Go string expression
 * `e` (a failing validation aborts the size pass with the error). `ind` is
 * the extra indentation of the enclosing block. */
char *
go_strk_size(int strk, const char *e, const char *ind) {
    char *call = strk_len_call(strk, e);
    char *r = go_gfmt("%s\t{\n%s\t\tucsn, err := %s\n%s\t\tif err != nil {\n"
                   "%s\t\t\treturn 0, 0, err\n%s\t\t}\n%s\t\tpayload += ucsn\n%s\t}\n",
                   ind, ind, call, ind, ind, ind, ind, ind);
    free(call);
    return r;
}

/* read-pass: `rdexpr` is the read<fn>Field(...) call; `assign` the
 * statement template (one %s = the value) run on success, e.g. "acc = %s". */
char *
go_strk_read(int strk, const char *recarg, const char *assign_fmt) {
    char *asg = go_gfmt(assign_fmt, "ucss");
    char *r = go_gfmt("\t{\n\t\tucss, err := read%sField(%s)\n\t\tif err != nil {\n"
                   "\t\t\treturn nil, err\n\t\t}\n\t\t%s\n\t}\n",
                   go_strk_fn(strk), recarg, asg);
    free(asg);
    return r;
}

/* ---------------------------------------------------------------------------
 * go_emit_prim — one scalar / bytes / bits member.
 * ------------------------------------------------------------------------- */
void
go_emit_prim(ectx *E, flat_member *m) {
    const char *tok = go_flat_ir_member_token(m);
    const char *prim = go_flat_ir_member_prim(m);
    char *offc = go_qconst(E->cnode, g_go_offconst_pfx(E->cnode, E->cpre, tok, go_flat_ir_name(E->t)));
    char *slot = go_gfmt("unsafe.Pointer(uintptr(%s) + uintptr(%s))", E->cbase, offc);
    const char *fgo = go_gf_field_goname(E->owner_go, tok);
    char *acc;
    {
        char *gtokA = fgo ? go_gown(fgo) : go_gcamel(tok);
        acc = go_gfmt("%s.%s", E->val, gtokA);
        free(gtokA);
    }
    const char *ft = go_gf_field_type(E->owner_go, tok);
    char *cast = go_field_cast(E->t, E->owner_go, tok, prim);
    int starred = *cast == '*';
    const char *cast0 = starred ? cast + 1 : cast;

    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
        const char *uel0 = go_unqual(ft);          /* may carry one leading '*' */
        const char *uel = (uel0 && uel0[0] == '*') ? uel0 + 1 : uel0;
        int is_str = uel && strcmp(uel, "string") == 0;
        int named_alias = ft && *ft && !is_str && !go_is_prim_view(ft);
        int ptr_ft = ft && *ft == '*';
        /* the SLOT's shape rules the pointer forms: a Go *[]byte or *string
         * field whose Flat member is an INLINE bytes_flat (a value-union
         * alt: asn1cgo_bytes_flat valueOctS) has NO pointer slot to test —
         * the record rides at slot+offset itself. Only a STARRED Flat
         * member (OPTIONAL bytes: asn1cgo_bytes_flat *x) takes the
         * p != nil + alloc/storePtr form. */
        int slot_ptr = ptr_ft && go_flat_ir_member_stars(m);
        const int strk0 = go_flat_ir_member_strk(m);
        const int strk = (is_str || strk0 >= 3) ? strk0 : 0;
        int ucs_done = 0;
        if(strk) {
            /* BMPString / UniversalString: UTF-8 <-> UCS-2/UCS-4 at the
             * boundary; same three slot shapes as the plain string forms. */
            const char *fn = go_strk_fn(strk);
            ucs_done = 1;
            if(slot_ptr) {
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil {\n\t\trec%d := fa.allocStruct(sizeofBytesFlat, alignInt64)\n"
                    "\t\twrite%sField(fa, rec%d, *%s)\n\t\tstorePtr(%s, rec%d)\n\t}\n",
                    acc, g_go_tmpseq, fn, g_go_tmpseq, acc, slot, g_go_tmpseq));
                {
                    char *rd = go_gfmt("*(**byte)(%s)", slot);
                    char *inner = go_gfmt("unsafe.Pointer(p)");
                    char *asg = go_gfmt("%s = &ucss", acc);
                    (*E->read) = go_gam((*E->read), go_gfmt(
                        "\tif p := %s; p != nil {\n\t\tucss, err := read%sField(%s)\n"
                        "\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\t%s\n\t}\n",
                        rd, fn, inner, asg));
                    free(rd); free(inner); free(asg);
                }
                {
                    char *deref = go_gfmt("*%s", acc);
                    char *sz = go_strk_size(strk, deref, "\t");
                    (*E->szt) = go_gam((*E->szt), go_gfmt(
                        "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBytesFlat)\n%s\t}\n",
                        acc, sz));
                    free(deref); free(sz);
                }
                g_go_tmpseq++;
            } else if(ptr_ft) {
                char *deref = go_gfmt("*%s", acc);
                (*E->fill) = go_gam((*E->fill), go_gfmt("\twrite%sField(fa, %s, *%s)\n", fn, slot, acc));
                (*E->szt) = go_gam((*E->szt), go_strk_size(strk, deref, ""));
                {
                    char *asg = go_gfmt("%s = &ucss", acc);
                    char *rd = go_gfmt("\t{\n\t\tucss, err := read%sField(%s)\n\t\tif err != nil {\n"
                                    "\t\t\treturn nil, err\n\t\t}\n\t\t%s\n\t}\n", fn, slot, asg);
                    (*E->read) = go_gam((*E->read), rd);
                    free(asg);
                }
                free(deref);
            } else {
                char *asg = go_gfmt("%s = %%s", acc);
                (*E->fill) = go_gam((*E->fill), go_gfmt("\twrite%sField(fa, %s, %s)\n", fn, slot, acc));
                (*E->szt) = go_gam((*E->szt), go_strk_size(strk, acc, ""));
                (*E->read) = go_gam((*E->read), go_strk_read(strk, slot, asg));
                free(asg);
            }
        } else if(is_str && !ptr_ft) {
            (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteStringField(fa, %s, %s)\n", slot, acc));
            (*E->szt) = go_gam((*E->szt), go_gfmt("\tpayload += uintptr(len(%s))\n", acc));
        } else if(named_alias && !ptr_ft) {
            (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteBytesField(fa, %s, []byte(%s))\n", slot, acc));
            (*E->szt) = go_gam((*E->szt), go_gfmt("\tpayload += uintptr(len([]byte(%s)))\n", acc));
        } else if(slot_ptr) {
            /* an OPTIONAL bytes field whose Go type is *[]byte / *string
             * AND whose Flat slot is a pointer: nil = absent (a non-nil
             * pointer slot is allocated + filled). BOTH twins allocate the
             * record and store the pointer — the bytes twin historically
             * wrote the {buf,len} record AT the pointer slot (16B into an
             * 8B slot, clobbering the next member); same shape as the
             * string twin now. */
            (*E->fill) = go_gam((*E->fill), go_gfmt(
                "\tif %s != nil {\n\t\trec%d := fa.allocStruct(sizeofBytesFlat, alignInt64)\n"
                "\t\twrite%sField(fa, rec%d, %s*%s))\n\t\tstorePtr(%s, rec%d)\n\t}\n",
                acc, g_go_tmpseq, is_str ? "String" : "Bytes", g_go_tmpseq,
                is_str ? "string(" : "[]byte(", acc, slot, g_go_tmpseq));
            if(is_str) {
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := readStringField(unsafe.Pointer(p))\n\t\t%s = &sd\n\t}\n",
                    slot, acc));
            } else {
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := readBytesField(unsafe.Pointer(p))\n\t\t%s = &sd\n\t}\n",
                    slot, acc));
            }
            /* the fill allocates the bytes record in the FIXED region: the
             * size pass must add it under the same guard (payload-only
             * sizing undercounted — the same class as the leaf arm). */
            if(is_str) {
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBytesFlat)\n\t\tpayload += uintptr(len(string(*%s)))\n\t}\n",
                    acc, acc));
            } else {
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBytesFlat)\n\t\tpayload += uintptr(len([]byte(*%s)))\n\t}\n",
                    acc, acc));
            }
            g_go_tmpseq++;
        } else if(ptr_ft) {
            /* a value-union alt: the Go field is *[]byte or *string but the
             * Flat member is INLINE bytes_flat — no pointer slot, no nil
             * test; write/read the record at the slot itself. The union
             * alt is always present when selected, so unconditionally
             * deref the Go pointer (decode wrote it; a nil Go pointer at
             * encode means an unselected alt slot filled with zeros). */
            char *sdn2 = go_gfmt("sd%d", g_go_tmpseq++);
            if(is_str) {
                (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteStringField(fa, %s, *%s)\n", slot, acc));
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tpayload += uintptr(len(string(*%s)))\n", acc));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\t%s := readStringField(%s)\n\t%s = &%s\n", sdn2, slot, acc, sdn2));
            } else {
                (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteBytesField(fa, %s, *%s)\n", slot, acc));
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tpayload += uintptr(len([]byte(*%s)))\n", acc));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\t%s := readBytesField(%s)\n\t%s = &%s\n", sdn2, slot, acc, sdn2));
            }
            free(sdn2);
        } else {
            (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteBytesField(fa, %s, %s)\n", slot, acc));
            /* sizing: the plain []byte (non-alias, non-ptr, non-str) member
             * allocs its byte slice in the payload region — reserve it
             * (the tail form after the starred one). */
            (*E->szt) = go_gam((*E->szt), go_gfmt("\tpayload += uintptr(len(%s))\n", acc));
        }
        /* read: a named []byte alias / plain []byte / string (ptr handled
         * above). SIZING NOTE: every fill-site
         * branch above ALREADY emitted its own szt line — the tail must
         * emit NONE. A tail `payload += len(...)` for is_str would be a
         * SECOND count of the same member (payload over-reserved by
         * exactly the sum of its string lengths, breaking the
         * exact-consumption invariant). */
        if(!ptr_ft && !ucs_done) {
            if(is_str) {
                (*E->read) = go_gam((*E->read), go_gfmt("\t%s = readStringField(%s)\n", acc, slot));
            } else if(named_alias) {
                (*E->read) = go_gam((*E->read), go_gfmt("\t%s = %s(readBytesField(%s))\n", acc, cast0, slot));
            } else {
                (*E->read) = go_gam((*E->read), go_gfmt("\t%s = readBytesField(%s)\n", acc, slot));
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
                if(strcmp(go_unqual(uelb), "BitString") == 0) {
                    const char *tm = go_flat_ir_module(E->t);
                    if(tm && g_go_emit_mod && strcmp(tm, g_go_emit_mod) != 0) {
                        char *pk = go_gmodule_pkg(tm);
                        bst2 = go_gfmt("%s.BitString", pk);
                        free(pk);
                    }
                }
            }
            if(!bst2) bst2 = go_gown(ft + 1);
            char *sdn = go_gfmt("sd%d", g_go_tmpseq++);
            char *lbs3 = go_local_bitstring();
            if(go_flat_ir_member_stars(m)) {
                /* a STARRED Flat slot (OPTIONAL BIT STRING): the C member is
                 * BIT_STRING_t *x — alloc the record, write through it,
                 * storePtr (never the record inline into the pointer slot). */
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil {\n"
                    "\t\twv := fa.allocStruct(sizeofBitsFlat, alignInt64)\n"
                    "\t\twriteBitsField(fa, wv, %s(*%s))\n"
                    "\t\tstorePtr(%s, wv)\n\t}\n",
                    acc, lbs3, acc, slot));
                /* sizing (the e2connectionUpdate catch): the
                 * fill's writeBitsField allocs payload for the byte slice —
                 * the size fn MUST reserve it (same rule as the bytes member
                 * path; an undercount panics blockArena.allocPayload on
                 * any BitsField-bearing struct). */
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(sizeofBitsFlat)\n\t\tpayload += uintptr(len((*%s).Bytes))\n\t}\n",
                    acc, acc));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n"
                    "\t\t%s := %s(readBitsField(unsafe.Pointer(p)))\n"
                    "\t\t%s = &%s\n\t}\n",
                    slot, sdn, bst2, acc, sdn));
            } else {
                /* a value-union alt: Go *BitString over an INLINE bits
                 * flat — the record rides at the slot itself. */
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\twriteBitsField(fa, %s, %s(*%s))\n", slot, lbs3, acc));
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tpayload += uintptr(len((*%s).Bytes))\n", acc));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\t%s := %s(readBitsField(%s))\n\t%s = &%s\n",
                    sdn, bst2, slot, acc, sdn));
            }
            free(sdn);
            free(lbs3);
            free(bst2);
        } else {
        {
            char *wa = go_bits_bridge(go_flat_ir_module(E->t), acc, 1);
            (*E->fill) = go_gam((*E->fill), go_gfmt("\twriteBitsField(fa, %s, %s)\n", slot, wa));
            free(wa);
        }
        /* sizing: the plain (non-star, non-alias) member's bytes payload
         * (same rule as the starred form above). */
        (*E->szt) = go_gam((*E->szt), go_gfmt("\tpayload += uintptr(len(%s.Bytes))\n", acc));
        {
            char *rd = go_gfmt("readBitsField(%s)", slot);
            char *rb = go_bits_bridge(go_flat_ir_module(E->t), rd, 0);
            (*E->read) = go_gam((*E->read), go_gfmt("\t%s = %s\n", acc, rb));
            free(rd); free(rb);
        }
        }
    } else if(prim && strcmp(prim, "_bool32") == 0) {
        /* a starred bool view (an OPTIONAL BOOLEAN whose Go field is *bool
         * or a named *int32 alias): deref for truth; read wraps a temp.
         * A plain bool: store 0/1, read back != 0.
         * A STARRED FLAT SLOT (OPTIONAL member, int32_t *x in the .h) is a
         * pointer slot: alloc the leaf, write through it, storePtr — never
         * the value inline into the pointer field (value-in-slot would make
         * to_tree deref a garbage/1 "pointer"). */
        if(go_flat_ir_member_stars(m)) {
            /* the leaf carves its slot from the 8-aligned fixed region:
             * allocate the PADDED width (8) so the region's alignment
             * invariant holds — a 4-byte int32 alloc between int64 allocs
             * forces 4 bytes of padding the width-summed sizing pass never
             * counts (measured live: undercount by 8 for two bools). C
             * reads the int32 through the stored pointer; bytes 4..7 stay
             * zero. */
            char *bn = go_gfmt("b%d", g_go_tmpseq++);
            (*E->fill) = go_gam((*E->fill), go_gfmt(
                "\tif %s != nil {\n\t\t%s := fa.allocStruct(uintptr(8), alignInt64)\n"
                "\t\tif *%s {\n\t\t\t*(*int32)(unsafe.Pointer(%s)) = 1\n\t\t}\n"
                "\t\tstorePtr(%s, %s)\n\t}\n",
                acc, bn, acc, bn, slot, bn));
            (*E->szt) = go_gam((*E->szt), go_gfmt(
                "\tif %s != nil {\n\t\tfixed += uintptr(8)\n\t}\n", acc));
            /* read: through the stored pointer slot */
            (*E->read) = go_gam((*E->read), go_gfmt(
                "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := *(*int32)(unsafe.Pointer(p)) != 0\n\t\t%s = &sd\n\t}\n",
                slot, acc));
            free(bn);
        } else if(ft && *ft == '*') {
            /* strip the pointer star + any package qualifier: the pointee's
             * own spelling (bool or a named scalar alias). */
            const char *st = ft + 1;
            const char *uel = go_unqual(st);
            if(strcmp(uel, "bool") == 0) {
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil && *%s {\n\t\t*(*int32)(%s) = 1\n\t}\n",
                    acc, acc, slot));
                /* read: a value-union alt is SELECTED whenever the switch
                 * dispatched here — a false wire value (int32==0) must
                 * still materialize the *bool alt (pointing at false), or
                 * Encode's selected-alt nil guard fires on it
                 * (a `false` value of a *bool alt). */
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\tsd := *(*int32)(%s) != 0\n\t%s = &sd\n",
                    slot, acc));
            } else {
                char *tn = go_gfmt("b%d", g_go_tmpseq++);
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil && *(*%s)(%s) != 0 {\n\t\t*(*int32)(%s) = 1\n\t}\n",
                    acc, uel, acc, slot));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\t%s := %s(*(*int32)(%s) != 0)\n\t%s = &%s\n",
                    tn, uel, slot, acc, tn));
                free(tn);
            }
        } else {
            (*E->fill) = go_gam((*E->fill), go_gfmt("\tif %s {\n\t\t*(*int32)(%s) = 1\n\t}\n", acc, slot));
            (*E->read) = go_gam((*E->read), go_gfmt("\t%s = *(*int32)(%s) != 0\n", acc, slot));
        }
    } else if(prim) {
        const char *gt = go_gprim_go(prim);
        if(gt && *gt) {
            if(go_flat_ir_member_stars(m)) {
                /* a STARRED FLAT SLOT over a prim leaf (OPTIONAL scalar
                 * member — int64_t *x in the .h): alloc the leaf, store the
                 * converted value through it, storePtr; size adds the leaf
                 * under the same guard (same class as _bool32 above). */
                char *pn = go_gfmt("p%d", g_go_tmpseq++);
                int gw = go_gprim_width(prim);
                if(gw < 8) gw = 8;   /* padded width: keep the fixed region
                                      * 8-aligned (see the _bool32 arm) */
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil {\n\t\t%s := fa.allocStruct(uintptr(%d), alignInt64)\n"
                    "\t\t*(*%s)(unsafe.Pointer(%s)) = %s(*%s)\n\t\tstorePtr(%s, %s)\n\t}\n",
                    acc, pn, gw,
                    gt, pn, gt, acc, slot, pn));
                (*E->read) = go_gam((*E->read), go_gfmt(
                    "\tif p := *(**byte)(%s); p != nil {\n\t\tsd := %s(*(*%s)(unsafe.Pointer(p)))\n\t\t%s = &sd\n\t}\n",
                    slot, cast0, gt, acc));
                (*E->szt) = go_gam((*E->szt), go_gfmt(
                    "\tif %s != nil {\n\t\tfixed += uintptr(%d)\n\t}\n", acc, gw));
                free(pn);
            } else if(ft && *ft == '*') {
                /* a POINTER field over a prim slot (an OPTIONAL ENUMERATED
                 * whose Go field is the *Named PR form): store deref'd (via
                 * the RAW prim conversion — named-alias assignability trap);
                 * read wraps the named conversion in a temp. */
                char *tn = go_gfmt("sd%d", g_go_tmpseq++);
                (*E->fill) = go_gam((*E->fill), go_gfmt(
                    "\tif %s != nil {\n\t\t*(*%s)(%s) = %s(*%s)\n\t}\n",
                    acc, gt, slot, gt, acc));
                (*E->read) = go_gam((*E->read), go_gfmt(
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
            (*E->fill) = go_gam((*E->fill), go_gfmt("\t*(*%s)(%s) = %s(%s)\n", gt, slot, gt, acc));
            (*E->read) = go_gam((*E->read), go_gfmt("\t%s = %s(*(*%s)(%s))\n", acc, cast0, gt, slot));
            }
        } else {
            char *m2 = go_gfmt("member %s of %s: unmapped prim %s", tok, go_flat_ir_name(E->t), prim);
            GFAIL(m2); free(m2);
        }
    }
    free(offc); free(slot); free(acc); free(cast);
}

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
const char *go_hdf_fill(ectx *E, flat_type *target) {
    static char buf[32];
    if(!go_conv_is_scc(target)) return "";
    snprintf(buf, sizeof buf, ", %s",
             (E->depth && *E->depth) ? "depth+1" : "0");
    return buf;
}
const char *go_hdf_size(ectx *E, flat_type *target) {
    static char buf[32];
    if(!go_conv_is_scc(target)) return "";
    /* MIRRORS go_hdf_fill (one increment per SCC edge, the seq-of Items hop
     * included): the size walk must trip at the same depth the fill walk
     * does — a flat ", depth" never incremented, so a cyclic value
     * stack-overflowed the size pass instead of tripping the depth guard (E_DEPTH).
     * Same parity form: non-SCC host = plain 0. */
    snprintf(buf, sizeof buf, ", %s",
             (E->depth && *E->depth) ? "depth+1" : "0");
    return buf;
}
