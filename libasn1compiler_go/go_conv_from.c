/*
 * go_conv_from.c — the `_from_tree` emission (tree -> Flat).
 *
 * Mirror of go_conv_to.c: the same IR walk, the same accessors, the same
 * node-kind dispatch; every output allocation goes through
 * `asn1cgo_arena_alloc` (the from_tree allocation rule: "every output allocation is
 * asn1cgo_arena_alloc; buffers are copied — never aliased; lists:
 * count = list.count, items = arena_alloc(count * sizeof), loop; CHOICE:
 * switch on in->present, convert only the selected alternative; INTEGER_t
 * via asn_INTEGER2umax/asn_INTEGER2imax with E_INTERNAL on failure").
 *
 * The entry signature carries the arena: the emitted function form is
 *   int <X>_from_tree(asn1cgo_arena *ar, const <X>_t *in, <X>_flat *out,
 *                     asn1cgo_err *err);
 * The arena accessor prefix `ar` threads through every emitter below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "asn1c_internal.h"     /* arg_t (required before asn1c_misc.h) */
#include "asn1c_misc.h"         /* asn1c_prefix (per-spec prefix) */

#include "go_conv.h"
#include "go_conv_internal.h"

/* The IR surface (go_flat.c, post-walk contract) is declared in go_conv.h
 * (the flat_type and flat_member prototypes; go_conv_internal.h includes it). */

/* go_conv_to.c's shared per-node pieces this mirror needs. */
extern int conv_is_scc(const void *t);

static char *
ir_resolve2(const char *ref) {
    return (char *)go_conv_ir_ref_resolve(ref);
}

/* the Flat-side scalar ctype of a prim token (mirrors the Flat member). */
static const char *
flat_scalar(const char *prim) {
    if(!prim) return "int64_t";
    if(strcmp(prim, "double") == 0) return "double";
    if(strcmp(prim, "uint64_t") == 0) return "uint64_t";
    if(strcmp(prim, "int32_t") == 0) return "int32_t";
    if(strcmp(prim, "_bool32") == 0) return "int32_t";
    return "int64_t";
}

/* ---------------------------------------------------------------------------
 * Member arms (from_tree): in_acc/out_acc are full accessors.
 *
 * Receiver contract — one comment per arm kind, stated once
 * here for this family): every receiver operand the arms emit is an LVALUE
 * ACCESS expression; address-of (&) attaches at CALL BOUNDARIES only (the
 * child converter's by-value args, "ar, &in->tok, &out->tok, err").
 * Pointer-slot members (stars=1) receive/emit the pointer VALUE (arena-
 * allocated) — never &-of-pointer. Tree-side reads deref in (const
 * <T>_t *in); Flat-side writes store through out.
 * ------------------------------------------------------------------------- */
static char *struct_members_from(void *t, const char *in_acc,
                                 const char *out_acc);
static char *ioc_node_from_body(void *t);

/* OBJECT IDENTIFIER / RELATIVE-OID (strz 2 / 3): the tree slot's contents
 * octets become the little-endian arcs of the Flat bytes record, through the
 * asn1cgo_oid_get helper of the converter preamble. in_ptr is a pointer to
 * the tree OBJECT_IDENTIFIER_t, out_rec a pointer to the Flat record; larg /
 * marg are the (already quoted, or NULL) label arguments of asn1cgo_fail. */
static int
strz_oid(int strz) { return strz >= 2; }

static char *
oid_get_blk(const char *ind, int strz, const char *in_ptr, const char *out_rec,
            const char *larg, const char *marg) {
    return cfmt("%s{\n%s    int orc = asn1cgo_oid_get(ar, (const void *)(%s), %s, %d);\n"
                "%s    if (orc == -2) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, %s, %s, NULL);\n"
                "%s    if (orc) return asn1cgo_fail(err, ASN1CGO_E_DECODE, %s, %s, \"%s contents are not a valid arc encoding\");\n%s}\n",
                ind, ind, in_ptr, out_rec, strz == 3,
                ind, larg, marg,
                ind, larg, marg, strz == 3 ? "RELATIVE-OID" : "OBJECT IDENTIFIER", ind);
}

static char *
arm_prim_from(void *t, void *m, const char *in_acc, const char *out_acc) {
    const char *prim = go_flat_ir_member_prim(m);
    char *mlab = conv_member_label(m);   /* display label (fail args;
                                          * token accessors go through
                                          * in_acc/out_acc — no tok needed) */
    int stars = go_flat_ir_member_stars(m);
    char *label = conv_type_label(t);   /* display label */
    char *s = cstrdup("");
    if(go_flat_ir_member_wide(m) && prim
       && (strcmp(prim, "uint64_t") == 0 || strcmp(prim, "int64_t") == 0)) {
        /* INTEGER_t-backed wide member: read through the INTEGER2[iu]max verb. */
        int u = strcmp(prim, "uint64_t") == 0;
        const char *fn = u ? "asn_INTEGER2umax" : "asn_INTEGER2imax";
        const char *vt = u ? "uintmax_t" : "intmax_t";
        const char *ft = u ? "uint64_t" : "int64_t";
        if(stars) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s v;\n", vt); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s((const INTEGER_t *)%s, &v) != 0)\n", fn, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"%s failed\");\n", label, mlab, fn); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = (%s *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s));\n", out_acc, ft, out_acc, ft); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        *%s = (%s)v;\n    } else %s = NULL;\n", out_acc, ft, out_acc); s = ca(s, _cf); free(_cf); }
        } else {
            { char *_cf = cfmt("    {\n        %s v;\n", vt); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s((const INTEGER_t *)&%s, &v) != 0)\n", fn, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"%s failed\");\n", label, mlab, fn); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = (%s)v;\n    }\n", out_acc, ft); s = ca(s, _cf); free(_cf); }
        }
        free(mlab); free(label);
        return s;
    }
    if(stars) {
        /* OPTIONAL OCTET/BIT STRING member (the pointer bytes slot):
         * arena-alloc the bytes/bits Flat, copy; NULL = absent. */
        if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        asn1cgo_bytes_flat *b = asn1cgo_arena_alloc(ar, sizeof(*b), _Alignof(asn1cgo_bytes_flat));\n"); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!b) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            if(strz_oid(go_flat_ir_member_strz(m))) {
                char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
                char *_cf = oid_get_blk("        ", go_flat_ir_member_strz(m), in_acc, "b", la, ma);
                s = ca(s, _cf); free(_cf); free(la); free(ma);
                { char *_cf2 = cfmt("        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf2); free(_cf2); }
            } else {
            { char *_cf = cfmt("        b->len = (size_t)%s->size;\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s->size) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            b->buf = (uint8_t *)asn1cgo_arena_alloc(ar, (size_t)%s->size, 8);\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!b->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            memcpy(b->buf, %s->buf, (size_t)%s->size);\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        }\n        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        asn1cgo_bits_flat *b = asn1cgo_arena_alloc(ar, sizeof(*b), _Alignof(asn1cgo_bits_flat));\n"); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!b) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        b->len = (size_t)%s->size; b->bits_unused = (int32_t)%s->bits_unused;\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s->size) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            b->buf = (uint8_t *)asn1cgo_arena_alloc(ar, (size_t)%s->size, 8);\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!b->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            memcpy(b->buf, %s->buf, (size_t)%s->size);\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        }\n        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "uint64_t") == 0) {
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = (uint64_t *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(uint64_t));\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        *%s = (uint64_t)*%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("    } else %s = NULL;\n", out_acc); s = ca(s, _cf); free(_cf); }
        } else {
            const char *ft = flat_scalar(prim);
            { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = (%s *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s));\n", out_acc, ft, out_acc, ft); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        *%s = (%s)*%s;\n", out_acc, ft, in_acc); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("    } else %s = NULL;\n", out_acc); s = ca(s, _cf); free(_cf); }
        }
        free(mlab); free(label);
        return s;
    }
    if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0 && strz_oid(go_flat_ir_member_strz(m))) {
        char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
        char *ip = cfmt("&%s", in_acc), *op = cfmt("&%s", out_acc);
        char *_cf = oid_get_blk("    ", go_flat_ir_member_strz(m), ip, op, la, ma);
        s = ca(s, _cf); free(_cf); free(la); free(ma); free(ip); free(op);
    } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
        { char *_cf = cfmt("    %s.len = (size_t)%s.size;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    if (%s.len) {\n", out_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s.len, 1);\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    } else {\n");
        { char *_cf = cfmt("        %s.buf = NULL;\n", out_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    }\n");
    } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
        { char *_cf = cfmt("    %s.len = (size_t)%s.size;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    %s.bits_unused = (int32_t)%s.bits_unused;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    if (%s.len) {\n", out_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s.len, 1);\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    } else {\n");
        { char *_cf = cfmt("        %s.buf = NULL;\n", out_acc); s = ca(s, _cf); free(_cf); }
        s = ca(s, "    }\n");
    } else if(prim && strcmp(prim, "uint64_t") == 0) {
        { char *_cf = cfmt("    %s = (uint64_t)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "double") == 0) {
        { char *_cf = cfmt("    %s = (double)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "int32_t") == 0) {
        { char *_cf = cfmt("    %s = (int32_t)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else if(prim && strcmp(prim, "_bool32") == 0) {
        /* BOOLEAN Flat column is int32_t (0/1): canonicalize */
        { char *_cf = cfmt("    %s = %s ? 1 : 0;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    } else {
        { char *_cf = cfmt("    %s = (int64_t)%s;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
    }
    free(mlab); free(label);
    return s;
}

static char *
arm_ref_from(void *t, void *m, const char *in_acc, const char *out_acc) {
    char *mlab = conv_member_label(m);   /* display label (fail args) */
    const char *ref = go_flat_ir_member_ref(m);
    int stars = go_flat_ir_member_stars(m);
    void *r = ir_resolve2(ref);
    char *label = conv_type_label(t);   /* display label */
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
    int guarded = conv_is_scc(t) && conv_is_scc(r);

    if(go_flat_ir_is_leaf(r)) {
        const char *prim = go_flat_ir_prim(r);
        if(conv_is_wide(go_flat_ir_cid(r))) {
            /* wide INTEGER ref (native Flat width) */
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        uint64_t *v = (uint64_t *)asn1cgo_arena_alloc(ar, sizeof(*v), _Alignof(uint64_t));\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!v) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (asn_INTEGER2umax((const INTEGER_t *)%s, (uintmax_t *)v) != 0)\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"asn_INTEGER2umax failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = v;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            } else {
                { char *_cf = cfmt("    {\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        uintmax_t v = 0;\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (asn_INTEGER2umax((const INTEGER_t *)&%s, &v) != 0)\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"asn_INTEGER2umax failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = (uint64_t)v;\n    }\n", out_acc); s = ca(s, _cf); free(_cf); }
            }
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        asn1cgo_bytes_flat *b = asn1cgo_arena_alloc(ar, sizeof(*b), _Alignof(asn1cgo_bytes_flat));\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!b) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                if(strz_oid(go_flat_ir_strz(r))) {
                    char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
                    char *_cf = oid_get_blk("        ", go_flat_ir_strz(r), in_acc, "b", la, ma);
                    s = ca(s, _cf); free(_cf); free(la); free(ma);
                    { char *_cf2 = cfmt("        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf2); free(_cf2); }
                } else {
                { char *_cf = cfmt("        b->len = (size_t)%s->size;\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s->size) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            b->buf = (uint8_t *)asn1cgo_arena_alloc(ar, (size_t)%s->size, 8);\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!b->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(b->buf, %s->buf, (size_t)%s->size);\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        }\n        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                }
            } else if(strz_oid(go_flat_ir_strz(r))) {
                char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
                char *ip = cfmt("&%s", in_acc), *op = cfmt("&%s", out_acc);
                char *_cf = oid_get_blk("    ", go_flat_ir_strz(r), ip, op, la, ma);
                s = ca(s, _cf); free(_cf); free(la); free(ma); free(ip); free(op);
            } else {
                { char *_cf = cfmt("    %s.len = (size_t)%s.size;\n", out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("    if (%s.len) {\n", out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s.len, 1);\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("    } else {\n        %s.buf = NULL;\n    }\n", out_acc); s = ca(s, _cf); free(_cf); }
            }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        asn1cgo_bits_flat *b = asn1cgo_arena_alloc(ar, sizeof(*b), _Alignof(asn1cgo_bits_flat));\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!b) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        b->len = (size_t)%s->size; b->bits_unused = (int32_t)%s->bits_unused;\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s->size) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            b->buf = (uint8_t *)asn1cgo_arena_alloc(ar, (size_t)%s->size, 8);\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!b->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(b->buf, %s->buf, (size_t)%s->size);\n", in_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        }\n        %s = b;\n    } else {\n        %s = NULL;\n    }\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
            } else {
                { char *_cf = cfmt("    %s.len = (size_t)%s.size;\n    %s.bits_unused = (int32_t)%s.bits_unused;\n", out_acc, in_acc, out_acc, in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("    if (%s.len) {\n", out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s.len, 1);\n", out_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        memcpy(%s.buf, %s.buf, %s.len);\n", out_acc, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("    } else {\n        %s.buf = NULL;\n    }\n", out_acc); s = ca(s, _cf); free(_cf); }
            }
        } else {
            /* scalar leaf reference */
            const char *ft = flat_scalar(prim);
            if(stars) {
                { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        %s = (%s *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s));\n", out_acc, ft, out_acc, ft); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        *%s = (%s)*%s;\n    } else %s = NULL;\n", out_acc, ft, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
            } else {
                { char *_cf = cfmt("    %s = (%s)%s;\n", out_acc, ft, in_acc); s = ca(s, _cf); free(_cf); }
            }
        }
        free(mlab); free(rb); free(rflat); free(label);
        return s;
    }

    /* constructed target: a NAMED SEQUENCE OF reference member delegates
     * to the named type's own converter (the from_tree mirror of the
     * nested-member
     * template — the reference names a top-level type assignment with its
     * own conv pair; to_tree deleted its inline twin already). The generic
     * child-call tail below handles it unchanged. */

    /* constructed target: child call (arena-threaded) */
    if(stars) {
        { char *_cf = cfmt("    if (%s) {\n", in_acc); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        %s = (%s_flat *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s_flat));\n", out_acc, rb, out_acc, rb); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_acc, label, mlab); s = ca(s, _cf); free(_cf); }
        if(guarded) {
            s = ca(s, "        if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
            { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        int rc = %s_from_tree(ar, %s, %s, err);\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        err->depth--;\n");
            s = ca(s, "        if (rc) return err->code;\n");
        } else {
            { char *_cf = cfmt("        if (%s_from_tree(ar, %s, %s, err)) return err->code;\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("    } else %s = NULL;\n", out_acc); s = ca(s, _cf); free(_cf); }
    } else {
        if(guarded) {
            s = ca(s, "    if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
            { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("    int rc = %s_from_tree(ar, &%s, &%s, err);\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
            s = ca(s, "    err->depth--;\n");
            s = ca(s, "    if (rc) return err->code;\n");
        } else {
            { char *_cf = cfmt("    if (%s_from_tree(ar, &%s, &%s, err)) return err->code;\n", rb, in_acc, out_acc); s = ca(s, _cf); free(_cf); }
        }
    }
    free(mlab); free(rb); free(rflat); free(label);
    return s;
}

/* ---------------------------------------------------------------------------
 * CHOICE switch (from_tree): switch on in-><sel>.present, convert ONLY the
 * selected alt into out-><sel>.<alt> (the from_tree CHOICE rule). The Flat
 * stores alts inline at
 * their own tokens (no choice union on the Flat side).
 * ------------------------------------------------------------------------- */
static char *choice_switch_from_deref(void *t, const char *in_sel,
                                      const char *out_sel, const char *deref);
static char *
choice_switch_from(void *t, const char *in_sel, const char *out_sel) {
    return choice_switch_from_deref(t, in_sel, out_sel, "->");
}

/* deref = the accessor suffix into the CHOICE holder: "." for an inline
 * (by-value) wrapper slot (the tree nests the wrapper by value),
 * "->" for the node level and a calloc'd/pointer slot. */
static char *
choice_switch_from_deref(void *t, const char *in_sel, const char *out_sel,
                         const char *deref) {
    char *label = conv_type_label(t);   /* display label */
    char *tb_ = conv_tree_base(t);   /* prefixed base for the PR enum */
    char *prbase = cstrdup(tb_);
    char *s = cstrdup("");
    { char *_cf = cfmt("    %s%spresent = (int32_t)%s%spresent;\n", out_sel, deref, in_sel, deref); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    switch (%s%spresent) {\n", in_sel, deref); s = ca(s, _cf); free(_cf); }
    int nm = go_flat_ir_members(t);
    for(int i = 0; i < nm; i++) {
        void *mtmp = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(mtmp);
        /* the C tree's name of the alt (differs from the Flat member token
         * only for an alt named `present`, see go_flat_last_member_tree_token) */
        const char *ttok = go_flat_ir_member_tree_token(mtmp);
        char *mlab = conv_member_label(mtmp);   /* display label */
        if(strcmp(tok, "present") == 0) { free(mlab); continue; }
        char *pr = cfmt("%s_PR_%s", prbase, ttok);
        int stars = go_flat_ir_member_stars(mtmp);
        /* NULL alt: no Flat slot; present set, nothing converted. */
        if(conv_is_null_alt(go_flat_ir_cid(t), tok)) {
            { char *_cf = cfmt("    case %s:\n", pr); s = ca(s, _cf); free(_cf); }
            s = ca(s, "        break;   /* NULL alt carries no slot */\n");
            free(pr); free(mlab);
            continue;
        }
        { char *_cf = cfmt("    case %s:\n", pr); s = ca(s, _cf); free(_cf); }
        if(go_flat_ir_member_is_prim(mtmp)) {
            const char *prim = go_flat_ir_member_prim(mtmp);
            void *rt = NULL; (void)rt;
            if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0 && strz_oid(go_flat_ir_member_strz(mtmp))) {
                char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
                char *ip = cfmt("&%s%schoice.%s", in_sel, deref, ttok);
                char *op = cfmt("&%s%s%s", out_sel, deref, tok);
                char *_cf = oid_get_blk("        ", go_flat_ir_member_strz(mtmp), ip, op, la, ma);
                s = ca(s, _cf); free(_cf); free(la); free(ma); free(ip); free(op);
            } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
                { char *_cf = cfmt("        %s%s%s.len = (size_t)%s%schoice.%s.size;\n", out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s%s%s.len) {\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s%s%s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s%s%s.len, 1);\n", out_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s%s%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s%s%s.buf, %s%schoice.%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, ttok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        } else {\n            %s%s%s.buf = NULL;\n        }\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
                { char *_cf = cfmt("        %s%s%s.len = (size_t)%s%schoice.%s.size;\n        %s%s%s.bits_unused = (int32_t)%s%schoice.%s.bits_unused;\n", out_sel, deref, tok, in_sel, deref, ttok, out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s%s%s.len) {\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s%s%s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s%s%s.len, 1);\n", out_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (!%s%s%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            memcpy(%s%s%s.buf, %s%schoice.%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, ttok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        } else {\n            %s%s%s.buf = NULL;\n        }\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            } else if(go_flat_ir_member_wide(mtmp) && prim
                      && (strcmp(prim, "uint64_t") == 0 || strcmp(prim, "int64_t") == 0)) {
                /* INTEGER_t-backed wide alt */
                int u = strcmp(prim, "uint64_t") == 0;
                const char *fn = u ? "asn_INTEGER2umax" : "asn_INTEGER2imax";
                const char *vt = u ? "uintmax_t" : "intmax_t";
                const char *ft = u ? "uint64_t" : "int64_t";
                const char *amp = stars ? "" : "&";
                { char *_cf = cfmt("        {\n            %s v = 0;\n", vt); s = ca(s, _cf); free(_cf); }
                if(stars) { char *_cf = cfmt("            if (!%s%schoice.%s) return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"alt NULL\");\n", in_sel, deref, ttok, label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (%s((const INTEGER_t *)%s%s%schoice.%s, &v) != 0)\n", fn, amp, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("                return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"%s failed\");\n", label, mlab, fn); s = ca(s, _cf); free(_cf); }
                if(stars) {
                    char *oslot = cfmt("%s%s%s", out_sel, deref, tok);
                    { char *_cf = cfmt("            %s = (%s *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s));\n", oslot, ft, oslot, ft); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", oslot, label, mlab); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            *%s = (%s)v;\n        }\n", oslot, ft); s = ca(s, _cf); free(_cf); }
                    free(oslot);
                } else {
                    { char *_cf = cfmt("            %s%s%s = (%s)v;\n        }\n", out_sel, deref, tok, ft); s = ca(s, _cf); free(_cf); }
                }
            } else if(prim && strcmp(prim, "_bool32") == 0) {
                /* BOOLEAN Flat column is int32_t (0/1): canonicalize a
                 * decoded tree BOOLEAN to 0/1 at the Flat boundary. */
                { char *_cf = cfmt("        %s%s%s = %s%schoice.%s ? 1 : 0;\n", out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
            } else {
                const char *ft = flat_scalar(prim);
                { char *_cf = cfmt("        %s%s%s = (%s)%s%schoice.%s;\n", out_sel, deref, tok, ft, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
            }
            s = ca(s, "        break;\n");
            free(pr); free(mlab);
            continue;
        }
        const char *ref = go_flat_ir_member_ref(mtmp);
        void *r = go_flat_ir_member_is_ref(mtmp) && ref
                       ? ir_resolve2(ref) : NULL;
        char *rb = r ? conv_tree_base(r) : cstrdup("");
        if(!r || !*rb) {
            fprintf(stderr, "asn1cgo: conv: choice alt %s of %s unresolved\n",
                    tok, label);
            conv_failed_set();
            free(pr); free(mlab); free(rb);
            continue;
        }
        if(stars) {
            char *oslot = cfmt("%s%s%s", out_sel, deref, tok);
            { char *_cf = cfmt("        %s = (%s_flat *)asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(%s_flat));\n", oslot, rb, oslot, rb); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", oslot, label, mlab); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(r)) {
                /* unbraced switch arm: no local decl (a second guarded arm
                 * would redeclare); guard, call, decrement, test inline */
                s = ca(s, "        if (++err->depth > ASN1CGO_MAX_DEPTH)\n");
                { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("        if (%s_from_tree(ar, %s%schoice.%s, %s, err)) { err->depth--; return err->code; }\n", rb, in_sel, deref, ttok, oslot); s = ca(s, _cf); free(_cf); }
                s = ca(s, "        err->depth--;\n");
            } else {
                { char *_cf = cfmt("        if (%s_from_tree(ar, %s%schoice.%s, %s, err)) return err->code;\n", rb, in_sel, deref, ttok, oslot); s = ca(s, _cf); free(_cf); }
            }
            free(oslot);
        } else {
            if(conv_is_wide(go_flat_ir_cid(r))) {
                { char *_cf = cfmt("        {\n            uintmax_t v = 0;\n"); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            if (asn_INTEGER2umax((const INTEGER_t *)&in%schoice.%s, &v) != 0)\n", deref, ttok); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("                return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"asn_INTEGER2umax failed\");\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("            %s%s%s = (uint64_t)v;\n        }\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
            } else if(go_flat_ir_is_leaf(r)) {
                const char *prim = go_flat_ir_prim(r);
                if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0 && strz_oid(go_flat_ir_strz(r))) {
                    char *la = cfmt("\"%s\"", label), *ma = cfmt("\"%s\"", mlab);
                    char *ip = cfmt("&%s%schoice.%s", in_sel, deref, ttok);
                    char *op = cfmt("&%s%s%s", out_sel, deref, tok);
                    char *_cf = oid_get_blk("        ", go_flat_ir_strz(r), ip, op, la, ma);
                    s = ca(s, _cf); free(_cf); free(la); free(ma); free(ip); free(op);
                } else if(prim && (strcmp(prim, "asn1cgo_bytes_flat") == 0
                            || strcmp(prim, "asn1cgo_bits_flat") == 0)) {
                    { char *_cf = cfmt("        %s%s%s.len = (size_t)%s%schoice.%s.size;\n", out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                    if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0)
                        { char *_cf = cfmt("        %s%s%s.bits_unused = (int32_t)%s%schoice.%s.bits_unused;\n", out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("        if (%s%s%s.len) {\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            %s%s%s.buf = (uint8_t *)asn1cgo_arena_alloc(ar, %s%s%s.len, 1);\n", out_sel, deref, tok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            if (!%s%s%s.buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, deref, tok, label, mlab); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("            memcpy(%s%s%s.buf, %s%schoice.%s.buf, %s%s%s.len);\n", out_sel, deref, tok, in_sel, deref, ttok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("        } else {\n            %s%s%s.buf = NULL;\n        }\n", out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                } else if(prim && strcmp(prim, "_bool32") == 0) {
                    /* BOOLEAN (0/1): canonicalize at the Flat boundary. */
                    { char *_cf = cfmt("        %s%s%s = %s%schoice.%s ? 1 : 0;\n", out_sel, deref, tok, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                } else {
                    const char *ft = flat_scalar(prim);
                    { char *_cf = cfmt("        %s%s%s = (%s)%s%schoice.%s;\n", out_sel, deref, tok, ft, in_sel, deref, ttok); s = ca(s, _cf); free(_cf); }
                }
            } else {
                if(r && conv_is_scc(t) && conv_is_scc(r)) {
                    /* depth mirror: a by-value CHOICE alt into a recursion-
                     * SCC type; guard the entry, call, decrement, test. */
                    { char *_cf = cfmt("        if (++err->depth > ASN1CGO_MAX_DEPTH) return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                    { char *_cf = cfmt("        int itrc = %s_from_tree(ar, &%s%schoice.%s, &%s%s%s, err);\n", rb, in_sel, deref, ttok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
                    s = ca(s, "        err->depth--;\n");
                    s = ca(s, "        if (itrc) return err->code;\n");
                } else {
                    { char *_cf = cfmt("        if (%s_from_tree(ar, &%s%schoice.%s, &%s%s%s, err)) return err->code;\n", rb, in_sel, deref, ttok, out_sel, deref, tok); s = ca(s, _cf); free(_cf); }
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
    free(prbase); free(tb_); free(label);
    return s;
}

/* FT_NESTED member arm: seqof wrapper -> arena items loop; struct/choice
 * wrapper -> descend one accessor level. */
static char *
arm_nested_from(void *t, void *m, const char *in_acc, const char *out_acc) {
    const char *tok = go_flat_ir_member_token(m);
    char *mlab = conv_member_label(m);   /* display label (fail args) */
    int stars = go_flat_ir_member_stars(m);
    int nix = go_flat_ir_member_nested_ix(m);
    void *n = (nix >= 0 && nix < go_flat_ir_n_types())
                  ? go_flat_ir_type(nix) : NULL;
    char *label = conv_type_label(t);   /* display label */
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
        const char *elem = go_flat_ir_elem(n);
        if(go_flat_ir_elem_prim(n)) {
            fprintf(stderr,
                    "asn1cgo: conv: SEQUENCE (OF primitive %s) at %s.%s has "
                    "no authored template (fail loud)\n",
                    elem ? elem : "?", label, mlab);
            conv_failed_set();
        }
        void *rt = ir_resolve2(elem);
        char *rb = rt ? conv_tree_base(rt) : NULL;
        char *rflat = rt ? conv_flat_name(rt) : NULL;
        if(!rb || !*rb) {
            fprintf(stderr, "asn1cgo: conv: unresolved seqof elem %s at %s\n",
                    elem ? elem : "?", label);
            conv_failed_set();
            free(mlab); free(label); free(in_sel); free(out_sel);
            return s;
        }
        if(stars) {
            /* OPTIONAL inline SEQ OF: Flat carries *{items,count}. Receivers
             * are member lvalue exprs (the token-comparison rule: the
             * _Alignof operand is the out member, never a local alias
             * of it). */
            { char *_cf = cfmt("    if (%s) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        typeof(*%s) *lo = (typeof(*%s) *)asn1cgo_arena_alloc(ar, sizeof(*lo), _Alignof(*%s));\n", out_sel, out_sel, out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!lo) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = lo;\n", out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        lo->count = (size_t)%s->list.count;\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        lo->items = NULL;\n"); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (lo->count) {\n"); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            lo->items = (%s_flat *)asn1cgo_arena_alloc(ar, lo->count * sizeof(*lo->items), _Alignof(%s_flat));\n", rb, rb); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!lo->items) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            for (size_t i = 0; i < lo->count; i++) {\n"); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt)) {
                /* depth mirror: the loop edge re-enters the recursion SCC. */
                { char *_cf = cfmt("                if (++err->depth > ASN1CGO_MAX_DEPTH) return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("                int itrc = %s_from_tree(ar, (const %s_t *)%s->list.array[i], &lo->items[i], err);\n", rb, rb, in_sel); s = ca(s, _cf); free(_cf); }
                s = ca(s, "                err->depth--;\n");
                s = ca(s, "                if (itrc) return err->code;\n");
            } else {
                { char *_cf = cfmt("                if (%s_from_tree(ar, (const %s_t *)%s->list.array[i], &lo->items[i], err)) return err->code;\n", rb, rb, in_sel); s = ca(s, _cf); free(_cf); }
            }
            { char *_cf = cfmt("            }\n        }\n    }\n"); s = ca(s, _cf); free(_cf); }
        } else {
            /* INLINE {items,count} member: the Flat slot IS the wrapper
             * (by value) — write through it directly (no lo pointer, no
             * block braces: the member receivers are plain lvalues). */
            { char *_cf = cfmt("        %s.count = (size_t)%s.list.count;\n", out_sel, in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s.items = NULL;\n", out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (%s.count) {\n", out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            %s.items = (%s_flat *)asn1cgo_arena_alloc(ar, %s.count * sizeof(*%s.items), _Alignof(%s_flat));\n", out_sel, rb, out_sel, out_sel, rb); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            if (!%s.items) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            for (size_t i = 0; i < %s.count; i++) {\n", out_sel); s = ca(s, _cf); free(_cf); }
            if(conv_is_scc(t) && conv_is_scc(rt)) {
                /* depth mirror: the loop edge re-enters the recursion SCC. */
                { char *_cf = cfmt("                if (++err->depth > ASN1CGO_MAX_DEPTH) return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", \"%s\", \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label, mlab); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("                int itrc = %s_from_tree(ar, (const %s_t *)%s.list.array[i], &%s.items[i], err);\n", rb, rb, in_sel, out_sel); s = ca(s, _cf); free(_cf); }
                s = ca(s, "                err->depth--;\n");
                s = ca(s, "                if (itrc) return err->code;\n");
            } else {
                { char *_cf = cfmt("                if (%s_from_tree(ar, (const %s_t *)%s.list.array[i], &%s.items[i], err)) return err->code;\n", rb, rb, in_sel, out_sel); s = ca(s, _cf); free(_cf); }
            }
            { char *_cf = cfmt("            }\n        }\n"); s = ca(s, _cf); free(_cf); }
        }
        free(rb); free(rflat);
    } else if(go_conv_ir_is_choice(n)) {
        /* INLINE wrapper slot: the Flat member IS the wrapper value —
         * compose "." into it; a starred wrapper is a pointer after
         * arena-alloc ("->"). */
        char *b = choice_switch_from_deref(n, in_sel, out_sel,
                                           stars ? "->" : ".");
        if(stars) {
            /* OPTIONAL nested wrapper pointer: allocate first, then inside */
            char *wrap = cstrdup("");
            { char *_cf = cfmt("    if (%s) {\n", in_sel); wrap = ca(wrap, _cf); free(_cf); }
            /* arena output (freed with the arena) — never plain calloc, which
             * would leak and was unchecked */
            { char *_cf = cfmt("        %s = asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(max_align_t));\n", out_sel, out_sel); wrap = ca(wrap, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); wrap = ca(wrap, _cf); free(_cf); }
            s = ca(s, wrap);
            free(wrap);
            s = ca(s, b);
            s = ca(s, "    }\n");
        } else {
            s = ca(s, b);
        }
        free(b);
    } else {
        /* nested struct wrapper (an inline SEQUENCE): descend one accessor
         * level over its members -- '.' into a by-value slot, '->' through a
         * starred (OPTIONAL) one, which is a pointer on both the tree and the
         * Flat side. */
        if(stars) {
            { char *_cf = cfmt("    if (%s) {\n", in_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        %s = (typeof(%s))asn1cgo_arena_alloc(ar, sizeof(*%s), _Alignof(max_align_t));\n", out_sel, out_sel, out_sel); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("        if (!%s) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", \"%s\", NULL);\n", out_sel, label, mlab); s = ca(s, _cf); free(_cf); }
            char *ipfx = cfmt("%s->", in_sel);
            char *opfx = cfmt("%s->", out_sel);
            char *body = struct_members_from(n, ipfx, opfx);
            s = ca(s, body);
            free(body); free(ipfx); free(opfx);
            { char *_cf = cfmt("    } else %s = NULL;\n", out_sel); s = ca(s, _cf); free(_cf); }
        } else {
            char *ipfx = cfmt("%s.", in_sel);
            char *opfx = cfmt("%s.", out_sel);
            char *body = struct_members_from(n, ipfx, opfx);
            s = ca(s, body);
            free(body); free(ipfx); free(opfx);
        }
    }
    free(mlab); free(label); free(in_sel); free(out_sel);
    return s;
}

/* Walk one struct-like node's members (from_tree arms). */
static char *
struct_members_from(void *t, const char *in_acc, const char *out_acc) {
    char *s = cstrdup("");
    int nm = go_flat_ir_members(t);
    for(int i = 0; i < nm; i++) {
        void *m = go_flat_ir_member(t, i);
        const char *tok = go_flat_ir_member_token(m);
        char *ia = cfmt("%s%s", in_acc, tok);
        char *oa = cfmt("%s%s", out_acc, tok);
        char *body = NULL;
        if(go_flat_ir_member_is_default(m) && go_flat_ir_member_tree_ptr(m)) {
            /* DEFAULT member whose C tree slot is a pointer: the C decoder
             * fills an absent default, so NULL here is a runtime bug --
             * report it, never substitute the Go zero value. */
            char *ml = conv_member_label(m), *tl = conv_type_label(t);
            char *pre = cfmt(
                "    if (!%s) return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", \"%s\", \"DEFAULT member is NULL after decode\");\n",
                ia, tl, ml);
            free(ia);
            ia = cfmt("(*%s%s)", in_acc, tok);
            body = go_flat_ir_member_is_prim(m) ? arm_prim_from(t, m, ia, oa)
                                                : arm_ref_from(t, m, ia, oa);
            { char *j = ca(pre, body); free(body); body = j; }
            free(ml); free(tl);
        } else if(go_flat_ir_member_is_prim(m)) {
            body = arm_prim_from(t, m, ia, oa);
        } else if(go_flat_ir_member_is_ref(m)) {
            body = arm_ref_from(t, m, ia, oa);
        } else {
            body = arm_nested_from(t, m, in_acc, out_acc);
        }
        s = ca(s, body);
        free(body); free(ia); free(oa);
    }
    return s;
}

/* ---------------------------------------------------------------------------
 * Node-level from_tree body: kind dispatch. conv_from_node is the mirror
 * entry go_conv_to.c's package writer calls per node.
 * ------------------------------------------------------------------------- */
static char *
node_from_body(void *t) {
    char *label = conv_type_label(t);   /* display label */
    char *s = cstrdup("");
    if(go_flat_ir_is_leaf(t)) {
        const char *prim = go_flat_ir_prim(t);
        if(conv_is_wide(go_flat_ir_cid(t))) {
            { char *_cf = cfmt(
                "    {\n"
                "        uintmax_t v = 0;\n"
                "        if (asn_INTEGER2umax((const INTEGER_t *)in, &v) != 0)\n"
                "            return asn1cgo_fail(err, ASN1CGO_E_INTERNAL, \"%s\", NULL, \"asn_INTEGER2umax failed\");\n"
                "        *out = (uint64_t)v;\n"
                "    }\n", label); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0 && strz_oid(go_flat_ir_strz(t))) {
            { char *_cf = cfmt(
                "    {\n"
                "        int orc = asn1cgo_oid_get(ar, (const void *)in, out, %d);\n"
                "        if (orc == -2) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n"
                "        if (orc) return asn1cgo_fail(err, ASN1CGO_E_DECODE, \"%s\", NULL, \"%s contents are not a valid arc encoding\");\n"
                "    }\n", go_flat_ir_strz(t) == 3, label, label,
                go_flat_ir_strz(t) == 3 ? "RELATIVE-OID" : "OBJECT IDENTIFIER"); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "asn1cgo_bytes_flat") == 0) {
            { char *_cf = cfmt(
                "    out->len = (size_t)((const OCTET_STRING_t *)in)->size;\n"
                "    if (out->len) {\n"
                "        out->buf = (uint8_t *)asn1cgo_arena_alloc(ar, out->len, 1);\n"
                "        if (!out->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, \"arena bytes (%%zu)\", out->len);\n"
                "        memcpy(out->buf, ((const OCTET_STRING_t *)in)->buf, out->len);\n"
                "    } else {\n"
                "        out->buf = NULL;\n"
                "    }\n", label); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "asn1cgo_bits_flat") == 0) {
            { char *_cf = cfmt(
                "    {\n"
                "        const BIT_STRING_t *b = (const BIT_STRING_t *)in;\n"
                "        out->len = (size_t)b->size;\n"
                "        out->bits_unused = (int32_t)b->bits_unused;\n"
                "        if (out->len) {\n"
                "            out->buf = (uint8_t *)asn1cgo_arena_alloc(ar, out->len, 1);\n"
                "            if (!out->buf) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, \"arena bits (%%zu)\", out->len);\n"
                "            memcpy(out->buf, b->buf, out->len);\n"
                "        } else {\n"
                "            out->buf = NULL;\n"
                "        }\n"
                "    }\n", label); s = ca(s, _cf); free(_cf); }
        } else if(go_flat_ir_null_leaf(t)) {
            s = ca(s, "    (void)in;\n    *out = 0;\n");
        } else if(go_flat_ir_inline_elem(t) && go_flat_ir_tree_ctype(t)) {
            /* inline SEQUENCE OF element leaf: read through its exact C
             * tree type (see leaf_to_body) */
            const char *ct = go_flat_ir_tree_ctype(t);
            if(strcmp(ct, "NULL_t") == 0)
                s = ca(s, "    (void)in;\n    *out = 0;\n");
            else { char *_cf = cfmt("    *out = (%s)(*(const %s *)in);\n", prim ? (strcmp(prim, "_bool32") == 0 ? "int32_t" : prim) : "int64_t", ct); s = ca(s, _cf); free(_cf); }
        } else if(prim && strcmp(prim, "double") == 0) {
            s = ca(s, "    *out = (double)(*(const double *)in);\n");
        } else if(prim && strcmp(prim, "uint64_t") == 0) {
            s = ca(s, "    *out = (uint64_t)(*(const unsigned long *)in);\n");
        } else {
            s = ca(s, "    *out = (int64_t)(*(const long *)in);\n");
        }
        free(label);
        return s;
    }
    if(go_flat_ir_is_alias(t)) {
        char *rb = cstrdup("");
        void *rt = ir_resolve2(go_flat_ir_alias_of(t));
        char *rbase = rt ? conv_tree_base(rt) : NULL;
        if(!rbase || !*rbase) {
            fprintf(stderr, "asn1cgo: conv: alias %s unresolved\n", label);
            conv_failed_set();
        } else {
            { char *_cf = cfmt("    return %s_from_tree(ar, (const %s_t *)in, (%s_flat *)out, err);\n",
                               rbase, rbase, rbase);
              rb = ca(rb, _cf); free(_cf); }
        }
        s = ca(s, rb);
        free(rb); free(rbase); free(label);
        return s;
    }
    if(go_flat_ir_is_seqof(t)) {
        const char *elem = go_flat_ir_elem(t);
        if(go_flat_ir_elem_prim(t)) {
            fprintf(stderr,
                    "asn1cgo: conv: named SEQUENCE (OF primitive %s) %s has "
                    "no authored template (fail loud)\n",
                    elem ? elem : "?", label);
            conv_failed_set();
        }
        void *rt = ir_resolve2(elem);
        char *rb = rt ? conv_tree_base(rt) : NULL;
        if(!rb || !*rb) {
            fprintf(stderr, "asn1cgo: conv: unresolved seqof elem %s (%s)\n",
                    elem ? elem : "?", label);
            conv_failed_set();
            free(label);
            return s;
        }
        int scc_edge = rt && conv_is_scc(rt);
        { char *_cf = cfmt("    out->count = (size_t)in->list.count;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    out->items = NULL;\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("    if (out->count) {\n"); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        out->items = (%s_flat *)asn1cgo_arena_alloc(ar, out->count * sizeof(*out->items), _Alignof(%s_flat));\n", rb, rb); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        if (!out->items) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("        for (size_t i = 0; i < out->count; i++) {\n"); s = ca(s, _cf); free(_cf); }
        if(scc_edge) {
            /* depth mirror: the loop edge re-enters the recursion SCC —
             * guard each item (arena output: no ASN_STRUCT_FREE on error). */
            { char *_cf = cfmt("            if (++err->depth > ASN1CGO_MAX_DEPTH) return asn1cgo_fail(err, ASN1CGO_E_DEPTH, \"%s\", NULL, \"depth > %%d\", ASN1CGO_MAX_DEPTH);\n", label); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("            int itrc = %s_from_tree(ar, (const %s_t *)in->list.array[i], &out->items[i], err);\n", rb, rb); s = ca(s, _cf); free(_cf); }
            s = ca(s, "            err->depth--;\n");
            s = ca(s, "            if (itrc) return err->code;\n");
        } else {
            { char *_cf = cfmt("            if (%s_from_tree(ar, (const %s_t *)in->list.array[i], &out->items[i], err)) return err->code;\n", rb, rb); s = ca(s, _cf); free(_cf); }
        }
        { char *_cf = cfmt("        }\n    }\n"); s = ca(s, _cf); free(_cf); }
        free(rb);
        free(label);
        return s;
    }
    if(go_conv_ir_is_choice(t)) {
        char *sw = choice_switch_from(t, "in", "out");
        s = ca(s, sw);
        free(sw);
        free(label);
        return s;
    }
    /* struct node: an IOC spec node adds the decode-side table cross-check
     * (id read off the wire; E_IOC_MISMATCH defensive) before the
     * alt conversion; a plain struct walks its members. */
    if(conv_ioc_has(go_flat_ir_cid(t))) {
        char *b = ioc_node_from_body(t);
        s = ca(s, b);
        free(b);
        free(label);
        return s;
    }
    char *b = struct_members_from(t, "in->", "out->");
    s = ca(s, b);
    free(b);
    free(label);
    return s;
}

/* IOC spec-node from_tree body (the IOC decode rule): id/criticality copied off
 * the wire, the (id, present) pair cross-checked against the table
 * (E_IOC_MISMATCH defensive), then the selected alt converted.
 * The alt payloads convert through their own <alt>_from_tree. */
static char *
ioc_node_from_body(void *t) {
    const char *cid = go_flat_ir_cid(t);
    char *label = conv_type_label(t);   /* display label */
    char *s = cstrdup("");
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
    const char *id_member = rows[0]->id_member;
    int has_crit = (rows[0]->crit_gov != NULL);   /* a class without a
                                                   * &criticality column has
                                                   * no criticality member
                                                   * on either side */
    char *tb_ = conv_tree_base(t);   /* prefixed base for the PR enum */
    char *prbase = cfmt("%s__value", tb_);   /* the __value PR enum base */
    /* copy id (criticality iff the class carries the column); look the
     * pair up (inverse rows). */
    { char *_cf = cfmt("    out->%s = (int64_t)in->%s;\n", id_member, id_member); s = ca(s, _cf); free(_cf); }
    if(has_crit)
    { char *_cf = cfmt("    out->criticality = (int32_t)in->criticality;\n"); s = ca(s, _cf); free(_cf); }
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
    { char *_cf = cfmt("        if (in->value.present == 0)\n"); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        if ((int32_t)in->value.present != want_pr)\n"); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_IOC_MISMATCH, \"%s\", \"value\", \"%s=%%lld decoded-present=%%d want pr=%%d\", (long long)in->%s, (int)in->value.present, (int)want_pr);\n",
                   label, id_member, id_member); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        out->value.present = (int32_t)in->value.present;\n"); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        switch (in->value.present) {\n"); s = ca(s, _cf); free(_cf); }
    for(int i = 0; i < nrows; i++) {
        const conv_ioc_row *r = rows[i];
        /* dedup alt arms (many-to-one: several ids, one present) */
        int dup = 0;
        for(int j = 0; j < i; j++)
            if(strcmp(rows[j]->alt_token, r->alt_token) == 0) { dup = 1; break; }
        if(dup) continue;
        const char *pfx = asn1c_prefix();
        const char *amsg = (r->alt_msg && *r->alt_msg) ? r->alt_msg
                                                       : r->alt_token;
        { char *_cf = cfmt("        case (int32_t)%s_PR_%s:\n", prbase, r->alt_token); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            if (%s%s_from_tree(ar, &in->value.choice.%s, &out->value.%s, err)) return err->code;\n",
                       pfx ? pfx : "", amsg, r->alt_token, r->alt_token); s = ca(s, _cf); free(_cf); }
        { char *_cf = cfmt("            break;\n"); s = ca(s, _cf); free(_cf); }
    }
    { char *_cf = cfmt("        case (int32_t)%s_PR_NOTHING:\n", prbase); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_NOTHING, \"%s\", \"value\", NULL);\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        default:\n"); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("            return asn1cgo_fail(err, ASN1CGO_E_CHOICE_BAD, \"%s\", \"value\", \"present=%%d\", (int)in->value.present);\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        }\n    }\n"); s = ca(s, _cf); free(_cf); }
    free(prbase); free(tb_); free(label);
    return s;
}

/* The public per-node from_body entry (go_conv_to.c's emit driver uses it). */
char *
conv_from_node(void *t, int scc) {
    (void)scc;   /* guards are placed at call sites, not here */
    return node_from_body(t);
}
