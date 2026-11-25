/*
 * go_glue_pkg.c — the PDU API wrappers, the glue text shared by
 * every package, the package file header and the final text of one fn.
 *
 * Part of the Go<->Flat glue emission; go_glue.c has the overview.
 */
#include "go_glue_internal.h"

/* ---------------------------------------------------------------------------
 * The PDU API + per-package file assembly (the go_glue_emit driver is in
 * go_glue.c).
 * ------------------------------------------------------------------------- */

/* the ONE emitter of the Encode/xer wrapper bodies — the
 * PDU-root arena reservation (budget += sizeof(root), root allocStruct'd
 * before any child alloc) lives HERE and nowhere else on the Go side.
 * Before this, emit_pdu_api carried two inline gfmt blocks, one per
 * wrapper, with the reservation text duplicated — the exact shape of the
 * an earlier sizing bug (Encode got the +sizeof(root) budget + reservation,
 * xer silently didn't; e2removal-init xer -> present=13). `kind` switches
 * only the decl line and the C entry-point name; every other line — size,
 * two-region budget WITH sizeof(root), allocStruct reserve, fill, entry
 * call, KeepAlive, GoBytes copy — is emitted from this single template for
 * BOTH wrappers of EVERY PDU root. Decode's root reservation is likewise
 * one path, on the C side: entry_decode's asn1cgo_arena_alloc(flat)
 * (go_entry.c). */
static char *
entry_go_wrapper(const char *kind, const char *go, const char *fngo,
                 const char *pv, const char *label,
                 const char *tb, const char *fna, const char *root_sz,
                 const char *d0) {
    char *s;
    if(strcmp(kind, "encode") == 0)
        s = cfmt("func (p *%s) Encode() ([]byte, error) {\n", go);
    else if(strcmp(kind, "uperenc") == 0)
        s = cfmt("func (p *%s) EncodeUPER() ([]byte, error) {\n", go);
    else if(strcmp(kind, "jerenc") == 0)
        s = cfmt("func (p *%s) EncodeJER() ([]byte, error) {\n", go);
    else
        s = cfmt("func xer%s(p *%s) ([]byte, error) {\n", go, go);
    { char *_cf = cfmt(
        "\tif p == nil {\n\t\treturn nil, &rt.Error{Code: rt.CodeArg, TypeName: \"%s\"}\n\t}\n"
        "\tfixed, payload, err := size%s(%s%s)\n"
        "\tif err != nil { return nil, err }\n"
        "\tfa, base := newBlockArena(fixed, uintptr(%s), payload)\n"
        "\tif fa == nil {\n\t\treturn nil, &rt.Error{Code: rt.CodeAlloc, TypeName: \"%s\"}\n\t}\n"
        "\tdefer C.asn1cgo_block_free(base)\n"
        "\troot := fa.allocStruct(uintptr(%s), alignInt64)\n"
        "\tif err := fill%s(fa, root, %s%s); err != nil {\n\t\treturn nil, err\n\t}\n"
        "\tfa.exact(\"%s\")   /* consumed == reserved, exactly */\n"
        "\tvar cerr C.asn1cgo_err\n"
        "\tvar cbuf C.asn1cgo_buf\n"
        "\trc := C.asn1cgo_%s_%s((*C.%s)(root), &cbuf, &cerr)\n"
        "\truntime.KeepAlive(fa)\n\truntime.KeepAlive(p)\n"
        "\tif rc != 0 {\n\t\tC.asn1cgo_buf_free(&cbuf)\n\t\treturn nil, goErr(&cerr)\n\t}\n"
        "\tout := C.GoBytes(unsafe.Pointer(cbuf.buf), C.int(cbuf.len))\n"
        "\tC.asn1cgo_buf_free(&cbuf)\n"
        "\treturn append([]byte(nil), out...), nil\n"
        "}\n\n",
        label, fngo, pv, d0, root_sz, label, root_sz, fngo, pv, d0, label, kind, tb, fna);
      s = ca(s, _cf); free(_cf); }
    return s;
}

extern int go_jer_enabled(void);

/* One PDU root's Decode-style function: `fn` the Go name prefix ("Decode" /
 * "DecodeUPER" / "DecodeJER"), `ent` the C entry part ("decode" / "uperdec" /
 * "jerdec"). */
static char *
pdu_decode_fn(const char *fn, const char *ent, const char *go,
              const char *fngo, const char *label, const char *fna,
              const char *tb) {
    /* an alias returns its own Go type over the target's reader */
    char *ret = strcmp(go, fngo) ? gfmt("(*%s)(v)", go) : strdup("v");
    char *r = gfmt(
        "func %s%s(b []byte) (*%s, error) {\n"
        "\tif len(b) == 0 {\n\t\treturn nil, &rt.Error{Code: rt.CodeArg, TypeName: \"%s\"}\n\t}\n"
        "\tvar cerr C.asn1cgo_err\n"
        "\tvar arena *C.asn1cgo_arena\n"
        "\tvar flat *C.%s\n"
        "\trc := C.asn1cgo_%s_%s((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &arena, &flat, &cerr)\n"
        "\truntime.KeepAlive(b)\n"
        "\tif rc != 0 {\n"
        "\t\tif arena != nil {\n\t\t\tC.asn1cgo_arena_free(arena)\n\t\t}\n"
        "\t\treturn nil, goErr(&cerr)\n\t}\n"
        "\tv, err := read%s(unsafe.Pointer(flat))\n"
        "\tC.asn1cgo_arena_free(arena)\n"
        "\tif err != nil { return nil, err }\n"
        "\treturn %s, nil\n"
        "}\n\n",
        fn, go, go, label, fna, ent, tb, fngo, ret);
    free(ret);
    return r;
}

/* one PDU root's API surface + its type fn queueing. `tb` = the
 * tree base (<P><cid>, the entry-point name suffix), `go` = the Go type. */
void
emit_pdu_api(flat_type *rt_, const conv_pdu *al, gsb *src) {
    char *tb = conv_tree_base(rt_);
    /* fngo: the base of the size/fill/read fns (the node's); go: the Go
     * type of the API. An alias (Alias ::= Msg, type Alias Msg) has its own
     * Go type and entry points and converts the pointer for the node's fns. */
    char *fngo = gcamel_flat(go_flat_ir_name(rt_));
    char *go = al ? strdup(al->alias_go) : strdup(fngo);
    char *label = al ? strdup(al->alias_label) : conv_type_label(rt_);
    char *pv;
    if(al) {
        const char *tm = go_flat_ir_module(rt_);
        char *tpk = (tm && strcmp(tm, al->alias_module) != 0)
                        ? gmodule_pkg(tm) : NULL;
        char *tq = tpk ? gfmt("%s.%s", tpk, fngo) : strdup(fngo);
        free(tpk);
        pv = gfmt("(*%s)(p)", tq);
        free(tq);
        free(tb);
        tb = gfmt("%s%s", asn1c_prefix() ? asn1c_prefix() : "", al->alias_cid);
    } else {
        pv = strdup("p");
    }
    if(!tb || !*tb) {
        char *m2 = gfmt("PDU node %s has no tree base", go_flat_ir_name(rt_));
        GFAIL(m2); free(m2); free(go); free(label); free(fngo); free(pv);
        return;
    }
    emit_type_fn(rt_);
    char *fna = gown(go_flat_ir_name(rt_));   /* the C Flat typedef name */
    const char *d0 = conv_is_scc(rt_) ? ", 0" : "";   /* the root call's depth arg */

    sb_am(src, gfmt(go_jer_enabled()
        ? "// %s — the public API (Encode/Decode/EncodeUPER/DecodeUPER/EncodeJER/DecodeJER entry points; xer unexported).\n"
        : "// %s — the public API (Encode/Decode/EncodeUPER/DecodeUPER entry points; xer unexported).\n", go));
    /* the ROOT's own struct: the size fns count only CHILD allocations
     * (every nested caller allocs the child slot via allocStruct and so
     * counts it), but the PDU root's Flat sits at the block base for
     * free — its sizeof must be added to the arena budget AND the base
     * reserved via allocStruct, or the first child alloc lands at offset
     * 0 ON TOP of the root (the choice-present overwritten bug class).
     * BOTH Encode and xer fill the root Flat; BOTH reserve it — via the
     * ONE shared body template (entry_go_wrapper). */
    char *root_sz = g_szconst(go_flat_ir_name(rt_));
    {
        char *wb = entry_go_wrapper("encode", go, fngo, pv, label, tb, fna, root_sz, d0);
        sb_am(src, wb);   /* gam frees wb */
    }
    sb_am(src, pdu_decode_fn("Decode", "decode", go, fngo, label, fna, tb));
    {
        char *wb = entry_go_wrapper("xer", go, fngo, pv, label, tb, fna, root_sz, d0);
        sb_am(src, wb);   /* gam frees wb */
    }
    {
        char *wb = entry_go_wrapper("uperenc", go, fngo, pv, label, tb, fna, root_sz, d0);
        sb_am(src, wb);   /* gam frees wb */
        sb_am(src, pdu_decode_fn("DecodeUPER", "uperdec", go, fngo, label, fna, tb));
    }
    if(go_jer_enabled()) {
        char *wb = entry_go_wrapper("jerenc", go, fngo, pv, label, tb, fna, root_sz, d0);
        sb_am(src, wb);   /* gam frees wb */
        sb_am(src, pdu_decode_fn("DecodeJER", "jerdec", go, fngo, label, fna, tb));
    }
    free(root_sz);
    free(tb); free(go); free(label); free(fna); free(fngo); free(pv);
}

/* The shared glue statics (blockArena + field helpers + goErr) — emitted
 * once per package (byte-stable text). */
const char *GLUE_STATICS =
    "// rt/shared Flat layout consts (asn1cgo_bytes_flat/asn1cgo_bits_flat,\n"
"// rt/types.h; x86-64 SysV). The layout.go init() probe cross-checks these\n"
"// against cgo's C compiler view (rt/types.h include below).\n"
"const (\n"
"\tsizeofBytesFlat       = 16\n"
"\toffBytesFlatBuf       = 0\n"
"\toffBytesFlatLen       = 8\n"
"\tsizeofBitsFlat        = 24\n"
"\toffBitsFlatBuf        = 0\n"
"\toffBitsFlatLen        = 8\n"
"\toffBitsFlatBitsUnused = 16\n"
"\talignPtr              = 8\n"
"\talignInt64            = 8\n"
"\talignInt32            = 4\n"
")\n"
"\n"
"// ---- the Go-side bump allocator over one C block ----\n"
    "\n"
    "type blockArena struct {\n"
    "\tmem        []byte\n"
    "\tfixedEnd   uintptr\n"
    "\tstructCur  uintptr\n"
    "\tpayloadCur uintptr\n"
    "}\n"
    "\n"
    "// newBlockArena: fixed structs from the front, variable payloads from the\n"
    "// rear — a payload can never overlap a fixed struct's footprint (the\n"
    "// two-region split). The fixed region is fixedSize+rootSize (the PDU root\n"
    "// Flat is reserved at the block base). Returns (nil, nil) — which the\n"
    "// caller reports as E_ALLOC — if the total overflows uintptr, does not fit\n"
    "// an int (unsafe.Slice), or the block allocation fails (asn1cgo_block_alloc\n"
    "// is plain malloc returning NULL; cgo's C.malloc would abort on OOM).\n"
    "func newBlockArena(fixedSize, rootSize, payloadSize uintptr) (*blockArena, unsafe.Pointer) {\n"
    "	fixedSize2 := fixedSize + rootSize\n"
    "	if fixedSize2 < fixedSize {\n\t\treturn nil, nil\n\t}\n"
    "	n := fixedSize2 + payloadSize\n"
    "	if n < fixedSize2 || n > uintptr(math.MaxInt) {\n\t\treturn nil, nil\n\t}\n"
    "	if n == 0 {\n\t\tn = 1\n\t}\n"
    "	p := C.asn1cgo_block_alloc(C.size_t(n))\n"
    "	if p == nil {\n\t\treturn nil, nil\n\t}\n"
    "	mem := unsafe.Slice((*byte)(p), int(n))\n"
    "\tfor i := range mem {\n\t\tmem[i] = 0\n\t}\n"
    "\treturn &blockArena{mem: mem, fixedEnd: fixedSize2, structCur: 0, payloadCur: fixedSize2}, p\n"
    "}\n"
    "\n"
    "func (a *blockArena) allocStruct(n, align uintptr) unsafe.Pointer {\n"
    "\ta.structCur = alignUp(a.structCur, align)\n"
    "\tend := a.structCur + n\n"
    "\tif end > a.fixedEnd {\n\t\tpanic(\"asn1cgo: fixed-region undercounted by \" + strconv.Itoa(int(end-a.fixedEnd)))\n\t}\n"
    "\t// n == 0 (an empty SEQUENCE {}) can sit at len(mem): take the address\n"
    "\t// from the data pointer instead of indexing mem (still C memory).\n"
    "\taddr := unsafe.Add(unsafe.Pointer(unsafe.SliceData(a.mem)), a.structCur)\n"
    "\ta.structCur = end\n"
    "\treturn addr\n"
    "}\n"
    "\n"
    "func (a *blockArena) allocPayload(n uintptr) unsafe.Pointer {\n"
    "\tend := a.payloadCur + n\n"
    "\tif end > uintptr(len(a.mem)) {\n\t\tpanic(\"asn1cgo: payload-region undercounted by \" + strconv.Itoa(int(end-uintptr(len(a.mem)))))\n\t}\n"
    "\taddr := unsafe.Add(unsafe.Pointer(unsafe.SliceData(a.mem)), a.payloadCur)\n"
    "\ta.payloadCur = end\n"
    "\treturn addr\n"
    "}\n"
    "\n"
    "// exact invariant: after a fill, what the\n"
    "// arena CONSUMED must equal what the size pass RESERVED — exactly, not\n"
    "// <=. structCur reaches fixedEnd only if every sized struct was\n"
    "// allocated; payloadCur reaches len(mem) only if every sized payload\n"
    "// byte was written. An over-reserving size fn (consumed < reserved)\n"
    "// wastes budget and hides fill/size drift; an under-reserving one\n"
    "// already panics in the alloc guards above. Names the type + both\n"
    "// deltas so the offending size fn is identifiable from the panic.\n"
    "func (a *blockArena) exact(typeName string) {\n"
    "\tif a.structCur != a.fixedEnd || a.payloadCur != uintptr(len(a.mem)) {\n"
    "\t\tpanic(\"asn1cgo: arena budget not exactly consumed for \" + typeName +\n"
    "\t\t\t\": struct \" + strconv.Itoa(int(a.structCur)) + \"/\" + strconv.Itoa(int(a.fixedEnd)) +\n"
    "\t\t\t\", payload \" + strconv.Itoa(int(a.payloadCur)) + \"/\" + strconv.Itoa(int(len(a.mem))))\n"
    "\t}\n"
    "}\n"
    "\n"
    "func storePtr(slot, val unsafe.Pointer) {\n\t*(**byte)(slot) = (*byte)(val)\n}\n"
    "\n"
    "func alignUp(n, a uintptr) uintptr { return (n + a - 1) &^ (a - 1) }\n"
    "\n"
    "// maxEncodeDepth mirrors ASN1CGO_MAX_DEPTH (the rt err.h) on the\n"
    "// Go side: a cyclic Go value fails E_DEPTH before any C call.\n"
    "const maxEncodeDepth = 64\n"
    "\n"
    "func writeBytesField(fa *blockArena, recAddr unsafe.Pointer, b []byte) {\n"
    "\tif len(b) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(b)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(b)), b)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = uintptr(len(b))\n"
    "}\n"
    "\n"
    "func writeStringField(fa *blockArena, recAddr unsafe.Pointer, s string) {\n"
    "\tif len(s) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(s)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(s)), s)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = uintptr(len(s))\n"
    "}\n"
    "\n"
    /* the bits helpers ride behind their own markers (__GLUE_WRITEBITS__
     * / __GLUE_READBITS__): a package with no BIT STRING anywhere never
     * emits them, so the BITSTR placeholder never resolves to an undefined
     * type; a bits-carrying package gets them at their historical slots. */
    "//__GLUE_WRITEBITS__\n"
    "\n"
    "func b32FromBool(b bool) int32 {\n\tif b {\n\t\treturn 1\n\t}\n\treturn 0\n}\n\n"
    "func readBytesField(recAddr unsafe.Pointer) []byte {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn nil\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\treturn append([]byte(nil), unsafe.Slice(bufPtr, int(n))...)\n"
    "}\n"
    "\n"
    "func readStringField(recAddr unsafe.Pointer) string {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn \"\"\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\treturn string(append([]byte(nil), unsafe.Slice(bufPtr, int(n))...))\n"
    "}\n"
    "\n"
    /* position marker: replaced by the bits-helpers chunk (GLUE_BITS) when
     * the package's emitted bodies reference them, deleted otherwise — the
     * helpers keep their historical slot next to the bytes/string pair so
     * bits-carrying packages stay byte-identical. */
    "//__GLUE_READBITS__\n"
    "\n"
    "// goErr copies a C asn1cgo_err (this preamble's err.h = the rt err.h) into\n"
    "// a *rt.Error; the copy is the caller's only stable handle (the ONE\n"
    "// Go error surface lives in rt).\n"
    "func goErr(cerr *C.asn1cgo_err) error {\n"
    "\tif cerr == nil || cerr.code == 0 {\n\t\treturn nil\n\t}\n"
    "\te := &rt.Error{Code: rt.Code(cerr.code)}\n"
    "\tif cerr.type_name != nil {\n\t\te.TypeName = C.GoString(cerr.type_name)\n\t}\n"
    "\tif cerr.field != nil {\n\t\te.Field = C.GoString(cerr.field)\n\t}\n"
    "\te.Message = C.GoStringN(&cerr.msg[0], C.int(C.asn1cgo_err_msg_len(cerr)))\n"
    "\treturn e\n"
    "}\n";

/* the bits helpers, appended to a package's glue ONLY when its emitted
 * bodies reference them (any package with a BIT STRING does; a spec with none
 * omits the pair and never resolves the BITSTR placeholder). The
 * chunk text is carved verbatim from the static block above. */
const char *GLUE_WRITE_BITS =
    "func writeBitsField(fa *blockArena, recAddr unsafe.Pointer, bs BITSTR) {\n"
    "\t*(*int32)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatBitsUnused)) = bs.BitsUnused\n"
    "\tif len(bs.Bytes) == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(uintptr(len(bs.Bytes)))\n"
    "\tcopy(unsafe.Slice((*byte)(payload), len(bs.Bytes)), bs.Bytes)\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatLen)) = uintptr(len(bs.Bytes))\n"
    "}\n"
    "\n";

/* BMPString / UniversalString helpers (go_glue.c strk_*): UTF-8 in Go,
 * UCS-2 / UCS-4 big-endian in the C buffer. Each pair is appended to a
 * package only when its bodies use it. The size pass validates, so the fill
 * never sees an unrepresentable string; a defensive U+FFFD keeps the byte
 * count identical to the size pass if it ever did. */
const char *GLUE_STRCONV_COMMON =
    "// ucsEncErr builds the error for a Go string that has no BMPString /\n"
    "// UniversalString form (encode side: the value violates the type).\n"
    "func ucsEncErr(typ, msg string) error {\n"
    "\treturn &rt.Error{Code: rt.CodeConstraint, TypeName: typ, Message: msg}\n"
    "}\n"
    "\n"
    "// ucsDecErr builds the error for a C buffer that is not a valid\n"
    "// BMPString / UniversalString (decode side).\n"
    "func ucsDecErr(typ, msg string) error {\n"
    "\treturn &rt.Error{Code: rt.CodeDecode, TypeName: typ, Message: msg}\n"
    "}\n"
    "\n"
    "// ucsBadUTF8 reports whether the rune r at s[i] came from invalid UTF-8\n"
    "// (range yields U+FFFD for it; a genuine U+FFFD is EF BF BD).\n"
    "func ucsBadUTF8(s string, i int, r rune) bool {\n"
    "\treturn r == 0xFFFD && !(i+3 <= len(s) && s[i] == 0xEF && s[i+1] == 0xBF && s[i+2] == 0xBD)\n"
    "}\n"
    "\n";

const char *GLUE_STRCONV_BMP =
    "func bmpLen(s string) (uintptr, error) {\n"
    "\tvar n uintptr\n"
    "\tfor i, r := range s {\n"
    "\t\tif ucsBadUTF8(s, i, r) {\n"
    "\t\t\treturn 0, ucsEncErr(\"BMPString\", \"value is not valid UTF-8\")\n"
    "\t\t}\n"
    "\t\tif r > 0xFFFF {\n"
    "\t\t\treturn 0, ucsEncErr(\"BMPString\", \"character U+\"+strconv.FormatInt(int64(r), 16)+\" is outside the Basic Multilingual Plane\")\n"
    "\t\t}\n"
    "\t\tn += 2\n"
    "\t}\n"
    "\treturn n, nil\n"
    "}\n"
    "\n"
    "func writeBMPField(fa *blockArena, recAddr unsafe.Pointer, s string) {\n"
    "\tvar n uintptr\n"
    "\tfor range s {\n\t\tn += 2\n\t}\n"
    "\tif n == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(n)\n"
    "\tb := unsafe.Slice((*byte)(payload), int(n))\n"
    "\tj := 0\n"
    "\tfor _, r := range s {\n"
    "\t\tif r > 0xFFFF {\n\t\t\tr = 0xFFFD\n\t\t}\n"
    "\t\tb[j] = byte(r >> 8)\n\t\tb[j+1] = byte(r)\n\t\tj += 2\n"
    "\t}\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = n\n"
    "}\n"
    "\n"
    "func readBMPField(recAddr unsafe.Pointer) (string, error) {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn \"\", nil\n\t}\n"
    "\tif n%2 != 0 {\n"
    "\t\treturn \"\", ucsDecErr(\"BMPString\", \"length \"+strconv.Itoa(int(n))+\" is not a multiple of 2\")\n"
    "\t}\n"
    "\tb := unsafe.Slice(*(**byte)(recAddr), int(n))\n"
    "\trs := make([]rune, 0, len(b)/2)\n"
    "\tfor i := 0; i < len(b); i += 2 {\n"
    "\t\tr := rune(b[i])<<8 | rune(b[i+1])\n"
    "\t\tif r >= 0xD800 && r <= 0xDFFF {\n"
    "\t\t\treturn \"\", ucsDecErr(\"BMPString\", \"code unit U+\"+strconv.FormatInt(int64(r), 16)+\" is a surrogate\")\n"
    "\t\t}\n"
    "\t\trs = append(rs, r)\n"
    "\t}\n"
    "\treturn string(rs), nil\n"
    "}\n"
    "\n";

const char *GLUE_STRCONV_UNIV =
    "func univLen(s string) (uintptr, error) {\n"
    "\tvar n uintptr\n"
    "\tfor i, r := range s {\n"
    "\t\tif ucsBadUTF8(s, i, r) {\n"
    "\t\t\treturn 0, ucsEncErr(\"UniversalString\", \"value is not valid UTF-8\")\n"
    "\t\t}\n"
    "\t\tn += 4\n"
    "\t}\n"
    "\treturn n, nil\n"
    "}\n"
    "\n"
    "func writeUnivField(fa *blockArena, recAddr unsafe.Pointer, s string) {\n"
    "\tvar n uintptr\n"
    "\tfor range s {\n\t\tn += 4\n\t}\n"
    "\tif n == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(n)\n"
    "\tb := unsafe.Slice((*byte)(payload), int(n))\n"
    "\tj := 0\n"
    "\tfor _, r := range s {\n"
    "\t\tb[j] = byte(r >> 24)\n\t\tb[j+1] = byte(r >> 16)\n\t\tb[j+2] = byte(r >> 8)\n\t\tb[j+3] = byte(r)\n\t\tj += 4\n"
    "\t}\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = n\n"
    "}\n"
    "\n"
    "func readUnivField(recAddr unsafe.Pointer) (string, error) {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n == 0 {\n\t\treturn \"\", nil\n\t}\n"
    "\tif n%4 != 0 {\n"
    "\t\treturn \"\", ucsDecErr(\"UniversalString\", \"length \"+strconv.Itoa(int(n))+\" is not a multiple of 4\")\n"
    "\t}\n"
    "\tb := unsafe.Slice(*(**byte)(recAddr), int(n))\n"
    "\trs := make([]rune, 0, len(b)/4)\n"
    "\tfor i := 0; i < len(b); i += 4 {\n"
    "\t\tu := uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])\n"
    "\t\tif u > 0x10FFFF || (u >= 0xD800 && u <= 0xDFFF) {\n"
    "\t\t\treturn \"\", ucsDecErr(\"UniversalString\", \"code point U+\"+strconv.FormatUint(uint64(u), 16)+\" is not a Unicode scalar value\")\n"
    "\t\t}\n"
    "\t\trs = append(rs, rune(u))\n"
    "\t}\n"
    "\treturn string(rs), nil\n"
    "}\n"
    "\n";

/* OBJECT IDENTIFIER / RELATIVE-OID helpers: the Go value is the []uint64
 * arcs, the Flat bytes record holds one little-endian uint32 per arc (the
 * C converters feed them to OBJECT_IDENTIFIER_set_arcs / RELATIVE_OID_set_arcs
 * and back from the _get_arcs functions). The C arc type is 32 bits, so an
 * arc above 4294967295 is an error, never truncated. */
const char *GLUE_STRCONV_OID =
    "func oidLen(a []uint64, rel bool) (uintptr, error) {\n"
    "\ttyp := \"OBJECT IDENTIFIER\"\n"
    "\tif rel {\n\t\ttyp = \"RELATIVE-OID\"\n\t}\n"
    "\tfor i, v := range a {\n"
    "\t\tif v > 0xFFFFFFFF {\n"
    "\t\t\treturn 0, ucsEncErr(typ, \"arc \"+strconv.Itoa(i)+\" (\"+strconv.FormatUint(v, 10)+\") exceeds 4294967295, the largest arc the C runtime holds\")\n"
    "\t\t}\n"
    "\t}\n"
    "\treturn uintptr(len(a)) * 4, nil\n"
    "}\n"
    "\n"
    "func writeOIDField(fa *blockArena, recAddr unsafe.Pointer, a []uint64) {\n"
    "\tn := uintptr(len(a)) * 4\n"
    "\tif n == 0 {\n\t\treturn\n\t}\n"
    "\tpayload := fa.allocPayload(n)\n"
    "\tb := unsafe.Slice((*byte)(payload), int(n))\n"
    "\tfor i, v := range a {\n"
    "\t\tb[4*i] = byte(v)\n\t\tb[4*i+1] = byte(v >> 8)\n\t\tb[4*i+2] = byte(v >> 16)\n\t\tb[4*i+3] = byte(v >> 24)\n"
    "\t}\n"
    "\tstorePtr(recAddr, payload)\n"
    "\t*(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen)) = n\n"
    "}\n"
    "\n"
    "func writeROIDField(fa *blockArena, recAddr unsafe.Pointer, a []uint64) {\n"
    "\twriteOIDField(fa, recAddr, a)\n"
    "}\n"
    "\n"
    "func readOIDField(recAddr unsafe.Pointer) ([]uint64, error) {\n"
    "\treturn readOIDArcs(recAddr, \"OBJECT IDENTIFIER\")\n"
    "}\n"
    "\n"
    "func readROIDField(recAddr unsafe.Pointer) ([]uint64, error) {\n"
    "\treturn readOIDArcs(recAddr, \"RELATIVE-OID\")\n"
    "}\n"
    "\n"
    "func readOIDArcs(recAddr unsafe.Pointer, typ string) ([]uint64, error) {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBytesFlatLen))\n"
    "\tif n%4 != 0 {\n"
    "\t\treturn nil, ucsDecErr(typ, \"arc buffer length \"+strconv.Itoa(int(n))+\" is not a multiple of 4\")\n"
    "\t}\n"
    "\tif n == 0 {\n\t\treturn []uint64{}, nil\n\t}\n"
    "\tb := unsafe.Slice(*(**byte)(recAddr), int(n))\n"
    "\ta := make([]uint64, n/4)\n"
    "\tfor i := range a {\n"
    "\t\ta[i] = uint64(b[4*i]) | uint64(b[4*i+1])<<8 | uint64(b[4*i+2])<<16 | uint64(b[4*i+3])<<24\n"
    "\t}\n"
    "\treturn a, nil\n"
    "}\n"
    "\n";

const char *GLUE_READ_BITS =
    "func readBitsField(recAddr unsafe.Pointer) BITSTR {\n"
    "\tn := *(*uintptr)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatLen))\n"
    "\tbs := BITSTR{BitsUnused: *(*int32)(unsafe.Pointer(uintptr(recAddr) + offBitsFlatBitsUnused))}\n"
    "\tif n == 0 {\n\t\treturn bs\n\t}\n"
    "\tbufPtr := *(**byte)(recAddr)\n"
    "\tbs.Bytes = append([]byte(nil), unsafe.Slice(bufPtr, int(n))...)\n"
    "\treturn bs\n"
    "}\n"
    "\n";

/* the alignment consts go to layout.go (already emitted there by go_flat.c
 * as const alignPtr/alignInt64/alignInt32? — go_flat.c emits per-type consts
 * only; the alignment consts + alignUp + must were skeleton-stage glue-scope items,
 * so the glue package header declares align* + gofmts them itself. */

/* the per-package file header. `module` = the go.mod module path (basename
 * or <prefix>/<basename>), `pkg` the package dir/name, `flat_hdr` the
 * package flat header, `pdu_externs` the entry-point extern decls text,
 * `flat_externs` extra flat includes, `rt_module` the runtime module's path
 * (asn1cgo-rt or <prefix>/asn1cgo-rt). */
extern int go_oer_disabled(void);

char *
pkg_header(const char *module, const char *pkg, const char *flat_hdr,
           const char *flat_includes, const char *pdu_externs,
           const char *rt_module) {
    char *s = strdup(GO_GENERATED_BANNER "//go:build amd64\n\n");
    s = ga(s, "// glue.go — generated Go<->Flat glue.\n");
    s = ga(s, "// Encode: one C block -> fill via the Go-side bump allocator -> the C\n");
    s = ga(s, "// entry point -> C.GoBytes copy -> buf_free + free (deferred, every\n");
    s = ga(s, "// path). Decode: the C entry point -> a deep copy into Go values\n");
    s = ga(s, "// (nothing aliases the arena) -> arena_free (every path). No Go pointer\n");
    s = ga(s, "// is stored in C memory; no package-level C state; each call owns its\n");
    s = ga(s, "// own arena, so the API is safe for concurrent use.\n");
    s = ga(s, "package ");
    s = ga(s, pkg);
    s = ga(s, "\n\n/*\n");
    s = ga(s, "#cgo CFLAGS: -I${SRCDIR}/../internal/cspec -I${SRCDIR}/../internal/cspec/rt");
    if(go_oer_disabled()) s = ga(s, " -DASN_DISABLE_OER_SUPPORT");
    s = ga(s, "\n");
    s = ga(s, "#include \"rt/arena.h\"\n");
    s = ga(s, "#include \"rt/err.h\"\n");
    s = ga(s, "#include \"rt/types.h\"\n");
    s = ga(s, "#include <stdlib.h>\n");
    s = ga(s, flat_includes);
    s = ga(s, "\ntypedef struct { uint8_t *buf; size_t len; } asn1cgo_buf;\n");
    s = ga(s, "extern void asn1cgo_buf_free(asn1cgo_buf *b);\n");
    s = ga(s, pdu_externs);
    s = ga(s, "*/\nimport \"C\"\n\n");
    s = ga(s, "// the C world (the asn1c tree copy + conv/entry C) lives in internal/\n");
    s = ga(s, "// cspec; the import links its objects into every build of this package\n");
    s = ga(s, "// (process-global externs under Go static linking).\n");
    s = ga(s, "import _ \"");
    s = ga(s, module);
    s = ga(s, "/internal/cspec\"\n\n");
    s = ga(s, "import (\n");
    s = ga(s, "\trt \"");
    s = ga(s, rt_module ? rt_module : "asn1cgo-rt");
    s = ga(s, "/rt\"\n");
    s = ga(s, "\t\"math\"\n");
    s = ga(s, "\t\"runtime\"\n");
    s = ga(s, "\t\"strconv\"\n");
    s = ga(s, "\t\"unsafe\"\n");
    s = ga(s, ")\n");
    return s;
}

/* fmt the fns of one queued registry entry into the package source. The
 * entries were emitted in dependency order (queue order; a fn's callees are
 * queued before it completes — actually callees queue DURING body emission,
 * so reverse the registry for emission: callees first). */
void
emit_fn_text(gluefn *f, gsb *src) {
    if(!f || !f->done) return;
    flat_type *t = go_flat_ir_type(f->ix);
    if(!t) return;
    char *cam = gcamel_flat(go_flat_ir_name(t));
    char *qt = gtype_q(t);   /* the package-qualified type spelling */
    const char *dp = conv_is_scc(t) ? ", depth int" : "";

    sb_am(src, gfmt(
        "func size%s(v *%s%s) (fixed, payload uintptr, err error) {\n",
        cam, qt, dp));
    sb_a(src, f->sz);
    sb_a(src, "\treturn\n}\n\n");
    sb_am(src, gfmt(
        "func fill%s(fa *blockArena, slot unsafe.Pointer, v *%s%s) error {\n",
        cam, qt, dp));
    sb_a(src, f->fill);
    /* a fill body that already returns (a delegation) must not get the
     * trailer `return nil` — unreachable. Mirror of the read side. */
    {
        const char *fb = f->fill ? f->fill : "";
        int fill_returns = 0;
        for(const char *q = fb; *q; ) {
            const char *eol = strchr(q, '\n');
            size_t ll = eol ? (size_t)(eol - q) : strlen(q);
            if(ll > 8 && strncmp(q, "\treturn ", 8) == 0) fill_returns = 1;
            if(!eol) break;
            q = eol + 1;
        }
        sb_a(src, fill_returns ? "}\n\n" : "\treturn nil\n}\n\n");
    }
    if(f->leaf_pdu) {
        sb_am(src, gfmt(
            "func read%s(slot unsafe.Pointer) (*%s, error) {\n\tv := new(%s)\n",
            cam, qt, qt));
    } else {
    sb_am(src, gfmt(
        "func read%s(slot unsafe.Pointer) (*%s, error) {\n\tv := &%s{}\n",
        cam, qt, qt));
    }
    {
        const char *rb = f->read ? f->read : "";
        int has_return = 0, uses_v = 0;
        for(const char *q = rb; *q; ) {
            const char *eol = strchr(q, '\n');
            size_t ll = eol ? (size_t)(eol - q) : strlen(q);
            if(ll > 8 && strncmp(q, "\treturn ", 8) == 0) has_return = 1;
            if(!eol) break;
            q = eol + 1;
        }
        if(strstr(rb, "v.") || strstr(rb, "= v") || strstr(rb, "(v)") || strstr(rb, "[v]"))
            uses_v = 1;
        size_t rbl = 0;
        while(rb[rbl] == ' ' || rb[rbl] == '\t' || rb[rbl] == '\n') rbl++;
        if(rb[rbl] == 0) has_return = 0;
        /* a returning, v-free body: blank the decl by hoisting `var _ =` —
         * simplest legal form: emit `_ = v` BEFORE the body (still used),
         * then the body, then just the close. */
        if(has_return && !uses_v)
            sb_a(src, "\t_ = v\n");
        sb_a(src, f->read);
        if(has_return) {
            sb_a(src, "}\n\n");
        } else {
            sb_a(src, "\tvar err error\n\t_ = err\n\treturn v, nil\n}\n\n");
        }
    }
    free(cam); free(qt);
}
