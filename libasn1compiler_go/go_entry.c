/*
 * go_entry.c — the entry-point emission
 * and the shared emission utilities of the conv TUs (file writing, mkdir,
 * the cspec package writer, the conv driver).
 *
 * Per recorded PDU root (go_conv_record_pdu — the walk mirrors asn1c's
 * -pdu=auto rule) three entry points are emitted into the spec's
 * <pkg>_entry.c, per the frozen entry-point shape (byte-for-byte):
 *
 *   int asn1cgo_encode_<PDU>(const <P>_PDU>_flat *in, asn1cgo_buf *out,
 *                            asn1cgo_err *err)
 *       calloc tree -> _to_tree -> asn_check_constraints (errbuf form)
 *       -> asn_encode_to_new_buffer(ATS_ALIGNED_BASIC_PER) -> ASN_STRUCT_FREE
 *       (r.result.encoded is BYTES, not bits)
 *
 *   int asn1cgo_decode_<PDU>(const uint8_t *buf, size_t len,
 *                            asn1cgo_arena **arena_out, <PDU>_flat **out,
 *                            asn1cgo_err *err)
 *       arena_new -> arena_alloc(flat) -> asn_decode -> trailing check
 *       -> asn_check_constraints (post-decode) -> _from_tree -> ASN_STRUCT_FREE ->
 *       hand arena+flat to the caller (Go frees)
 *
 *   int asn1cgo_xer_<PDU>(const <PDU>_flat *in, asn1cgo_buf *xer_out,
 *                         asn1cgo_err *err)
 *       _to_tree -> asn_encode_to_new_buffer(ATS_CANONICAL_XER) -> free
 *
 * asn1cgo_buf + asn1cgo_buf_free live in the asn1cgo-rt module (the per-spec prefix rule
 * amendment): the entry .c carries the local typedef only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

/* The rt runtime version every generated go.mod requires (single source:
 * the release script reads this same literal). */
#define ASN1CGO_RT_VERSION "v0.3.1"

#include "asn1c_internal.h"
#include "asn1c_misc.h"

#include "go_constructs.h"
#include "go_conv.h"
#include "go_conv_internal.h"
#include <ctype.h>
#include "go_strmap.h"

/* The IR surface (go_flat.c). */

/* The per-node body emitters (go_conv_to.c / go_conv_from.c). */
extern char *node_to_body_pub(void *t);
extern char *conv_from_node(void *t, int scc);

/* One PDU's three entry points (encode/decode/xer), emitted text. */
static char *
entry_encode(void *rt, const char *fbasename, const char *tbasename) {
    char *label = conv_type_label(rt);   /* td->name display label */
    char *s = cstrdup("");
    s = ca(s, "/* ---- encode ---- */\n");
    { char *_cf = cfmt("int asn1cgo_encode_%s(\n"
                   "        const %s_flat *in,\n"
                   "        asn1cgo_buf *out, asn1cgo_err *err) {\n",
                   tbasename, fbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!in || !out || !err) return asn1cgo_fail(err, ASN1CGO_E_ARG, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    out->buf = NULL; out->len = 0;\n\n");
    { char *_cf = cfmt("    %s_t *tree = (%s_t *)asn1cgo_calloc(1, sizeof(*tree));\n", tbasename, tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!tree) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (%s_to_tree(in, tree, err)) {\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        ASN_STRUCT_FREE(asn_DEF_%s, tree);\n        return err->code;\n    }\n\n", tbasename); s = ca(s, _cf); free(_cf); }
    /* constraints with the pinned errbuf API (the ASSUMPTION A4 form). */
    s = ca(s, "    char cerr[256];\n    size_t cerrlen = sizeof(cerr);\n");
    { char *_cf = cfmt("    if (asn_check_constraints(&asn_DEF_%s, tree, cerr, &cerrlen) != 0) {\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        ASN_STRUCT_FREE(asn_DEF_%s, tree);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_CONSTRAINT, \"%s\", NULL,\n"
                   "                            \"%%.*s\", (int)(cerrlen < sizeof(cerr) ? cerrlen : sizeof(cerr)-1), cerr);\n    }\n\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    asn_encode_to_new_buffer_result_t r =\n"
             "        asn_encode_to_new_buffer(NULL, ATS_ALIGNED_BASIC_PER,\n");
    { char *_cf = cfmt("                                 &asn_DEF_%s, tree);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    ASN_STRUCT_FREE(asn_DEF_%s, tree);\n", tbasename); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    if (r.result.encoded < 0 || !r.buffer) {\n        free(r.buffer);\n");
    { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_ENCODE, \"%s\", NULL, \"aper encode failed\");\n    }\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    out->buf = (uint8_t *)r.buffer;\n    out->len = (size_t)r.result.encoded;   /* bytes, not bits */\n    return 0;\n}\n\n");
    free(label);
    return s;
}

static char *
entry_decode(void *rt, const char *fbasename, const char *tbasename) {
    char *label = conv_type_label(rt);   /* td->name display label */
    char *s = cstrdup("");
    s = ca(s, "/* ---- decode ---- */\n");
    { char *_cf = cfmt("int asn1cgo_decode_%s(\n"
                   "        const uint8_t *buf, size_t len, asn1cgo_arena **arena_out,\n"
                   "        %s_flat **out, asn1cgo_err *err) {\n",
                   tbasename, fbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!buf || !arena_out || !out || !err) return asn1cgo_fail(err, ASN1CGO_E_ARG, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    *arena_out = NULL; *out = NULL;\n\n");
    s = ca(s, "    asn1cgo_arena *ar = asn1cgo_arena_new(0);\n");
    { char *_cf = cfmt("    if (!ar) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    %s_flat *flat = (%s_flat *)asn1cgo_arena_alloc(ar, sizeof(*flat), _Alignof(%s_flat));\n", fbasename, fbasename, fbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!flat) { asn1cgo_arena_free(ar); return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL); }\n\n", label); s = ca(s, _cf); free(_cf); }
    /* C-side stack guard: hand asn_decode a stack-local ctx with
     * max_stack_size = ASN1CGO_C_STACK_MAX so asn1c's ASN__STACK_OVERFLOW_CHECK
     * (measured from the ctx's address, hence dctx MUST stay a local here)
     * bounds the C decoder's recursion before the input is fully decoded.
     * per_decoder.c copies a non-NULL ctx only when max_stack_size != 0, and
     * substitutes its own 30000-byte default only for a NULL ctx. Overrun
     * surfaces as RC_FAIL, indistinguishable from other malformed input, so
     * it maps to E_DECODE. ASN1CGO_MAX_DEPTH (64 units) is the separate,
     * precise cap applied in *_from_tree; the default stack budget is sized
     * so that no input within that cap trips the C guard. */
    s = ca(s, "    void *sptr = NULL;\n    asn_codec_ctx_t dctx = {0};   /* stack local: the guard measures from its address */\n    dctx.max_stack_size = ASN1CGO_C_STACK_MAX;\n    asn_dec_rval_t dr = asn_decode(&dctx, ATS_ALIGNED_BASIC_PER,\n");
    { char *_cf = cfmt("                                   &asn_DEF_%s, (void **)&sptr, buf, len);\n", tbasename); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    if (dr.code != RC_OK) {\n");
    { char *_cf = cfmt("        if (sptr) ASN_STRUCT_FREE(asn_DEF_%s, sptr);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        asn1cgo_arena_free(ar);\n        return asn1cgo_fail(err, ASN1CGO_E_DECODE, \"%s\", NULL, \"aper decode RC=%%d (malformed input, or C stack budget ASN1CGO_C_STACK_MAX exceeded)\", dr.code);\n    }\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    /* Trailing bytes after the PDU are an error. */\n");
    s = ca(s, "    if (dr.consumed < len) {\n");
    { char *_cf = cfmt("        ASN_STRUCT_FREE(asn_DEF_%s, sptr);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        asn1cgo_arena_free(ar);\n        return asn1cgo_fail(err, ASN1CGO_E_TRAILING, \"%s\", NULL, \"%%zu trailing bytes\", len - dr.consumed);\n    }\n\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    /* asn1c's APER decoder does not range/size/permitted-alphabet\n");
    s = ca(s, "     * check; reject a decoded Tree its own constraints would fail. */\n");
    s = ca(s, "    char cerr[256];\n    size_t cerrlen = sizeof(cerr);\n");
    { char *_cf = cfmt("    if (asn_check_constraints(&asn_DEF_%s, sptr, cerr, &cerrlen) != 0) {\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        ASN_STRUCT_FREE(asn_DEF_%s, sptr);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        asn1cgo_arena_free(ar);\n        return asn1cgo_fail(err, ASN1CGO_E_CONSTRAINT, \"%s\", NULL,\n"
                   "                            \"%%.*s\", (int)(cerrlen < sizeof(cerr) ? cerrlen : sizeof(cerr)-1), cerr);\n    }\n\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    int rc = %s_from_tree(ar, (const %s_t *)sptr, flat, err);\n", tbasename, tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    ASN_STRUCT_FREE(asn_DEF_%s, sptr);\n", tbasename); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    if (rc) { asn1cgo_arena_free(ar); return err->code; }\n\n");
    s = ca(s, "    *arena_out = ar;       /* caller (Go) frees */\n    *out = flat;\n    return 0;\n}\n\n");
    free(label);
    return s;
}

static char *
entry_xer(void *rt, const char *fbasename, const char *tbasename) {
    char *label = conv_type_label(rt);   /* td->name display label */
    char *s = cstrdup("");
    s = ca(s, "/* ---- xer (ATS_CANONICAL_XER) ---- */\n");
    { char *_cf = cfmt("int asn1cgo_xer_%s(\n"
                   "        const %s_flat *in,\n"
                   "        asn1cgo_buf *xer_out, asn1cgo_err *err) {\n",
                   tbasename, fbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!in || !xer_out || !err) return asn1cgo_fail(err, ASN1CGO_E_ARG, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    xer_out->buf = NULL; xer_out->len = 0;\n\n");
    { char *_cf = cfmt("    %s_t *tree = (%s_t *)asn1cgo_calloc(1, sizeof(*tree));\n", tbasename, tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (!tree) return asn1cgo_fail(err, ASN1CGO_E_ALLOC, \"%s\", NULL, NULL);\n", label); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    if (%s_to_tree(in, tree, err)) {\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("        ASN_STRUCT_FREE(asn_DEF_%s, tree);\n        return err->code;\n    }\n", tbasename); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    asn_encode_to_new_buffer_result_t r =\n"
             "        asn_encode_to_new_buffer(NULL, ATS_CANONICAL_XER,\n");
    { char *_cf = cfmt("                                 &asn_DEF_%s, tree);\n", tbasename); s = ca(s, _cf); free(_cf); }
    { char *_cf = cfmt("    ASN_STRUCT_FREE(asn_DEF_%s, tree);\n", tbasename); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    if (r.result.encoded < 0 || !r.buffer) {\n        free(r.buffer);\n");
    { char *_cf = cfmt("        return asn1cgo_fail(err, ASN1CGO_E_ENCODE, \"%s\", NULL, \"xer encode failed\");\n    }\n", label); s = ca(s, _cf); free(_cf); }
    s = ca(s, "    xer_out->buf = (uint8_t *)r.buffer;\n    xer_out->len = (size_t)r.result.encoded;\n    return 0;\n}\n");
    free(label);
    return s;
}

/* ---------------------------------------------------------------------------
 * File utilities (shared by the conv emission; this TU owns file IO).
 * ------------------------------------------------------------------------- */
static int conv_copy_dir_files(const char *srcdir, const char *dstdir);
static int
conv_mkdir_p(const char *path) {
    char buf[4096];
    size_t n = strlen(path);
    if(n == 0 || n >= sizeof buf) {
        fprintf(stderr, "asn1cgo: conv: bad directory path (empty or too long): '%s'\n", path);
        return -1;
    }
    memcpy(buf, path, n + 1);
    for(size_t i = 1; i < n; i++) {
        if(buf[i] == '/') {
            buf[i] = '\0';
            if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: conv: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
            buf[i] = '/';
        }
    }
    if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: conv: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
    return 0;
}

static char *
conv_path(const char *dir, const char *leaf) {
    size_t a = strlen(dir), b = strlen(leaf);
    char *p = malloc(a + 1 + b + 1);
    if(!p) { conv_failed_set(); return cstrdup(""); }
    memcpy(p, dir, a); p[a] = '/'; memcpy(p + a + 1, leaf, b); p[a + 1 + b] = 0;
    return p;
}

static int
conv_fwrite_all(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if(!f) {
        fprintf(stderr, "asn1cgo: conv: cannot write '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    size_t n = strlen(text);
    int ok = fwrite(text, 1, n, f) == n;
    if(fclose(f) != 0) ok = 0;
    if(!ok) {
        fprintf(stderr, "asn1cgo: conv: write failed under '%s'\n", path);
        return -1;
    }
    return 0;
}

/* Copy one file's bytes (returns 0/-1). */
static int
conv_copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if(!in) {
        fprintf(stderr, "asn1cgo: conv: cannot read '%s': %s\n",
                src, strerror(errno));
        return -1;
    }
    FILE *out = fopen(dst, "wb");
    if(!out) {
        fprintf(stderr, "asn1cgo: conv: cannot write '%s': %s\n",
                dst, strerror(errno));
        fclose(in);
        return -1;
    }
    char buf[65536];
    size_t n;
    int ok = 1;
    while((n = fread(buf, 1, sizeof buf, in)) > 0)
        if(fwrite(buf, 1, n, out) != n) { ok = 0; break; }
    if(ferror(in)) ok = 0;
    fclose(in);
    if(fclose(out) != 0) ok = 0;
    if(!ok) {
        fprintf(stderr, "asn1cgo: conv: copy '%s' -> '%s' failed\n", src, dst);
        return -1;
    }
    return 0;
}

/* module_pkg (lowercase, '-' -> '_'; mirrors go_flat.c's helper). */
static char *
conv_module_pkg(const char *module_name) {
    const char *s = module_name ? module_name : "_";
    char *out = malloc(strlen(s) + 1);
    if(!out) { conv_failed_set(); return cstrdup(""); }
    size_t j = 0;
    for(size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        out[j++] = (char)(c == '-' ? '_' : tolower(c));
    }
    out[j] = '\0';
    return out;
}

/* ---------------------------------------------------------------------------
 * go_conv_emit — the cspec package writer.
 *
 * Layout under <go_outdir> (= the spec's Go module root):
 *   internal/cspec/<P><pkg>_conv.c   converters + IOC dispatch + entry C
 *   internal/cspec/<unprefixed .c/.h from ASN1C_DESTDIR starting with the run
 *                                    prefix>  — the asn1c-generated C copy
 *                                    (runtime .c/pdu_collection.c/converter-
 *                                    example.c are unprefixed and drop out)
 *   internal/cspec/cgo.go            the minimal cgo package file
 *   internal/cspec/rt headers        header-only rt copy (gated
 *                                    byte-identical to asn1cgo-rt's)
 * plus <go_outdir>/go.mod's rt require (and replace in ASN1CGO_RT_LOCAL mode). Returns 0/-1.
 * ------------------------------------------------------------------------- */

/* rt cgo.go text (byte-stable). RETIRED by the single-source rt move: the
 * module's errors.go is copied verbatim from libasn1compiler_go/rt/go/rt
 * (copy == source byte-for-byte); no cgo.go is emitted. The
 * string is deleted; this comment marks where it lived. */


/* cspec cgo.go text (the import path is parameterized by the rt module). */
extern int go_oer_disabled(void);

static char *
cspec_cgo_go_text(void) {
    const char *oer_def = go_oer_disabled() ? " -DASN_DISABLE_OER_SUPPORT" : "";
    return cfmt(
        GO_GENERATED_BANNER
        "//go:build amd64\n"
        "\n"
        "// Package cspec holds THIS spec's entire C world (the asn1c tree\n"
        "// copy + every <pkg>_flat.h + the conv/entry C): every generated\n"
        "// .c of the spec, EXCLUDING the shared asn1c runtime .c (ONE copy\n"
        "// in the asn1cgo-rt module — imported below so its objects join\n"
        "// every link that pulls this package) and the asn_pdu_collection /\n"
        "// converter-example artifacts.\n"
        "package cspec\n"
        "\n"
        "/*\n"
        // every header this package compiles against is INSIDE
        // the module — generated spec headers at ${SRCDIR}, the rt +
        // asn1c-runtime header copies under ${SRCDIR}/rt. C symbols resolve
        // at the final link from the rt package's cgo objects; NO include
        // path may cross the module boundary (the file-proxy consumer leg
        // gates this).
        "#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/rt%s -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations\n"
        "*/\n"
        "import \"C\"\n"
        "\n", oer_def);
    /* the asn1cgo-rt import line is appended by the caller, gated on
     * the rt module actually being emitted (ASN1CGO_FORK_SKEL) — a dangling
     * module reference breaks every go build of the tree. */
}

/* Which files does a cspec copy take from the destdir? Only files starting
 * with the run prefix: generated-type .c/.h (prefixed), never
 * the runtime set / pdu_collection.c / converter-example.c (unprefixed). */
static char *conv_path_sk_probe(const char *nm);

static int
conv_copy_prefixed_files(const char *srcdir, const char *dstdir) {
    const char *pfx = asn1c_prefix();
    size_t pl = pfx ? strlen(pfx) : 0;
    DIR *d = opendir(srcdir);
    if(!d) {
        fprintf(stderr, "asn1cgo: conv: cannot open destdir '%s': %s\n",
                srcdir, strerror(errno));
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while((e = readdir(d)) != NULL) {
        const char *nm = e->d_name;
        size_t nl = strlen(nm);
        if(nl < 3) continue;
        int is_c = strcmp(nm + nl - 2, ".c") == 0;
        int is_h = strcmp(nm + nl - 2, ".h") == 0;
        if(!is_c && !is_h) continue;
        /* the NEVER-COMPILED artifacts drop in BOTH modes; the runtime
         * set (same basename as a fork skeletons file) drops in the
         * UNPREFIXED mode only — under a prefix they never match pl. */
        if(strcmp(nm, "pdu_collection.c") == 0) continue;
        if(strcmp(nm, "converter-example.c") == 0) continue;
        if(pl == 0) {
            /* unprefixed run: the prefix filter is vacuous — every file
             * matches. Exclude the runtime set by skeletons basename: a
             * same-basename .c/.h in the fork skeletons IS a runtime copy
             * (the one-copy rule lives in asn1cgo-rt). */
            char *sk = conv_path_sk_probe(nm);
            if(sk) { free(sk); continue; }
        }
        if(pl && strncmp(nm, pfx, pl) != 0) continue;   /* unprefixed drops */
        char *src = conv_path(srcdir, nm);
        char *dst = conv_path(dstdir, nm);
        if(conv_copy_file(src, dst) < 0) rc = -1;
        free(src); free(dst);
        if(rc) break;
    }
    closedir(d);
    return rc;
}

/* Copy every *_flat.h from srcdir (flat) into dstdir; rt/ subdir skipped. */
static int
conv_copy_flat_headers(const char *srcdir, const char *dstdir) {
    DIR *d = opendir(srcdir);
    if(!d) return 0;   /* no c/ dir yet (skeleton-stage layout): nothing to copy */
    struct dirent *e;
    int rc = 0;
    while((e = readdir(d)) != NULL) {
        const char *nm = e->d_name;
        size_t nl = strlen(nm);
        if(nl < 7 || strncmp(nm + nl - 7, "_flat.h", 7) != 0) continue;
        if(e->d_type == DT_DIR) continue;
        char *src = conv_path(srcdir, nm);
        char *dst = conv_path(dstdir, nm);
        if(conv_copy_file(src, dst) < 0) rc = -1;
        free(src); free(dst);
        if(rc) break;
    }
    closedir(d);
    return rc;
}

/* Directories handed over by the driver (-S / -D). The ASN1CGO_FORK_SKEL and
 * ASN1C_DESTDIR env vars remain optional overrides and win when set. */
static char *g_skel_dir = NULL;
static char *g_dest_dir = NULL;

static char *dup_trim_slashes(const char *s) {
    size_t n = strlen(s);
    char *r = malloc(n + 1);
    if(!r) return NULL;
    memcpy(r, s, n + 1);
    while(n > 1 && r[n - 1] == '/') r[--n] = '\0';
    return r;
}

/* Record the driver's skeletons dir and C destdir (NULL/"" destdir => "."). */
int go_entry_set_dirs(const char *skeletons_dir, const char *destdir) {
    free(g_skel_dir); free(g_dest_dir);
    g_skel_dir = (skeletons_dir && *skeletons_dir)
                     ? dup_trim_slashes(skeletons_dir) : NULL;
    g_dest_dir = dup_trim_slashes((destdir && *destdir) ? destdir : ".");
    return g_dest_dir ? 0 : -1;
}

/* Effective skeletons dir: env override, else the driver's -S. */
static const char *go_skel_dir(void) {
    const char *e = getenv("ASN1CGO_FORK_SKEL");
    if(e && *e) return e;
    return g_skel_dir;
}

/* Effective C destdir: env override, else the driver's -D (default "."). */
static const char *go_dest_dir(void) {
    const char *e = getenv("ASN1C_DESTDIR");
    if(e && *e) return e;
    return g_dest_dir;
}

/* nm exists in the fork skeletons dir (a runtime file; the ASN1CGO_FORK_SKEL
 * env names it — NULL when unset, i.e. the caller then keeps the file). */
static char *conv_path_sk_probe(const char *nm) {
    const char *sk = go_skel_dir();
    if(!sk || !*sk) return NULL;
    char *p = malloc(strlen(sk) + 1 + strlen(nm) + 1);
    if(!p) return NULL;
    sprintf(p, "%s/%s", sk, nm);
    struct stat st;
    if(stat(p, &st) == 0) return p;
    free(p);
    return NULL;
}

/* rt_src_file: resolve a file of the single rt source root
 * (libasn1compiler_go/rt/go/rt). The root is located relative to THIS
 * source file's compiled location: compiled as
 * <fork>/libasn1compiler_go/go_entry.c, the source is <fork>/
 * libasn1compiler_go/rt/go/rt. The path is taken from ASN1CGO_RT_SRC when
 * set (an explicit override), else derived from ASN1CGO_FORK_SKEL's
 * parent (the fork root whose skeletons/ that variable names), else
 * <skeletons>/go-rt (the installed layout).
 * Returns a malloc'd path (caller frees) or NULL when unresolvable. */
static char *rt_src_file(const char *name) {
    const char *o = getenv("ASN1CGO_RT_SRC");
    if(o && *o) return conv_path(o, name);
    const char *sk = go_skel_dir();
    if(sk && *sk) {
        const char *slash = strrchr(sk, '/');
        {
            /* no slash: skeletons is a bare relative dir, parent is "." */
            const char *par = slash ? sk : ".";
            size_t pl = slash ? (size_t)(slash - sk) : 1;   /* the fork root */
            char *p = malloc(pl + 1 + strlen("libasn1compiler_go/rt/go/rt/")
                             + strlen(name) + 1);
            if(p) {
                memcpy(p, par, pl);
                sprintf(p + pl, "/libasn1compiler_go/rt/go/rt/%s", name);
                struct stat st;
                if(stat(p, &st) == 0 && S_ISREG(st.st_mode)) return p;
            }
            free(p);
        }
        /* installed layout: `make install` puts the rt C files the
         * generator copies in <pkgdatadir>/go-rt, and -S defaults to
         * <pkgdatadir> */
        char *q = malloc(strlen(sk) + strlen("/go-rt/") + strlen(name) + 1);
        if(q) {
            sprintf(q, "%s/go-rt/%s", sk, name);
            struct stat st;
            if(stat(q, &st) == 0 && S_ISREG(st.st_mode)) return q;
            free(q);
        }
    }
    return NULL;
}

/* Copy one named rt source file to dstdir. Returns 0 ok, -1 (diag). */
static int
conv_copy_rt_file(const char *dstdir, const char *name) {
    char *src = rt_src_file(name);
    if(!src) {
        fprintf(stderr,
                "asn1cgo: conv: rt source file '%s' not found — set "
                "ASN1CGO_FORK_SKEL to <fork>/skeletons (source lives at "
                "<fork>/libasn1compiler_go/rt/go/rt) or ASN1CGO_RT_SRC "
                "to that rt dir\n", name);
        return -1;
    }
    char *dst = conv_path(dstdir, name);
    int rc = conv_copy_file(src, dst);
    if(rc < 0)
        fprintf(stderr, "asn1cgo: conv: cannot copy rt source '%s' -> '%s'\n",
                src, dst);
    free(src); free(dst);
    return rc;
}

/* copy one asn1c-runtime HEADER from the fork skeletons into
 * dstdir. The asn1c runtime headers (asn_application.h, constr_*.h, ...)
 * are skeleton files, NOT rt/go files; like the rt trio they land under
 * cspec/rt so the package's includes never leave the module (byte-
 * identical copies of the skeleton headers). */
static int
conv_copy_skel_header(const char *dstdir, const char *name) {
    char *src = conv_path_sk_probe(name);
    if(!src) {
        fprintf(stderr,
                "asn1cgo: conv: asn1c runtime header '%s' not found in the "
                "fork skeletons — pass -S <fork>/skeletons "
                "(or set ASN1CGO_FORK_SKEL)\n", name);
        return -1;
    }
    char *dst = conv_path(dstdir, name);
    int rc = conv_copy_file(src, dst);
    if(rc < 0)
        fprintf(stderr, "asn1cgo: conv: cannot copy runtime header '%s' "
                " -> '%s'\n", src, dst);
    free(src); free(dst);
    return rc;
}

/* The asn1c runtime headers every generated spec's c/ .h + .c include,
 * DIRECT AND TRANSITIVE over quoted AND angle includes of skeleton files
 * (computed over the pinned skeletons; config.h is excluded — its include
 * in asn_system.h is HAVE_CONFIG_H-guarded and cgo never defines that;
 * true system headers — stdio.h, inttypes.h, … — resolve from libc). A
 * spec needing one more is a generator change that updates this closed
 * list, by construction loud. */
static const char *skel_header_files[] = {
    "ANY.h",
    "BIT_STRING.h",
    "BOOLEAN.h",
    "INTEGER.h",
    "NULL.h",
    "NativeEnumerated.h",
    "NativeInteger.h",
    "NativeReal.h",
    "OCTET_STRING.h",
    "OPEN_TYPE.h",
    "PrintableString.h",
    "asn_SEQUENCE_OF.h",
    "asn_SET_OF.h",
    "asn_application.h",
    "asn_bit_data.h",
    "asn_codecs.h",
    "asn_codecs_prim.h",
    "asn_internal.h",
    "asn_ioc.h",
    "asn_random_fill.h",
    "asn_system.h",
    "ber_decoder.h",
    "ber_tlv_length.h",
    "ber_tlv_tag.h",
    "constr_CHOICE.h",
    "constr_SEQUENCE.h",
    "constr_SEQUENCE_OF.h",
    "constr_SET_OF.h",
    "constr_TYPE.h",
    "constraints.h",
    "der_encoder.h",
    "oer_decoder.h",
    "oer_encoder.h",
    "oer_support.h",
    "per_decoder.h",
    "per_encoder.h",
    "per_support.h",
    "xer_decoder.h",
    "xer_encoder.h",
};

/* The asn1cgo-rt module is NO LONGER EMITTED (single-source rt move): the
 * BUILD supplies it (go.work/replace) from libasn1compiler_go/rt/go.
 * The generator's obligations shrink to: the rt FILES the generated tree
 * itself needs in place (c/rt + internal/cspec/rt header copies), and the
 * versioned require in <go_outdir>/go.mod. */


/* ASN1CGO_RT_LOCAL support. Resolves the env dir against the -Fgo dir's
 * parent: *gomod_rel = the `replace` target (relative to the -Fgo dir, i.e.
 * "../<sub>", when the dir is inside the parent; absolute otherwise),
 * *work_entry = the go.work `use` entry ("./<sub>" or absolute). Both
 * malloc'd; both NULL when the env var is unset. Returns 0, -1 on error. */
static int
rt_local_paths(const char *go_outdir, char **gomod_rel, char **work_entry) {
    *gomod_rel = NULL; *work_entry = NULL;
    const char *loc = getenv("ASN1CGO_RT_LOCAL");
    if(!loc || !*loc) return 0;
    char *rl = realpath(loc, NULL);
    if(!rl) {
        fprintf(stderr, "asn1cgo: ASN1CGO_RT_LOCAL '%s': %s\n", loc,
                strerror(errno));
        return -1;
    }
    const char *slash = strrchr(go_outdir, '/');
    char *par = NULL;
    if(!slash) par = realpath(".", NULL);
    else if(slash == go_outdir) par = strdup("/");
    else {
        char *tmp = strndup(go_outdir, (size_t)(slash - go_outdir));
        par = tmp ? realpath(tmp, NULL) : NULL;
        free(tmp);
    }
    size_t pl = par ? strlen(par) : 0;
    if(par && pl > 1 && strncmp(rl, par, pl) == 0 && rl[pl] == '/') {
        *gomod_rel = cfmt("../%s", rl + pl + 1);
        *work_entry = cfmt("./%s", rl + pl + 1);
    } else if(par && strcmp(rl, par) == 0) {
        *gomod_rel = strdup("..");
        *work_entry = strdup(".");
    } else {
        *gomod_rel = strdup(rl);
        *work_entry = strdup(rl);
    }
    free(par); free(rl);
    return (*gomod_rel && *work_entry) ? 0 : -1;
}

/* Copy every regular file of srcdir into dstdir (flat). */
static int conv_copy_dir_files(const char *srcdir, const char *dstdir);
static int
conv_copy_dir_files(const char *srcdir, const char *dstdir) {
    DIR *d = opendir(srcdir);
    if(!d) {
        fprintf(stderr, "asn1cgo: conv: cannot open '%s': %s\n",
                srcdir, strerror(errno));
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while((e = readdir(d)) != NULL) {
        const char *nm = e->d_name;
        if(nm[0] == '.') continue;
        struct stat st;
        char *sp = conv_path(srcdir, nm);
        if(stat(sp, &st) == 0 && S_ISREG(st.st_mode)) {
            char *dp = conv_path(dstdir, nm);
            if(conv_copy_file(sp, dp) < 0) rc = -1;
            free(dp);
        }
        free(sp);
        if(rc) break;
    }
    closedir(d);
    return rc;
}

/* Resolve a tree type base to the .h file name the C backend wrote for it
 * (asn1c keeps ORIGINAL hyphens in file names while type symbols collapse
 * them to underscores: KPM_MeasurementInfo-Action-List.h defines
 * KPM_MeasurementInfo_Action_List_t). Scans ASN1C_DESTDIR for the .h whose
 * text contains "} <base>_t;". Returns a malloc'd file name or NULL. */
static gsmap g_hdr_ix;           /* base -> index into g_hdr_names */
static char **g_hdr_names;
static int g_hdr_n, g_hdr_built;

/* One pass over the destination's .h files (the lookup used to reopen and
 * rescan every header per call): every line ending "<sep><ident>_t;" with
 * <sep> a space, tab, '}' or '*' (or the line start) registers <ident> ->
 * that file; the first file in directory order wins, as before. */
static void
conv_header_index(void) {
    if(g_hdr_built) return;
    g_hdr_built = 1;
    const char *dd = go_dest_dir();
    DIR *d = (dd && *dd) ? opendir(dd) : NULL;
    if(!d) return;
    struct dirent *e;
    int cap = 0;
    while((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if(nl < 3 || strcmp(e->d_name + nl - 2, ".h") != 0) continue;
        char *p = conv_path(dd, e->d_name);
        FILE *f = fopen(p, "r");
        free(p);
        if(!f) continue;
        int fidx = -1;
        char line[1024];
        while(fgets(line, sizeof line, f)) {
            size_t ll = strlen(line);
            while(ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r' ||
                             line[ll-1] == ' ' || line[ll-1] == '\t'))
                ll--;
            if(ll < 3 || memcmp(line + ll - 3, "_t;", 3) != 0) continue;
            size_t end = ll - 3, st = end;
            while(st > 0 && (isalnum((unsigned char)line[st-1])
                             || line[st-1] == '_'))
                st--;
            if(st == end) continue;
            if(st > 0 && line[st-1] != ' ' && line[st-1] != '\t'
               && line[st-1] != '}' && line[st-1] != '*')
                continue;
            line[end] = '\0';
            int dummy;
            if(gsmap_get(&g_hdr_ix, line + st, &dummy)) continue;
            if(fidx < 0) {
                if(g_hdr_n == cap) {
                    cap = cap ? cap * 2 : 256;
                    char **nn = realloc(g_hdr_names, (size_t)cap * sizeof *nn);
                    if(!nn) break;
                    g_hdr_names = nn;
                }
                g_hdr_names[g_hdr_n] = cstrdup(e->d_name);
                fidx = g_hdr_n++;
            }
            gsmap_put_first(&g_hdr_ix, line + st, fidx);
        }
        fclose(f);
    }
    closedir(d);
}

static char *
conv_find_header(const char *base) {
    const char *dd = go_dest_dir();
    if(!dd || !*dd || !base || !*base) return NULL;
    conv_header_index();
    int v;
    return gsmap_get(&g_hdr_ix, base, &v) ? cstrdup(g_hdr_names[v]) : NULL;
}

/* ---------------------------------------------------------------------------
 * go_conv_emit — assemble the cspec package for this spec run.
 * go_rt_module = the runtime module's import path (asn1cgo-rt, or
 * <prefix>/asn1cgo-rt when ASN1CGO_GO_MODULE_PREFIX is set).
 * ------------------------------------------------------------------------- */
/* The converter-preamble helpers of OBJECT IDENTIFIER / RELATIVE-OID values.
 * asn1cgo_oid_set: little-endian arcs -> the tree slot (0, -1 the arc
 * function rejected the value, -2 allocation failure). asn1cgo_oid_get: the
 * tree slot's contents octets -> little-endian arcs in a Flat bytes record
 * (0, -1 malformed, -2 allocation failure); the get is the grow-and-retry
 * of OBJECT_IDENTIFIER.h. */
static const char GO_OID_PREAMBLE[] =
    "#include <errno.h>\n"
    "#include \"OBJECT_IDENTIFIER.h\"\n"
    "#include \"RELATIVE-OID.h\"\n"
    "\n"
    "static int\n"
    "asn1cgo_oid_set(void *slot, const uint8_t *buf, size_t len, int rel) {\n"
    "    size_t n = len / 4, i;\n"
    "    int rc;\n"
    "    asn_oid_arc_t *arcs = (asn_oid_arc_t *)asn1cgo_calloc(n ? n : 1, sizeof(*arcs));\n"
    "    if (!arcs) return -2;\n"
    "    for (i = 0; i < n; i++)\n"
    "        arcs[i] = (asn_oid_arc_t)buf[4 * i] | ((asn_oid_arc_t)buf[4 * i + 1] << 8)\n"
    "                | ((asn_oid_arc_t)buf[4 * i + 2] << 16) | ((asn_oid_arc_t)buf[4 * i + 3] << 24);\n"
    "    errno = 0;\n"
    "    rc = rel ? RELATIVE_OID_set_arcs((RELATIVE_OID_t *)slot, arcs, n)\n"
    "             : OBJECT_IDENTIFIER_set_arcs((OBJECT_IDENTIFIER_t *)slot, arcs, n);\n"
    "    free(arcs);\n"
    "    if (rc == 0) return 0;\n"
    "    return errno == ENOMEM ? -2 : -1;\n"
    "}\n"
    "\n"
    "static int\n"
    "asn1cgo_oid_get(asn1cgo_arena *ar, const void *slot, asn1cgo_bytes_flat *out, int rel) {\n"
    "    const OBJECT_IDENTIFIER_t *o = (const OBJECT_IDENTIFIER_t *)slot;\n"
    "    asn_oid_arc_t fixed[16];\n"
    "    asn_oid_arc_t *arcs = fixed;\n"
    "    size_t slots = sizeof(fixed) / sizeof(fixed[0]), i;\n"
    "    ssize_t n;\n"
    "    out->len = 0;\n"
    "    out->buf = NULL;\n"
    "    if (!o->buf) return (rel && o->size == 0) ? 0 : -1;\n"
    "    n = rel ? RELATIVE_OID_get_arcs((const RELATIVE_OID_t *)o, arcs, slots)\n"
    "            : OBJECT_IDENTIFIER_get_arcs(o, arcs, slots);\n"
    "    if (n < 0) return -1;\n"
    "    if ((size_t)n > slots) {\n"
    "        ssize_t n2;\n"
    "        slots = (size_t)n;\n"
    "        arcs = (asn_oid_arc_t *)asn1cgo_calloc(slots, sizeof(*arcs));\n"
    "        if (!arcs) return -2;\n"
    "        n2 = rel ? RELATIVE_OID_get_arcs((const RELATIVE_OID_t *)o, arcs, slots)\n"
    "                 : OBJECT_IDENTIFIER_get_arcs(o, arcs, slots);\n"
    "        if (n2 != n) { free(arcs); return -1; }\n"
    "    }\n"
    "    if (n > 0) {\n"
    "        uint8_t *b = (uint8_t *)asn1cgo_arena_alloc(ar, (size_t)n * 4, 8);\n"
    "        if (!b) {\n"
    "            if (arcs != fixed) free(arcs);\n"
    "            return -2;\n"
    "        }\n"
    "        for (i = 0; i < (size_t)n; i++) {\n"
    "            b[4 * i] = (uint8_t)arcs[i];\n"
    "            b[4 * i + 1] = (uint8_t)(arcs[i] >> 8);\n"
    "            b[4 * i + 2] = (uint8_t)(arcs[i] >> 16);\n"
    "            b[4 * i + 3] = (uint8_t)(arcs[i] >> 24);\n"
    "        }\n"
    "        out->buf = b;\n"
    "        out->len = (size_t)n * 4;\n"
    "    }\n"
    "    if (arcs != fixed) free(arcs);\n"
    "    return 0;\n"
    "}\n"
    "\n";

int
go_conv_emit(const char *go_outdir, const char *go_rt_module) {
    if(!go_outdir || !*go_outdir) return 0;
    if(g_conv_failed_) return -1;

    const char *prefix = asn1c_prefix();
    if(!prefix) prefix = "";

    /* group the IR nodes per module package (mirror go_flat_emit's route) */
    int n = go_flat_ir_n_types();
    char **mods = NULL;
    int n_mods = 0, cap_mods = 0;
    for(int i = 0; i < n; i++) {
        void *t = go_flat_ir_type(i);
        const char *mod = go_flat_ir_module(t);
        if(!mod || !*mod) continue;
        int seen = 0;
        for(int j = 0; j < n_mods; j++)
            if(strcmp(mods[j], mod) == 0) { seen = 1; break; }
        if(seen) continue;
        if(n_mods + 1 > cap_mods) {
            cap_mods = cap_mods ? cap_mods * 2 : 8;
            mods = realloc(mods, (size_t)cap_mods * sizeof(char *));
            if(!mods) { conv_failed_set(); return -1; }
        }
        mods[n_mods++] = cstrdup(mod);
    }

    /* cspec dir */
    char *cspec = conv_path(go_outdir, "internal/cspec");
    if(conv_mkdir_p(cspec) < 0) { free(cspec); return -1; }

    /* 0. the c/ dir's rt includes (<go_outdir>/c/rt/), ALL from the
     * embedded blobs — the <P><pkg>_flat.h headers go_flat_emit wrote under
     * c/ include "rt/types.h", so the conv package's include path resolves
     * self-contained (the external rt module stays byte-identical to this
     * copy; any drift is directly diffable). */
    {
        char *crtdir = conv_path(go_outdir, "c/rt");
        if(conv_mkdir_p(crtdir) < 0) { free(crtdir); return -1; }
        static const char *rt_files0[] = {
            "arena.h", "err.h", "types.h", "arena.c", "err.c",
        };
        for(size_t i = 0; i < sizeof rt_files0 / sizeof rt_files0[0]; i++) {
            if(conv_copy_rt_file(crtdir, rt_files0[i]) < 0) {
                free(crtdir);
                return -1;
            }
        }
        free(crtdir);
    }

    /* 0b. the flat headers under <go_outdir>/c/ into cspec/ (their includers
     * — the conv .c files — sit in THIS dir; cgo's CFLAGS carries only
     * -I${SRCDIR}, so the flat headers must be beside the conv files or
     * nothing resolves) */
    {
        char *fdir = conv_path(go_outdir, "c");
        conv_copy_flat_headers(fdir, cspec);
        free(fdir);
    }

    /* 1. the asn1c C copy from ASN1C_DESTDIR (prefixed files only) */
    {
        const char *destdir = go_dest_dir();
        if(destdir && *destdir) {
            if(conv_copy_prefixed_files(destdir, cspec) < 0)
                return -1;
        } else {
            fprintf(stderr,
                    "asn1cgo: conv: no C output directory (-D / "
                    "ASN1C_DESTDIR) — cannot populate internal/cspec\n");
            return -1;
        }
    }

    /* 2. per-package <P><pkg>_conv.c: every package-scoped node's converter
     * pair + this package's PDUs' entry points, in IR walk order. */
    int rc = 0;
    for(int mi = 0; mi < n_mods && rc == 0; mi++) {
        char *pkg = conv_module_pkg(mods[mi]);
        char *cname = cfmt("%s%s_conv.c", prefix, pkg);
        char *cpath = conv_path(cspec, cname);
        char *s = cfmt("/* Generated by asn1cgo — do not edit. */\n");
        /* includes: the rt headers (this cspec's rt/ copy), the asn1c tree
         * headers of every type this package's converters touch (the asn_DEF
         * symbols + tree typedefs), then the flat header. The tree-include
         * set: this package's own nodes' headers + every resolved ref/nested/
         * seqof-elem target's header (foreign packages included; quoted, one
         * per distinct file, walk order), mirroring the frozen units' include
         * discipline. */
        s = ca(s, "#include \"rt/arena.h\"\n#include \"rt/err.h\"\n#include \"rt/types.h\"\n#include <stdlib.h>\n#include <string.h>\n");
        {
            char **incs = NULL;
            int n_incs = 0, cap_incs = 0;
            for(int i = 0; i < n; i++) {
                void *t = go_flat_ir_type(i);
                const char *mod = go_flat_ir_module(t);
                if(!mod || strcmp(mod, mods[mi]) != 0) continue;
                /* every header this node's converter references: the node
                 * itself (asn_DEF_<X> in seqof loops/tree types) + each ref
                 * or seqof-elem target, recursing through nested wrapper
                 * members (a wrapper's own refs/seqof-elems are emitted
                 * inline in this node's converter). */
                char **want = calloc((size_t)n, sizeof(char *));
                int n_want = 0;
                if(!want) { conv_failed_set(); return -1; }
                const char *cid = go_flat_ir_cid(t);
                if(cid && *cid) {
                    char *b = conv_tree_base(t);
                    char *h = conv_find_header(b);
                    if(h) want[n_want++] = h;
                    free(b);
                }
                if(go_flat_ir_is_seqof(t) && !go_flat_ir_elem_prim(t)) {
                    void *r = go_conv_ir_ref_resolve(go_flat_ir_elem(t));
                    if(r) {
                        char *b = conv_tree_base(r);
                        if(b && *b) {
                            char *h = conv_find_header(b);
                            if(h) want[n_want++] = h;
                        }
                        free(b);
                    }
                }
                int nm2 = go_flat_ir_members(t);
                for(int k = 0; k < nm2; k++) {
                    void *m2 = go_flat_ir_member(t, k);
                    if(go_flat_ir_member_is_ref(m2)) {
                        void *r = go_conv_ir_ref_resolve(go_flat_ir_member_ref(m2));
                        if(r) {
                            char *b = conv_tree_base(r);
                            if(b && *b) {
                            char *h = conv_find_header(b);
                            if(h) want[n_want++] = h;
                        }
                            free(b);
                        }
                    } else if(go_flat_ir_member_is_nested(m2)) {
                        int nix2 = go_flat_ir_member_nested_ix(m2);
                        void *nt = (nix2 >= 0 && nix2 < n) ? go_flat_ir_type(nix2) : NULL;
                        if(!nt) continue;
                        if(go_flat_ir_is_seqof(nt)) {
                            if(!go_flat_ir_elem_prim(nt)) {
                                void *r = go_conv_ir_ref_resolve(go_flat_ir_elem(nt));
                                if(r) {
                                    char *b = conv_tree_base(r);
                                    if(b && *b) {
                            char *h = conv_find_header(b);
                            if(h) want[n_want++] = h;
                        }
                                    free(b);
                                }
                            }
                        } else {
                            /* wrapper node: its own member refs + nested
                             * seqof elems (2 levels cover the walk's mint
                             * depth: value-union alts and the inline-CHOICE
                             * under a wrapper). */
                            int wn2 = go_flat_ir_members(nt);
                            for(int k2 = 0; k2 < wn2; k2++) {
                                void *m3 = go_flat_ir_member(nt, k2);
                                if(go_flat_ir_member_is_ref(m3)) {
                                    void *r = go_conv_ir_ref_resolve(go_flat_ir_member_ref(m3));
                                    if(r) {
                                        char *b = conv_tree_base(r);
                                        if(b && *b) {
                            char *h = conv_find_header(b);
                            if(h) want[n_want++] = h;
                        }
                                        free(b);
                                    }
                                } else if(go_flat_ir_member_is_nested(m3)) {
                                    int nix3 = go_flat_ir_member_nested_ix(m3);
                                    void *nt3 = (nix3 >= 0 && nix3 < n) ? go_flat_ir_type(nix3) : NULL;
                                    if(nt3 && go_flat_ir_is_seqof(nt3)
                                       && !go_flat_ir_elem_prim(nt3)) {
                                        void *r = go_conv_ir_ref_resolve(go_flat_ir_elem(nt3));
                                        if(r) {
                                            char *b = conv_tree_base(r);
                                            if(b && *b) {
                            char *h = conv_find_header(b);
                            if(h) want[n_want++] = h;
                        }
                                            free(b);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for(int w = 0; w < n_want; w++) {
                    int seen = 0;
                    for(int q = 0; q < n_incs; q++)
                        if(strcmp(incs[q], want[w]) == 0) { seen = 1; break; }
                    if(seen) { free(want[w]); continue; }
                    /* include only headers the C backend actually wrote:
                     * an inline/nested construct has NO own header (the .h
                     * nests it under its parent) — probe ASN1C_DESTDIR. */
                    {
                        const char *dd = go_dest_dir();
                        if(dd && *dd) {
                            char *probe = conv_path(dd, want[w]);
                            FILE *pf = fopen(probe, "r");
                            free(probe);
                            if(!pf) { free(want[w]); continue; }
                            fclose(pf);
                        }
                    }
                    if(n_incs + 1 > cap_incs) {
                        cap_incs = cap_incs ? cap_incs * 2 : 32;
                        incs = realloc(incs, (size_t)cap_incs * sizeof(char *));
                        if(!incs) { conv_failed_set(); return -1; }
                    }
                    incs[n_incs++] = want[w];
                }
                free(want);
            }
            for(int q = 0; q < n_incs; q++) {
                char *inc = cfmt("#include \"%s\"\n", incs[q]);
                s = ca(s, inc);
                free(inc); free(incs[q]);
            }
            free(incs);
        }
        {
            /* every OTHER package's flat header (the package flat headers
             * pull each other for cross-package members — the flat .h's own
             * include list; the conv file sees one closure). */
            for(int mj = 0; mj < n_mods; mj++) {
                if(mj == mi) continue;
                char *mp = conv_module_pkg(mods[mj]);
                char *fh = cfmt("%s%s_flat.h", prefix, mp);
                free(mp);
                char *fp = conv_path(cspec, fh);
                char *fdir = conv_path(go_outdir, "c");
                char *fpath = conv_path(fdir, fh);
                FILE *ff = fopen(fpath, "r");
                if(ff) {
                    fclose(ff);
                    char *inc = cfmt("#include \"%s\"\n", fh);
                    s = ca(s, inc);
                    free(inc);
                }
                free(fh); free(fp); free(fdir); free(fpath);
            }
            char *fh = cfmt("%s%s_flat.h", prefix, pkg);
            char *inc = cfmt("#include \"%s\"\n", fh);
            s = ca(s, inc);
            free(fh); free(inc);
        }
        s = ca(s, "#include \"asn_application.h\"\n#include \"asn_internal.h\"\n\n");
        /* the per-spec file carries the asn1cgo_buf TYPEDEF only
         * (the shared asn1cgo_buf_free definition lives in asn1cgo-rt). */
        s = ca(s, "typedef struct { uint8_t *buf; size_t len; } asn1cgo_buf;\n\n");
        /* OBJECT IDENTIFIER / RELATIVE-OID: the arc <-> contents-octets
         * helpers the converters call (only when the walk classified one,
         * so every other tree is unchanged). The Flat bytes record holds the
         * arcs, one little-endian uint32 per arc. */
        size_t oid_at = 0;
        int oid_hdrs = (go_string_hdr_mask() & (1u << 15)) != 0;
        if(oid_hdrs) oid_at = strlen(s);

        /* forward decls: every package-scoped converter pair (a
         * nested_only node has no own typedef/converter — its body rides
         * the parent's converter through the inline-wrapper arms). */
        /* inline element types (the anonymous element of a SEQUENCE OF)
         * have no `<base>_t` typedef in the asn1c tree: alias it to the
         * C type the tree really uses, so every converter below spells
         * the element like any other node. */
        {
            int any = 0;
            for(int i = 0; i < n; i++) {
                void *t = go_flat_ir_type(i);
                const char *mod = go_flat_ir_module(t);
                if(!mod || strcmp(mod, mods[mi]) != 0) continue;
                if(!go_flat_ir_inline_elem(t)) continue;
                char *base = conv_tree_base(t);
                if(!base || !*base) { free(base); continue; }
                const char *ct = go_flat_ir_tree_ctype(t);
                if(!any) { s = ca(s, "/* ---- inline element tree types ---- */\n"); any = 1; }
                if(ct && strcmp(ct, "struct") == 0) {
                    /* the C type has a struct tag only (an inline CHOICE alt) */
                    char *_cf = cfmt("typedef struct %s %s_t;\n", base, base); s = ca(s, _cf); free(_cf);
                } else {
                    char *_cf = cfmt("typedef %s %s_t;\n", ct && *ct ? ct : base, base); s = ca(s, _cf); free(_cf);
                }
                free(base);
            }
            if(any) s = ca(s, "\n");
        }
        s = ca(s, "/* ---- converter forward decls ---- */\n");
        for(int i = 0; i < n; i++) {
            void *t = go_flat_ir_type(i);
            const char *mod = go_flat_ir_module(t);
            if(!mod || strcmp(mod, mods[mi]) != 0) continue;
            if(go_flat_ir_is_nested_only(t)) continue;
            char *base = conv_tree_base(t);
            if(!base || !*base) continue;
            char *fname = conv_flat_name(t);
            { char *_cf = cfmt("int %s_to_tree(const %s *, %s_t *, asn1cgo_err *);\n", base, fname, base); s = ca(s, _cf); free(_cf); }
            { char *_cf = cfmt("int %s_from_tree(asn1cgo_arena *, const %s_t *, %s *, asn1cgo_err *);\n", base, base, fname); s = ca(s, _cf); free(_cf); }
            free(base); free(fname);
        }
        /* foreign-package converter pairs this package's bodies call (their
         * headers are included above; a cross-package call without a decl
         * is an implicit-declaration error). */
        for(int i = 0; i < n; i++) {
            void *t = go_flat_ir_type(i);
            const char *mod = go_flat_ir_module(t);
            if(!mod || strcmp(mod, mods[mi]) == 0) continue;
            if(go_flat_ir_is_nested_only(t)) continue;
            char *base = conv_tree_base(t);
            if(!base || !*base) { free(base); continue; }
            char *h = conv_find_header(base);
            if(!h) { free(base); free(h); continue; }
            /* only when the package includes that header (it was probed
             * into incs) — match by header name */
            int hit = 0;
            FILE *probe = NULL;
            char *pp = NULL;
            (void)hit; (void)probe; (void)pp;
            /* emit only when this package actually INCLUDES that header
             * (the include line is already in s — the flat/tree types are
             * then typed here; a decl without the include references
             * unknown types). */
            char *inc_line = cfmt("#include \"%s\"\n", h);
            if(strstr(s, inc_line)) {
                { char *_cf = cfmt("int %s_to_tree(const %s_flat *, %s_t *, asn1cgo_err *);\n", base, base, base); s = ca(s, _cf); free(_cf); }
                { char *_cf = cfmt("int %s_from_tree(asn1cgo_arena *, const %s_t *, %s_flat *, asn1cgo_err *);\n", base, base, base); s = ca(s, _cf); free(_cf); }
            }
            free(inc_line);
            free(h); free(base);
        }
        s = ca(s, "\n");

        /* bodies */
        for(int i = 0; i < n; i++) {
            void *t = go_flat_ir_type(i);
            const char *mod = go_flat_ir_module(t);
            if(!mod || strcmp(mod, mods[mi]) != 0) continue;
            if(go_flat_ir_is_nested_only(t)) continue;   /* rides the parent */
            char *base = conv_tree_base(t);
            if(!base || !*base) continue;   /* anonymous nested node */
            char *fname = conv_flat_name(t);   /* the Flat type (bare for
                                                * container clones) */
            char *label = conv_type_label(t);  /* td->name display
                                                * label (falls back to base
                                                * when unrecorded) */
            char *tobody = node_to_body_pub(t);
            char *frombody = conv_from_node(t, 0);
            { char *_cf = cfmt("int\n%s_to_tree(const %s *in, %s_t *out, asn1cgo_err *err) {\n    if (!in || !out) return asn1cgo_fail(err, ASN1CGO_E_ARG, \"%s\", NULL, NULL);\n    /* out assumed zeroed (calloc) by caller */\n", base, fname, base, label); s = ca(s, _cf); free(_cf); }
            s = ca(s, tobody);
            s = ca(s, "    return 0;\n}\n\n");
            { char *_cf = cfmt("int\n%s_from_tree(asn1cgo_arena *ar, const %s_t *in, %s *out, asn1cgo_err *err) {\n    if (!ar || !in || !out) return asn1cgo_fail(err, ASN1CGO_E_ARG, \"%s\", NULL, NULL);\n", base, base, fname, label); s = ca(s, _cf); free(_cf); }
            s = ca(s, frombody);
            s = ca(s, "    return 0;\n}\n\n");
            free(base); free(fname); free(label); free(tobody); free(frombody);
        }

        /* this package's PDU entry points */
        int any_pdu = 0;
        for(int pi = 0; pi < g_conv_n_pdus; pi++) {
            void *rt = go_conv_ir_ref_resolve(g_conv_pdus[pi].cid);
            const char *pmod = rt ? go_flat_ir_module(rt) : NULL;
            if(!pmod || strcmp(pmod, mods[mi]) != 0) continue;
            char *tb = conv_tree_base(rt);
            if(!tb || !*tb) continue;
            /* fb = the Flat BASE: the IR flat name (bare for container
             * clones) minus _flat; entry_* compose the suffix. */
            char *fbn = conv_flat_name(rt);
            char *fb = fbn ? cstrdup(fbn) : cstrdup(tb);
            if(fb && *fb) {
                size_t fl = strlen(fb);
                if(fl > 5 && strcmp(fb + fl - 5, "_flat") == 0)
                    fb[fl - 5] = '\0';
            }
            free(fbn);
            { char *eb = entry_encode(rt, fb, tb); s = ca(s, eb); free(eb); }
            { char *db = entry_decode(rt, fb, tb); s = ca(s, db); free(db); }
            { char *xb = entry_xer(rt, fb, tb); s = ca(s, xb); free(xb); }
            free(tb); free(fb);
            any_pdu = 1;
        }
        (void)any_pdu;

        /* the OID helpers go into this file only when a converter in it
         * calls them (they are static: an unused one warns) */
        if(oid_hdrs && (strstr(s + oid_at, "asn1cgo_oid_set(")
                        || strstr(s + oid_at, "asn1cgo_oid_get("))) {
            size_t pl = strlen(GO_OID_PREAMBLE), sl = strlen(s);
            char *ns = malloc(sl + pl + 1);
            if(!ns) { rc = -1; }
            else {
                memcpy(ns, s, oid_at);
                memcpy(ns + oid_at, GO_OID_PREAMBLE, pl);
                memcpy(ns + oid_at + pl, s + oid_at, sl - oid_at + 1);
                free(s);
                s = ns;
            }
        }
        if(rc == 0 && conv_fwrite_all(cpath, s) < 0) rc = -1;
        free(s); free(cname); free(cpath); free(pkg);
    }
    if(rc < 0) return -1;

    /* 3. cgo.go + the rt header-only copy */
    {
        char *p = conv_path(cspec, "cgo.go");
        {
            char *base = cspec_cgo_go_text();
            const char *rtm = (go_rt_module && *go_rt_module)
                                  ? go_rt_module : "asn1cgo-rt";
            char *imp = cfmt(
                "// pull the shared runtime objects into every link that includes\n"
                "// this package (cross-package C symbols resolve through Go static\n"
                "// linking).\n"
                "import _ \"%s/rt\"\n", rtm);
            char *txt = base;
            if(go_skel_dir())
                txt = ca(txt, imp);
            if(conv_fwrite_all(p, txt) < 0) { free(txt); free(p); return -1; }
            free(txt); free(imp);
        }
        free(p);
    }
    {
        char *rtdir = conv_path(cspec, "rt");
        if(conv_mkdir_p(rtdir) < 0) return -1;
        /* header-only rt copy, byte-identical to the single rt source:
         * copied from libasn1compiler_go/rt/go/rt. */
        static const char *rt_files2[] = {
            "arena.h", "err.h", "types.h",
        };
        for(size_t i = 0; i < sizeof rt_files2 / sizeof rt_files2[0]; i++) {
            if(conv_copy_rt_file(rtdir, rt_files2[i]) < 0) {
                free(rtdir);
                return -1;
            }
        }
        /* the asn1c-runtime headers the spec .h include, from
         * the fork skeletons, BESIDE the rt trio — the package's own
         * copies; no include path may cross the module boundary. */
        for(size_t i = 0;
            i < sizeof skel_header_files / sizeof skel_header_files[0];
            i++) {
            if(conv_copy_skel_header(rtdir, skel_header_files[i]) < 0) {
                free(rtdir);
                return -1;
            }
        }
        /* the headers of the other restricted string / time types, only when
         * the walk classified one (a PrintableString-only tree is unchanged) */
        {
            unsigned used = go_string_hdr_mask();
            for(int i = 0; used >> i; i++) {
                const char *hn = go_string_hdr_name(i);
                if(!(used >> i & 1u) || !hn) continue;
                if(conv_copy_skel_header(rtdir, hn) < 0) {
                    free(rtdir);
                    return -1;
                }
            }
        }
        free(rtdir);
    }

    /* 4. the asn1cgo-rt module skeleton: NOT EMITTED (single-source rt
     * move). The build supplies the module via go.work/replace from
     * <fork>/libasn1compiler_go/rt/go; the require below carries the
     * version. Nothing to do here — the block is kept as a numbered
     * placeholder so the step numbering below stays stable. */

    /* 5. go.mod require/replace + go.work when absent */
    {
        char *gm = conv_path(go_outdir, "go.mod");
        FILE *f = fopen(gm, "r");
        long sz = 0;
        char *txt = NULL;
        if(f) {
            fseek(f, 0, SEEK_END);
            sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            txt = malloc((size_t)sz + 1);
            if(txt && fread(txt, 1, (size_t)sz, f) == (size_t)sz)
                txt[sz] = '\0';
            else { free(txt); txt = NULL; }
            fclose(f);
        }
        if(txt) {
            /* Fetch mode (default): `require <rt> <version>` only; the
             * user runs `go mod tidy` once to record the go.sum hash.
             * Local mode (ASN1CGO_RT_LOCAL): plus `replace <rt> => <dir>`. */
            if(!strstr(txt, ASN1CGO_RT_MODULE)) {
                char *rel = NULL, *wk = NULL;
                if(rt_local_paths(go_outdir, &rel, &wk) < 0) {
                    conv_failed_set();
                } else {
                    FILE *o = fopen(gm, "w");
                    if(!o) {
                        fprintf(stderr, "asn1cgo: conv: cannot write '%s': %s\n",
                                gm, strerror(errno));
                        conv_failed_set();
                    } else {
                        int ok = fprintf(o, "%s", txt) >= 0
                            && fprintf(o, "\nrequire %s %s\n", ASN1CGO_RT_MODULE,
                                       ASN1CGO_RT_VERSION) >= 0;
                        if(ok && rel)
                            ok = fprintf(o, "replace %s => %s\n",
                                         ASN1CGO_RT_MODULE, rel) >= 0;
                        if(fclose(o) != 0) ok = 0;
                        if(!ok) {
                            fprintf(stderr, "asn1cgo: conv: write failed: %s: %s\n",
                                    gm, strerror(errno));
                            conv_failed_set();
                        }
                    }
                }
                free(rel); free(wk);
            }
            free(txt);
        } else {
            fprintf(stderr, "asn1cgo: conv: go.mod not found under '%s' "
                    "(go_emit_files writes it first)\n", go_outdir);
            conv_failed_set();
        }
        free(gm);
    }
    /* go.work (parent of the -Fgo dir) is NOT touched here: go_generate
     * updates it via go_workfile_plan/go_workfile_write only after the whole
     * tree was staged and published, so a failed run never modifies it. */

    for(int j = 0; j < n_mods; j++) free(mods[j]);
    free(mods);
    free(cspec);
    if(g_conv_failed_) return -1;
    return 0;
}

/* ---------------------------------------------------------------------------
 * go.work maintenance, split in two so a failed run never modifies it:
 *   go_workfile_plan  — read <parent>/go.work, compute the new text (pure);
 *                       *new_text = NULL when nothing needs writing.
 *   go_workfile_write — replace the file atomically (temp file + rename).
 * Semantics (unchanged from the in-place version): only when the fork
 * skeleton dir is known and go_outdir has a parent component; absent/empty
 * file -> minted with ./asn1cgo-rt and ./<base>; otherwise the `use (...)`
 * block is re-emitted keeping ./asn1cgo-rt and every entry whose dir still
 * exists (dead ones pruned), each entry once, and ./<base> ensured.
 * ------------------------------------------------------------------------- */
int go_workfile_plan(const char *go_outdir, char **new_text);
int go_workfile_write(const char *go_outdir, const char *new_text);
int go_workfile_lock(const char *go_outdir, int *fd);
void go_workfile_unlock(int fd);

static char *
workfile_parent(const char *go_outdir) {
    const char *slash = strrchr(go_outdir, '/');
    if(!slash || slash == go_outdir) return NULL;
    char *p = malloc((size_t)(slash - go_outdir) + 1);
    if(!p) return NULL;
    memcpy(p, go_outdir, (size_t)(slash - go_outdir));
    p[slash - go_outdir] = '\0';
    return p;
}

/* Serialise the go.work read-modify-write (and the tree publish) between
 * concurrent generators sharing a parent dir. Exclusive flock(2) on
 * <parent>/.go.work.lock — a separate file, NOT go.work itself, because the
 * atomic rename in go_workfile_write replaces go.work's inode. The lock file
 * is created 0666&~umask if absent and deliberately left in place afterwards.
 * Taken only when go_workfile_plan would touch go.work (same conditions:
 * skeleton dir known and go_outdir has a parent component); otherwise
 * *fd = -1 and nothing is locked. Returns 0 ok, -1 (message printed) on
 * failure. NOTE: flock is advisory and may be a no-op or unreliable on some
 * network filesystems (e.g. old NFS); it only protects cooperating
 * asn1c processes. */
int
go_workfile_lock(const char *go_outdir, int *fd) {
    *fd = -1;
    if(!go_skel_dir()) return 0;
    char *parent = workfile_parent(go_outdir);
    if(!parent) return 0;
    char *lk = conv_path(parent, ".go.work.lock");
    int f = open(lk, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if(f < 0) {
        fprintf(stderr, "asn1cgo: cannot open lock file '%s': %s\n", lk,
                strerror(errno));
    } else {
        int r;
        while((r = flock(f, LOCK_EX)) != 0 && errno == EINTR) { }
        if(r != 0) {
            fprintf(stderr, "asn1cgo: cannot lock '%s': %s\n", lk,
                    strerror(errno));
            close(f);
            f = -1;
        }
    }
    free(lk); free(parent);
    if(f < 0) return -1;
    *fd = f;
    return 0;
}

void
go_workfile_unlock(int fd) {
    if(fd >= 0) close(fd);       /* closing drops the flock */
}

int
go_workfile_plan(const char *go_outdir, char **new_text) {
    *new_text = NULL;
    if(!go_skel_dir()) return 0;
    char *parent = workfile_parent(go_outdir);
    if(!parent) return 0;
    const char *base = strrchr(go_outdir, '/') + 1;
    char *gw = conv_path(parent, "go.work");
    int rc = 0;
    char *cur = NULL;
    size_t n = 0;

    FILE *f = fopen(gw, "r");
    if(f) {
        size_t cap = 0;
        int c2;
        while((c2 = fgetc(f)) != EOF) {
            if(n + 2 > cap) {
                char *nc = realloc(cur, cap ? cap * 2 : 256);
                if(!nc) { free(cur); cur = NULL; n = 0; rc = -1; break; }
                cur = nc;
                cap = cap ? cap * 2 : 256;
            }
            cur[n++] = (char)c2;
        }
        if(rc == 0 && ferror(f)) {
            fprintf(stderr, "asn1cgo: cannot read '%s': %s\n", gw,
                    strerror(errno));
            rc = -1;
        } else if(rc < 0) {
            fprintf(stderr, "asn1cgo: out of memory reading '%s'\n", gw);
        }
        if(cur) cur[n] = '\0';
        fclose(f);
    } else if(errno != ENOENT) {
        fprintf(stderr, "asn1cgo: cannot read '%s': %s\n", gw,
                strerror(errno));
        rc = -1;
    }
    if(rc < 0) { free(cur); free(gw); free(parent); return -1; }

    if(n == 0) {                       /* absent or empty: mint */
        char *rel = NULL, *wk = NULL;
        if(rt_local_paths(go_outdir, &rel, &wk) < 0) rc = -1;
        else if(wk)
            *new_text = cfmt("go " GO_MOD_GO_VERSION
                             "\n\nuse (\n\t%s\n\t./%s\n)\n", wk, base);
        else
            *new_text = cfmt("go " GO_MOD_GO_VERSION
                             "\n\nuse (\n\t./%s\n)\n", base);
        free(rel); free(wk);
    } else {
        char *rp = strrchr(cur, ')');
        char *ub = strstr(cur, "use (");
        if(rp && ub && ub < rp) {
            const char *head_end = strchr(ub + 5, '\n');
            if(!head_end || head_end > (const char *)rp)
                head_end = (const char *)rp;
            size_t off = (size_t)(head_end - cur) + 1;
            char *out = NULL;
            size_t on = 0, ocap = 0;
#define GW_APPEND(p, len) do { \
                size_t l__ = (len); \
                if(on + l__ + 1 > ocap) { \
                    size_t nc__ = (on + l__ + 1) * 2; \
                    char *r__ = realloc(out, nc__); \
                    if(!r__) { rc = -1; break; } \
                    out = r__; ocap = nc__; \
                } \
                memcpy(out + on, (p), l__); on += l__; out[on] = '\0'; \
            } while(0)
            GW_APPEND(cur, off);
            char *base_path = cfmt("./%s", base);
            char **seen = NULL;
            int n_seen = 0;
            const char *l = ub + 5;
            while(rc == 0 && l < (const char *)rp) {
                const char *eol2 = strchr(l, '\n');
                if(!eol2 || eol2 > (const char *)rp) eol2 = (const char *)rp;
                if(eol2 > l + 1 && l[0] == '\t' && (l[1] == '.' || l[1] == '/')) {
                    size_t el0 = (size_t)(eol2 - l) - 1;
                    char *entry = malloc(el0 + 1);
                    if(!entry) { rc = -1; break; }
                    memcpy(entry, l + 1, el0);
                    entry[el0] = 0;
                    int keep;
                    {
                        /* keep an entry only while its dir exists (a stale
                         * ./asn1cgo-rt from the old layout survives as long
                         * as the dir does). Absolute entries: as-is. */
                        char *dirp = entry[0] == '/' ? strdup(entry)
                                                     : cfmt("%s/%s", parent, entry + 2);
                        struct stat st3;
                        keep = dirp && stat(dirp, &st3) == 0;
                        free(dirp);
                    }
                    for(int i = 0; keep && i < n_seen; i++)
                        if(strcmp(seen[i], entry) == 0) keep = 0;   /* dedupe */
                    if(keep) {
                        char **ns = realloc(seen, (size_t)(n_seen + 1) * sizeof *seen);
                        if(!ns) { free(entry); rc = -1; break; }
                        seen = ns;
                        seen[n_seen++] = entry;     /* owned, freed below */
                        GW_APPEND(l, (size_t)(eol2 - l));
                        GW_APPEND("\n", 1);
                    } else {
                        free(entry);
                    }
                }
                if(eol2 >= (const char *)rp) break;
                l = eol2 + 1;
            }
            if(rc == 0) {
                int have_base = 0;
                char *lrel = NULL, *lwk = NULL;
                if(rt_local_paths(go_outdir, &lrel, &lwk) < 0) rc = -1;
                for(int i = 0; i < n_seen; i++)
                    if(strcmp(seen[i], base_path) == 0) have_base = 1;
                if(rc == 0 && lwk) {
                    int have = 0;
                    for(int i = 0; i < n_seen; i++)
                        if(strcmp(seen[i], lwk) == 0) have = 1;
                    if(!have) {
                        char *ln = cfmt("\t%s\n", lwk);
                        GW_APPEND(ln, strlen(ln));
                        free(ln);
                    }
                }
                free(lrel); free(lwk);
                if(!have_base) {
                    char *ln = cfmt("\t./%s\n", base);
                    GW_APPEND(ln, strlen(ln));
                    free(ln);
                }
                GW_APPEND(rp, strlen(rp));
            }
            for(int i = 0; i < n_seen; i++) free(seen[i]);
            free(seen);
            free(base_path);
#undef GW_APPEND
            if(rc < 0) {
                fprintf(stderr, "asn1cgo: out of memory updating '%s'\n", gw);
                free(out);
            } else if(strcmp(out, cur) != 0) {
                *new_text = out;       /* changed */
            } else {
                free(out);             /* identical: leave the file alone */
            }
        }
        /* no `use (` block (e.g. single-line form): left untouched, as before */
    }
    free(cur); free(gw); free(parent);
    return rc;
}

int
go_workfile_write(const char *go_outdir, const char *new_text) {
    char *parent = workfile_parent(go_outdir);
    if(!parent) return 0;
    char *gw = conv_path(parent, "go.work");
    char *tmp = conv_path(parent, ".go.work.asn1cgo-tmp-XXXXXX");
    int rc = -1;
    struct stat st;
    mode_t mode;
    if(stat(gw, &st) == 0) {
        mode = st.st_mode & 0777;
    } else {
        mode_t um = umask(0);
        umask(um);
        mode = 0666 & ~um;
    }
    int fd = mkstemp(tmp);
    if(fd < 0) {
        fprintf(stderr, "asn1cgo: cannot create temp file: %s: %s\n", tmp,
                strerror(errno));
    } else {
        size_t len = strlen(new_text);
        FILE *o = fdopen(fd, "w");
        if(!o) {
            fprintf(stderr, "asn1cgo: cannot write '%s': %s\n", tmp,
                    strerror(errno));
            close(fd);
            unlink(tmp);
        } else {
            int ok = fwrite(new_text, 1, len, o) == len;
            if(fflush(o) != 0) ok = 0;
            if(ok && fchmod(fd, mode) != 0) ok = 0;
            if(fclose(o) != 0) ok = 0;
            if(!ok) {
                fprintf(stderr, "asn1cgo: write failed: %s: %s\n", tmp,
                        strerror(errno));
                unlink(tmp);
            } else if(rename(tmp, gw) != 0) {
                fprintf(stderr, "asn1cgo: cannot rename %s -> %s: %s\n", tmp,
                        gw, strerror(errno));
                unlink(tmp);
            } else {
                rc = 0;
            }
        }
    }
    free(tmp); free(gw); free(parent);
    return rc;
}
