/*
 * go_backend.c — entry point of the Go backend.
 *
 * The driver (asn1c/asn1c.c) dispatches to asn1cgo_generate() as an
 * in-process sibling of the C backend, on the same parsed and fixed asn1p_t
 * AST, after the C backend (asn1_compile) has run. The driver maps a non-zero
 * return here to a non-zero process exit.
 *
 * The Go backend runs the classification walk (go_walk_asts) as a support
 * gate, then — when `-Fgo=<dir>` is in effect — resolves every Go name and
 * emits the package skeleton (go_generate in go_names.c). A clean walk with an
 * empty go_outdir returns 0 silently (name/dump paths may still run inside
 * go_generate via ASN1CGO_DUMP_NAMES, but no files are written). Any
 * classification failure, name collision, or invalid go_outdir returns -1; the
 * driver maps a non-zero return to EX_SOFTWARE (exit 70).
 */
#include <stdio.h>             /* size_t/NULL transitively (asn1 headers need them) */
#include <asn1parser.h>         /* asn1p_t */
#include <asn1compiler.h>       /* enum asn1c_flags */
#include "go_constructs.h"      /* go_walk_asts */

/*
 * The Go backend splits into two passes, both run after the support gate
 * (go_walk_asts):
 *   - go_generate  (go_names.c): resolve every Go name, write the name dump
 *     (ASN1CGO_DUMP_NAMES), then call go_emit_files on a clean pass. This is
 *     the entry that turns `-Fgo=<dir>` into output on disk, and the entry that
 *     serves a dump-only run.
 * go_emit_files is, in turn, declared extern inside go_names.c (flat surface,
 * no header churn — same style as the driver's own asn1cgo_generate extern).
 */
extern int go_generate(asn1p_t *, const char *, enum asn1c_flags);

/*
 * Declared extern in asn1c/asn1c.c (the driver). asn1compiler.h is not modified
 * to declare this, so this TU carries its own forward declaration; it matches
 * the driver declaration exactly.
 */
extern int asn1cgo_generate(asn1p_t *asn, const char *go_outdir,
                            enum asn1c_flags flags);

int
asn1cgo_generate(asn1p_t *asn, const char *go_outdir, enum asn1c_flags flags) {
    /* Support gate first: any off-table construct is a hard error before the
     * Go side touches the disk. */
    int rc = go_walk_asts(asn);
    if(rc) return -1;
    /* go_generate is the name pass: it resolves every Go name, writes the name
     * dump when ASN1CGO_DUMP_NAMES names a file, and writes the package skeleton
     * when go_outdir is non-empty. The driver dispatches here only when -Fgo is
     * in effect (go_outdir != NULL), so a name/dump run always carries a -Fgo
     * dir (the dump rides -Fgo; no driver-level env gate this step). */
    if(go_outdir)
        if(go_generate(asn, go_outdir, flags) != 0)
            return -1;          /* -> driver EX_SOFTWARE (70) */
    return 0;
}
