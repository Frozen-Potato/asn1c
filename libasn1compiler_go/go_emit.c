/*
 * go_emit.c — file/directory emission for the Go backend (package skeleton + leaf declarations).
 *
 * Writes the package skeleton (go.mod at the outdir root, one
 * <module_pkg>/types.go per ASN.1 module) AND the leaf-type
 * DECLARATIONS: every leaf type assignment's `type X <underlying>` line, the
 * BitString helper once per BIT-STRING-owning module, CHOICE/ENUM/value
 * const blocks (with the values the name pass recorded from asn1c's own AST
 * fields), each const re-stating its type — the comparison unit decl form. Struct
 * bodies, CHOICE alt pointer sets, flat structs, converters are the struct-body
 * stage.
 *
 * Layout (the output-root rule): go_outdir IS the module root. <go_outdir>/go.mod declares
 * `module <basename>` (the last path segment of go_outdir); one subdir per
 * module named by the module identifier lowercased with '-' -> '_'
 * (<module_pkg>), each holding types.go with `package <module_pkg>`.
 *
 * Emission is gated: go_emit_files is called only after the name pass is
 * clean, so a failed walk writes nothing (the diagnostic already went to
 * stderr and the driver returns EX_SOFTWARE). All output lands under the
 * fresh go_outdir; nothing is written into the C backend's -D directory.
 *
 * Leaf-decl text lives in go_types.c (go_types_emit_*): this file owns the
 * FILE lifecycle and the per-module walk order; go_types.c owns each line's
 * exact bytes.
 *
 * The name rows arrive PRE-SORTED in dump order (module, path, kind, goName
 * — the same qsort go_generate runs for the dump), so the per-module
 * declaration order is deterministic: a `type`/`inline`/`spec-key` row
 * prints its leaf line, then its const block (the enum-const/choice-const/
 * value-const rows that follow it in sort order share its goType). Const
 * rows group by their owning type via the goType field, not adjacency, so
 * sort order can interleave kinds freely.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700       /* nftw, mkdtemp */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>              /* tolower */
#include <errno.h>
#include <sys/stat.h>           /* mkdir(2) */
#include <sys/types.h>
#include <ftw.h>
#include <unistd.h>

#include <asn1parser.h>         /* asn1p_t, asn1p_module_t */
#include <asn1p_list.h>         /* TQ_FOR */

#include "go_constructs.h"      /* go_types_emit_* */
#include "go_conv.h"           /* GO_GENERATED_BANNER */

/* Self-prototype: go_emit_files is called by go_names.c (extern there) and
 * defined here; the explicit proto silences -Wmissing-prototypes. */
int go_emit_files(asn1p_t *asn, const char *go_outdir);

/* Leaf-declaration interface with go_names.c: the per-module declaration writer.
 * Defined in go_names.c (which owns the name-row struct and the walk data —
 * no struct layout is mirrored across TUs); go_emit calls it once per module
 * while that module's types.go is open, immediately after the package clause.
 * go_emit_module_imports writes the same module's import block (returns the
 * number of imports; 0 = none, no block is written). Both return -1 on write
 * error. */
extern int go_emit_module_imports(FILE *out, const char *module);
extern int go_emit_module_decls(FILE *out, const char *module);

/* last path segment of go_outdir (the module basename). Returns a pointer INTO
 * `path` (borrowed) or NULL if path is empty. */
static const char *
basename_of(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Recursive mkdir. EEXIST on a non-empty final is OK only if it is a directory;
 * any other errno fails. Returns 0 on success, -1 with a diagnostic. */
static int
mkpath(const char *path) {
    char buf[4096];
    size_t n = strlen(path);
    if(n == 0 || n >= sizeof buf) {
        fprintf(stderr, "asn1cgo: bad directory path (empty or too long): %s\n",
                path);
        return -1;
    }
    memcpy(buf, path, n + 1);

    for(size_t i = 1; i < n; i++) {
        if(buf[i] == '/') {
            buf[i] = '\0';
            if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
                fprintf(stderr, "asn1cgo: cannot create directory: %s: %s\n",
                        buf, strerror(errno));
                return -1;
            }
            buf[i] = '/';
        }
    }
    if(mkdir(buf, 0777) < 0 && errno != EEXIST) {
        fprintf(stderr, "asn1cgo: cannot create directory: %s: %s\n",
                buf, strerror(errno));
        return -1;
    }
    return 0;
}

/* module_pkg = module identifier lowercased, '-' -> '_'. malloc'd, never NULL. */
static char *
module_pkg(const char *module_name) {
    const char *s = module_name ? module_name : "_";
    char *out = malloc(strlen(s) + 1);
    if(!out) return strdup("");
    size_t j = 0;
    for(size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if(c == '-') out[j++] = '_';
        else out[j++] = (char)tolower(c);
    }
    out[j] = '\0';
    return out;
}

/* Join dir + '/' + leaf into a malloc'd path. */
static char *
join_path(const char *dir, const char *leaf) {
    size_t a = strlen(dir), b = strlen(leaf);
    char *p = malloc(a + 1 + b + 1);
    if(!p) return strdup("");
    memcpy(p, dir, a); p[a] = '/'; memcpy(p + a + 1, leaf, b); p[a + 1 + b] = 0;
    return p;
}

/* Write go.mod: `module <module-path>\n\ngo <ver>\n`, where the module path
 * is basename-only or <prefix>/<basename> per ASN1CGO_GO_MODULE_PREFIX (the
 * composed string is owned by go_names.c and live for the whole emit; the
 * basename_of fallback covers a caller outside the emit window). Returns 0
 * ok, -1 + diag. */
const char *go_names_module_path(void);
static int
write_go_mod(const char *outdir) {
    const char *mpath = go_names_module_path();
    if(!mpath || !*mpath) mpath = basename_of(outdir);
    char *path = join_path(outdir, "go.mod");
    FILE *f = fopen(path, "w");
    if(!f) {
        fprintf(stderr, "asn1cgo: cannot write '%s': %s\n",
                path, strerror(errno));
        free(path);
        return -1;
    }
    int ok = fprintf(f, "module %s\n\ngo %s\n", mpath, GO_MOD_GO_VERSION) >= 0;
    if(fclose(f) != 0) ok = 0;
    if(!ok) {
        fprintf(stderr, "asn1cgo: write failed: %s: %s\n",
                path, strerror(errno));
        free(path);
        return -1;
    }
    free(path);
    return 0;
}

/* Write <pkgdir>/types.go: the banner + package clause + the leaf
 * declarations (go_emit_module_decls, defined in go_names.c over the name
 * rows). Returns 0 ok. */
static int
write_types_go(const char *outdir, const char *pkg, const char *module) {
    char *pkgdir = join_path(outdir, pkg);
    if(mkpath(pkgdir) < 0) { free(pkgdir); return -1; }
    char *path = join_path(pkgdir, "types.go");
    FILE *f = fopen(path, "w");
    if(!f) {
        fprintf(stderr, "asn1cgo: cannot write '%s': %s\n",
                path, strerror(errno));
        free(path); free(pkgdir);
        return -1;
    }
    /* A package clause alone is a valid, empty Go package: builds, vets,
     * gofmts clean — every emitted file must stay gofmt-clean. Leaf-decl layout:
     * banner, package clause, blank line, (optional) import block, blank
     * line, declarations — the gofmt canon. The banner precedes the package
     * clause and never takes a blank line after itself when the module is
     * EMPTY (a trailing blank line would fail gofmt), so it is written as
     * part of the same first-line group. */
    if(fputs(GO_GENERATED_BANNER, f) < 0
       || fprintf(f, "package %s\n", pkg) < 0
       || go_emit_module_imports(f, module) < 0
       || go_emit_module_decls(f, module) < 0) {
        fprintf(stderr, "asn1cgo: write failed: %s: %s\n", path,
                errno ? strerror(errno) : "I/O error");
        fclose(f);
        free(path); free(pkgdir);
        return -1;
    }
    if(fclose(f) != 0) {
        fprintf(stderr, "asn1cgo: write failed: %s: %s\n", path,
                strerror(errno));
        free(path); free(pkgdir);
        return -1;
    }
    free(path); free(pkgdir);
    return 0;
}

/*
 * go_emit_files — write the package skeleton + leaf declarations under
 * go_outdir. The module set comes straight off the AST, in the same TQ_FOR
 * order the name pass uses (deterministic); each module's declarations come
 * from the name rows via go_emit_module_decls (go_names.c).
 *
 * go_outdir validity (basename rules) is enforced in go_names.c::go_generate
 * before this is reached; here we assume a well-formed path.
 *
 * Returns 0 on full success, -1 on any I/O error (caller maps to non-zero exit).
 */
int
go_emit_files(asn1p_t *asn, const char *go_outdir) {
    if(!go_outdir || !*go_outdir) return 0;

    if(mkpath(go_outdir) < 0) return -1;   /* the staging dir */
    if(write_go_mod(go_outdir) < 0) return -1;

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next) {
        /* Skip asn1c's auto-loaded standard-modules (asn1c.c:539 sets the tag):
         * the C backend emits no headers for them, and we mirror that — they
         * would otherwise mint spurious package dirs. */
        if(mod->_tags & MT_STANDARD_MODULE)
            continue;
        char *pkg = module_pkg(mod->ModuleName);
        if(write_types_go(go_outdir, pkg, mod->ModuleName) < 0) {
            free(pkg);
            return -1;
        }
        free(pkg);
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * All-or-nothing publication of the -Fgo tree.
 *
 * go_generate writes every stage into a staging directory created next to the
 * target (same parent => same filesystem => rename(2) is atomic):
 *
 *     <parent>/.<basename>.asn1cgo-tmp-XXXXXX
 *
 * and only after every stage succeeded swaps it in with go_outdir_publish.
 * On any failure go_outdir_discard removes the staging dir only; the target is
 * never touched before the swap. Recursive deletion is confined to directories
 * this code created itself (the staging dir, or the renamed-aside old tree);
 * rm_tree refuses any path whose last component lacks the ".asn1cgo-" marker.
 * ------------------------------------------------------------------------- */

int go_outdir_stage(const char *go_outdir, char **tmp_out);
int go_outdir_publish(const char *go_outdir, const char *tmp, char **old_out);
void go_outdir_rollback(const char *go_outdir, const char *tmp, char *old);
int go_outdir_commit(char *old);
void go_outdir_discard(const char *tmp);

static int
rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *ftw) {
    (void)sb; (void)flag; (void)ftw;
    return remove(p);                   /* FTW_PHYS: a symlink is unlinked, never followed */
}

/* Remove a directory tree that this module created. Returns 0 / -1 (diag). */
static int
rm_tree(const char *dir) {
    const char *base = basename_of(dir);
    if(!dir || !*dir || !base || base[0] != '.' || !strstr(base, ".asn1cgo-")) {
        fprintf(stderr, "asn1cgo: refusing to remove '%s': not a directory "
                "created by asn1cgo\n", dir ? dir : "(null)");
        return -1;
    }
    if(nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS) != 0) {
        fprintf(stderr, "asn1cgo: cannot remove directory tree: %s: %s\n",
                dir, strerror(errno));
        return -1;
    }
    return 0;
}

/* "<parent>/.<base>.asn1cgo-<kind>-XXXXXX" for go_outdir; malloc'd or NULL. */
static char *
sibling_template(const char *go_outdir, const char *kind) {
    const char *slash = strrchr(go_outdir, '/');
    size_t plen = slash ? (size_t)(slash - go_outdir) : 0;
    const char *base = basename_of(go_outdir);
    size_t n = plen + 1 + 1 + strlen(base) + strlen(".asn1cgo--XXXXXX")
               + strlen(kind) + 1;
    char *t = malloc(n);
    if(!t) {
        fprintf(stderr, "asn1cgo: out of memory\n");
        return NULL;
    }
    if(slash)
        snprintf(t, n, "%.*s/.%s.asn1cgo-%s-XXXXXX", (int)plen, go_outdir,
                 base, kind);
    else
        snprintf(t, n, ".%s.asn1cgo-%s-XXXXXX", base, kind);
    return t;
}

/* Create the staging dir for go_outdir (and the missing parents of go_outdir).
 * A pre-existing go_outdir that is not a directory is refused. */
int
go_outdir_stage(const char *go_outdir, char **tmp_out) {
    struct stat st;
    *tmp_out = NULL;
    if(stat(go_outdir, &st) == 0) {
        if(!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "asn1cgo: -Fgo target exists and is not a "
                    "directory: %s\n", go_outdir);
            return -1;
        }
    } else if(errno != ENOENT) {
        fprintf(stderr, "asn1cgo: cannot stat -Fgo target: %s: %s\n",
                go_outdir, strerror(errno));
        return -1;
    }
    const char *slash = strrchr(go_outdir, '/');
    if(slash && slash != go_outdir) {
        char *parent = malloc((size_t)(slash - go_outdir) + 1);
        if(!parent) { fprintf(stderr, "asn1cgo: out of memory\n"); return -1; }
        memcpy(parent, go_outdir, (size_t)(slash - go_outdir));
        parent[slash - go_outdir] = '\0';
        int rc = mkpath(parent);
        free(parent);
        if(rc < 0) return -1;
    }
    char *t = sibling_template(go_outdir, "tmp");
    if(!t) return -1;
    if(!mkdtemp(t)) {
        fprintf(stderr, "asn1cgo: cannot create staging directory: %s: %s\n",
                t, strerror(errno));
        free(t);
        return -1;
    }
    /* mkdtemp makes it 0700; give it what mkdir(…, 0777) would have. */
    mode_t um = umask(0);
    umask(um);
    if(chmod(t, 0777 & ~um) != 0) {
        fprintf(stderr, "asn1cgo: cannot chmod staging directory: %s: %s\n",
                t, strerror(errno));
        rm_tree(t);
        free(t);
        return -1;
    }
    *tmp_out = t;
    return 0;
}

/* Swap the staged tree in. On success *old_out is the renamed-aside previous
 * tree (malloc'd; NULL when there was none) for go_outdir_commit, or
 * go_outdir_rollback to undo. On failure the target is as it was. */
int
go_outdir_publish(const char *go_outdir, const char *tmp, char **old_out) {
    struct stat st;
    *old_out = NULL;
    if(stat(go_outdir, &st) != 0) {
        if(errno != ENOENT) {
            fprintf(stderr, "asn1cgo: cannot stat -Fgo target: %s: %s\n",
                    go_outdir, strerror(errno));
            return -1;
        }
        if(rename(tmp, go_outdir) != 0) {
            fprintf(stderr, "asn1cgo: cannot rename %s -> %s: %s\n",
                    tmp, go_outdir, strerror(errno));
            return -1;
        }
        return 0;
    }
    if(!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "asn1cgo: -Fgo target exists and is not a "
                "directory: %s\n", go_outdir);
        return -1;
    }
    /* reserve a unique name for the old tree, then rename over the (empty)
     * reservation, which POSIX allows for directories. */
    char *old = sibling_template(go_outdir, "old");
    if(!old) return -1;
    if(!mkdtemp(old)) {
        fprintf(stderr, "asn1cgo: cannot create directory: %s: %s\n",
                old, strerror(errno));
        free(old);
        return -1;
    }
    if(rename(go_outdir, old) != 0) {
        fprintf(stderr, "asn1cgo: cannot rename %s -> %s: %s\n",
                go_outdir, old, strerror(errno));
        rmdir(old);                     /* our own empty reservation */
        free(old);
        return -1;
    }
    if(rename(tmp, go_outdir) != 0) {
        int e = errno;
        fprintf(stderr, "asn1cgo: cannot rename %s -> %s: %s\n",
                tmp, go_outdir, strerror(e));
        if(rename(old, go_outdir) != 0)
            fprintf(stderr, "asn1cgo: cannot restore previous tree: "
                    "rename %s -> %s: %s (previous tree is intact at %s)\n",
                    old, go_outdir, strerror(errno), old);
        free(old);
        return -1;
    }
    *old_out = old;
    return 0;
}

/* Undo a successful go_outdir_publish: put the old tree back, drop the new
 * one. Frees `old`. */
void
go_outdir_rollback(const char *go_outdir, const char *tmp, char *old) {
    if(rename(go_outdir, tmp) != 0) {
        fprintf(stderr, "asn1cgo: cannot roll back %s -> %s: %s\n",
                go_outdir, tmp, strerror(errno));
        free(old);
        return;
    }
    if(old && rename(old, go_outdir) != 0)
        fprintf(stderr, "asn1cgo: cannot restore previous tree: rename "
                "%s -> %s: %s\n", old, go_outdir, strerror(errno));
    free(old);
    rm_tree(tmp);
}

/* Final step: delete the old tree. A failure only leaves a hidden leftover
 * directory (warned about); the new tree is already in place. Frees `old`. */
int
go_outdir_commit(char *old) {
    int rc = 0;
    if(old && rm_tree(old) < 0) {
        fprintf(stderr, "asn1cgo: warning: previous -Fgo tree left behind "
                "at %s; remove it manually\n", old);
        rc = -1;
    }
    free(old);
    return rc;
}

/* Failure path: remove the staging dir (and nothing else). */
void
go_outdir_discard(const char *tmp) {
    if(tmp) rm_tree(tmp);
}
