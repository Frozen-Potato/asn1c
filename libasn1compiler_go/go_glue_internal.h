/*
 * go_glue_internal.h — shared declarations of the Go<->Flat glue emission.
 *
 * Private to the go_glue*.c files (go_glue.c has the overview): the
 * includes they all use, the name-row accessors (go_names.c), the fn
 * registry and emission-context types, the file-scope state one piece
 * defines and others use, and the functions one piece defines and others
 * call. Nothing outside go_glue*.c includes it.
 */
#ifndef GO_GLUE_INTERNAL_H
#define GO_GLUE_INTERNAL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asn1c_internal.h"      /* arg_t + asn1p_expr_t before asn1c_misc.h
                                 * (the go_entry.c include discipline) */
#include "asn1c_misc.h"          /* asn1c_prefix */
#include "go_conv.h"             /* flat IR surface + conv facts (PDU roots) */
#include "go_conv_internal.h"    /* g_conv_pdus, conv_* helpers */
#include "go_strmap.h"
#include "go_rows.h"             /* the name-row surface (go_names.c; the bag
                                 * outlives the glue emit) */
#define GFAIL(msg) do { fprintf(stderr, "asn1cgo: glue: %s\n", (msg)); \
                        glue_failed = 1; } while(0)
typedef struct { char *name; long value; } goneconst;
#define g_asserts (g_asserts_sb.p)

/* ---- the fn registry ----------------------------------------------------
 * One entry per emitted local fn (keyed by flat IR node index). Nested-only
 * nodes are INLINED, not registered. The registry dedups a diamond (two
 * members referencing the same type) and orders emission by first need. */

typedef struct {
    int ix;                    /* flat index of the node (the fn's type)  */
    char *sz, *fill, *read;    /* body lines (indent embedded)            */
    int queued, active, done;
    int leaf_pdu;              /* a scalar-alias leaf PDU (no &T{} read)  */
} gluefn;

/* ectx: one node's emission context (nested walks chain host bases). */
typedef struct {
    flat_type *t;          /* the node being walked                       */
    const char *owner_go;  /* its Go struct-owner name (row anchor;
                            * UNQUALIFIED — row keys are unqualified)    */
    const char *cbase;     /* C-address base expr for its member slots    */
    const char *cnode;     /* the flat NODE NAME its off consts key on
                            * (a nested walk keeps the HOST package node;
                            * composite consts carry the inner tokens)   */
    const char *cpre;      /* the composite const token prefix: "" at a
                            * package node, "<M>" inside one nested level
                            * (off<Node><M><Inner> = off<Node> + cpre<I>) */
    const char *val;       /* the Go value expr (borrowed; a *T or &F)    */
    char **szt, **fill, **read;  /* body-accumulator SLOTS (shared by ctx
                             * copies: ga moves the buffer, the slot
                             * stays; a copied ctx always sees the
                             * current string)                              */
    const char *depth;     /* the depth arg expr ("depth") or NULL        */
    int depth_on;          /* the walked node threads depth        */
} ectx;

/* the per-package item-helper text list (order = first reference; the
 * emit_items_helper dedup table is reset with it per package). */
typedef struct { char *sz, *fill, *read; } itemh;

/* --------------------------------------------------------------------- */
/* File-scope state shared between the go_glue*.c files. */

/* go_glue.c */
extern int glue_failed;
extern int g_tmpseq;

/* go_glue_util.c */
extern const char *g_emit_mod;
extern goneconst *g_loconsts;
extern int g_n_loconsts, g_cap_loconsts;
extern gsmap g_loconst_seen;
extern gsb g_asserts_sb;
extern gluefn **g_fns;
extern int g_n_fns, g_cap_fns;

/* go_glue_fn.c */
extern itemh *g_items;
extern int g_n_items, g_cap_items;

/* go_glue_pkg.c */
extern const char *GLUE_STATICS;
extern const char *GLUE_WRITE_BITS;
extern const char *GLUE_STRCONV_COMMON;
extern const char *GLUE_STRCONV_BMP;
extern const char *GLUE_STRCONV_UNIV;
extern const char *GLUE_STRCONV_OID;
extern const char *GLUE_READ_BITS;

/* --------------------------------------------------------------------- */
/* Functions shared between the go_glue*.c files. */

/* go_glue_util.c */
char *ga(char *a, const char *b);
char *gam(char *a, char *b);
void sb_a(gsb *b, const char *s);
void sb_am(gsb *b, char *s);
void sb_set(gsb *b, char *s);
__attribute__((format(printf, 1, 2)))
char *gfmt(const char *fmt, ...);
void free_const(const void *p);
char *gown(const char *s);
char *gjoin(const char *dir, const char *leaf);
int gmkdir_p(const char *path);
char *expand_oneline_ifs(char *src);
char *reindent_case_blocks(char *src);
int gfwrite_all(const char *path, const char *text);
char *gmodule_pkg(const char *module_name);
char *gcamel(const char *s);
char *gcamel_tok_in(const char *node_name, const char *tok);
char *gcamel_flat(const char *node_name);
char *g_szconst(const char *node_name);
char *g_offconst_pfx(const char *node_name, const char *pre,
                     const char *tok, const char *tnode);
char *cpre_chain(const char *pre, const char *tok, const char *tnode);
void asserts_reset(void);
void node_asserts(flat_type *t);
char *qconst(const char *node_name, char *o);
int gprim_width(const char *prim);
const char *gprim_go(const char *prim);
const char *gprim_slot(const char *prim);
const char *gprim_own(const char *prim);
char *gconv_store(const char *prim, const char *gt, const char *val);
char *gconv_load(const char *prim, const char *cast, const char *raw);
const char *gf_goname(flat_type *t);
const char *gf_field_goname(const char *owner, const char *token);
const char *gf_field_type(const char *owner, const char *token);
const char *gf_present_type(const char *owner);
const char *unqual(const char *n);
int fn_ix(flat_type *t);
gluefn *fn_queue(int ix);
char *fnbase(flat_type *t);
int n_is_seqof(flat_type *t);
int n_is_leaf(flat_type *t);
char *gtype_q(flat_type *t);
int dep_is_scc(flat_type *t);
char *errlit(flat_type *t, const char *mfield, const char *code, const char *msg);
int glue_ident_char(char c);
char *local_bitstring(void);
char *owner_bitstring(const char *mod);
char *bits_bridge(const char *mod, const char *expr, int to_local);
int is_prim_view(const char *ft);
char *field_cast(flat_type *t, const char *owner_go, const char *tok,
                 const char *prim);
char *qualify_alias(const char *alias_in);

/* go_glue_prim.c */
const char *strk_fn(int strk);
const char *strk_gotype(int strk);
char *strk_size(int strk, const char *e, const char *ind);
char *strk_read(int strk, const char *recarg, const char *assign_fmt);
void emit_prim(ectx *E, flat_member *m);
const char *hdf_fill(ectx *E, flat_type *target);
const char *hdf_size(ectx *E, flat_type *target);

/* go_glue_ref.c */
void emit_ref(ectx *E, flat_member *m, flat_type *r);

/* go_glue_member.c */
const char *gowner(flat_type *t, char **owned_out);
void emit_choice_at(ectx *E, flat_type *ch, const char *body_base,
                    const char *pv);
void emit_member(ectx *E, flat_member *m);

/* go_glue_fn.c */
void item_helpers_reset(void);
void emit_items_helper(flat_type *er);
void emit_type_fn(flat_type *t);

/* go_glue_pkg.c */
void emit_pdu_api(flat_type *rt_, const conv_pdu *al, gsb *src);
char *pkg_header(const char *module, const char *pkg, const char *flat_hdr,
                 const char *flat_includes, const char *pdu_externs,
                 const char *rt_module);
void emit_fn_text(gluefn *f, gsb *src);
extern int go_jer_enabled(void);

#endif /* GO_GLUE_INTERNAL_H */
