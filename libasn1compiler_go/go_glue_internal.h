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
#include <asn1_portable.h>     /* Windows: mkdir(2) with one argument */

#include "asn1c_internal.h"      /* arg_t + asn1p_expr_t before asn1c_misc.h
                                 * (the go_entry.c include discipline) */
#include "asn1c_misc.h"          /* asn1c_prefix */
#include "go_conv.h"             /* flat IR surface + conv facts (PDU roots) */
#include "go_conv_internal.h"    /* g_go_conv_pdus, conv_* helpers */
#include "go_strmap.h"
#include "go_rows.h"             /* the name-row surface (go_names.c; the bag
                                 * outlives the glue emit) */
#define GFAIL(msg) do { fprintf(stderr, "asn1cgo: glue: %s\n", (msg)); \
                        go_glue_failed = 1; } while(0)
typedef struct { char *name; long value; } goneconst;
#define g_asserts (g_go_asserts_sb.p)

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
 * go_emit_items_helper dedup table is reset with it per package). */
typedef struct { char *sz, *fill, *read; } itemh;

/* --------------------------------------------------------------------- */
/* File-scope state shared between the go_glue*.c files. */

/* go_glue.c */
extern int go_glue_failed;
extern int g_go_tmpseq;

/* go_glue_util.c */
extern const char *g_go_emit_mod;
extern goneconst *g_go_loconsts;
extern int g_go_n_loconsts, g_go_cap_loconsts;
extern gsmap g_go_loconst_seen;
extern gsb g_go_asserts_sb;
extern gluefn **g_go_fns;
extern int g_go_n_fns, g_go_cap_fns;

/* go_glue_fn.c */
extern itemh *g_go_items;
extern int g_go_n_items;

/* go_glue_pkg.c */
extern const char *GO_GLUE_STATICS;
extern const char *GO_GLUE_WRITE_BITS;
extern const char *GO_GLUE_STRCONV_COMMON;
extern const char *GO_GLUE_STRCONV_BMP;
extern const char *GO_GLUE_STRCONV_UNIV;
extern const char *GO_GLUE_STRCONV_OID;
extern const char *GO_GLUE_READ_BITS;

/* --------------------------------------------------------------------- */
/* Functions shared between the go_glue*.c files. */

/* go_glue_util.c */
char *go_ga(char *a, const char *b);
char *go_gam(char *a, char *b);
void go_sb_a(gsb *b, const char *s);
void go_sb_am(gsb *b, char *s);
void go_sb_set(gsb *b, char *s);
__attribute__((format(ASN1_PRINTF, 1, 2)))
char *go_gfmt(const char *fmt, ...);
void go_free_const(const void *p);
char *go_gown(const char *s);
char *go_gjoin(const char *dir, const char *leaf);
int go_gmkdir_p(const char *path);
char *go_expand_oneline_ifs(char *src);
char *go_reindent_case_blocks(char *src);
int go_gfwrite_all(const char *path, const char *text);
char *go_gmodule_pkg(const char *module_name);
char *go_gcamel(const char *s);
char *go_gcamel_tok_in(const char *node_name, const char *tok);
char *go_gcamel_flat(const char *node_name);
char *g_go_szconst(const char *node_name);
char *g_go_offconst_pfx(const char *node_name, const char *pre,
                     const char *tok, const char *tnode);
char *go_cpre_chain(const char *pre, const char *tok, const char *tnode);
void go_asserts_reset(void);
void go_node_asserts(flat_type *t);
char *go_qconst(const char *node_name, char *o);
int go_gprim_width(const char *prim);
const char *go_gprim_go(const char *prim);
const char *go_gprim_slot(const char *prim);
const char *go_gprim_own(const char *prim);
char *go_gconv_store(const char *prim, const char *gt, const char *val);
char *go_gconv_load(const char *prim, const char *cast, const char *raw);
const char *go_gf_goname(flat_type *t);
const char *go_gf_field_goname(const char *owner, const char *token);
const char *go_gf_field_type(const char *owner, const char *token);
const char *go_gf_present_type(const char *owner);
const char *go_unqual(const char *n);
int go_fn_ix(flat_type *t);
gluefn *go_fn_queue(int ix);
char *go_fnbase(flat_type *t);
int go_n_is_seqof(flat_type *t);
int go_n_is_leaf(flat_type *t);
char *go_gtype_q(flat_type *t);
int go_dep_is_scc(flat_type *t);
char *go_errlit(flat_type *t, const char *mfield, const char *code, const char *msg);
int go_glue_ident_char(char c);
char *go_local_bitstring(void);
char *go_owner_bitstring(const char *mod);
char *go_bits_bridge(const char *mod, const char *expr, int to_local);
int go_is_prim_view(const char *ft);
char *go_field_cast(flat_type *t, const char *owner_go, const char *tok,
                 const char *prim);
char *go_qualify_alias(const char *alias_in);

/* go_glue_prim.c */
const char *go_strk_fn(int strk);
const char *go_strk_gotype(int strk);
char *go_strk_size(int strk, const char *e, const char *ind);
char *go_strk_read(int strk, const char *recarg, const char *assign_fmt);
void go_emit_prim(ectx *E, flat_member *m);
const char *go_hdf_fill(ectx *E, flat_type *target);
const char *go_hdf_size(ectx *E, flat_type *target);

/* go_glue_ref.c */
void go_emit_ref(ectx *E, flat_member *m, flat_type *r);

/* go_glue_member.c */
const char *go_gowner(flat_type *t, char **owned_out);
void go_emit_choice_at(ectx *E, flat_type *ch, const char *body_base,
                    const char *pv);
void go_emit_member(ectx *E, flat_member *m);

/* go_glue_fn.c */
void go_item_helpers_reset(void);
void go_emit_items_helper(flat_type *er);
void go_emit_type_fn(flat_type *t);

/* go_glue_pkg.c */
void go_emit_pdu_api(flat_type *rt_, const conv_pdu *al, gsb *src);
char *go_pkg_header(const char *module, const char *pkg, const char *flat_hdr,
                 const char *flat_includes, const char *pdu_externs,
                 const char *rt_module);
void go_emit_fn_text(gluefn *f, gsb *src);
extern int go_jer_enabled(void);

#endif /* GO_GLUE_INTERNAL_H */
