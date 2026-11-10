/*
 * go_conv_internal.h — shared state/helpers of the conv/entry emission TUs
 * (go_conv_to.c: _to_tree emission, go_conv_from.c: _from_tree emission,
 * go_ioc.c: IOC tables, go_entry.c: entry points).
 *
 * The Flat IR (go_flat.c) is the single structural source; these TUs read it
 * through the go_flat_ir_* accessors (go_conv.h documents the recording
 * surface the walk drives). The naming rule — every identifier string that
 * appears in output is produced by go_names.c — is kept per-TU: each conv TU
 * holds its own static naming helpers derived from IR cids, mirroring the
 * go_flat.c precedent (no cross-TU name surface is added).
 *
 * Naming (derived from the IR, whose cid IS the walk's GO_MKID output):
 *   function name  <Base>_to_tree / <Base>_from_tree   (Base = prefixed cid,
 *                 underscores kept — the comparison set' RANfunction_Name_to_tree,
 *                 BinRange_Value_to_tree; prefix INCLUDED per the per-spec prefix rule)
 *   flat type      go_flat_ir_name(t)   (<P><cid>_flat already)
 *   tree type      tree_typename(t)     (<P><cid>_t; go_conv_tree_typename)
 *   asn_DEF_       "asn_DEF_" + tree base (asn_DEF_<P><cid>)
 *   type label     the comparison set' hyphenated display name is a hand-authored
 *                 comparison artifact; the generator uses the tree base verbatim
 *                 (the identifier the emitted code can always reconstruct).
 */
#ifndef GO_CONV_INTERNAL_H
#define GO_CONV_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- shared emission helpers (defined once in go_conv_to.c) ------------- */

/* Append b to a (malloc growth; a returned unchanged on OOM). */
char *ca(char *a, const char *b);

/* printf into a fresh malloc'd string. */
__attribute__((format(printf, 1, 2)))
char *cfmt(const char *fmt, ...);

/* strdup that never returns NULL ("" on OOM). */
char *cstrdup(const char *s);

/* The one failed flag shared by the conv emission TUs. */
extern int g_conv_failed_;
#define conv_failed_set() do { g_conv_failed_ = 1; } while(0)

/* tree type base of a node: cid with the run prefix ensured ONCE (the IR
 * cid is already prefix-stripped; the tree typedef is <P><cid>_t). NULL for
 * an anonymous nested node (no converter of its own). Shared static buffer
 * per call site is unsafe across nested use — RETURNS A MALLOC'D STRING the
 * caller frees. */
char *conv_tree_base(const void *t);

/* The flat type name of a node (malloc'd copy of go_flat_ir_name). */
char *conv_flat_name(const void *t);

/* One converter pair's emitted "type label": the display label — the
 * recorded td->name string (ASN.1 Identifier verbatim, prefix-free,
 * hyphens kept) — falling back to the prefixed tree base when unrecorded.
 * Malloc'd. */
char *conv_type_label(const void *t);

/* A member's emitted display label: its recorded ASN.1 Identifier
 * (hyphens kept, asn1c_C.c:3119), falling back to the member token.
 * Malloc'd. */
char *conv_member_label(const void *m);

/* ---- the recorded-fact tables (defined in go_ioc.c) ---------------------- */

typedef struct {
    char *spec_cid;      /* prefix-stripped spec node cid (<X>_IEs / envelope) */
    char *id_member;     /* "id" (id-dispatch) or "procedureCode" (procedure-dispatch) */
    long id;
    long criticality;    /* Criticality numbering: reject=0/ignore=1/notify=2;
                          * -1 when the class has no &criticality column */
    int present;         /* the row's __value_PR slot (deduped alt sequence) */
    char *alt_token;     /* the value-union member token */
    char *alt_msg;       /* the alt payload's own cid ("" = not a named msg) */
    int is_envelope;     /* procedure-dispatch envelope (InitiatingMessage/...) */
    char *id_gov;        /* governing Go type of the id column (R2 of its
                          * declared type; "" = unresolvable) */
    char *crit_gov;      /* governing Go type of the criticality column, or
                          * NULL when the class declares no &criticality */
    int id_literal;      /* 1 = the id cell was an INTEGER literal (no value
                          * assignment to reference; the ctor body carries a
                          * typed conversion and the name suffix Id<decimal>) */
} conv_ioc_row;

extern conv_ioc_row *g_conv_iocs;
extern int g_conv_n_iocs, g_conv_cap_iocs;

typedef struct { char *node_cid, *alt_token; } conv_null_alt;
extern conv_null_alt *g_conv_nullalts;
extern int g_conv_n_nullalts, g_conv_cap_nullalts;

typedef struct { char *cid; } conv_pdu;
extern conv_pdu *g_conv_pdus;
extern int g_conv_n_pdus, g_conv_cap_pdus;

typedef struct { char *cid; } conv_wide;
extern conv_wide *g_conv_wides;
extern int g_conv_n_wides, g_conv_cap_wides;

/* Prefix-stripping equality: does recorded cid equal the node's cid (either
 * side may carry the run prefix)? */
int conv_cid_eq(const char *a, const char *b);

/* Is node cid a recorded wide-INTEGER leaf (the native-width INTEGER Flat rule)? */
int conv_is_wide(const char *cid);

/* Is node cid a recorded PDU root? */
int conv_is_pdu(const char *cid);

/* Is (node_cid, alt_token) a recorded NULL alt? */
int conv_is_null_alt(const char *node_cid, const char *alt_token);

/* The first recorded IOC row of spec node cid (NULL when none). */
const conv_ioc_row *conv_ioc_first(const char *spec_cid);

/* Does spec node cid have ANY recorded IOC row? */
int conv_ioc_has(const char *spec_cid);

/* ---- per-node emission surface (implemented in the owning TUs) ----------- */

/* is node cid in a recursion SCC (Tarjan over IR one-hop ref edges)?
 * Computed once by the first caller; returns 0/1. */
int conv_is_scc(const void *t);

/* The per-node from_tree body (go_conv_from.c) and the per-node
 * to_tree body's public form (go_conv_to.c) — both called by the emit
 * driver / go_entry.c; declared here to keep -Wmissing-prototypes quiet.
 * Malloc'd; caller frees. */
char *conv_from_node(void *t, int scc);
char *node_to_body_pub(void *t);

/* Emit the whole conv/entry output for go_conv_emit (go_conv_to.c drives the
 * per-node to/from emission in dependency order and the package writing). */
struct conv_out;

#endif /* GO_CONV_INTERNAL_H */
