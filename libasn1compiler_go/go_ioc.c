/*
 * go_ioc.c — walk-recorded conv facts + the shared conv tables
 * (IOC containers and open types: id/procedure dispatch, NULL-alt,
 * per-spec prefix and IOC error-code).
 *
 * Two roles:
 *   1. The recording functions declared in go_conv.h, called by go_names.c at
 *      the exact points where the walk reads the IOC table / alt markers /
 *      PDU rule / INTEGER classification. Recording, not re-derivation: the
 *      walk owns every structural decision; this TU stores what it decided.
 *   2. The shared tables + lookup helpers the conv emitters (go_conv_to.c /
 *      go_conv_from.c / go_entry.c) read.
 *
 * id-dispatch and procedure-dispatch share one row shape: (id_member, id, criticality, present,
 * alt_token, alt_msg). id-dispatch keys id_member="id"; procedure-dispatch keys "procedureCode"
 * with is_envelope=1 and rows hung off the three envelope CIDs.
 *
 * SCC membership (the per-SCC depth rule) is not recorded: the Flat IR carries every ref edge,
 * so go_conv_to.c computes it (Tarjan) — no walk coupling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "asn1c_internal.h"     /* arg_t (required before asn1c_misc.h) */
#include "asn1c_misc.h"         /* asn1c_prefix (the per-spec prefix rule; asn1c_misc.h:55) */

#include "go_conv.h"
#include "go_conv_internal.h"

/* The IR label/token accessors (go_flat.c; the same void* surface the other
 * conv TUs use). */
extern const char *go_conv_ir_tree_base_override(const void *t);
extern const char *go_conv_ir_type_label(const void *t);
extern const char *go_conv_ir_member_label(const void *m);

/* ---- the tables ----------------------------------------------------------- */

conv_ioc_row *g_conv_iocs = NULL;
int g_conv_n_iocs = 0, g_conv_cap_iocs = 0;

conv_null_alt *g_conv_nullalts = NULL;
int g_conv_n_nullalts = 0, g_conv_cap_nullalts = 0;

conv_pdu *g_conv_pdus = NULL;
int g_conv_n_pdus = 0, g_conv_cap_pdus = 0;

conv_wide *g_conv_wides = NULL;
int g_conv_n_wides = 0, g_conv_cap_wides = 0;

int g_conv_failed_ = 0;

/* ---- shared string helpers (all conv TUs link these) ---------------------- */

char *
ca(char *a, const char *b) {
    size_t la = a ? strlen(a) : 0;
    size_t lb = b ? strlen(b) : 0;
    char *r = realloc(a, la + lb + 1);
    if(!r) return a;
    memcpy(r + la, b ? b : "", lb);
    r[la + lb] = '\0';
    return r;
}

__attribute__((format(printf, 1, 2)))
char *
cfmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if(n < 0) { va_end(ap2); return cstrdup(""); }
    char *s = malloc((size_t)n + 1);
    if(!s) { conv_failed_set(); va_end(ap2); return cstrdup(""); }
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

char *
cstrdup(const char *s) {
    char *r = strdup(s ? s : "");
    if(!r) conv_failed_set();
    return r;
}

/* Strip the run prefix off cid (returns a pointer INTO the argument). */
static const char *
cid_strip(const char *cid) {
    const char *pfx = asn1c_prefix();
    if(pfx && *pfx && cid && strncmp(cid, pfx, strlen(pfx)) == 0)
        return cid + strlen(pfx);
    return cid;
}

/* strip + strdup (the stored form of every recorded cid). */
static char *
cid_dup(const char *cid) {
    return cstrdup(cid_strip(cid ? cid : ""));
}

int
conv_cid_eq(const char *a, const char *b) {
    if(!a || !b) return 0;
    return strcmp(cid_strip(a), cid_strip(b)) == 0;
}

/* The IR name accessor (go_flat.c; declared here not to widen go_flat.h —
 * the conv TUs link against the IR through this one symbol). */


/* tree type base of a node: the IR name (<P><cid>_flat, prefix included per
 * the per-spec prefix rule) minus "_flat" = <P><cid>, the tree typedef base (<P><cid>_t) and the
 * converter name base. NULL for an anonymous nested node (its IR name is the
 * empty-issued "_flat"). Malloc'd; caller frees. */
char *
conv_tree_base(const void *t) {
    /* the override first (the bare-named container clones carry a prefixed
     * tree typedef; per-spec prefix and Flat naming) */
    const char *ov = t ? go_conv_ir_tree_base_override((void *)t) : NULL;
    if(ov && *ov) return cstrdup(ov);
    const char *nm = t ? go_conv_ir_name((void *)t) : NULL;
    if(!nm || !*nm) return NULL;
    size_t n = strlen(nm);
    if(n < 6 || strcmp(nm + n - 5, "_flat") != 0) return NULL;
    char *b = malloc(n - 5 + 1);
    if(!b) { conv_failed_set(); return cstrdup(""); }
    memcpy(b, nm, n - 5);
    b[n - 5] = '\0';
    return b;
}

char *
conv_flat_name(const void *t) {
    return cstrdup(t ? go_conv_ir_name((void *)t) : "");
}

char *
conv_type_label(const void *t) {
    /* the recorded td->name display label (expr->Identifier verbatim,
     * prefix-free, hyphens kept — e.g. "E2SM-KPM-RANfunction-Description",
     * E2SM-KPM-RANfunction-Description.c:308, unprefixed even under an
     * ASN1C_PREFIX run); falls back to the prefixed tree base when
     * unrecorded. */
    const char *lbl = go_conv_ir_type_label(t);
    if(lbl && *lbl) return cstrdup(lbl);
    return conv_tree_base(t);
}

/* The member's display label (its recorded ASN.1 Identifier, hyphens kept —
 * the td-member name string, asn1c_C.c:3119); falls back to the member
 * token. Malloc'd. */
char *
conv_member_label(const void *m) {
    const char *lbl = go_conv_ir_member_label(m);
    if(lbl && *lbl) return cstrdup(lbl);
    lbl = go_flat_ir_member_token((void *)m);
    return cstrdup(lbl ? lbl : "");
}

int
conv_is_wide(const char *cid) {
    if(!cid) return 0;
    for(int i = 0; i < g_conv_n_wides; i++)
        if(conv_cid_eq(g_conv_wides[i].cid, cid)) return 1;
    return 0;
}

int
conv_is_pdu(const char *cid) {
    if(!cid) return 0;
    for(int i = 0; i < g_conv_n_pdus; i++)
        if(conv_cid_eq(g_conv_pdus[i].cid, cid)) return 1;
    return 0;
}

int
conv_is_null_alt(const char *node_cid, const char *alt_token) {
    if(!node_cid || !alt_token) return 0;
    for(int i = 0; i < g_conv_n_nullalts; i++)
        if(conv_cid_eq(g_conv_nullalts[i].node_cid, node_cid)
           && strcmp(g_conv_nullalts[i].alt_token, alt_token) == 0)
            return 1;
    return 0;
}

const conv_ioc_row *
conv_ioc_first(const char *spec_cid) {
    for(int i = 0; i < g_conv_n_iocs; i++)
        if(conv_cid_eq(g_conv_iocs[i].spec_cid, spec_cid))
            return &g_conv_iocs[i];
    return NULL;
}

int
conv_ioc_has(const char *spec_cid) {
    return conv_ioc_first(spec_cid) != NULL;
}

/* ---- recording (called by go_names.c through go_conv.h) ------------------- */

void
go_conv_record_ioc_row(const char *spec_cid, const char *id_member,
                       long id, long criticality, int present,
                       const char *alt_token, const char *alt_msg,
                       int is_envelope, const char *id_gov,
                       const char *crit_gov, int id_literal) {
    if(g_conv_n_iocs + 1 > g_conv_cap_iocs) {
        int nc = g_conv_cap_iocs ? g_conv_cap_iocs * 2 : 64;
        conv_ioc_row *nr = realloc(g_conv_iocs,
                                   (size_t)nc * sizeof(conv_ioc_row));
        if(!nr) { conv_failed_set(); return; }
        g_conv_iocs = nr;
        g_conv_cap_iocs = nc;
    }
    conv_ioc_row *r = &g_conv_iocs[g_conv_n_iocs++];
    r->spec_cid = cid_dup(spec_cid);
    r->id_member = cstrdup(id_member ? id_member : "id");
    r->id = id;
    r->criticality = criticality;
    r->present = present;
    r->alt_token = cstrdup(alt_token ? alt_token : "");
    r->alt_msg = cid_dup(alt_msg ? alt_msg : "");
    r->is_envelope = is_envelope;
    r->id_gov = cstrdup(id_gov ? id_gov : "");
    r->crit_gov = crit_gov ? cstrdup(crit_gov) : NULL;
    r->id_literal = id_literal;
}

void
go_conv_record_null_alt(const char *node_cid, const char *alt_token) {
    if(g_conv_n_nullalts + 1 > g_conv_cap_nullalts) {
        int nc = g_conv_cap_nullalts ? g_conv_cap_nullalts * 2 : 16;
        conv_null_alt *nr = realloc(g_conv_nullalts,
                                    (size_t)nc * sizeof(conv_null_alt));
        if(!nr) { conv_failed_set(); return; }
        g_conv_nullalts = nr;
        g_conv_cap_nullalts = nc;
    }
    conv_null_alt *r = &g_conv_nullalts[g_conv_n_nullalts++];
    r->node_cid = cid_dup(node_cid);
    r->alt_token = cstrdup(alt_token ? alt_token : "");
}

void
go_conv_record_pdu(const char *cid) {
    if(g_conv_n_pdus + 1 > g_conv_cap_pdus) {
        int nc = g_conv_cap_pdus ? g_conv_cap_pdus * 2 : 64;
        conv_pdu *nr = realloc(g_conv_pdus, (size_t)nc * sizeof(conv_pdu));
        if(!nr) { conv_failed_set(); return; }
        g_conv_pdus = nr;
        g_conv_cap_pdus = nc;
    }
    for(int i = 0; i < g_conv_n_pdus; i++)
        if(conv_cid_eq(g_conv_pdus[i].cid, cid)) return;
    g_conv_pdus[g_conv_n_pdus++].cid = cid_dup(cid);
}

void
go_conv_record_wide_integer(const char *cid) {
    if(g_conv_n_wides + 1 > g_conv_cap_wides) {
        int nc = g_conv_cap_wides ? g_conv_cap_wides * 2 : 16;
        conv_wide *nr = realloc(g_conv_wides, (size_t)nc * sizeof(conv_wide));
        if(!nr) { conv_failed_set(); return; }
        g_conv_wides = nr;
        g_conv_cap_wides = nc;
    }
    for(int i = 0; i < g_conv_n_wides; i++)
        if(conv_cid_eq(g_conv_wides[i].cid, cid)) return;
    g_conv_wides[g_conv_n_wides++].cid = cid_dup(cid);
}
