/*
 * go_walk.c — walk the fixed ASN.1 AST and classify every construct.
 *
 * This step emits nothing. It walks the post-fix AST (the driver runs the C
 * fix pass, then asn1_compile, before dispatching here) and classifies each
 * module / top-level assignment / inline member against the supported-construct
 * table (go_constructs.h). Any construct off the table aborts the walk with a
 * non-zero return, which the driver maps to a non-zero process exit naming the
 * offending module, top-level type, member path and construct.
 *
 * Recursion model: the inline member walk descends into a type assignment's own
 * inline children only, never into the members of a referenced type. The parser
 * materialises `T ::= SEQUENCE { f T }` as an A1TC_REFERENCE member, not an
 * inline copy, so the inline subtree of one assignment is finite and acyclic by
 * construction. Recursion BETWEEN assignments (mutual cycles; the only kind in
 * the in-scope specs — direct self-refs, if any, are also inline reference
 * members) is detected by a SEPARATE per-module Tarjan pass over the type-ref
 * graph, run once for coverage only (see go_walk_recursion at the bottom). That
 * pass is coverage-only -- it never rejects; it annotates RECURSIVE_REF.
 *
 * Markers (OPTIONAL / DEFAULT) are recorded ALONGSIDE the terminal
 * classification, never instead of it: every member's terminal type is
 * classified (and may be rejected) regardless of which markers it carries.
 */
#include "go_constructs.h"

#include <stdio.h>             /* size_t/NULL transitively (asn1 headers need them) */
#include <string.h>
#include <stdlib.h>

#include <asn1parser.h>         /* asn1p_t, asn1p_expr_t, asn1p_module_t */
#include <asn1p_list.h>         /* TQ_FOR, TQ_FIRST */
#include <asn1_namespace.h>     /* asn1_namespace_t, asn1_namespace_* */
#include <asn1_ref.h>           /* asn1p_ref_t, RLT_*, asn1p_ref_string */
#include <asn1fix_export.h>     /* asn1f_find_terminal_type_ex */

#define HAS_FLAG(flags, bit)    (((flags) & (bit)) == (bit))
#define DIM(a)                  (sizeof(a) / sizeof((a)[0]))

/* ------------------------------------------------------------------------- */
/*
 * Optional coverage tally. When ASN1CGO_DUMP_COVERAGE names a file, the walk
 * records per-kind counts + a small set of (module,type) witnesses and writes
 * them out at the end. A caller aggregates the per-group runs
 * dumps let the caller aggregate per-group runs and assert the table is
 * neither over- nor under-specified. Off by default.
 */
#define COV_MAX_TYPES_PER_KIND 8
struct cov_type { const char *module; const char *type; };
static struct {
    long count;
    struct cov_type types[COV_MAX_TYPES_PER_KIND];
    int n_types;
} g_cov[GO_CONSTR__COUNT];
static int   g_cov_on = 0;
static char  g_cov_path[4096];

/*
 * Recursion report: the set of recursive top-level type names (the union of
 * non-trivial SCC members + self-referencing types), accumulated across all
 * modules of one invocation. Written as a distinct section of the coverage
 * file so a caller can compare it exactly against find_recursion.py on the
 * same specs (same names; ultimately the same SCC partition). cap-resized;
 * coverage only.
 */
static char **g_rec_names = NULL;
static int    g_rec_n = 0, g_rec_cap = 0;

/*
 * Recursive SCCs: one sorted, comma-joined group per non-trivial SCC (and one
 * for each self-loop singleton). Emitted as "CYCLE <names>" lines so a
 * caller can compare the PARTITION (not just the name union) against
 * find_recursion.py on the same specs.
 */
static char **g_cycles = NULL;
static int    g_cycles_n = 0, g_cycles_cap = 0;

/* Max-alternatives tracking: the largest CHOICE encountered (root+ext
 * counts split) and the type that holds it; printed on refusal and whenever
 * ASN1CGO_DUMP_CHOICE_ALTS=1 (opt-in surface, the dump-env convention). */
static int g_choice_max_alts = -1;
static int g_choice_max_ext_index = -1;
static char g_choice_max_where[256] = "";

/* max-alternatives report */
static void
choice_alts_report_maybe(const char *module, const char *type) {
    const char *r = getenv("ASN1CGO_DUMP_CHOICE_ALTS");
    if(r && *r) {
        fprintf(stderr,
                "asn1cgo: CHOICE alternatives report: max alts = %d, max ext index = %d\n",
                g_choice_max_alts, g_choice_max_ext_index);
    }
    (void)module; (void)type;
}

static void
cov_init(void) {
    const char *p = getenv("ASN1CGO_DUMP_COVERAGE");
    if(p && *p) {
        g_cov_on = 1;
        snprintf(g_cov_path, sizeof g_cov_path, "%s", p);
    }
}

static void
cov_note(go_construct_e k, const char *module, const char *type) {
    if(!g_cov_on) return;
    if(k < 0 || k >= GO_CONSTR__COUNT) return;
    g_cov[k].count++;
    int i;
    for(i = 0; i < g_cov[k].n_types; i++) {
        const char *m = g_cov[k].types[i].module;
        const char *t = g_cov[k].types[i].type;
        if(m && module && strcmp(m, module) == 0
           && t && type && strcmp(t, type) == 0)
            return;
    }
    if(g_cov[k].n_types < COV_MAX_TYPES_PER_KIND) {
        g_cov[k].types[g_cov[k].n_types].module = module;
        g_cov[k].types[g_cov[k].n_types].type = type;
        g_cov[k].n_types++;
    }
}

/* Record one recursive type by name (deduped). The name alone is what
 * find_recursion.py reports per dump; the SCC partition is recovered by
 * re-grouping these names the same way. */
static void
cov_add_recursion(const char *module, const char *type) {
    (void)module;
    if(!g_cov_on || !type) return;
    int i;
    for(i = 0; i < g_rec_n; i++)
        if(g_rec_names[i] && strcmp(g_rec_names[i], type) == 0)
            return;
    if(g_rec_n == g_rec_cap) {
        int nc = g_rec_cap ? g_rec_cap * 2 : 16;
        char **nn = realloc(g_rec_names, (size_t)nc * sizeof(char *));
        if(!nn) return;
        g_rec_names = nn;
        g_rec_cap = nc;
    }
    g_rec_names[g_rec_n] = strdup(type);
    if(g_rec_names[g_rec_n]) g_rec_n++;
}

/* Record one recursive SCC group. `names` is already caller-sorted and
 * comma-joined; stored verbatim (strdup). The set of groups is directly
 * comparable to find_recursion.py's cycles on the same specs. */
static void
cov_add_cycle(const char *joined) {
    if(!g_cov_on || !joined) return;
    for(int i = 0; i < g_cycles_n; i++)
        if(g_cycles[i] && strcmp(g_cycles[i], joined) == 0)
            return;
    if(g_cycles_n == g_cycles_cap) {
        int nc = g_cycles_cap ? g_cycles_cap * 2 : 16;
        char **nn = realloc(g_cycles, (size_t)nc * sizeof(char *));
        if(!nn) return;
        g_cycles = nn;
        g_cycles_cap = nc;
    }
    g_cycles[g_cycles_n] = strdup(joined);
    if(g_cycles[g_cycles_n]) g_cycles_n++;
}

static void
cov_write(void) {
    if(!g_cov_on) return;
    FILE *f = fopen(g_cov_path, "w");
    if(!f) return;
    int k;
    for(k = 0; k < GO_CONSTR__COUNT; k++) {
        fprintf(f, "%s\t%ld", go_construct_name((go_construct_e)k),
                g_cov[k].count);
        int i;
        for(i = 0; i < g_cov[k].n_types; i++)
            fprintf(f, "\t%s/%s",
                    g_cov[k].types[i].module ? g_cov[k].types[i].module : "?",
                    g_cov[k].types[i].type   ? g_cov[k].types[i].type   : "?");
        fprintf(f, "\n");
    }
    /* Recursion report: sorted recursive type names. The exact set
     * find_recursion.py reports for the same specs. */
    fputs("RECURSION\t", f);
    {
        int i, j;
        for(i = 0; i < g_rec_n; i++)
            for(j = i + 1; j < g_rec_n; j++)
                if(strcmp(g_rec_names[i], g_rec_names[j]) > 0) {
                    char *t = g_rec_names[i];
                    g_rec_names[i] = g_rec_names[j];
                    g_rec_names[j] = t;
                }
        for(i = 0; i < g_rec_n; i++)
            fprintf(f, "%s%s", g_rec_names[i], i + 1 < g_rec_n ? "," : "");
    }
    fputs("\n", f);
    /* SCC partition: one CYCLE line per non-trivial SCC (+ self-loop singles),
     * sorted, so the partition (not just the name union) is directly
     * comparable to find_recursion.py on the same specs. */
    {
        int i, j;
        for(i = 0; i < g_cycles_n; i++)
            for(j = i + 1; j < g_cycles_n; j++)
                if(strcmp(g_cycles[i], g_cycles[j]) > 0) {
                    char *t = g_cycles[i];
                    g_cycles[i] = g_cycles[j];
                    g_cycles[j] = t;
                }
        for(i = 0; i < g_cycles_n; i++)
            fprintf(f, "CYCLE\t%s\n", g_cycles[i]);
    }
    fclose(f);
    for(int i = 0; i < g_rec_n; i++) free(g_rec_names[i]);
    g_rec_n = 0;
    for(int i = 0; i < g_cycles_n; i++) free(g_cycles[i]);
    g_cycles_n = 0;
}

/* ------------------------------------------------------------------------- */
/*
 * Diagnostic for an unsupported terminal. Uses asn1c's own type string when it
 * has one, else the numeric expr_type (asn1p_expr_type2str returns NULL for
 * REFERENCE / EXTENSIBLE / CLASSFIELD / ...).
 */
static const char *
type_name_or_null(const asn1p_expr_t *t) {
    if(!t) return NULL;
    unsigned et = (unsigned)t->expr_type;
    if(et < DIM(asn1p_expr_type2str))
        return asn1p_expr_type2str[et];
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*
 * Resolve a fixed-type class-field reference (lowercase &field, e.g.
 * `id E2AP-PROTOCOL-IES.&id`) to the class's declared field type, the way the
 * C backend does (asn1c_C.c:2653-2655, :2710-2720). Find the CLASS top-level
 * assignment, find its &field declaration, return that decl's declared type
 * expression. E.g. &id -> ProtocolIE-ID (INTEGER); &criticality -> Criticality
 * (ENUMERATED). Returns NULL if the class/field cannot be located.
 *
 * Stops at the class/field boundary: the declared type is itself a plain
 * (non-class-field) reference that asn1f_find_terminal_type_ex can chase.
 */
static asn1p_expr_t *
resolve_classfield_decltype(asn1p_t *asn, const asn1p_expr_t *member) {
    asn1p_ref_t *ref = member->reference;
    if(!ref || ref->comp_count < 2) return NULL;
    const char *classname = ref->components[0].name;
    const char *fieldname = ref->components[1].name;
    if(!classname || !fieldname) return NULL;

    asn1p_module_t *mod;
    asn1p_expr_t *class_expr = NULL;
    TQ_FOR(mod, &(asn->modules), mod_next) {
        TQ_FOR(class_expr, &(mod->members), next) {
            if(class_expr->meta_type == AMT_OBJECTCLASS
               && class_expr->Identifier
               && strcmp(class_expr->Identifier, classname) == 0)
                goto found;
        }
    }
    return NULL;

found:;
    asn1p_expr_t *field;
    TQ_FOR(field, &(class_expr->members), next) {
        if(!field->Identifier || strcmp(field->Identifier, fieldname) != 0)
            continue;
        /* A fixed-type class field `&id ProtocolIE-ID` is modelled with the
         * declared type as the field's first child (the field itself is a
         * CLASSFIELD marker). Return that child. */
        asn1p_expr_t *first = TQ_FIRST(&field->members);
        return first ? first : field;
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Walker context threaded through the inline recursion. */
struct walk_ctx {
    const char *module;     /* active module->ModuleName */
    const char *toptype;    /* Identifier of the top-level assignment */
};

static int walk_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
                        asn1_namespace_t *ns, asn1p_t *asn,
                        const char *parent_path);

/*
 * walk a single child. Returns 0 ok, -1 failure (caller aborts).
 */
static int
walk_child(struct walk_ctx *ctx, asn1p_expr_t *child,
           asn1_namespace_t *ns, asn1p_t *asn, const char *parent_path) {
    const char *cid = child->Identifier ? child->Identifier : "?";
    char path[1024];
    if(parent_path && *parent_path)
        snprintf(path, sizeof path, "%s.%s", parent_path, cid);
    else
        snprintf(path, sizeof path, "%s", cid);

    /* Extension marker child "..." : recorded, no terminal, no recurse. */
    if(child->expr_type == A1TC_EXTENSIBLE) {
        cov_note(GO_CONSTR_EXTMARK, ctx->module, ctx->toptype);
        return 0;
    }

    /*
     * Reference shapes are resolved BEFORE any terminal chase. A class-field
     * reference stays an A1TC_REFERENCE on the post-fix AST and must not reach
     * asn1f_find_terminal_type_ex.
     *
     * The terminal is used only to classify the member's type. Recursion into
     * children is decided separately and ONLY descends into the child's own
     * inline .members — never into a referenced type's members. So a reference
     * child (A1TC_REFERENCE) classifies to its terminal's kind but, having no
     * inline children of its own, recurses nowhere; the referenced type is
     * walked on its own as a top-level assignment.
     */
    go_construct_e kind;
    asn1p_expr_t *terminal;

    if(go_construct_is_open_type(child)) {
        kind = GO_CONSTR_OPEN_TYPE;
        terminal = child;
        cov_note(kind, ctx->module, ctx->toptype);
    } else if(go_construct_is_classfield_fixedtype(child)) {
        asn1p_expr_t *decl = resolve_classfield_decltype(asn, child);
        asn1p_expr_t *decltype = decl;
        if(decl && (decl->expr_type == A1TC_REFERENCE
                    || decl->meta_type == AMT_TYPEREF)) {
            asn1p_expr_t *t = asn1f_find_terminal_type_ex(asn, ns, decl);
            if(t) decltype = t;
        }
        terminal = decltype ? decltype : decl;
        if(!terminal) {
            fprintf(stderr,
                    "asn1cgo: unresolvable class-field reference in module %s: "
                    "type %s, member %s, ref %s\n",
                    ctx->module ? ctx->module : "?",
                    ctx->toptype ? ctx->toptype : "?", path,
                    asn1p_ref_string(child->reference));
            return -1;
        }
        kind = go_construct_classify(terminal);
        cov_note(kind, ctx->module, ctx->toptype);
    } else {
        /* Plain member: deref a reference to its terminal, then classify. */
        if(child->expr_type == A1TC_REFERENCE
           || child->meta_type == AMT_TYPEREF) {
            asn1p_expr_t *t = asn1f_find_terminal_type_ex(asn, ns, child);
            if(t == NULL) {
                /* One-fail contract: an unresolvable reference fails. */
                fprintf(stderr,
                        "asn1cgo: unresolvable type reference in module %s: "
                        "type %s, member %s, ref %s\n",
                        ctx->module ? ctx->module : "?",
                        ctx->toptype ? ctx->toptype : "?", path,
                        asn1p_ref_string(child->reference));
                return -1;
            }
            terminal = t;
        } else {
            terminal = child;
        }

        /* named-bit BIT STRING rejection (terminal-side). */
        if(go_construct_is_namedbit_bitstring(terminal)) {
            fprintf(stderr,
                    "asn1cgo: BIT STRING, named bits in module %s: "
                    "type %s, member %s, construct BIT STRING\n",
                    ctx->module ? ctx->module : "?",
                    ctx->toptype ? ctx->toptype : "?", path);
            return -1;
        }

        kind = go_construct_classify(terminal);
        cov_note(kind, ctx->module, ctx->toptype);
    }

    /* Terminal-type reject. Markers never excuse an unsupported terminal
     * (e.g. a SET OF member is rejected even if OPTIONAL). */
    if(kind == GO_CONSTR_UNSUPPORTED) {
        const char *cs = type_name_or_null(terminal);
        if(cs)
            fprintf(stderr,
                    "asn1cgo: %s in module %s: type %s, member %s, "
                    "construct %s\n",
                    cs, ctx->module ? ctx->module : "?",
                    ctx->toptype ? ctx->toptype : "?", path, cs);
        else
            fprintf(stderr,
                    "asn1cgo: unsupported in module %s: type %s, member %s, "
                    "expr_type=0x%x\n",
                    ctx->module ? ctx->module : "?",
                    ctx->toptype ? ctx->toptype : "?", path,
                    terminal ? (unsigned)terminal->expr_type : 0);
        return -1;
    }

    /*
     * Marker annotations (alongside the terminal kind). DEFAULT before OPTIONAL.
     * Marker layout (asn1p_expr.h:205-215): EM_INDIRECT=0x01, EM_OMITABLE=0x02,
     * EM_OPTIONAL=0x07 (bits 0,1,2), EM_DEFAULT=0x0F (bits 0,1,2,3). OPTIONAL and
     * DEFAULT OVERLAP on bits 1,2, so `(flags & 0x0E)` is NOT a clean DEFAULT test
     * (an OPTIONAL 0x07 member hits 0x06). The DEFAULT-only bit is bit 3 =
     * EM_DEFAULT & ~EM_OPTIONAL = 0x08: a DEFAULT member carries 0x0F at parse
     * (asn1p_y.y:2225) -> 0x0E after a fix step clears EM_INDIRECT, either way bit
     * 3 is set; a pure-OPTIONAL 0x07 member has bit 3 clear. So DEFAULT =
     * (flags & 0x08); OPTIONAL = ((flags & EM_OPTIONAL)==EM_OPTIONAL), which a
     * DEFAULT member (0x0E & 0x07 == 0x06) correctly fails.
     *
     * RECURSIVE_REF is NOT a marker annotation here: EM_UNRECURSE is stamped by
     * expr_break_recursion in asn1c_C.c for three unrelated reasons (indirect
     * CHOICE, safe-naming, recursion) and cannot discriminate recursion -- it
     * fires 100+ times in the non-recursive specs. Recursion coverage comes from
     * the per-module Tarjan pass (go_walk_recursion), not from a member flag.
     */
    if(child->marker.flags & (EM_DEFAULT & ~EM_OPTIONAL)) {
        cov_note(GO_CONSTR_DEFAULT, ctx->module, ctx->toptype);
        fprintf(stderr,
                "asn1cgo: DEFAULT member in module %s: type %s, member %s, "
                "construct DEFAULT\n",
                ctx->module ? ctx->module : "?",
                ctx->toptype ? ctx->toptype : "?", path);
        return -1;
    }
    if((child->marker.flags & EM_OPTIONAL) == EM_OPTIONAL)
        cov_note(GO_CONSTR_OPTIONAL, ctx->module, ctx->toptype);

    /*
     * Recurse into the child's OWN inline children only — when the child itself
     * is a constructed type (an inline anonymous SEQUENCE/CHOICE/SEQUENCE OF).
     * A reference child carries no inline children; its referenced type is a
     * separate top-level assignment walked on its own. This bounds the walk to
     * one assignment's inline subtree, so recursion between assignments cannot
     * loop here (it is detected instead via the EM_UNRECURSE marker).
     */
    if(child->expr_type == ASN_CONSTR_SEQUENCE
       || child->expr_type == ASN_CONSTR_CHOICE
       || child->expr_type == ASN_CONSTR_SEQUENCE_OF) {
        if(walk_members(ctx, child, ns, asn, path) < 0)
            return -1;
    }
    return 0;
}

static int
walk_members(struct walk_ctx *ctx, asn1p_expr_t *parent,
             asn1_namespace_t *ns, asn1p_t *asn, const char *parent_path) {
    asn1p_expr_t *child;
    /* CHOICE extension indices >= 64 refused by default.
     *
     * The APER extension-alternative index is a "normally small
     * non-negative whole number" (X.691 #11.6): uper_put_nsnnwn
     * (per_support.c:101) takes the short 7-bit form only for n <= 63; an
     * index >= 64 falls to the multi-byte form, untested in this project
     * (all three target specs' CHOICEs sit far below the boundary; the
     * counts are in the construct tables). Override:
     * ASN1CGO_ALLOW_CHOICE_EXT64=1 (generation proceeds; output identical
     * to an unguarded run — the -D debug flag is untouched).
     *
     * Index arithmetic mirrors asn1c_C.c's member-table walk (~:468): the
     * extension marker child ("...", A1TC_EXTENSIBLE) flips comp_mode;
     * every OTHER child increments the element counter. The extension
     * index of an alt is (element index - ext_start), ext_start = the
     * element count at the first marker (asn1c's first_extension). */
    if(parent->expr_type == ASN_CONSTR_CHOICE) {
        asn1p_expr_t *v;
        int elements = 0, comp_mode = 0, first_extension = -1;
        int max_ext_index = -1;
        const char *ovr = getenv("ASN1CGO_ALLOW_CHOICE_EXT64");
        TQ_FOR(v, &(parent->members), next) {
            if(v->expr_type == A1TC_EXTENSIBLE) {
                if((++comp_mode) == 1)
                    first_extension = elements;
                continue;
            }
            if(comp_mode >= 1) {
                int ext_index = elements - first_extension;
                if(ext_index > max_ext_index) max_ext_index = ext_index;
            }
            elements++;
        }
        {
            int total_alts = elements;   /* post-loop: all non-marker members */
            if(total_alts > g_choice_max_alts) {
                g_choice_max_alts = total_alts;
                g_choice_max_ext_index = max_ext_index;
                snprintf(g_choice_max_where, sizeof g_choice_max_where,
                         "%s:%s", ctx->module ? ctx->module : "?",
                         ctx->toptype ? ctx->toptype : "?");
            }
            choice_alts_report_maybe(ctx->module, ctx->toptype);
        }
        if(max_ext_index >= 64) {
            if(ovr && *ovr) {
                fprintf(stderr,
                        "asn1cgo: CHOICE ext index %d >= 64 OVERRIDDEN via ASN1CGO_ALLOW_CHOICE_EXT64 (untested nsnnwn >= 64 path; output at caller's risk)\n",
                        max_ext_index);
            } else {
                fprintf(stderr,
                        "asn1cgo: CHOICE extension alternative index %d >= 64 (X.691 #11.6 short-form boundary; the >= 64 nsnnwn encoding is untested in this project) - REFUSED. Set ASN1CGO_ALLOW_CHOICE_EXT64=1 to override.\n",
                        max_ext_index);
                fprintf(stderr,
                        "asn1cgo:   in module %s: type %s, CHOICE at %s\n",
                        ctx->module ? ctx->module : "?",
                        ctx->toptype ? ctx->toptype : "?",
                        parent_path && *parent_path ? parent_path : "(top level)");
                return -1;
            }
        }
    }
    TQ_FOR(child, &(parent->members), next) {
        if(walk_child(ctx, child, ns, asn, parent_path) < 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
static int
walk_expr(struct walk_ctx *ctx, asn1p_expr_t *expr,
          asn1_namespace_t *ns, asn1p_t *asn) {
    /* Parameterized template: never walk the template, walk its
     * specializations (mirror asn1compiler.c:116-130). */
    if(expr->lhs_params && expr->spec_index == -1) {
        int i;
        for(i = 0; i < expr->specializations.pspecs_count; i++) {
            asn1p_expr_t *clone = expr->specializations.pspec[i].my_clone;
            if(clone && walk_expr(ctx, clone, ns, asn) < 0)
                return -1;
        }
        return 0;
    }

    /* Value assignments are not types. */
    if(expr->meta_type == AMT_VALUE)
        return 0;

    if(expr->meta_type == AMT_OBJECTCLASS) {
        cov_note(GO_CONSTR_IOC_CLASS, ctx->module, expr->Identifier);
        return 0;
    }
    if(expr->meta_type == AMT_OBJECT || expr->meta_type == AMT_VALUESET) {
        cov_note(GO_CONSTR_IOC_OBJSET, ctx->module, expr->Identifier);
        return 0;
    }

    /* Type assignment: terminal of the outer type, then its inline members. */
    asn1p_expr_t *terminal = expr;
    if(expr->expr_type == A1TC_REFERENCE || expr->meta_type == AMT_TYPEREF) {
        asn1p_expr_t *t = asn1f_find_terminal_type_ex(asn, ns, expr);
        if(t == NULL) {
            fprintf(stderr,
                    "asn1cgo: unresolvable type reference in module %s: "
                    "type %s, ref %s\n",
                    ctx->module ? ctx->module : "?",
                    expr->Identifier ? expr->Identifier : "?",
                    expr->reference ? asn1p_ref_string(expr->reference) : "?");
            return -1;
        }
        terminal = t;
    }

    const char *save_toptype = ctx->toptype;
    ctx->toptype = expr->Identifier ? expr->Identifier : "?";

    /* Top-level named-bit BIT STRING is rejected. */
    if(go_construct_is_namedbit_bitstring(terminal)) {
        fprintf(stderr,
                "asn1cgo: BIT STRING, named bits in module %s: type %s, "
                "construct BIT STRING\n",
                ctx->module ? ctx->module : "?", ctx->toptype);
        ctx->toptype = save_toptype;
        return -1;
    }

    go_construct_e kind = go_construct_classify(terminal);
    cov_note(kind, ctx->module, ctx->toptype);
    if(kind == GO_CONSTR_UNSUPPORTED) {
        const char *cs = type_name_or_null(terminal);
        if(cs)
            fprintf(stderr,
                    "asn1cgo: %s in module %s: type %s, construct %s\n",
                    cs, ctx->module ? ctx->module : "?", ctx->toptype, cs);
        else
            fprintf(stderr,
                    "asn1cgo: unsupported in module %s: type %s, "
                    "expr_type=0x%x\n",
                    ctx->module ? ctx->module : "?", ctx->toptype,
                    terminal ? (unsigned)terminal->expr_type : 0);
        ctx->toptype = save_toptype;
        return -1;
    }

    /*
     * Recurse into the assignment's OWN inline members only. S ::= SEQUENCE {…}
     * has those fields on the assignment expr itself; S ::= T (an alias) carries
     * no inline fields, so nothing is recursed into here — T is walked on its
     * own as a separate top-level assignment. This keeps the walk inline-only
     * and termination-safe at the top level too.
     */
    int rc = 0;
    if(expr->expr_type == ASN_CONSTR_SEQUENCE
       || expr->expr_type == ASN_CONSTR_CHOICE
       || expr->expr_type == ASN_CONSTR_SEQUENCE_OF)
        rc = walk_members(ctx, expr, ns, asn, NULL);

    ctx->toptype = save_toptype;
    return rc;
}

/* ========================================================================= *
 * Recursion coverage — per-module Tarjan SCC over the type-ref graph.
 *
 * Coverage only: this annotates RECURSIVE_REF and writes a recursion report.
 * It NEVER rejects. It runs only when ASN1CGO_DUMP_COVERAGE names a file, so a
 * plain -Fgo incurs nothing.
 *
 * Edge model (mirrors tools/find_recursion.py, which tokenises the asn1c -EF
 * text the same AST underlies): every top-level TYPE assignment is a vertex.
 * There is an edge v -> w iff type v's inline body references type w, where a
 * reference resolves via asn1f_find_terminal_type_ex to a top-level assignment
 * whose Identifier IS w and IS a type in the same module. Member identifiers
 * and ASN-keyword tokens never resolve to a type, so they drop out exactly as
 * find_recursion's "keep only names defined in-scope" filter drops them. A
 * self-reference (v -> v) is kept. The recursion set = the union of SCCs with
 * >1 member, plus any vertex that has a self-edge. This is the same
 * classification find_recursion uses.
 *
 * Per-module (each module's AST region is its own vertex set + edge set),
 * exactly as find_recursion parses each dump file independently.
 * ========================================================================= */

/* A maximal-recursion-limit-free iterative Tarjan. The AST is small (E2SM-RC
 * is ~290 assignments), but recursion depth is unbounded in principle, so the
 * traversal is made iterative via an explicit work stack rather than the
 * recursive textbook form. */
struct vertex {
    asn1p_expr_t *expr;         /* the top-level type assignment        */
    const char *name;           /* expr->Identifier (key)               */
    int idx, low, scc;          /* Tarjan bookkeeping (-1 = unvisited)  */
    int on_stack;               /* boolean                              */
    /* adjacency list: indices into the per-module vertex array            */
    int *adj;
    int n_adj, cap_adj;
    int self_edge;
};

static void
v_add_edge(struct vertex *v, int w) {
    for(int i = 0; i < v->n_adj; i++)
        if(v->adj[i] == w) return;      /* dedup: one edge v -> w */
    if(v->n_adj == v->cap_adj) {
        int nc = v->cap_adj ? v->cap_adj * 2 : 4;
        int *na = realloc(v->adj, (size_t)nc * sizeof(int));
        if(!na) return;                 /* OOM: drop the edge (coverage only) */
        v->adj = na;
        v->cap_adj = nc;
    }
    v->adj[v->n_adj++] = w;
}

static void
v_free(struct vertex *v) {
    free(v->adj);
    v->adj = NULL;
    v->n_adj = v->cap_adj = 0;
}

/*
 * Collect the set of type NAMES referenced inside `top`, deeply. Walks `top`'s
 * own inline member subtree (not into referenced-type bodies) -- the same
 * inline-only boundary the classifier respects -- and for every reference child
 * (including the element of an anonymous SEQUENCE OF T, and a SEQUENCE OF T
 * element that is itself a reference) records the resolved terminal's
 * Identifier when that terminal is a top-level type in the module.
 *
 * `types`/`n_types` is the module's vertex table for fast membership (a name is
 * an edge target only if it names a top-level type).
 */
/*
 * Collect the set of type NAMES referenced inside `top`, deeply. Walks `top`'s
 * own inline member subtree (not into referenced-type bodies) -- the same
 * inline-only boundary the classifier respects -- and for every reference child
 * (including the element of an anonymous SEQUENCE OF T, and a SEQUENCE OF T
 * element that is itself a reference) records the IMMEDIATE reference target
 * name when that name is a top-level type in the module.
 *
 * One-hop, by immediate-reference-name only -- NOT terminal-chased. This is
 * what mirrors tools/find_recursion.py: that script tokenises the asn1c -EF
 * text into names defined in-scope, so `T ::= U` is the single edge T -> U
 * (one hop), and `field AliasA` inside type C is the edge C -> AliasA (one hop,
 * NOT chased through the alias to whatever AliasA resolves to). Chasing through
 * an alias would collapse AliasA out of its own cycle, mis-counting the SCCs.
 *
 * `vtab`/`n_types` is the module's vertex table for membership (an edge target
 * is valid only when it names a top-level type in this module).
 */
static void
collect_edges_into(struct vertex *dst, asn1p_expr_t *node,
                   asn1_namespace_t *ns, asn1p_t *asn,
                   struct vertex *vtab, int n_types) {
    if(!node) return;
    (void)ns; (void)asn;

    asn1p_expr_t *child;
    TQ_FOR(child, &(node->members), next) {
        if(child->expr_type == A1TC_EXTENSIBLE) continue;

        /* A reference member: its ONE-HOP target is reference->components[0].name
         * (e.g. member `a AliasA OPTIONAL` -> "AliasA"). Class-field references
         * (&id/&criticality, 2-comp with &lex_type) have no in-scope type as
         * their first component, so they contribute no edge -- matching
         * find_recursion, where &id etc. do not name an assignment. */
        if(child->reference && child->reference->comp_count >= 1
           && child->reference->components[0].name) {
            const char *tgt = child->reference->components[0].name;
            for(int j = 0; j < n_types; j++) {
                if(vtab[j].name && strcmp(vtab[j].name, tgt) == 0) {
                    v_add_edge(dst, j);
                    break;
                }
            }
            /* Do not descend past a reference: its body belongs to the other
             * assignment, walked by that assignment's own vertex. */
            continue;
        }

        /* An inline constructed type: descend into it. The element of
         * `SEQUENCE OF T` where T is a reference is covered above at the
         * element child; the anonymous element of `SEQUENCE OF SEQUENCE{...}`
         * is inline-only (no reference) and recurses here. */
        if(child->expr_type == ASN_CONSTR_SEQUENCE
           || child->expr_type == ASN_CONSTR_CHOICE
           || child->expr_type == ASN_CONSTR_SEQUENCE_OF) {
            collect_edges_into(dst, child, ns, asn, vtab, n_types);
        }
    }
}

/*
 * Iterative Tarjan. Produces v->scc = an SCC id per vertex and returns the SCC
 * count. Iterative because the type graph is unbounded in depth in principle.
 * The DFS path stack can hold at most n vertices (each vertex is pushed once,
 * when first discovered unvisited), so all stacks are sized n.
 */
static int
tarjan_scc(struct vertex *vtab, int n) {
    int *stk = malloc((size_t)n * sizeof(int));           /* Tarjan SCC stack  */
    unsigned char *on = calloc((size_t)n, 1);             /* on stk?           */
    int *work = malloc((size_t)n * sizeof(int));          /* DFS frame: vertex */
    int *wi   = malloc((size_t)n * sizeof(int));          /* DFS frame: adj..  */
    if(!stk || !on || !work || !wi || n == 0) {
        free(stk); free(on); free(work); free(wi);
        return 0;                       /* coverage only: bail out gracefully */
    }
    int sp = 0, wtop = 0, scc_count = 0, counter = 0;

    for(int root = 0; root < n; root++) {
        if(vtab[root].idx != -1) continue;
        work[wtop] = root; wi[wtop] = 0; wtop++;
        while(wtop > 0) {
            int v = work[wtop - 1];
            if(vtab[v].idx == -1) {
                vtab[v].idx = vtab[v].low = counter++;
                stk[sp++] = v; on[v] = 1;
            }
            if(wi[wtop - 1] < vtab[v].n_adj) {
                int w = vtab[v].adj[wi[wtop - 1]++];
                if(vtab[w].idx == -1) {
                    /* descend into w: push a frame. wtop < n always, since each
                     * vertex is pushed at most once and there are n vertices. */
                    work[wtop] = w; wi[wtop] = 0; wtop++;
                } else if(on[w]) {
                    if(vtab[w].idx < vtab[v].low) vtab[v].low = vtab[w].idx;
                }
            } else {
                wtop--;                  /* pop v */
                if(vtab[v].low == vtab[v].idx) {
                    int w;
                    do {
                        w = stk[--sp];
                        on[w] = 0;
                        vtab[w].scc = scc_count;
                    } while(w != v);
                    scc_count++;
                }
                if(wtop > 0) {           /* propagate low to parent frame */
                    int p = work[wtop - 1];
                    if(vtab[v].low < vtab[p].low) vtab[p].low = vtab[v].low;
                }
            }
        }
    }
    free(stk); free(on); free(work); free(wi);
    return scc_count;
}

/*
 * Run the recursion pass for one module and, if coverage is on, fold its
 * recursive types into the per-kind RECURSIVE_REF tally + report buffer.
 */
static void
go_walk_recursion(asn1p_module_t *mod, asn1_namespace_t *ns, asn1p_t *asn) {
    if(!g_cov_on) return;

    /* Build the vertex table: every top-level TYPE assignment in this module. */
    struct vertex *vtab = NULL;
    int n = 0, cap = 0;
    asn1p_expr_t *expr;
    TQ_FOR(expr, &(mod->members), next) {
        if(!expr->Identifier)                       continue;
        if(expr->meta_type == AMT_VALUE)            continue;
        if(expr->meta_type == AMT_OBJECTCLASS
           || expr->meta_type == AMT_OBJECT
           || expr->meta_type == AMT_VALUESET)      continue;
        /* Skip parameterized templates; their specializations are the real
         * vertices (mirror asn1compiler.c:116-130). A template that has no
         * specializations yet contributes no vertex. */
        if(expr->lhs_params && expr->spec_index == -1) {
            int i;
            for(i = 0; i < expr->specializations.pspecs_count; i++) {
                asn1p_expr_t *clone = expr->specializations.pspec[i].my_clone;
                if(!clone || !clone->Identifier) continue;
                if(n == cap) {
                    cap = cap ? cap * 2 : 32;
                    vtab = realloc(vtab, (size_t)cap * sizeof(struct vertex));
                    if(!vtab) return;
                }
                memset(&vtab[n], 0, sizeof(struct vertex));
                vtab[n].expr = clone;
                vtab[n].name = clone->Identifier;
                vtab[n].idx = vtab[n].low = vtab[n].scc = -1;
                n++;
            }
            continue;
        }
        if(n == cap) {
            cap = cap ? cap * 2 : 32;
            vtab = realloc(vtab, (size_t)cap * sizeof(struct vertex));
            if(!vtab) return;
        }
        memset(&vtab[n], 0, sizeof(struct vertex));
        vtab[n].expr = expr;
        vtab[n].name = expr->Identifier;
        vtab[n].idx = vtab[n].low = vtab[n].scc = -1;
        n++;
    }
    if(n == 0) { free(vtab); return; }

    /* Edges: for each vertex, collect its inline reference targets. */
    for(int i = 0; i < n; i++) {
        /* A top-level ALIAS (`T ::= U`) is itself an A1TC_REFERENCE with no
         * inline members: its one-hop edge is its own RHS reference name. This
         * is the case find_recursion's tokenizer covers (the `::=` RHS text);
         * collect_edges_into only sees .members, so handle the alias here. One
         * hop by name -- NOT terminal-chased -- so the alias stays in its own
         * SCC (chasing through it would drop it from its cycle). */
        asn1p_expr_t *vx = vtab[i].expr;
        if(vx->reference && vx->reference->comp_count >= 1
           && vx->reference->components[0].name) {
            const char *tgt = vx->reference->components[0].name;
            for(int j = 0; j < n; j++)
                if(vtab[j].name && strcmp(vtab[j].name, tgt) == 0) {
                    v_add_edge(&vtab[i], j); break;
                }
        }
        collect_edges_into(&vtab[i], vtab[i].expr, ns, asn, vtab, n);
    }
    /* Record self-edges (find_recursion counts a self-loop as a cycle). */
    for(int i = 0; i < n; i++) {
        for(int a = 0; a < vtab[i].n_adj; a++)
            if(vtab[i].adj[a] == i) vtab[i].self_edge = 1;
    }

    int n_scc = tarjan_scc(vtab, n);

    /* Mark SCC sizes to decide which vertices are recursive. */
    int *scc_size = NULL;
    if(n_scc > 0) {
        scc_size = calloc((size_t)n_scc, sizeof(int));
        if(scc_size) {
            for(int i = 0; i < n; i++) {
                if(vtab[i].scc >= 0 && vtab[i].scc < n_scc) scc_size[vtab[i].scc]++;
            }
        }
    }

    /* Fold recursive types into the coverage tally/report. */
    for(int i = 0; i < n; i++) {
        int recursive = 0;
        if(scc_size && vtab[i].scc >= 0 && scc_size[vtab[i].scc] > 1) recursive = 1;
        if(vtab[i].self_edge) recursive = 1;
        if(recursive) {
            cov_note(GO_CONSTR_RECURSIVE_REF, mod->ModuleName, vtab[i].name);
            cov_add_recursion(mod->ModuleName ? mod->ModuleName : "?",
                              vtab[i].name ? vtab[i].name : "?");
        }
    }

    /* Emit the SCC partition: one sorted group per non-trivial SCC, plus a
     * singleton per self-looping vertex (find_recursion counts self-loops as
     * cycles). The grouping matches find_recursion's cycles on the same specs. */
    if(scc_size) {
        for(int s = 0; s < n_scc; s++) {
            /* gather this SCC's names */
            const char **names = NULL;
            int cnt = 0;
            if(scc_size[s] > 1) {
                names = malloc((size_t)scc_size[s] * sizeof(char *));
                if(!names) continue;
                for(int i = 0; i < n && cnt < scc_size[s]; i++)
                    if(vtab[i].scc == s && vtab[i].name)
                        names[cnt++] = vtab[i].name;
            } else {
                /* size == 1: emit only the self-looping singletons */
                int found = -1;
                for(int i = 0; i < n; i++)
                    if(vtab[i].scc == s) { found = i; break; }
                if(found < 0 || !vtab[found].self_edge) continue;
                names = malloc(sizeof(char *));
                if(!names) continue;
                names[cnt++] = vtab[found].name;
            }
            /* sort the group (simple insertion sort; groups are tiny) */
            for(int a = 0; a < cnt; a++)
                for(int b = a + 1; b < cnt; b++)
                    if(strcmp(names[a], names[b]) > 0) {
                        const char *t = names[a];
                        names[a] = names[b];
                        names[b] = t;
                    }
            /* join */
            size_t len = 1;
            for(int a = 0; a < cnt; a++) len += strlen(names[a]) + 1;
            char *joined = malloc(len);
            if(joined) {
                joined[0] = '\0';
                for(int a = 0; a < cnt; a++) {
                    if(a) strcat(joined, ",");
                    strcat(joined, names[a]);
                }
                cov_add_cycle(joined);
                free(joined);
            }
            free(names);
        }
    }

    free(scc_size);
    for(int i = 0; i < n; i++) v_free(&vtab[i]);
    free(vtab);
}

/* ========================================================================= *
 * "[[ ... ]]" extension-addition group — source-level rejection.
 *
 * The post-emit AST carries no trace of a bracket group: asn1c's C EMIT pass
 * mints an `ext<N>` Identifier on each group (asn1c_C.c:378-385 / :618-633) and
 * leaves no flag/field distinguishing it from a hand-written
 * `f SEQUENCE{...} OPTIONAL`, so a rejection cannot be fired from the AST the
 * walker receives. The construct IS present, verbatim, in the module's SOURCE,
 * so this rejects it there: a byte-level scan of each distinct source file,
 * run BEFORE the walk, mirroring exactly what the lexer accepts as the `[[`
 * token. Because it scans source text, it is unaffected by the emit pass.
 *
 * Token rule mirrored from asn1p_l.l:534 `"[["  return TOK_VBracketLeft;` --
 * the literal two-byte sequence, NO whitespace between the brackets (a `[ [`
 * lexes as two separate `[` tokens at asn1p_l.l:440, never matching `[[`).
 *
 * Skipped text mirrors the lexer so a `[[` inside a comment or quoted string is
 * not counted (these are states where the lexer will not emit TOK_VBracketLeft):
 *   - `--` comments (asn1p_l.l:115-123): run to end-of-line `\n` OR to the next
 *     `--` (a lone `-` between is eaten);
 *   - C-style block comments (asn1p_l.l:125-130): from slash-star to the next
 *     star-slash;
 *   - `"..."` quoted strings (asn1p_l.l:178 `\"[^\"]*`): run to the next `"`.
 *
 * Each distinct mod->source_file_name (asn1p_module.h:55) is scanned ONCE even
 * if several modules live in it. A file that cannot be opened is a loud failure
 * (never silently skipped). On a hit, the diagnostic names the module owning
 * the file and the top-level type = the assignment whose expr->_lineno
 * (asn1p_expr.h:242) is the largest value <= the hit line; the FIRST hit is
 * reported (per-file), for determinism. Construct = "Extension addition group
 * [[ ]]".
 * ========================================================================= */

/* Per-invocation record of already-scanned source files. Small linear scan;
 * the number of distinct files per invocation is tiny (<= a handful). */
static const char **g_bracket_scanned = NULL;
static int           g_bracket_scanned_n = 0, g_bracket_scanned_cap = 0;

static int
bracket_already_scanned(const char *path) {
    int i;
    for(i = 0; i < g_bracket_scanned_n; i++)
        if(g_bracket_scanned[i] && path
           && strcmp(g_bracket_scanned[i], path) == 0)
            return 1;
    return 0;
}

static void
bracket_mark_scanned(const char *path) {
    if(g_bracket_scanned_n == g_bracket_scanned_cap) {
        int nc = g_bracket_scanned_cap ? g_bracket_scanned_cap * 2 : 8;
        const char **nn = realloc(g_bracket_scanned,
                                  (size_t)nc * sizeof(char *));
        if(!nn) return;                  /* drop the dedup on OOM (safe) */
        g_bracket_scanned = nn;
        g_bracket_scanned_cap = nc;
    }
    g_bracket_scanned[g_bracket_scanned_n++] = path;
}

/*
 * Find the first 1-based line number in `buf`[0..len) that contains an
 * out-of-comment/out-of-string `[[`, or 0 if none. Lexer-state faithful.
 *
 * Returns 0 = none found, >0 = the 1-based line of the first hit.
 */
static int
bracket_scan_buf(const char *buf, size_t len) {
    size_t i = 0;
    int line = 1;
    enum { S_CODE, S_DASH, S_BLOCK, S_STRING } st = S_CODE;
    const char *b = buf;
    while(i < len) {
        char c = b[i];
        if(c == '\n') { line++; i++; continue; }

        switch(st) {
        case S_CODE:
            if(c == '"') { st = S_STRING; i++; }
            else if(c == '-' && i + 1 < len && b[i+1] == '-')
                st = S_DASH, i += 2;             /* -- comment open */
            else if(c == '/' && i + 1 < len && b[i+1] == '*')
                st = S_BLOCK, i += 2;            /* block comment open */
            else if(c == '[' && i + 1 < len && b[i+1] == '[')
                return line;                     /* HIT: exact 2-byte [[ */
            else i++;
            break;
        case S_DASH:
            /* inside a -- comment: ends at `\n` (handled above) or next `--`;
             * a single `-` is eaten (asn1p_l.l:121). */
            if(c == '-' && i + 1 < len && b[i+1] == '-')
                st = S_CODE, i += 2;             /* -- closes the comment */
            else if(c == '-') i++;
            else i++;
            break;
        case S_BLOCK:
            /* inside a C-style block comment: ends at the next star-slash */
            if(c == '*' && i + 1 < len && b[i+1] == '/')
                st = S_CODE, i += 2;
            else i++;
            break;
        case S_STRING:
            /* inside "...": ends at the next " (the lexer does not \-escape). */
            if(c == '"') st = S_CODE;
            i++;
            break;
        }
    }
    return 0;
}

/*
 * Locate the top-level assignment whose _lineno is the largest value <= target.
 * Walks the module's top-level members; ties/best-match by line proximity.
 */
static const char *
nearest_toptype(asn1p_module_t *mod, int target) {
    asn1p_expr_t *expr;
    const char *best = NULL;
    int best_line = -1;
    TQ_FOR(expr, &(mod->members), next) {
        if(!expr->Identifier) continue;
        int ln = expr->_lineno;
        if(ln <= target && ln > best_line) {
            best_line = ln;
            best = expr->Identifier;
        }
    }
    return best ? best : "?";
}

/*
 * Scan one module's source file (once) for an extension-addition `[[` group.
 * Returns 0 = clean, -1 = hit (diagnostic emitted), -2 = file unopenable.
 */
static int
bracket_check_module(asn1p_module_t *mod) {
    const char *path = mod->source_file_name;
    if(!path) return 0;                       /* no recorded source: nothing to scan */
    if(bracket_already_scanned(path)) return 0;
    bracket_mark_scanned(path);

    FILE *f = fopen(path, "rb");
    if(!f) {
        fprintf(stderr,
                "asn1cgo: cannot open module source %s in module %s "
                "(construct Extension addition group [[ ]])\n",
                path, mod->ModuleName ? mod->ModuleName : "?");
        return -2;
    }
    /* Read whole file into memory. These files are small source specs. */
    char *buf = NULL;
    size_t cap = 0, len = 0;
    int ch;
    while((ch = fgetc(f)) != EOF) {
        if(len == cap) {
            size_t nc = cap ? cap * 2 : 4096;
            char *nb = realloc(buf, nc);
            if(!nb) { fclose(f); free(buf); return 0; }   /* OOM: skip cleanly */
            buf = nb; cap = nc;
        }
        buf[len++] = (char)ch;
    }
    fclose(f);

    int hit = bracket_scan_buf(buf, len);
    free(buf);
    if(hit > 0) {
        fprintf(stderr,
                "asn1cgo: Extension addition group [[ ]] in module %s: "
                "type %s, source %s:%d, construct Extension addition group [[ ]]\n",
                mod->ModuleName ? mod->ModuleName : "?",
                nearest_toptype(mod, hit), path, hit);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
int
go_walk_asts(asn1p_t *asn) {
    cov_init();

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next) {
        asn1_namespace_t *ns = asn1_namespace_new_from_module(mod, 1);
        struct walk_ctx ctx;
        ctx.module = mod->ModuleName;
        ctx.toptype = NULL;

        /* Source-level [[ ]] rejection runs BEFORE the walk, per distinct
         * source file. A hit or an unopenable file aborts with a diagnostic. */
        int brc = bracket_check_module(mod);
        if(brc != 0) {
            asn1_namespace_free(ns);
            cov_write();
            return -1;
        }

        asn1p_expr_t *expr;
        int rc = 0;
        TQ_FOR(expr, &(mod->members), next) {
            if(walk_expr(&ctx, expr, ns, asn) < 0) { rc = -1; break; }
        }
        /* Recursion coverage runs after a clean inline walk (a failing walk
         * still reports at the top level). Coverage-only; never rejects. */
        go_walk_recursion(mod, ns, asn);
        asn1_namespace_free(ns);
        if(rc < 0) {
            cov_write();
            return -1;
        }
    }
    cov_write();
    return 0;
}
