/*
 * go_constructs.c — see go_constructs.h.
 *
 * Classification of ASN.1 expressions into the Go backend's construct kind
 * enum. Markers (OPTIONAL / DEFAULT / EM_UNRECURSE) are intentionally NOT
 * applied here: they are attributes of a member that annotate its terminal
 * kind, never replace it (go_walk.c records them alongside classify()).
 *
 * Reference resolution for class-field members is split out from classify():
 * a member like `value E2AP-PROTOCOL-IES.&Value` is still an A1TC_REFERENCE on
 * the post-fix AST, so it never reaches classify() as a terminal. go_walk.c
 * consults the is_open_type / is_classfield_* predicates first and only hands
 * an already-dereferenced terminal to classify().
 */
#include "go_constructs.h"

#include <asn1parser.h>         /* asn1p_expr_t, meta/expr_type enums */
#include <asn1p_list.h>         /* TQ_FIRST */
#include <asn1_ref.h>           /* asn1p_ref_t, RLT_* (libasn1common) */

/* ------------------------------------------------------------------------- */
const char *
go_construct_name(go_construct_e k) {
    switch(k) {
    case GO_CONSTR_SEQUENCE:       return "SEQUENCE";
    case GO_CONSTR_CHOICE:         return "CHOICE";
    case GO_CONSTR_SEQUENCE_OF:    return "SEQUENCE OF";
    case GO_CONSTR_ENUMERATED:     return "ENUMERATED";
    case GO_CONSTR_OPTIONAL:       return "OPTIONAL";
    case GO_CONSTR_DEFAULT:        return "DEFAULT";
    case GO_CONSTR_EXTMARK:        return "EXTENSION";
    case GO_CONSTR_BIT_STRING:     return "BIT STRING";
    case GO_CONSTR_OCTET_STRING:   return "OCTET STRING";
    case GO_CONSTR_INTEGER:        return "INTEGER";
    case GO_CONSTR_BOOLEAN:        return "BOOLEAN";
    case GO_CONSTR_NULL:           return "NULL";
    case GO_CONSTR_REAL:           return "REAL";
    case GO_CONSTR_OID:            return "OBJECT IDENTIFIER";
    case GO_CONSTR_STRING:         return "string";
    case GO_CONSTR_IOC_CLASS:      return "IOC-CLASS";
    case GO_CONSTR_IOC_OBJSET:     return "IOC-OBJECTSET";
    case GO_CONSTR_OPEN_TYPE:      return "OPEN-TYPE";
    case GO_CONSTR_RECURSIVE_REF:  return "RECURSIVE-REF";
    case GO_CONSTR_UNSUPPORTED:    return "UNSUPPORTED";
    default:                       return "?";
    }
}


/* ------------------------------------------------------------------------- */
/* Per-type facts for GO_CONSTR_STRING: the C typedef and the skeleton headers
 * it needs beyond the always-copied PrintableString.h. */
static const struct {
    int expr_type;
    const char *ctype;
    unsigned hdrs;              /* bitmask over g_hdr_names */
} g_string_info[] = {
    { ASN_STRING_PrintableString,   "PrintableString_t",   0 },
    { ASN_STRING_IA5String,         "IA5String_t",         1u << 0 },
    { ASN_STRING_VisibleString,     "VisibleString_t",     1u << 1 },
    { ASN_STRING_ISO646String,      "ISO646String_t",      (1u << 2) | (1u << 1) },
    { ASN_STRING_NumericString,     "NumericString_t",     1u << 3 },
    { ASN_STRING_UniversalString,   "UniversalString_t",   1u << 4 },
    { ASN_STRING_BMPString,         "BMPString_t",         1u << 5 },
    { ASN_STRING_UTF8String,        "UTF8String_t",        1u << 6 },
    { ASN_STRING_GeneralString,     "GeneralString_t",     1u << 7 },
    { ASN_STRING_GraphicString,     "GraphicString_t",     1u << 8 },
    { ASN_STRING_TeletexString,     "TeletexString_t",     1u << 9 },
    { ASN_STRING_T61String,         "T61String_t",         1u << 10 },
    { ASN_STRING_VideotexString,    "VideotexString_t",    1u << 11 },
    { ASN_STRING_ObjectDescriptor,  "ObjectDescriptor_t",  (1u << 12) | (1u << 8) },
    { ASN_BASIC_UTCTime,            "UTCTime_t",           1u << 13 },
    { ASN_BASIC_GeneralizedTime,    "GeneralizedTime_t",   1u << 14 },
};
static const char *const g_hdr_names[] = {
    "IA5String.h", "VisibleString.h", "ISO646String.h", "NumericString.h",
    "UniversalString.h", "BMPString.h", "UTF8String.h", "GeneralString.h",
    "GraphicString.h", "TeletexString.h", "T61String.h", "VideotexString.h",
    "ObjectDescriptor.h", "UTCTime.h", "GeneralizedTime.h",
    "OBJECT_IDENTIFIER.h", "RELATIVE-OID.h",
};
static unsigned g_hdr_used;

static void
note_string_use(int expr_type) {
    for(size_t i = 0; i < sizeof g_string_info / sizeof g_string_info[0]; i++)
        if(g_string_info[i].expr_type == expr_type)
            g_hdr_used |= g_string_info[i].hdrs;
}

/* OBJECT IDENTIFIER / RELATIVE-OID: both headers (the converter helpers use
 * both arc APIs). */
static void
note_oid_use(void) { g_hdr_used |= (1u << 15) | (1u << 16); }

int
go_oid_is_relative(const asn1p_expr_t *t) {
    return t && t->expr_type == ASN_BASIC_RELATIVE_OID;
}

unsigned go_string_hdr_mask(void) { return g_hdr_used; }

const char *
go_string_hdr_name(int idx) {
    if(idx < 0 || (size_t)idx >= sizeof g_hdr_names / sizeof g_hdr_names[0])
        return NULL;
    return g_hdr_names[idx];
}

const char *
go_string_ctype(const asn1p_expr_t *t) {
    if(!t) return NULL;
    for(size_t i = 0; i < sizeof g_string_info / sizeof g_string_info[0]; i++)
        if(g_string_info[i].expr_type == (int)t->expr_type)
            return g_string_info[i].ctype;
    return NULL;
}

go_string_sub_e
go_string_subkind(const asn1p_expr_t *t) {
    if(t && t->expr_type == ASN_STRING_BMPString) return GO_STR_BMP;
    if(t && t->expr_type == ASN_STRING_UniversalString) return GO_STR_UNIVERSAL;
    return GO_STR_PLAIN;
}

const char *
go_construct_name_of(const asn1p_expr_t *t) {
    go_construct_e k = go_construct_classify(t);
    if(k == GO_CONSTR_STRING) {
        const char *n = ASN_EXPR_TYPE2STR(t->expr_type);
        if(n) return n;
    }
    return go_construct_name(k);
}

/* ------------------------------------------------------------------------- */
/*
 * classify() maps a *terminal* expression to a kind. The caller has already
 * resolved references (open type, fixed-type class field, plain type ref) and
 * produced the terminal here. meta_type drives the IOC cases; expr_type drives
 * everything else. Anything off the supported list (SET, ...) falls through to UNSUPPORTED.
 *
 * NOTE: GO_CONSTR_OPEN_TYPE and GO_CONSTR_RECURSIVE_REF are NOT produced here.
 * OPEN_TYPE is a reference-shape (lower/uppercase &field), decided before
 * terminal-chasing (go_walk.c). RECURSIVE_REF is a marker attribute, not a
 * terminal kind. So this function returns the terminal's type kind.
 */
go_construct_e
go_construct_classify(const asn1p_expr_t *t) {
    if(t == NULL) return GO_CONSTR_UNSUPPORTED;

    /* IOC: object class / object set are meta-typed, not expr-typed. */
    if(t->meta_type == AMT_OBJECTCLASS) return GO_CONSTR_IOC_CLASS;
    if(t->meta_type == AMT_OBJECT)      return GO_CONSTR_IOC_OBJSET;
    if(t->meta_type == AMT_VALUESET)    return GO_CONSTR_IOC_OBJSET;

    switch(t->expr_type) {
    /* Constructed records. */
    case ASN_CONSTR_SEQUENCE:    return GO_CONSTR_SEQUENCE;
    case ASN_CONSTR_CHOICE:      return GO_CONSTR_CHOICE;
    case ASN_CONSTR_SEQUENCE_OF:
    case ASN_CONSTR_SET_OF:      return GO_CONSTR_SEQUENCE_OF;
    case ASN_CONSTR_SET:         /* rejected */
        return GO_CONSTR_UNSUPPORTED;

    /* Basic leaves. */
    case ASN_BASIC_BOOLEAN:      return GO_CONSTR_BOOLEAN;
    case ASN_BASIC_NULL:         return GO_CONSTR_NULL;
    case ASN_BASIC_INTEGER:      return GO_CONSTR_INTEGER;
    case ASN_BASIC_REAL:         return GO_CONSTR_REAL;
    case ASN_BASIC_ENUMERATED:   return GO_CONSTR_ENUMERATED;
    case ASN_BASIC_OCTET_STRING: return GO_CONSTR_OCTET_STRING;
    case ASN_BASIC_OBJECT_IDENTIFIER:
    case ASN_BASIC_RELATIVE_OID:
        note_oid_use();
        return GO_CONSTR_OID;

    /*
     * BIT STRING, plain or named-bit (`BIT STRING { a(0), b(1) }`): the value
     * type is the same; the identifier children in .members only produce the
     * bit-position constants (go_names.c, emit_bit_names).
     */
    case ASN_BASIC_BIT_STRING:   return GO_CONSTR_BIT_STRING;

    /*
     * Every restricted character string type and the two time types are
     * OCTET STRING in C and `string` in Go (go_string_subkind says whether the
     * glue converts the buffer).
     */
    case ASN_STRING_PrintableString:
    case ASN_STRING_IA5String:
    case ASN_STRING_VisibleString:
    case ASN_STRING_ISO646String:
    case ASN_STRING_NumericString:
    case ASN_STRING_UniversalString:
    case ASN_STRING_BMPString:
    case ASN_STRING_UTF8String:
    case ASN_STRING_GeneralString:
    case ASN_STRING_GraphicString:
    case ASN_STRING_TeletexString:
    case ASN_STRING_T61String:
    case ASN_STRING_VideotexString:
    case ASN_STRING_ObjectDescriptor:
    case ASN_BASIC_UTCTime:
    case ASN_BASIC_GeneralizedTime:
        note_string_use(t->expr_type);
        return GO_CONSTR_STRING;

    /* ANY (deprecated) is not the same as a class open type; reject if seen. */
    case ASN_TYPE_ANY:           return GO_CONSTR_UNSUPPORTED;

    default:
        break;
    }
    return GO_CONSTR_UNSUPPORTED;
}

/* ------------------------------------------------------------------------- */
/*
 * is_open_type — uppercase "&Value" open-type field reference. Mirrors
 * is_open_type() in libasn1compiler/asn1c_C.c:305: a 2-component reference
 * whose second component is RLT_AmpUppercase. The member stays a reference on
 * the post-fix AST; ASN_CONSTR_OPEN_TYPE only exists as a synthesised emit-time
 * node (asn1c_C.c:1071-1108) and is never seen here.
 */
int
go_construct_is_open_type(const asn1p_expr_t *expr) {
    return expr
        && expr->meta_type == AMT_TYPEREF
        && expr->expr_type == A1TC_REFERENCE
        && expr->reference
        && expr->reference->comp_count == 2
        && expr->reference->components[1].lex_type == RLT_AmpUppercase;
}

/* any 2-component class-field reference (&field), upper- or lowercase */
int
go_construct_is_classfield_ref(const asn1p_expr_t *expr) {
    if(!expr
       || expr->meta_type != AMT_TYPEREF
       || expr->expr_type != A1TC_REFERENCE
       || !expr->reference
       || expr->reference->comp_count != 2)
        return 0;
    enum asn1p_ref_lex_type_e lt = expr->reference->components[1].lex_type;
    return lt == RLT_AmpUppercase || lt == RLT_Amplowercase;
}

/* lowercase "&field" fixed-type class-field reference (asn1c_C.c:2653-2655) */
int
go_construct_is_classfield_fixedtype(const asn1p_expr_t *expr) {
    return expr
        && expr->meta_type == AMT_TYPEREF
        && expr->expr_type == A1TC_REFERENCE
        && expr->reference
        && expr->reference->comp_count == 2
        && expr->reference->components[1].lex_type == RLT_Amplowercase;
}

/* ------------------------------------------------------------------------- */
/*
 * No "[[ ... ]]" bracket-group predicate is needed. The C emit pass mints an
 * `ext<N>` Identifier on the shared AST for each bracket group
 * (asn1c-fork/libasn1compiler/asn1c_C.c:378-385 / :618-633:
 * `sprintf(ext_name,"ext%d",...); v->Identifier=strdup(ext_name);` under guard
 * `(ASN_CONSTR_SEQUENCE) && (flags & EM_OPTIONAL) && (Identifier==NULL)`).
 * asn1_compile runs before the Go dispatch (asn1c.c:450), so by the time the
 * walker sees the node it is an OPTIONAL inline SEQUENCE member named ext<N>
 * and takes the ordinary inline-SEQUENCE path: field `Ext<N> *<T>Ext<N>`.
 * The numbering therefore matches C by construction, and the names go through
 * the usual clash finder.
 */
