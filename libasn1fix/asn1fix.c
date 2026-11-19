#include "asn1fix_internal.h"
#include "asn1fix.h"

/* Print everything to stderr */
static void _default_error_logger(int _severity, const char *fmt, ...);

/*
 * Internal check functions.
 */
static int asn1f_fix_module__phase_1(arg_t *arg);
static int asn1f_fix_module__phase_2(arg_t *arg);
static int asn1f_fix_simple(arg_t *arg);	/* For INTEGER/ENUMERATED */
static int asn1f_fix_constructed(arg_t *arg);	/* For SEQUENCE/SET/CHOICE */
static int asn1f_resolve_constraints(arg_t *arg); /* For subtype constraints */
static int asn1f_check_constraints(arg_t *arg);	/* For subtype constraints */
static int asn1f_check_duplicate(arg_t *arg);
static int asn1f_apply_unique_index(arg_t *arg);
static int phase_1_1(arg_t *arg, int prm2);
static int asn1f_fix_late_specializations(arg_t *arg, int with_phase_2);
static void asn1f_clear_spec_marks(asn1p_t *asn);

/*
 * Marks on the root of a specialization (the clone of a parameterized type
 * made for one set of actual parameters), private to asn1f_process():
 * set when phase I (phase_1_1) and phase II (unique indexes) have processed
 * it. A specialization made after that phase passed its parameterized type
 * (first used from another module, or from a type defined after it) gets
 * the phase late, from asn1f_fix_late_specializations().
 */
#define    A1F_SPEC_PHASE1    (1u << 14)
#define    A1F_SPEC_PHASE2    (1u << 15)
#define    A1F_IS_SPEC_ROOT(e)    ((e)->spec_index >= 0)

static int a1f_unique_index;

arg_t a1f_replace_me_with_proper_interface_arg;

/*
 * Scan every module defined here in search for inconsistences.
 */
int
asn1f_process(asn1p_t *asn, enum asn1f_flags flags,
		error_logger_f error_logger) {
	arg_t arg;
	int fatals = 0;
	int warnings = 0;
	int ret;

	/*
	 * Check validity of arguments.
	 */
	if(asn == NULL) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * If errors handler is not specified, default to internal one.
	 */
	if(error_logger == 0) {
		error_logger = _default_error_logger;
	}

	memset(&arg, 0, sizeof(arg));
	arg.asn = asn;
	arg.eh = error_logger;

	if(flags & A1F_DEBUG) {
		arg.debug = arg.eh;
		arg.debug(-1, "Called %s() with flags %d", __func__, flags);
		flags &= ~A1F_DEBUG;
	}

	/* Allow SIZE() constraint for INTEGER and other types */
	if(flags & A1F_EXTENDED_SizeConstraint) {
		arg.flags |= A1F_EXTENDED_SizeConstraint;
		flags &= ~A1F_EXTENDED_SizeConstraint;
		if(arg.debug) {
			arg.debug(-1,
				"Extended SizeConstraint support enabled");
		}
	}

	a1f_replace_me_with_proper_interface_arg = arg;

	/*
	 * Check that we haven't missed an unknown flag.
	 */
	if(flags) {
		errno = EINVAL;
		return -1;
	}

    /*
     * Process each module in the list.
     * PHASE I.
     */
    TQ_FOR(arg.mod, &(asn->modules), mod_next) {
        arg.ns = asn1_namespace_new_from_module(arg.mod, 0);
        ret = asn1f_fix_module__phase_1(&arg);
        /*
         * These lines are used for illustration purposes.
         * RET2RVAL() is used everywhere else.
         */
        if(ret == -1) fatals++;
        if(ret == 1) warnings++;
        asn1_namespace_free(arg.ns);
        arg.ns = 0;
    }
    /* Specializations first used from a later module. */
    if(asn1f_fix_late_specializations(&arg, 0) == -1) fatals++;
    /* PHASE II. */
    TQ_FOR(arg.mod, &(asn->modules), mod_next) {
        arg.ns = asn1_namespace_new_from_module(arg.mod, 0);
        ret = asn1f_fix_module__phase_2(&arg);
        if(ret == -1) fatals++;
        if(ret == 1) warnings++;
        asn1_namespace_free(arg.ns);
        arg.ns = 0;
    }
    /* Specializations made during phase II (both phases). */
    ret = asn1f_fix_late_specializations(&arg, 1);
    if(ret == -1) fatals++;
    if(ret == 1) warnings++;
    asn1f_clear_spec_marks(asn);

    memset(&a1f_replace_me_with_proper_interface_arg, 0, sizeof(arg_t));

	/*
	 * Compute a return value.
	 */
	return fatals?-1:warnings?1:0;
}

/*
 * Check the internals of a single module.
 */
static int
asn1f_fix_module__phase_1(arg_t *arg) {
	asn1p_expr_t *expr;
	int rvalue = 0;
	int ret;
	asn1p_module_t *omod;

	/*
	 * Check that we don't have a similarly named module.
	 */
	TQ_FOR(omod, &arg->asn->modules, mod_next) {
		int sameNames;
		if(omod == arg->mod) break;
		sameNames = strcmp(omod->ModuleName, arg->mod->ModuleName)?0:1;
		if(omod->module_oid && arg->mod->module_oid) {
			/* Compare only the OID. */
			if(asn1p_oid_compare(omod->module_oid,
					arg->mod->module_oid) == 0) {
				FATAL("ASN.1 module %s in %s "
					"has the same OBJECT IDENTIFIER"
					" as module %s",
					omod->ModuleName,
					omod->source_file_name,
					arg->mod->ModuleName
				);
				RET2RVAL(-1, rvalue);
			} else if(sameNames) {
				WARNING("ASN.1 module %s is defined more than once, with different OIDs", omod->ModuleName);
				RET2RVAL(1, rvalue);
			}
		} else if(sameNames) {
			FATAL("ASN.1 module %s is defined more than once",
				omod->ModuleName);
			RET2RVAL(-1, rvalue);
		}
	}

	switch((arg->mod->module_flags & MSF_MASK_TAGS)) {
	case MSF_NOFLAGS:
	case MSF_EXPLICIT_TAGS:
	case MSF_IMPLICIT_TAGS:
	case MSF_AUTOMATIC_TAGS:
		break;
	default:
		FATAL("Module %s defined with ambiguous global tagging mode",
			arg->mod->ModuleName);
		RET2RVAL(-1, rvalue);
	}

	switch((arg->mod->module_flags & MSF_MASK_INSTRUCTIONS)) {
	case MSF_NOFLAGS:
		/*
		 * arg->mod->module_flags |= MSF_TAG_INSTRUCTIONS;
		 */
		break;
	case MSF_unk_INSTRUCTIONS:
		WARNING("Module %s defined with unrecognized "
			"encoding reference", arg->mod->ModuleName);
		RET2RVAL(1, rvalue);
		/* Fall through */
	case MSF_TAG_INSTRUCTIONS:
	case MSF_XER_INSTRUCTIONS:
		break;
	default:
		FATAL("Module %s defined with ambiguous encoding reference",
			arg->mod->ModuleName);
		RET2RVAL(-1, rvalue);
	}

	/*
	 * Do various non-recursive transformations.
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		arg->expr = expr;
		ret = phase_1_1(arg, 0);
		RET2RVAL(ret, rvalue);
		/*
		 * Make sure everybody's behaving well.
		 */
		assert(arg->expr == expr);
	}
	TQ_FOR(expr, &(arg->mod->members), next) {
		arg->expr = expr;
		ret = phase_1_1(arg, 1);
		RET2RVAL(ret, rvalue);
		assert(arg->expr == expr);
	}



	/*
	 * 5. Automatic tagging
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {

		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_fix_constr_autotag);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	/*
	 * 8. fix BIT STRING
	 * 9. fix spaces in cstrings
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_fix_bit_string);
		RET2RVAL(ret, rvalue);

		ret = asn1f_recurse_expr(arg, asn1f_fix_cstring);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	/*
	 * ... Check for tags distinctness.
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_check_constr_tags_distinct);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	return rvalue;
}

static int
asn1f_fix_module__phase_2(arg_t *arg) {
	asn1p_expr_t *expr;
	int rvalue = 0;
	int ret;

	TQ_FOR(expr, &(arg->mod->members), next) {

		arg->expr = expr;

		/*
		 * Dereference DEFAULT values.
		 */
		ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_defaults);
		RET2RVAL(ret, rvalue);

		/*
		 * Resolve references in constraints (the second pass).
		 */
		ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
		RET2RVAL(ret, rvalue);

		/*
		 * Check semantic validity of constraints.
		 */
		ret = asn1f_recurse_expr(arg, asn1f_check_constraints);
		RET2RVAL(ret, rvalue);

		/*
		 * Uniquely tag each inner type.
		 */
		asn1f_apply_unique_index(0);
		ret = asn1f_recurse_expr(arg, asn1f_apply_unique_index);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	return rvalue;
}

static int
phase_1_1(arg_t *arg, int prm2) {
	asn1p_expr_t *expr = arg->expr;
	int rvalue = 0;
	int ret;

	if(expr->lhs_params && expr->spec_index == -1) {
		int i;
		if(!prm2)
			/* Do not process the parameterized type just yet */
			return 0;
		for(i = 0; i < expr->specializations.pspecs_count; i++) {
			arg->expr = expr->specializations.pspec[i].my_clone;
			ret = phase_1_1(arg, 0);
			RET2RVAL(ret, rvalue);
		}
		arg->expr = expr;	/* revert */
		return rvalue;
	} else if(prm2) {
		return 0;	/* Already done! */
	}
	if(A1F_IS_SPEC_ROOT(expr))
		expr->_mark |= A1F_SPEC_PHASE1;

	/* Check whether this type is a duplicate */
	if(!expr->lhs_params) {
		ret = asn1f_check_duplicate(arg);
		RET2RVAL(ret, rvalue);
	}

	DEBUG("=== Now processing \"%s\" (%d/0x%x) at line %d ===",
		expr->Identifier, expr->meta_type, expr->expr_type,
		expr->_lineno);
	assert(expr->meta_type != AMT_INVALID);

	/*
	 * 2.1 Pre-process simple types (ENUMERATED, INTEGER, etc).
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_simple);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.5.4
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_types);
	RET2RVAL(ret, rvalue);

	/*
	 * Fix tagging of top-level types.
	 */
	ret = asn1f_fix_constr_tag(arg, 1);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.[234] Process SEQUENCE/SET/CHOICE types.
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_constructed);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.5.5
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_values);
	RET2RVAL(ret, rvalue);

	/*
	 * Resolve references in constraints.
	 */
	ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
	RET2RVAL(ret, rvalue);

	/*
	 * Parse class information object sets.
	 */
	ret = asn1f_parse_class_object(arg);
	RET2RVAL(ret, rvalue);

	/*
	 * 6. INTEGER value processed at 2.5.4.
	 */

	return rvalue;
}

static int
asn1f_fix_simple(arg_t *arg) {
	int rvalue = 0;
	int ret;

	ret = asn1f_fix_enum(arg);
	RET2RVAL(ret, rvalue);

	ret = asn1f_fix_integer(arg);
	RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_fix_constructed(arg_t *arg) {
	int rvalue = 0;
	int ret;

	switch(arg->expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		break;
	default:
		return 0;
	}

	/* Check identifier distinctness */
	ret = asn1f_check_unique_expr(arg);
	RET2RVAL(ret, rvalue);

	/* Fix extensibility */
	ret = asn1f_fix_constr_ext(arg);
	RET2RVAL(ret, rvalue);

	/* Fix tagging */
	ret = asn1f_fix_constr_tag(arg, 0);
	RET2RVAL(ret, rvalue);

	/* Import COMPONENTS OF stuff */
	ret = asn1f_pull_components_of(arg);
	RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_resolve_constraints(arg_t *arg) {
	asn1p_expr_t *top_parent;
	asn1p_expr_type_e etype;
	int rvalue = 0;
	int ret;

	top_parent = asn1f_find_terminal_type(arg, arg->expr);
	if(top_parent)
		etype = top_parent->expr_type;
	else	etype = A1TC_INVALID;

	DEBUG("(%s)", arg->expr->Identifier);

    ret = asn1constraint_resolve(arg, arg->expr->constraints, etype, 0);
    RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_check_constraints(arg_t *arg) {
	static enum asn1p_constraint_type_e test_types[] = {
		ACT_EL_RANGE, ACT_CT_SIZE, ACT_CT_FROM };
	asn1p_expr_t *top_parent;
	asn1cnst_range_t *range;
	asn1p_expr_type_e etype;
	unsigned int i;
	int rvalue = 0;
	int ret;

	DEBUG("(%s{%d/%d})",
		arg->expr->Identifier,
		arg->expr->meta_type, arg->expr->expr_type);

	top_parent = asn1f_find_terminal_type(arg, arg->expr);
	if(!top_parent)
		return 0;
	etype = top_parent->expr_type;

	ret = asn1constraint_pullup(arg);
	RET2RVAL(ret, rvalue);

	for(i = 0; i < sizeof(test_types)/sizeof(test_types[0]); i++) {
		range = asn1constraint_compute_constraint_range(
				arg->expr->Identifier,
				etype,
				arg->expr->combined_constraints,
				test_types[i], 0, 0,
				CPR_noflags /* ignore -fbless-SIZE */);
		if(!range && errno == EPERM) {
			FATAL("This error happened for \"%s\" (meta %d) "
				"at line %d",
				arg->expr->Identifier,
				arg->expr->meta_type,
				arg->expr->_lineno);
			return -1;
		}
		asn1constraint_range_free(range);
	}

	return rvalue;
}

static int
asn1f_check_duplicate(arg_t *arg) {
	arg_t tmparg = *arg;
	int rvalue = 0;

	/*
	 * This is a linear scan in search of a similar type.
	 * The linear scan is just fine for the task, no need to over-optimize.
	 */
	TQ_FOR(tmparg.mod, &arg->asn->modules, mod_next) {
		int critical = 1;	/* FATAL */

		if((arg->mod->_tags & MT_STANDARD_MODULE)
		!= (tmparg.mod->_tags & MT_STANDARD_MODULE)) {
			/* Ignore clashes with standard module */
			critical = 0;	/* WARNING */
		}

		TQ_FOR(tmparg.expr, &(tmparg.mod->members), next) {
			int diff_files;	/* different files */

			assert(tmparg.expr->Identifier);
			assert(arg->expr->Identifier);

			if(arg->expr->spec_index != -1)
				continue;

			if(tmparg.expr == arg->expr) break;

			if(strcmp(tmparg.expr->Identifier,
				  arg->expr->Identifier))
				continue;

			/* resolve clash of Identifier in different modules */
			int oid_exist = (tmparg.expr->module->module_oid && arg->expr->module->module_oid);
			if ((!oid_exist && strcmp(tmparg.expr->module->ModuleName, arg->expr->module->ModuleName)) ||
				(oid_exist && !asn1p_oid_compare(tmparg.expr->module->module_oid, arg->expr->module->module_oid))) {

				tmparg.expr->_mark |= TM_NAMECLASH;
				arg->expr->_mark |= TM_NAMECLASH;
				continue;
			}

			diff_files = strcmp(arg->mod->source_file_name,
					tmparg.mod->source_file_name) ? 1 : 0;

			LOG(critical,
			"ASN.1 expression \"%s\" at line %d of module %s\n"
			"clashes with expression \"%s\" at line %d of module %s"
			"%s%s%s.\n"
			"Rename or remove either instance "
				"to resolve the conflict",
				arg->expr->Identifier,
				arg->expr->_lineno,
				arg->mod->ModuleName,
				tmparg.expr->Identifier,
				tmparg.expr->_lineno,
				tmparg.mod->ModuleName,
				diff_files ? " (" : "",
				diff_files ? tmparg.mod->source_file_name : "",
				diff_files ? ")" : "");
			if(critical)
				return -1;
			RET2RVAL(1, rvalue);
		}
		if(tmparg.mod == arg->mod) break;
	}

	return rvalue;
}

static int
asn1f_apply_unique_index(arg_t *arg) {
	if(!arg) { a1f_unique_index = 0; return 0; }

	if(A1F_IS_SPEC_ROOT(arg->expr))
		arg->expr->_mark |= A1F_SPEC_PHASE2;
	arg->expr->_type_unique_index = ++a1f_unique_index;

	return 0;
}

/* The largest unique index in expr, its members and its specializations */
static int
asn1f_max_unique_index(asn1p_expr_t *expr) {
    asn1p_expr_t *m;
    int max = expr->_type_unique_index;
    int i, v;
    for(i = 0; i < expr->specializations.pspecs_count; i++) {
        v = asn1f_max_unique_index(expr->specializations.pspec[i].my_clone);
        if(v > max) max = v;
    }
    TQ_FOR(m, &(expr->members), next) {
        v = asn1f_max_unique_index(m);
        if(v > max) max = v;
    }
    return max;
}

/*
 * Run phase I (and with with_phase_2, phase II) on every specialization that
 * missed it: a parameterized type defined in one module and first used from
 * a later one is cloned after its own module was processed, and a clone made
 * while phase II walks a type can belong to a type the walk already passed.
 * Without this the clone kept unresolved constraints and unique index 0, and
 * the C code referred to undefined asn_PER_memb_<x>_constr_0 tables.
 * Repeats until no new specialization appears (fixing one may create others).
 */
static int
asn1f_fix_late_specializations(arg_t *arg, int with_phase_2) {
    asn1p_module_t *mod;
    asn1p_expr_t *expr;
    int rvalue = 0;
    int progress;
    int ret;
    int i;

    do {
        progress = 0;
        TQ_FOR(mod, &(arg->asn->modules), mod_next) {
            arg->mod = mod;
            arg->ns = asn1_namespace_new_from_module(mod, 0);
            TQ_FOR(expr, &(mod->members), next) {
                if(!expr->lhs_params || expr->spec_index != -1)
                    continue;
                for(i = 0; i < expr->specializations.pspecs_count; i++) {
                    asn1p_expr_t *clone =
                        expr->specializations.pspec[i].my_clone;
                    arg->expr = clone;
                    if(!(clone->_mark & A1F_SPEC_PHASE1)) {
                        progress = 1;
                        ret = phase_1_1(arg, 0);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg,
                            asn1f_fix_constr_autotag);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg, asn1f_fix_bit_string);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg, asn1f_fix_cstring);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg,
                            asn1f_check_constr_tags_distinct);
                        RET2RVAL(ret, rvalue);
                        clone->_mark |= A1F_SPEC_PHASE1;
                    }
                    if(with_phase_2 && !(clone->_mark & A1F_SPEC_PHASE2)) {
                        progress = 1;
                        ret = asn1f_recurse_expr(arg,
                            asn1f_fix_dereference_defaults);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
                        RET2RVAL(ret, rvalue);
                        ret = asn1f_recurse_expr(arg, asn1f_check_constraints);
                        RET2RVAL(ret, rvalue);
                        /* Continue the numbering of the parameterized type */
                        a1f_unique_index = asn1f_max_unique_index(expr);
                        ret = asn1f_recurse_expr(arg, asn1f_apply_unique_index);
                        RET2RVAL(ret, rvalue);
                        clone->_mark |= A1F_SPEC_PHASE2;
                    }
                }
            }
            asn1_namespace_free(arg->ns);
            arg->ns = 0;
            if(rvalue == -1) return -1;
        }
    } while(progress);

    return rvalue;
}

static void
asn1f_clear_spec_marks(asn1p_t *asn) {
    asn1p_module_t *mod;
    asn1p_expr_t *expr;
    int i;
    TQ_FOR(mod, &(asn->modules), mod_next) {
        TQ_FOR(expr, &(mod->members), next) {
            for(i = 0; i < expr->specializations.pspecs_count; i++)
                expr->specializations.pspec[i].my_clone->_mark &=
                    ~(A1F_SPEC_PHASE1 | A1F_SPEC_PHASE2);
        }
    }
}

/*
 * Print everything to stderr
 */
static void
_default_error_logger(int _severity, const char *fmt, ...) {
	va_list ap;
	char *pfx = "";

	switch(_severity) {
	case -1: pfx = "DEBUG: "; break;
	case 0: pfx = "WARNING: "; break;
	case 1: pfx = "FATAL: "; break;
	}
	
	fprintf(stderr, "%s", pfx);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
