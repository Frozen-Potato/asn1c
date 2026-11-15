#ifndef	ASN1C_CONSTRAINT_H
#define	ASN1C_CONSTRAINT_H

int asn1c_emit_constraint_checking_code(arg_t *arg, int type_level);
/* type_level: 1 for <T>_constraint of a type, 0 for memb_<m>_constraint */

#endif	/* ASN1C_CONSTRAINT_H */
