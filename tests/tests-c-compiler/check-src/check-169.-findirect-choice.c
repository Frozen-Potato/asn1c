/*
 * "struct X" of an alias of an alias (PFL ::= Freq) names the real struct:
 * a PFL_t pointer is assignable to the SEQUENCE/CHOICE members and the
 * pointee is complete.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#pragma GCC diagnostic error "-Wincompatible-pointer-types"

#include <M.h>
#include <C.h>

int
main(int ac, char **av) {
	M_t m;
	C_t c;
	PFL_t *p;

	(void)ac;	/* Unused argument */
	(void)av;	/* Unused argument */

	memset(&m, 0, sizeof(m));
	memset(&c, 0, sizeof(c));

	p = calloc(1, sizeof(PFL_t));
	assert(p);
	p->f = 42;
	m.pf = p;
	assert(m.pf->f == 42);

	p = calloc(1, sizeof(PFL_t));
	assert(p);
	p->f = 16383;
	c.present = C_PR_pf;
	c.choice.pf = p;
	assert(c.choice.pf->f == 16383);

	ASN_STRUCT_RESET(asn_DEF_M, &m);
	ASN_STRUCT_RESET(asn_DEF_C, &c);
	return 0;
}
