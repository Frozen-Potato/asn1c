/*
 * A type-level constraint function must not call itself: constrained aliases
 * of BOOLEAN / INTEGER / REAL / SET OF / SEQUENCE OF return, and still reject
 * a violating value (size of a list, an element out of range).
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <B1.h>
#include <I1.h>
#include <L3.h>
#include <L4.h>
#include <St2.h>
#include <Fl.h>
#include <BLi.h>
#include <T.h>

static int chk(const asn_TYPE_descriptor_t *td, const void *p) {
	return asn_check_constraints(td, p, 0, 0);
}

static void fill_int(void *list, long n) {
	long i;
	for(i = 0; i < n; i++) {
		long *v = calloc(1, sizeof(*v));
		*v = i;
		assert(ASN_SEQUENCE_ADD(list, v) == 0);
	}
}

static void fill_it(BLi_t *l, int n, long val) {
	int i;
	for(i = 0; i < n; i++) {
		long *v = calloc(1, sizeof(*v));
		*v = val;
		assert(ASN_SEQUENCE_ADD(&l->list, v) == 0);
	}
}

int main(void) {
	B1_t b1 = 1;
	I1_t i1 = 12345;
	Fl_t fl = 1.5;
	L3_t l3;
	L4_t l4;
	St2_t st2;
	BLi_t bli;
	T_t t;
	int i;

	alarm(10);	/* a self-calling constraint function must fail, not hang */

	assert(chk(&asn_DEF_B1, &b1) == 0);
	assert(chk(&asn_DEF_I1, &i1) == 0);
	assert(chk(&asn_DEF_Fl, &fl) == 0);

	for(i = 0; i < 2; i++) {
		memset(&l3, 0, sizeof(l3));
		fill_int(&l3, i ? 4 : 3);
		assert(chk(&asn_DEF_L3, &l3) == (i ? -1 : 0));
		ASN_STRUCT_RESET(asn_DEF_L3, &l3);
	}

	for(i = 0; i < 2; i++) {
		memset(&l4, 0, sizeof(l4));
		fill_int(&l4, i ? 3 : 2);
		assert(chk(&asn_DEF_L4, &l4) == (i ? -1 : 0));
		ASN_STRUCT_RESET(asn_DEF_L4, &l4);
	}

	for(i = 0; i < 2; i++) {
		memset(&st2, 0, sizeof(st2));
		fill_int(&st2, i ? 4 : 3);
		assert(chk(&asn_DEF_St2, &st2) == (i ? -1 : 0));
		ASN_STRUCT_RESET(asn_DEF_St2, &st2);
	}

	/* BLi: 4 valid, 5 too many, 4 with an element 300 out of range. */
	memset(&bli, 0, sizeof(bli));
	fill_it(&bli, 4, 7);
	assert(chk(&asn_DEF_BLi, &bli) == 0);
	ASN_STRUCT_RESET(asn_DEF_BLi, &bli);
	fill_it(&bli, 5, 7);
	assert(chk(&asn_DEF_BLi, &bli) == -1);
	ASN_STRUCT_RESET(asn_DEF_BLi, &bli);
	fill_it(&bli, 4, 7);
	*(long *)bli.list.array[2] = 300;
	assert(chk(&asn_DEF_BLi, &bli) == -1);
	ASN_STRUCT_RESET(asn_DEF_BLi, &bli);

	/* T with the OPTIONAL BLi present: valid, then with a bad element. */
	memset(&t, 0, sizeof(t));
	t.a = 1;
	t.b = calloc(1, sizeof(*t.b));
	fill_it(t.b, 2, 1);
	assert(chk(&asn_DEF_T, &t) == 0);
	*(long *)t.b->list.array[1] = 300;
	assert(chk(&asn_DEF_T, &t) == -1);
	ASN_STRUCT_RESET(asn_DEF_T, &t);

	return 0;
}
