#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <Msg.h>

int
main(int ac, char **av) {
	Msg_t m;

	(void)ac;	/* Unused argument */
	(void)av;	/* Unused argument */

	memset(&m, 0, sizeof(m));

	/*
	 * Only checking that asn1c accepts the module under -fcompound-names
	 * (no false name clash) and the generated code compiles.
	 */

	return 0;
}
