/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_random_fill.h>
#include <constr_TYPE.h>

#ifdef	_WIN32
/* The Windows C runtime has no random(3), and its rand() has 15 bits only. */
static long
asn__win_random(void) {
    return (long)((((unsigned long)rand() << 30) ^ ((unsigned long)rand() << 15)
                   ^ (unsigned long)rand())
                  & 0x7fffffffUL);
}
#define	random()	asn__win_random()
#define	ASN__RANDOM_MAX	0x7fffffff
#else
#define	ASN__RANDOM_MAX	RAND_MAX
#endif

int
asn_random_fill(const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
                size_t length) {

    if(td && td->op->random_fill) {
        asn_random_fill_result_t res =
            td->op->random_fill(td, struct_ptr, 0, length);
        return (res.code == ARFILL_OK) ? 0 : -1;
    } else {
        return -1;
    }
}

static uintmax_t
asn__intmax_range(intmax_t lb, intmax_t ub) {
    assert(lb <= ub);
    if((ub < 0) == (lb < 0)) {
        return ub - lb;
    } else if(lb < 0) {
        return 1 + ((uintmax_t)ub + (uintmax_t)-(lb + 1));
    } else {
        assert(!"Unreachable");
        return 0;
    }
}

intmax_t
asn_random_between(intmax_t lb, intmax_t rb) {
    if(lb == rb) {
        return lb;
    } else {
        const uintmax_t intmax_max = ((~(uintmax_t)0) >> 1);
        uintmax_t range = asn__intmax_range(lb, rb);
        uintmax_t value = 0;
        uintmax_t got_entropy = 0;

        assert(ASN__RANDOM_MAX > 0xffffff);    /* Seen 7ffffffd! */
        assert(range < intmax_max);

        for(; got_entropy < range;) {
            got_entropy = (got_entropy << 24) | 0xffffff;
            value = (value << 24) | (random() % 0xffffff);
        }

        return lb + (intmax_t)(value % (range + 1));
    }
}
