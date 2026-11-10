/*
 * asn1cgo_buf_free — the ONE shared definition for generated trees: each
 * spec's entry .c carries only the asn1cgo_buf typedef; generated spec
 * packages never define this (the staging units keep their own
 * local definitions and link WITHOUT this file). This file is therefore
 * source-only: it ships in the generated/rt module, never in the
 * the staging comparison set (an RTDIR glob over the staging rt dir
 * would double-define against every unit's local copy).
 */
#include <stdlib.h>
#include <stdint.h>

typedef struct { uint8_t *buf; size_t len; } asn1cgo_rt_buf;

void asn1cgo_buf_free(void *b) {
    if (b) free(((asn1cgo_rt_buf *)b)->buf);
}
