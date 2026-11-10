/*
 * asn1cgo arena.
 * Chunked bump allocator. Chunks are a singly-linked list, never realloc'd,
 * so handed-out pointers are stable for the arena's lifetime. All
 * allocations are zero-filled. Used only for Flat/Tree *output*
 * (`_from_tree` results); Tree memory built *to* the codec is calloc/free'd
 * (the arena-free rule), because ASN_STRUCT_FREE -> FREEMEM -> free.
 */
#ifndef ASN1CGO_RT_ARENA_H
#define ASN1CGO_RT_ARENA_H

#include <stddef.h>

typedef struct asn1cgo_arena asn1cgo_arena;

/* NULL on OOM. first_chunk = size of the initial chunk (0 => default). */
asn1cgo_arena *asn1cgo_arena_new(size_t first_chunk);

/* Zeroed; n bytes, aligned to align (power-of-two). NULL on OOM. */
void *asn1cgo_arena_alloc(asn1cgo_arena *, size_t n, size_t align);

/* Frees all chunks; the arena handle is invalid after. */
void asn1cgo_arena_free(asn1cgo_arena *);

/* Bytes handed out so far (for tests / sizing-pass reconciliation). */
size_t asn1cgo_arena_used(const asn1cgo_arena *);


/* ---- Arena balance + fault injection ----
 * Balance: arena_new increments, arena_free decrements a process-global
 * live-arena counter; asn1cgo_arena_balance() == 0 means every arena
 * created was freed (asserted by tests after EVERY path, errors included).
 * Fault hook: asn1cgo_arena_fail_at(n) makes the n-th rt ALLOCATION EVENT
 * return NULL (process lifetime, 1-based; n<=0 disables injection but
 * keeps counting). An "event" is one arena_new call plus each
 * arena_alloc call that passes its !a/n==0 guard — i.e. every rt
 * allocation the E_ALLOC failure paths in the generated code can see.
 * Deterministic E_ALLOC fault injection: the sweep is
 * n = 1..asn1cgo_arena_events() (the event count of the un-injected run,
 * read after asn1cgo_arena_fail_at(0) + the call to survey). */
long asn1cgo_arena_balance(void);
void asn1cgo_arena_fail_at(long n);
unsigned long asn1cgo_arena_events(void);

#endif /* ASN1CGO_RT_ARENA_H */
