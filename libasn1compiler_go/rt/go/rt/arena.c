/*
 * asn1cgo arena implementation.
 *
 * Chunk policy: new chunk size = max(request, 2 x previous), capped
 * at 16 MiB. A chunk is never realloc'd. Within a chunk we bump with natural
 * alignment (round the cursor up to `align`). Align is a power of two.
 */
#include "arena.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ASN1CGO_ARENA_MAX_CHUNK (16u * 1024u * 1024u)  /* 16 MiB cap */
#define ASN1CGO_ARENA_FIRST_DEFAULT 4096u

typedef struct chunk {
    struct chunk *next;
    size_t        cap;     /* usable bytes after `bump` */
    size_t        bump;    /* bytes handed out in this chunk */
    /* payload follows, suitably aligned via max_align_t below */
} chunk;

struct asn1cgo_arena {
    chunk    *head;        /* most-recently-allocated chunk (allocates here) */
    chunk    *tail;        /* oldest, for free walk */
    size_t    last_size;   /* size of last chunk allocated, for growth rule */
    size_t    used;        /* total bytes handed out across all chunks */
};

/* Round `n` up to a multiple of `align` (align is a power of two). */
static inline size_t align_up(size_t n, size_t align) {
    return (n + (align - 1)) & ~(align - 1);
}

/* Payload of a chunk starts after a maximally-aligned chunk header. */
#define HDR (align_up(sizeof(chunk), _Alignof(max_align_t)))

static chunk *chunk_new(size_t cap, chunk *prev_link_into_next) {
    /* `prev_link_into_next`: if non-NULL, its ->next is set to this chunk.
     * Callers wire head->next themselves; kept simple here. */
    (void)prev_link_into_next;
    chunk *c = (chunk *)malloc(HDR + cap);
    if (!c) return NULL;
    c->next = NULL;
    c->cap = cap;
    c->bump = 0;
    return c;
}


/* Balance counter (see arena.h). Relaxed atomics: arenas are created and
 * freed from many goroutines concurrently, so the counter must not race. The
 * value is exact only when no new/free calls are in flight. */
static _Atomic long arena_live = 0;

/* Fault injection is TEST-ONLY and single-threaded, and compiled in only
 * under ASN1CGO_ARENA_FAULTS (Go build tag asn1cgo_faults). Without it
 * asn1cgo_arena_fail_at() is a no-op, asn1cgo_arena_events() returns 0 and
 * no per-allocation counter exists on the hot path. */
#ifdef ASN1CGO_ARENA_FAULTS
static long arena_fail_ctr = 0;      /* allocation events since fail_at set */
static long arena_fail_at_n = 0;     /* 0 = injection off (counting on) */
static unsigned long arena_events_total = 0;  /* events since fail_at(0) arm */

#define ARENA_EVENT_FAILS() (arena_fail_at_n > 0 && ++arena_fail_ctr >= arena_fail_at_n)
#define ARENA_EVENT() (arena_events_total++)

void asn1cgo_arena_fail_at(long n) { arena_fail_ctr = 0; arena_fail_at_n = n; arena_events_total = 0; }
unsigned long asn1cgo_arena_events(void) { return arena_events_total; }
#else
#define ARENA_EVENT_FAILS() 0
#define ARENA_EVENT() ((void)0)

void asn1cgo_arena_fail_at(long n) { (void)n; }
unsigned long asn1cgo_arena_events(void) { return 0; }
#endif

long asn1cgo_arena_balance(void) {
    return atomic_load_explicit(&arena_live, memory_order_relaxed);
}

asn1cgo_arena *asn1cgo_arena_new(size_t first_chunk) {
    ARENA_EVENT();
    if (ARENA_EVENT_FAILS()) return NULL;
    asn1cgo_arena *a = (asn1cgo_arena *)calloc(1, sizeof(*a));
    if (!a) return NULL;
    if (first_chunk == 0) first_chunk = ASN1CGO_ARENA_FIRST_DEFAULT;
    ARENA_EVENT();                       /* the first chunk is an event too */
    a->head = a->tail = ARENA_EVENT_FAILS() ? NULL : chunk_new(first_chunk, NULL);
    if (!a->head) { free(a); return NULL; }
    a->last_size = first_chunk;
    /* Count the arena live only once it fully exists, so a failed
     * construction never leaves the balance off by one. */
    atomic_fetch_add_explicit(&arena_live, 1, memory_order_relaxed);
    return a;
}

void *asn1cgo_arena_alloc(asn1cgo_arena *a, size_t n, size_t align) {
    if (!a || n == 0) return NULL;
    if (align == 0) align = 1;
    ARENA_EVENT();
    if (ARENA_EVENT_FAILS()) return NULL;

    /* Relative offset of the payload base, usable for pointer math. */
    unsigned char *base = (unsigned char *)a->head + HDR;
    size_t cursor = align_up(a->head->bump, align);

    /* Need a new chunk? */
    if (cursor + n > a->head->cap) {
        size_t want = n + align;                /* room for alignment slack */
        size_t grow = a->last_size * 2;
        size_t next = want > grow ? want : grow;
        if (next > ASN1CGO_ARENA_MAX_CHUNK) next = ASN1CGO_ARENA_MAX_CHUNK;
        /* If even the cap can't hold this single alloc, fail (no oversized
         * chunks). Sizing pass is expected to keep every node < cap. */
        if (next < want) return NULL;

        chunk *c = chunk_new(next, NULL);
        if (!c) return NULL;
        a->head->next = c;     /* head becomes the new chunk */
        a->head = c;
        a->last_size = next;
        base = (unsigned char *)a->head + HDR;
        cursor = 0;            /* fresh chunk, first alloc is aligned to base */
    }

    void *p = base + cursor;
    a->head->bump = cursor + n;
    a->used += n;
    memset(p, 0, n);
    return p;
}

void asn1cgo_arena_free(asn1cgo_arena *a) {
    if (!a) return;
    atomic_fetch_sub_explicit(&arena_live, 1, memory_order_relaxed);
    chunk *c = a->tail;
    while (c) {
        chunk *nx = c->next;
        free(c);
        c = nx;
    }
    free(a);
}

size_t asn1cgo_arena_used(const asn1cgo_arena *a) {
    return a ? a->used : 0;
}
