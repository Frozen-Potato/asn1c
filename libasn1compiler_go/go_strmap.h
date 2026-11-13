/*
 * go_strmap.h — a minimal string-keyed hash map (open addressing, FNV-1a)
 * and a length-tracking string buffer, shared by go_flat.c and go_glue.c.
 * Keys are copied; values are plain ints (an index, or 0/-1 for "none").
 * Both are static-inline so each TU carries its own copy.
 */
#ifndef GO_STRMAP_H
#define GO_STRMAP_H

#include <stdlib.h>
#include <string.h>

typedef struct {
    char **key;
    int *val;
    size_t cap, n;     /* cap is a power of two (or 0) */
} gsmap;

static inline size_t
gsmap_hash(const char *s) {
    size_t h = 1469598103934665603ULL;
    for(; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

static inline void
gsmap_free(gsmap *m) {
    for(size_t i = 0; i < m->cap; i++) free(m->key[i]);
    free(m->key); free(m->val);
    m->key = NULL; m->val = NULL; m->cap = m->n = 0;
}

/* 1 = found (*val set), 0 = absent. */
static inline int
gsmap_get(const gsmap *m, const char *k, int *val) {
    if(!m->cap) return 0;
    for(size_t i = gsmap_hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        if(!m->key[i]) return 0;
        if(strcmp(m->key[i], k) == 0) { *val = m->val[i]; return 1; }
    }
}

/* Insert k -> v unless k is already present (first insert wins). 0 on OOM. */
static inline int
gsmap_put_first(gsmap *m, const char *k, int v) {
    if((m->n + 1) * 2 > m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 64;
        char **nk = calloc(nc, sizeof *nk);
        int *nv = calloc(nc, sizeof *nv);
        if(!nk || !nv) { free(nk); free(nv); return 0; }
        for(size_t i = 0; i < m->cap; i++) {
            if(!m->key[i]) continue;
            size_t j = gsmap_hash(m->key[i]) & (nc - 1);
            while(nk[j]) j = (j + 1) & (nc - 1);
            nk[j] = m->key[i]; nv[j] = m->val[i];
        }
        free(m->key); free(m->val);
        m->key = nk; m->val = nv; m->cap = nc;
    }
    size_t i = gsmap_hash(k) & (m->cap - 1);
    for(;; i = (i + 1) & (m->cap - 1)) {
        if(!m->key[i]) break;
        if(strcmp(m->key[i], k) == 0) return 1;
    }
    char *kd = strdup(k);
    if(!kd) return 0;
    m->key[i] = kd; m->val[i] = v; m->n++;
    return 1;
}

/* key -> ordered list of ints (insertion order kept). */
typedef struct {
    gsmap ix;
    int **l;
    int *n, *cap;
    int cnt;
} gsmulti;

static inline void
gsmulti_free(gsmulti *m) {
    for(int i = 0; i < m->cnt; i++) free(m->l[i]);
    free(m->l); free(m->n); free(m->cap);
    gsmap_free(&m->ix);
    memset(m, 0, sizeof *m);
}

static inline int
gsmulti_add(gsmulti *m, const char *k, int v) {
    int id;
    if(!gsmap_get(&m->ix, k, &id)) {
        int *nn = realloc(m->n, ((size_t)m->cnt + 1) * sizeof(int));
        if(nn) m->n = nn;
        int *nc = realloc(m->cap, ((size_t)m->cnt + 1) * sizeof(int));
        if(nc) m->cap = nc;
        int **nl = realloc(m->l, ((size_t)m->cnt + 1) * sizeof(int *));
        if(nl) m->l = nl;
        if(!nn || !nc || !nl) return 0;
        id = m->cnt;
        m->l[id] = NULL; m->n[id] = 0; m->cap[id] = 0;
        if(!gsmap_put_first(&m->ix, k, id)) return 0;
        m->cnt++;
    }
    if(m->n[id] == m->cap[id]) {
        int c = m->cap[id] ? m->cap[id] * 2 : 4;
        int *x = realloc(m->l[id], (size_t)c * sizeof(int));
        if(!x) return 0;
        m->l[id] = x; m->cap[id] = c;
    }
    m->l[id][m->n[id]++] = v;
    return 1;
}

/* The list for k (NULL, *n = 0 when absent). */
static inline const int *
gsmulti_get(const gsmulti *m, const char *k, int *n) {
    int id;
    if(!gsmap_get(&m->ix, k, &id)) { *n = 0; return NULL; }
    *n = m->n[id];
    return m->l[id];
}

/* Growable string buffer that tracks its length (amortized O(1) append). */
typedef struct { char *p; size_t len, cap; } gsb;

static inline int
gsb_add(gsb *b, const char *s, size_t n) {
    if(b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while(nc < b->len + n + 1) nc *= 2;
        char *r = realloc(b->p, nc);
        if(!r) return 0;
        b->p = r; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 1;
}

static inline int gsb_adds(gsb *b, const char *s) { return gsb_add(b, s, strlen(s)); }

/* The contents as an owned string (never NULL); the buffer is emptied. */
static inline char *
gsb_take(gsb *b) {
    char *r = b->p ? b->p : strdup("");
    b->p = NULL; b->len = b->cap = 0;
    return r;
}

#endif
