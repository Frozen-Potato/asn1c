package rt

/*
#include "arena.h"
*/
import "C"

// Unexported cgo shims for this package's own tests (cgo is not allowed in
// _test.go files).

func arenaNew(first uint) *C.asn1cgo_arena { return C.asn1cgo_arena_new(C.size_t(first)) }
func arenaAlloc(a *C.asn1cgo_arena, n, align uint) bool {
	return C.asn1cgo_arena_alloc(a, C.size_t(n), C.size_t(align)) != nil
}
func arenaFree(a *C.asn1cgo_arena) { C.asn1cgo_arena_free(a) }
