//go:build asn1cgo_faults

package rt

// The asn1cgo_faults build tag compiles the deterministic allocation-fault
// injection (ArenaFailAt / ArenaEvents) into the C arena. Test-only and
// single-threaded; without the tag those hooks are no-ops.

/*
#cgo CFLAGS: -DASN1CGO_ARENA_FAULTS
*/
import "C"
