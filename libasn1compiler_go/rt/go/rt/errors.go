//go:build amd64

// errors.go — the ONE shared Go error model. The Error
// type, one Code constant per C asn1cgo_err_code, and ONE exported sentinel
// per code live here, in the asn1cgo-rt module, exactly once; every spec
// package returns *rt.Error, so errors.Is works uniformly across specs
// — including a mixed-spec test asserting errors from two spec
// packages against the same sentinel.
//
// The C side of this package is the canonical rt/err.h + err.c (identical
// across every spec package, byte for byte). This file is the single source: the generator copies it into
// every emitted asn1cgo-rt module verbatim; the identity check compares
// the copy to THIS file, never to generator output.
//
// Single cgo surface: the arena bridge functions
// ride here, not in a separate cgo.go. The published preamble carries only
// what consumers need — the include path, the libs the skeleton subset
// links, and the headers. Compile strictness for consumers comes from
// CGO_CFLAGS in the consumer's environment, not from this file.
//
// OER: generated trees made with -no-gen-OER compile their C with
// -DASN_DISABLE_OER_SUPPORT; this module defines it by default too. Trees
// generated with OER enabled also work for APER without any tag (the OER
// codec pointers are just NULL). `-tags asn1cgo_oer` only compiles the
// runtime's OER codec in; the generated Go API is APER-only, so it matters
// only if you call the C OER functions yourself.
package rt

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo !asn1cgo_oer CFLAGS: -DASN_DISABLE_OER_SUPPORT
#cgo LDFLAGS: -lm -lpthread
#include "arena.h"
#include "err.h"
*/
import "C"

// ArenaBalance reports the process-global live-arena count (arena.c's
// balance counter): 0 == every arena created was freed. Tests assert
// this after EVERY decode/error path.
func ArenaBalance() int64 { return int64(C.asn1cgo_arena_balance()) }

// ArenaFailAt arms the deterministic allocation-fault hook
// E_ALLOC injection (n-th rt allocation EVENT returns NULL, 1-based;
// n<=0 disables injection but keeps counting events).
func ArenaFailAt(n int64) { C.asn1cgo_arena_fail_at(C.long(n)) }

// ArenaEvents reports the rt allocation-event count since the last
// ArenaFailAt arm. The sweep reads it after an un-injected run
// (ArenaFailAt(0)) to get that run's total N, then sweeps n = 1..N.
func ArenaEvents() uint64 { return uint64(C.asn1cgo_arena_events()) }

// Code mirrors asn1cgo_err_code one-for-one . The Ok code is
// CodeOk (not Ok): the Err-prefixed names are the SENTINELS below — one
// namespace, twelve members, no collision between a Code const and the
// error value of the same name.
type Code int

const (
	CodeOk            Code = 0
	CodeArg           Code = -1
	CodeAlloc         Code = -2
	CodeConstraint    Code = -3
	CodeEncode        Code = -4
	CodeDecode        Code = -5
	CodeTrailing      Code = -6
	CodeChoiceNothing Code = -7
	CodeChoiceBad     Code = -8
	CodeIOCUnknown    Code = -9
	CodeIOCMismatch   Code = -10
	CodeDepth         Code = -11
	CodeInternal      Code = -12
)

// One exported sentinel per code:
// errors.Is(err, rt.ErrConstraint), errors.Is(err, rt.ErrDecode), ...
// Each is a distinct *codeError value; Is matches by Code, so a sentinel
// from this package matches an *Error returned by ANY spec package.
var (
	ErrArg           = &codeError{CodeArg, "asn1cgo: NULL argument"}
	ErrAlloc         = &codeError{CodeAlloc, "asn1cgo: allocation failed"}
	ErrConstraint    = &codeError{CodeConstraint, "asn1cgo: constraint violation"}
	ErrEncode        = &codeError{CodeEncode, "asn1cgo: encode failed"}
	ErrDecode        = &codeError{CodeDecode, "asn1cgo: decode failed"}
	ErrTrailing      = &codeError{CodeTrailing, "asn1cgo: trailing bytes after PDU"}
	ErrChoiceNothing = &codeError{CodeChoiceNothing, "asn1cgo: CHOICE present == NOTHING"}
	ErrChoiceBad     = &codeError{CodeChoiceBad, "asn1cgo: CHOICE present out of range or alt nil"}
	ErrIOCUnknown    = &codeError{CodeIOCUnknown, "asn1cgo: unknown IOC id"}
	ErrIOCMismatch   = &codeError{CodeIOCMismatch, "asn1cgo: IOC id, value mismatch"}
	ErrDepth         = &codeError{CodeDepth, "asn1cgo: recursion depth exceeded"}
	ErrInternal      = &codeError{CodeInternal, "asn1cgo: internal invariant violated"}
)

// codeError is the sentinel's type: a Code + message pair. Exported
// sentinels are *codeError values; Is compares Codes, not pointers.
type codeError struct {
	code Code
	msg  string
}

func (e *codeError) Error() string { return e.msg }

// Error is the one error type every spec package's glue returns.
// The old per-package asn1cgoError is retired. TypeName/Field
// name the innermost ASN.1 type/member; Message carries the constraint
// path or codec message.
type Error struct {
	Code     Code
	TypeName string
	Field    string
	Message  string
}

func (e *Error) Error() string {
	s := "asn1cgo code=" + itoa(uintptr(-e.Code)) + " type=" + e.TypeName
	if e.Field != "" {
		s += " field=" + e.Field
	}
	if e.Message != "" {
		s += " msg=" + e.Message
	}
	return s
}

// Is matches the exported sentinel of e.Code: errors.Is on a
// returned *Error is true against exactly one rt sentinel.
func (e *Error) Is(target error) bool {
	ce, ok := target.(*codeError)
	if !ok {
		return false
	}
	return e.Code == ce.code
}

// goErr copies a C asn1cgo_err into a fresh *Error. The C struct's type and
// field strings are static strings from the generated/converter code (never
// freed); msg is a fixed in-struct array. The copy is made immediately, so
// nothing aliases C memory beyond the call.
func goErr(cerr *C.asn1cgo_err) error {
	if cerr == nil || cerr.code == 0 {
		return nil
	}
	e := &Error{Code: Code(cerr.code)}
	if cerr.type_name != nil {
		e.TypeName = C.GoString(cerr.type_name)
	}
	if cerr.field != nil {
		e.Field = C.GoString(cerr.field)
	}
	e.Message = C.GoStringN(&cerr.msg[0], C.int(C.asn1cgo_err_msg_len(cerr)))
	return e
}

// itoa is the decimal formatter shared with the glue/layout files (the
// layout.go form; uintptr-typed, values here are always >= 0).
func itoa(v uintptr) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
