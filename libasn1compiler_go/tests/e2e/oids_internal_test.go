// Internal test of the OBJECT IDENTIFIER / RELATIVE-OID glue helpers of the
// generated package oids (tests/e2e/oids.asn). Copied into the oids package
// directory by tests/run-e2e.sh (the helpers and the XER entry points are
// unexported).
//
// It covers what the public API cannot reach: a C buffer whose length is not
// a multiple of 4 (the converters always write whole arcs), the write/read
// pair on a real arena, and the XER encoder, which is the C runtime's dotted
// text.
package oids

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
)

type bytesRec struct {
	buf *byte
	n   uintptr
}

func TestReadOIDFieldErrors(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 7, 101} {
		b := make([]byte, n)
		r := &bytesRec{buf: &b[0], n: uintptr(n)}
		a, err := readOIDField(unsafe.Pointer(r))
		var re *rt.Error
		if !errors.As(err, &re) || !errors.Is(err, rt.ErrDecode) || !strings.Contains(re.Message, "not a multiple of 4") {
			t.Errorf("length %d: err = %v, want an rt.ErrDecode about a multiple of 4", n, err)
		}
		if a != nil {
			t.Errorf("length %d: returned %v with an error", n, a)
		}
	}
}

func TestReadOIDFieldValues(t *testing.T) {
	// little endian, one uint32 per arc
	b := []byte{1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12}
	r := &bytesRec{buf: &b[0], n: uintptr(len(b))}
	a, err := readOIDField(unsafe.Pointer(r))
	if err != nil || !reflect.DeepEqual(a, []uint64{1, math.MaxUint32, 0x12345678}) {
		t.Errorf("readOIDField = %v, %v", a, err)
	}
	a, err = readOIDField(unsafe.Pointer(&bytesRec{}))
	if err != nil || a == nil || len(a) != 0 {
		t.Errorf("empty record: %v, %v (want a non-nil empty slice)", a, err)
	}
}

func TestOIDLen(t *testing.T) {
	if n, err := oidLen([]uint64{1, 3, math.MaxUint32}, false); err != nil || n != 12 {
		t.Errorf("oidLen = %d, %v", n, err)
	}
	if n, err := oidLen(nil, true); err != nil || n != 0 {
		t.Errorf("oidLen(nil) = %d, %v", n, err)
	}
	for _, rel := range []bool{false, true} {
		_, err := oidLen([]uint64{1, 3, math.MaxUint32 + 1}, rel)
		var re *rt.Error
		if !errors.As(err, &re) || !errors.Is(err, rt.ErrConstraint) || !strings.Contains(re.Message, "arc 2") {
			t.Errorf("oidLen over 32 bits (rel=%v): %v", rel, err)
		}
		if rel != strings.HasPrefix(re.TypeName, "RELATIVE") {
			t.Errorf("TypeName = %q for rel=%v", re.TypeName, rel)
		}
	}
}

// XER goes through the C runtime: the value is the dotted text, and the
// generated xer functions agree with the C converter (oids_test.go).
func TestOidsXER(t *testing.T) {
	for _, c := range []struct {
		name string
		enc  func() ([]byte, error)
		want string
	}{
		{"oid", func() ([]byte, error) { v := OidTop{1, 3, 6, 1, 4, 1, 53148}; return xerOidTop(&v) }, "<OidTop>1.3.6.1.4.1.53148</OidTop>"},
		{"oid-2-999-1", func() ([]byte, error) { v := OidTop{2, 999, 1}; return xerOidTop(&v) }, "<OidTop>2.999.1</OidTop>"},
		{"roid", func() ([]byte, error) { v := RoidTop{8571, 3, 2}; return xerRoidTop(&v) }, "<RoidTop>8571.3.2</RoidTop>"},
		{"roid-empty", func() ([]byte, error) { v := RoidTop{}; return xerRoidTop(&v) }, "<RoidTop/>"},
	} {
		out, err := c.enc()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		got := strings.TrimSpace(string(out))
		if strings.Replace(got, "></RoidTop>", "/>", 1) != strings.Replace(c.want, "></RoidTop>", "/>", 1) {
			t.Errorf("%s: XER %q, want %q", c.name, got, c.want)
		}
	}
	v := OidTop{1, 3 + 40, 1}
	if _, err := xerOidTop(&v); !errors.Is(err, rt.ErrConstraint) {
		t.Errorf("XER of an invalid OID: err = %v, want rt.ErrConstraint", err)
	}
}
