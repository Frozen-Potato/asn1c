// Internal test of the BMPString / UniversalString glue helpers of the
// generated package strs (tests/e2e/strings.asn). Copied into the strs package
// directory by tests/run-e2e.sh (the helpers are unexported).
//
// It covers what the public API cannot reach: a C buffer with an odd UCS-2
// length or a length that is not a multiple of 4 (APER always counts whole
// characters), and the write/read pair on a real arena.
package strs

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
)

// bytesRec mirrors asn1cgo_bytes_flat {buf, len}.
type bytesRec struct {
	buf *byte
	n   uintptr
}

func recOf(b []byte) *bytesRec {
	r := &bytesRec{n: uintptr(len(b))}
	if len(b) > 0 {
		r.buf = &b[0]
	}
	return r
}

func wantDecErr(t *testing.T, what string, err error, msg string) {
	t.Helper()
	var re *rt.Error
	if !errors.As(err, &re) || !errors.Is(err, rt.ErrDecode) {
		t.Errorf("%s: err = %v, want an rt.ErrDecode *rt.Error", what, err)
		return
	}
	if !strings.Contains(re.Message, msg) {
		t.Errorf("%s: message %q lacks %q", what, re.Message, msg)
	}
}

func TestReadBMPFieldErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		msg  string
	}{
		{"odd-1", []byte{0x00}, "not a multiple of 2"},
		{"odd-3", []byte{0x00, 0x61, 0x00}, "not a multiple of 2"},
		{"odd-long", make([]byte, 101), "not a multiple of 2"},
		{"high-surrogate", []byte{0xD8, 0x00}, "surrogate"},
		{"low-surrogate-last", []byte{0x00, 0x61, 0xDC, 0x00}, "surrogate"},
		{"surrogate-max", []byte{0xDF, 0xFF}, "surrogate"},
	} {
		s, err := readBMPField(unsafe.Pointer(recOf(c.b)))
		wantDecErr(t, c.name, err, c.msg)
		if s != "" {
			t.Errorf("%s: returned %q with an error", c.name, s)
		}
	}
	// the code units either side of the surrogate block are fine
	for _, u := range [][]byte{{0xD7, 0xFF}, {0xE0, 0x00}, {0xFF, 0xFD}, {0xFF, 0xFF}, {0x00, 0x00}} {
		if s, err := readBMPField(unsafe.Pointer(recOf(u))); err != nil || len([]rune(s)) != 1 {
			t.Errorf("% x: %q %v", u, s, err)
		}
	}
	if s, err := readBMPField(unsafe.Pointer(recOf(nil))); s != "" || err != nil {
		t.Errorf("empty: %q %v", s, err)
	}
}

func TestReadUnivFieldErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		msg  string
	}{
		{"len-1", []byte{0x00}, "not a multiple of 4"},
		{"len-2", []byte{0x00, 0x61}, "not a multiple of 4"},
		{"len-3", []byte{0x00, 0x00, 0x61}, "not a multiple of 4"},
		{"len-6", make([]byte, 6), "not a multiple of 4"},
		{"surrogate", []byte{0x00, 0x00, 0xD8, 0x00}, "not a Unicode scalar"},
		{"surrogate-hi", []byte{0x00, 0x00, 0xDF, 0xFF}, "not a Unicode scalar"},
		{"above-10ffff", []byte{0x00, 0x11, 0x00, 0x00}, "not a Unicode scalar"},
		{"top-bit", []byte{0x80, 0x00, 0x00, 0x41}, "not a Unicode scalar"},
		{"all-ones", []byte{0xFF, 0xFF, 0xFF, 0xFF}, "not a Unicode scalar"},
		{"second-bad", []byte{0x00, 0x00, 0x00, 0x61, 0x00, 0x11, 0x00, 0x00}, "not a Unicode scalar"},
	} {
		s, err := readUnivField(unsafe.Pointer(recOf(c.b)))
		wantDecErr(t, c.name, err, c.msg)
		if s != "" {
			t.Errorf("%s: returned %q with an error", c.name, s)
		}
	}
	for _, u := range [][]byte{{0x00, 0x00, 0xD7, 0xFF}, {0x00, 0x00, 0xE0, 0x00}, {0x00, 0x10, 0xFF, 0xFF}, {0x00, 0x00, 0x00, 0x00}} {
		if s, err := readUnivField(unsafe.Pointer(recOf(u))); err != nil || len([]rune(s)) != 1 {
			t.Errorf("% x: %q %v", u, s, err)
		}
	}
	if s, err := readUnivField(unsafe.Pointer(recOf(nil))); s != "" || err != nil {
		t.Errorf("empty: %q %v", s, err)
	}
}

func TestStringLenErrors(t *testing.T) {
	for _, c := range []struct {
		name, s, msg string
		univ         bool
	}{
		{"bmp-non-bmp", "a\U0001D11E", "Basic Multilingual Plane", false},
		{"bmp-bad", "\xff", "not valid UTF-8", false},
		{"bmp-surrogate", "\xed\xa0\x80", "not valid UTF-8", false},
		{"univ-bad", "\xff", "not valid UTF-8", true},
		{"univ-overlong", "\xc0\x80", "not valid UTF-8", true},
		{"univ-surrogate", "\xed\xbf\xbf", "not valid UTF-8", true},
	} {
		var err error
		if c.univ {
			_, err = univLen(c.s)
		} else {
			_, err = bmpLen(c.s)
		}
		var re *rt.Error
		if !errors.As(err, &re) || !errors.Is(err, rt.ErrConstraint) || !strings.Contains(re.Message, c.msg) {
			t.Errorf("%s: err = %v, want rt.ErrConstraint containing %q", c.name, err, c.msg)
		}
	}
	// lengths: 2 bytes / character for BMP, 4 for Universal
	if n, err := bmpLen("é✓￿�"); n != 8 || err != nil {
		t.Errorf("bmpLen = %d, %v", n, err)
	}
	if n, err := univLen("é✓\U0001D11E�"); n != 16 || err != nil {
		t.Errorf("univLen = %d, %v", n, err)
	}
}

// goArena is a blockArena over Go memory: room for one bytes record and n
// payload bytes (no C allocation, so the test file needs no cgo).
func goArena(n uintptr) *blockArena {
	return &blockArena{mem: make([]byte, sizeofBytesFlat+int(n)), fixedEnd: sizeofBytesFlat, payloadCur: sizeofBytesFlat}
}

// The write helpers followed by the read helpers on a real arena return what
// went in, including U+FFFD (which Go's range also yields for invalid UTF-8)
// and U+FFFF / U+10FFFF.
func TestWriteReadBlock(t *testing.T) {
	for _, s := range []string{"", "a", "héllo ✓", "�", "x￿y", strings.Repeat("é", 300)} {
		n, err := bmpLen(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		fa := goArena(n)
		rec := fa.allocStruct(sizeofBytesFlat, alignInt64)
		writeBMPField(fa, rec, s)
		got, err := readBMPField(rec)
		if err != nil || got != s {
			t.Errorf("bmp %q: got %q, %v", s, got, err)
		}
		fa.exact("bmp")
	}
	for _, s := range []string{"", "a", "héllo ✓", "�", "𝄞", "\U0010ffff", strings.Repeat("𝄞", 300)} {
		n, err := univLen(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		fa := goArena(n)
		rec := fa.allocStruct(sizeofBytesFlat, alignInt64)
		writeUnivField(fa, rec, s)
		got, err := readUnivField(rec)
		if err != nil || got != s {
			t.Errorf("univ %q: got %q, %v", s, got, err)
		}
		fa.exact("univ")
	}
}
