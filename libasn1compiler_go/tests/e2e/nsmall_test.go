// "Normally small" values >= 64 (tests/e2e/nsmall.asn): a SEQUENCE with 70
// extension additions (extension bitmap length, X.691 #11.9.3.4), a CHOICE
// with 70 extension alternatives and an ENUMERATED with 70 extension values
// (X.691 #11.6). Mirrors C check-164.
//
// Round-trips through the Go API (APER) at indices 0, 63, 64, 65, 69, compares
// the bytes with HAND-COMPUTED APER/UPER for index 64 (the layouts are
// written out in the C test, tests/tests-c-compiler/check-src/check-164.-gen-PER.c)
// and, when ASN1CGO_C_CONVERTER is set, with the C converter's APER, UPER and
// XER (XER has no exported Go entry point, so it is exercised through the
// converter on the Go-produced APER).
package e2e

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	rt "asn1cgo.test/asn1cgo-rt/rt"
	ns "asn1cgo.test/go/nsmall"
)

var nsIdx = []int{0, 63, 64, 65, 69}

// Hand-computed index-64 encodings (BOOLEAN TRUE payloads), see check-164.
var (
	nsSeqA = []byte{0xE0, 0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x01, 0x80}
	nsSeqU = []byte{0xE8, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00, 0xC0, 0x00}
	nsChA  = []byte{0xC0, 0x01, 0x40, 0x01, 0x80}
	nsChU  = []byte{0xC0, 0x50, 0x00, 0x60, 0x00}
	nsEnA  = []byte{0xC0, 0x01, 0x40}
	nsEnU  = []byte{0xC0, 0x50, 0x00}
)

func nsSeq(i int) *ns.Seq70 {
	s := &ns.Seq70{R: true}
	tr := true
	reflect.ValueOf(s).Elem().FieldByName(fmt.Sprintf("E%d", i)).Set(reflect.ValueOf(&tr))
	return s
}

func nsCh(i int) *ns.Ch70 {
	c := &ns.Ch70{Present: ns.Ch70Pr(i + 2)} // Nothing=0, R=1, C0=2, ...
	tr := true
	reflect.ValueOf(c).Elem().FieldByName(fmt.Sprintf("C%d", i)).Set(reflect.ValueOf(&tr))
	return c
}

func TestNSmallConstants(t *testing.T) {
	if ns.Ch70PrC64 != 66 || ns.En70V64 != 65 || ns.En70V0 != 1 || ns.En70V69 != 70 {
		t.Fatalf("unexpected generated constants: %d %d %d %d", ns.Ch70PrC64, ns.En70V64, ns.En70V0, ns.En70V69)
	}
}

func TestNSmallRoundTripAPER(t *testing.T) {
	for _, i := range nsIdx {
		s := nsSeq(i)
		b, err := s.Encode()
		if err != nil {
			t.Fatalf("Seq70 e%d: Encode: %v", i, err)
		}
		back, err := ns.DecodeSeq70(b)
		if err != nil {
			t.Fatalf("Seq70 e%d: Decode: %v", i, err)
		}
		if !reflect.DeepEqual(back, s) {
			t.Errorf("Seq70 e%d: decoded %+v, want %+v", i, back, s)
		}

		c := nsCh(i)
		b, err = c.Encode()
		if err != nil {
			t.Fatalf("Ch70 c%d: Encode: %v", i, err)
		}
		cb, err := ns.DecodeCh70(b)
		if err != nil {
			t.Fatalf("Ch70 c%d: Decode: %v", i, err)
		}
		if !reflect.DeepEqual(cb, c) {
			t.Errorf("Ch70 c%d: decoded %+v, want %+v", i, cb, c)
		}

		e := ns.En70(i + 1)
		b, err = e.Encode()
		if err != nil {
			t.Fatalf("En70 v%d: Encode: %v", i, err)
		}
		eb, err := ns.DecodeEn70(b)
		if err != nil {
			t.Fatalf("En70 v%d: Decode: %v", i, err)
		}
		if *eb != e {
			t.Errorf("En70 v%d: decoded %d, want %d", i, *eb, e)
		}
		balanced(t, fmt.Sprintf("index %d", i))
	}
}

func TestNSmallHandAPER(t *testing.T) {
	s := nsSeq(64)
	if b, err := s.Encode(); err != nil || !bytes.Equal(b, nsSeqA) {
		t.Errorf("Seq70 e64 APER = % x (%v), want % x", b, err, nsSeqA)
	}
	c := nsCh(64)
	if b, err := c.Encode(); err != nil || !bytes.Equal(b, nsChA) {
		t.Errorf("Ch70 c64 APER = % x (%v), want % x", b, err, nsChA)
	}
	e := ns.En70V64
	if b, err := e.Encode(); err != nil || !bytes.Equal(b, nsEnA) {
		t.Errorf("En70 v64 APER = % x (%v), want % x", b, err, nsEnA)
	}
	// The hand-computed bytes decode to the same values.
	if back, err := ns.DecodeSeq70(nsSeqA); err != nil || !reflect.DeepEqual(back, s) {
		t.Errorf("Seq70 hand decode: %+v, %v", back, err)
	}
	if back, err := ns.DecodeCh70(nsChA); err != nil || !reflect.DeepEqual(back, c) {
		t.Errorf("Ch70 hand decode: %+v, %v", back, err)
	}
	if back, err := ns.DecodeEn70(nsEnA); err != nil || *back != e {
		t.Errorf("En70 hand decode: %v, %v", back, err)
	}
	balanced(t, "hand")
}

func TestNSmallDecodeErrors(t *testing.T) {
	for _, n := range []int{1, 2, 3, 6, len(nsSeqA) - 3, len(nsSeqA) - 1} {
		_, err := ns.DecodeSeq70(nsSeqA[:n])
		wantErr(t, fmt.Sprintf("Seq70 truncated %d", n), err, rt.ErrDecode)
	}
	for _, n := range []int{1, 2, len(nsChA) - 2, len(nsChA) - 1} {
		_, err := ns.DecodeCh70(nsChA[:n])
		wantErr(t, fmt.Sprintf("Ch70 truncated %d", n), err, rt.ErrDecode)
	}
	for _, n := range []int{1, 2} {
		_, err := ns.DecodeEn70(nsEnA[:n])
		wantErr(t, fmt.Sprintf("En70 truncated %d", n), err, rt.ErrDecode)
	}
	// An empty input is an argument error, not a decode error.
	_, err := ns.DecodeSeq70(nil)
	wantErr(t, "Seq70 empty", err, rt.ErrArg)
	// Zero octet count / zero bitmap length after the long-form flag.
	_, err = ns.DecodeSeq70([]byte{0xE0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	wantErr(t, "Seq70 zero length", err, rt.ErrDecode)
	_, err = ns.DecodeCh70([]byte{0xC0, 0, 0, 0, 0})
	wantErr(t, "Ch70 zero octet count", err, rt.ErrDecode)
	_, err = ns.DecodeEn70([]byte{0xC0, 0, 0, 0})
	wantErr(t, "En70 zero octet count", err, rt.ErrDecode)
	// Octet count 4 is outside what is produced and accepted.
	_, err = ns.DecodeEn70([]byte{0xC0, 0x04, 0, 0, 0, 1})
	wantErr(t, "En70 octet count 4", err, rt.ErrDecode)
	balanced(t, "errors")
}

func TestNSmallCConverter(t *testing.T) {
	bin := converter(t)
	type tc struct {
		pdu    string
		aper   []byte
		hand64 []byte // hand-computed UPER of index 64, nil otherwise
		xerEl  string
	}
	var cases []tc
	for _, i := range nsIdx {
		sb, _ := nsSeq(i).Encode()
		cb, _ := nsCh(i).Encode()
		ev := ns.En70(i + 1)
		eb, _ := ev.Encode()
		var su, cu, eu []byte
		if i == 64 {
			su, cu, eu = nsSeqU, nsChU, nsEnU
		}
		cases = append(cases,
			tc{"Seq70", sb, su, fmt.Sprintf("<e%d><true/></e%d>", i, i)},
			tc{"Ch70", cb, cu, fmt.Sprintf("<c%d><true/></c%d>", i, i)},
			tc{"En70", eb, eu, fmt.Sprintf("<v%d/>", i)})
	}
	for _, c := range cases {
		name := fmt.Sprintf("%s % x", c.pdu, c.aper)
		if re := convPDU(t, bin, c.pdu, c.aper, "-iaper", "-oaper"); !bytes.Equal(re, c.aper) {
			t.Errorf("%s: C APER re-encode % x", name, re)
		}
		xer := convPDU(t, bin, c.pdu, c.aper, "-iaper", "-oxer")
		if !strings.Contains(strings.Join(strings.Fields(string(xer)), ""), c.xerEl) {
			t.Errorf("%s: XER lacks %s:\n%s", name, c.xerEl, xer)
		}
		// The converter's XER decoder reports "Unexpected end of input" for a
		// bare top-level ENUMERATED even with the root value (<En70><r/></En70>),
		// independent of the nsnnwn code, so En70 is checked on its XER text only.
		if c.pdu != "En70" {
			if re := convPDU(t, bin, c.pdu, xer, "-ixer", "-oaper"); !bytes.Equal(re, c.aper) {
				t.Errorf("%s: XER round trip -> APER % x", name, re)
			}
		}
		uper := convPDU(t, bin, c.pdu, c.aper, "-iaper", "-oper")
		if c.hand64 != nil && !bytes.Equal(uper, c.hand64) {
			t.Errorf("%s: C UPER = % x, want hand-computed % x", name, uper, c.hand64)
		}
		if re := convPDU(t, bin, c.pdu, uper, "-iper", "-oaper"); !bytes.Equal(re, c.aper) {
			t.Errorf("%s: UPER round trip -> APER % x", name, re)
		}
	}
}
