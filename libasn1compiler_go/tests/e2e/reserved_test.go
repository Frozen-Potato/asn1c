// CHOICE alternatives (and SEQUENCE members, enumerators) named after a C
// reserved word (tests/e2e/reserved.asn). asn1c upper-cases the first letter
// of the union member (`Explicit`) but keeps the lower-case _PR constant
// (`C_PR_explicit`); building the module is the first check. Every
// alternative is encoded in Go, compared with the C converter's APER of the
// same value written as XER, and decoded back. Copied into the generated
// module by tests/run-e2e.sh with default_test.go (the converter helpers).
package e2e

import (
	"bytes"
	"testing"

	rs "asn1cgo.test/go/reserved"
)

func TestReservedRoundTrip(t *testing.T) {
	bin := converter(t)
	yes, i5, i2 := true, int64(5), int64(2)
	oct := []byte{0xAB, 0xCD}
	cases := []struct {
		pdu string
		xer string
		enc func() ([]byte, error)
		chk func(aper []byte) bool
	}{
		{"RsH", "<RsH><explicit><true/></explicit><int>2</int></RsH>",
			func() ([]byte, error) { v := rs.RsH{Explicit: true, Int: &i2}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsH(b); return err == nil && v.Explicit && v.Int != nil && *v.Int == 2 }},
		{"RsC", "<RsC><explicit><true/></explicit></RsC>",
			func() ([]byte, error) { v := rs.RsC{Present: rs.RsCPrExplicit, Explicit: &yes}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsC(b); return err == nil && v.Present == rs.RsCPrExplicit && *v.Explicit }},
		{"RsC", "<RsC><x></x></RsC>",
			func() ([]byte, error) { v := rs.RsC{Present: rs.RsCPrX}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsC(b); return err == nil && v.Present == rs.RsCPrX }},
		{"RsE", "<RsE><auto/></RsE>",
			func() ([]byte, error) { e := rs.RsEAuto; return e.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsE(b); return err == nil && *v == rs.RsEAuto }},
		{"RsR", "<RsR><explicit><true/></explicit></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrExplicit, Explicit: &yes}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrExplicit && *v.Explicit }},
		{"RsR", "<RsR><int>5</int></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrInt, Int: &i5}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrInt && *v.Int == 5 }},
		{"RsR", "<RsR><auto>ABCD</auto></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrAuto, Auto: &oct}; return v.Encode() },
			func(b []byte) bool {
				v, err := rs.DecodeRsR(b)
				return err == nil && v.Present == rs.RsRPrAuto && bytes.Equal(*v.Auto, oct)
			}},
		{"RsR", "<RsR><default><a>3</a></default></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrDefault, Default: &rs.RsRDefault{A: 3}}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrDefault && v.Default.A == 3 }},
		{"RsR", "<RsR><struct><q>3</q></struct></RsR>",
			func() ([]byte, error) {
				q := int64(3)
				v := rs.RsR{Present: rs.RsRPrStruct, Struct: &rs.RsRStruct{Present: rs.RsRStructPrQ, Q: &q}}; return v.Encode()
			},
			func(b []byte) bool {
				v, err := rs.DecodeRsR(b)
				return err == nil && v.Present == rs.RsRPrStruct && v.Struct.Present == rs.RsRStructPrQ && *v.Struct.Q == 3
			}},
		{"RsR", "<RsR><x></x></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrX}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrX }},
		{"RsR", "<RsR><static></static></RsR>",
			func() ([]byte, error) { v := rs.RsR{Present: rs.RsRPrStatic}; return v.Encode() },
			func(b []byte) bool { v, err := rs.DecodeRsR(b); return err == nil && v.Present == rs.RsRPrStatic }},
	}
	for _, c := range cases {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.xer, err)
			continue
		}
		if ref := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER % x", c.xer, aper, ref)
		}
		if got := normXML(convPDU(t, bin, c.pdu, aper, "-iaper", "-oxer")); got != normXML([]byte(c.xer)) {
			t.Errorf("C XER of the Go APER = %s, want %s", got, c.xer)
		}
		if !c.chk(aper) {
			t.Errorf("%s: decode mismatch", c.xer)
		}
	}
}
