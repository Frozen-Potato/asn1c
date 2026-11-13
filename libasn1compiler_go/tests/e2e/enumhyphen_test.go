// Enumerators and named bits that differ only by a hyphen
// (tests/e2e/enumhyphen.asn): `d1` / `d-1` get the Go names DriftD1 /
// DriftD_1. Every enumerator value and named-bit combination is encoded in Go,
// compared with the C converter's APER of the same value written as XER, and
// decoded back; the constant values and the distinctness of the names are
// checked too. Copied into the generated module by tests/run-e2e.sh together
// with default_test.go (the converter helpers).
package e2e

import (
	"bytes"
	"testing"

	eh "asn1cgo.test/go/enumhyphen"
)

func TestEnumHyphenConstants(t *testing.T) {
	if eh.DriftD1 != 0 || eh.DriftD_1 != 1 || eh.DriftD2 != 2 || eh.DriftD_2 != 3 {
		t.Errorf("Drift: %d %d %d %d", eh.DriftD1, eh.DriftD_1, eh.DriftD2, eh.DriftD_2)
	}
	if eh.DriftD1 == eh.DriftD_1 || eh.DriftD2 == eh.DriftD_2 {
		t.Error("hyphenated and plain enumerators must be different values")
	}
	if eh.TEA1 != 0 || eh.TEA_1 != 1 {
		t.Errorf("inline enum: %d %d", eh.TEA1, eh.TEA_1)
	}
	var _ int = eh.BB1
	if eh.BB1 != 0 || eh.BB_1 != 1 || eh.BB1 == eh.BB_1 {
		t.Errorf("named bits: %d %d", eh.BB1, eh.BB_1)
	}
}

func TestEnumHyphenRoundTrip(t *testing.T) {
	bin := converter(t)
	es := []struct {
		v   eh.TE
		xer string
	}{{eh.TEA1, "a1"}, {eh.TEA_1, "a-1"}}
	ds := []struct {
		v   eh.Drift
		xer string
	}{{eh.DriftD1, "d1"}, {eh.DriftD_1, "d-1"}, {eh.DriftD2, "d2"}, {eh.DriftD_2, "d-2"}}
	for _, e := range es {
		for _, d := range ds {
			for bits := 0; bits < 4; bits++ {
				var b eh.B
				b.Bytes = []byte{0}
				b.BitsUnused = 6
				txt := "00"
				if bits&1 != 0 { // named bit b1 = position 0
					b.Bytes[0] |= 0x80
					txt = "1" + txt[1:]
				}
				if bits&2 != 0 { // named bit b-1 = position 1
					b.Bytes[0] |= 0x40
					txt = txt[:1] + "1"
				}
				xer := "<T><e><" + e.xer + "/></e><d><" + d.xer + "/></d><b>" + txt + "</b></T>"
				v := eh.T{E: e.v, D: d.v, B: b}
				aper, err := v.Encode()
				if err != nil {
					t.Errorf("%s: encode: %v", xer, err)
					continue
				}
				if ref := convPDU(t, bin, "T", []byte(xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
					t.Errorf("%s: Go APER % x != C APER % x", xer, aper, ref)
				}
				got := normXML(convPDU(t, bin, "T", aper, "-iaper", "-oxer"))
				if got != normXML([]byte(xer)) {
					t.Errorf("C XER of the Go APER = %s, want %s", got, xer)
				}
				back, err := eh.DecodeT(aper)
				if err != nil {
					t.Errorf("%s: decode: %v", xer, err)
					continue
				}
				if back.E != e.v || back.D != d.v || !bytes.Equal(back.B.Bytes, b.Bytes) || back.B.BitsUnused != b.BitsUnused {
					t.Errorf("%s: decoded %+v", xer, *back)
				}
			}
		}
	}
}
