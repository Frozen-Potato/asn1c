// An alias of an alias as an OPTIONAL SEQUENCE member and as a CHOICE
// alternative (tests/e2e/optalias.asn, built with -findirect-choice). The C
// headers name the real struct (`struct Freq *pf`), so the Go converters can
// size and fill it. M is encoded with pf present and absent, C with each
// alternative; each is compared with the C converter's APER of the same value
// written as XER and decoded back. Copied into the generated module by
// tests/run-e2e.sh together with default_test.go (the converter helpers).
package e2e

import (
	"bytes"
	"testing"

	oa "asn1cgo.test/go/optalias"
)

func TestOptAliasRoundTrip(t *testing.T) {
	bin := converter(t)
	check := func(pdu, xer string, aper []byte, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: encode: %v", xer, err)
			return
		}
		if ref := convPDU(t, bin, pdu, []byte(xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER % x", xer, aper, ref)
		}
		if got := normXML(convPDU(t, bin, pdu, aper, "-iaper", "-oxer")); got != normXML([]byte(xer)) {
			t.Errorf("C XER of the Go APER = %s, want %s", got, xer)
		}
	}

	// M with pf present.
	m := oa.M{A: 2, Pf: &oa.Freq{F: 16383}}
	aper, err := m.Encode()
	check("M", "<M><a>2</a><pf><f>16383</f></pf></M>", aper, err)
	if err == nil {
		back, err := oa.DecodeM(aper)
		if err != nil {
			t.Fatalf("decode M: %v", err)
		}
		if back.A != 2 || back.Pf == nil || back.Pf.F != 16383 {
			t.Errorf("M decoded %+v", *back)
		}
	}

	// M with pf absent.
	m = oa.M{A: 1}
	aper, err = m.Encode()
	check("M", "<M><a>1</a></M>", aper, err)
	if err == nil {
		back, err := oa.DecodeM(aper)
		if err != nil {
			t.Fatalf("decode M: %v", err)
		}
		if back.A != 1 || back.Pf != nil {
			t.Errorf("M decoded %+v", *back)
		}
	}

	// C, alternative pf.
	c := oa.C{Present: oa.CPrPf, Pf: &oa.Freq{F: 77}}
	aper, err = c.Encode()
	check("C", "<C><pf><f>77</f></pf></C>", aper, err)
	if err == nil {
		back, err := oa.DecodeC(aper)
		if err != nil {
			t.Fatalf("decode C: %v", err)
		}
		if back.Present != oa.CPrPf || back.Pf == nil || back.Pf.F != 77 {
			t.Errorf("C decoded %+v", *back)
		}
	}

	// C, alternative a.
	a := int64(3)
	c = oa.C{Present: oa.CPrA, A: &a}
	aper, err = c.Encode()
	check("C", "<C><a>3</a></C>", aper, err)
	if err == nil {
		back, err := oa.DecodeC(aper)
		if err != nil {
			t.Fatalf("decode C: %v", err)
		}
		if back.Present != oa.CPrA || back.A == nil || *back.A != 3 {
			t.Errorf("C decoded %+v", *back)
		}
	}
}
