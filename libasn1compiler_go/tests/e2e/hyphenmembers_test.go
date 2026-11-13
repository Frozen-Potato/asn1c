// SEQUENCE fields, CHOICE alternatives, type names and value names that differ
// only by a hyphen before a digit (tests/e2e/hyphenmembers.asn): `a1` / `a-1`
// get the Go names A1 / A_1, the inline types SA1 / SA_1, the constants
// ChPrA1 / ChPrA_1, the DEFAULT constants SB1Default / SB_1Default and the types
// T1 / T_1. Values are encoded in Go, compared with the C converter's APER of
// the same value written as XER, and decoded back. Copied into the generated
// module by tests/run-e2e.sh together with default_test.go (the converter
// helpers).
package e2e

import (
	"bytes"
	"reflect"
	"testing"

	hm "asn1cgo.test/go/hyphenmembers"
)

func TestHyphenMembersNames(t *testing.T) {
	if hm.ChPrA1 == hm.ChPrA_1 || hm.ChPrC1 == hm.ChPrC_1 {
		t.Error("the constants of a1 / a-1 must differ")
	}
	if hm.ChPrA1 != 1 || hm.ChPrA_1 != 2 || hm.ChPrC1 != 3 || hm.ChPrC_1 != 4 {
		t.Errorf("ChPr: %d %d %d %d", hm.ChPrA1, hm.ChPrA_1, hm.ChPrC1, hm.ChPrC_1)
	}
	if !hm.SB1Default || hm.SB_1Default != 4 {
		t.Errorf("defaults: %v %v", hm.SB1Default, hm.SB_1Default)
	}
	if hm.IdId1 != 1 || hm.IdId_1 != 2 {
		t.Errorf("value names: %d %d", hm.IdId1, hm.IdId_1)
	}
	var _ hm.T1 = true
	var _ hm.T_1 = 3
	var _ hm.SA1 = hm.SA1{X: 1}
	var _ hm.SA_1 = hm.SA_1{Y: true}
	if reflect.TypeOf(hm.S{}.A1) == reflect.TypeOf(hm.S{}.A_1) {
		t.Error("S.A1 and S.A_1 must have different inline types")
	}
	if reflect.TypeOf(hm.S{}.L_1).Elem() != reflect.TypeOf(hm.SL_1Member{}) {
		t.Errorf("S.L_1 element type %v", reflect.TypeOf(hm.S{}.L_1).Elem())
	}
}

func TestHyphenMembersRoundTrip(t *testing.T) {
	bin := converter(t)
	tr, fl := true, false
	s := hm.S{
		A1: hm.SA1{X: 3}, A_1: hm.SA_1{Y: true},
		B1: false, B_1: 7,
		E1: hm.SE1Q, E_1: hm.SE_1P,
		L1: hm.SL1{1, 2}, L_1: hm.SL_1{{Z: true}, {Z: false}},
	}
	sx := "<a1><x>3</x></a1><a-1><y><true/></y></a-1><b1><false/></b1><b-1>7</b-1>" +
		"<e1><q/></e1><e-1><p/></e-1><l1><INTEGER>1</INTEGER><INTEGER>2</INTEGER></l1>" +
		"<l-1><SEQUENCE><z><true/></z></SEQUENCE><SEQUENCE><z><false/></z></SEQUENCE></l-1>"
	cs := []struct {
		v   hm.Ch
		xer string
	}{
		{hm.Ch{Present: hm.ChPrA1, A1: &tr}, "<a1><true/></a1>"},
		{hm.Ch{Present: hm.ChPrA1, A1: &fl}, "<a1><false/></a1>"},
		{hm.Ch{Present: hm.ChPrA_1}, "<a-1></a-1>"},
		{hm.Ch{Present: hm.ChPrC1, C1: &hm.ChC1{X: 6}}, "<c1><x>6</x></c1>"},
		{hm.Ch{Present: hm.ChPrC_1, C_1: &hm.ChC_1{Y: true}}, "<c-1><y><true/></y></c-1>"},
	}
	for _, c := range cs {
		u := hm.U{T1: true, T_1: 2, S: s, C: c.v}
		xer := "<U><t1><true/></t1><t-1>2</t-1><s>" + sx + "</s><c>" + c.xer + "</c></U>"
		aper, err := u.Encode()
		if err != nil {
			t.Errorf("%s: encode: %v", c.xer, err)
			continue
		}
		if ref := convPDU(t, bin, "U", []byte(xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER % x", c.xer, aper, ref)
		}
		got := normXML(convPDU(t, bin, "U", aper, "-iaper", "-oxer"))
		if got != normXML([]byte(xer)) {
			t.Errorf("C XER of the Go APER = %s, want %s", got, xer)
		}
		back, err := hm.DecodeU(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.xer, err)
			continue
		}
		if !reflect.DeepEqual(*back, u) {
			t.Errorf("%s: decoded %+v, want %+v", c.xer, *back, u)
		}
	}
}
