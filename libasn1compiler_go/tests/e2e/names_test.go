package e2e

import (
	"bytes"
	"reflect"
	"testing"

	eh "asn1cgo.test/go/enumhyphen"
	hm "asn1cgo.test/go/hyphenmembers"
	sh "asn1cgo.test/go/shadow"
)

// Inline SEQUENCE / CHOICE field names that repeat a name of the enclosing
// struct (tests/e2e/names.asn). Copied into the generated module by
// tests/run-e2e.sh together with seqof_test.go (the siCase helpers) and
// default_test.go (the converter helpers).
//
// Per case: Go APER == the C converter's APER of the same value written as
// XER, Go's decode gives the value back, and the converter's XER of the Go
// APER is the given XER. Inner and outer same-named fields get different
// values so a mix-up shows.
func shCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
	bl := siBool
	el := func(name string, inner ...string) string {
		s := "<" + name + ">"
		for _, i := range inner {
			s += i
		}
		return s + "</" + name + ">"
	}
	i64 := func(v int64) *int64 { return &v }

	for _, b := range []struct{ in, out bool }{{true, false}, {false, true}, {true, true}, {false, false}} {
		n := "-" + bl(b.in) + bl(b.out)
		add(siMk("seq"+n, "ShSeq", el("ShSeq", el("a", el("x", bl(b.in)), el("y", "2")), el("x", bl(b.out))),
			&sh.ShSeq{A: sh.ShSeqA{X: b.in, Y: 2}, X: b.out}, sh.DecodeShSeq))
		add(siMk("seqrev"+n, "ShSeqRev", el("ShSeqRev", el("x", bl(b.out)), el("a", el("x", bl(b.in)), el("y", "3"))),
			&sh.ShSeqRev{X: b.out, A: sh.ShSeqRevA{X: b.in, Y: 3}}, sh.DecodeShSeqRev))
	}

	add(siMk("choice-a", "ShChoice", el("ShChoice", el("a", el("x", bl(true)), el("l", "5"))),
		&sh.ShChoice{Present: sh.ShChoicePrA, A: &sh.ShChoiceA{X: true, L: 5}}, sh.DecodeShChoice))
	add(siMk("choice-l", "ShChoice", el("ShChoice", el("l", "2")),
		&sh.ShChoice{Present: sh.ShChoicePrL, L: i64(2)}, sh.DecodeShChoice))

	l := func(v sh.ShL) *sh.ShL { return &v }
	add(siMk("deep-a", "ShDeep", el("ShDeep", el("p", el("a", el("x", bl(false)), el("l", "6")))),
		&sh.ShDeep{P: sh.ShDeepP{Present: sh.ShDeepPPrA, A: &sh.ShDeepPA{X: false, L: 6}}}, sh.DecodeShDeep))
	add(siMk("deep-l", "ShDeep", el("ShDeep", el("p", el("l", "1"))),
		&sh.ShDeep{P: sh.ShDeepP{Present: sh.ShDeepPPrL, L: l(1)}}, sh.DecodeShDeep))

	add(siMk("sib", "ShSib", el("ShSib", el("a", el("l", bl(true))), el("b", el("l", bl(false))), el("c", el("c", bl(true)))),
		&sh.ShSib{A: sh.ShSibA{L: true}, B: sh.ShSibB{L: false}, C: sh.ShSibC{C: true}}, sh.DecodeShSib))
	return cs
}

func TestShadowRoundTrip(t *testing.T) {
	for _, c := range shCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
	}
}

func TestShadowCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range shCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref, ok := siConv(t, bin, c, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		xer, ok := siConv(t, bin, c, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
	}
}

// Enumerators and named bits that differ only by a hyphen
// (tests/e2e/names.asn): `d1` / `d-1` get the Go names DriftD1 /
// DriftD_1. Every enumerator value and named-bit combination is encoded in Go,
// compared with the C converter's APER of the same value written as XER, and
// decoded back; the constant values and the distinctness of the names are
// checked too. Copied into the generated module by tests/run-e2e.sh together
// with default_test.go (the converter helpers).
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

// SEQUENCE fields, CHOICE alternatives, type names and value names that differ
// only by a hyphen before a digit (tests/e2e/names.asn): `a1` / `a-1`
// get the Go names A1 / A_1, the inline types SA1 / SA_1, the constants
// ChPrA1 / ChPrA_1, the DEFAULT constants SB1Default / SB_1Default and the types
// T1 / T_1. Values are encoded in Go, compared with the C converter's APER of
// the same value written as XER, and decoded back. Copied into the generated
// module by tests/run-e2e.sh together with default_test.go (the converter
// helpers).
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
