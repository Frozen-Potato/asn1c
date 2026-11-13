// SET (tests/e2e/set.asn). Copied into the generated module by
// tests/run-e2e.sh together with seqofinline_test.go (the siCase helpers),
// setof_test.go (soMk) and default_test.go (the converter helpers).
//
// A SET is a Go struct like a SEQUENCE; Encode writes the root members in
// canonical (tag) order, Decode reads them back in that order. SetBasic,
// SetGrp, SetTail, SetTags and SetCh are the vectors of the C tests
// 171-set-per-OK: the exact APER bytes are asserted. Every case also checks
// that Decode of the bytes gives the value back and that the C converter
// agrees (APER of the XER value, APER re-encode, XER of the APER).
package e2e

import (
	"bytes"
	"testing"

	st "asn1cgo.test/go/phcset"
	sg "asn1cgo.test/go/phcsettags"
)

func setMk[T any](name, pdu, xer string, aper []byte, v *T, dec func([]byte) (*T, error)) soCase {
	return soMk(name, pdu, xer, aper, v, v, dec)
}

func setCases() []soCase {
	var cs []soCase
	add := func(c soCase) { cs = append(cs, c) }
	i64 := func(v int64) *int64 { return &v }
	bp := siPtr[bool]
	bl := siBool
	el := func(name string, inner ...string) string {
		s := "<" + name + ">"
		for _, i := range inner {
			s += i
		}
		return s + "</" + name + ">"
	}

	// SetBasic: canonical order a, b, c; the extension addition d.
	add(setMk("basic-b", "SetBasic",
		el("SetBasic", el("a", "5"), el("b", bl(true)), el("c", "0A0B")),
		[]byte{0x6c, 0x02, 0x0a, 0x0b},
		&st.SetBasic{A: 5, B: bp(true), C: []byte{0x0a, 0x0b}}, st.DecodeSetBasic))
	add(setMk("basic-d", "SetBasic",
		el("SetBasic", el("a", "5"), el("c", "0A"), el("d", "2")),
		[]byte{0xa8, 0x01, 0x0a, 0x01, 0x01, 0x80},
		&st.SetBasic{A: 5, C: []byte{0x0a}, D: i64(2)}, st.DecodeSetBasic))

	// SetGrp: the [[ ]] group is Ext1.
	add(setMk("grp-a", "SetGrp", el("SetGrp", el("a", "1")),
		[]byte{0x10}, &st.SetGrp{A: 1}, st.DecodeSetGrp))
	add(setMk("grp-g", "SetGrp",
		el("SetGrp", el("a", "1"), el("ext1", el("g1", bl(true)), el("g2", "3"))),
		[]byte{0x90, 0x10, 0x01, 0xf0},
		&st.SetGrp{A: 1, Ext1: &st.SetGrpExt1{G1: true, G2: i64(3)}}, st.DecodeSetGrp))
	add(setMk("grp-g-opt-absent", "SetGrp",
		el("SetGrp", el("a", "1"), el("ext1", el("g1", bl(false)))),
		nil, &st.SetGrp{A: 1, Ext1: &st.SetGrpExt1{G1: false}}, st.DecodeSetGrp))

	// SetTail: the root member e follows the addition d.
	add(setMk("tail", "SetTail",
		el("SetTail", el("a", "1"), el("e", bl(true)), el("d", "2")),
		[]byte{0x98, 0x08, 0x01, 0x80},
		&st.SetTail{A: 1, E: true, D: i64(2)}, st.DecodeSetTail))

	// SetTags: canonical order y[0], x[1], z[2] gives e9, not ce.
	add(setMk("tags", "SetTags",
		el("SetTags", el("y", bl(true)), el("x", "2"), el("z", "9")),
		[]byte{0xe9}, &sg.SetTags{Z: 9, Y: true, X: i64(2)}, sg.DecodeSetTags))
	add(setMk("tags-no-x", "SetTags",
		el("SetTags", el("y", bl(true)), el("z", "9")),
		nil, &sg.SetTags{Z: 9, Y: true}, sg.DecodeSetTags))

	// SetCh: an untagged CHOICE sorts by its smallest tag, so u precedes n.
	add(setMk("ch-q", "SetCh", el("SetCh", el("u", "<q/>"), el("n", "6")),
		[]byte{0x60}, &sg.SetCh{N: 6, U: sg.SetChU{Present: sg.SetChUPrQ}}, sg.DecodeSetCh))
	add(setMk("ch-p", "SetCh", el("SetCh", el("u", el("p", bl(false))), el("n", "6")),
		[]byte{0xb0}, &sg.SetCh{N: 6, U: sg.SetChU{Present: sg.SetChUPrP, P: bp(false)}}, sg.DecodeSetCh))

	// SET as a member, OPTIONAL member and inline member.
	basic := st.SetMemb{A: 2, B: bp(false), C: []byte{7}}
	basicX := el("s", el("a", "2"), el("b", bl(false)), el("c", "07"))
	add(setMk("hold", "StHold",
		el("StHold", basicX, el("i", el("x", bl(true)))),
		nil, &st.StHold{S: basic, I: st.StHoldI{X: true}}, st.DecodeStHold))
	add(setMk("hold-opt", "StHold",
		el("StHold", basicX, el("o", el("a", "1"), el("ext1", el("g1", bl(true)))), el("i", el("x", bl(false)), el("y", "3"))),
		nil, &st.StHold{S: basic, O: &st.SetOptM{A: 1, Ext1: &st.SetOptMExt1{G1: true}}, I: st.StHoldI{Y: i64(3)}}, st.DecodeStHold))

	// SET as a CHOICE alternative (named and inline).
	add(setMk("alt-s", "StAlt", el("StAlt", basicX),
		nil, &st.StAlt{Present: st.StAltPrS, S: &basic}, st.DecodeStAlt))
	add(setMk("alt-i", "StAlt", el("StAlt", el("i", el("x", bl(true)), el("y", "1"))),
		nil, &st.StAlt{Present: st.StAltPrI, I: &st.StAltI{X: true, Y: i64(1)}}, st.DecodeStAlt))
	add(setMk("alt-n", "StAlt", el("StAlt", "<n/>"),
		nil, &st.StAlt{Present: st.StAltPrN}, st.DecodeStAlt))

	// SET OF SET: the list sorts the encoded elements.
	row := func(f bool, n int64) st.StListMember { return st.StListMember{F: f, N: n} }
	rx := func(f bool, n string) string { return el("SET", el("f", bl(f)), el("n", n)) }
	add(soMk("list", "StList", el("StList", rx(false, "1"), rx(true, "5")), nil,
		&st.StList{row(true, 5), row(false, 1)}, &st.StList{row(false, 1), row(true, 5)}, st.DecodeStList))

	// DEFAULT members (the C XER writer spells them out).
	add(setMk("def-at", "SetDef", el("SetDef", el("a", "3"), el("b", bl(true)), el("c", "9")),
		nil, &st.SetDef{A: st.SetDefADefault, B: st.SetDefBDefault, C: 9}, st.DecodeSetDef))
	add(setMk("def-away", "SetDef", el("SetDef", el("a", "6"), el("b", bl(false)), el("c", "200")),
		nil, &st.SetDef{A: 6, B: false, C: 200}, st.DecodeSetDef))
	return cs
}

func TestSetRoundTrip(t *testing.T) {
	for _, c := range setCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if c.aper != nil && !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: Go APER % x, want % x", c.name, aper, c.aper)
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
	}
}

func TestSetCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range setCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref, ok := siConv(t, bin, c.siCase, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		if re, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re, ok := siConv(t, bin, c.siCase, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

// The C XER writer emits the root members in canonical order; the reader
// accepts them in any order (textual order here) and APER is the same.
func TestSetXerAnyOrder(t *testing.T) {
	bin := converter(t)
	for _, c := range []struct {
		pdu, xer string
		aper     []byte
	}{
		{"SetTags", "<SetTags><z>9</z><y><true/></y><x>2</x></SetTags>", []byte{0xe9}},
		{"SetCh", "<SetCh><n>6</n><u><q/></u></SetCh>", []byte{0x60}},
		{"SetCh", "<SetCh><n>6</n><u><p><false/></p></u></SetCh>", []byte{0xb0}},
	} {
		got, ok := siConv(t, bin, siCase{name: c.pdu, pdu: c.pdu}, []byte(c.xer), "-ixer", "-oaper")
		if ok && !bytes.Equal(got, c.aper) {
			t.Errorf("%s: C APER of %s = % x, want % x", c.pdu, c.xer, got, c.aper)
		}
	}
}
