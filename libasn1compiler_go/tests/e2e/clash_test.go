// The same type name in two modules (tests/e2e/clash_a.asn, clash_b.asn): the
// C headers must spell the recursion-safe "struct ClItem" so the generated
// converters compile (a build failure is the regression). Copied into the
// generated module by tests/run-e2e.sh together with seqofinline_test.go (the
// siCase helpers) and default_test.go (the converter helpers).
//
// Per case: Go APER == the C converter's APER of the same value written as
// XER, Go's decode gives the value back, and the converter's XER of the Go
// APER is the given XER.
package e2e

import (
	"bytes"
	"testing"

	ca "asn1cgo.test/go/moda"
	cb "asn1cgo.test/go/modb"
)

func clCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
	el := func(name string, inner ...string) string {
		s := "<" + name + ">"
		for _, i := range inner {
			s += i
		}
		return s + "</" + name + ">"
	}
	ai := func(a, b string) string { return a + b } // concatenates XER fragments
	itemA := func(a, b string) string { return ai(el("a", a), el("b", "<"+b+"/>")) }
	itemX := func(hex string) string { return el("x", hex) }
	ia := func(a int64, b bool) ca.ModAClItem { return ca.ModAClItem{A: a, B: b} }

	// TopA: OPTIONAL member absent / present, 1..4 element list, both alts.
	add(siMk("a-absent-p", "TopA",
		el("TopA", el("l", el("ClItem", itemA("1", "true"))), el("c", el("p", itemA("7", "false")))),
		&ca.TopA{L: ca.TopAL{ia(1, true)}, C: ca.TopAC{Present: ca.TopACPrP, P: &ca.ModAClItem{A: 7}}}, ca.DecodeTopA))
	pi := ia(3, true)
	add(siMk("a-present-q", "TopA",
		el("TopA", el("i", itemA("3", "true")),
			el("l", el("ClItem", itemA("0", "false")), el("ClItem", itemA("5", "true")),
				el("ClItem", itemA("6", "false")), el("ClItem", itemA("2", "true"))),
			el("c", "<q/>")),
		&ca.TopA{I: &pi, L: ca.TopAL{ia(0, false), ia(5, true), ia(6, false), ia(2, true)},
			C: ca.TopAC{Present: ca.TopACPrQ}}, ca.DecodeTopA))

	// TopB: the other module's Item, an OCTET STRING.
	add(siMk("b-absent", "TopB",
		el("TopB", el("l", el("ClItem", itemX("0A"))), ""),
		&cb.TopB{L: cb.TopBL{{X: []byte{0x0a}}}}, cb.DecodeTopB))
	add(siMk("b-present", "TopB",
		el("TopB", el("i", itemX("FF")), el("l", el("ClItem", itemX("DEADBEEF")), el("ClItem", itemX("00")))),
		&cb.TopB{I: &cb.ModBClItem{X: []byte{0xff}}, L: cb.TopBL{{X: []byte{0xde, 0xad, 0xbe, 0xef}}, {X: []byte{0}}}}, cb.DecodeTopB))
	return cs
}

func TestClashRoundTrip(t *testing.T) {
	for _, c := range clCases() {
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

func TestClashCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range clCases() {
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
