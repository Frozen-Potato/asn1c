// Inline SEQUENCE / CHOICE field names that repeat a name of the enclosing
// struct (tests/e2e/shadow.asn). Copied into the generated module by
// tests/run-e2e.sh together with seqofinline_test.go (the siCase helpers) and
// default_test.go (the converter helpers).
//
// Per case: Go APER == the C converter's APER of the same value written as
// XER, Go's decode gives the value back, and the converter's XER of the Go
// APER is the given XER. Inner and outer same-named fields get different
// values so a mix-up shows.
package e2e

import (
	"bytes"
	"testing"

	sh "asn1cgo.test/go/shadow"
)

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
