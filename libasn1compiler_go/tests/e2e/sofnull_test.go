// SEQUENCE OF a named NULL type (tests/e2e/sofnull.asn). Copied into the
// generated module by tests/run-e2e.sh together with seqofinline_test.go (the
// siCase helpers) and default_test.go (the converter helpers).
//
// The element is a reference to a NULL type, directly (SnN) or through an
// alias (SnN2), at top level, as a SEQUENCE member, as an OPTIONAL member and
// as a CHOICE alternative, with counts 0, 1 and the SIZE maximum. A plain
// member / alternative of the NULL type itself is covered too. Per case: Go
// APER == the C converter's APER of the same value written as XER, Go's decode
// gives the value back, and the converter's XER of the Go APER is the given XER.
package e2e

import (
	"bytes"
	"strings"
	"testing"

	sn "asn1cgo.test/go/sofnull"
)

// snSl makes the Go value of a decoded list of n NULLs: nil when empty (the
// decoder's spelling of an empty list).
func snSl[T any](n int) []T {
	if n == 0 {
		return nil
	}
	return make([]T, n)
}

func snCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
	el := func(name string, inner ...string) string {
		return "<" + name + ">" + strings.Join(inner, "") + "</" + name + ">"
	}
	nulls := func(tag string, n int) []string {
		var o []string
		for i := 0; i < n; i++ {
			o = append(o, "<"+tag+"/>")
		}
		return o
	}

	for _, n := range []int{0, 1, 4} {
		sfx := string(rune('0' + n))
		add(siMk("top-"+sfx, "SnTop", el("SnTop", nulls("SnN", n)...), func() *sn.SnTop { v := sn.SnTop(snSl[sn.SnN](n)); return &v }(), sn.DecodeSnTop))
		add(siMk("alias-"+sfx, "SnAlias", el("SnAlias", nulls("SnN2", n)...), func() *sn.SnAlias { v := sn.SnAlias(snSl[sn.SnN](n)); return &v }(), sn.DecodeSnAlias))
		a := sn.SnMemA(snSl[sn.SnN](n))
		b := sn.SnMemB(snSl[sn.SnN](n))
		add(siMk("mem-"+sfx, "SnMem", el("SnMem", el("a", nulls("SnN", n)...), el("flag", "<true/>")),
			&sn.SnMem{A: a, Flag: true}, sn.DecodeSnMem))
		add(siMk("mem-opt-"+sfx, "SnMem", el("SnMem", el("a", nulls("SnN", n)...), el("b", nulls("SnN2", n)...), el("flag", "<false/>")),
			&sn.SnMem{A: a, B: &b, Flag: false}, sn.DecodeSnMem))
		alt := sn.SnAltA(snSl[sn.SnN](n))
		add(siMk("alt-"+sfx, "SnAlt", el("SnAlt", el("a", nulls("SnN", n)...)),
			&sn.SnAlt{Present: sn.SnAltPrA, A: &alt}, sn.DecodeSnAlt))
	}
	add(siMk("alt-null", "SnAlt", el("SnAlt", "<b/>"), &sn.SnAlt{Present: sn.SnAltPrB}, sn.DecodeSnAlt))
	add(siMk("alt-bool", "SnAlt", el("SnAlt", el("c", "<true/>")), func() *sn.SnAlt {
		t := true
		return &sn.SnAlt{Present: sn.SnAltPrC, C: &t}
	}(), sn.DecodeSnAlt))
	add(siMk("plain", "SnPlain", el("SnPlain", "<n/>", el("flag", "<true/>")),
		&sn.SnPlain{Flag: true}, sn.DecodeSnPlain))
	add(siMk("plain-opt", "SnPlain", el("SnPlain", "<n/>", "<o/>", el("flag", "<false/>")),
		&sn.SnPlain{O: &sn.SnN{}}, sn.DecodeSnPlain))
	return cs
}

func TestSofNullRoundTrip(t *testing.T) {
	for _, c := range snCases() {
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

func TestSofNullCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range snCases() {
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
