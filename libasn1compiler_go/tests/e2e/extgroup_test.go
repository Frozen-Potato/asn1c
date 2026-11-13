// "[[ ]]" extension addition groups (tests/e2e/extgroup.asn): each group is an
// optional nested struct, Ext<N> *<T>Ext<N>. Copied into the generated module
// by tests/run-e2e.sh together with seqofinline_test.go (the siCase helpers)
// and default_test.go (the converter helpers).
//
// Per case of egCases: Go APER == the C converter's APER of the same value
// written as XER, Go's decode gives the value back, and the converter's XER of
// the Go APER is the given XER. The "old version" tests decode bytes produced
// by the C converter from a value of GrpOld, the type before any group existed.
package e2e

import (
	"bytes"
	"testing"

	eg "asn1cgo.test/go/extgroup"
)

func egCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
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

	one := func(name string, v *eg.GrpOne, parts ...string) {
		add(siMk(name, "GrpOne", el("GrpOne", parts...), v, eg.DecodeGrpOne))
	}
	one("one-absent", &eg.GrpOne{A: 2}, el("a", "2"))
	one("one-present", &eg.GrpOne{A: 1, Ext1: &eg.GrpOneExt1{B: true, C: 5}},
		el("a", "1"), el("ext1", el("b", bl(true)), el("c", "5")))
	one("one-present-zero", &eg.GrpOne{A: 0, Ext1: &eg.GrpOneExt1{B: false, C: 0}},
		el("a", "0"), el("ext1", el("b", bl(false)), el("c", "0")))

	mu := func(name string, v *eg.GrpMulti, parts ...string) {
		add(siMk(name, "GrpMulti", el("GrpMulti", parts...), v, eg.DecodeGrpMulti))
	}
	mu("multi-none", &eg.GrpMulti{A: 3}, el("a", "3"))
	mu("multi-1", &eg.GrpMulti{A: 3, Ext1: &eg.GrpMultiExt1{B: true}},
		el("a", "3"), el("ext1", el("b", bl(true))))
	mu("multi-2", &eg.GrpMulti{A: 3, Ext2: &eg.GrpMultiExt2{C: true}},
		el("a", "3"), el("ext2", el("c", bl(true))))
	mu("multi-2-opt", &eg.GrpMulti{A: 3, Ext2: &eg.GrpMultiExt2{C: false, D: i64(6)}},
		el("a", "3"), el("ext2", el("c", bl(false)), el("d", "6")))
	mu("multi-both", &eg.GrpMulti{A: 0, Ext1: &eg.GrpMultiExt1{B: false}, Ext2: &eg.GrpMultiExt2{C: true, D: i64(0)}},
		el("a", "0"), el("ext1", el("b", bl(false))), el("ext2", el("c", bl(true)), el("d", "0")))

	mx := func(name string, v *eg.GrpMixed, parts ...string) {
		add(siMk(name, "GrpMixed", el("GrpMixed", parts...), v, eg.DecodeGrpMixed))
	}
	mx("mixed-none", &eg.GrpMixed{A: 1}, el("a", "1"))
	mx("mixed-plain", &eg.GrpMixed{A: 1, X: bp(true), Y: i64(3), Z: bp(false)},
		el("a", "1"), el("x", bl(true)), el("y", "3"), el("z", bl(false)))
	mx("mixed-ext1", &eg.GrpMixed{A: 1, Ext1: &eg.GrpMixedExt1{B: true}},
		el("a", "1"), el("ext1", el("b", bl(true))))
	mx("mixed-ext2", &eg.GrpMixed{A: 1, Ext2: &eg.GrpMixedExt2{C: true, D: bp(false)}},
		el("a", "1"), el("ext2", el("c", bl(true)), el("d", bl(false))))
	mx("mixed-all", &eg.GrpMixed{A: 2, X: bp(false), Ext1: &eg.GrpMixedExt1{B: false}, Y: i64(7),
		Ext2: &eg.GrpMixedExt2{C: false}, Z: bp(true)},
		el("a", "2"), el("x", bl(false)), el("ext1", el("b", bl(false))), el("y", "7"),
		el("ext2", el("c", bl(false))), el("z", bl(true)))
	mx("mixed-y-only", &eg.GrpMixed{A: 0, Y: i64(2)}, el("a", "0"), el("y", "2"))

	in := func(name string, v *eg.GrpInline, parts ...string) {
		add(siMk(name, "GrpInline", el("GrpInline", parts...), v, eg.DecodeGrpInline))
	}
	in("inline-none", &eg.GrpInline{S: eg.GrpInlineS{P: true}}, el("s", el("p", bl(true))))
	in("inline-s1", &eg.GrpInline{S: eg.GrpInlineS{P: false, Ext1: &eg.GrpInlineSExt1{Q: true}}},
		el("s", el("p", bl(false)), el("ext1", el("q", bl(true)))))
	in("inline-s2", &eg.GrpInline{S: eg.GrpInlineS{P: true, Ext2: &eg.GrpInlineSExt2{R: false}}},
		el("s", el("p", bl(true)), el("ext2", el("r", bl(false)))))
	in("inline-o", &eg.GrpInline{S: eg.GrpInlineS{P: true},
		O: &eg.GrpInlineO{P: false, Ext1: &eg.GrpInlineOExt1{Q: 3}}},
		el("s", el("p", bl(true))), el("o", el("p", bl(false)), el("ext1", el("q", "3"))))
	in("inline-all", &eg.GrpInline{
		S: eg.GrpInlineS{P: true, Ext1: &eg.GrpInlineSExt1{Q: false}, Ext2: &eg.GrpInlineSExt2{R: true}},
		O: &eg.GrpInlineO{P: true}, Ext1: &eg.GrpInlineExt1{T: true}},
		el("s", el("p", bl(true)), el("ext1", el("q", bl(false))), el("ext2", el("r", bl(true)))),
		el("o", el("p", bl(true))), el("ext1", el("t", bl(true))))

	df := func(name string, v *eg.GrpDef, parts ...string) {
		add(siMk(name, "GrpDef", el("GrpDef", parts...), v, eg.DecodeGrpDef))
	}
	df("def-absent", &eg.GrpDef{A: 3}, el("a", "3"))
	// the C XER writer spells out a DEFAULT member
	df("def-at-default", &eg.GrpDef{A: 3, Ext1: &eg.GrpDefExt1{C: eg.GrpDefExt1CDefault, D: eg.GrpDefExt1DDefault}},
		el("a", "3"), el("ext1", el("c", "4"), el("d", bl(true))))
	df("def-away", &eg.GrpDef{A: 3, Ext1: &eg.GrpDefExt1{B: bp(true), C: 9, D: false}},
		el("a", "3"), el("ext1", el("b", bl(true)), el("c", "9"), el("d", bl(false))))
	df("def-c-away", &eg.GrpDef{A: 0, Ext1: &eg.GrpDefExt1{C: 0, D: true}},
		el("a", "0"), el("ext1", el("c", "0"), el("d", bl(true))))
	return cs
}

func TestExtGroupRoundTrip(t *testing.T) {
	for _, c := range egCases() {
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

func TestExtGroupCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range egCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref, ok := siConv(t, bin, c, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		if re, ok := siConv(t, bin, c, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re, ok := siConv(t, bin, c, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

// Bytes produced by the C converter from a GrpOld value (a sender that predates
// every group) decode with each group nil, in every type that extends it; a
// DEFAULT member of an absent group stays unreachable (the group is nil).
func TestExtGroupOldVersionDecode(t *testing.T) {
	bin := converter(t)
	for a := int64(0); a <= 3; a++ {
		c := siCase{name: "grpold-" + itoa(a), pdu: "GrpOld"}
		old, ok := siConv(t, bin, c, []byte("<GrpOld><a>"+itoa(a)+"</a></GrpOld>"), "-ixer", "-oaper")
		if !ok {
			continue
		}
		if v, err := eg.DecodeGrpOne(old); err != nil || v.A != a || v.Ext1 != nil {
			t.Errorf("a=%d: GrpOne = %+v, %v", a, v, err)
		}
		if v, err := eg.DecodeGrpMulti(old); err != nil || v.A != a || v.Ext1 != nil || v.Ext2 != nil {
			t.Errorf("a=%d: GrpMulti = %+v, %v", a, v, err)
		}
		if v, err := eg.DecodeGrpMixed(old); err != nil || v.A != a || v.X != nil || v.Ext1 != nil ||
			v.Y != nil || v.Ext2 != nil || v.Z != nil {
			t.Errorf("a=%d: GrpMixed = %+v, %v", a, v, err)
		}
		if v, err := eg.DecodeGrpDef(old); err != nil || v.A != a || v.Ext1 != nil {
			t.Errorf("a=%d: GrpDef = %+v, %v", a, v, err)
		}
	}
}

// A nil group is absent: the same bytes as a value of the version that predates
// the group, and no error.
func TestExtGroupNilIsAbsent(t *testing.T) {
	for a := int64(0); a <= 3; a++ {
		oldB, err := (&eg.GrpOld{A: a}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		for name, e := range map[string]siEncoder{
			"GrpOne": &eg.GrpOne{A: a}, "GrpMulti": &eg.GrpMulti{A: a},
			"GrpMixed": &eg.GrpMixed{A: a}, "GrpDef": &eg.GrpDef{A: a},
		} {
			b, err := e.Encode()
			if err != nil || !bytes.Equal(b, oldB) {
				t.Errorf("a=%d %s: % x, %v; want % x", a, name, b, err, oldB)
			}
		}
	}
}
