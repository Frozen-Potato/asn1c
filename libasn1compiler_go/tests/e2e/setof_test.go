// SET OF (tests/e2e/setof.asn). Copied into the generated module by
// tests/run-e2e.sh together with seqofinline_test.go (the siCase helpers) and
// default_test.go (the converter helpers).
//
// A SET OF is a Go slice like a SEQUENCE OF, and Encode writes the elements in
// canonical order (sorted by their standalone encodings), so an unsorted input
// comes back sorted. The first three types are the vectors of the C test
// 170-set-of-aper-OK: the exact APER bytes are asserted. Every case also
// checks that Decode of the bytes gives the sorted value and that the C
// converter agrees (APER of the XER value, APER re-encode, XER of the APER).
package e2e

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	so "asn1cgo.test/go/setof"
)

// soCase is a siCase whose decoded value is the sorted value, not the input.
type soCase struct {
	siCase
	aper []byte // exact APER, nil when only cross-checked against the C side
}

func soMk[T any](name, pdu, xer string, aper []byte, in, want *T, dec func([]byte) (*T, error)) soCase {
	return soCase{
		siCase: siCase{
			name: name, pdu: pdu, xer: xer,
			enc: func() ([]byte, error) { return any(in).(siEncoder).Encode() },
			dec: func(b []byte) error {
				got, err := dec(b)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("decoded %+v, want %+v", got, want)
				}
				return nil
			},
		},
		aper: aper,
	}
}

func soCases() []soCase {
	var cs []soCase
	add := func(c soCase) { cs = append(cs, c) }
	el := func(name string, inner ...string) string {
		s := "<" + name + ">"
		for _, i := range inner {
			s += i
		}
		return s + "</" + name + ">"
	}
	ints := func(vs ...int) []string {
		var o []string
		for _, v := range vs {
			o = append(o, el("INTEGER", fmt.Sprint(v)))
		}
		return o
	}
	i64 := func(vs ...int64) []int64 { return vs }

	// The C test vectors.
	inA, wantA := so.SoInt(i64(3, 1, 200)), so.SoInt(i64(1, 3, 200))
	add(soMk("int-a", "SoInt", el("SoInt", ints(1, 3, 200)...), []byte{0x60, 0x01, 0x03, 0xc8}, &inA, &wantA, so.DecodeSoInt))
	sorted := so.SoInt(i64(1, 3, 200))
	add(soMk("int-sorted", "SoInt", el("SoInt", ints(1, 3, 200)...), []byte{0x60, 0x01, 0x03, 0xc8}, &sorted, &sorted, so.DecodeSoInt))
	add(soMk("int-e", "SoInt", el("SoInt"), []byte{0x00}, &so.SoInt{}, func() *so.SoInt { v := so.SoInt(nil); return &v }(), so.DecodeSoInt))
	add(soMk("octs-a", "SoOcts",
		el("SoOcts", el("OCTET_STRING"), el("OCTET_STRING", "01"), el("OCTET_STRING", "0102")),
		[]byte{3, 0, 1, 1, 2, 1, 2},
		&so.SoOcts{{1, 2}, {1}, {}}, &so.SoOcts{nil, {1}, {1, 2}}, so.DecodeSoOcts))
	add(soMk("seq-a", "SoSeq",
		el("SoSeq",
			el("SEQUENCE", el("f", "<false/>"), el("o", "BBCC")),
			el("SEQUENCE", el("f", "<true/>"), el("o", "AA"))),
		[]byte{0x24, 0xbb, 0xcc, 0x90, 0xaa},
		&so.SoSeq{{F: true, O: []byte{0xaa}}, {F: false, O: []byte{0xbb, 0xcc}}},
		&so.SoSeq{{F: false, O: []byte{0xbb, 0xcc}}, {F: true, O: []byte{0xaa}}}, so.DecodeSoSeq))

	// Extensible SIZE.
	xin, xwant := so.SoExt(i64(9, 2, 5)), so.SoExt(i64(2, 5, 9))
	add(soMk("ext", "SoExt", el("SoExt", ints(2, 5, 9)...), nil, &xin, &xwant, so.DecodeSoExt))

	// Member, OPTIONAL member, CHOICE alternative.
	ma, mwant := so.SoMemA(i64(7, 0, 255, 7)), so.SoMemA(i64(0, 7, 7, 255))
	add(soMk("mem", "SoMem", el("SoMem", el("a", ints(0, 7, 7, 255)...), el("flag", "<true/>")), nil,
		&so.SoMem{A: ma, Flag: true}, &so.SoMem{A: mwant, Flag: true}, so.DecodeSoMem))
	ob, obw := so.SoOptB(i64(4, 3)), so.SoOptB(i64(3, 4))
	add(soMk("opt-set", "SoOpt", el("SoOpt", el("flag", "<false/>"), el("b", ints(3, 4)...)), nil,
		&so.SoOpt{B: &ob}, &so.SoOpt{B: &obw}, so.DecodeSoOpt))
	add(soMk("opt-absent", "SoOpt", el("SoOpt", el("flag", "<true/>")), nil,
		&so.SoOpt{Flag: true}, &so.SoOpt{Flag: true}, so.DecodeSoOpt))
	aa, aw := so.SoAltA(i64(200, 100)), so.SoAltA(i64(100, 200))
	add(soMk("alt-a", "SoAlt", el("SoAlt", el("a", ints(100, 200)...)), nil,
		&so.SoAlt{Present: so.SoAltPrA, A: &aa}, &so.SoAlt{Present: so.SoAltPrA, A: &aw}, so.DecodeSoAlt))
	bt := true
	add(soMk("alt-b", "SoAlt", el("SoAlt", el("b", "<true/>")), nil,
		&so.SoAlt{Present: so.SoAltPrB, B: &bt}, &so.SoAlt{Present: so.SoAltPrB, B: &bt}, so.DecodeSoAlt))

	// Nested lists: SET OF SET OF SEQUENCE. Inner and outer lists are sorted.
	row := func(f bool, n int64) so.SoNestMemberMember { return so.SoNestMemberMember{F: f, N: n} }
	nin := so.SoNest{
		{row(true, 5), row(false, 2)},
		{row(false, 1)},
	}
	nwant := so.SoNest{
		{row(false, 1)},
		{row(false, 2), row(true, 5)},
	}
	add(soMk("nest", "SoNest", "", nil, &nin, &nwant, so.DecodeSoNest))

	// SET OF a NULL type.
	for n := 0; n <= 4; n += 2 {
		in := so.SoNull(make([]so.SoN, n))
		w := so.SoNull(make([]so.SoN, n))
		if n == 0 {
			w = nil
		}
		want := &w
		xs := make([]string, n)
		for i := range xs {
			xs[i] = "<SoN/>"
		}
		add(soMk(fmt.Sprintf("null-%d", n), "SoNull", el("SoNull", xs...), nil, &in, want, so.DecodeSoNull))
	}
	return cs
}

func TestSetOfRoundTrip(t *testing.T) {
	for _, c := range soCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if c.aper != nil && !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: Go APER % x, want % x", c.name, aper, c.aper)
		}
		if c.dec == nil {
			continue
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
	}
}

func TestSetOfCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range soCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if c.xer != "" {
			if ref, ok := siConv(t, bin, c.siCase, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
				t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
			}
		}
		if re, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c.siCase, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if c.xer != "" {
			if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
				t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
			}
		}
		if re, ok := siConv(t, bin, c.siCase, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}
