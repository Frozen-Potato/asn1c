package e2e

import (
	"bytes"
	"reflect"
	"testing"

	ao "asn1cgo.test/go/aliasother"
	at "asn1cgo.test/go/aliastypes"
)

// Type assignments that only rename another type (tests/e2e/alias.asn).
// Copied into the generated module by tests/run-e2e.sh together with
// seqof_test.go (the siCase helpers) and default_test.go (the converter
// helpers). Each alias is a PDU of its own: Encode / Decode use its own C
// descriptor, so the C converter run with -p <Alias> must agree with Go.
// The expected APER bytes are asn1tools' (X.691).
type alCase struct {
	siCase
	aper []byte
}

func alCases() []alCase {
	yes := true
	two := int64(2)
	mk := func(c siCase, aper ...byte) alCase { return alCase{c, aper} }
	return []alCase{
		mk(siMk("AlSeqT", "AlSeqT", "<AlSeqT><id>5</id><flag><true/></flag></AlSeqT>",
			&at.AlSeqT{Id: 5, Flag: &yes}, at.DecodeAlSeqT), 0x40, 0x05, 0x80),
		mk(siMk("AlSeqAA", "AlSeqAA", "<AlSeqAA><id>5</id><flag><true/></flag></AlSeqAA>",
			&at.AlSeqAA{Id: 5, Flag: &yes}, at.DecodeAlSeqAA), 0x40, 0x05, 0x80),
		mk(siMk("AlSetA", "AlSetA", "<AlSetA><x>3</x><y><true/></y></AlSetA>",
			&at.AlSetA{X: 3, Y: true}, at.DecodeAlSetA), 0x70),
		mk(siMk("AlLstA", "AlLstA", "<AlLstA><INTEGER>1</INTEGER><INTEGER>2</INTEGER><INTEGER>7</INTEGER></AlLstA>",
			&at.AlLstA{1, 2, 7}, at.DecodeAlLstA), 0x8a, 0xe0),
		mk(siMk("AlInst", "AlInst", "<AlInst><v><true/></v></AlInst>",
			&at.AlInst{V: true}, at.DecodeAlInst), 0x80),
		mk(siMk("AlMem", "AlMem", "<AlMem><e><z/></e><c><a>2</a></c></AlMem>",
			&at.AlMem{E: at.AlEnZ, C: at.AlCh{Present: at.AlChPrA, A: &two}}, at.DecodeAlMem), 0x88),
		mk(siMk("AlXCh", "AlXCh", "<AlXCh><b><true/></b></AlXCh>",
			&ao.AlXCh{Present: at.AlChPrB, B: &yes}, ao.DecodeAlXCh), 0x60),
		mk(siMk("AlXSeq", "AlXSeq", "<AlXSeq><id>5</id><flag><true/></flag></AlXSeq>",
			&ao.AlXSeq{Id: 5, Flag: &yes}, ao.DecodeAlXSeq), 0x40, 0x05, 0x80),
	}
}

func TestAliasRoundTrip(t *testing.T) {
	for _, c := range alCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: APER % x, want % x", c.name, aper, c.aper)
		}
		if err := c.dec(aper); err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
		}
	}
}

func TestAliasCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range alCases() {
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
	}
}

// A SEQUENCE, SET or CHOICE alias is a Go defined type over its target: the
// values convert both ways, and a CHOICE alias uses the target's Pr
// constants. AlSeqA is not a PDU (AlSeqAA refers to it, -pdu=auto), so it
// has no functions; AlSeqAA, an alias of an alias, has.
func TestAliasTypes(t *testing.T) {
	v := at.AlSeq{Id: 7}
	a := at.AlSeqT(v)
	if back := at.AlSeq(a); !reflect.DeepEqual(back, v) {
		t.Errorf("AlSeq(AlSeqT(v)) = %+v, want %+v", back, v)
	}
	if reflect.TypeOf(at.AlSeqT{}) == reflect.TypeOf(at.AlSeq{}) {
		t.Errorf("AlSeqT is the same Go type as AlSeq")
	}
	x := ao.AlXSeq(v)
	if at.AlSeq(x).Id != 7 {
		t.Errorf("AlXSeq conversion lost the value")
	}
	aa := at.AlSeqAA(at.AlSeqA(v))
	b, err := (&aa).EncodeUPER()
	if err != nil {
		t.Fatal(err)
	}
	back, err := at.DecodeUPERAlSeqAA(b)
	if err != nil || at.AlSeq(*back) != v {
		t.Errorf("AlSeqAA UPER round trip: %+v, %v", back, err)
	}
	c := at.AlChA{Present: at.AlChPrB}
	if at.AlCh(c).Present != at.AlChPrB {
		t.Errorf("AlChA conversion lost Present")
	}
}
