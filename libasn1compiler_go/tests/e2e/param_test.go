package e2e

import (
	"bytes"
	"testing"

	pa "asn1cgo.test/go/param"
)

// Specializations of parameterized types that are not information object
// containers (tests/e2e/param.asn): each is its own Go type named after its
// C type (PPair{INTEGER (0..7)} -> C PPair_11P0_t -> Go PPair11P0). Copied into
// the generated module by tests/run-e2e.sh together with seqof_test.go (the
// siCase helpers) and default_test.go (the converter helpers). Every value is
// encoded in Go, compared with the C converter's APER of the same value
// written as XER, re-encoded by the C converter and decoded back in Go.
func paCases() []siCase {
	yes, no := true, false
	oct := []byte{0xAB, 0xCD}
	five := int64(5)
	return []siCase{
		siMk("PMsg/all", "PMsg",
			"<PMsg><i><v>7</v><w><true/></w></i><s><v>abc</v></s>"+
				"<c><a>ABCD</a></c><l><true/><false/><true/></l>"+
				"<li><PPair><v><k>3</k></v></PPair><PPair><v><k>9</k></v><w><false/></w></PPair></li>"+
				"<r><n>100</n></r><sm>5</sm><o><v><k>0</k></v></o>"+
				"<nn><v><v><true/></v></v><w><false/></w></nn></PMsg>",
			&pa.PMsg{
				I:  pa.PPair11P0{V: 7, W: &yes},
				S:  pa.PPair11P1{V: "abc"},
				C:  pa.POpt12P0{Present: pa.POpt12P0PrA, A: &oct},
				L:  pa.PLst14P0{true, false, true},
				Li: pa.PLst14P1{{V: pa.PItem{K: 3}}, {V: pa.PItem{K: 9}, W: &no}},
				R:  pa.PRng14P0{N: 100},
				Sm: pa.PSmall15P0(five),
				O:  &pa.PPair11P2{V: pa.PItem{K: 0}},
				Nn: &pa.PPair11P3{V: pa.PPair11P5{V: true}, W: &no},
			}, pa.DecodePMsg),
		siMk("PMsg/min", "PMsg",
			"<PMsg><i><v>0</v></i><s><v></v></s><c><b/></c><l><false/></l>"+
				"<li><PPair><v><k>1</k></v></PPair></li><r><n>0</n></r><sm>0</sm></PMsg>",
			&pa.PMsg{
				I:  pa.PPair11P0{V: 0},
				S:  pa.PPair11P1{V: ""},
				C:  pa.POpt12P0{Present: pa.POpt12P0PrB},
				L:  pa.PLst14P0{false},
				Li: pa.PLst14P1{{V: pa.PItem{K: 1}}},
				R:  pa.PRng14P0{N: 0},
				Sm: 0,
			}, pa.DecodePMsg),
		siMk("PCh/p", "PCh", "<PCh><p><v>3</v><w><true/></w></p></PCh>",
			&pa.PCh{Present: pa.PChPrP, P: &pa.PPair11P4{V: 3, W: &yes}}, pa.DecodePCh),
		siMk("PCh/q", "PCh", "<PCh><q><a><k>4</k></a></q></PCh>",
			&pa.PCh{Present: pa.PChPrQ, Q: &pa.POpt12P1{Present: pa.POpt12P1PrA, A: &pa.PItem{K: 4}}}, pa.DecodePCh),
	}
}

func TestParamRoundTrip(t *testing.T) {
	for _, c := range paCases() {
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

func TestParamCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range paCases() {
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
	}
}

// PCh.p is PPair{INTEGER (0..3)}, its own specialization, not the one of
// PPair{INTEGER (0..7)}: v takes 2 bits, not 3. Choice index 0, w present,
// v = 3, w = TRUE: 0 1 11 1 -> 78.
func TestParamConstraintKept(t *testing.T) {
	yes := true
	b, err := (&pa.PCh{Present: pa.PChPrP, P: &pa.PPair11P4{V: 3, W: &yes}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x78}) {
		t.Errorf("PCh p {3, TRUE} APER = % x, want 78", b)
	}
	if _, err := (&pa.PCh{Present: pa.PChPrP, P: &pa.PPair11P4{V: 4}}).Encode(); err == nil {
		t.Errorf("PCh p {4} encoded; v is INTEGER (0..3)")
	}
}

// The Go values of the specializations are distinct types: PPair{INTEGER} and
// PPair{UTF8String} must not collapse into one Go type.
func TestParamDistinctTypes(t *testing.T) {
	var a any = pa.PPair11P0{}
	if _, ok := a.(pa.PPair11P1); ok {
		t.Fatal("PPair11P0 and PPair11P1 are the same Go type")
	}
}
