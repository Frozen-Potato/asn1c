// SEQUENCE OF with an inline element type (tests/e2e/seqofinline.asn). Copied
// into the generated module by tests/run-e2e.sh together with default_test.go
// (the converter helpers) and bitstr_test.go (bsText/bsXML).
//
// Every case is a value of a SEQUENCE OF whose element is an anonymous type —
// INTEGER, BOOLEAN, OCTET STRING, BIT STRING, PrintableString, REAL, NULL,
// SEQUENCE, CHOICE, ENUMERATED, a named-bit BIT STRING or another SEQUENCE
// OF — at top level, as a SEQUENCE member, as an OPTIONAL member and as a
// CHOICE alternative, with an empty list, a short list and a list at the SIZE
// upper bound. Per case:
//
//   - Go APER == the C converter's APER of the same value written as XER;
//   - Go's decode of that APER gives the value back (reflect.DeepEqual);
//   - the converter's XER of the Go APER is the given XER, and re-encodes to
//     the same APER;
//
// The allocation-fault sweep over the same values is in faults_test.go.
package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	si "asn1cgo.test/go/seqofinl"
)

type siCase struct {
	name, pdu, xer string
	enc            func() ([]byte, error)
	dec            func([]byte) error // decode + compare with the encoded value
}

type siEncoder interface{ Encode() ([]byte, error) }

func siMk[T any](name, pdu, xer string, v *T, dec func([]byte) (*T, error)) siCase {
	return siCase{
		name: name, pdu: pdu, xer: xer,
		enc: func() ([]byte, error) { return any(v).(siEncoder).Encode() },
		dec: func(b []byte) error {
			got, err := dec(b)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, v) {
				return fmt.Errorf("decoded %+v, want %+v", got, v)
			}
			return nil
		},
	}
}

func siBool(b bool) string {
	if b {
		return "<true/>"
	}
	return "<false/>"
}

func siList(pdu string, elems ...string) string {
	return "<" + pdu + ">" + strings.Join(elems, "") + "</" + pdu + ">"
}

func siInts(vs ...int64) []string {
	var o []string
	for _, v := range vs {
		o = append(o, "<INTEGER>"+strconv.FormatInt(v, 10)+"</INTEGER>")
	}
	return o
}

func siBools(vs ...bool) []string {
	var o []string
	for _, v := range vs {
		o = append(o, siBool(v))
	}
	return o
}

func siOcts(vs ...[]byte) []string {
	var o []string
	for _, v := range vs {
		o = append(o, "<OCTET_STRING>"+strings.ToUpper(fmt.Sprintf("%x", v))+"</OCTET_STRING>")
	}
	return o
}

func siStrs(vs ...string) []string {
	var o []string
	for _, v := range vs {
		o = append(o, "<PrintableString>"+v+"</PrintableString>")
	}
	return o
}

func siNulls(n int) []string {
	var o []string
	for i := 0; i < n; i++ {
		o = append(o, "<NULL/>")
	}
	return o
}

func siBits(tag string, vs ...si.BitString) []string {
	var o []string
	for _, v := range vs {
		o = append(o, "<"+tag+">"+bsText(v.Bytes, v.BitsUnused)+"</"+tag+">")
	}
	return o
}

func siPtr[T any](v T) *T { return &v }

func siCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }

	// ---- primitive elements, top level ----
	add(siMk("inttop-empty", "IntTop", siList("IntTop"), new(si.IntTop), si.DecodeIntTop))
	add(siMk("inttop-1", "IntTop", siList("IntTop", siInts(2)...), &si.IntTop{2}, si.DecodeIntTop))
	add(siMk("inttop-max", "IntTop", siList("IntTop", siInts(0, 1, 2, 3)...), &si.IntTop{0, 1, 2, 3}, si.DecodeIntTop))
	add(siMk("widetop-empty", "WideTop", siList("WideTop"), new(si.WideTop), si.DecodeWideTop))
	add(siMk("widetop-max", "WideTop", siList("WideTop", siInts(-1000000000, 0, 1000000000, 7)...), &si.WideTop{-1000000000, 0, 1000000000, 7}, si.DecodeWideTop))
	add(siMk("freetop-3", "FreeTop", siList("FreeTop", siInts(-5, 123456789012, 0)...), &si.FreeTop{-5, 123456789012, 0}, si.DecodeFreeTop))
	add(siMk("booltop-empty", "BoolTop", siList("BoolTop"), new(si.BoolTop), si.DecodeBoolTop))
	add(siMk("booltop-1", "BoolTop", siList("BoolTop", siBools(true)...), &si.BoolTop{true}, si.DecodeBoolTop))
	add(siMk("booltop-max", "BoolTop", siList("BoolTop", siBools(true, false, true, false)...), &si.BoolTop{true, false, true, false}, si.DecodeBoolTop))
	add(siMk("octtop-empty", "OctTop", siList("OctTop"), new(si.OctTop), si.DecodeOctTop))
	add(siMk("octtop-1", "OctTop", siList("OctTop", siOcts([]byte{1})...), &si.OctTop{{1}}, si.DecodeOctTop))
	add(siMk("octtop-max", "OctTop", siList("OctTop", siOcts([]byte{1, 2, 3}, []byte{0xff}, []byte{4, 5}, []byte{6})...),
		&si.OctTop{{1, 2, 3}, {0xff}, {4, 5}, {6}}, si.DecodeOctTop))
	b3 := si.BitString{Bytes: []byte{0xA0}, BitsUnused: 5} // 101
	b8 := si.BitString{Bytes: []byte{0x81}}                // 10000001
	b1 := si.BitString{Bytes: []byte{0x80}, BitsUnused: 7} // 1
	add(siMk("bittop-empty", "BitTop", siList("BitTop"), new(si.BitTop), si.DecodeBitTop))
	add(siMk("bittop-1", "BitTop", siList("BitTop", siBits("BIT_STRING", b3)...), &si.BitTop{b3}, si.DecodeBitTop))
	add(siMk("bittop-max", "BitTop", siList("BitTop", siBits("BIT_STRING", b1, b3, b8, b3)...), &si.BitTop{b1, b3, b8, b3}, si.DecodeBitTop))
	add(siMk("strtop-empty", "StrTop", siList("StrTop"), new(si.StrTop), si.DecodeStrTop))
	add(siMk("strtop-1", "StrTop", siList("StrTop", siStrs("ab")...), &si.StrTop{"ab"}, si.DecodeStrTop))
	add(siMk("strtop-max", "StrTop", siList("StrTop", siStrs("a", "bc", "def", "ghij")...), &si.StrTop{"a", "bc", "def", "ghij"}, si.DecodeStrTop))
	add(siMk("realtop-empty", "RealTop", siList("RealTop"), new(si.RealTop), si.DecodeRealTop))
	add(siMk("realtop-2", "RealTop", siList("RealTop", "<REAL>1.5</REAL>", "<REAL>-2.0</REAL>"), &si.RealTop{1.5, -2}, si.DecodeRealTop))
	add(siMk("nulltop-empty", "NullTop", siList("NullTop"), new(si.NullTop), si.DecodeNullTop))
	add(siMk("nulltop-1", "NullTop", siList("NullTop", siNulls(1)...), &si.NullTop{{}}, si.DecodeNullTop))
	add(siMk("nulltop-max", "NullTop", siList("NullTop", siNulls(4)...), &si.NullTop{{}, {}, {}, {}}, si.DecodeNullTop))

	// ---- primitive elements as members / OPTIONAL members / alternatives ----
	holder := func(name string, v *si.InlHolder) {
		x := "<a>" + strings.Join(siInts(v.A...), "") + "</a>"
		if v.B != nil {
			x += "<b>" + strings.Join(siBools(*v.B...), "") + "</b>"
		}
		if v.C != nil {
			x += "<c>" + strings.Join(siOcts(*v.C...), "") + "</c>"
		}
		if v.D != nil {
			x += "<d>" + strings.Join(siNulls(len(*v.D)), "") + "</d>"
		}
		x += "<flag>" + siBool(v.Flag) + "</flag>"
		add(siMk(name, "InlHolder", "<InlHolder>"+x+"</InlHolder>", v, si.DecodeInlHolder))
	}
	holder("holder-min", &si.InlHolder{Flag: true})
	holder("holder-a", &si.InlHolder{A: si.InlHolderA{3, 0, 1, 2}, Flag: false})
	holder("holder-all", &si.InlHolder{
		A:    si.InlHolderA{1},
		B:    &si.InlHolderB{true, false, true, false},
		C:    &si.InlHolderC{{1, 2, 3}, {9}},
		D:    &si.InlHolderD{{}, {}, {}},
		Flag: true,
	})
	// OPTIONAL present but empty is distinct from absent on the wire.
	holder("holder-empty-optionals", &si.InlHolder{
		B: new(si.InlHolderB), C: new(si.InlHolderC), D: new(si.InlHolderD), Flag: true,
	})

	alt := func(name, inner string, v *si.InlAlt) {
		add(siMk(name, "InlAlt", "<InlAlt>"+inner+"</InlAlt>", v, si.DecodeInlAlt))
	}
	alt("alt-a-empty", "<a></a>", &si.InlAlt{Present: si.InlAltPrA, A: new(si.InlAltA)})
	alt("alt-a-max", "<a>"+strings.Join(siInts(3, 2, 1, 0), "")+"</a>", &si.InlAlt{Present: si.InlAltPrA, A: &si.InlAltA{3, 2, 1, 0}})
	alt("alt-b", "<b>"+strings.Join(siStrs("x", "yz"), "")+"</b>", &si.InlAlt{Present: si.InlAltPrB, B: &si.InlAltB{"x", "yz"}})
	alt("alt-c", "<c>"+siBool(true)+"</c>", &si.InlAlt{Present: si.InlAltPrC, C: siPtr(true)})

	// ---- constructed elements, top level ----
	add(siMk("seqtop-empty", "SeqTop", siList("SeqTop"), new(si.SeqTop), si.DecodeSeqTop))
	add(siMk("seqtop-2", "SeqTop", siList("SeqTop",
		"<SEQUENCE><x>1</x></SEQUENCE>",
		"<SEQUENCE><x>3</x><y>"+siBool(true)+"</y></SEQUENCE>"),
		&si.SeqTop{{X: 1}, {X: 3, Y: siPtr(true)}}, si.DecodeSeqTop))
	add(siMk("seqtop-max", "SeqTop", siList("SeqTop",
		"<SEQUENCE><x>0</x></SEQUENCE>", "<SEQUENCE><x>1</x><y>"+siBool(false)+"</y></SEQUENCE>",
		"<SEQUENCE><x>2</x></SEQUENCE>", "<SEQUENCE><x>3</x><y>"+siBool(true)+"</y></SEQUENCE>"),
		&si.SeqTop{{X: 0}, {X: 1, Y: siPtr(false)}, {X: 2}, {X: 3, Y: siPtr(true)}}, si.DecodeSeqTop))
	add(siMk("choicetop-empty", "ChoiceTop", siList("ChoiceTop"), new(si.ChoiceTop), si.DecodeChoiceTop))
	add(siMk("choicetop-max", "ChoiceTop", siList("ChoiceTop",
		"<x>2</x>", "<y>"+siBool(true)+"</y>",
		"<x>0</x>", "<y>"+siBool(false)+"</y>"),
		&si.ChoiceTop{
			{Present: si.ChoiceTopMemberPrX, X: siPtr(int64(2))},
			{Present: si.ChoiceTopMemberPrY, Y: siPtr(true)},
			{Present: si.ChoiceTopMemberPrX, X: siPtr(int64(0))},
			{Present: si.ChoiceTopMemberPrY, Y: siPtr(false)},
		}, si.DecodeChoiceTop))
	add(siMk("enumtop-empty", "EnumTop", siList("EnumTop"), new(si.EnumTop), si.DecodeEnumTop))
	add(siMk("enumtop-max", "EnumTop", siList("EnumTop", "<green/>", "<blue/>", "<red/>", "<green/>"),
		&si.EnumTop{si.EnumTopMemberGreen, si.EnumTopMemberBlue, si.EnumTopMemberRed, si.EnumTopMemberGreen}, si.DecodeEnumTop))
	add(siMk("nesttop-empty", "NestTop", siList("NestTop"), new(si.NestTop), si.DecodeNestTop))
	add(siMk("nesttop-max", "NestTop", siList("NestTop",
		"<SEQUENCE_OF>"+strings.Join(siInts(1, 2), "")+"</SEQUENCE_OF>",
		"<SEQUENCE_OF></SEQUENCE_OF>",
		"<SEQUENCE_OF>"+strings.Join(siInts(-7), "")+"</SEQUENCE_OF>"),
		&si.NestTop{{1, 2}, nil, {-7}}, si.DecodeNestTop))
	add(siMk("nest3top-max", "Nest3Top", siList("Nest3Top",
		"<SEQUENCE_OF>"+strings.Join(siBools(true, false), "")+"</SEQUENCE_OF>",
		"<SEQUENCE_OF>"+strings.Join(siBools(false), "")+"</SEQUENCE_OF>"),
		&si.Nest3Top{{true, false}, {false}}, si.DecodeNest3Top))
	add(siMk("bitsnamedtop-max", "BitsNamedTop", siList("BitsNamedTop", siBits("BIT_STRING", b3, b3, b1, b8)...),
		&si.BitsNamedTop{b3, b3, b1, b8}, si.DecodeBitsNamedTop))

	// ---- constructed elements as members / OPTIONAL members / alternatives ----
	sm := func(name string, v *si.SeqMem) {
		x := "<a>"
		for _, e := range v.A {
			x += "<SEQUENCE><x>" + strconv.FormatInt(e.X, 10) + "</x><y>" + siBool(e.Y) + "</y></SEQUENCE>"
		}
		x += "</a>"
		if v.B != nil {
			x += "<b>"
			for _, e := range *v.B {
				if e.Present == si.SeqMemBMemberPrX {
					x += "<x>" + strconv.FormatInt(*e.X, 10) + "</x>"
				} else {
					x += "<y>" + siBool(*e.Y) + "</y>"
				}
			}
			x += "</b>"
		}
		if v.C != nil {
			x += "<c>"
			for _, e := range *v.C {
				x += map[si.SeqMemCMember]string{si.SeqMemCMemberRed: "<red/>", si.SeqMemCMemberGreen: "<green/>"}[e]
			}
			x += "</c>"
		}
		if v.D != nil {
			x += "<d>" + strings.Join(siBits("BIT_STRING", *v.D...), "") + "</d>"
		}
		x += "<flag>" + siBool(v.Flag) + "</flag>"
		add(siMk(name, "SeqMem", "<SeqMem>"+x+"</SeqMem>", v, si.DecodeSeqMem))
	}
	q2 := si.BitString{Bytes: []byte{0xC0}, BitsUnused: 6} // 11
	sm("seqmem-min", &si.SeqMem{Flag: true})
	sm("seqmem-a-max", &si.SeqMem{A: si.SeqMemA{{X: 0, Y: true}, {X: 1}, {X: 2, Y: true}, {X: 3}}, Flag: false})
	sm("seqmem-all", &si.SeqMem{
		A: si.SeqMemA{{X: 3, Y: true}},
		B: &si.SeqMemB{
			{Present: si.SeqMemBMemberPrX, X: siPtr(int64(3))},
			{Present: si.SeqMemBMemberPrY, Y: siPtr(true)},
		},
		C:    &si.SeqMemC{si.SeqMemCMemberGreen, si.SeqMemCMemberRed, si.SeqMemCMemberGreen, si.SeqMemCMemberRed},
		D:    &si.SeqMemD{q2, q2, q2},
		Flag: true,
	})
	sm("seqmem-empty-optionals", &si.SeqMem{B: new(si.SeqMemB), C: new(si.SeqMemC), D: new(si.SeqMemD), Flag: true})

	altc := func(name, inner string, v *si.InlAltC) {
		add(siMk(name, "InlAltC", "<InlAltC>"+inner+"</InlAltC>", v, si.DecodeInlAltC))
	}
	altc("altc-a-empty", "<a></a>", &si.InlAltC{Present: si.InlAltCPrA, A: new(si.InlAltCA)})
	altc("altc-a-max", "<a><SEQUENCE><x>0</x></SEQUENCE><SEQUENCE><x>1</x></SEQUENCE><SEQUENCE><x>2</x></SEQUENCE><SEQUENCE><x>3</x></SEQUENCE></a>",
		&si.InlAltC{Present: si.InlAltCPrA, A: &si.InlAltCA{{X: 0}, {X: 1}, {X: 2}, {X: 3}}})
	altc("altc-b", "<b><green/><red/></b>", &si.InlAltC{Present: si.InlAltCPrB, B: &si.InlAltCB{si.InlAltCBMemberGreen, si.InlAltCBMemberRed}})
	altc("altc-c", "<c><SEQUENCE_OF>"+strings.Join(siBools(true, false), "")+"</SEQUENCE_OF><SEQUENCE_OF></SEQUENCE_OF></c>",
		&si.InlAltC{Present: si.InlAltCPrC, C: &si.InlAltCC{{true, false}, nil}})
	altc("altc-d", "<d>"+siBool(false)+"</d>", &si.InlAltC{Present: si.InlAltCPrD, D: siPtr(false)})
	return cs
}

func TestSeqofInlineRoundTrip(t *testing.T) {
	for _, c := range siCases() {
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

// siConv runs the C converter, reporting a failure against the case (not
// fatally) so one bad value does not hide the rest.
func siConv(t *testing.T, bin string, c siCase, data []byte, args ...string) ([]byte, bool) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	a := append(append([]string{}, args...), "-p", c.pdu, f)
	out, err := exec.Command(bin, a...).CombinedOutput()
	if err != nil {
		t.Errorf("%s: converter %v on %q: %v\n%s", c.name, args, data, err, out)
		return nil, false
	}
	return out, true
}

func TestSeqofInlineCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range siCases() {
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

var siEmptyEl = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_-]*)></([A-Za-z_][A-Za-z0-9_-]*)>`)

// siSelfClose rewrites every empty element <x></x> as <x/> (the converter
// prints an empty list either way).
func siSelfClose(x string) string {
	return siEmptyEl.ReplaceAllStringFunc(x, func(m string) string {
		g := siEmptyEl.FindStringSubmatch(m)
		if g[1] != g[2] {
			return m
		}
		return "<" + g[1] + "/>"
	})
}

// The element-name constants of an inline named-bit BIT STRING element.
func TestSeqofInlineBitNames(t *testing.T) {
	if si.BitsNamedTopMemberP != 0 || si.BitsNamedTopMemberQ != 1 || si.BitsNamedTopMemberR != 2 {
		t.Errorf("BitsNamedTop bit constants = %d %d %d", si.BitsNamedTopMemberP, si.BitsNamedTopMemberQ, si.BitsNamedTopMemberR)
	}
	if si.SeqMemDMemberP != 0 || si.SeqMemDMemberQ != 1 {
		t.Errorf("SeqMem.d bit constants = %d %d", si.SeqMemDMemberP, si.SeqMemDMemberQ)
	}
	if si.EnumTopMemberRed != 0 || si.EnumTopMemberGreen != 1 || si.EnumTopMemberBlue != 2 {
		t.Errorf("EnumTop value constants wrong")
	}
}

// A list longer than SIZE and an element outside its range are encode errors,
// not panics or silent truncation.
func TestSeqofInlineConstraints(t *testing.T) {
	tooLong := si.IntTop{0, 1, 2, 3, 0}
	if _, err := tooLong.Encode(); err == nil {
		t.Errorf("IntTop with 5 elements (SIZE(0..4)) encoded")
	}
	bad := si.IntTop{4}
	if _, err := bad.Encode(); err == nil {
		t.Errorf("IntTop element 4 (0..3) encoded")
	}
	badS := si.SeqTop{{X: 9}}
	if _, err := badS.Encode(); err == nil {
		t.Errorf("SeqTop element x=9 (0..3) encoded")
	}
}
