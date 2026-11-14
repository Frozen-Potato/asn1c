package e2e

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"

	ca "asn1cgo.test/go/moda"
	cb "asn1cgo.test/go/modb"
	xba "asn1cgo.test/go/xbsa"
	xbb "asn1cgo.test/go/xbsb"
	xa "asn1cgo.test/go/xmsa"
	xb "asn1cgo.test/go/xmsb"
	xc "asn1cgo.test/go/xmsc"
	xoa "asn1cgo.test/go/xoa"
	xob "asn1cgo.test/go/xob"
)

// The same type name in two modules (tests/e2e/xmod.asn, modules ModA and ModB): the
// C headers must spell the recursion-safe "struct ClItem" so the generated
// converters compile (a build failure is the regression). Copied into the
// generated module by tests/run-e2e.sh together with seqof_test.go (the
// siCase helpers) and default_test.go (the converter helpers).
//
// Per case: Go APER == the C converter's APER of the same value written as
// XER, Go's decode gives the value back, and the converter's XER of the Go
// APER is the given XER.
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

// A named SEQUENCE OF imported from another module (tests/e2e/xmod.asn):
// as an OPTIONAL member, as a required member, and by a third module that
// imports both the list and the types of the second module that use it. The generated glue must qualify the list type
// with the owning package exactly once; building the module is the first
// check. Msg values with 1 and 4 items are encoded in Go, compared with the C
// converter's APER of the same value written as XER, and decoded back. Copied
// into the generated module by tests/run-e2e.sh with default_test.go.
func xmsItems(n int) (items xa.XsList, xer string) {
	for i := 0; i < n; i++ {
		items = append(items, xa.XsItem{A: int64(i * 2)})
		xer += "<XsItem><a>" + strconv.Itoa(i*2) + "</a></XsItem>"
	}
	return
}

func TestXmodSeqOfRoundTrip(t *testing.T) {
	bin := converter(t)
	type enc interface{ Encode() ([]byte, error) }
	check := func(pdu, xer string, v enc, dec func([]byte) (any, error)) {
		t.Helper()
		aper, err := v.Encode()
		if err != nil {
			t.Errorf("%s: encode: %v", pdu, err)
			return
		}
		if ref := convPDU(t, bin, pdu, []byte(xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s %s: Go APER % x != C APER % x", pdu, xer, aper, ref)
		}
		got, err := dec(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", pdu, err)
		} else if !reflect.DeepEqual(got, v) {
			t.Errorf("%s: decoded %+v, want %+v", pdu, got, v)
		}
	}
	for _, n := range []int{1, 4} {
		l, lx := xmsItems(n)
		check("XsMsgOpt", "<XsMsgOpt><i>2</i><l>"+lx+"</l></XsMsgOpt>", &xb.XsMsgOpt{I: 2, L: &l},
			func(b []byte) (any, error) { return xb.DecodeXsMsgOpt(b) })
		check("XsMsgReq", "<XsMsgReq><l>"+lx+"</l><i>1</i></XsMsgReq>", &xb.XsMsgReq{L: l, I: 1},
			func(b []byte) (any, error) { return xb.DecodeXsMsgReq(b) })
		check("XsTop", "<XsTop><o><i>2</i><l>"+lx+"</l></o><l>"+lx+"</l></XsTop>",
			&xc.XsTop{O: xb.XsSide{I: 2, L: &l}, L: l},
			func(b []byte) (any, error) { return xc.DecodeXsTop(b) })
	}
	l1, lx1 := xmsItems(1)
	check("XsMsgOpt", "<XsMsgOpt><i>0</i></XsMsgOpt>", &xb.XsMsgOpt{},
		func(b []byte) (any, error) { return xb.DecodeXsMsgOpt(b) })
	check("XsTop", "<XsTop><o><i>0</i></o><l>"+lx1+"</l></XsTop>", &xc.XsTop{L: l1},
		func(b []byte) (any, error) { return xc.DecodeXsTop(b) })
}

// BIT STRING shapes imported into a module that has its own BIT STRING
// (tests/e2e/xmod.asn): a plain member, a DEFAULT member, an inline
// SEQUENCE OF BIT STRING member and a named SEQUENCE OF BIT STRING. Each
// package declares its own BitString type, so the imported values are the
// owner's type while the importing package's glue helpers take its own.
// Building the module is the first check. Each Msg is encoded in Go and must
// equal fixed APER bytes (themselves the C converter's APER of the XER below),
// the C converter must render the Go bytes as the fixed XER, and decoding the
// bytes must give back the input. Copied into the generated module by
// tests/run-e2e.sh with default_test.go.
func TestXmodBitStringRoundTrip(t *testing.T) {
	bin := converter(t)
	bs := func(b byte, unused int32) xba.BitString { return xba.BitString{Bytes: []byte{b}, BitsUnused: unused} }
	cases := []struct {
		name string
		v    xbb.XbMsg
		xer  string
		aper []byte
	}{
		{"all-set",
			xbb.XbMsg{
				P:   xba.XbPlain{Bm: bs(0xa5, 0), N: 5},
				D:   xba.XbDef{Bm: bs(0x50, 4), N: 2},
				I:   xba.XbInl{L: xba.XbInlL{bs(0x90, 4)}},
				L:   xba.XbList{bs(0x10, 4)},
				Own: xbb.BitString{Bytes: []byte{0xc0}, BitsUnused: 4},
			},
			"<XbMsg><p><bm>10100101</bm><n>5</n></p><d><bm>0101</bm><n>2</n></d>" +
				"<i><l><BIT_STRING>1001</BIT_STRING></l></i><l><BIT_STRING>0001</BIT_STRING></l><own>1100</own></XbMsg>",
			[]byte{0xa5, 0xb5, 0x40, 0x01, 0x90, 0x01, 0x1c}},
		{"default-and-empty",
			xbb.XbMsg{
				P:   xba.XbPlain{Bm: bs(0x00, 0), N: 0},
				D:   xba.XbDef{Bm: xba.XbDefBmDefault, N: 7},
				I:   xba.XbInl{},
				L:   xba.XbList{bs(0xf0, 4), bs(0x00, 4)},
				Own: xbb.BitString{Bytes: []byte{0x10}, BitsUnused: 4},
			},
			"<XbMsg><p><bm>00000000</bm><n>0</n></p><d><bm>1010</bm><n>7</n></d>" +
				"<i><l></l></i><l><BIT_STRING>1111</BIT_STRING><BIT_STRING>0000</BIT_STRING></l><own>0001</own></XbMsg>",
			[]byte{0x00, 0x0e, 0x00, 0x02, 0xf0, 0x10}},
	}
	squash := func(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }
	for _, c := range cases {
		aper, err := c.v.Encode()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: Go APER % x, want % x", c.name, aper, c.aper)
		}
		if ref := convPDU(t, bin, "XbMsg", []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, c.aper) {
			t.Errorf("%s: C APER of the XER % x, want % x", c.name, ref, c.aper)
		}
		if x := squash(convPDU(t, bin, "XbMsg", aper, "-iaper", "-oxer")); x != c.xer {
			t.Errorf("%s: XER of the Go bytes %s, want %s", c.name, x, c.xer)
		}
		got, err := xbb.DecodeXbMsg(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
		} else if !reflect.DeepEqual(got, &c.v) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, &c.v)
		}
	}
}

// OPTIONAL members of imported types (tests/e2e/xmod.asn): an OPTIONAL
// named BIT STRING member and an OPTIONAL inline SEQUENCE OF member, imported
// by a module that declares no BIT STRING of its own. The importing glue must
// spell the owner's BitString and the owner's list type package-qualified;
// building the module is the first check. Each value is encoded in Go and
// must equal fixed APER bytes (themselves the C converter's APER of the XER
// below), the C converter must render the Go bytes as the fixed XER, and
// decoding the bytes must give back the input (present and absent OPTIONALs).
// Copied into the generated module by tests/run-e2e.sh with default_test.go.
func TestXmodOptRoundTrip(t *testing.T) {
	bin := converter(t)
	rn := xoa.XoRnti{Bytes: []byte{0xab, 0xcd}}
	cases := []struct {
		name string
		v    xob.XoMsg
		xer  string
		aper []byte
	}{
		{"present",
			xob.XoMsg{
				B: xoa.XoBits{R: &rn, K: 5},
				L: xoa.XoList{L: &xoa.XoListL{{N: 1}, {N: 6}}, K: 2},
			},
			"<XoMsg><b><r>1010101111001101</r><k>5</k></b><l><l><XoIt><n>1</n></XoIt><XoIt><n>6</n></XoIt></l><k>2</k></l></XoMsg>",
			[]byte{0xd5, 0xe6, 0xda, 0x72}},
		{"absent",
			xob.XoMsg{
				B: xoa.XoBits{K: 3},
				L: xoa.XoList{K: 7},
			},
			"<XoMsg><b><k>3</k></b><l><k>7</k></l></XoMsg>",
			[]byte{0x37}},
	}
	squash := func(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }
	for _, c := range cases {
		aper, err := c.v.Encode()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		ref := convPDU(t, bin, "XoMsg", []byte(c.xer), "-ixer", "-oaper")
		if !bytes.Equal(aper, ref) {
			t.Errorf("%s: Go APER % x, C APER of the XER % x", c.name, aper, ref)
		}
		if !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: Go APER % x, want % x", c.name, aper, c.aper)
		}
		if x := squash(convPDU(t, bin, "XoMsg", aper, "-iaper", "-oxer")); x != c.xer {
			t.Errorf("%s: XER of the Go bytes %s, want %s", c.name, x, c.xer)
		}
		got, err := xob.DecodeXoMsg(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
		} else if !reflect.DeepEqual(got, &c.v) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, &c.v)
		}
	}
}
