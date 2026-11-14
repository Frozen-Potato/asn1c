// BIT STRING shapes imported into a module that has its own BIT STRING
// (tests/e2e/xmodbits.asn): a plain member, a DEFAULT member, an inline
// SEQUENCE OF BIT STRING member and a named SEQUENCE OF BIT STRING. Each
// package declares its own BitString type, so the imported values are the
// owner's type while the importing package's glue helpers take its own.
// Building the module is the first check. Each Msg is encoded in Go and must
// equal fixed APER bytes (themselves the C converter's APER of the XER below),
// the C converter must render the Go bytes as the fixed XER, and decoding the
// bytes must give back the input. Copied into the generated module by
// tests/run-e2e.sh with default_test.go.
package e2e

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	xa "asn1cgo.test/go/xbsa"
	xb "asn1cgo.test/go/xbsb"
)

func TestXmodBitStringRoundTrip(t *testing.T) {
	bin := converter(t)
	bs := func(b byte, unused int32) xa.BitString { return xa.BitString{Bytes: []byte{b}, BitsUnused: unused} }
	cases := []struct {
		name string
		v    xb.XbMsg
		xer  string
		aper []byte
	}{
		{"all-set",
			xb.XbMsg{
				P:   xa.XbPlain{Bm: bs(0xa5, 0), N: 5},
				D:   xa.XbDef{Bm: bs(0x50, 4), N: 2},
				I:   xa.XbInl{L: xa.XbInlL{bs(0x90, 4)}},
				L:   xa.XbList{bs(0x10, 4)},
				Own: xb.BitString{Bytes: []byte{0xc0}, BitsUnused: 4},
			},
			"<XbMsg><p><bm>10100101</bm><n>5</n></p><d><bm>0101</bm><n>2</n></d>" +
				"<i><l><BIT_STRING>1001</BIT_STRING></l></i><l><BIT_STRING>0001</BIT_STRING></l><own>1100</own></XbMsg>",
			[]byte{0xa5, 0xb5, 0x40, 0x01, 0x90, 0x01, 0x1c}},
		{"default-and-empty",
			xb.XbMsg{
				P:   xa.XbPlain{Bm: bs(0x00, 0), N: 0},
				D:   xa.XbDef{Bm: xa.XbDefBmDefault, N: 7},
				I:   xa.XbInl{},
				L:   xa.XbList{bs(0xf0, 4), bs(0x00, 4)},
				Own: xb.BitString{Bytes: []byte{0x10}, BitsUnused: 4},
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
		got, err := xb.DecodeXbMsg(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
		} else if !reflect.DeepEqual(got, &c.v) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, &c.v)
		}
	}
}
