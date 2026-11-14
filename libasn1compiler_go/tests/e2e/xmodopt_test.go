// OPTIONAL members of imported types (tests/e2e/xmodopt.asn): an OPTIONAL
// named BIT STRING member and an OPTIONAL inline SEQUENCE OF member, imported
// by a module that declares no BIT STRING of its own. The importing glue must
// spell the owner's BitString and the owner's list type package-qualified;
// building the module is the first check. Each value is encoded in Go and
// must equal fixed APER bytes (themselves the C converter's APER of the XER
// below), the C converter must render the Go bytes as the fixed XER, and
// decoding the bytes must give back the input (present and absent OPTIONALs).
// Copied into the generated module by tests/run-e2e.sh with default_test.go.
package e2e

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	xa "asn1cgo.test/go/xoa"
	xb "asn1cgo.test/go/xob"
)

func TestXmodOptRoundTrip(t *testing.T) {
	bin := converter(t)
	rn := xa.XoRnti{Bytes: []byte{0xab, 0xcd}}
	cases := []struct {
		name string
		v    xb.XoMsg
		xer  string
		aper []byte
	}{
		{"present",
			xb.XoMsg{
				B: xa.XoBits{R: &rn, K: 5},
				L: xa.XoList{L: &xa.XoListL{{N: 1}, {N: 6}}, K: 2},
			},
			"<XoMsg><b><r>1010101111001101</r><k>5</k></b><l><l><XoIt><n>1</n></XoIt><XoIt><n>6</n></XoIt></l><k>2</k></l></XoMsg>",
			[]byte{0xd5, 0xe6, 0xda, 0x72}},
		{"absent",
			xb.XoMsg{
				B: xa.XoBits{K: 3},
				L: xa.XoList{K: 7},
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
		got, err := xb.DecodeXoMsg(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
		} else if !reflect.DeepEqual(got, &c.v) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, &c.v)
		}
	}
}
