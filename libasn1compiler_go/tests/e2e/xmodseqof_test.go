// A named SEQUENCE OF imported from another module (tests/e2e/xmodseqof.asn):
// as an OPTIONAL member, as a required member, and by a third module that
// imports both the list and the types of the second module that use it. The generated glue must qualify the list type
// with the owning package exactly once; building the module is the first
// check. Msg values with 1 and 4 items are encoded in Go, compared with the C
// converter's APER of the same value written as XER, and decoded back. Copied
// into the generated module by tests/run-e2e.sh with default_test.go.
package e2e

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"

	xa "asn1cgo.test/go/xmsa"
	xb "asn1cgo.test/go/xmsb"
	xc "asn1cgo.test/go/xmsc"
)

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
