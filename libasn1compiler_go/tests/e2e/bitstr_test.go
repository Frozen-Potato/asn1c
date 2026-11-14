// BIT STRING members across modules (tests/e2e/bitstr.asn). Copied into the
// generated module by tests/run-e2e.sh together with default_test.go (the
// converter helpers) and namedbit_test.go (a fourth module that owns BIT
// STRING members in the same -Fgo run).
//
//   - OPTIONAL inline BIT STRING (C: BIT_STRING_t *): absent and present,
//     fixed and variable size, and a TNLinformation-shaped SEQUENCE. A present
//     value used to be written INTO the pointer slot and crash the C encoder.
//   - Several modules in one run, each with its own BitString type (one that
//     only imports a BIT STRING type, one that owns members), all building.
//   - OPTIONAL references to BIT STRING types: plain, named-bit, imported.
//
// Every case: the Go APER equals the C converter's APER of the same value
// written as XER; Go's decode renders the given value; the converter's XER of
// the Go bytes is the given value; and the converter re-encodes the Go bytes
// identically. Arena accounting (consumed == reserved) is asserted by the
// generated code itself on every Encode.
package e2e

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"asn1cgo.test/go/bitsa"
	"asn1cgo.test/go/bitsb"
	"asn1cgo.test/go/bitsc"
	"asn1cgo.test/go/ebs"
)

// bsParts builds the buffer of an n-bit string (MSB first) with the given bit
// positions set, plus its unused-bit count.
func bsParts(n int, set ...int) ([]byte, int32) {
	b := make([]byte, (n+7)/8)
	for _, p := range set {
		b[p/8] |= 0x80 >> (p % 8)
	}
	var u int32
	if n%8 != 0 {
		u = int32(8 - n%8)
	}
	return b, u
}

// bsText renders bits as the '0'/'1' text XER uses.
func bsText(b []byte, unused int32) string {
	var sb strings.Builder
	for i := 0; i < len(b)*8-int(unused); i++ {
		if b[i/8]&(0x80>>(i%8)) != 0 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

func bsXML(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }

type bsCase struct {
	name string
	pdu  string
	xer  string
	enc  func() ([]byte, error)
	dec  func([]byte) (string, error) // Go decode, rendered like xer
}

const tru = "<flag><true/></flag>"

func optElem(name string, p *bitsa.BitString) string {
	if p == nil {
		return ""
	}
	return "<" + name + ">" + bsText(p.Bytes, p.BitsUnused) + "</" + name + ">"
}

func bsCases() []bsCase {
	var cs []bsCase
	add := func(c bsCase) { cs = append(cs, c) }

	// 1. inline OPTIONAL BIT STRING (SIZE(8)): absent, 0x00, 0xA5.
	fixed := func(name string, bs *bitsa.BitString) {
		add(bsCase{name, "OptFixed",
			"<OptFixed>" + optElem("opt", bs) + tru + "</OptFixed>",
			func() ([]byte, error) { v := bitsa.OptFixed{Opt: bs, Flag: true}; return v.Encode() },
			func(b []byte) (string, error) {
				v, err := bitsa.DecodeOptFixed(b)
				if err != nil {
					return "", err
				}
				return "<OptFixed>" + optElem("opt", v.Opt) + "<flag>" + map[bool]string{true: "<true/>", false: "<false/>"}[v.Flag] + "</flag></OptFixed>", nil
			}})
	}
	fixed("optfixed-absent", nil)
	fixed("optfixed-00", &bitsa.BitString{Bytes: []byte{0x00}})
	fixed("optfixed-a5", &bitsa.BitString{Bytes: []byte{0xA5}})

	// ... and variable size, SIZE(1..160, ...): 1, 16 and 160 bits.
	variable := func(name string, bs *bitsa.BitString) {
		add(bsCase{name, "OptVar",
			"<OptVar>" + optElem("opt", bs) + tru + "</OptVar>",
			func() ([]byte, error) { v := bitsa.OptVar{Opt: bs, Flag: true}; return v.Encode() },
			func(b []byte) (string, error) {
				v, err := bitsa.DecodeOptVar(b)
				if err != nil {
					return "", err
				}
				return "<OptVar>" + optElem("opt", v.Opt) + tru + "</OptVar>", nil
			}})
	}
	variable("optvar-absent", nil)
	for _, n := range []int{1, 16, 160} {
		b, u := bsParts(n, 0, n-1, n/2)
		variable("optvar-"+strconv.Itoa(n), &bitsa.BitString{Bytes: b, BitsUnused: u})
	}

	// 2. TNLinformation shape.
	tnl := func(name string, addr bitsa.BitString, port *bitsa.BitString) {
		x := "<TnlInfo><tnlAddress>" + bsText(addr.Bytes, addr.BitsUnused) + "</tnlAddress>" + optElem("tnlPort", port) + "</TnlInfo>"
		add(bsCase{name, "TnlInfo", x,
			func() ([]byte, error) { v := bitsa.TnlInfo{TnlAddress: addr, TnlPort: port}; return v.Encode() },
			func(b []byte) (string, error) {
				v, err := bitsa.DecodeTnlInfo(b)
				if err != nil {
					return "", err
				}
				return "<TnlInfo><tnlAddress>" + bsText(v.TnlAddress.Bytes, v.TnlAddress.BitsUnused) + "</tnlAddress>" + optElem("tnlPort", v.TnlPort) + "</TnlInfo>", nil
			}})
	}
	a32, u32 := bsParts(32, 0, 7, 8, 31)
	a160, u160 := bsParts(160, 1, 100, 159)
	tnl("tnl-no-port", bitsa.BitString{Bytes: a32, BitsUnused: u32}, nil)
	tnl("tnl-port", bitsa.BitString{Bytes: a32, BitsUnused: u32}, &bitsa.BitString{Bytes: []byte{0x1F, 0x90}})
	tnl("tnl-port-160", bitsa.BitString{Bytes: a160, BitsUnused: u160}, &bitsa.BitString{Bytes: []byte{0x00, 0x00}})

	// 3. one module that only imports, one that owns members.
	{
		b, u := bsParts(4, 0, 3)
		own := bitsb.BitString{Bytes: b, BitsUnused: u}
		add(bsCase{"bitsb-own", "OwnBits", "<OwnBits><b>1001</b>" + tru + "</OwnBits>",
			func() ([]byte, error) { v := bitsb.OwnBits{B: own, Flag: true}; return v.Encode() },
			func(x []byte) (string, error) {
				v, err := bitsb.DecodeOwnBits(x)
				if err != nil {
					return "", err
				}
				return "<OwnBits><b>" + bsText(v.B.Bytes, v.B.BitsUnused) + "</b>" + tru + "</OwnBits>", nil
			}})
	}
	imp := func(name string, opt *bitsa.RangedBits) {
		rb, ru := bsParts(6, 1, 5)
		req := bitsa.RangedBits{Bytes: rb, BitsUnused: ru}
		o := ""
		if opt != nil {
			o = "<opt>" + bsText(opt.Bytes, opt.BitsUnused) + "</opt>"
		}
		x := "<ImpHolder><req>010001</req>" + o + tru + "</ImpHolder>"
		add(bsCase{name, "ImpHolder", x,
			func() ([]byte, error) { v := bitsc.ImpHolder{Req: req, Opt: opt, Flag: true}; return v.Encode() },
			func(b []byte) (string, error) {
				v, err := bitsc.DecodeImpHolder(b)
				if err != nil {
					return "", err
				}
				o := ""
				if v.Opt != nil {
					o = "<opt>" + bsText(v.Opt.Bytes, v.Opt.BitsUnused) + "</opt>"
				}
				return "<ImpHolder><req>" + bsText(v.Req.Bytes, v.Req.BitsUnused) + "</req>" + o + tru + "</ImpHolder>", nil
			}})
	}
	imp("bitsc-absent", nil)
	{
		b, u := bsParts(9, 0, 8)
		imp("bitsc-present", &bitsa.RangedBits{Bytes: b, BitsUnused: u})
	}

	// 4. OPTIONAL references to BIT STRING types.
	{
		rb, ru := bsParts(7, 0, 6)
		cb, cu := bsParts(8, 0, 3, 7)
		refCase := func(name string, ref *bitsa.RangedBits, caps *bitsa.CapsBits) {
			render := func(pre string, r *bitsa.RangedBits, c *bitsa.CapsBits) string {
				s := "<" + pre + ">"
				if r != nil {
					s += "<ref>" + bsText(r.Bytes, r.BitsUnused) + "</ref>"
				}
				if c != nil {
					s += "<caps>" + bsText(c.Bytes, c.BitsUnused) + "</caps>"
				}
				return s + tru + "</" + pre + ">"
			}
			add(bsCase{name, "RefHolder", render("RefHolder", ref, caps),
				func() ([]byte, error) { v := bitsa.RefHolder{Ref: ref, Caps: caps, Flag: true}; return v.Encode() },
				func(b []byte) (string, error) {
					v, err := bitsa.DecodeRefHolder(b)
					if err != nil {
						return "", err
					}
					return render("RefHolder", v.Ref, v.Caps), nil
				}})
			// the same, with the types imported from the other module
			var xr *bitsa.RangedBits = ref
			var xc *bitsa.CapsBits = caps
			add(bsCase{"x" + name, "XRefHolder", render("XRefHolder", xr, xc),
				func() ([]byte, error) { v := bitsb.XRefHolder{Ref: xr, Caps: xc, Flag: true}; return v.Encode() },
				func(b []byte) (string, error) {
					v, err := bitsb.DecodeXRefHolder(b)
					if err != nil {
						return "", err
					}
					return render("XRefHolder", v.Ref, v.Caps), nil
				}})
		}
		r := &bitsa.RangedBits{Bytes: rb, BitsUnused: ru}
		c := &bitsa.CapsBits{Bytes: cb, BitsUnused: cu}
		refCase("ref-absent", nil, nil)
		refCase("ref-only", r, nil)
		refCase("caps-only", nil, c)
		refCase("ref-and-caps", r, c)
	}
	return cs
}

func TestBitStrRoundTrip(t *testing.T) {
	for _, c := range bsCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		got, err := c.dec(aper)
		if err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
			continue
		}
		if got != c.xer {
			t.Errorf("%s: Go decode = %s, want %s (APER % x)", c.name, got, c.xer, aper)
		}
	}
}

func TestBitStrCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range bsCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		if re := convPDU(t, bin, c.pdu, aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer := convPDU(t, bin, c.pdu, aper, "-iaper", "-oxer")
		if got := bsXML(xer); got != c.xer {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re := convPDU(t, bin, c.pdu, xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

// A present OPTIONAL BIT STRING encodes to the hand-computed APER.
func TestBitStrHandAPER(t *testing.T) {
	v := bitsa.OptFixed{Opt: &bitsa.BitString{Bytes: []byte{0xA5}}, Flag: true}
	got, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// opt-present bit 1, 8 bits 0xA5, flag 1: 1 10100101 1 -> D2 C0
	if want := []byte{0xD2, 0xC0}; !bytes.Equal(got, want) {
		t.Errorf("OptFixed = % x, want % x", got, want)
	}
}

// ---- zero-length BIT STRING (module EBS) ----
//
// Zero-length BIT STRING (tests/e2e/ebs.asn): a valid value that the Go side
// both decodes and must be able to encode. Covered as an OPTIONAL member, a
// plain member (next to OCTET STRINGs), a CHOICE alternative and a SEQUENCE OF
// element. Each case is encoded in Go and must equal fixed APER bytes (the C
// converter's APER of the XER below); the C converter must render the Go bytes
// as that XER; decoding the bytes must give back the input (a zero-length
// BIT STRING decodes to a Bytes slice of length 0); and re-encoding the
// decoded value must give the same bytes. Copied into the generated module by
// tests/run-e2e.sh with default_test.go.
//
// APER, worked out per X.691 (every length determinant is octet-aligned):
//
// 	EbT{o: zero-length, p: '1'B, q: '01'H}
// 	  preamble o,r = 1,0 -> 10, pad to the octet: 80
// 	  o: length 0 -> 00;  p: length 1 -> 01, bits '1' + pad -> 80
// 	  q: length 1 -> 01, 01                          => 80 00 01 80 01 01
// 	EbT{p: '1'B, q: '01'H}: preamble 00, then p, q    => 00 01 80 01 01
// 	EbC{a: zero-length}: choice index 0 (1 bit), pad: 00, length 0: 00 => 00 00
// 	EbL{zero-length, '1'B}: count 2 -> 02; 00; 01 80  => 02 00 01 80

func TestZeroLengthBitString(t *testing.T) {
	bin := converter(t)
	empty := ebs.BitString{}
	one := ebs.BitString{Bytes: []byte{0x80}, BitsUnused: 7}
	cases := []struct {
		name string
		pdu  string
		enc  func() ([]byte, error)
		dec  func([]byte) (any, error)
		want any
		xer  string
		aper []byte
	}{
		{"opt-present", "EbT",
			func() ([]byte, error) { return (&ebs.EbT{O: &empty, P: one, Q: []byte{1}}).Encode() },
			func(b []byte) (any, error) { return ebs.DecodeEbT(b) },
			&ebs.EbT{O: &empty, P: one, Q: []byte{1}},
			"<EbT><o></o><p>1</p><q>01</q></EbT>",
			[]byte{0x80, 0x00, 0x01, 0x80, 0x01, 0x01}},
		{"plain-empty", "EbT",
			func() ([]byte, error) { return (&ebs.EbT{P: empty, Q: []byte{1}}).Encode() },
			func(b []byte) (any, error) { return ebs.DecodeEbT(b) },
			&ebs.EbT{P: empty, Q: []byte{1}},
			"<EbT><p></p><q>01</q></EbT>",
			[]byte{0x00, 0x00, 0x01, 0x01}},
		{"plain-one", "EbT",
			func() ([]byte, error) { return (&ebs.EbT{P: one, Q: []byte{1}}).Encode() },
			func(b []byte) (any, error) { return ebs.DecodeEbT(b) },
			&ebs.EbT{P: one, Q: []byte{1}},
			"<EbT><p>1</p><q>01</q></EbT>",
			[]byte{0x00, 0x01, 0x80, 0x01, 0x01}},
		{"choice-alt", "EbC",
			func() ([]byte, error) { return (&ebs.EbC{Present: ebs.EbCPrA, A: &empty}).Encode() },
			func(b []byte) (any, error) { return ebs.DecodeEbC(b) },
			&ebs.EbC{Present: ebs.EbCPrA, A: &empty},
			"<EbC><a></a></EbC>",
			[]byte{0x00, 0x00}},
		{"seqof-element", "EbL",
			func() ([]byte, error) { l := ebs.EbL{empty, one}; return (&l).Encode() },
			func(b []byte) (any, error) { return ebs.DecodeEbL(b) },
			&ebs.EbL{empty, one},
			"<EbL><BIT_STRING></BIT_STRING><BIT_STRING>1</BIT_STRING></EbL>",
			[]byte{0x02, 0x00, 0x01, 0x80}},
	}
	squash := func(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }
	for _, c := range cases {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if !bytes.Equal(aper, c.aper) {
			t.Errorf("%s: Go APER % x, want % x", c.name, aper, c.aper)
		}
		if ref := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, c.aper) {
			t.Errorf("%s: C APER of the XER % x, want % x", c.name, ref, c.aper)
		}
		if x := squash(convPDU(t, bin, c.pdu, aper, "-iaper", "-oxer")); x != c.xer {
			t.Errorf("%s: XER of the Go bytes %s, want %s", c.name, x, c.xer)
		}
		got, err := c.dec(aper)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, c.want)
		}
		again, err := reencode(got)
		if err != nil {
			t.Errorf("%s: re-encode: %v", c.name, err)
		} else if !bytes.Equal(again, c.aper) {
			t.Errorf("%s: re-encoded % x, want % x", c.name, again, c.aper)
		}
	}
}

func reencode(v any) ([]byte, error) {
	switch x := v.(type) {
	case *ebs.EbT:
		return x.Encode()
	case *ebs.EbC:
		return x.Encode()
	case *ebs.EbL:
		return x.Encode()
	}
	return nil, nil
}
