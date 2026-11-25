package e2e

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"asn1cgo.test/go/bitsa"
	"asn1cgo.test/go/bitsb"
	"asn1cgo.test/go/bitsc"
	"asn1cgo.test/go/ebs"
	nb "asn1cgo.test/go/namedbit"
)

// Named-bit BIT STRING (tests/e2e/bits.asn). Mirrors C check-167.
//
// A named-bit BIT STRING is a plain BitString value in Go; the names are int
// bit-position constants. The wire encoding is the C runtime's, reached through
// the glue (Encode / Decode<T> for APER, EncodeUPER / DecodeUPER<T> for UPER).
// The constraint is checked on the given value, so a value shorter than the
// SIZE lower bound is rejected, as in C. Both PER forms remove trailing 0 bits
// of a named-bit type and pad up to the SIZE lower bound (X.691 16.2, 16.3).
//
// For every case: the Go APER and UPER bytes are the hand-computed ones and
// decode to the canonical value; the Go APER bytes equal the C converter's
// APER for the same value written as XER; the converter re-encodes the Go
// bytes identically; the converter's XER of the Go bytes is the canonical
// value and decodes back to the same APER; and the converter's UPER of the Go
// APER bytes is Go's own UPER (and its XER the canonical value).
// bitsOf builds an n-bit BitString (MSB first, as the C buffer holds it) with
// the given bit positions set.
func bitsOf(n int, set ...int) nb.BitString {
	bs := nb.BitString{Bytes: make([]byte, (n+7)/8)}
	if n%8 != 0 {
		bs.BitsUnused = int32(8 - n%8)
	}
	for _, p := range set {
		bs.Bytes[p/8] |= 0x80 >> (p % 8)
	}
	if n == 0 {
		bs.Bytes = nil
	}
	return bs
}

// bitText renders a BitString as the '0'/'1' text XER uses.
func bitText(bs nb.BitString) string {
	var sb strings.Builder
	for i := 0; i < len(bs.Bytes)*8-int(bs.BitsUnused); i++ {
		if bs.Bytes[i/8]&(0x80>>(i%8)) != 0 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

// nbConverter / nbConv: the C converter built from the same C tree (this file
// is copied into its own generated module by run-e2e.sh, apart from
// default_test.go's helpers).
func nbConverter(t *testing.T) string {
	t.Helper()
	c := os.Getenv("ASN1CGO_C_CONVERTER")
	if c == "" {
		t.Skip("ASN1CGO_C_CONVERTER not set")
	}
	return c
}

func nbConv(t *testing.T, bin, pdu string, data []byte, args ...string) []byte {
	t.Helper()
	f := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	a := append(append([]string{}, args...), "-p", pdu, f)
	out, err := exec.Command(bin, a...).CombinedOutput()
	if err != nil {
		t.Fatalf("converter %v: %v\n%s", args, err, out)
	}
	return out
}

func normXML(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }

func TestNamedBitConstants(t *testing.T) {
	// Values are the bit positions, in declaration order, not sorted; the
	// constants are plain ints, not values of the BitString type.
	var _ int = nb.CapsC
	if nb.CapsC != 7 || nb.CapsA != 0 || nb.CapsB != 3 {
		t.Errorf("Caps bits: %d %d %d", nb.CapsC, nb.CapsA, nb.CapsB)
	}
	if nb.FixedLo != 0 || nb.FixedHi != 5 || nb.RangedP != 0 || nb.RangedQ != 2 ||
		nb.OpenP != 0 || nb.OpenQ != 2 {
		t.Error("Fixed/Ranged/Open bits")
	}
	// Inline member and CHOICE alternative: named like an inline ENUMERATED.
	if nb.HolderOptX != 1 || nb.HolderOptY != 4 || nb.HolderReqU != 0 || nb.HolderReqV != 2 || nb.SelectorFlagsOn != 0 || nb.SelectorFlagsOff != 1 {
		t.Error("inline bits")
	}
	if nb.ItemM != 1 || nb.ItemN != 2 {
		t.Error("Item bits")
	}
}

type nbCase struct {
	name  string
	pdu   string
	xer   string                                 // the value as given, as XER: the C oracle's input
	aper  string                                 // hex of the APER (hand-computed)
	uper  string                                 // hex of the UPER (hand-computed)
	canon string                                 // XER of what both decode to: trailing 0 bits removed, padded to the SIZE lower bound (X.691 16.2, 16.3)
	enc   func(u bool) ([]byte, error)           // Go Encode, or EncodeUPER if u
	dec   func(b []byte, u bool) (string, error) // Go Decode<T> (DecodeUPER<T> if u), rendered like xer
}

// simpleCase: a top-level type whose whole value is one BitString.
func simpleCase[T ~struct {
	Bytes      []byte
	BitsUnused int32
}](name, pdu string, bs nb.BitString, aper, uper, canonBits string,
	dec, udec func([]byte) (*T, error)) nbCase {
	el := func(bits string) string { return "<" + pdu + ">" + bits + "</" + pdu + ">" }
	return nbCase{name, pdu, el(bitText(bs)), aper, uper, el(canonBits),
		func(u bool) ([]byte, error) {
			v := T(bs)
			return encodeAny(&v, u)
		},
		func(b []byte, u bool) (string, error) {
			d := dec
			if u {
				d = udec
			}
			v, err := d(b)
			if err != nil {
				return "", err
			}
			return el(bitText(nb.BitString(*v))), nil
		}}
}

func encodeAny(v any, u bool) ([]byte, error) {
	type enc interface {
		Encode() ([]byte, error)
		EncodeUPER() ([]byte, error)
	}
	switch x := v.(type) {
	case *nb.Caps, *nb.Fixed, *nb.Ranged, *nb.Open:
		if u {
			return x.(enc).EncodeUPER()
		}
		return x.(enc).Encode()
	}
	panic("encodeAny")
}

func holderCase(name string, req nb.BitString, aper, uper, canonBits string) nbCase {
	el := func(bits string) string { return "<Holder><req>" + bits + "</req><flag><true/></flag></Holder>" }
	return nbCase{name, "Holder", el(bitText(req)), aper, uper, el(canonBits),
		func(u bool) ([]byte, error) {
			h := nb.Holder{Req: req, Flag: true}
			if u {
				return h.EncodeUPER()
			}
			return h.Encode()
		},
		func(b []byte, u bool) (string, error) {
			dec := nb.DecodeHolder
			if u {
				dec = nb.DecodeUPERHolder
			}
			h, err := dec(b)
			if err != nil {
				return "", err
			}
			if h.Opt != nil {
				return "opt present", nil
			}
			return el(bitText(h.Req)), nil
		}}
}

func selectorCase(name string, sel nb.Selector, alt, bits, aper, uper, canonBits string) nbCase {
	el := func(bits string) string { return "<Selector><" + alt + ">" + bits + "</" + alt + "></Selector>" }
	return nbCase{name, "Selector", el(bits), aper, uper, el(canonBits),
		func(u bool) ([]byte, error) {
			if u {
				return sel.EncodeUPER()
			}
			return sel.Encode()
		},
		func(b []byte, u bool) (string, error) {
			dec := nb.DecodeSelector
			if u {
				dec = nb.DecodeUPERSelector
			}
			s, err := dec(b)
			if err != nil {
				return "", err
			}
			switch s.Present {
			case nb.SelectorPrFlags:
				return "<Selector><flags>" + bitText(*s.Flags) + "</flags></Selector>", nil
			case nb.SelectorPrPlain:
				return "<Selector><plain>" + bitText(*s.Plain) + "</plain></Selector>", nil
			case nb.SelectorPrNamed:
				return "<Selector><named>" + bitText(nb.BitString(*s.Named)) + "</named></Selector>", nil
			}
			return "", nil
		}}
}

func nbCases() []nbCase {
	var cs []nbCase
	add := func(c nbCase) { cs = append(cs, c) }

	// No bits set (8 zero bits; an empty value is "not given" in C), only the
	// highest-numbered named bit, trailing zero bits: APER and UPER drop them.
	add(simpleCase[nb.Caps]("caps-none", "Caps", bitsOf(8), "00", "00", "", nb.DecodeCaps, nb.DecodeUPERCaps))
	add(simpleCase[nb.Caps]("caps-highest-only", "Caps", bitsOf(8, nb.CapsC), "0801", "0801", "00000001", nb.DecodeCaps, nb.DecodeUPERCaps))
	add(simpleCase[nb.Caps]("caps-trailing-zeros", "Caps", bitsOf(16, nb.CapsA, nb.CapsB), "0490", "0490", "1001", nb.DecodeCaps, nb.DecodeUPERCaps))
	// Only an unused bit set (7 bits, all 0): not a value bit, so the
	// value is empty.
	add(simpleCase[nb.Caps]("caps-unused-bit", "Caps", nb.BitString{Bytes: []byte{0x01}, BitsUnused: 1}, "00", "00", "", nb.DecodeCaps, nb.DecodeUPERCaps))
	add(simpleCase[nb.Caps]("caps-all-named", "Caps", bitsOf(8, nb.CapsA, nb.CapsB, nb.CapsC), "0891", "0891", "10010001", nb.DecodeCaps, nb.DecodeUPERCaps))

	// SIZE(8): fixed, nothing to drop or pad.
	add(simpleCase[nb.Fixed]("fixed-none", "Fixed", bitsOf(8), "00", "00", "00000000", nb.DecodeFixed, nb.DecodeUPERFixed))
	add(simpleCase[nb.Fixed]("fixed-hi-only", "Fixed", bitsOf(8, nb.FixedHi), "04", "04", "00000100", nb.DecodeFixed, nb.DecodeUPERFixed))
	add(simpleCase[nb.Fixed]("fixed-lo-hi", "Fixed", bitsOf(8, nb.FixedLo, nb.FixedHi), "84", "84", "10000100", nb.DecodeFixed, nb.DecodeUPERFixed))

	// SIZE(4..12): the lower bound (4) above the highest set bit pads the
	// value up to 4 bits; 4 bits is the shortest value Go may give.
	add(simpleCase[nb.Ranged]("ranged-none", "Ranged", bitsOf(4), "0000", "00", "0000", nb.DecodeRanged, nb.DecodeUPERRanged))
	add(simpleCase[nb.Ranged]("ranged-p-only", "Ranged", bitsOf(12, nb.RangedP), "0080", "08", "1000", nb.DecodeRanged, nb.DecodeUPERRanged))
	add(simpleCase[nb.Ranged]("ranged-q-trailing", "Ranged", bitsOf(10, nb.RangedQ), "0020", "02", "0010", nb.DecodeRanged, nb.DecodeUPERRanged))
	add(simpleCase[nb.Ranged]("ranged-full", "Ranged", bitsOf(12, nb.RangedP, 11), "808010", "8801", "100000000001", nb.DecodeRanged, nb.DecodeUPERRanged))
	add(simpleCase[nb.Open]("open-none", "Open", bitsOf(4), "0000", "0000", "0000", nb.DecodeOpen, nb.DecodeUPEROpen))
	add(simpleCase[nb.Open]("open-p-only", "Open", bitsOf(12, nb.OpenP), "0080", "0400", "1000", nb.DecodeOpen, nb.DecodeUPEROpen))
	add(simpleCase[nb.Open]("open-q-trailing", "Open", bitsOf(10, nb.OpenQ), "0020", "0100", "0010", nb.DecodeOpen, nb.DecodeUPEROpen))

	// Inline member, SIZE(3..6); the OPTIONAL one beside it stays absent.
	add(holderCase("holder-uv", bitsOf(5, nb.HolderReqU, nb.HolderReqV), "00b0", "16", "101"))
	add(holderCase("holder-none", bitsOf(3), "0010", "02", "000"))
	add(holderCase("holder-u-trailing", bitsOf(6, nb.HolderReqU), "0090", "12", "100"))

	// CHOICE alternatives: inline named-bit, plain, and a named-bit type.
	{
		b := bitsOf(2, nb.SelectorFlagsOff)
		add(selectorCase("sel-flags", nb.Selector{Present: nb.SelectorPrFlags, Flags: &b}, "flags", "01", "000240", "0090", "01"))
	}
	{
		b := bitsOf(2, 0)
		add(selectorCase("sel-plain", nb.Selector{Present: nb.SelectorPrPlain, Plain: &b}, "plain", "10", "60", "60", "10"))
	}
	{
		b := nb.Item(bitsOf(8, nb.ItemN))
		add(selectorCase("sel-named", nb.Selector{Present: nb.SelectorPrNamed, Named: &b}, "named", "00100000", "800320", "80c8", "001"))
	}

	// SEQUENCE OF a named-bit type: item 2 has no bit set, item 1 and 3
	// have trailing zeros.
	{
		items := []nb.BitString{bitsOf(8, nb.ItemM), bitsOf(8), bitsOf(8, nb.ItemM, nb.ItemN)}
		add(nbCase{"list", "List",
			"<List><Item>01000000</Item><Item>00000000</Item><Item>01100000</Item></List>",
			"030240" + "00" + "0360", "030240" + "00d8", "<List><Item>01</Item><Item></Item><Item>011</Item></List>",
			func(u bool) ([]byte, error) {
				l := make(nb.List, len(items))
				for i, it := range items {
					l[i] = nb.Item(it)
				}
				if u {
					return l.EncodeUPER()
				}
				return l.Encode()
			},
			func(b []byte, u bool) (string, error) {
				dec := nb.DecodeList
				if u {
					dec = nb.DecodeUPERList
				}
				l, err := dec(b)
				if err != nil {
					return "", err
				}
				s := "<List>"
				for _, it := range *l {
					s += "<Item>" + bitText(nb.BitString(it)) + "</Item>"
				}
				return s + "</List>", nil
			}})
	}
	return cs
}

func TestNamedBitRoundTrip(t *testing.T) {
	for _, c := range nbCases() {
		aper, err := c.enc(false)
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		got, err := c.dec(aper, false)
		if err != nil {
			t.Errorf("%s: decode % x: %v", c.name, aper, err)
			continue
		}
		if h := hex.EncodeToString(aper); h != c.aper {
			t.Errorf("%s: Go APER = %s, want %s", c.name, h, c.aper)
		}
		if got != c.canon {
			t.Errorf("%s: Go decode = %s, want %s (APER % x)", c.name, got, c.canon, aper)
		}
		// UPER: the same value, the hand-computed bytes, the same canonical
		// value back.
		uper, err := c.enc(true)
		if err != nil {
			t.Errorf("%s: EncodeUPER: %v", c.name, err)
			continue
		}
		if h := hex.EncodeToString(uper); h != c.uper {
			t.Errorf("%s: Go UPER = %s, want %s", c.name, h, c.uper)
		}
		if got, err := c.dec(uper, true); err != nil || got != c.canon {
			t.Errorf("%s: Go DecodeUPER = %s, %v, want %s (UPER % x)", c.name, got, err, c.canon, uper)
		}
	}
}

func TestNamedBitCConverter(t *testing.T) {
	bin := nbConverter(t)
	for _, c := range nbCases() {
		aper, err := c.enc(false)
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		// The same value written as XER encodes to the same APER bytes in C.
		if ref := nbConv(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper"); !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		// C decodes the Go bytes and re-encodes them identically.
		if re := nbConv(t, bin, c.pdu, aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		// C's XER of the Go bytes is the canonical value, and goes back to APER.
		xer := nbConv(t, bin, c.pdu, aper, "-iaper", "-oxer")
		if got := normXML(xer); got != c.canon {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.canon)
		}
		if re := nbConv(t, bin, c.pdu, xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
		// UPER of the Go bytes: the same canonical value.
		uper := nbConv(t, bin, c.pdu, aper, "-iaper", "-oper")
		if got := hex.EncodeToString(uper); got != c.uper {
			t.Errorf("%s: C UPER = %s, want %s", c.name, got, c.uper)
		}
		ux := nbConv(t, bin, c.pdu, uper, "-iper", "-oxer")
		if got := normXML(ux); got != c.canon {
			t.Errorf("%s: C XER of the UPER = %s, want %s", c.name, got, c.canon)
		}
		// Go's own UPER is the C converter's.
		if gu, err := c.enc(true); err != nil || !bytes.Equal(gu, uper) {
			t.Errorf("%s: Go UPER % x, %v != C UPER % x", c.name, gu, err, uper)
		}
	}
}

// BIT STRING members across modules (tests/e2e/bits.asn). Copied into the
// generated module by tests/run-e2e.sh together with default_test.go (the
// converter helpers) and bits_test.go (a fourth module that owns BIT
// STRING members in the same -Fgo run).
//
//   - OPTIONAL inline BIT STRING (C: BIT_STRING_t *): absent and present,
//     fixed and variable size, and a SEQUENCE of an address-like BIT STRING plus an optional port-like one. A present
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

	// 2. Address + optional port shape.
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

// Len / Bit / SetBit on the BitString helper and on named BIT STRING types
// (a defined type `type Caps BitString` gets its own, through BitString's).
// Bit 0 is the first bit (the most significant bit of Bytes[0]), as the
// named-bit constants count.
func TestBitStringMethods(t *testing.T) {
	same := func(name string, got, want nb.BitString) {
		t.Helper()
		if !bytes.Equal(got.Bytes, want.Bytes) || got.BitsUnused != want.BitsUnused {
			t.Errorf("%s: %x/%d, want %x/%d", name, got.Bytes, got.BitsUnused, want.Bytes, want.BitsUnused)
		}
	}

	var z nb.BitString
	if z.Len() != 0 || z.Bit(0) || z.Bit(-1) {
		t.Errorf("zero BitString: Len %d", z.Len())
	}
	z.SetBit(3, false) // past the end: no change
	same("clear past the end", z, nb.BitString{})

	var c nb.Caps
	c.SetBit(nb.CapsB, true)
	same("Caps b", nb.BitString(c), bitsOf(4, nb.CapsB))
	c.SetBit(nb.CapsC, true)
	c.SetBit(nb.CapsA, true)
	same("Caps a b c", nb.BitString(c), bitsOf(8, nb.CapsA, nb.CapsB, nb.CapsC))
	if c.Len() != 8 || !c.Bit(nb.CapsA) || !c.Bit(nb.CapsB) || !c.Bit(nb.CapsC) || c.Bit(1) || c.Bit(8) || c.Bit(-1) {
		t.Errorf("Caps bits: Len %d", c.Len())
	}
	c.SetBit(nb.CapsB, false)
	same("Caps b cleared", nb.BitString(c), bitsOf(8, nb.CapsA, nb.CapsC))
	c.SetBit(9, true) // into a second byte
	same("Caps bit 9", nb.BitString(c), bitsOf(10, nb.CapsA, nb.CapsC, 9))

	// Growing clears the unused bits of the last byte first.
	g := nb.BitString{Bytes: []byte{0xff}, BitsUnused: 4}
	g.SetBit(6, true)
	same("grow over unused bits", g, bitsOf(7, 0, 1, 2, 3, 6))
	// A longer Bytes than BitsUnused says: the extra bytes are dropped.
	g = nb.BitString{Bytes: []byte{0x80, 0xff}, BitsUnused: 12}
	if g.Len() != 4 {
		t.Errorf("Len %d, want 4", g.Len())
	}
	g.SetBit(5, true)
	same("grow over extra bytes", g, bitsOf(6, 0, 5))

	// Other modules' types, and a value that went through the encoders.
	var x bitsa.CapsBits
	x.SetBit(bitsa.CapsBitsC, true)
	if x.Len() != 8 || !x.Bit(bitsa.CapsBitsC) || x.Bit(bitsa.CapsBitsA) {
		t.Errorf("bitsa.CapsBits: %x/%d", x.Bytes, x.BitsUnused)
	}
	var it nb.Item
	it.SetBit(nb.ItemN, true)
	enc, err := (&nb.Selector{Present: nb.SelectorPrNamed, Named: &it}).Encode()
	if err != nil {
		t.Fatalf("Selector Encode: %v", err)
	}
	back, err := nb.DecodeSelector(enc)
	if err != nil {
		t.Fatalf("DecodeSelector: %v", err)
	}
	if back.Named == nil || !back.Named.Bit(nb.ItemN) || back.Named.Bit(nb.ItemM) || back.Named.Len() != 3 {
		t.Errorf("Selector named: %+v", back.Named)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("SetBit(-1): no panic")
			}
		}()
		c.SetBit(-1, true)
	}()
}
