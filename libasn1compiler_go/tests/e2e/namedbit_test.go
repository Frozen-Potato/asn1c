// Named-bit BIT STRING (tests/e2e/namedbit.asn). Mirrors C check-167.
//
// A named-bit BIT STRING is a plain BitString value in Go; the names are int
// bit-position constants. The wire encoding is the C runtime's, reached through
// the glue: Go has APER only, and the C APER encoder writes the bits it is
// given (the constraint is checked on the given value, so a value shorter than
// the SIZE lower bound is rejected, as in C). Trailing-zero compaction and
// padding up to the SIZE lower bound are UPER behaviour in the C runtime; they
// show through the converter's UPER output for the very bytes Go produced.
//
// For every case: the Go APER bytes equal the C converter's APER for the same
// value written as XER; the converter re-encodes the Go bytes identically; the
// converter's XER of the Go bytes is the given value and decodes back to the
// same APER; Go's own decode agrees; and the converter's UPER of the Go bytes
// is the hand-computed, compacted/padded one (and its XER the compacted value).
package e2e

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	nb "asn1cgo.test/go/namedbit"
)

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
	name    string
	pdu     string
	xer     string // the value as XER: the C oracle's input, and what Go and C decode the APER to
	uper    string // hex of the C UPER of the Go bytes (hand-computed)
	uperXER string // XER of that UPER: the compacted / padded value
	enc     func() ([]byte, error)
	dec     func([]byte) (string, error) // Go decode, rendered like xer
}

// simpleCase: a top-level type whose whole value is one BitString.
func simpleCase[T ~struct {
	Bytes      []byte
	BitsUnused int32
}](name, pdu string, bs nb.BitString, uper, uperBits string,
	dec func([]byte) (*T, error)) nbCase {
	el := func(bits string) string { return "<" + pdu + ">" + bits + "</" + pdu + ">" }
	return nbCase{name, pdu, el(bitText(bs)), uper, el(uperBits),
		func() ([]byte, error) {
			v := T(bs)
			return encodeAny(&v)
		},
		func(b []byte) (string, error) {
			v, err := dec(b)
			if err != nil {
				return "", err
			}
			return el(bitText(nb.BitString(*v))), nil
		}}
}

func encodeAny(v any) ([]byte, error) {
	switch x := v.(type) {
	case *nb.Caps:
		return x.Encode()
	case *nb.Fixed:
		return x.Encode()
	case *nb.Ranged:
		return x.Encode()
	case *nb.Open:
		return x.Encode()
	}
	panic("encodeAny")
}

func holderCase(name string, req nb.BitString, uper, uperBits string) nbCase {
	el := func(bits string) string { return "<Holder><req>" + bits + "</req><flag><true/></flag></Holder>" }
	return nbCase{name, "Holder", el(bitText(req)), uper, el(uperBits),
		func() ([]byte, error) { h := nb.Holder{Req: req, Flag: true}; return h.Encode() },
		func(b []byte) (string, error) {
			h, err := nb.DecodeHolder(b)
			if err != nil {
				return "", err
			}
			if h.Opt != nil {
				return "opt present", nil
			}
			return el(bitText(h.Req)), nil
		}}
}

func selectorCase(name string, sel nb.Selector, alt, bits, uper, uperBits string) nbCase {
	el := func(bits string) string { return "<Selector><" + alt + ">" + bits + "</" + alt + "></Selector>" }
	return nbCase{name, "Selector", el(bits), uper, el(uperBits),
		func() ([]byte, error) { return sel.Encode() },
		func(b []byte) (string, error) {
			s, err := nb.DecodeSelector(b)
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
	// highest-numbered named bit, trailing zero bits: UPER drops them.
	add(simpleCase[nb.Caps]("caps-none", "Caps", bitsOf(8), "00", "", nb.DecodeCaps))
	add(simpleCase[nb.Caps]("caps-highest-only", "Caps", bitsOf(8, nb.CapsC), "0801", "00000001", nb.DecodeCaps))
	add(simpleCase[nb.Caps]("caps-trailing-zeros", "Caps", bitsOf(16, nb.CapsA, nb.CapsB), "0490", "1001", nb.DecodeCaps))
	add(simpleCase[nb.Caps]("caps-all-named", "Caps", bitsOf(8, nb.CapsA, nb.CapsB, nb.CapsC), "0891", "10010001", nb.DecodeCaps))

	// SIZE(8): fixed, nothing to drop or pad.
	add(simpleCase[nb.Fixed]("fixed-none", "Fixed", bitsOf(8), "00", "00000000", nb.DecodeFixed))
	add(simpleCase[nb.Fixed]("fixed-hi-only", "Fixed", bitsOf(8, nb.FixedHi), "04", "00000100", nb.DecodeFixed))
	add(simpleCase[nb.Fixed]("fixed-lo-hi", "Fixed", bitsOf(8, nb.FixedLo, nb.FixedHi), "84", "10000100", nb.DecodeFixed))

	// SIZE(4..12): the lower bound (4) above the highest set bit pads the
	// UPER value up to 4 bits; 4 bits is the shortest value Go may give.
	add(simpleCase[nb.Ranged]("ranged-none", "Ranged", bitsOf(4), "00", "0000", nb.DecodeRanged))
	add(simpleCase[nb.Ranged]("ranged-p-only", "Ranged", bitsOf(12, nb.RangedP), "08", "1000", nb.DecodeRanged))
	add(simpleCase[nb.Ranged]("ranged-q-trailing", "Ranged", bitsOf(10, nb.RangedQ), "02", "0010", nb.DecodeRanged))
	add(simpleCase[nb.Ranged]("ranged-full", "Ranged", bitsOf(12, nb.RangedP, 11), "8801", "100000000001", nb.DecodeRanged))
	add(simpleCase[nb.Open]("open-none", "Open", bitsOf(4), "0000", "0000", nb.DecodeOpen))
	add(simpleCase[nb.Open]("open-p-only", "Open", bitsOf(12, nb.OpenP), "0400", "1000", nb.DecodeOpen))
	add(simpleCase[nb.Open]("open-q-trailing", "Open", bitsOf(10, nb.OpenQ), "0100", "0010", nb.DecodeOpen))

	// Inline member, SIZE(3..6); the OPTIONAL one beside it stays absent.
	add(holderCase("holder-uv", bitsOf(5, nb.HolderReqU, nb.HolderReqV), "16", "101"))
	add(holderCase("holder-none", bitsOf(3), "02", "000"))
	add(holderCase("holder-u-trailing", bitsOf(6, nb.HolderReqU), "12", "100"))

	// CHOICE alternatives: inline named-bit, plain, and a named-bit type.
	{
		b := bitsOf(2, nb.SelectorFlagsOff)
		add(selectorCase("sel-flags", nb.Selector{Present: nb.SelectorPrFlags, Flags: &b}, "flags", "01", "0090", "01"))
	}
	{
		b := bitsOf(2, 0)
		add(selectorCase("sel-plain", nb.Selector{Present: nb.SelectorPrPlain, Plain: &b}, "plain", "10", "60", "10"))
	}
	{
		b := nb.Item(bitsOf(8, nb.ItemN))
		add(selectorCase("sel-named", nb.Selector{Present: nb.SelectorPrNamed, Named: &b}, "named", "00100000", "80c8", "001"))
	}

	// SEQUENCE OF a named-bit type: item 2 has no bit set, item 1 and 3
	// have trailing zeros.
	{
		items := []nb.BitString{bitsOf(8, nb.ItemM), bitsOf(8), bitsOf(8, nb.ItemM, nb.ItemN)}
		add(nbCase{"list", "List",
			"<List><Item>01000000</Item><Item>00000000</Item><Item>01100000</Item></List>",
			"030240" + "00d8", "<List><Item>01</Item><Item></Item><Item>011</Item></List>",
			func() ([]byte, error) {
				l := make(nb.List, len(items))
				for i, it := range items {
					l[i] = nb.Item(it)
				}
				return l.Encode()
			},
			func(b []byte) (string, error) {
				l, err := nb.DecodeList(b)
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

func TestNamedBitCConverter(t *testing.T) {
	bin := nbConverter(t)
	for _, c := range nbCases() {
		aper, err := c.enc()
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
		// C's XER of the Go bytes is the given value, and goes back to APER.
		xer := nbConv(t, bin, c.pdu, aper, "-iaper", "-oxer")
		if got := normXML(xer); got != c.xer {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re := nbConv(t, bin, c.pdu, xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
		// UPER of the Go bytes: trailing zeros dropped, SIZE lower bound padded.
		uper := nbConv(t, bin, c.pdu, aper, "-iaper", "-oper")
		if got := hex.EncodeToString(uper); got != c.uper {
			t.Errorf("%s: C UPER = %s, want %s", c.name, got, c.uper)
		}
		ux := nbConv(t, bin, c.pdu, uper, "-iper", "-oxer")
		if got := normXML(ux); got != c.uperXER {
			t.Errorf("%s: C XER of the UPER = %s, want %s", c.name, got, c.uperXER)
		}
	}
}
