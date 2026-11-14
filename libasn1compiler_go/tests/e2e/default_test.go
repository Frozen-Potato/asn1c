// DEFAULT members (tests/e2e/default.asn). Copied into the generated module
// by tests/run-e2e.sh. A DEFAULT member is a plain value in Go: Decode always
// yields the effective value, Encode always hands the value to the C codec,
// which omits a member equal to its DEFAULT.
//
// The C converter (ASN1CGO_C_CONVERTER, built by run-e2e.sh from the same C
// tree) is used as a cross-check for APER/UPER/XER; because it shares the
// runtime with the Go codec, key cases also assert HAND-COMPUTED APER bytes.
package e2e

import (
	"bytes"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
	df "asn1cgo.test/go/defaults"
)

// dflt returns a DefaultsPDU with every DEFAULT member set to its generated
// default constant (the Go zero value is NOT the default).
func dflt() *df.DefaultsPDU {
	return &df.DefaultsPDU{
		Flag:   df.DefaultsPDUFlagDefault,
		Small:  df.DefaultsPDUSmallDefault,
		Signed: df.DefaultsPDUSignedDefault,
		Min32:  df.DefaultsPDUMin32Default,
		Min64:  df.DefaultsPDUMin64Default,
		Colour: df.DefaultsPDUColourDefault,
		Inl:    df.DefaultsPDUInlDefault,
		Name:   df.DefaultsPDUNameDefault,
		Octs:   append([]byte(nil), df.DefaultsPDUOctsDefault...),
		Bits:   df.BitString{Bytes: append([]byte(nil), df.DefaultsPDUBitsDefault.Bytes...), BitsUnused: df.DefaultsPDUBitsDefault.BitsUnused},
		Inner:  df.Inner{X: df.InnerXDefault, Y: df.InnerYDefault},
	}
}

func extDflt() *df.ExtDefaults {
	return &df.ExtDefaults{
		A:       df.ExtDefaultsADefault,
		ExtZero: df.ExtDefaultsExtZeroDefault,
		ExtNon:  df.ExtDefaultsExtNonDefault,
	}
}

func balanced(t *testing.T, what string) {
	t.Helper()
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("%s: ArenaBalance = %d, want 0", what, bal)
	}
}

func TestDefaultConstants(t *testing.T) {
	if df.DefaultsPDUFlagDefault != true || df.DefaultsPDUSmallDefault != 0 ||
		df.DefaultsPDUSignedDefault != -1 ||
		df.DefaultsPDUMin32Default != -2147483648 ||
		df.DefaultsPDUMin64Default != -9223372036854775808 ||
		df.DefaultsPDUColourDefault != df.ColourGreen ||
		df.DefaultsPDUInlDefault != df.DefaultsPDUInlB ||
		df.DefaultsPDUNameDefault != "hi" ||
		!bytes.Equal(df.DefaultsPDUOctsDefault, []byte{0xAB}) ||
		!reflect.DeepEqual(df.DefaultsPDUBitsDefault, df.BitString{Bytes: []byte{0xA0}, BitsUnused: 5}) ||
		df.InnerXDefault != false || df.InnerYDefault != 200 ||
		df.ExtDefaultsADefault != true ||
		df.ExtDefaultsExtZeroDefault != 0 || df.ExtDefaultsExtNonDefault != 5 {
		t.Fatal("generated DEFAULT constants have wrong values")
	}
	// The zero value is not the default.
	if reflect.DeepEqual(&df.DefaultsPDU{}, dflt()) {
		t.Fatal("zero value equals the default value")
	}
}

// Hand-computed APER (X.691 aligned variant), see the comments per case.
//
// All defaults: preamble = ext bit (0) + 10 presence bits for the root DEFAULT
// members (all 0) = 11 bits; Inner: ext 0 + x,y presence 00 = 3 bits;
// 14 zero bits -> 00 00.
var handCases = []struct {
	name string
	mut  func(*df.DefaultsPDU)
	want []byte
}{
	{"all-default", func(*df.DefaultsPDU) {}, []byte{0x00, 0x00}},
	// flag=FALSE: presence bit 1 (bit 1), value bit 0 (bit 10).
	// bits: 0 | 1000000000 | 0 | 000 -> 0100 0000 0000 000(0)
	{"flag-false", func(p *df.DefaultsPDU) { p.Flag = false }, []byte{0x40, 0x00}},
	// small=3: presence bit 2; value '011' at bits 11..13 (0..7 -> 3 bits).
	// bits: 0 | 0100000000 | 011 | 000 -> 0010 0000 0000 1100 0(0000000)
	{"small-3", func(p *df.DefaultsPDU) { p.Small = 3 }, []byte{0x20, 0x0c, 0x00}},
	// name="ab": presence bit 8; after the 11 preamble bits the string is
	// octet-aligned: length 02, 'a','b'; then Inner (000).
	{"name-ab", func(p *df.DefaultsPDU) { p.Name = "ab" }, []byte{0x00, 0x80, 0x02, 0x61, 0x62, 0x00}},
}

func TestDefaultHandAPER(t *testing.T) {
	for _, c := range handCases {
		p := dflt()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		back, err := df.DecodeDefaultsPDU(c.want)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
}

// A value equal to the default clears the presence bits and the extension bit.
func TestDefaultOmittedOnWire(t *testing.T) {
	b, err := dflt().Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 2 || b[0] != 0 || b[1] != 0 {
		t.Fatalf("all-default APER = % x, want 00 00 (ext bit and every presence bit clear)", b)
	}
	// Each root member in turn: equal to its default -> presence bit clear
	// (the first byte pair stays 00 00 whatever else is set to default).
	back, err := df.DecodeDefaultsPDU(b)
	if err != nil || !reflect.DeepEqual(back, dflt()) {
		t.Fatalf("decode: %+v, %v", back, err)
	}
	balanced(t, "omitted")
}

// Extension additions: a default-equal addition is treated as absent (like a
// root member), so the extension bit is 0 when every addition is defaulted.
func TestDefaultExtensionAdditions(t *testing.T) {
	// Hand-computed APER, ext bit 0 / additions absent: ext(0) + presence of
	// `a` (0) = 00. The decoder must fill every DEFAULT with its default.
	got, err := df.DecodeExtDefaults([]byte{0x00})
	if err != nil || !reflect.DeepEqual(got, extDflt()) {
		t.Fatalf("decode 00: %+v, %v (want %+v)", got, err, extDflt())
	}
	// ext(1) a(0) nslength(7 bits: 0|000001 = 2 additions) bitmap 01 (only
	// extNon) -> 1000 0000 | 101(00000) = 80 a0; open type: 01 a0 (5='101').
	got, err = df.DecodeExtDefaults([]byte{0x80, 0xa0, 0x01, 0xa0})
	w := extDflt()
	if err != nil || !reflect.DeepEqual(got, w) {
		t.Fatalf("decode 80a001a0: %+v, %v (want %+v)", got, err, w)
	}
	// Only extNon present with 4 ('100' -> 80), extZero absent -> default 0.
	got, err = df.DecodeExtDefaults([]byte{0x80, 0xa0, 0x01, 0x80})
	w = extDflt()
	w.ExtNon = 4
	if err != nil || !reflect.DeepEqual(got, w) {
		t.Fatalf("decode 80a00180: %+v, %v (want %+v)", got, err, w)
	}
	// Only extZero present (3 = '011' -> 60): bitmap 10 -> byte1 c0.
	// extNon absent -> filled with 5 (APER decoder default fill).
	got, err = df.DecodeExtDefaults([]byte{0x80, 0xc0, 0x01, 0x60})
	w = extDflt()
	w.ExtZero = 3
	if err != nil || !reflect.DeepEqual(got, w) {
		t.Fatalf("decode 80c00160: %+v, %v (want %+v)", got, err, w)
	}
	// Encode / decode round trips, both default-equal and not.
	for _, c := range []struct {
		name string
		v    df.ExtDefaults
	}{
		{"defaults", *extDflt()},
		{"zero", df.ExtDefaults{A: true, ExtZero: 0, ExtNon: 0}},
		{"zero-5", df.ExtDefaults{A: false, ExtZero: 7, ExtNon: 5}},
		{"both", df.ExtDefaults{A: true, ExtZero: 1, ExtNon: 6}},
		{"a-false", df.ExtDefaults{A: false, ExtZero: 0, ExtNon: 5}},
	} {
		b, err := c.v.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		back, err := df.DecodeExtDefaults(b)
		if err != nil || !reflect.DeepEqual(*back, c.v) {
			t.Errorf("%s: % x -> %+v, %v", c.name, b, back, err)
		}
		balanced(t, c.name)
	}

	// Hand-computed APER encodings. A member equal to its DEFAULT is omitted both
	// in the root and among the extension additions; when every addition is
	// absent the extension bit is 0 and no bitmap is written.
	//   defaults:           ext(0) a-presence(0)                  -> 00
	//   a=FALSE, defaults:  ext(0) a-presence(1) a(0) = 010       -> 40
	//   only extNon=6:      ext(1) a-pres(0) nslength(0|000001: 2 additions)
	//                       bitmap(01) -> 1000 0000 | 101(00000) = 80 a0,
	//                       open type 01 + '110'(00000)           -> 80 a0 01 c0
	//   only extZero=3:     bitmap(10) -> 80 c0, open type 01 + '011' -> 80 c0 01 60
	//   both non-default:   bitmap(11) -> 80 e0, open types 01 60, 01 c0
	for _, c := range []struct {
		name string
		v    df.ExtDefaults
		want []byte
	}{
		{"defaults", df.ExtDefaults{A: true, ExtZero: 0, ExtNon: 5}, []byte{0x00}},
		{"a-false", df.ExtDefaults{A: false, ExtZero: 0, ExtNon: 5}, []byte{0x40}},
		{"only-extNon", df.ExtDefaults{A: true, ExtZero: 0, ExtNon: 6}, []byte{0x80, 0xa0, 0x01, 0xc0}},
		{"only-extZero", df.ExtDefaults{A: true, ExtZero: 3, ExtNon: 5}, []byte{0x80, 0xc0, 0x01, 0x60}},
		{"both", df.ExtDefaults{A: true, ExtZero: 3, ExtNon: 6}, []byte{0x80, 0xe0, 0x01, 0x60, 0x01, 0xc0}},
	} {
		b, err := c.v.Encode()
		if err != nil || !bytes.Equal(b, c.want) {
			t.Errorf("%s: APER = % x, %v; want % x", c.name, b, err, c.want)
		}
		back, err := df.DecodeExtDefaults(c.want)
		if err != nil || !reflect.DeepEqual(*back, c.v) {
			t.Errorf("%s: decode % x -> %+v, %v", c.name, c.want, back, err)
		}
		balanced(t, c.name)
	}
}

// Decoding bytes with a member absent yields the DEFAULT in the Go field.
func TestDefaultDecodeAbsent(t *testing.T) {
	got, err := df.DecodeDefaultsPDU([]byte{0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, dflt()) {
		t.Fatalf("decoded %+v, want all defaults %+v", got, dflt())
	}
	balanced(t, "absent")
}

var nonDefault = []struct {
	name string
	mut  func(*df.DefaultsPDU)
}{
	{"flag", func(p *df.DefaultsPDU) { p.Flag = false }},
	{"small", func(p *df.DefaultsPDU) { p.Small = 7 }},
	{"signed", func(p *df.DefaultsPDU) { p.Signed = 10 }},
	{"signed-0", func(p *df.DefaultsPDU) { p.Signed = 0 }},
	{"min32", func(p *df.DefaultsPDU) { p.Min32 = -2147483647 }},
	{"min32-0", func(p *df.DefaultsPDU) { p.Min32 = 0 }},
	{"min64-0", func(p *df.DefaultsPDU) { p.Min64 = 0 }},
	{"min64-max", func(p *df.DefaultsPDU) { p.Min64 = 9223372036854775807 }},
	{"min64-min+1", func(p *df.DefaultsPDU) { p.Min64 = -9223372036854775807 }},
	{"colour", func(p *df.DefaultsPDU) { p.Colour = df.ColourBlue }},
	{"inl", func(p *df.DefaultsPDU) { p.Inl = df.DefaultsPDUInlC }},
	// (digits only: this runtime's UPER codec garbles other PrintableString
	// characters, which is unrelated to DEFAULT and only matters for the UPER
	// cross-check below)
	{"name", func(p *df.DefaultsPDU) { p.Name = "42" }},
	{"octs", func(p *df.DefaultsPDU) { p.Octs = []byte{1, 2, 3} }},
	{"octs-empty", func(p *df.DefaultsPDU) { p.Octs = []byte{} }},
	{"bits-8", func(p *df.DefaultsPDU) { p.Bits = df.BitString{Bytes: []byte{0xFF}, BitsUnused: 0} }},
	{"inner.x", func(p *df.DefaultsPDU) { p.Inner.X = true }},
	{"inner.y", func(p *df.DefaultsPDU) { p.Inner.Y = 0 }},
	{"everything", func(p *df.DefaultsPDU) {
		p.Flag, p.Small, p.Signed, p.Min64 = false, 1, -10, 42
		p.Colour, p.Inl, p.Name = df.ColourRed, df.DefaultsPDUInlA, "42"
		p.Octs, p.Bits = []byte{0}, df.BitString{Bytes: []byte{0x80}, BitsUnused: 7}
		p.Inner = df.Inner{X: true, Y: 255}
	}},
}

func TestDefaultRoundTrip(t *testing.T) {
	base, err := dflt().Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range nonDefault {
		p := dflt()
		c.mut(p)
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if bytes.Equal(b, base) {
			t.Errorf("%s: non-default value encoded like the default", c.name)
		}
		back, err := df.DecodeDefaultsPDU(b)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if p.Octs != nil && len(p.Octs) == 0 {
			back.Octs = []byte{} // empty vs nil is not a wire difference
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
}

func TestDefaultErrors(t *testing.T) {
	p := dflt()
	p.Small = 8 // outside (0..7)
	_, err := p.Encode()
	wantErr(t, "constraint", err, rt.ErrConstraint)
	p = dflt()
	p.Inner.Y = 256
	_, err = p.Encode()
	wantErr(t, "nested constraint", err, rt.ErrConstraint)
	var nilp *df.DefaultsPDU
	_, err = nilp.Encode()
	wantErr(t, "nil", err, rt.ErrArg)
	_, err = df.DecodeDefaultsPDU([]byte{0xff, 0xff, 0xff})
	wantErr(t, "garbage", err, rt.ErrDecode)
	b, _ := dflt().Encode()
	_, err = df.DecodeDefaultsPDU(append(b, 0))
	wantErr(t, "trailing", err, rt.ErrTrailing)
	_, err = df.DecodeDefaultsPDU([]byte{0x01})
	wantErr(t, "truncated", err, rt.ErrDecode)
}

// ---- cross-check against the C converter ----

func converter(t *testing.T) string {
	t.Helper()
	c := os.Getenv("ASN1CGO_C_CONVERTER")
	if c == "" {
		t.Skip("ASN1CGO_C_CONVERTER not set")
	}
	return c
}

// conv runs the C converter on data and returns stdout.
func conv(t *testing.T, bin string, data []byte, args ...string) []byte {
	return convPDU(t, bin, "DefaultsPDU", data, args...)
}

func convPDU(t *testing.T, bin, pdu string, data []byte, args ...string) []byte {
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

func TestDefaultCConverter(t *testing.T) {
	bin := converter(t)
	cases := append([]struct {
		name string
		mut  func(*df.DefaultsPDU)
	}{{"all-default", func(*df.DefaultsPDU) {}}}, nonDefault...)
	for _, c := range cases {
		p := dflt()
		c.mut(p)
		aper, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// C decodes the Go APER and re-encodes: APER round-trips bit-exact.
		if re := conv(t, bin, aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		// XER of the decoded value, then back through the C XER decoder.
		xer := conv(t, bin, aper, "-iaper", "-oxer")
		if re := conv(t, bin, xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x\n%s", c.name, re, aper, xer)
		}
		// UPER output decodes (as UPER) to the same APER.
		uper := conv(t, bin, aper, "-iaper", "-oper")
		if re := conv(t, bin, uper, "-iper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: UPER round trip -> APER % x != Go % x", c.name, re, aper)
		}
		if c.name == "all-default" {
			// UPER of the all-default value: 15 zero bits -> 00 00.
			if !bytes.Equal(uper, []byte{0x00, 0x00}) {
				t.Errorf("all-default UPER = % x, want 00 00", uper)
			}
			// XER of an absent/default member contains the element with its default.
			for _, el := range []string{
				"<flag><true/></flag>", "<small>0</small>", "<signed>-1</signed>",
				"<min32>-2147483648</min32>", "<min64>-9223372036854775808</min64>", "<colour><green/></colour>",
				"<inl><b/></inl>", "<name>hi</name>", "<octs>AB</octs>",
				"<bits>101</bits>", "<x><false/></x>", "<y>200</y>",
			} {
				if !strings.Contains(strings.Join(strings.Fields(string(xer)), ""), el) {
					t.Errorf("XER lacks %s:\n%s", el, xer)
				}
			}
		}
	}
	// Extension additions through the C converter (APER/UPER/XER).
	for _, v := range []df.ExtDefaults{*extDflt(), {A: false, ExtZero: 2, ExtNon: 0}, {A: true, ExtZero: 0, ExtNon: 7}, {A: true, ExtZero: 3, ExtNon: 5}, {A: false, ExtZero: 0, ExtNon: 5}, {A: true, ExtZero: 3, ExtNon: 6}} {
		aper, err := v.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if re := convPDU(t, bin, "ExtDefaults", aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("ext %+v: C APER % x != Go % x", v, re, aper)
		}
		xer := convPDU(t, bin, "ExtDefaults", aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, "ExtDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("ext %+v: XER round trip % x != Go % x\n%s", v, re, aper, xer)
		}
		uper := convPDU(t, bin, "ExtDefaults", aper, "-iaper", "-oper")
		if re := convPDU(t, bin, "ExtDefaults", uper, "-iper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("ext %+v: UPER round trip % x != Go % x", v, re, aper)
		}
	}
	// Absent additions (ext bit 0): XER shows the defaults.
	x := string(convPDU(t, bin, "ExtDefaults", []byte{0x00}, "-iaper", "-oxer"))
	x = strings.Join(strings.Fields(x), "")
	for _, el := range []string{"<a><true/></a>", "<extZero>0</extZero>", "<extNon>5</extNon>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent additions lacks %s: %s", el, x)
		}
	}
	// A hand-written XER with every DEFAULT member spelled out as its
	// default encodes to the all-absent APER (00 00); one with the members
	// left out decodes to the same value.
	full := `<DefaultsPDU><flag><true/></flag><small>0</small><signed>-1</signed>` +
		`<min32>-2147483648</min32><min64>-9223372036854775808</min64><colour><green/></colour>` +
		`<inl><b/></inl><name>hi</name><octs>AB</octs><bits>101</bits>` +
		`<inner><x><false/></x><y>200</y></inner></DefaultsPDU>`
	if got := conv(t, bin, []byte(full), "-ixer", "-oaper"); !bytes.Equal(got, []byte{0, 0}) {
		t.Errorf("XER(all defaults spelled out) -> APER = % x, want 00 00", got)
	}
	sparse := `<DefaultsPDU><inner/></DefaultsPDU>`
	if got := conv(t, bin, []byte(sparse), "-ixer", "-oaper"); !bytes.Equal(got, []byte{0, 0}) {
		t.Errorf("XER(members absent) -> APER = % x, want 00 00", got)
	}
}

func TestDefaultNoLeak(t *testing.T) {
	// Repeated encode/decode keeps the arena balanced.
	for i := 0; i < 50; i++ {
		p := dflt()
		p.Name = "n"
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := df.DecodeDefaultsPDU(b); err != nil {
			t.Fatal(err)
		}
	}
	balanced(t, "loop")
}

// INTEGER_t storage (Big ::= INTEGER (0..2^40-1)): the C slot is a pointer to
// INTEGER_t for the default 0 as well as for 5.
func TestDefaultWideInteger(t *testing.T) {
	if df.WideDefaultsW5Default != 5 || df.WideDefaultsW0Default != 0 {
		t.Fatal("wide default constants")
	}
	d := df.WideDefaults{W5: df.WideDefaultsW5Default, W0: df.WideDefaultsW0Default}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// ext(0) + two presence bits (0) = 000 -> 00
	if !bytes.Equal(b, []byte{0x00}) {
		t.Fatalf("all-default APER = % x, want 00", b)
	}
	back, err := df.DecodeWideDefaults(b)
	if err != nil || *back != d {
		t.Fatalf("decode: %+v, %v", back, err)
	}
	cases := []df.WideDefaults{
		{W5: 6, W0: 0}, {W5: 5, W0: 1}, {W5: 0, W0: 0},
		{W5: 1099511627775, W0: 1099511627775}, {W5: 4294967296, W0: 7},
	}
	for _, c := range cases {
		b, err := c.Encode()
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		back, err := df.DecodeWideDefaults(b)
		if err != nil || *back != c {
			t.Errorf("%+v: % x -> %+v, %v", c, b, back, err)
		}
		if bin := os.Getenv("ASN1CGO_C_CONVERTER"); bin != "" {
			if re := convPDU(t, bin, "WideDefaults", b, "-iaper", "-oaper"); !bytes.Equal(re, b) {
				t.Errorf("%+v: C re-encode % x != % x", c, re, b)
			}
			xer := convPDU(t, bin, "WideDefaults", b, "-iaper", "-oxer")
			if re := convPDU(t, bin, "WideDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, b) {
				t.Errorf("%+v: XER round trip % x != % x", c, re, b)
			}
		}
		balanced(t, "wide")
	}
	over := df.WideDefaults{W5: 1099511627776}
	_, err = over.Encode()
	wantErr(t, "wide constraint", err, rt.ErrConstraint)
}

// ---- NULL and REAL DEFAULT (RealDefaults) ----

func realDflt() *df.RealDefaults {
	return &df.RealDefaults{
		N: df.RealDefaultsNDefault, R: df.RealDefaultsRDefault,
		Z: df.RealDefaultsZDefault, M: df.RealDefaultsMDefault,
		P: df.RealDefaultsPDefault, Q: df.RealDefaultsQDefault,
		Nz: df.RealDefaultsNzDefault, Na: df.RealDefaultsNaDefault,
		B: true,
	}
}

// sameReal compares two floats the way the DEFAULT does: by value, but a NaN
// equals a NaN and -0.0 differs from 0.0.
func sameReal(a, b float64) bool {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.IsNaN(a) && math.IsNaN(b)
	}
	return math.Float64bits(a) == math.Float64bits(b)
}

func sameRealDefaults(a, b *df.RealDefaults) bool {
	return a.N == b.N && a.B == b.B && sameReal(a.R, b.R) &&
		sameReal(a.Z, b.Z) && sameReal(a.M, b.M) && sameReal(a.P, b.P) &&
		sameReal(a.Q, b.Q) && sameReal(a.Nz, b.Nz) && sameReal(a.Na, b.Na)
}

func TestRealDefaultConstants(t *testing.T) {
	if df.RealDefaultsRDefault != 1.5 || df.RealDefaultsZDefault != 0 ||
		df.RealDefaultsMDefault != -2.25 ||
		!math.IsInf(df.RealDefaultsPDefault, 1) ||
		!math.IsInf(df.RealDefaultsQDefault, -1) ||
		df.RealDefaultsNzDefault != 0 || !math.Signbit(df.RealDefaultsNzDefault) ||
		!math.IsNaN(df.RealDefaultsNaDefault) ||
		df.RealDefaultsNDefault != struct{}{} {
		t.Fatal("generated REAL / NULL DEFAULT values are wrong")
	}
	if math.Signbit(df.RealDefaultsZDefault) {
		t.Fatal("DEFAULT 0 is minus zero")
	}
}

// Hand-computed APER. The preamble is eight presence bits (n r z m p q nz na)
// and then the members present, each REAL as a length octet and the X.690
// content; b is the last bit.
//
//	all defaults:  00000000 | b=1                          -> 00 80
//	r=2.5:         01000000 | 03 80 ff 05 (5 * 2^-1) | b   -> 40 03 80 ff 05 80
//	z=-0.0:        00100000 | 01 43 (minus zero)     | b   -> 20 01 43 80
//	m=0.0:         00010000 | 00 (zero: no content)  | b   -> 10 00 80
//	p=1.0:         00001000 | 03 80 00 01            | b   -> 08 03 80 00 01 80
//	nz=+0.0:       00000010 | 00 (zero: no content)  | b   -> 02 00 80
//	na=1.0:        00000001 | 03 80 00 01            | b   -> 01 03 80 00 01 80
//	b=false:       00000000 | b=0                          -> 00 00
var realHandCases = []struct {
	name string
	mut  func(*df.RealDefaults)
	want []byte
}{
	{"all-default", func(*df.RealDefaults) {}, []byte{0x00, 0x80}},
	{"r-2.5", func(p *df.RealDefaults) { p.R = 2.5 }, []byte{0x40, 0x03, 0x80, 0xff, 0x05, 0x80}},
	{"z-minus-zero", func(p *df.RealDefaults) { p.Z = math.Copysign(0, -1) }, []byte{0x20, 0x01, 0x43, 0x80}},
	{"m-zero", func(p *df.RealDefaults) { p.M = 0 }, []byte{0x10, 0x00, 0x80}},
	{"p-1", func(p *df.RealDefaults) { p.P = 1 }, []byte{0x08, 0x03, 0x80, 0x00, 0x01, 0x80}},
	{"nz-plus-zero", func(p *df.RealDefaults) { p.Nz = 0 }, []byte{0x02, 0x00, 0x80}},
	{"na-1", func(p *df.RealDefaults) { p.Na = 1 }, []byte{0x01, 0x03, 0x80, 0x00, 0x01, 0x80}},
	{"b-false", func(p *df.RealDefaults) { p.B = false }, []byte{0x00, 0x00}},
}

func TestRealDefaultHandAPER(t *testing.T) {
	for _, c := range realHandCases {
		p := realDflt()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		back, err := df.DecodeRealDefaults(c.want)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !sameRealDefaults(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
}

// Other values round-trip, among them infinities and a -0.0 member whose
// DEFAULT is 0.
func TestRealDefaultRoundTrip(t *testing.T) {
	base, err := realDflt().Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		mut  func(*df.RealDefaults)
	}{
		{"r-0.1", func(p *df.RealDefaults) { p.R = 0.1 }},
		{"r-large", func(p *df.RealDefaults) { p.R = 1e300 }},
		{"r-neg", func(p *df.RealDefaults) { p.R = -1.5 }},
		{"r-nan", func(p *df.RealDefaults) { p.R = math.NaN() }},
		{"z-5", func(p *df.RealDefaults) { p.Z = 5 }},
		{"m-pinf", func(p *df.RealDefaults) { p.M = math.Inf(1) }},
		{"p-minf", func(p *df.RealDefaults) { p.P = math.Inf(-1) }},
		{"q-pinf", func(p *df.RealDefaults) { p.Q = math.Inf(1) }},
		{"nz-1.5", func(p *df.RealDefaults) { p.Nz = 1.5 }},
		{"na-zero", func(p *df.RealDefaults) { p.Na = 0 }},
		{"na-inf", func(p *df.RealDefaults) { p.Na = math.Inf(1) }},
		{"everything", func(p *df.RealDefaults) {
			p.R, p.Z, p.M, p.P = 3, math.Copysign(0, -1), 9.75, -8
			p.Q, p.Nz, p.Na, p.B = 100, 7, -0.5, false
		}},
	} {
		p := realDflt()
		c.mut(p)
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if bytes.Equal(b, base) {
			t.Errorf("%s: non-default value encoded like the default", c.name)
		}
		back, err := df.DecodeRealDefaults(b)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !sameRealDefaults(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
	// The all-default value decodes from the two bytes with every default
	// filled in, NULL included.
	got, err := df.DecodeRealDefaults([]byte{0x00, 0x80})
	if err != nil || !sameRealDefaults(got, realDflt()) {
		t.Fatalf("decode 00 80: %+v, %v", got, err)
	}
	balanced(t, "real-absent")
}

func TestRealDefaultCConverter(t *testing.T) {
	bin := converter(t)
	cases := []struct {
		name string
		mut  func(*df.RealDefaults)
	}{{"all-default", func(*df.RealDefaults) {}}}
	for _, c := range realHandCases[1:] {
		cases = append(cases, struct {
			name string
			mut  func(*df.RealDefaults)
		}{c.name, c.mut})
	}
	for _, c := range cases {
		p := realDflt()
		c.mut(p)
		aper, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// C decodes the Go APER and re-encodes it bit-exact.
		if re := convPDU(t, bin, "RealDefaults", aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer := convPDU(t, bin, "RealDefaults", aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, "RealDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip % x != Go % x\n%s", c.name, re, aper, xer)
		}
		uper := convPDU(t, bin, "RealDefaults", aper, "-iaper", "-oper")
		if re := convPDU(t, bin, "RealDefaults", uper, "-iper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: UPER round trip % x != Go % x", c.name, re, aper)
		}
	}
	// XER of the absent members shows the defaults.
	x := strings.Join(strings.Fields(string(convPDU(t, bin, "RealDefaults",
		[]byte{0x00, 0x80}, "-iaper", "-oxer"))), "")
	for _, el := range []string{"<n></n>", "<r>1.5</r>", "<m>-2.25</m>",
		"<p><PLUS-INFINITY/></p>", "<q><MINUS-INFINITY/></q>",
		"<nz>-0</nz>", "<na><NOT-A-NUMBER/></na>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent members lacks %s: %s", el, x)
		}
	}
}

// ---- named-bit BIT STRING, OBJECT IDENTIFIER and RELATIVE-OID DEFAULT ----

func bsCopy(b df.BitString) df.BitString {
	return df.BitString{Bytes: append([]byte(nil), b.Bytes...), BitsUnused: b.BitsUnused}
}

func bitDflt() *df.BitDefaults {
	return &df.BitDefaults{
		A: bsCopy(df.BitDefaultsADefault),
		E: bsCopy(df.BitDefaultsEDefault),
		F: df.FixedPerms(bsCopy(df.BitString(df.BitDefaultsFDefault))),
		G: df.RangePerms(bsCopy(df.BitString(df.BitDefaultsGDefault))),
		H: df.Perms(bsCopy(df.BitString(df.BitDefaultsHDefault))),
		B: true,
	}
}

func TestNamedBitDefaultConstants(t *testing.T) {
	for _, c := range []struct {
		name string
		got  df.BitString
		want df.BitString
	}{
		// { p, r }: bits 0 and 2 (3 bits)
		{"a", df.BitDefaultsADefault, df.BitString{Bytes: []byte{0xa0}, BitsUnused: 5}},
		// { }: no bit
		{"e", df.BitDefaultsEDefault, df.BitString{Bytes: []byte{}, BitsUnused: 0}},
		// { write } under SIZE (4): padded to 4 bits
		{"f", df.BitString(df.BitDefaultsFDefault), df.BitString{Bytes: []byte{0x40}, BitsUnused: 4}},
		// { read } under SIZE (2..6): padded to the lower bound, 2 bits
		{"g", df.BitString(df.BitDefaultsGDefault), df.BitString{Bytes: []byte{0x80}, BitsUnused: 6}},
		{"h", df.BitString(df.BitDefaultsHDefault), df.BitString{Bytes: []byte{}, BitsUnused: 0}},
	} {
		if !bytes.Equal(c.got.Bytes, c.want.Bytes) || c.got.BitsUnused != c.want.BitsUnused {
			t.Errorf("%s: DEFAULT = %+v, want %+v", c.name, c.got, c.want)
		}
	}
}

// Hand-computed APER. The preamble is five presence bits (a e f g h), then the
// members present, then b.
//
//	all defaults:           00000 | b=1                       -> 04
//	f={read}  SIZE (4):     00100 | 1000 (4 bits)       | b   -> 24 40
//	g={read,write} (2..6):  00010 | 000 (length 2) 11   | b   -> 10 e0
//	g={} (2..6):            00010 | 000 (length 2) 00   | b   -> 10 20
//	b=false:                00000 | b=0                       -> 00
//
// The values with trailing 0 bits are equal to the default and are omitted.
var bitHandCases = []struct {
	name string
	mut  func(*df.BitDefaults)
	want []byte
}{
	{"all-default", func(*df.BitDefaults) {}, []byte{0x04}},
	{"f-read", func(p *df.BitDefaults) { p.F = df.FixedPerms{Bytes: []byte{0x80}, BitsUnused: 4} }, []byte{0x24, 0x40}},
	{"g-read-write", func(p *df.BitDefaults) { p.G = df.RangePerms{Bytes: []byte{0xc0}, BitsUnused: 6} }, []byte{0x10, 0xe0}},
	{"g-empty", func(p *df.BitDefaults) { p.G = df.RangePerms{Bytes: []byte{0x00}, BitsUnused: 6} }, []byte{0x10, 0x20}},
	{"b-false", func(p *df.BitDefaults) { p.B = false }, []byte{0x00}},
	// equal to the default, whatever the trailing 0 bits
	{"a-trailing-zeros", func(p *df.BitDefaults) { p.A = df.BitString{Bytes: []byte{0xa0, 0x00}} }, []byte{0x04}},
	{"a-unused-garbage", func(p *df.BitDefaults) { p.A = df.BitString{Bytes: []byte{0xa7}, BitsUnused: 5} }, []byte{0x04}},
	{"e-zero-bits", func(p *df.BitDefaults) { p.E = df.BitString{Bytes: []byte{0x00}, BitsUnused: 3} }, []byte{0x04}},
	{"f-eight-bits", func(p *df.BitDefaults) { p.F = df.FixedPerms{Bytes: []byte{0x40}, BitsUnused: 4} }, []byte{0x04}},
	{"g-padded", func(p *df.BitDefaults) { p.G = df.RangePerms{Bytes: []byte{0x80}, BitsUnused: 2} }, []byte{0x04}},
	{"h-zeros", func(p *df.BitDefaults) { p.H = df.Perms{Bytes: []byte{0x00}, BitsUnused: 0} }, []byte{0x04}},
}

func sameBits(a, b df.BitString) bool {
	return bytes.Equal(a.Bytes, b.Bytes) && a.BitsUnused == b.BitsUnused
}

func TestNamedBitDefaultHandAPER(t *testing.T) {
	for _, c := range bitHandCases {
		p := bitDflt()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		balanced(t, c.name)
	}
}

func TestNamedBitDefaultDecodeAbsent(t *testing.T) {
	got, err := df.DecodeBitDefaults([]byte{0x04})
	if err != nil {
		t.Fatal(err)
	}
	want := bitDflt()
	if !sameBits(got.A, want.A) || !sameBits(got.E, want.E) ||
		!sameBits(df.BitString(got.F), df.BitString(want.F)) ||
		!sameBits(df.BitString(got.G), df.BitString(want.G)) ||
		!sameBits(df.BitString(got.H), df.BitString(want.H)) || !got.B {
		t.Fatalf("absent members decode to %+v, want %+v", got, want)
	}
	balanced(t, "bit-absent")
}

func TestNamedBitDefaultRoundTrip(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*df.BitDefaults)
	}{
		{"a-p", func(p *df.BitDefaults) { p.A = df.BitString{Bytes: []byte{0x80}, BitsUnused: 7} }},
		{"a-pqr", func(p *df.BitDefaults) { p.A = df.BitString{Bytes: []byte{0xe0}, BitsUnused: 5} }},
		{"e-q", func(p *df.BitDefaults) { p.E = df.BitString{Bytes: []byte{0x40}, BitsUnused: 6} }},
		{"f-read", func(p *df.BitDefaults) { p.F = df.FixedPerms{Bytes: []byte{0x80}, BitsUnused: 4} }},
		{"g-both", func(p *df.BitDefaults) { p.G = df.RangePerms{Bytes: []byte{0xc0}, BitsUnused: 6} }},
		{"h-exec", func(p *df.BitDefaults) { p.H = df.Perms{Bytes: []byte{0x20}, BitsUnused: 5} }},
	} {
		p := bitDflt()
		c.mut(p)
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if bytes.Equal(b, []byte{0x04}) {
			t.Errorf("%s: non-default value encoded like the default", c.name)
		}
		back, err := df.DecodeBitDefaults(b)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		// Re-encoding the decoded value gives the same bytes.
		again, err := back.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Errorf("%s: re-encode % x (%v), want % x", c.name, again, err, b)
		}
		balanced(t, c.name)
	}
}

func TestNamedBitDefaultCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range bitHandCases {
		p := bitDflt()
		c.mut(p)
		aper, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if re := convPDU(t, bin, "BitDefaults", aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer := convPDU(t, bin, "BitDefaults", aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, "BitDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip % x != Go % x\n%s", c.name, re, aper, xer)
		}
	}
	// C's own encoder on a value with trailing 0 bits agrees with Go's.
	x := strings.Join(strings.Fields(string(convPDU(t, bin, "BitDefaults",
		[]byte{0x04}, "-iaper", "-oxer"))), "")
	for _, el := range []string{"<a>101</a>", "<e></e>", "<f>0100</f>", "<g>10</g>", "<h></h>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent members lacks %s: %s", el, x)
		}
	}
}

func oidDflt() *df.OidDefaults {
	return &df.OidDefaults{
		O: append([]uint64(nil), df.OidDefaultsODefault...),
		N: append([]uint64(nil), df.OidDefaultsNDefault...),
		R: append([]uint64(nil), df.OidDefaultsRDefault...),
		B: true,
	}
}

func TestOidDefaultConstants(t *testing.T) {
	if !reflect.DeepEqual([]uint64(df.OidDefaultsODefault), []uint64{1, 3, 6, 1, 4, 1, 9363}) ||
		!reflect.DeepEqual([]uint64(df.OidDefaultsNDefault), []uint64{1, 3, 7}) ||
		!reflect.DeepEqual([]uint64(df.OidDefaultsRDefault), []uint64{1, 2, 300}) {
		t.Fatalf("generated OID DEFAULT values are wrong: %v %v %v",
			df.OidDefaultsODefault, df.OidDefaultsNDefault, df.OidDefaultsRDefault)
	}
}

// Hand-computed APER. The preamble is three presence bits (o n r); a present
// member is length-prefixed at an octet boundary; b is the last bit.
//
//	all defaults:        000 | b=1                              -> 10
//	o=1.3.6.1.4.1.9364:  100 | pad | 07 2b 06 01 04 01 c9 14 | b -> 80 07 2b 06 01 04 01 c9 14 80
//	n=1.3.8:             010 | pad | 02 2b 08              | b    -> 40 02 2b 08 80
//	r=1.2:               001 | pad | 02 01 02              | b    -> 20 02 01 02 80
//	b=false:             000 | b=0                              -> 00
var oidHandCases = []struct {
	name string
	mut  func(*df.OidDefaults)
	want []byte
}{
	{"all-default", func(*df.OidDefaults) {}, []byte{0x10}},
	{"o-9364", func(p *df.OidDefaults) { p.O = []uint64{1, 3, 6, 1, 4, 1, 9364} },
		[]byte{0x80, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xc9, 0x14, 0x80}},
	{"n-8", func(p *df.OidDefaults) { p.N = []uint64{1, 3, 8} }, []byte{0x40, 0x02, 0x2b, 0x08, 0x80}},
	{"r-1-2", func(p *df.OidDefaults) { p.R = []uint64{1, 2} }, []byte{0x20, 0x02, 0x01, 0x02, 0x80}},
	{"b-false", func(p *df.OidDefaults) { p.B = false }, []byte{0x00}},
}

func TestOidDefaultHandAPER(t *testing.T) {
	for _, c := range oidHandCases {
		p := oidDflt()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		back, err := df.DecodeOidDefaults(c.want)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
	// A longer and a shorter value than the default are not the default.
	for _, arcs := range [][]uint64{{1, 3, 6, 1, 4, 1}, {1, 3, 6, 1, 4, 1, 9363, 0}} {
		p := oidDflt()
		p.O = arcs
		b, err := p.Encode()
		if err != nil || bytes.Equal(b, []byte{0x10}) {
			t.Fatalf("%v encoded as % x (%v)", arcs, b, err)
		}
		back, err := df.DecodeOidDefaults(b)
		if err != nil || !reflect.DeepEqual(back.O, arcs) {
			t.Fatalf("%v decoded as %v (%v)", arcs, back, err)
		}
	}
	balanced(t, "oid-prefix")
}

func TestOidDefaultCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range oidHandCases {
		p := oidDflt()
		c.mut(p)
		aper, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if re := convPDU(t, bin, "OidDefaults", aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer := convPDU(t, bin, "OidDefaults", aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, "OidDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip % x != Go % x\n%s", c.name, re, aper, xer)
		}
	}
	x := strings.Join(strings.Fields(string(convPDU(t, bin, "OidDefaults",
		[]byte{0x10}, "-iaper", "-oxer"))), "")
	for _, el := range []string{"<o>1.3.6.1.4.1.9363</o>", "<n>1.3.7</n>", "<r>1.2.300</r>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent members lacks %s: %s", el, x)
		}
	}
}
