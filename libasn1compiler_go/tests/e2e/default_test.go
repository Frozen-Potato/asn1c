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
	dfb "asn1cgo.test/go/defaultsoidbase"
	dc "asn1cgo.test/go/defaultscom"
	dt "asn1cgo.test/go/defaultstop"
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

func oidRefDflt() *df.OidRefDefaults {
	cp := func(a []uint64) []uint64 { return append([]uint64(nil), a...) }
	return &df.OidRefDefaults{
		A: cp(df.OidRefDefaultsADefault), B: cp(df.OidRefDefaultsBDefault),
		C: cp(df.OidRefDefaultsCDefault), D: cp(df.OidRefDefaultsDDefault),
		E: cp(df.OidRefDefaultsEDefault), F: cp(df.OidRefDefaultsFDefault),
		G: cp(df.OidRefDefaultsGDefault), I: cp(df.OidRefDefaultsIDefault),
		Z: true,
	}
}

func TestOidRefDefaultConstants(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want []uint64
	}{
		{"a", df.OidRefDefaultsADefault, []uint64{1, 3, 6, 1}},
		{"b", df.OidRefDefaultsBDefault, []uint64{1, 3, 6, 1, 5}},
		{"c", df.OidRefDefaultsCDefault, []uint64{1, 3, 6, 1, 4, 1}},
		{"d", df.OidRefDefaultsDDefault, []uint64{1, 3, 6, 1}},
		{"e", df.OidRefDefaultsEDefault, []uint64{2, 5, 29, 15}},
		{"f", df.OidRefDefaultsFDefault, []uint64{1, 3, 6, 1, 8, 9}},
		{"g", df.OidRefDefaultsGDefault, []uint64{1, 3, 6, 1, 42}},
		{"i", df.OidRefDefaultsIDefault, []uint64{8, 9, 1}},
	} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s DEFAULT = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// Hand-computed APER: eight presence bits (a b c d e f g i) then z.
//
//	all defaults:    00 | z=1                       -> 00 80
//	a=1.3.6.2:       80 | 03 2b 06 02 | z           -> 80 03 2b 06 02 80
//	i=8.9.2:         01 | 03 08 09 02 | z           -> 01 03 08 09 02 80
var oidRefHandCases = []struct {
	name string
	mut  func(*df.OidRefDefaults)
	want []byte
}{
	{"all-default", func(*df.OidRefDefaults) {}, []byte{0x00, 0x80}},
	{"a-1-3-6-2", func(p *df.OidRefDefaults) { p.A = []uint64{1, 3, 6, 2} },
		[]byte{0x80, 0x03, 0x2b, 0x06, 0x02, 0x80}},
	{"i-8-9-2", func(p *df.OidRefDefaults) { p.I = []uint64{8, 9, 2} },
		[]byte{0x01, 0x03, 0x08, 0x09, 0x02, 0x80}},
}

func TestOidRefDefaultHandAPER(t *testing.T) {
	for _, c := range oidRefHandCases {
		p := oidRefDflt()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		back, err := df.DecodeOidRefDefaults(c.want)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
}

func TestOidRefDefaultCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range oidRefHandCases {
		p := oidRefDflt()
		c.mut(p)
		aper, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if re := convPDU(t, bin, "OidRefDefaults", aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer := convPDU(t, bin, "OidRefDefaults", aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, "OidRefDefaults", xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip % x != Go % x\n%s", c.name, re, aper, xer)
		}
	}
	x := strings.Join(strings.Fields(string(convPDU(t, bin, "OidRefDefaults",
		[]byte{0x00, 0x80}, "-iaper", "-oxer"))), "")
	for _, el := range []string{"<a>1.3.6.1</a>", "<b>1.3.6.1.5</b>", "<c>1.3.6.1.4.1</c>",
		"<d>1.3.6.1</d>", "<e>2.5.29.15</e>", "<f>1.3.6.1.8.9</f>", "<g>1.3.6.1.42</g>", "<i>8.9.1</i>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent members lacks %s: %s", el, x)
		}
	}
}

// ---- DEFAULT of a SEQUENCE / SET / SEQUENCE OF / SET OF member ----
//
// The field is a plain value; the exported default is a func returning a new
// value (the Go zero value is not the DEFAULT).

func consT() *df.ConsT {
	return &df.ConsT{
		F: df.ConsTFDefault(), A: df.ConsTADefault(), B: df.ConsTBDefault(),
		D: df.ConsTDDefault(), E: df.ConsTEDefault(), G: df.ConsTGDefault(),
		Z: true,
	}
}

func consU() *df.ConsU {
	return &df.ConsU{
		H: df.ConsUHDefault(), I: df.ConsUIDefault(), L: df.ConsULDefault(),
		M: df.ConsUMDefault(), T: df.ConsUTDefault(), Z: true,
	}
}

func TestConsDefaultValues(t *testing.T) {
	if got, want := df.ConsTFDefault(), (df.ConsTF{M: 5}); got != want {
		t.Errorf("ConsTFDefault = %+v, want %+v", got, want)
	}
	if got, want := df.ConsTADefault(), (df.Pt{X: 1, Y: 2}); got != want {
		t.Errorf("ConsTADefault = %+v, want %+v", got, want)
	}
	if got, want := df.ConsTBDefault(), (df.Pt{X: 1, Y: 2}); got != want {
		t.Errorf("ConsTBDefault (value reference) = %+v, want %+v", got, want)
	}
	// d = { } is the empty list; e = { 1, 2 }; g = { x 4 } with y filled from
	// its own DEFAULT.
	if got := df.ConsTDDefault(); len(got) != 0 {
		t.Errorf("ConsTDDefault = %v, want empty", got)
	}
	if got, want := df.ConsTEDefault(), (df.Ls{1, 2}); !reflect.DeepEqual(got, want) {
		t.Errorf("ConsTEDefault = %v, want %v", got, want)
	}
	if got, want := df.ConsTGDefault(), (df.Pt{X: 4, Y: 7}); got != want {
		t.Errorf("ConsTGDefault = %+v, want %+v", got, want)
	}
	// SET, SEQUENCE OF Pt, nested SEQUENCE with a SEQUENCE OF, imported
	// value, SET OF.
	if got, want := df.ConsUHDefault(), (df.St{P: 3, Q: true, R: "x"}); got != want {
		t.Errorf("ConsUHDefault = %+v, want %+v", got, want)
	}
	if got, want := df.ConsUIDefault(), (df.ConsUI{{X: 1, Y: 7}, {X: 2, Y: 3}}); !reflect.DeepEqual(got, want) {
		t.Errorf("ConsUIDefault = %v, want %v", got, want)
	}
	if got, want := df.ConsULDefault(), (df.ConsUL{N: df.ConsULN{V: df.Ls{3, 4}, W: 9}}); !reflect.DeepEqual(got, want) {
		t.Errorf("ConsULDefault = %+v, want %+v", got, want)
	}
	if got, want := df.ConsUMDefault(), (dfb.ImpPt{X: 9, Y: 8}); got != want {
		t.Errorf("ConsUMDefault (imported value) = %+v, want %+v", got, want)
	}
	if got, want := df.ConsUTDefault(), (df.ConsUT{"A", "B"}); !reflect.DeepEqual(got, want) {
		t.Errorf("ConsUTDefault = %v, want %v", got, want)
	}
	// An inline SEQUENCE member whose only member has a hyphen.
	if got, want := df.Golden81OtherDefault(), (df.Golden81Other{Member1: 5}); got != want {
		t.Errorf("Golden81OtherDefault = %+v, want %+v", got, want)
	}
	// The DEFAULT member of an inline SEQUENCE.
	if got, want := df.ConsNestedOuterInnerDefault(), (df.Pt{X: 3, Y: 7}); got != want {
		t.Errorf("ConsNestedOuterInnerDefault = %+v, want %+v", got, want)
	}
	// The zero value is not the default.
	if reflect.DeepEqual(&df.ConsT{}, consT()) {
		t.Fatal("zero value equals the default value")
	}
	balanced(t, "cons-values")
}

// Each call returns a new value: mutating one does not change the next.
func TestConsDefaultIndependent(t *testing.T) {
	a := df.ConsTEDefault()
	a[0] = 9
	a = append(a, 4)
	if got := df.ConsTEDefault(); !reflect.DeepEqual(got, df.Ls{1, 2}) {
		t.Errorf("ConsTEDefault after mutation = %v", got)
	}
	i := df.ConsUIDefault()
	i[0].X = 99
	i[1] = df.Pt{}
	if got := df.ConsUIDefault(); got[0].X != 1 || got[1].X != 2 {
		t.Errorf("ConsUIDefault after mutation = %v", got)
	}
	l := df.ConsULDefault()
	l.N.V[0] = 0
	if got := df.ConsULDefault(); got.N.V[0] != 3 {
		t.Errorf("ConsULDefault after mutation = %+v", got)
	}
	tt := df.ConsUTDefault()
	tt[0] = "zz"
	if got := df.ConsUTDefault(); got[0] != "A" {
		t.Errorf("ConsUTDefault after mutation = %v", got)
	}
	balanced(t, "cons-independent")
}

// Hand-computed APER (X.691), identical to the bytes of the C check of the
// same shape: ConsT has 6 presence bits (f a b d e g) + z.
//   all absent:  000000 1 -> 02
//   a.y = 3:     presence a (010000), a = x(1 byte, 01) y-present 1 y(3): 42 01 03 80
//   d = { 0 }:   presence d, size 1, the element (0 in 4 bits): 10 84
var consTHand = []struct {
	name string
	mut  func(*df.ConsT)
	want []byte
}{
	{"all-default", func(*df.ConsT) {}, []byte{0x02}},
	{"a-y-3", func(p *df.ConsT) { p.A.Y = 3 }, []byte{0x42, 0x01, 0x03, 0x80}},
	{"d-0", func(p *df.ConsT) { p.D = df.Ls{0} }, []byte{0x10, 0x84}},
}

func TestConsDefaultHandAPER(t *testing.T) {
	for _, c := range consTHand {
		p := consT()
		c.mut(p)
		got, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: APER = % x, want % x", c.name, got, c.want)
		}
		back, err := df.DecodeConsT(c.want)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, back, p)
		}
		balanced(t, c.name)
	}
}

// Absent on the wire -> the decoded field equals XDefault(); a field set to
// XDefault() encodes exactly like the all-absent value.
func TestConsDefaultAbsentAndOmitted(t *testing.T) {
	got, err := df.DecodeConsT([]byte{0x02})
	if err != nil || !reflect.DeepEqual(got, consT()) {
		t.Fatalf("decode 02: %+v, %v", got, err)
	}
	// g = { x 4 } with y absent in the value equals the default { x 4, y 7 }.
	p := consT()
	p.G = df.Pt{X: 4, Y: 7}
	if b, err := p.Encode(); err != nil || !bytes.Equal(b, []byte{0x02}) {
		t.Fatalf("g = default: % x, %v", b, err)
	}
	for name, mut := range map[string]func(*df.ConsT){
		"f": func(p *df.ConsT) { p.F = df.ConsTFDefault() },
		"d": func(p *df.ConsT) { p.D = df.ConsTDDefault() },
		"e": func(p *df.ConsT) { p.E = df.ConsTEDefault() },
	} {
		q := &df.ConsT{Z: true}
		q.A, q.B, q.G = df.ConsTADefault(), df.ConsTBDefault(), df.ConsTGDefault()
		q.F, q.D, q.E = df.ConsTFDefault(), df.ConsTDDefault(), df.ConsTEDefault()
		mut(q)
		if b, err := q.Encode(); err != nil || !bytes.Equal(b, []byte{0x02}) {
			t.Errorf("%s = default: % x, %v", name, b, err)
		}
	}

	u := consU()
	ub, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// five presence bits (h i l m t) + z
	if !bytes.Equal(ub, []byte{0x04}) {
		t.Fatalf("ConsU all-default = % x, want 04", ub)
	}
	back, err := df.DecodeConsU(ub)
	if err != nil || !reflect.DeepEqual(back, consU()) {
		t.Fatalf("decode ConsU 04: %+v, %v", back, err)
	}

	g := &df.Golden81{Other: df.Golden81OtherDefault()}
	gb, err := g.Encode()
	if err != nil {
		t.Fatal(err)
	}
	gback, err := df.DecodeGolden81(gb)
	if err != nil || gback.Other != df.Golden81OtherDefault() {
		t.Fatalf("Golden81 % x -> %+v, %v", gb, gback, err)
	}
	z, _ := (&df.Golden81{Other: df.Golden81Other{Member1: 2}}).Encode()
	if bytes.Equal(z, gb) {
		t.Fatalf("Golden81 non-default encodes like the default: % x", z)
	}

	n := &df.ConsNested{Outer: df.ConsNestedOuter{Inner: df.ConsNestedOuterInnerDefault()}, Z: true}
	nb, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	nback, err := df.DecodeConsNested(nb)
	if err != nil || !reflect.DeepEqual(nback, n) {
		t.Fatalf("ConsNested % x -> %+v, %v", nb, nback, err)
	}
	balanced(t, "cons-absent")
}

// A different value round-trips.
func TestConsDefaultOtherValues(t *testing.T) {
	for name, mut := range map[string]func(*df.ConsU){
		"h":      func(p *df.ConsU) { p.H = df.St{P: 1, Q: false, R: "abc"} },
		"i":      func(p *df.ConsU) { p.I = df.ConsUI{{X: 5, Y: 6}} },
		"i-nil":  func(p *df.ConsU) { p.I = nil },
		"l":      func(p *df.ConsU) { p.L.N.V = df.Ls{1}; p.L.N.W = 2 },
		"m":      func(p *df.ConsU) { p.M = dfb.ImpPt{X: 1, Y: 1} },
		"t":      func(p *df.ConsU) { p.T = df.ConsUT{"Z"} },
	} {
		p := consU()
		mut(p)
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(b, []byte{0x04}) && name != "i-nil" {
			t.Errorf("%s: encodes like the default", name)
		}
		back, err := df.DecodeConsU(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if name == "i-nil" {
			// an empty list is not the default list
			if len(back.I) != 0 {
				t.Errorf("%s: I = %v", name, back.I)
			}
			continue
		}
		if !reflect.DeepEqual(back, p) {
			t.Errorf("%s: %+v, want %+v", name, back, p)
		}
	}
	balanced(t, "cons-other")
}

// The C converter (same C tree) agrees on every encoding, and an XER round
// trip keeps it.
func TestConsDefaultCConverter(t *testing.T) {
	bin := converter(t)
	check := func(pdu, name string, aper []byte) {
		t.Helper()
		if re := convPDU(t, bin, pdu, aper, "-iaper", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s %s: C APER re-encode % x != Go % x", pdu, name, re, aper)
		}
		xer := convPDU(t, bin, pdu, aper, "-iaper", "-oxer")
		if re := convPDU(t, bin, pdu, xer, "-ixer", "-oaper"); !bytes.Equal(re, aper) {
			t.Errorf("%s %s: XER round trip % x != Go % x\n%s", pdu, name, re, aper, xer)
		}
	}
	for _, c := range consTHand {
		p := consT()
		c.mut(p)
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		check("ConsT", c.name, b)
	}
	// The absent members as XER of the C decoder: every default is written in.
	x := strings.Join(strings.Fields(string(convPDU(t, bin, "ConsT", []byte{0x02}, "-iaper", "-oxer"))), "")
	for _, el := range []string{"<f><m>5</m></f>", "<a><x>1</x><y>2</y></a>", "<d></d>",
		"<e><INTEGER>1</INTEGER><INTEGER>2</INTEGER></e>", "<g><x>4</x><y>7</y></g>"} {
		if !strings.Contains(x, el) {
			t.Errorf("XER of absent members lacks %s: %s", el, x)
		}
	}
	u := consU()
	ub, _ := u.Encode()
	check("ConsU", "all-default", ub)
	u.L.N.W = 1
	ub, _ = u.Encode()
	check("ConsU", "l", ub)
	g := &df.Golden81{Other: df.Golden81OtherDefault()}
	gb, _ := g.Encode()
	check("Golden81", "default", gb)
	g.Other.Member1 = 1
	gb, _ = g.Encode()
	check("Golden81", "other", gb)
	n := &df.ConsNested{Outer: df.ConsNestedOuter{Inner: df.ConsNestedOuterInnerDefault(), K: true}, Z: true}
	nb, _ := n.Encode()
	check("ConsNested", "default", nb)
	n.Outer.Inner.X = 8
	nb, _ = n.Encode()
	check("ConsNested", "other", nb)
}

// The owner of the DEFAULT member is the element of an inline SEQUENCE OF, or
// an OPTIONAL inline SEQUENCE.
func TestConsDefaultInnerOwners(t *testing.T) {
	if got, want := df.ConsListLstMemberPDefault(), (df.Pt{X: 1, Y: 7}); got != want {
		t.Errorf("ConsListLstMemberPDefault = %+v, want %+v", got, want)
	}
	if got, want := df.ConsListOptQDefault(), (df.Pt{X: 2, Y: 7}); got != want {
		t.Errorf("ConsListOptQDefault = %+v, want %+v", got, want)
	}
	p := &df.ConsList{
		Lst: df.ConsListLst{{P: df.ConsListLstMemberPDefault(), K: true}, {P: df.Pt{X: 3, Y: 3}}},
		Opt: &df.ConsListOpt{Q: df.ConsListOptQDefault()},
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := df.DecodeConsList(b)
	if err != nil || !reflect.DeepEqual(back, p) {
		t.Fatalf("% x -> %+v, %v", b, back, err)
	}
	if bin := os.Getenv("ASN1CGO_C_CONVERTER"); bin != "" {
		if re := convPDU(t, bin, "ConsList", b, "-iaper", "-oaper"); !bytes.Equal(re, b) {
			t.Errorf("C APER re-encode % x != Go % x", re, b)
		}
	}
	balanced(t, "cons-inner")
}

// Default funcs of a module without a PDU (DefaultsCom) and of members owned
// by an inline SEQUENCE alternative of a CHOICE (DefaultsTop). Hand-computed
// APER, cross-checked with the C converter:
//   TopMsg b.p = {1,7}, k 2, n 3 -> 46   (p absent, k 2, n 3)
//   TopMsg b.p = {5,7}           -> 80 05 8c
//   TopM2 c.s.q = {2,7}          -> 00
func TestDefaultFuncNoPDUModuleAndChoiceAlt(t *testing.T) {
	if got, want := dc.ComBoxPDefault(), (dc.ComPt{X: 1, Y: 7}); got != want {
		t.Errorf("ComBoxPDefault = %+v, want %+v", got, want)
	}
	if got, want := dt.TopChSQDefault(), (dc.ComPt{X: 2, Y: 7}); got != want {
		t.Errorf("TopChSQDefault = %+v, want %+v", got, want)
	}
	if got, want := dt.TopDeepSMQDefault(), (dc.ComPt{X: 4, Y: 7}); got != want {
		t.Errorf("TopDeepSMQDefault = %+v, want %+v", got, want)
	}
	if got, want := dt.TopTCSQDefault(), (dc.ComPt{X: 3, Y: 7}); got != want {
		t.Errorf("TopTCSQDefault = %+v, want %+v", got, want)
	}
	// independent values (a struct is a value: a second call is unaffected)
	a := dc.ComBoxPDefault()
	a.X = 99
	if got := dc.ComBoxPDefault(); got.X != 1 {
		t.Errorf("second call = %+v", got)
	}

	msg := func(p dc.ComPt) *dt.TopMsg { return &dt.TopMsg{B: dc.ComBox{P: p, K: 2}, N: 3} }
	cases := []struct {
		name string
		msg  *dt.TopMsg
		want []byte
	}{
		{"default", msg(dc.ComBoxPDefault()), []byte{0x46}},
		{"other", msg(dc.ComPt{X: 5, Y: 7}), []byte{0x80, 0x05, 0x8c}},
	}
	bin := os.Getenv("ASN1CGO_C_CONVERTER")
	for _, c := range cases {
		b, err := c.msg.Encode()
		if err != nil || !bytes.Equal(b, c.want) {
			t.Fatalf("%s: % x, %v; want % x", c.name, b, err, c.want)
		}
		back, err := dt.DecodeTopMsg(c.want)
		if err != nil || !reflect.DeepEqual(back, c.msg) {
			t.Fatalf("%s: decoded %+v, %v", c.name, back, err)
		}
		if bin != "" {
			if re := convPDU(t, bin, "TopMsg", c.want, "-iaper", "-oaper"); !bytes.Equal(re, c.want) {
				t.Errorf("%s: C re-encode % x != % x", c.name, re, c.want)
			}
		}
	}
	// absent on the wire -> the decoded field equals the func's value
	back, _ := dt.DecodeTopMsg([]byte{0x46})
	if back.B.P != dc.ComBoxPDefault() {
		t.Errorf("absent p decoded as %+v", back.B.P)
	}
	// a different value (y differs) round-trips
	o := msg(dc.ComPt{X: 1, Y: 8})
	ob, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if ob2, _ := cases[0].msg.Encode(); bytes.Equal(ob, ob2) {
		t.Errorf("non-default encodes like the default")
	}
	if back, err := dt.DecodeTopMsg(ob); err != nil || !reflect.DeepEqual(back, o) {
		t.Errorf("other value: %+v, %v", back, err)
	}

	// the CHOICE alternative owner
	m2 := &dt.TopM2{C: dt.TopCh{Present: dt.TopChPrS, S: &dt.TopChS{Q: dt.TopChSQDefault()}}}
	b2, err := m2.Encode()
	if err != nil || !bytes.Equal(b2, []byte{0x00}) {
		t.Fatalf("TopM2 default: % x, %v", b2, err)
	}
	if back, err := dt.DecodeTopM2(b2); err != nil || !reflect.DeepEqual(back, m2) {
		t.Fatalf("TopM2 decode: %+v, %v", back, err)
	}
	m2.C.S.Q = dc.ComPt{X: 2, Y: 9}
	b2o, err := m2.Encode()
	if err != nil || bytes.Equal(b2o, b2) {
		t.Fatalf("TopM2 other: % x, %v", b2o, err)
	}
	if back, err := dt.DecodeTopM2(b2o); err != nil || !reflect.DeepEqual(back, m2) {
		t.Fatalf("TopM2 other decode: %+v, %v", back, err)
	}
	if bin != "" {
		for _, b := range [][]byte{b2, b2o} {
			if re := convPDU(t, bin, "TopM2", b, "-iaper", "-oaper"); !bytes.Equal(re, b) {
				t.Errorf("TopM2 C re-encode % x != % x", re, b)
			}
		}
	}

	// the nested shapes
	d := &dt.TopDeep{Present: dt.TopDeepPrS, S: &dt.TopDeepS{M: dt.TopDeepSM{Q: dt.TopDeepSMQDefault(), K: true}, J: true}}
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := dt.DecodeTopDeep(db); err != nil || !reflect.DeepEqual(back, d) {
		t.Fatalf("TopDeep: %+v, %v", back, err)
	}
	tt := &dt.TopT{C: dt.TopTC{Present: dt.TopTCPrS, S: &dt.TopTCS{Q: dt.TopTCSQDefault()}}}
	tb, err := tt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := dt.DecodeTopT(tb); err != nil || !reflect.DeepEqual(back, tt) {
		t.Fatalf("TopT: %+v, %v", back, err)
	}
	if bin != "" {
		for pdu, b := range map[string][]byte{"TopDeep": db, "TopT": tb} {
			if re := convPDU(t, bin, pdu, b, "-iaper", "-oaper"); !bytes.Equal(re, b) {
				t.Errorf("%s C re-encode % x != % x", pdu, re, b)
			}
		}
	}
	balanced(t, "default-nopdu-choice")
}
