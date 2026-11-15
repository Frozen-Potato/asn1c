package e2e

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"testing"

	r32 "asn1cgo.test/go/real32"
)

// float-narrowed REAL (tests/e2e/real32.asn). Copied into the generated
// module by tests/run-e2e.sh together with default_test.go (the converter
// helpers). A REAL that asn1c stores as a C float is float32 in Go; every
// other REAL is float64.

// The Go types are what the C side stores (compile-time checks).
var (
	_ float32    = r32.RsM{}.R
	_ *float32   = r32.RsO{}.R
	_ *float32   = r32.F32C{}.R
	_ []float32  = r32.RsL{}
	_ []r32.RsFl = r32.RsLF{}
	_ float32    = float32(r32.RsN{}.F)
	_ float32    = r32.RsD{}.R
	_ float32    = float32(r32.RsD{}.G)
	_ float32    = r32.RsDRDefault
	_ float32    = float32(r32.RsDGDefault)
	_ float64    = r32.RsM2{}.R
)

// the largest float32 the WITH COMPONENTS constraint (mantissa 24 bits,
// exponent up to 100) admits
var r32Max = float32(16777215 * math.Pow(2, 100))

var r32Vals = []float32{1.5, -2.25, 0.1, float32(math.Inf(1)), r32Max}

// r32XER spells a value the way the converter's XER reader takes it.
func r32XER(v float32) string {
	if math.IsInf(float64(v), 1) {
		return "<PLUS-INFINITY/>"
	}
	return strconv.FormatFloat(float64(v), 'g', -1, 64)
}

type r32Case struct {
	name, pdu, xer string
	enc            func() ([]byte, error)
	dec            func([]byte) (any, error)
	want           any
}

func r32Cases() []r32Case {
	var cs []r32Case
	for _, v := range r32Vals {
		v := v
		x := r32XER(v)
		n := fmt.Sprintf("%g", v)
		cs = append(cs,
			r32Case{"M/" + n, "RsM", "<RsM><a><true/></a><r>" + x + "</r></RsM>",
				(&r32.RsM{A: true, R: v}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsM(b) }, &r32.RsM{A: true, R: v}},
			r32Case{"O/" + n, "RsO", "<RsO><a><true/></a><r>" + x + "</r></RsO>",
				(&r32.RsO{A: true, R: &v}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsO(b) }, &r32.RsO{A: true, R: &v}},
			r32Case{"C/" + n, "F32C", "<F32C><r>" + x + "</r></F32C>",
				(&r32.F32C{Present: r32.F32CPrR, R: &v}).Encode,
				func(b []byte) (any, error) { return r32.DecodeF32C(b) }, &r32.F32C{Present: r32.F32CPrR, R: &v}},
			r32Case{"N/" + n, "RsN", "<RsN><a><true/></a><f>" + x + "</f></RsN>",
				(&r32.RsN{A: true, F: r32.RsFl(v)}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsN(b) }, &r32.RsN{A: true, F: r32.RsFl(v)}},
			r32Case{"L/" + n, "RsL", "<RsL><REAL>" + x + "</REAL><REAL>1.5</REAL></RsL>",
				(&r32.RsL{v, 1.5}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsL(b) }, &r32.RsL{v, 1.5}},
			r32Case{"LF/" + n, "RsLF", "<RsLF><RsFl>" + x + "</RsFl><RsFl>-2.25</RsFl></RsLF>",
				(&r32.RsLF{r32.RsFl(v), -2.25}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsLF(b) }, &r32.RsLF{r32.RsFl(v), -2.25}},
			r32Case{"D/" + n, "RsD", "<RsD><a><true/></a><r>" + x + "</r><g>" + x + "</g></RsD>",
				(&r32.RsD{A: true, R: v, G: r32.RsFl(v)}).Encode,
				func(b []byte) (any, error) { return r32.DecodeRsD(b) }, &r32.RsD{A: true, R: v, G: r32.RsFl(v)}},
		)
	}
	d := 1.0 / 3
	cs = append(cs, r32Case{"M2/double", "RsM2",
		"<RsM2><a><true/></a><r>" + strconv.FormatFloat(d, 'g', -1, 64) + "</r></RsM2>",
		(&r32.RsM2{A: true, R: d}).Encode,
		func(b []byte) (any, error) { return r32.DecodeRsM2(b) }, &r32.RsM2{A: true, R: d}})
	return cs
}

func TestReal32RoundTrip(t *testing.T) {
	for _, c := range r32Cases() {
		b, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		got, err := c.dec(b)
		if err != nil {
			t.Errorf("%s: decode: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: decoded %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Absent OPTIONAL stays nil; the other member is untouched.
func TestReal32OptionalAbsent(t *testing.T) {
	b, err := (&r32.RsO{A: true}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := r32.DecodeRsO(b)
	if err != nil || got.R != nil || !got.A {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// The Go APER equals the C converter's APER of the same value (written as
// XER), and the C converter reads the Go APER back to the same bytes.
func TestReal32CConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range r32Cases() {
		b, err := c.enc()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		cb := convPDU(t, bin, c.pdu, []byte(c.xer), "-ixer", "-oaper")
		if !bytes.Equal(cb, b) {
			t.Errorf("%s: C APER % x != Go APER % x", c.name, cb, b)
		}
		if re := convPDU(t, bin, c.pdu, b, "-iaper", "-oaper"); !bytes.Equal(re, b) {
			t.Errorf("%s: C re-encode % x != Go % x", c.name, re, b)
		}
	}
}

// Hand-computed APER of RsM{A: true, R: 1.5}: the BOOLEAN bit, then the REAL
// octet-aligned: length 3, content 80 (binary, base 2, positive, no scale)
// ff (exponent -1) 03 (mantissa 3), i.e. 3 * 2^-1. A float and a double REAL
// share the wire form.
func TestReal32KnownBytes(t *testing.T) {
	want := []byte{0x80, 0x03, 0x80, 0xff, 0x03}
	b, err := (&r32.RsM{A: true, R: 1.5}).Encode()
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("RsM APER % x (%v), want % x", b, err, want)
	}
	got, err := r32.DecodeRsM(b)
	if err != nil || got.R != 1.5 {
		t.Fatalf("% x -> %+v, %v", b, got, err)
	}
	d, err := (&r32.RsM2{A: true, R: 1.5}).Encode()
	if err != nil || !bytes.Equal(d, want) {
		t.Fatalf("RsM2 APER % x (%v), want % x", d, err, want)
	}
}

// A DEFAULT equal to the member is omitted on the wire; absent decodes to the
// float32 default.
func TestReal32Default(t *testing.T) {
	def := &r32.RsD{A: true, R: r32.RsDRDefault, G: r32.RsDGDefault}
	b, err := def.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 {
		t.Errorf("all-default APER = % x, want one byte (A and two presence bits)", b)
	}
	got, err := r32.DecodeRsD(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.R != float32(0.1) || float32(got.G) != float32(0.1) {
		t.Errorf("absent members decode to %v, %v, want float32(0.1)", got.R, got.G)
	}
	if !reflect.DeepEqual(got, def) {
		t.Errorf("decoded %+v, want %+v", got, def)
	}
	// a different value is present, so the encoding is longer
	o, err := (&r32.RsD{A: true, R: 1.5, G: r32.RsDGDefault}).Encode()
	if err != nil || len(o) <= len(b) {
		t.Errorf("non-default APER % x (%v), want longer than % x", o, err, b)
	}
	if bin := os.Getenv("ASN1CGO_C_CONVERTER"); bin != "" {
		if cb := convPDU(t, bin, "RsD", []byte("<RsD><a><true/></a></RsD>"), "-ixer", "-oaper"); !bytes.Equal(cb, b) {
			t.Errorf("C APER of absent members % x != Go % x", cb, b)
		}
	}
}
