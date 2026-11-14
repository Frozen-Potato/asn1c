// Mandatory extension additions (pointers in Go), INTEGER members wider than
// int64 and a CHOICE alternative named `present` (tests/e2e/extwide.asn).
// Copied into the generated module by tests/run-e2e.sh together with
// seqof_test.go (the siCase helpers) and default_test.go (the converter
// helpers).
//
// Per case of ewCases: Go APER == the C converter's APER of the same value
// written as XER, Go's decode gives the value back, and the converter's XER of
// the Go APER is the given XER. The "old version" tests decode bytes produced
// by the C converter from a value of ExtOld, the type before b and c existed.
package e2e

import (
	"bytes"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ew "asn1cgo.test/go/extwide"
)

func ewCases() []siCase {
	var cs []siCase
	add := func(c siCase) { cs = append(cs, c) }
	u64 := func(v uint64) *uint64 { return &v }
	i64 := func(v int64) *int64 { return &v }
	bp := siPtr[bool]
	bl := siBool
	el := func(name string, inner ...string) string {
		s := "<" + name + ">"
		for _, i := range inner {
			s += i
		}
		return s + "</" + name + ">"
	}
	wrap := el
	u := func(v uint64) string { return utoa(v) }

	// ---- AC1: mandatory extension additions ----
	nw := func(name string, v *ew.ExtNew, parts ...string) {
		add(siMk(name, "ExtNew", wrap("ExtNew", parts...), v, ew.DecodeExtNew))
	}
	// both additions absent: what an old sender produces; the C encoder
	// treats a NULL addition as absent
	nw("extnew-none", &ew.ExtNew{A: 2}, el("a", "2"))
	nw("extnew-b", &ew.ExtNew{A: 0, B: bp(true)}, el("a", "0"), el("b", bl(true)))
	nw("extnew-c", &ew.ExtNew{A: 3, C: i64(7)}, el("a", "3"), el("c", "7"))
	nw("extnew-bc", &ew.ExtNew{A: 1, B: bp(false), C: i64(5)}, el("a", "1"), el("b", bl(false)), el("c", "5"))

	mx := func(name string, v *ew.ExtMix, parts ...string) {
		add(siMk(name, "ExtMix", wrap("ExtMix", parts...), v, ew.DecodeExtMix))
	}
	d := []byte{0xAB, 0xCD}
	mx("extmix-none", &ew.ExtMix{A: 1}, el("a", "1"))
	mx("extmix-d", &ew.ExtMix{A: 1, D: &d}, el("a", "1"), el("d", "ABCD"))
	mx("extmix-c", &ew.ExtMix{A: 2, C: i64(0)}, el("a", "2"), el("c", "0"))
	mx("extmix-bcd", &ew.ExtMix{A: 3, B: bp(true), C: i64(7), D: &d},
		el("a", "3"), el("b", bl(true)), el("c", "7"), el("d", "ABCD"))

	// a DEFAULT addition is a plain value; a mandatory one next to it a pointer
	df := func(name string, v *ew.ExtDef, parts ...string) {
		add(siMk(name, "ExtDef", wrap("ExtDef", parts...), v, ew.DecodeExtDef))
	}
	// the C XER writer spells out a DEFAULT member
	df("extdef-default", &ew.ExtDef{A: 1, B: ew.ExtDefBDefault}, el("a", "1"), el("b", bl(true)))
	df("extdef-b", &ew.ExtDef{A: 1, B: false}, el("a", "1"), el("b", bl(false)))
	df("extdef-c", &ew.ExtDef{A: 0, B: true, C: i64(4)}, el("a", "0"), el("b", bl(true)), el("c", "4"))
	df("extdef-bc", &ew.ExtDef{A: 0, B: false, C: i64(4)}, el("a", "0"), el("b", bl(false)), el("c", "4"))

	// ---- AC2: INTEGER_t members (range 0..2^40-1, uint64 in Go) ----
	wm := func(name string, v *ew.WideMem, parts ...string) {
		add(siMk(name, "WideMem", wrap("WideMem", parts...), v, ew.DecodeWideMem))
	}
	wideVals := []struct {
		n string
		v uint64
	}{{"0", 0}, {"2", 2}, {"2p32", 1 << 32}, {"max", 1<<40 - 1}}
	for _, x := range wideVals {
		wm("widemem-"+x.n, &ew.WideMem{A: x.v, C: true}, el("a", u(x.v)), el("c", bl(true)))
		wm("widemem-opt-"+x.n, &ew.WideMem{A: 1, B: u64(x.v), C: false},
			el("a", "1"), el("b", u(x.v)), el("c", bl(false)))
	}
	wm("widemem-both-max", &ew.WideMem{A: 1<<40 - 1, B: u64(1<<40 - 1), C: true},
		el("a", u(1<<40-1)), el("b", u(1<<40-1)), el("c", bl(true)))

	wa := func(name string, v *ew.WideAlt, inner string) {
		add(siMk(name, "WideAlt", wrap("WideAlt", inner), v, ew.DecodeWideAlt))
	}
	for _, x := range wideVals {
		wa("widealt-a-"+x.n, &ew.WideAlt{Present: ew.WideAltPrA, A: u64(x.v)}, el("a", u(x.v)))
	}
	wa("widealt-b", &ew.WideAlt{Present: ew.WideAltPrB, B: bp(true)}, el("b", bl(true)))

	add(siMk("widelist-3", "WideList",
		wrap("WideList", "<INTEGER>0</INTEGER>", "<INTEGER>"+u(1<<32)+"</INTEGER>", "<INTEGER>"+u(1<<40-1)+"</INTEGER>"),
		&ew.WideList{0, 1 << 32, 1<<40 - 1}, ew.DecodeWideList))
	add(siMk("wideinseq", "WideInSeq",
		wrap("WideInSeq", el("l", "<INTEGER>"+u(1<<40-1)+"</INTEGER>", "<INTEGER>2</INTEGER>"), el("x", el("p", u(1<<32)))),
		&ew.WideInSeq{L: ew.WideInSeqL{1<<40 - 1, 2}, X: ew.WideInSeqX{Present: ew.WideInSeqXPrP, P: u64(1 << 32)}},
		ew.DecodeWideInSeq))

	// ---- AC2: the full uint64 range, the cases the C codec can encode ----
	add(siMk("u64opt-absent", "U64Opt", wrap("U64Opt", el("a", bl(true))), &ew.U64Opt{A: true}, ew.DecodeU64Opt))
	add(siMk("u64opt-absent-false", "U64Opt", wrap("U64Opt", el("a", bl(false))), &ew.U64Opt{A: false}, ew.DecodeU64Opt))
	add(siMk("u64alt-b", "U64Alt", wrap("U64Alt", el("b", bl(true))), &ew.U64Alt{Present: ew.U64AltPrB, B: bp(true)}, ew.DecodeU64Alt))

	// ---- AC3: a CHOICE alternative named present ----
	pc := func(name string, v *ew.PresChoice, inner string) {
		add(siMk(name, "PresChoice", wrap("PresChoice", inner), v, ew.DecodePresChoice))
	}
	pc("preschoice-present-0", &ew.PresChoice{Present: ew.PresChoicePrPresent, PresentAlt: i64(0)}, el("present", "0"))
	pc("preschoice-present-3", &ew.PresChoice{Present: ew.PresChoicePrPresent, PresentAlt: i64(3)}, el("present", "3"))
	pc("preschoice-b", &ew.PresChoice{Present: ew.PresChoicePrB, B: bp(false)}, el("b", bl(false)))
	pa := func(name string, v *ew.PresSeqAlt, inner string) {
		add(siMk(name, "PresSeqAlt", wrap("PresSeqAlt", inner), v, ew.DecodePresSeqAlt))
	}
	pa("pressegalt-b", &ew.PresSeqAlt{Present: ew.PresSeqAltPrB, B: bp(true)}, el("b", bl(true)))
	pa("pressegalt-present", &ew.PresSeqAlt{Present: ew.PresSeqAltPrPresent, PresentAlt: &ew.PresSeqAltPresent{Q: 2}},
		el("present", el("q", "2")))
	return cs
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for ; v > 0; v /= 10 {
		b = append([]byte{byte('0' + v%10)}, b...)
	}
	return string(b)
}

func TestExtWideRoundTrip(t *testing.T) {
	for _, c := range ewCases() {
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

func TestExtWideCConverter(t *testing.T) {
	bin := converter(t)
	for _, c := range ewCases() {
		aper, err := c.enc()
		if err != nil {
			t.Errorf("%s: encode: %v", c.name, err)
			continue
		}
		if ref, ok := siConv(t, bin, c, []byte(c.xer), "-ixer", "-oaper"); ok && !bytes.Equal(ref, aper) {
			t.Errorf("%s: Go APER % x != C APER of the XER value % x", c.name, aper, ref)
		}
		if re, ok := siConv(t, bin, c, aper, "-iaper", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: C APER re-encode % x != Go % x", c.name, re, aper)
		}
		xer, ok := siConv(t, bin, c, aper, "-iaper", "-oxer")
		if !ok {
			continue
		}
		if got := bsXML(xer); siSelfClose(got) != siSelfClose(c.xer) {
			t.Errorf("%s: C XER = %s, want %s", c.name, got, c.xer)
		}
		if re, ok := siConv(t, bin, c, xer, "-ixer", "-oaper"); ok && !bytes.Equal(re, aper) {
			t.Errorf("%s: XER round trip -> APER % x != Go % x", c.name, re, aper)
		}
	}
}

// A nil mandatory extension addition is encoded as absent: the same bytes as a
// value of the version that predates the addition, and no error (this is what
// the C runtime does with a NULL pointer, SEQUENCE__handle_extensions).
func TestExtNilMandatoryAddition(t *testing.T) {
	for a := int64(0); a <= 3; a++ {
		newB, err := (&ew.ExtNew{A: a}).Encode()
		if err != nil {
			t.Fatalf("a=%d: Encode of nil additions: %v", a, err)
		}
		oldB, err := (&ew.ExtOld{A: a}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(newB, oldB) {
			t.Errorf("a=%d: ExtNew{A} = % x, ExtOld{A} = % x", a, newB, oldB)
		}
	}
}

// Bytes produced by the C converter from an ExtOld value (an older sender)
// decode into the newer type with the additions nil, in every type that
// extends it.
func TestExtOldVersionDecode(t *testing.T) {
	bin := converter(t)
	for a := int64(0); a <= 3; a++ {
		c := siCase{name: "extold-" + itoa(a), pdu: "ExtOld"}
		old, ok := siConv(t, bin, c, []byte("<ExtOld><a>"+itoa(a)+"</a></ExtOld>"), "-ixer", "-oaper")
		if !ok {
			continue
		}
		n, err := ew.DecodeExtNew(old)
		if err != nil {
			t.Errorf("a=%d: DecodeExtNew(% x): %v", a, old, err)
		} else if want := (&ew.ExtNew{A: a}); !equalExt(n, want) {
			t.Errorf("a=%d: ExtNew = %+v, want %+v", a, n, want)
		}
		m, err := ew.DecodeExtMix(old)
		if err != nil {
			t.Errorf("a=%d: DecodeExtMix: %v", a, err)
		} else if m.A != a || m.B != nil || m.C != nil || m.D != nil {
			t.Errorf("a=%d: ExtMix = %+v", a, m)
		}
		df, err := ew.DecodeExtDef(old)
		if err != nil {
			t.Errorf("a=%d: DecodeExtDef: %v", a, err)
		} else if df.A != a || df.B != ew.ExtDefBDefault || df.C != nil {
			t.Errorf("a=%d: ExtDef = %+v (B must be its DEFAULT, C nil)", a, df)
		}
	}
}

func equalExt(a, b *ew.ExtNew) bool {
	return a.A == b.A && a.B == nil && b.B == nil && a.C == nil && b.C == nil
}

// The full uint64 range: the converted values are right (the generated C
// compiles and the INTEGER_t <-> uint64 conversion is what the cases above
// exercise), but the C runtime's PER codec stores constraint bounds in a long
// and cannot encode a present value of INTEGER (0..2^64-1) -- the C
// converter fails on exactly the same values. Go must fail where the converter
// fails, with an error and not a crash or a wrong encoding.
func TestU64RangeMatchesC(t *testing.T) {
	bin := converter(t)
	cFails := func(pdu, xer string) bool {
		f := filepath.Join(t.TempDir(), "in")
		if err := os.WriteFile(f, []byte(xer), 0o600); err != nil {
			t.Fatal(err)
		}
		return exec.Command(bin, "-p", pdu, "-ixer", "-oaper", f).Run() != nil
	}
	for _, v := range []uint64{0, 5, 1 << 63, math.MaxUint64} {
		b := utoa(v)
		_, err := (&ew.U64Mem{A: v}).Encode()
		if (err != nil) != cFails("U64Mem", "<U64Mem><a>"+b+"</a></U64Mem>") {
			t.Errorf("U64Mem %s: Go err=%v, C failure=%v", b, err, cFails("U64Mem", "<U64Mem><a>"+b+"</a></U64Mem>"))
		}
		vv := v
		_, err = (&ew.U64Opt{A: true, B: &vv}).Encode()
		x := "<U64Opt><a><true/></a><b>" + b + "</b></U64Opt>"
		if (err != nil) != cFails("U64Opt", x) {
			t.Errorf("U64Opt b=%s: Go err=%v, C failure=%v", b, err, cFails("U64Opt", x))
		}
		_, err = (&ew.U64Alt{Present: ew.U64AltPrA, A: &vv}).Encode()
		x = "<U64Alt><a>" + b + "</a></U64Alt>"
		if (err != nil) != cFails("U64Alt", x) {
			t.Errorf("U64Alt a=%s: Go err=%v, C failure=%v", b, err, cFails("U64Alt", x))
		}
	}
}
