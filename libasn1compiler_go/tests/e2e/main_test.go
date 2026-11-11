// End-to-end APER round-trip and error-path tests for the Go backend. It is
// copied into the generated module by tests/run-e2e.sh; it is not part of any
// module in the source tree.
//
// Error codes with a negative test below (TestErr*): ErrArg, ErrAlloc is
// covered by faults_test.go (build tag asn1cgo_faults), ErrConstraint,
// ErrDecode, ErrTrailing, ErrChoiceNothing, ErrChoiceBad, ErrDepth,
// ErrIOCMismatch, ErrIOCUnknown.
//
// Codes NOT reachable from caller input, hence not tested here:
//   - ErrAlloc outside fault injection: only a real malloc failure produces
//     it; the faults_test.go sweep injects it deterministically.
//   - ErrEncode: raised only when the C encoder fails after the Go side has
//     already validated and filled a well-formed flat tree (constraints and
//     CHOICE/IOC checks fire first, as ErrConstraint/ErrChoice*/ErrIOC*), so
//     no public input reaches it.
//   - ErrInternal: an "internal invariant violated" guard (e.g. the arena
//     exact-fit accounting); reaching it would be a generator/runtime bug.
//   - ErrIOCUnknown on DECODE: an unknown id surfaces as ErrDecode from the
//     C decoder. (On encode it is tested in TestErrIOCMismatch.)
package e2e

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"testing"

	rt "asn1cgo.test/asn1cgo-rt/rt"
	deep "asn1cgo.test/go/deep"
	ex "asn1cgo.test/go/synth_example"
)

func ptr[T any](v T) *T { return &v }

func TestEncodeKnownBytes(t *testing.T) {
	in := ex.ExamplePDU{
		RequestId: 7,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(42))},
		Note:      ptr("hi"),
	}
	got, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{0x40, 0x00, 0x07, 0x40, 0x2a, 0x08, 0x68, 0x69}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = % x, want % x", got, want)
	}
	out, err := ex.DecodeExamplePDU(got)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.RequestId != 7 || out.Payload.Present != ex.ExamplePayloadPrNumber ||
		out.Payload.Number == nil || *out.Payload.Number != 42 ||
		out.Note == nil || *out.Note != "hi" {
		t.Fatalf("decoded %+v does not match input", out)
	}
}

func TestTextRoundTrip(t *testing.T) {
	in := ex.ExamplePDU{
		RequestId: 65535,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrText, Text: ptr("hello")},
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := ex.DecodeExamplePDU(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.RequestId != 65535 || out.Payload.Present != ex.ExamplePayloadPrText ||
		out.Payload.Text == nil || *out.Payload.Text != "hello" {
		t.Fatalf("decoded %+v does not match input", out)
	}
}

func TestAbsentOptional(t *testing.T) {
	in := ex.ExamplePDU{
		RequestId: 1,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(0))},
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := ex.DecodeExamplePDU(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Note != nil {
		t.Fatalf("Note = %q, want nil", *out.Note)
	}
}

func TestConstraintViolation(t *testing.T) {
	in := ex.ExamplePDU{
		RequestId: 1,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(999))},
	}
	if _, err := in.Encode(); !errors.Is(err, rt.ErrConstraint) {
		t.Fatalf("Encode(999) err = %v, want rt.ErrConstraint", err)
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := ex.DecodeExamplePDU([]byte{0xff}); !errors.Is(err, rt.ErrDecode) {
		t.Fatalf("Decode(ff) err = %v, want rt.ErrDecode", err)
	}
}

// TestConcurrentDecode decodes from many goroutines at once and checks the
// process-global arena balance returns to exactly zero once all are done.
func TestConcurrentDecode(t *testing.T) {
	in := ex.ExamplePDU{
		RequestId: 9,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrText, Text: ptr("concurrent")},
		Note:      ptr("n"),
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const workers, iters = 16, 200
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				out, err := ex.DecodeExamplePDU(b)
				if err != nil {
					errs <- err
					return
				}
				if out.RequestId != 9 || out.Payload.Text == nil || *out.Payload.Text != "concurrent" {
					errs <- errors.New("decoded value mismatch")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Fatalf("ArenaBalance = %d after concurrent decode, want 0", bal)
	}
}

// A BOOLEAN used through a named type (Flag ::= BOOLEAN) must survive
// Encode -> Decode for both values, as a plain member, an OPTIONAL member
// (nil stays nil), a SEQUENCE OF element and a CHOICE alternative.
func TestNamedBoolean(t *testing.T) {
	for _, v := range []bool{true, false} {
		in := ex.FlagPDU{
			Enabled: ex.Flag(v),
			Flags:   ex.FlagPDUFlags{true, false, ex.Flag(v)},
			Sel:     ex.FlagChoice{Present: ex.FlagChoicePrFlag, Flag: ptr(ex.Flag(v))},
		}
		for _, withMaybe := range []bool{true, false} {
			in.Maybe = nil
			if withMaybe {
				in.Maybe = ptr(ex.Flag(!v))
			}
			b, err := in.Encode()
			if err != nil {
				t.Fatalf("Encode(%v,%v): %v", v, withMaybe, err)
			}
			out, err := ex.DecodeFlagPDU(b)
			if err != nil {
				t.Fatalf("Decode(%v,%v): %v", v, withMaybe, err)
			}
			if bool(out.Enabled) != v {
				t.Fatalf("Enabled = %v, want %v", out.Enabled, v)
			}
			if withMaybe != (out.Maybe != nil) || (withMaybe && bool(*out.Maybe) == v) {
				t.Fatalf("Maybe = %v (withMaybe=%v, v=%v)", out.Maybe, withMaybe, v)
			}
			if len(out.Flags) != 3 || !bool(out.Flags[0]) || bool(out.Flags[1]) || bool(out.Flags[2]) != v {
				t.Fatalf("Flags = %v", out.Flags)
			}
			if out.Sel.Present != ex.FlagChoicePrFlag || out.Sel.Flag == nil || bool(*out.Sel.Flag) != v {
				t.Fatalf("Sel = %+v", out.Sel)
			}
		}
	}
	b, err := (&ex.FlagPDU{Sel: ex.FlagChoice{Present: ex.FlagChoicePrNum, Num: ptr(int64(5))}}).Encode()
	if err != nil {
		t.Fatalf("Encode num: %v", err)
	}
	out, err := ex.DecodeFlagPDU(b)
	if err != nil || out.Sel.Present != ex.FlagChoicePrNum || out.Sel.Num == nil || *out.Sel.Num != 5 {
		t.Fatalf("Decode num: %+v, %v", out, err)
	}
}

// ---- negative tests: one per reachable error code ----

// wantErr asserts errors.Is(err, want) and that no arena leaked.
func wantErr(t *testing.T, what string, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
	}
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("%s: ArenaBalance = %d, want 0", what, bal)
	}
}

func goodExPDU() *ex.ExamplePDU {
	return &ex.ExamplePDU{
		RequestId: 7,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(42))},
		Note:      ptr("hi"),
	}
}

func goodExWire(t *testing.T) []byte {
	t.Helper()
	b, err := goodExPDU().Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func TestErrTrailing(t *testing.T) {
	b := append(goodExWire(t), 0, 0)
	_, err := ex.DecodeExamplePDU(b)
	wantErr(t, "good wire + 2 zero bytes", err, rt.ErrTrailing)
}

func TestErrDecodeTruncated(t *testing.T) {
	b := goodExWire(t)
	_, err := ex.DecodeExamplePDU(b[:3])
	wantErr(t, "wire[:3]", err, rt.ErrDecode)
}

func TestErrArg(t *testing.T) {
	// Current behaviour: empty input is ErrArg, not ErrDecode.
	_, err := ex.DecodeExamplePDU(nil)
	wantErr(t, "Decode(nil)", err, rt.ErrArg)
	_, err = ex.DecodeExamplePDU([]byte{})
	wantErr(t, "Decode([]byte{})", err, rt.ErrArg)
	var p *ex.ExamplePDU
	_, err = p.Encode()
	wantErr(t, "Encode(nil *PDU)", err, rt.ErrArg)
}

func TestErrChoiceNothing(t *testing.T) {
	in := goodExPDU()
	in.Payload = ex.ExamplePayload{Present: 0}
	_, err := in.Encode()
	wantErr(t, "Present=0", err, rt.ErrChoiceNothing)
}

func TestErrChoiceBad(t *testing.T) {
	in := goodExPDU()
	in.Payload = ex.ExamplePayload{Present: 99}
	_, err := in.Encode()
	wantErr(t, "Present=99", err, rt.ErrChoiceBad)

	in = goodExPDU()
	in.Payload = ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: nil}
	_, err = in.Encode()
	wantErr(t, "Present=Number, Number=nil", err, rt.ErrChoiceBad)
}

func TestErrConstraintMembers(t *testing.T) {
	in := goodExPDU()
	in.Note = ptr("") // SIZE(1..32)
	_, err := in.Encode()
	wantErr(t, `Note=""`, err, rt.ErrConstraint)

	in = goodExPDU()
	in.RequestId = -1 // (0..65535)
	_, err = in.Encode()
	wantErr(t, "RequestId=-1", err, rt.ErrConstraint)
}

// chain builds a Tree whose Node chain has n levels.
func chain(n int) *deep.Tree {
	var next *deep.Node
	for i := 0; i < n-1; i++ {
		next = &deep.Node{Val: 1, Next: next}
	}
	return &deep.Tree{Root: deep.Node{Val: 0, Next: next}}
}

// depthWire is the APER wire of an n-level Node chain: each non-last level
// is 0x80 0x01, the last level is 0x00 0x01.
func depthWire(n int) []byte {
	var w []byte
	for i := 0; i < n-1; i++ {
		w = append(w, 0x80, 0x01)
	}
	return append(w, 0x00, 0x01)
}

func TestErrDepth(t *testing.T) {
	_, err := chain(100).Encode()
	wantErr(t, "Encode 100 levels", err, rt.ErrDepth)
	_, err = deep.DecodeTree(depthWire(100))
	wantErr(t, "Decode 100 levels", err, rt.ErrDepth)

	// 64 levels is still fine in both directions.
	b, err := chain(64).Encode()
	if err != nil {
		t.Fatalf("Encode 64 levels: %v", err)
	}
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("ArenaBalance = %d, want 0", bal)
	}
	if _, err := deep.DecodeTree(b); err != nil {
		t.Fatalf("Decode 64 levels: %v", err)
	}
	if _, err := deep.DecodeTree(depthWire(64)); err != nil {
		t.Fatalf("Decode 64-level literal wire: %v", err)
	}
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("ArenaBalance = %d, want 0", bal)
	}
}

func TestErrIOCMismatch(t *testing.T) {
	// id=1 (IntVal row) carrying the BoolVal alternative.
	f := deep.NewFieldIdA(5)
	f.Value = deep.FieldValue{Present: deep.FieldValuePrBoolVal, BoolVal: ptr(deep.BoolVal(1))}
	_, err := (&deep.IOCMsg{Ies: deep.IOCMsgIes{f}}).Encode()
	wantErr(t, "id=A with BoolVal value", err, rt.ErrIOCMismatch)

	// An id that is in no row of the set at all: ErrIOCUnknown (checked
	// before the id-vs-alternative comparison), not ErrIOCMismatch.
	f = deep.NewFieldIdA(5)
	f.Id = 99
	_, err = (&deep.IOCMsg{Ies: deep.IOCMsgIes{f}}).Encode()
	wantErr(t, "id=99", err, rt.ErrIOCUnknown)
	if errors.Is(err, rt.ErrIOCMismatch) {
		t.Errorf("id=99 must not also match ErrIOCMismatch: %v", err)
	}
}

func TestIOCGoodAndUnknownIDDecode(t *testing.T) {
	good := []byte{0x08, 0x00, 0x01, 0x00, 0x01, 0x05}
	b, err := (&deep.IOCMsg{Ies: deep.IOCMsgIes{deep.NewFieldIdA(5)}}).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(b, good) {
		t.Fatalf("encoding = % x, want % x", b, good)
	}
	out, err := deep.DecodeIOCMsg(good)
	if err != nil || len(out.Ies) != 1 || out.Ies[0].Id != deep.ProtocolIEIDIdA ||
		out.Ies[0].Value.IntVal == nil || *out.Ies[0].Value.IntVal != 5 {
		t.Fatalf("Decode good: %+v, %v", out, err)
	}
	// Unknown IE id (0x01 -> 0x63). Current behaviour: ErrDecode.
	bad := append([]byte(nil), good...)
	bad[2] = 0x63
	_, err = deep.DecodeIOCMsg(bad)
	wantErr(t, "unknown IE id 0x63", err, rt.ErrDecode)
}

// Regression: the APER encoder wrote the CHOICE extension index in the
// range-bits form instead of X.691 #10.6 (normally small non-negative whole
// number), so its own decoder rejected the output. Ext-Choice has two
// extension alternatives; the 2nd (extFlag, ext index 1) must encode as
// ext-bit 1, '0' + 6 bits (000001), then an open type.
func TestChoiceExtensionIndex(t *testing.T) {
	cases := []struct {
		name string
		in   ex.ExtChoice
		want []byte
	}{
		{"root", ex.ExtChoice{Present: ex.ExtChoicePrBase, Base: ptr(int64(5))}, []byte{0x50}},
		{"ext0", ex.ExtChoice{Present: ex.ExtChoicePrExtNum, ExtNum: ptr(int64(5))}, []byte{0x80, 0x01, 0x05}},
		{"ext1", ex.ExtChoice{Present: ex.ExtChoicePrExtFlag, ExtFlag: ptr(true)}, []byte{0x81, 0x01, 0x80}},
	}
	for _, c := range cases {
		got, err := c.in.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatalf("%s: encoding = % x, want % x", c.name, got, c.want)
		}
		out, err := ex.DecodeExtChoice(got)
		if err != nil {
			t.Fatalf("%s: Decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(*out, c.in) {
			t.Fatalf("%s: decoded %+v, want %+v", c.name, *out, c.in)
		}
	}
}
