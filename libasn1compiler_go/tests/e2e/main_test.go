// End-to-end APER round-trip test for the Go backend. It is copied into the
// generated module by tests/run-e2e.sh; it is not part of any module in the
// source tree.
package e2e

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	rt "asn1cgo.test/asn1cgo-rt/rt"
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
