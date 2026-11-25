//go:build asn1cgo_faults

// Allocation-fault sweep of EncodeJER / DecodeJER<T> (see faults_test.go).
// Copied into the generated module by tests/run-e2e.sh for its -gen-JER run.
package e2e

import (
	"testing"

	ex "asn1cgo.test/go/synth_example"
)

func TestAllocFaultSweepJER(t *testing.T) {
	in := &ex.ExamplePDU{
		RequestId: 7,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(42))},
		Note:      ptr("hi"),
	}
	j, err := in.EncodeJER()
	if err != nil {
		t.Fatalf("EncodeJER: %v", err)
	}
	sweep(t, "EncodeJER", func() error { _, err := in.EncodeJER(); return err })
	sweep(t, "DecodeJER", func() error { _, err := ex.DecodeJERExamplePDU(j); return err })
}
