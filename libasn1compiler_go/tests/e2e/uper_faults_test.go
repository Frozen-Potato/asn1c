//go:build asn1cgo_faults

// Allocation-fault sweep of EncodeUPER / DecodeUPER<T> (see faults_test.go).
// Copied into the generated module by tests/run-e2e.sh.
package e2e

import (
	"testing"

	deep "asn1cgo.test/go/deep"
	ex "asn1cgo.test/go/synth_example"
)

func TestAllocFaultSweepUPER(t *testing.T) {
	in := &ex.ExamplePDU{
		RequestId: 7,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(42))},
		Note:      ptr("hi"),
	}
	u, err := in.EncodeUPER()
	if err != nil {
		t.Fatalf("EncodeUPER: %v", err)
	}
	sweep(t, "EncodeUPER", func() error { _, err := in.EncodeUPER(); return err })
	sweep(t, "DecodeUPER", func() error { _, err := ex.DecodeUPERExamplePDU(u); return err })

	ioc := &deep.IOCMsg{Ies: deep.IOCMsgIes{deep.NewFieldIdA(5), deep.NewFieldIdB(1)}}
	w, err := ioc.EncodeUPER()
	if err != nil {
		t.Fatalf("IOC EncodeUPER: %v", err)
	}
	sweep(t, "IOC EncodeUPER", func() error { _, err := ioc.EncodeUPER(); return err })
	sweep(t, "IOC DecodeUPER", func() error { _, err := deep.DecodeUPERIOCMsg(w); return err })
}
