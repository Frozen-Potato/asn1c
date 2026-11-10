//go:build asn1cgo_faults

// Allocation-fault sweep. Built only with -tags asn1cgo_faults (which also
// compiles the injection hooks into the runtime's C arena). Copied into the
// generated module by tests/run-e2e.sh.
package e2e

import (
	"errors"
	"testing"

	rt "asn1cgo.test/asn1cgo-rt/rt"
	ex "asn1cgo.test/go/synth_example"
)

// sweep runs op once un-injected to count the runtime allocation events N,
// then once per n = 1..N with the n-th event failing, and requires every
// injected run to return rt.ErrAlloc with no arena left alive.
func sweep(t *testing.T, name string, op func() error) {
	t.Helper()
	defer rt.ArenaFailAt(0)
	rt.ArenaFailAt(0)
	if err := op(); err != nil {
		t.Fatalf("%s: un-injected run failed: %v", name, err)
	}
	n := rt.ArenaEvents()
	t.Logf("%s: %d injectable allocation event(s)", name, n)
	if n == 0 {
		t.Logf("NOTE: %s has no injectable allocations (no rt allocation events), so nothing was swept", name)
	}
	for i := int64(1); i <= int64(n); i++ {
		rt.ArenaFailAt(i)
		err := op()
		if !errors.Is(err, rt.ErrAlloc) {
			t.Errorf("%s: fail at %d: err = %v, want rt.ErrAlloc", name, i, err)
		}
		if bal := rt.ArenaBalance(); bal != 0 {
			t.Errorf("%s: fail at %d: ArenaBalance = %d, want 0", name, i, bal)
		}
	}
	rt.ArenaFailAt(0)
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("%s: ArenaBalance = %d after sweep, want 0", name, bal)
	}
}

func TestAllocFaultSweep(t *testing.T) {
	in := &ex.ExamplePDU{
		RequestId: 7,
		Payload:   ex.ExamplePayload{Present: ex.ExamplePayloadPrNumber, Number: ptr(int64(42))},
		Note:      ptr("hi"),
	}
	wire, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	sweep(t, "Encode", func() error { _, err := in.Encode(); return err })
	sweep(t, "Decode", func() error { _, err := ex.DecodeExamplePDU(wire); return err })
}
