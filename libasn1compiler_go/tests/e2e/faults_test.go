//go:build asn1cgo_faults

// Allocation-fault sweep. Built only with -tags asn1cgo_faults (which also
// compiles the injection hooks into the runtime's C arena). Copied into the
// generated module by tests/run-e2e.sh.
package e2e

import (
	"errors"
	"testing"

	rt "asn1cgo.test/asn1cgo-rt/rt"
	deep "asn1cgo.test/go/deep"
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
		t.Errorf("%s: no injectable allocation events; the sweep would be vacuous", name)
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
	// Event 1 of Encode is the backing-block allocation (asn1cgo_block_alloc):
	// it must surface as ErrAlloc before any further cgo call, with nothing leaked.
	rt.ArenaFailAt(1)
	_, err = in.Encode()
	rt.ArenaFailAt(0)
	if !errors.Is(err, rt.ErrAlloc) {
		t.Errorf("Encode block alloc fail: err = %v, want rt.ErrAlloc", err)
	}
	if bal := rt.ArenaBalance(); bal != 0 {
		t.Errorf("Encode block alloc fail: ArenaBalance = %d, want 0", bal)
	}
	sweep(t, "Decode", func() error { _, err := ex.DecodeExamplePDU(wire); return err })
}

// The IOC spec exercises the SEQUENCE OF / IE-union conversion allocations.
func TestAllocFaultSweepIOC(t *testing.T) {
	in := &deep.IOCMsg{Ies: deep.IOCMsgIes{deep.NewFieldIdA(5), deep.NewFieldIdA(6)}}
	wire, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	sweep(t, "IOC Encode", func() error { _, err := in.Encode(); return err })
	sweep(t, "IOC Decode", func() error { _, err := deep.DecodeIOCMsg(wire); return err })
}
