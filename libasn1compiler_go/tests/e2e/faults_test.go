//go:build asn1cgo_faults

// Allocation-fault sweep. Built only with -tags asn1cgo_faults (which also
// compiles the injection hooks into the runtime's C arena). Copied into the
// generated module by tests/run-e2e.sh.
package e2e

import (
	"errors"
	"testing"

	rt "github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
	deep "asn1cgo.test/go/deep"
	bitsa "asn1cgo.test/go/bitsa"
	df "asn1cgo.test/go/defaults"
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

// DEFAULT members: the pointer-form tree slots are allocated by the
// conversion code on encode; every injected failure must report ErrAlloc and
// leave nothing alive (also the C-side fill of absent defaults on decode).
func TestAllocFaultSweepDefaults(t *testing.T) {
	in := dflt()
	in.Flag = false
	in.Name = "42"
	in.Octs = []byte{1, 2}
	sweep(t, "Defaults Encode", func() error { _, err := in.Encode(); return err })
	for _, wire := range [][]byte{{0x00, 0x00}, mustEncode(t, in)} {
		w := wire
		sweep(t, "Defaults Decode", func() error { _, err := df.DecodeDefaultsPDU(w); return err })
	}
	ext := extDflt()
	ext.ExtNon = 1
	sweep(t, "ExtDefaults Encode", func() error { _, err := ext.Encode(); return err })
	sweep(t, "ExtDefaults Decode", func() error { _, err := df.DecodeExtDefaults([]byte{0x00}); return err })
}

// A present OPTIONAL BIT STRING (a pointer record in the fixed region) and an
// OPTIONAL reference to a BIT STRING type, encode and decode.
func TestAllocFaultSweepBitString(t *testing.T) {
	tnl := &bitsa.TnlInfo{TnlAddress: bitsa.BitString{Bytes: []byte{1, 2, 3, 4}}, TnlPort: &bitsa.BitString{Bytes: []byte{0x1F, 0x90}}}
	sweep(t, "TnlInfo Encode", func() error { _, err := tnl.Encode(); return err })
	w, err := tnl.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sweep(t, "TnlInfo Decode", func() error { _, err := bitsa.DecodeTnlInfo(w); return err })
	ref := &bitsa.RefHolder{Ref: &bitsa.RangedBits{Bytes: []byte{0xA0}, BitsUnused: 1}, Flag: true}
	sweep(t, "RefHolder Encode", func() error { _, err := ref.Encode(); return err })
}

func mustEncode(t *testing.T, p *df.DefaultsPDU) []byte {
	t.Helper()
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SEQUENCE OF with inline element types: every case of seqofinline_test.go
// (primitive and constructed elements; top level, member, OPTIONAL member and
// CHOICE alternative), encode and decode.
func TestAllocFaultSweepSeqofInline(t *testing.T) {
	for _, c := range siCases() {
		c := c
		wire, err := c.enc()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		sweep(t, c.name+" Encode", func() error { _, err := c.enc(); return err })
		sweep(t, c.name+" Decode", func() error { return c.dec(wire) })
	}
}

// Inline SEQUENCE / CHOICE members and CHOICE alternatives: every case of
// inlconstr_test.go (required and OPTIONAL, nested, in SEQUENCE OF elements),
// encode and decode.
func TestAllocFaultSweepInlConstr(t *testing.T) {
	for _, c := range icCases() {
		c := c
		wire, err := c.enc()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		sweep(t, c.name+" Encode", func() error { _, err := c.enc(); return err })
		sweep(t, c.name+" Decode", func() error { return c.dec(wire) })
	}
}

// Mandatory extension additions, INTEGER members wider than int64 and the
// `present` alternative: every case of extwide_test.go, encode and decode.
func TestAllocFaultSweepExtWide(t *testing.T) {
	for _, c := range ewCases() {
		c := c
		wire, err := c.enc()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		sweep(t, c.name+" Encode", func() error { _, err := c.enc(); return err })
		sweep(t, c.name+" Decode", func() error { return c.dec(wire) })
	}
}

// Restricted character string and time types: every case of strings_test.go
// (top level, member, OPTIONAL, SEQUENCE OF element, CHOICE alternative,
// reference, extension addition), encode and decode.
func TestAllocFaultSweepStrings(t *testing.T) {
	for _, c := range stCases() {
		c := c
		wire, err := c.enc()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		sweep(t, c.name+" Encode", func() error { _, err := c.enc(); return err })
		sweep(t, c.name+" Decode", func() error { return c.dec(wire) })
	}
}

// OBJECT IDENTIFIER and RELATIVE-OID: every case of oids_test.go (top level,
// member, OPTIONAL, SEQUENCE OF element, CHOICE alternative, reference,
// extension addition, long arc lists), encode and decode.
func TestAllocFaultSweepOids(t *testing.T) {
	for _, c := range otCases() {
		c := c
		wire, err := c.enc()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		sweep(t, c.name+" Encode", func() error { _, err := c.enc(); return err })
		sweep(t, c.name+" Decode", func() error { return c.dec(wire) })
	}
}
