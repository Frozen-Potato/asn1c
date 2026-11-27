package e2e

import (
	"bytes"
	"testing"

	ot "asn1cgo.test/go/otunknown2"

	"github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
)

// asn1c -fopen-type-unknown (tests/e2e/otunknown2.asn): the set has the
// alternatives Unknown and UnknownRaw, so its Unknown alternative is
// UnknownRaw2. Copied into the generated module by tests/run-e2e.sh
// (run_open_type_unknown).
func TestOpenTypeUnknownNameClash(t *testing.T) {
	in := []byte(`{"ies":[{"id":1,"value":7},{"id":2,"value":true},{"id":9,"value":"x"}]}`)
	m, err := ot.DecodeJERMsg(in)
	if err != nil {
		t.Fatal(err)
	}
	ies := m.Ies
	if len(ies) != 3 || ies[0].Value.Present != ot.MsgIEsValuePrUnknown ||
		*ies[0].Value.Unknown != 7 ||
		ies[1].Value.Present != ot.MsgIEsValuePrUnknownRaw || !*ies[1].Value.UnknownRaw {
		t.Fatalf("known alternatives: %+v", ies)
	}
	// id 9 is new: its value is kept as received in UnknownRaw2
	if ies[2].Id != 9 || ies[2].Value.Present != ot.MsgIEsValuePrUnknownRaw2 {
		t.Fatalf("ies[2] %+v", ies[2])
	}
	r := ies[2].Value.UnknownRaw2
	if r == nil || r.Codec != rt.CodecJER || len(r.Bytes) == 0 {
		t.Fatalf("unknown value %+v", r)
	}
	out, err := m.EncodeJER()
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("encoded back as %s (%v), received %s", out, err, in)
	}
}
