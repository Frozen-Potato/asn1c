package e2e

import (
	"bytes"
	"testing"

	ot "asn1cgo.test/go/otunknown"

	"github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go/rt"
)

// asn1c -fopen-type-unknown (tests/e2e/otunknown.asn): the values of ids and
// procedures that a newer version of the module added
// (otunknown_vectors_test.go) decode as the Unknown alternative of their
// open type, keep the octets and the codec they were received with, and
// encode again unchanged with that codec only. Copied into the generated
// module by tests/run-e2e.sh (run_open_type_unknown).

type otCodec struct {
	name   string
	codec  rt.Codec
	vec    func(otVector) []byte
	decMsg func([]byte) (*ot.Msg, error)
	encMsg func(*ot.Msg) ([]byte, error)
	decPDU func([]byte) (*ot.PDU, error)
	encPDU func(*ot.PDU) ([]byte, error)
}

func otCodecs() []otCodec {
	return []otCodec{
		{"APER", rt.CodecAPER, func(v otVector) []byte { return v.aper },
			ot.DecodeMsg, (*ot.Msg).Encode, ot.DecodePDU, (*ot.PDU).Encode},
		{"UPER", rt.CodecUPER, func(v otVector) []byte { return v.uper },
			ot.DecodeUPERMsg, (*ot.Msg).EncodeUPER, ot.DecodeUPERPDU, (*ot.PDU).EncodeUPER},
		{"JER", rt.CodecJER, func(v otVector) []byte { return v.jer },
			ot.DecodeJERMsg, (*ot.Msg).EncodeJER, ot.DecodeJERPDU, (*ot.PDU).EncodeJER},
	}
}

// otOthersFail: encoding the same value with every other codec must fail.
func otOthersFail(t *testing.T, c otCodec, enc func(otCodec) error) {
	t.Helper()
	for _, o := range otCodecs() {
		if o.name != c.name && enc(o) == nil {
			t.Errorf("a %s value encoded as %s", c.name, o.name)
		}
	}
}

func otRaw(t *testing.T, what string, c otCodec, r *rt.OpenTypeRaw) {
	t.Helper()
	if r == nil || r.Codec != c.codec || len(r.Bytes) == 0 {
		t.Fatalf("%s %s: unknown value %+v", c.name, what, r)
	}
}

func TestOpenTypeUnknownMsg(t *testing.T) {
	for _, c := range otCodecs() {
		in := c.vec(otVectors["msg"])
		m, err := c.decMsg(in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		ies := m.Ies
		if len(ies) != 3 || ies[0].Value.Present != ot.MsgIEsValuePrINTEGER0255 ||
			*ies[0].Value.INTEGER0255 != 10 {
			t.Fatalf("%s: ies %+v", c.name, ies)
		}
		// id 6 is new: its value is kept as received
		if ies[1].Id != 6 || ies[1].Criticality != ot.CriticalityNotify ||
			ies[1].Value.Present != ot.MsgIEsValuePrUnknownRaw {
			t.Fatalf("%s: ies[1] %+v", c.name, ies[1])
		}
		otRaw(t, "ies[1]", c, ies[1].Value.UnknownRaw)
		// id 4 is known; its type happens to be named Unknown
		if ies[2].Value.Present != ot.MsgIEsValuePrUnknown || string(*ies[2].Value.Unknown) != "ab" {
			t.Fatalf("%s: ies[2] %+v", c.name, ies[2])
		}
		// every id of the empty extensible set is new
		if m.Ext == nil || len(*m.Ext) != 2 {
			t.Fatalf("%s: ext %+v", c.name, m.Ext)
		}
		for i, e := range *m.Ext {
			if e.Id != 9 || e.Value.Present != ot.ExtIEsValuePrUnknown {
				t.Fatalf("%s: ext[%d] %+v", c.name, i, e)
			}
			otRaw(t, "ext", c, e.Value.Unknown)
		}
		out, err := c.encMsg(m)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("%s: encoded back as %x (%v), received %x", c.name, out, err, in)
		}
		otOthersFail(t, c, func(o otCodec) error { _, err := o.encMsg(m); return err })

		// the same message built by hand from the kept values
		ext := ot.MsgExt{}
		for _, e := range *m.Ext {
			ext = append(ext, ot.ExtIEs{Id: 9, Criticality: ot.CriticalityIgnore,
				Value: ot.ExtIEsValue{Present: ot.ExtIEsValuePrUnknown,
					Unknown: &rt.OpenTypeRaw{Codec: c.codec, Bytes: append([]byte(nil), e.Value.Unknown.Bytes...)}}})
		}
		h := &ot.Msg{Ies: ot.MsgIes{ot.NewMsgIEsId1(10),
			{Id: 6, Criticality: ot.CriticalityNotify, Value: ot.MsgIEsValue{
				Present:    ot.MsgIEsValuePrUnknownRaw,
				UnknownRaw: &rt.OpenTypeRaw{Codec: c.codec, Bytes: ies[1].Value.UnknownRaw.Bytes}}},
			ot.NewMsgIEsId4(ot.Unknown("ab"))}, Ext: &ext}
		if out, err := c.encMsg(h); err != nil || !bytes.Equal(out, in) {
			t.Fatalf("%s: built by hand: %x (%v)", c.name, out, err)
		}
	}
}

func TestOpenTypeUnknownClosedSet(t *testing.T) {
	for _, c := range otCodecs() {
		if m, err := c.decMsg(c.vec(otVectors["closed"])); err == nil {
			t.Fatalf("%s: an id the closed set does not have decoded: %+v", c.name, m)
		}
	}
}

func TestOpenTypeUnknownPDU(t *testing.T) {
	for _, c := range otCodecs() {
		for _, name := range []string{"initiating", "successful"} {
			in := c.vec(otVectors[name])
			p, err := c.decPDU(in)
			if err != nil {
				t.Fatalf("%s %s: %v", c.name, name, err)
			}
			switch {
			case p.InitiatingMessage != nil:
				im := p.InitiatingMessage
				if im.ProcedureCode != 9 || im.Criticality != ot.CriticalityIgnore ||
					im.Value.Present != ot.InitiatingMessageValuePrUnknown {
					t.Fatalf("%s: %+v", c.name, im)
				}
				otRaw(t, name, c, im.Value.Unknown)
			case p.SuccessfulOutcome != nil:
				so := p.SuccessfulOutcome
				if so.ProcedureCode != 9 || so.Value.Present != ot.SuccessfulOutcomeValuePrUnknown {
					t.Fatalf("%s: %+v", c.name, so)
				}
				otRaw(t, name, c, so.Value.Unknown)
			default:
				t.Fatalf("%s %s: %+v", c.name, name, p)
			}
			out, err := c.encPDU(p)
			if err != nil || !bytes.Equal(out, in) {
				t.Fatalf("%s %s: encoded back as %x (%v)", c.name, name, out, err)
			}
			otOthersFail(t, c, func(o otCodec) error { _, err := o.encPDU(p); return err })
		}
	}
}

func TestOpenTypeUnknownErrors(t *testing.T) {
	raw := &rt.OpenTypeRaw{Codec: rt.CodecAPER, Bytes: []byte{0x80}}
	for name, m := range map[string]*ot.Msg{
		// an id of the set sent as the unknown alternative
		"known id 1 as UnknownRaw": {Ies: ot.MsgIes{{Id: 1, Value: ot.MsgIEsValue{
			Present: ot.MsgIEsValuePrUnknownRaw, UnknownRaw: raw}}}},
		// an id the set does not have with one of its alternatives
		"id 7 as INTEGER": {Ies: ot.MsgIes{{Id: 7, Value: ot.MsgIEsValue{
			Present: ot.MsgIEsValuePrINTEGER0255, INTEGER0255: new(int64)}}}},
		"UnknownRaw nil": {Ies: ot.MsgIes{{Id: 7, Value: ot.MsgIEsValue{
			Present: ot.MsgIEsValuePrUnknownRaw}}}},
		"no codec": {Ies: ot.MsgIes{{Id: 7, Value: ot.MsgIEsValue{
			Present: ot.MsgIEsValuePrUnknownRaw, UnknownRaw: &rt.OpenTypeRaw{Bytes: []byte{0x80}}}}}},
		"no octets": {Ies: ot.MsgIes{{Id: 7, Value: ot.MsgIEsValue{
			Present: ot.MsgIEsValuePrUnknownRaw, UnknownRaw: &rt.OpenTypeRaw{Codec: rt.CodecAPER}}}}},
	} {
		if _, err := m.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if n := rt.ArenaBalance(); n != 0 {
		t.Fatalf("arena balance %d", n)
	}
	if rt.CodecAPER.String() != "APER" || rt.Codec(42).String() != "Codec(42)" {
		t.Fatalf("Codec.String")
	}
}
