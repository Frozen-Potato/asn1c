package e2e

import (
	"bytes"
	"testing"

	ot "asn1cgo.test/go/otunknown"
)

// The test vectors of otunknown_test.go, encoded by the newer version of
// the module (tests/e2e/otunknown-peer.asn, compiled without
// -fopen-type-unknown): copied into that generated module by
// tests/run-e2e.sh together with otunknown_vectors_test.go.
func otPeerMsgs() map[string]func() ([]byte, []byte, []byte, error) {
	msgEnc := func(m *ot.Msg) func() ([]byte, []byte, []byte, error) {
		return func() ([]byte, []byte, []byte, error) {
			a, err := m.Encode()
			if err != nil {
				return nil, nil, nil, err
			}
			u, err := m.EncodeUPER()
			if err != nil {
				return nil, nil, nil, err
			}
			j, err := m.EncodeJER()
			return a, u, j, err
		}
	}
	pduEnc := func(p *ot.PDU) func() ([]byte, []byte, []byte, error) {
		return func() ([]byte, []byte, []byte, error) {
			a, err := p.Encode()
			if err != nil {
				return nil, nil, nil, err
			}
			u, err := p.EncodeUPER()
			if err != nil {
				return nil, nil, nil, err
			}
			j, err := p.EncodeJER()
			return a, u, j, err
		}
	}
	ext := ot.MsgExt{ot.NewExtIEsId9(7), ot.NewExtIEsId9(0)}
	closed := ot.MsgClosed{ot.NewClosedId3(5)}
	return map[string]func() ([]byte, []byte, []byte, error){
		"msg": msgEnc(&ot.Msg{
			Ies: ot.MsgIes{ot.NewMsgIEsId1(10), ot.NewMsgIEsId6(true),
				ot.NewMsgIEsId4(ot.Unknown("ab"))},
			Ext: &ext,
		}),
		"closed": msgEnc(&ot.Msg{Ies: ot.MsgIes{ot.NewMsgIEsId1(1)}, Closed: &closed}),
		"initiating": pduEnc(&ot.PDU{Present: ot.PDUPrInitiatingMessage,
			InitiatingMessage: &ot.InitiatingMessage{ProcedureCode: 9,
				Criticality: ot.CriticalityIgnore,
				Value: ot.InitiatingMessageValue{Present: ot.InitiatingMessageValuePrReqB,
					ReqB: &ot.ReqB{Z: []byte("hi")}}}}),
		"successful": pduEnc(&ot.PDU{Present: ot.PDUPrSuccessfulOutcome,
			SuccessfulOutcome: &ot.SuccessfulOutcome{ProcedureCode: 9,
				Criticality: ot.CriticalityIgnore,
				Value: ot.SuccessfulOutcomeValue{Present: ot.SuccessfulOutcomeValuePrRespA,
					RespA: &ot.RespA{Y: true}}}}),
	}
}

func TestOpenTypeUnknownPeerVectors(t *testing.T) {
	for name, enc := range otPeerMsgs() {
		a, u, j, err := enc()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v, ok := otVectors[name]
		if !ok {
			t.Errorf("%s: no vector; APER %x UPER %x JER %s", name, a, u, j)
			continue
		}
		if !bytes.Equal(a, v.aper) || !bytes.Equal(u, v.uper) || !bytes.Equal(j, v.jer) {
			t.Errorf("%s: encodes as APER %x UPER %x JER %s", name, a, u, j)
		}
	}
}
