package e2e

import "encoding/hex"

// The encodings of messages of the newer module version
// (tests/e2e/otunknown-peer.asn) that otunknown.asn does not fully know:
// otunknown_peer_test.go checks the peer still encodes them so, and
// otunknown_test.go decodes them with -fopen-type-unknown.
type otVector struct{ aper, uper, jer []byte }

func otHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var otVectors = map[string]otVector{
	// ies: id 1, id 6 (new), id 4; ext: id 9 (new) twice
	"msg": {
		otHex("48000100010a0006800180000400030261622000094001700009400100"),
		otHex("480004010a0006806000010030261622001280b80004a02000"),
		[]byte(`{"ies":[{"id":1,"criticality":"reject","value":10},` +
			`{"id":6,"criticality":"notify","value":true},` +
			`{"id":4,"criticality":"reject","value":"6162"}],` +
			`"ext":[{"id":9,"criticality":"ignore","value":7},` +
			`{"id":9,"criticality":"ignore","value":0}]}`),
	},
	// closed: id 3, which the closed set of otunknown.asn does not have
	"closed": {
		otHex("200001000101000003000105"),
		otHex("20000401010000600828"),
		[]byte(`{"ies":[{"id":1,"criticality":"reject","value":1}],` +
			`"closed":[{"id":3,"criticality":"reject","value":5}]}`),
	},
	// procedure 9 (new)
	"initiating": {
		otHex("00094003026869"),
		otHex("025030268690"),
		[]byte(`{"initiatingMessage":{"procedureCode":9,"criticality":"ignore","value":{"z":"6869"}}}`),
	},
	"successful": {
		otHex("4009400180"),
		otHex("42501800"),
		[]byte(`{"successfulOutcome":{"procedureCode":9,"criticality":"ignore","value":{"y":true}}}`),
	},
}
