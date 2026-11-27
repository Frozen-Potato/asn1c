//go:build amd64 || arm64

package rt

import "strconv"

// Codec names the encoding rules an OpenTypeRaw value was decoded with.
// The numbering is the C runtime's OPEN_TYPE_raw_codec_e (OPEN_TYPE_raw.h).
type Codec int64

const (
	CodecNone Codec = 0 // not set: encoding fails
	CodecBER  Codec = 1 // BER / DER: one complete TLV
	CodecOER  Codec = 2 // OER: the open type contents
	CodecUPER Codec = 3 // unaligned PER: the open type contents
	CodecAPER Codec = 4 // aligned PER: the open type contents
	CodecJER  Codec = 5 // JER: the JSON text of the value
)

// String returns the codec's name ("APER", ...), or "Codec(<n>)".
func (c Codec) String() string {
	switch c {
	case CodecNone:
		return "None"
	case CodecBER:
		return "BER"
	case CodecOER:
		return "OER"
	case CodecUPER:
		return "UPER"
	case CodecAPER:
		return "APER"
	case CodecJER:
		return "JER"
	}
	return "Codec(" + strconv.FormatInt(int64(c), 10) + ")"
}

// OpenTypeRaw is the value of an open type whose id is not in the
// extensible object set that governs it (packages generated with
// asn1c -fopen-type-unknown: the <T>Unknown alternative, X.681 14.10).
//
// Bytes is the encoding as it was received: the open type contents for
// APER, UPER and OER, the complete TLV for BER, the JSON text for JER. It
// can be encoded again only with the codec that decoded it (Codec); any
// other codec returns an error. To send a value of an id the module does
// not know, set Codec and Bytes to its encoding in the codec you will use.
type OpenTypeRaw struct {
	Codec Codec
	Bytes []byte
}
