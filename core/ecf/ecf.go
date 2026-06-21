package ecf

import (
	"github.com/fxamacker/cbor/v2"
)

// EncMode is the package-level deterministic CBOR encoder configured per
// RFC 8949 §4.2 (Entity Canonical Form).
var EncMode cbor.EncMode

// DecMode is the package-level CBOR decoder.
var DecMode cbor.DecMode

func init() {
	var err error
	EncMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("ecf: failed to create deterministic enc mode: " + err.Error())
	}
	DecMode, err = cbor.DecOptions{}.DecMode()
	if err != nil {
		panic("ecf: failed to create dec mode: " + err.Error())
	}
}

// Encode serializes v to deterministic CBOR (ECF).
func Encode(v interface{}) ([]byte, error) {
	return EncMode.Marshal(v)
}

// Decode deserializes CBOR data into v.
func Decode(data []byte, v interface{}) error {
	return DecMode.Unmarshal(data, v)
}

// hashableMap is the two-key CBOR map {data, type} used for hash computation.
// Keys are sorted per ECF: "data" (4 chars) before "type" (4 chars) — same
// encoded length, "data" < "type" lexicographically.
type hashableMap struct {
	Data cbor.RawMessage `cbor:"data"`
	Type string          `cbor:"type"`
}

// EncodeHashable encodes the {data, type} map for content hash computation.
// The data field is embedded as raw CBOR bytes (not re-encoded).
func EncodeHashable(entityType string, data cbor.RawMessage) ([]byte, error) {
	return EncMode.Marshal(hashableMap{
		Data: data,
		Type: entityType,
	})
}
