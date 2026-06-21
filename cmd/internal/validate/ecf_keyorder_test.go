package validate

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

func TestVerifyCanonicalKeyOrder_AcceptsCanonical(t *testing.T) {
	// Round-trip a representative entity-shaped value through the ECF
	// encoder; its output is canonical by construction, so the verifier
	// must accept it.
	type inner struct {
		A int    `cbor:"a"`
		B string `cbor:"b"`
	}
	type outer struct {
		Name   string         `cbor:"name"`
		Count  int            `cbor:"count"`
		Nested inner          `cbor:"nested"`
		List   []int          `cbor:"list"`
		Bytes  []byte         `cbor:"bytes"`
		Tags   map[string]int `cbor:"tags"`
	}
	v := outer{
		Name:   "peer",
		Count:  42,
		Nested: inner{A: 1, B: "x"},
		List:   []int{3, 2, 1},
		Bytes:  []byte{0xde, 0xad},
		Tags:   map[string]int{"z": 1, "a": 2, "m": 3},
	}
	enc, err := ecf.Encode(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := verifyCanonicalKeyOrder(enc); err != nil {
		t.Fatalf("verifier rejected canonical ECF output: %v", err)
	}
}

func TestVerifyCanonicalKeyOrder_RejectsOutOfOrder(t *testing.T) {
	// {"b": 1, "a": 2} encoded by hand with keys in the WRONG order.
	// a2 = map(2); 61 62 = "b"; 01; 61 61 = "a"; 02.
	bad := []byte{0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02}
	if err := verifyCanonicalKeyOrder(bad); err == nil {
		t.Fatalf("verifier accepted out-of-order map keys")
	}
}

func TestVerifyCanonicalKeyOrder_RejectsDuplicateKey(t *testing.T) {
	// {"a": 1, "a": 2} — duplicate key, non-canonical.
	dup := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}
	if err := verifyCanonicalKeyOrder(dup); err == nil {
		t.Fatalf("verifier accepted duplicate map key")
	}
}

func TestVerifyCanonicalKeyOrder_RejectsIndefinite(t *testing.T) {
	// 0xbf = indefinite-length map start — forbidden by ECF.
	indef := []byte{0xbf, 0x61, 0x61, 0x01, 0xff}
	if err := verifyCanonicalKeyOrder(indef); err == nil {
		t.Fatalf("verifier accepted indefinite-length map")
	}
}

func TestVerifyCanonicalKeyOrder_RejectsTrailingBytes(t *testing.T) {
	// Single uint 0x01 followed by a stray byte.
	if err := verifyCanonicalKeyOrder([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("verifier accepted trailing bytes")
	}
}
