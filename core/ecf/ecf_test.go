package ecf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncodeDeterministic(t *testing.T) {
	// Same input must always produce same output.
	input := map[string]int{"value": 42}
	b1, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("non-deterministic: %x != %x", b1, b2)
	}
}

func TestEncodeEmptyMap(t *testing.T) {
	// {} → A0
	b, err := Encode(map[string]int{})
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A0")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeSingleUint(t *testing.T) {
	// {"value": 42} → A1 65 76616C7565 18 2A
	b, err := Encode(map[string]uint{
		"value": 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A16576616C7565182A")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeKeyOrdering(t *testing.T) {
	// Keys sorted by encoded length, then lexicographic.
	// {"z": 1, "a": 2, "bb": 3, "aaa": 4}
	// Expected order: a, z, bb, aaa
	// A4 6161 02 617A 01 626262 03 63616161 04
	input := map[string]uint{
		"z":   1,
		"a":   2,
		"bb":  3,
		"aaa": 4,
	}
	b, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A4616102617A01626262036361616104")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeBoolean(t *testing.T) {
	// {"flag": true} → A1 64 666C6167 F5
	b, err := Encode(map[string]bool{"flag": true})
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A164666C6167F5")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}

	// {"flag": false} → A1 64 666C6167 F4
	b, err = Encode(map[string]bool{"flag": false})
	if err != nil {
		t.Fatal(err)
	}
	expected = mustHex("A164666C6167F4")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeNegativeInt(t *testing.T) {
	// {"value": -1} → A1 65 76616C7565 20
	b, err := Encode(map[string]int{"value": -1})
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A16576616C756520")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeByteString(t *testing.T) {
	// {"data": h'DEADBEEF'} → A1 64 64617461 44 DEADBEEF
	b, err := Encode(map[string][]byte{"data": mustHex("DEADBEEF")})
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex("A1646461746144DEADBEEF")
	if !bytes.Equal(b, expected) {
		t.Fatalf("expected %x, got %x", expected, b)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	original := map[string]interface{}{
		"name":  "test",
		"count": uint64(99),
	}
	b, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := Decode(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["name"] != "test" {
		t.Fatalf("expected name=test, got %v", decoded["name"])
	}
}

func TestEncodeHashable(t *testing.T) {
	// EncodeHashable must produce a 2-key map with "data" before "type".
	data, err := Encode(map[string]string{"key": "val"})
	if err != nil {
		t.Fatal(err)
	}
	raw := cbor.RawMessage(data)

	b, err := EncodeHashable("test/type", raw)
	if err != nil {
		t.Fatal(err)
	}

	// Decode and verify structure.
	var decoded map[string]cbor.RawMessage
	if err := Decode(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["data"]; !ok {
		t.Fatal("missing 'data' key")
	}
	if _, ok := decoded["type"]; !ok {
		t.Fatal("missing 'type' key")
	}

	// Verify determinism: same inputs → same bytes.
	b2, err := EncodeHashable("test/type", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("non-deterministic hashable encoding")
	}
}

func TestEncodeHashableKeyOrder(t *testing.T) {
	// "data" must come before "type" in ECF (same encoded length, alphabetical).
	// The map header byte for a 2-entry map is 0xA2.
	// Then "data" key (64 64617461) must appear before "type" key (64 74797065).
	data, err := Encode("hello")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeHashable("test", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}

	// Find positions of "data" and "type" text strings in output.
	dataKey := mustHex("6464617461") // CBOR text(4) "data"
	typeKey := mustHex("6474797065") // CBOR text(4) "type"

	dataPos := bytes.Index(b, dataKey)
	typePos := bytes.Index(b, typeKey)

	if dataPos < 0 || typePos < 0 {
		t.Fatalf("keys not found in output: %x", b)
	}
	if dataPos >= typePos {
		t.Fatalf("'data' key (pos %d) should come before 'type' key (pos %d) in ECF", dataPos, typePos)
	}
}
