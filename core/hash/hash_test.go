package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"

	"github.com/fxamacker/cbor/v2"
)

func TestComputeKnownHash(t *testing.T) {
	// Compute hash and verify it matches manual computation.
	data, err := ecf.Encode(map[string]string{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}

	h, err := Compute("test/type", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}

	if h.Algorithm != AlgorithmSHA256 {
		t.Fatalf("expected algorithm 0x00, got 0x%02x", h.Algorithm)
	}

	// Verify manually: SHA256(ECF({data: <raw>, type: "test/type"}))
	ecfBytes, _ := ecf.EncodeHashable("test/type", cbor.RawMessage(data))
	expected := sha256.Sum256(ecfBytes)
	if !bytes.Equal(h.EffectiveDigest(), expected[:]) {
		t.Fatalf("digest mismatch: got %x, expected %x", h.EffectiveDigest(), expected)
	}
}

func TestComputeDeterministic(t *testing.T) {
	data, err := ecf.Encode("hello")
	if err != nil {
		t.Fatal(err)
	}
	raw := cbor.RawMessage(data)

	h1, err := Compute("test", raw)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Compute("test", raw)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic: %s != %s", h1, h2)
	}
}

func TestValidate(t *testing.T) {
	data, _ := ecf.Encode("hello")
	raw := cbor.RawMessage(data)

	h, err := Compute("test", raw)
	if err != nil {
		t.Fatal(err)
	}

	// Valid hash.
	if err := Validate("test", raw, h); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Tampered digest.
	bad := h
	bad.Digest[0] ^= 0xFF
	if err := Validate("test", raw, bad); err == nil {
		t.Fatal("expected error for tampered hash")
	}
}

func TestBytes(t *testing.T) {
	h := Hash{Algorithm: AlgorithmSHA256}
	for i := 0; i < SHA256DigestSize; i++ {
		h.Digest[i] = byte(i)
	}

	b := h.Bytes()
	if len(b) != HashSize {
		t.Fatalf("expected %d bytes, got %d", HashSize, len(b))
	}
	if b[0] != AlgorithmSHA256 {
		t.Fatalf("expected algorithm byte 0x00, got 0x%02x", b[0])
	}
	for i := 0; i < SHA256DigestSize; i++ {
		if b[i+1] != byte(i) {
			t.Fatalf("byte %d: expected %d, got %d", i+1, i, b[i+1])
		}
	}
}

func TestFromBytes(t *testing.T) {
	original := Hash{Algorithm: AlgorithmSHA256}
	for i := 0; i < SHA256DigestSize; i++ {
		original.Digest[i] = byte(i + 10)
	}

	parsed, err := FromBytes(original.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != original {
		t.Fatalf("roundtrip failed: %v != %v", parsed, original)
	}
}

func TestFromBytesInvalidLength(t *testing.T) {
	_, err := FromBytes([]byte{0x00, 0x01}) // too short
	if err == nil {
		t.Fatal("expected error for short bytes")
	}

	_, err = FromBytes(make([]byte, 34)) // too long
	if err == nil {
		t.Fatal("expected error for long bytes")
	}
}

func TestFromBytesUnknownAlgorithm(t *testing.T) {
	b := make([]byte, HashSize)
	b[0] = 0x7E // unknown / unallocated
	_, err := FromBytes(b)
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestIsZero(t *testing.T) {
	var h Hash
	if !h.IsZero() {
		t.Fatal("zero value should be zero")
	}

	h.Digest[0] = 0x01
	if h.IsZero() {
		t.Fatal("non-zero value should not be zero")
	}
}

func TestString(t *testing.T) {
	h := Hash{Algorithm: AlgorithmSHA256}
	s := h.String()
	if !strings.HasPrefix(s, "ecf-sha256:") {
		t.Fatalf("expected ecf-sha256: prefix, got %s", s)
	}
	// Hex digest should be 64 characters.
	parts := strings.SplitN(s, ":", 2)
	if len(parts[1]) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(parts[1]), parts[1])
	}
}

func TestCBORRoundtrip(t *testing.T) {
	data, _ := ecf.Encode("test")
	h, err := Compute("mytype", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}

	// Marshal to CBOR.
	encoded, err := h.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal back.
	var decoded Hash
	if err := decoded.UnmarshalCBOR(encoded); err != nil {
		t.Fatal(err)
	}

	if decoded != h {
		t.Fatalf("roundtrip failed: %v != %v", decoded, h)
	}
}

func TestCBORWireFormat(t *testing.T) {
	// Wire format must be a CBOR byte string (major type 2), not a map.
	h := Hash{Algorithm: AlgorithmSHA256}
	for i := 0; i < SHA256DigestSize; i++ {
		h.Digest[i] = byte(i)
	}

	encoded, err := h.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	// First byte should be 0x58 (byte string, 1-byte length) followed by
	// 0x21 (33 = HashSize).
	if len(encoded) < 2 {
		t.Fatalf("encoded too short: %x", encoded)
	}
	if encoded[0] != 0x58 || encoded[1] != 0x21 {
		t.Fatalf("expected CBOR byte string header 58 21, got %02x %02x", encoded[0], encoded[1])
	}
}

func TestMapKey(t *testing.T) {
	// Hash must be usable as a Go map key.
	data1, _ := ecf.Encode("one")
	data2, _ := ecf.Encode("two")

	h1, _ := Compute("t", cbor.RawMessage(data1))
	h2, _ := Compute("t", cbor.RawMessage(data2))

	m := map[Hash]string{
		h1: "one",
		h2: "two",
	}

	if m[h1] != "one" {
		t.Fatalf("map lookup failed for h1")
	}
	if m[h2] != "two" {
		t.Fatalf("map lookup failed for h2")
	}
}

func TestStringRoundtrip(t *testing.T) {
	// Verify String() output can be parsed back.
	data, _ := ecf.Encode("test")
	h, _ := Compute("mytype", cbor.RawMessage(data))

	s := h.String()
	parts := strings.SplitN(s, ":", 2)
	if parts[0] != "ecf-sha256" {
		t.Fatalf("unexpected format: %s", parts[0])
	}

	digestBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	b := append([]byte{AlgorithmSHA256}, digestBytes...)
	parsed, err := FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}

	if parsed != h {
		t.Fatalf("string roundtrip failed")
	}
}

// V7 §1.3 / RULING-Q-OMITZERO-HASH-FIELD: optional hash fields
// emitted as CBOR null or empty byte string MUST decode as zero hash without
// error. Required-field semantics are enforced at the handler layer via
// IsZero(), not at decode.
func TestUnmarshalCBORNullDecodesAsZero(t *testing.T) {
	var h Hash
	if err := h.UnmarshalCBOR([]byte{0xf6}); err != nil {
		t.Fatalf("CBOR null (0xf6) MUST decode as zero hash per §1.3, got: %v", err)
	}
	if !h.IsZero() {
		t.Fatalf("expected zero hash after null decode, got %v", h)
	}
}

func TestUnmarshalCBORUndefinedDecodesAsZero(t *testing.T) {
	var h Hash
	if err := h.UnmarshalCBOR([]byte{0xf7}); err != nil {
		t.Fatalf("CBOR undefined (0xf7) MUST decode as zero hash per §1.3, got: %v", err)
	}
	if !h.IsZero() {
		t.Fatalf("expected zero hash after undefined decode, got %v", h)
	}
}

func TestUnmarshalCBOREmptyBytesDecodesAsZero(t *testing.T) {
	var h Hash
	// 0x40 == empty byte string (h''). Python cbor2 emits this for some
	// optional-hash-field shapes; §1.3 mandates accept.
	if err := h.UnmarshalCBOR([]byte{0x40}); err != nil {
		t.Fatalf("empty byte string MUST decode as zero hash per §1.3, got: %v", err)
	}
	if !h.IsZero() {
		t.Fatalf("expected zero hash after empty-bytes decode, got %v", h)
	}
}

func TestUnmarshalCBORMalformedStillRejects(t *testing.T) {
	// §1.3 covers null/zero/empty — not arbitrary wrong-length bytes.
	// 0x41 0x00 = 1-byte byte string. Neither null nor empty; rejection
	// is correct (real corruption, not the omitzero edge case).
	var h Hash
	if err := h.UnmarshalCBOR([]byte{0x41, 0x00}); err == nil {
		t.Fatal("expected error for malformed 1-byte hash input")
	}
}

func TestEmptyMapHash(t *testing.T) {
	// Verify hash of empty map data matches spec test vector.
	// The empty map {} encodes to A0 in ECF.
	// For hash, we encode {data: A0, type: ""} but this test just verifies
	// the computation is consistent.
	emptyMap, _ := ecf.Encode(map[string]interface{}{})
	h, err := Compute("", cbor.RawMessage(emptyMap))
	if err != nil {
		t.Fatal(err)
	}

	// Recompute manually.
	ecfBytes, _ := ecf.EncodeHashable("", cbor.RawMessage(emptyMap))
	expected := sha256.Sum256(ecfBytes)

	if !bytes.Equal(h.EffectiveDigest(), expected[:]) {
		t.Fatalf("empty map hash mismatch")
	}
}
