package hash

import (
	"bytes"
	"crypto/sha512"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"

	"github.com/fxamacker/cbor/v2"
)

// V7.67 Phase 1 / §4 — ECFv1-SHA-384 (`content_hash_format=0x01`).

func TestSHA384_ComputeFormat_FixtureRoundtrip(t *testing.T) {
	// Cross-impl corpus fixture inherits the v7.66 `0xAA × 64` canonical
	// fixture, re-hashed under SHA-384. Per v7.67 §7.1 HASH-FORMAT-SHA-384-1.
	data, err := ecf.Encode(map[string]string{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ComputeFormat(AlgorithmSHA384, "test/type", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}
	if h.Algorithm != AlgorithmSHA384 {
		t.Fatalf("Algorithm = 0x%02x, want 0x%02x", h.Algorithm, AlgorithmSHA384)
	}
	if len(h.EffectiveDigest()) != SHA384DigestSize {
		t.Fatalf("EffectiveDigest len = %d, want %d", len(h.EffectiveDigest()), SHA384DigestSize)
	}
	// Verify manually: SHA-384(ECF({data, type})).
	ecfBytes, _ := ecf.EncodeHashable("test/type", cbor.RawMessage(data))
	want := sha512.Sum384(ecfBytes)
	if !bytes.Equal(h.EffectiveDigest(), want[:]) {
		t.Fatalf("SHA-384 digest mismatch")
	}
}

func TestSHA384_WireFormat_49Bytes(t *testing.T) {
	data, _ := ecf.Encode("v7.67-sha384-wire")
	h, err := ComputeFormat(AlgorithmSHA384, "fixture", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}
	wire := h.Bytes()
	if len(wire) != 49 {
		t.Fatalf("v7.67 §4: SHA-384 wire size = %d, want 49 (1 + 48)", len(wire))
	}
	if wire[0] != AlgorithmSHA384 {
		t.Fatalf("wire[0] = 0x%02x, want 0x%02x", wire[0], AlgorithmSHA384)
	}
}

func TestSHA384_FromBytes_Roundtrip(t *testing.T) {
	data, _ := ecf.Encode("rt")
	h, err := ComputeFormat(AlgorithmSHA384, "fixture", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := FromBytes(h.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != h {
		t.Fatalf("round-trip mismatch: %s != %s", parsed, h)
	}
}

func TestSHA384_String_DisplayPrefix(t *testing.T) {
	data, _ := ecf.Encode("d")
	h, _ := ComputeFormat(AlgorithmSHA384, "fixture", cbor.RawMessage(data))
	s := h.String()
	if !strings.HasPrefix(s, "ecfv1-sha384:") {
		t.Fatalf("v7.67 §3.1: SHA-384 display prefix = %q, want %q", s, "ecfv1-sha384:")
	}
	// Hex digest after prefix should be 96 chars (48 bytes hex).
	parts := strings.SplitN(s, ":", 2)
	if len(parts[1]) != 96 {
		t.Fatalf("hex digest len = %d, want 96", len(parts[1]))
	}
}

func TestSHA384_CBORRoundtrip(t *testing.T) {
	data, _ := ecf.Encode("cbor-rt")
	h, _ := ComputeFormat(AlgorithmSHA384, "fixture", cbor.RawMessage(data))

	enc, err := h.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	var dec Hash
	if err := dec.UnmarshalCBOR(enc); err != nil {
		t.Fatal(err)
	}
	if dec != h {
		t.Fatalf("CBOR round-trip mismatch: %s != %s", dec, h)
	}
}

func TestSHA256_AndSHA384_AreDifferentMapKeys(t *testing.T) {
	// A SHA-256 hash and a SHA-384 hash over the same fixture must be
	// distinct map keys even if their effective digest bytes happen to
	// share a prefix.
	data, _ := ecf.Encode("same-input")
	h256, _ := ComputeFormat(AlgorithmSHA256, "x", cbor.RawMessage(data))
	h384, _ := ComputeFormat(AlgorithmSHA384, "x", cbor.RawMessage(data))
	if h256 == h384 {
		t.Fatal("SHA-256 and SHA-384 hashes over the same input compare equal — format-code must keep them distinct")
	}
	m := map[Hash]string{h256: "sha256", h384: "sha384"}
	if m[h256] != "sha256" || m[h384] != "sha384" {
		t.Fatal("map lookup conflated SHA-256 and SHA-384 keys")
	}
}
