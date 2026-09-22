package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// TestRecompute_SignsContentHashNotEcfBytes pins the CQ-22 / §7.3 construction:
// the message is the full content_hash (format code ‖ digest), NOT the raw ECF
// bytes. Sibling-independent — builds the vector shape in memory. Mutation: if
// recompute signed the ECF bytes, it would equal wantEcf and differ from wantCH.
func TestRecompute_SignsContentHashNotEcfBytes(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize) // all-zero, deterministic
	vec := map[interface{}]interface{}{
		"id": "signature.1",
		"input": map[interface{}]interface{}{
			"seed": seed,
			"entity": map[interface{}]interface{}{
				"type": "test/v1",
				"data": map[interface{}]interface{}{"x": int64(1)},
			},
		},
	}

	sig, msg, err := recompute(vec)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}

	// The message MUST be the full content_hash.
	dataRaw, _ := ecf.Encode(map[interface{}]interface{}{"x": int64(1)})
	h, _ := hash.Compute("test/v1", dataRaw)
	if hex.EncodeToString(msg) != hex.EncodeToString(h.Bytes()) {
		t.Fatalf("message is not the full content_hash: got %x want %x", msg, h.Bytes())
	}
	if msg[0] != hash.AlgorithmSHA256 || len(msg) != 1+hash.SHA256DigestSize {
		t.Fatalf("message missing format code / wrong length: %x", msg)
	}

	// The signature verifies over the content_hash message.
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("recomputed signature does not verify over the content_hash")
	}

	// The losing (pre-CQ-22) reading — signing the raw ECF bytes — must differ.
	ecfBytes, _ := ecf.EncodeHashable("test/v1", dataRaw)
	wrong := ed25519.Sign(ed25519.NewKeyFromSeed(seed), ecfBytes)
	if hex.EncodeToString(sig) == hex.EncodeToString(wrong) {
		t.Fatal("recompute signed the ECF bytes (the withdrawn reading), not the content_hash")
	}

	// Pin the known-good signature.1 value (the routed S-1 canonical).
	const want = "25217cd5348f32bd96c35886034f0b8bac111a5632b706acaed325f7cd93b27b2dfe95023a8308f36cd282f81666ee64c5382af2b02dd7b5702c5cf4d759b509"
	if hex.EncodeToString(sig) != want {
		t.Fatalf("signature.1 canonical drift: got %s want %s", hex.EncodeToString(sig), want)
	}
}
