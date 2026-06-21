package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// V7.67 Phase 1 / §3 — Ed448 sign/verify and PeerID round-trip.
//
// V7.67 Phase 2 unification: the keypair type is the algorithm-agnostic
// crypto.Keypair with KeyType=KeyTypeEd448; ed448-specific generation
// uses GenerateForKeyType(KeyTypeEd448) or Ed448FromSeed.

func TestEd448_FixedSeed_Determinism(t *testing.T) {
	var seed [Ed448SeedLen]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	kp1 := Ed448FromSeed(seed)
	kp2 := Ed448FromSeed(seed)
	if !bytes.Equal(kp1.PublicKeyBytes(), kp2.PublicKeyBytes()) {
		t.Fatal("Ed448FromSeed not deterministic")
	}
	if len(kp1.PublicKeyBytes()) != Ed448PublicKeyLen {
		t.Fatalf("public key len = %d, want %d", len(kp1.PublicKeyBytes()), Ed448PublicKeyLen)
	}
	if len(kp1.PrivateKey) != Ed448PrivateKeyLen {
		t.Fatalf("private key len = %d, want %d", len(kp1.PrivateKey), Ed448PrivateKeyLen)
	}
	if kp1.KeyType != KeyTypeEd448 {
		t.Fatalf("KeyType = 0x%02x, want 0x%02x", kp1.KeyType, KeyTypeEd448)
	}
}

func TestEd448_SignVerifyRoundtrip(t *testing.T) {
	kp, err := GenerateForKeyType(KeyTypeEd448)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("v7.67 Phase 1 Ed448 sign/verify roundtrip")
	sig := kp.Sign(msg)
	if len(sig) != Ed448SignatureLen {
		t.Fatalf("sig len = %d, want %d", len(sig), Ed448SignatureLen)
	}
	if !Verify(KeyTypeEd448, kp.PublicKey, msg, sig) {
		t.Fatal("verify rejected legitimate signature")
	}
	if Verify(KeyTypeEd448, kp.PublicKey, []byte("tampered"), sig) {
		t.Fatal("verify accepted tampered message")
	}
	badSig := append([]byte{}, sig...)
	badSig[0] ^= 0xFF
	if Verify(KeyTypeEd448, kp.PublicKey, msg, badSig) {
		t.Fatal("verify accepted tampered signature")
	}
}

func TestEd448_PeerID_CanonicalForm(t *testing.T) {
	var seed [Ed448SeedLen]byte
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	kp := Ed448FromSeed(seed)

	pid := kp.PeerID()
	if err := pid.Validate(); err != nil {
		t.Fatalf("canonical Ed448 PeerID failed Validate(): %v", err)
	}
	dec, err := pid.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if dec.KeyType != KeyTypeEd448 {
		t.Fatalf("decoded key_type = 0x%02x, want 0x%02x (Ed448)", dec.KeyType, KeyTypeEd448)
	}
	if dec.HashType != HashTypeSHA256 {
		t.Fatalf("decoded hash_type = 0x%02x, want 0x%02x (SHA-256-form — v7.67 §3.2 canonical pair)",
			dec.HashType, HashTypeSHA256)
	}
	if len(dec.Digest) != SHA256DigestLen {
		t.Fatalf("decoded digest len = %d, want %d", len(dec.Digest), SHA256DigestLen)
	}
}

func TestEd448_KeyTypeStringPin(t *testing.T) {
	if KeyTypeStringEd448 != "ed448" {
		t.Fatalf("v7.67 §3.3 pin: KeyTypeStringEd448 = %q, want %q", KeyTypeStringEd448, "ed448")
	}
	if got, ok := KeyTypeByte("ed448"); !ok || got != KeyTypeEd448 {
		t.Fatalf("KeyTypeByte(\"ed448\") = (0x%02x, %v), want (0x%02x, true)", got, ok, KeyTypeEd448)
	}
	if got := KeyTypeString(KeyTypeEd448); got != KeyTypeStringEd448 {
		t.Fatalf("KeyTypeString(0x%02x) = %q, want %q", KeyTypeEd448, got, KeyTypeStringEd448)
	}
	if ht, err := CanonicalHashType(KeyTypeEd448); err != nil || ht != HashTypeSHA256 {
		t.Fatalf("CanonicalHashType(Ed448) = (0x%02x, %v), want (0x%02x, nil)", ht, err, HashTypeSHA256)
	}
}

func TestEd448_PeerID_NonCanonicalPubKeyLen(t *testing.T) {
	// A 32-byte public_key (Ed25519-sized) is not a valid Ed448 pubkey;
	// mint MUST refuse.
	bad := make([]byte, 32)
	_, err := PeerIDFromPublicKey(bad, KeyTypeEd448)
	if err == nil || !strings.Contains(err.Error(), "ed448") {
		t.Fatalf("expected mint refusal for short Ed448 pubkey, got: %v", err)
	}
}
