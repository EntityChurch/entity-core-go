package crypto

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.PrivateKey) != 64 {
		t.Fatalf("expected 64-byte private key, got %d", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(kp.PublicKey))
	}
}

func TestFromSeed(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	kp1 := FromSeed(seed)
	kp2 := FromSeed(seed)

	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Fatal("same seed should produce same keypair")
	}
}

func TestSignVerify(t *testing.T) {
	kp, _ := Generate()
	message := []byte("hello world")

	sig := kp.Sign(message)
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}

	if !Verify(kp.KeyType, kp.PublicKey, message, sig) {
		t.Fatal("valid signature should verify")
	}

	// Tampered message.
	if Verify(kp.KeyType, kp.PublicKey, []byte("tampered"), sig) {
		t.Fatal("tampered message should not verify")
	}

	// Tampered signature.
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if Verify(kp.KeyType, kp.PublicKey, message, badSig) {
		t.Fatal("tampered signature should not verify")
	}
}

func TestPeerIDDerivation(t *testing.T) {
	kp, _ := Generate()
	pid := kp.PeerID()

	if len(string(pid)) == 0 {
		t.Fatal("PeerID should not be empty")
	}

	if err := pid.Validate(); err != nil {
		t.Fatalf("PeerID validation failed: %v", err)
	}
}

func TestPeerIDDeterministic(t *testing.T) {
	var seed [32]byte
	kp := FromSeed(seed)

	pid1 := kp.PeerID()
	pid2 := kp.PeerID()

	if pid1 != pid2 {
		t.Fatalf("PeerID should be deterministic: %s != %s", pid1, pid2)
	}
}

func TestPeerIDVerifyPublicKey(t *testing.T) {
	kp, _ := Generate()
	pid := kp.PeerID()

	if !pid.VerifyPublicKey(kp.PublicKey) {
		t.Fatal("PeerID should verify against its public key")
	}

	// Different keypair.
	other, _ := Generate()
	if pid.VerifyPublicKey(other.PublicKey) {
		t.Fatal("PeerID should not verify against different public key")
	}
}

func TestPeerIDValidateInvalid(t *testing.T) {
	bad := PeerID("not-valid-base58!!!")
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for invalid PeerID")
	}
}

func TestIdentityEntity(t *testing.T) {
	kp, _ := Generate()
	ent, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}

	if ent.Type != TypePeer {
		t.Fatalf("expected type %s, got %s", TypePeer, ent.Type)
	}
	if ent.ContentHash.IsZero() {
		t.Fatal("content hash should not be zero")
	}

	// Validate the entity.
	if err := ent.Validate(); err != nil {
		t.Fatalf("identity entity validation failed: %v", err)
	}
}

func TestPeerIDLength(t *testing.T) {
	// PeerID for Ed25519+SHA256 should be 46 Base58 characters.
	var seed [32]byte
	kp := FromSeed(seed)
	pid := kp.PeerID()

	// Note: Base58 encoding length can vary slightly depending on leading zeros.
	// The spec says 46 characters for the typical case.
	if len(string(pid)) < 44 || len(string(pid)) > 48 {
		t.Fatalf("PeerID length %d outside expected range [44, 48]", len(string(pid)))
	}
}
