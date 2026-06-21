package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"testing"
)

// TestBirationalRoundtripFromSeed — self-consistent property check that
// validates the Ed25519→X25519 birational map by deriving the same X25519
// public key two independent ways from one shared seed:
//
//	(1) seed → SHA-512 → clamped scalar a → A_ed = a·B_ed
//	    → x25519_pub_via_birational = (1+y_A)/(1-y_A) mod 2^255-19
//
//	(2) seed → SHA-512 → clamped scalar a → x25519_pub_via_scalar = a·9 (Montgomery)
//
// The Ed25519 and Curve25519 base-point scalars are the same clamped
// 32-byte value (RFC 7748 + RFC 8032 share clamping discipline). The
// birational map y → u = (1+y)/(1-y) sends a·B_ed → a·B_mont, so the two
// X25519 pubkeys above MUST be byte-equal. This is the canonical
// internal check used by libsodium's test suite for
// crypto_sign_ed25519_pk_to_curve25519.
func TestBirationalRoundtripFromSeed(t *testing.T) {
	seeds := [][]byte{
		bytes.Repeat([]byte{0x00}, ed25519.SeedSize),
		bytes.Repeat([]byte{0x42}, ed25519.SeedSize),
		bytes.Repeat([]byte{0xAB}, ed25519.SeedSize),
	}
	for i, seed := range seeds {
		priv := ed25519.NewKeyFromSeed(seed)
		var edPub [32]byte
		copy(edPub[:], priv.Public().(ed25519.PublicKey))

		// Path 1: birational image of the Ed25519 public key.
		viaBirational, err := BirationalEdToX25519(edPub)
		if err != nil {
			t.Fatalf("seed[%d]: BirationalEdToX25519: %v", i, err)
		}

		// Path 2: derive the same X25519 pubkey from the clamped SHA-512
		// scalar of the seed (the shared private-key derivation step).
		h := sha512.Sum512(seed)
		var scalar [32]byte
		copy(scalar[:], h[:32])
		// Standard Ed25519 / X25519 scalar clamp (RFC 7748 §5):
		scalar[0] &= 0xF8
		scalar[31] &= 0x7F
		scalar[31] |= 0x40

		xPriv, err := ecdh.X25519().NewPrivateKey(scalar[:])
		if err != nil {
			t.Fatalf("seed[%d]: NewPrivateKey: %v", i, err)
		}
		viaScalar := xPriv.PublicKey().Bytes()

		if !bytes.Equal(viaBirational[:], viaScalar) {
			t.Fatalf("seed[%d]: birational/scalar X25519 pubkeys diverge\n  via-birational: %x\n  via-scalar:     %x",
				i, viaBirational[:], viaScalar)
		}
	}
}

// TestValidateKeySeparation — positive and negative cases.
func TestValidateKeySeparation(t *testing.T) {
	// Authoring an independent X25519 keypair PASSES.
	identitySeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	identityPriv := ed25519.NewKeyFromSeed(identitySeed)
	var identityPK [32]byte
	copy(identityPK[:], identityPriv.Public().(ed25519.PublicKey))

	independentX25519, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatalf("independent X25519 keygen: %v", err)
	}
	var independentPK [32]byte
	copy(independentPK[:], independentX25519.PublicKey().Bytes())

	if err := ValidateKeySeparation(identityPK, independentPK); err != nil {
		t.Fatalf("independent keypair MUST pass separation: %v", err)
	}

	// Re-using the identity pubkey bytes verbatim FAILS.
	if err := ValidateKeySeparation(identityPK, identityPK); err == nil {
		t.Fatalf("identity-as-encryption-key MUST fail separation, got nil")
	} else if !errors.Is(err, ErrEncryptionKeyDerivedFromIdentity) {
		t.Fatalf("identity-as-encryption-key: wrong error: %v", err)
	}

	// Birational(identity) FAILS — the forbidden libsodium-style derivation.
	birational, err := BirationalEdToX25519(identityPK)
	if err != nil {
		t.Fatalf("BirationalEdToX25519: %v", err)
	}
	if err := ValidateKeySeparation(identityPK, birational); err == nil {
		t.Fatalf("birational(identity) MUST fail separation, got nil")
	} else if !errors.Is(err, ErrEncryptionKeyDerivedFromIdentity) {
		t.Fatalf("birational(identity): wrong error: %v", err)
	}
}
