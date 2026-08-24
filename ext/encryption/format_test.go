package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The content_hash_format seam under encryption — V7 §1.2 (home format),
// §1.8 + v7.69 §4.5a (a reference is the AUTHORED hash, never a
// re-derivation), and ENCRYPTION §16's ENC-ROUNDTRIP-FORMAT-1.
//
// These tests do what nothing in this repo did before them: turn SHA-384
// on. `entity-peer --hash-type sha384` has shipped for a while and all
// three implementations honor it, but no encryption test had ever set it,
// so every SHA-256/SHA-384 divergence in this package was invisible by
// construction. ComputePubkeyHash was wrong for exactly that reason.

// testPubkeyData builds a pubkey data shape from a fresh X25519 key.
func testPubkeyData(t *testing.T) (*ecdh.PrivateKey, types.EncryptionPubkeyData) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519: %v", err)
	}
	return priv, types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        priv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          1000,
	}
}

// withHomeFormat runs fn with the process-global authoring format set,
// restoring it afterwards. Safe here only because Go runs the tests of one
// package sequentially unless they call t.Parallel — which nothing in this
// file does, deliberately. Anything outside a test wanting a specific
// format must name it via ComputePubkeyHashFormat instead of reaching for
// this pattern.
func withHomeFormat(t *testing.T, alg byte, fn func()) {
	t.Helper()
	prev := entity.DefaultHashAlgorithm()
	entity.SetDefaultHashAlgorithm(alg)
	defer entity.SetDefaultHashAlgorithm(prev)
	fn()
}

// TestComputePubkeyHashFollowsHomeFormat is the regression for the defect
// this file was written to find: ComputePubkeyHash called hash.Compute
// (unconditionally SHA-256) while documenting itself as following the
// peer's default format.
//
// The assertion that matters is the SECOND one — agreement with
// entity.NewEntity. That is the pairing that breaks a live SHA-384 peer:
// the pubkey entity is published through NewEntity at its home-format
// hash, and every path and recipient_key binding comes from here. If the
// two disagree, the peer publishes a key at one address and names it at
// another.
func TestComputePubkeyHashFollowsHomeFormat(t *testing.T) {
	_, data := testPubkeyData(t)
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatalf("encode pubkey data: %v", err)
	}

	for _, tc := range []struct {
		name    string
		alg     byte
		wantLen int
	}{
		{"sha256-home", hash.AlgorithmSHA256, 33},
		{"sha384-home", hash.AlgorithmSHA384, 49},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHomeFormat(t, tc.alg, func() {
				got, err := ComputePubkeyHash(data)
				if err != nil {
					t.Fatalf("ComputePubkeyHash: %v", err)
				}
				if got.Algorithm != tc.alg {
					t.Fatalf("ComputePubkeyHash algorithm = 0x%02x under home format 0x%02x; "+
						"a pubkey entity is content this peer authors, so V7 §1.2 makes it the home format",
						got.Algorithm, tc.alg)
				}
				if n := len(got.Bytes()); n != tc.wantLen {
					t.Fatalf("wire form = %d bytes, want %d", n, tc.wantLen)
				}

				// The pairing that actually breaks a deployment.
				ent, err := entity.NewEntity(types.TypeEncryptionPubkey, raw)
				if err != nil {
					t.Fatalf("NewEntity: %v", err)
				}
				if !bytes.Equal(ent.ContentHash.Bytes(), got.Bytes()) {
					t.Fatalf("ComputePubkeyHash %x disagrees with the authored entity %x "+
						"under home format 0x%02x — the key would be published at one address and named at another",
						got.Bytes(), ent.ContentHash.Bytes(), tc.alg)
				}
			})
		})
	}
}

// TestComputePubkeyHashFormatIsIndependentOfHome pins the explicit-format
// variant: it must answer for the format it was handed no matter what the
// process default is, or the cross-format vector cannot state its own
// inputs without mutating a global.
func TestComputePubkeyHashFormatIsIndependentOfHome(t *testing.T) {
	_, data := testPubkeyData(t)

	var underSHA256, underSHA384 hash.Hash
	withHomeFormat(t, hash.AlgorithmSHA384, func() {
		var err error
		if underSHA256, err = ComputePubkeyHashFormat(hash.AlgorithmSHA256, data); err != nil {
			t.Fatalf("ComputePubkeyHashFormat(sha256): %v", err)
		}
		if underSHA384, err = ComputePubkeyHashFormat(hash.AlgorithmSHA384, data); err != nil {
			t.Fatalf("ComputePubkeyHashFormat(sha384): %v", err)
		}
	})
	if underSHA256.Algorithm != hash.AlgorithmSHA256 {
		t.Fatalf("explicit sha256 request answered 0x%02x under a SHA-384 home", underSHA256.Algorithm)
	}
	if underSHA384.Algorithm != hash.AlgorithmSHA384 {
		t.Fatalf("explicit sha384 request answered 0x%02x", underSHA384.Algorithm)
	}
	// Same data shape, different address space — V7 §1.2's "does not dedup
	// or converge" stated as bytes.
	if bytes.Equal(underSHA256.Bytes(), underSHA384.Bytes()) {
		t.Fatal("one data shape hashed to identical bytes under two formats")
	}
}

// TestPeerModeBindsRecipientAuthoredFormat is ENC-ROUNDTRIP-FORMAT-1's
// core assertion at the library level: a SHA-256-home sender encrypting to
// a SHA-384-home recipient binds the recipient's authored 49-byte hash and
// round-trips.
//
// It also pins WHERE the discipline is enforced, because that is easy to
// assume wrongly. The algorithm byte is bound into both the HKDF info and
// the AAD, so a re-derived recipient_key changes the AEAD key — but a
// re-deriving sender is self-consistent, and PeerDecrypt rebuilds both
// from the wrapper's own recipient_key, so the wrapper still opens with
// the right private key. The AEAD does NOT catch this. What catches it is
// the recipient's key LOOKUP: the re-derived hash names an entity the
// recipient never authored, so the recipient cannot select a private key
// for it at all. The last sub-assertion states that, so nobody later
// "simplifies" the check into a decrypt-must-fail that would not fail.
func TestPeerModeBindsRecipientAuthoredFormat(t *testing.T) {
	recipientPriv, data := testPubkeyData(t)

	// The recipient's home is SHA-384; this is the hash it publishes under.
	authored, err := ComputePubkeyHashFormat(hash.AlgorithmSHA384, data)
	if err != nil {
		t.Fatalf("authored hash: %v", err)
	}
	if authored.Algorithm != hash.AlgorithmSHA384 {
		t.Fatalf("authored algorithm = 0x%02x, want 0x01", authored.Algorithm)
	}

	// The sender's home is SHA-256, and it must not matter.
	var ed types.EncryptedData
	withHomeFormat(t, hash.AlgorithmSHA256, func() {
		ed, err = PeerEncrypt(PeerEncryptInput{
			RecipientPubkey:     data.PublicKey,
			RecipientPubkeyHash: authored,
			Plaintext:           []byte("cross-format greeting"),
		})
	})
	if err != nil {
		t.Fatalf("PeerEncrypt: %v", err)
	}
	if !bytes.Equal(ed.RecipientKey.Bytes(), authored.Bytes()) {
		t.Fatalf("bound recipient_key %x != recipient's authored hash %x",
			ed.RecipientKey.Bytes(), authored.Bytes())
	}
	if n := len(ed.RecipientKey.Bytes()); n != 49 {
		t.Fatalf("bound recipient_key is %d bytes; the recipient's SHA-384 form is 49", n)
	}

	got, err := PeerDecrypt(PeerDecryptInput{Wrapper: ed, RecipientPriv: recipientPriv.Bytes()})
	if err != nil {
		t.Fatalf("PeerDecrypt across formats: %v", err)
	}
	if !bytes.Equal(got, []byte("cross-format greeting")) {
		t.Fatal("cross-format round-trip plaintext mismatch")
	}

	// The forbidden move, and what it actually costs.
	reDerived, err := ComputePubkeyHashFormat(hash.AlgorithmSHA256, data)
	if err != nil {
		t.Fatalf("re-derived hash: %v", err)
	}
	if bytes.Equal(reDerived.Bytes(), authored.Bytes()) {
		t.Fatal("re-derivation produced the authored hash — the test has no teeth")
	}
	wrong, err := PeerEncrypt(PeerEncryptInput{
		RecipientPubkey:     data.PublicKey,
		RecipientPubkeyHash: reDerived,
		Plaintext:           []byte("cross-format greeting"),
	})
	if err != nil {
		t.Fatalf("PeerEncrypt (re-derived): %v", err)
	}
	if bytes.Equal(wrong.Ciphertext, ed.Ciphertext) {
		t.Fatal("re-derived recipient_key produced identical ciphertext — " +
			"the algorithm byte is not reaching the AEAD key derivation")
	}
	// Self-consistent, therefore NOT caught by the AEAD.
	if _, err := PeerDecrypt(PeerDecryptInput{
		Wrapper: wrong, RecipientPriv: recipientPriv.Bytes(),
	}); err != nil {
		t.Fatalf("re-derived wrapper failed to open (%v) — if this ever starts failing, "+
			"the enforcement point moved and ENC-ROUNDTRIP-FORMAT-1's rationale needs rewriting", err)
	}
	// Caught here instead: the recipient's published-key lookup.
	published := map[hash.Hash]bool{authored: true}
	if published[wrong.RecipientKey] {
		t.Fatal("re-derived recipient_key resolved against the recipient's published set")
	}
	if !published[ed.RecipientKey] {
		t.Fatal("correctly-bound recipient_key did not resolve against the published set")
	}
}
