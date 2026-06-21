package encryption

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestSelfRoundtrip — fast smoke that self-mode encrypt+decrypt round-trips
// with a cheap Argon2id profile (NOT the v1 baseline). Used to exercise
// every code path without paying the 64 MiB / 3 pass Argon2id cost on
// every test invocation.
func TestSelfRoundtrip(t *testing.T) {
	cheap := types.KDFParams{
		Argon2Version: types.Argon2idVersion,
		MemoryCost:    8, // 8 KiB
		TimeCost:      1,
		Parallelism:   1,
		OutputLen:     32,
	}
	plaintext := []byte("the canary sings at midnight")
	passphrase := []byte("super-secret-passphrase-1234")

	ed, err := SelfEncrypt(passphrase, "test-key", plaintext, SelfEncryptParams{Params: cheap})
	if err != nil {
		t.Fatalf("SelfEncrypt: %v", err)
	}
	if ed.Mode != types.EncryptionModeSelf {
		t.Fatalf("Mode = %q, want %q", ed.Mode, types.EncryptionModeSelf)
	}
	if len(ed.Nonce) != AEADNonceSize {
		t.Fatalf("Nonce len = %d, want %d", len(ed.Nonce), AEADNonceSize)
	}
	if len(ed.KDFSalt) < KDFSaltMinBytes {
		t.Fatalf("KDFSalt len = %d, want >= %d", len(ed.KDFSalt), KDFSaltMinBytes)
	}
	if len(ed.Ciphertext) != len(plaintext)+AEADOverhead {
		t.Fatalf("Ciphertext len = %d, want %d", len(ed.Ciphertext), len(plaintext)+AEADOverhead)
	}

	got, err := SelfDecrypt(passphrase, ed)
	if err != nil {
		t.Fatalf("SelfDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}

	// Wrong passphrase → encryption_aead_failed.
	if _, err := SelfDecrypt([]byte("wrong-passphrase-1234567"), ed); err == nil {
		t.Fatalf("SelfDecrypt with wrong passphrase: want error, got nil")
	}
}

// TestSelfAADTamperDetection — flipping any AAD-bound field MUST cause
// decryption to fail (encryption_aead_failed). Covers ENC-AAD-1 for
// self mode.
func TestSelfAADTamperDetection(t *testing.T) {
	cheap := types.KDFParams{Argon2Version: types.Argon2idVersion, MemoryCost: 8, TimeCost: 1, Parallelism: 1, OutputLen: 32}
	plaintext := []byte("aad-tamper-canary")
	passphrase := []byte("aad-tamper-passphrase")
	ed, err := SelfEncrypt(passphrase, "test-key", plaintext, SelfEncryptParams{Params: cheap})
	if err != nil {
		t.Fatalf("SelfEncrypt: %v", err)
	}

	// Flipping the nonce → AAD changes → tag fails.
	tamperedNonce := bytes.Clone(ed.Nonce)
	tamperedNonce[0] ^= 0xFF
	bad := ed
	bad.Nonce = tamperedNonce
	if _, err := SelfDecrypt(passphrase, bad); err == nil {
		t.Fatalf("tampered nonce: want error, got nil")
	}

	// Flipping the kdf_salt → AAD changes → tag fails (and also re-derives
	// a different aead_key, so this is doubly-detected).
	tamperedSalt := bytes.Clone(ed.KDFSalt)
	tamperedSalt[0] ^= 0xFF
	bad = ed
	bad.KDFSalt = tamperedSalt
	if _, err := SelfDecrypt(passphrase, bad); err == nil {
		t.Fatalf("tampered kdf_salt: want error, got nil")
	}

	// Flipping the kdf_params → AAD changes → tag fails (F2-4: params now
	// bound into AAD; v2.3 missed this, v2.4 closed it).
	tamperedParams := *ed.KDFParams
	tamperedParams.TimeCost = ed.KDFParams.TimeCost + 1
	bad = ed
	bad.KDFParams = &tamperedParams
	if _, err := SelfDecrypt(passphrase, bad); err == nil {
		t.Fatalf("tampered kdf_params: want error, got nil")
	}

	// Flipping the key_id → AAD doesn't bind key_id directly, but HKDF info
	// does — so derivation diverges and tag fails.
	bad = ed
	bad.KeyID = "different-key"
	if _, err := SelfDecrypt(passphrase, bad); err == nil {
		t.Fatalf("tampered key_id: want error, got nil")
	}

	// Flipping a ciphertext byte → tag fails.
	tamperedCT := bytes.Clone(ed.Ciphertext)
	tamperedCT[0] ^= 0xFF
	bad = ed
	bad.Ciphertext = tamperedCT
	if _, err := SelfDecrypt(passphrase, bad); err == nil {
		t.Fatalf("tampered ciphertext: want error, got nil")
	}
}

// TestSelfKAT1 — §16.2 ENC-SELF-KAT-1 with the v2.4 8-key AAD shape and
// the v2.5 R3 ENC-KAT-INNER plaintext (system/note real-entity ECF).
// Produces reference AAD hex + ciphertext hex for the byte-pin lock
// (§16.5). Runs at v1 baseline Argon2id (m=65536, t=3, p=1) — slow but
// matches the spec's pinned inputs verbatim. Cohort byte-equality with
// Rust + Python + Keystone closes BLOCK-0.
//
// Pinned inputs per §16.2 (v2.5 R3):
//
//	mode             = "self"
//	enc_key_type     = 0x00
//	aead_id          = 0x01 (XChaCha20-Poly1305)
//	kdf_id           = 0x01 (HKDF-SHA-256)
//	nonce            = 24 bytes of 0x42
//	kdf_salt         = 16 bytes of 0x43
//	passphrase       = utf8("entity-core/test/self-kat-1")  (no NUL)
//	key_id           = "test-key-1"
//	kdf_params       = baseline (v1.3 / 64 MiB / t=3 / p=1 / 32 bytes)
//	plaintext        = ECF(ENC-KAT-INNER)  — system/note{body, created:0}
func TestSelfKAT1(t *testing.T) {
	if testing.Short() {
		t.Skip("ENC-SELF-KAT-1 runs Argon2id at v1 baseline (64 MiB / t=3) — slow; skip -short")
	}
	const (
		passphrase = "entity-core/test/self-kat-1"
		keyID      = "test-key-1"
	)
	plaintext, err := EncKATInnerPlaintext()
	if err != nil {
		t.Fatalf("EncKATInnerPlaintext: %v", err)
	}
	t.Logf("ENC-KAT-INNER plaintext (%d bytes): %s", len(plaintext), hex.EncodeToString(plaintext))
	nonce := bytes.Repeat([]byte{0x42}, 24)
	kdfSalt := bytes.Repeat([]byte{0x43}, 16)
	params := DefaultKDFParams()

	// Independently derive the AAD bytes so we can log them.
	aad, err := SelfAAD(types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256, nonce, kdfSalt, params)
	if err != nil {
		t.Fatalf("SelfAAD: %v", err)
	}
	t.Logf("ENC-SELF-KAT-1 AAD (%d bytes): %s", len(aad), hex.EncodeToString(aad))

	ed, err := SelfEncrypt(
		[]byte(passphrase),
		keyID,
		plaintext,
		SelfEncryptParams{Nonce: nonce, KDFSalt: kdfSalt, Params: params},
	)
	if err != nil {
		t.Fatalf("SelfEncrypt: %v", err)
	}
	t.Logf("ENC-SELF-KAT-1 ciphertext (%d bytes): %s", len(ed.Ciphertext), hex.EncodeToString(ed.Ciphertext))

	// Round-trip sanity.
	got, err := SelfDecrypt([]byte(passphrase), ed)
	if err != nil {
		t.Fatalf("SelfDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch")
	}
}
