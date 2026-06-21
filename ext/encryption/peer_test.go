package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestPeerRoundtrip — fresh recipient + fresh ephemeral, encrypt + decrypt
// round-trips. Exercises every PeerEncrypt / PeerDecrypt code path.
func TestPeerRoundtrip(t *testing.T) {
	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	recipientPub := recipientPriv.PublicKey().Bytes()

	pubkeyHash, err := ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        recipientPub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          0,
	})
	if err != nil {
		t.Fatalf("ComputePubkeyHash: %v", err)
	}

	plaintext := []byte("greetings from the sender")
	ed, err := PeerEncrypt(PeerEncryptInput{
		RecipientPubkey:     recipientPub,
		RecipientPubkeyHash: pubkeyHash,
		Plaintext:           plaintext,
	})
	if err != nil {
		t.Fatalf("PeerEncrypt: %v", err)
	}
	if ed.Mode != types.EncryptionModePeer {
		t.Fatalf("Mode = %q, want %q", ed.Mode, types.EncryptionModePeer)
	}
	if len(ed.EphemeralKey) != X25519PublicSize {
		t.Fatalf("EphemeralKey len = %d, want %d", len(ed.EphemeralKey), X25519PublicSize)
	}
	if ed.RecipientKey != pubkeyHash {
		t.Fatalf("RecipientKey mismatch")
	}

	got, err := PeerDecrypt(PeerDecryptInput{
		Wrapper:       ed,
		RecipientPriv: recipientPriv.Bytes(),
	})
	if err != nil {
		t.Fatalf("PeerDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q vs %q", got, plaintext)
	}

	// Wrong recipient → AEAD fails.
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := PeerDecrypt(PeerDecryptInput{Wrapper: ed, RecipientPriv: wrongPriv.Bytes()}); err == nil {
		t.Fatalf("wrong recipient: want error, got nil")
	}
}

// TestPeerAADTamperDetection — flipping any AAD-bound field MUST fail.
// Covers ENC-AAD-1 for peer mode.
func TestPeerAADTamperDetection(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pubkeyHash, _ := ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType: uint(types.EncKeyTypeX25519), PublicKey: recipientPriv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
	})
	ed, err := PeerEncrypt(PeerEncryptInput{
		RecipientPubkey:     recipientPriv.PublicKey().Bytes(),
		RecipientPubkeyHash: pubkeyHash,
		Plaintext:           []byte("tamper canary"),
	})
	if err != nil {
		t.Fatalf("PeerEncrypt: %v", err)
	}

	tamper := func(name string, mutate func(*types.EncryptedData)) {
		t.Helper()
		bad := ed
		mutate(&bad)
		if _, err := PeerDecrypt(PeerDecryptInput{Wrapper: bad, RecipientPriv: recipientPriv.Bytes()}); err == nil {
			t.Fatalf("tamper %q: want error, got nil", name)
		}
	}
	tamper("nonce", func(e *types.EncryptedData) {
		e.Nonce = bytes.Clone(e.Nonce)
		e.Nonce[0] ^= 0xFF
	})
	tamper("ephemeral_key", func(e *types.EncryptedData) {
		e.EphemeralKey = bytes.Clone(e.EphemeralKey)
		e.EphemeralKey[0] ^= 0xFF
	})
	tamper("ciphertext", func(e *types.EncryptedData) {
		e.Ciphertext = bytes.Clone(e.Ciphertext)
		e.Ciphertext[0] ^= 0xFF
	})
}

// TestPeerKAT1 — §16.3 ENC-PEER-KAT-1 with v2.4 7-key AAD shape and the
// v2.5 R3 ENC-KAT-INNER plaintext (system/note real-entity ECF).
// Produces reference hex for the byte-pin lock (§16.5).
//
// Pinned inputs per §16.3 (v2.5 R3):
//
//	mode             = "peer"
//	enc_key_type     = 0x01  (X25519)
//	aead_id          = 0x01
//	kdf_id           = 0x01
//	nonce            = 24 bytes of 0x44
//	recipient_seed   = 32 bytes of 0x45  (recipient static priv)
//	sender_eph_seed  = 32 bytes of 0x46  (sender ephemeral priv)
//	plaintext        = ECF(ENC-KAT-INNER) — same canonical inner as §16.2
//
// derived recipient_pubkey_hash = content_hash(system/encryption-pubkey{
//	enc_key_type:0x01, public_key:<recipient_pubkey>,
//	supported_aead_ids:[0x01], supported_kdf_ids:[0x01], created:0
// })
func TestPeerKAT1(t *testing.T) {
	recipientSeed := bytes.Repeat([]byte{0x45}, 32)
	senderEphSeed := bytes.Repeat([]byte{0x46}, 32)
	nonce := bytes.Repeat([]byte{0x44}, 24)
	plaintext, err := EncKATInnerPlaintext()
	if err != nil {
		t.Fatalf("EncKATInnerPlaintext: %v", err)
	}
	t.Logf("ENC-KAT-INNER plaintext (%d bytes): %s", len(plaintext), hex.EncodeToString(plaintext))

	recipientPriv, err := ecdh.X25519().NewPrivateKey(recipientSeed)
	if err != nil {
		t.Fatalf("recipient priv: %v", err)
	}
	recipientPub := recipientPriv.PublicKey().Bytes()
	t.Logf("recipient_pubkey (32B): %s", hex.EncodeToString(recipientPub))

	pubkeyHash, err := ComputePubkeyHash(types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        recipientPub,
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          0,
	})
	if err != nil {
		t.Fatalf("ComputePubkeyHash: %v", err)
	}
	t.Logf("recipient_pubkey_hash (33B wire): %s", hex.EncodeToString(pubkeyHash.Bytes()))

	// Derive sender ephemeral pub for logging.
	ephPriv, _ := ecdh.X25519().NewPrivateKey(senderEphSeed)
	t.Logf("sender_ephemeral_pubkey (32B): %s", hex.EncodeToString(ephPriv.PublicKey().Bytes()))

	aad, err := PeerAAD(
		types.EncKeyTypeX25519, types.AEADIDXChaCha20Poly1305, types.KDFIDHKDFSHA256,
		nonce, pubkeyHash, ephPriv.PublicKey().Bytes(),
	)
	if err != nil {
		t.Fatalf("PeerAAD: %v", err)
	}
	t.Logf("ENC-PEER-KAT-1 AAD (%d bytes): %s", len(aad), hex.EncodeToString(aad))

	ed, err := PeerEncrypt(PeerEncryptInput{
		RecipientPubkey:      recipientPub,
		RecipientPubkeyHash:  pubkeyHash,
		Plaintext:            plaintext,
		Nonce:                nonce,
		EphemeralPrivateSeed: senderEphSeed,
	})
	if err != nil {
		t.Fatalf("PeerEncrypt: %v", err)
	}
	t.Logf("ENC-PEER-KAT-1 ciphertext (%d bytes): %s", len(ed.Ciphertext), hex.EncodeToString(ed.Ciphertext))

	got, err := PeerDecrypt(PeerDecryptInput{
		Wrapper:       ed,
		RecipientPriv: recipientSeed,
	})
	if err != nil {
		t.Fatalf("PeerDecrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: %q vs %q", got, plaintext)
	}
}
