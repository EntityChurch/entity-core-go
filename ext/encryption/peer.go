package encryption

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §7 mode=peer — non-interactive single-shot hybrid encryption to one
// recipient. PRIMARY in v1.0. Structurally equivalent to age / NaCl
// crypto_box / libsodium sealed-box.
//
// What this provides (§7.1 honest framing):
//   - Receiver authentication (only recipient-cert private holder decrypts)
//   - Sender ephemerality (fresh per-message keypair, discarded after)
//   - Sender authentication (via system/signature at invariant pointer,
//     wired by §7.4 sender-auth path — separate from this primitive)
//
// What this does NOT provide:
//   - Forward secrecy against recipient-key compromise (no ratchet)
//   - Interactive future-secrecy
//
// HKDF info pins the recipient_pubkey_hash uniform-across-tiers per F-GO-1
// — the bound bytes are hash.Bytes() (33-byte SHA-256 wire form: algorithm
// byte || 32-byte digest).
const peerInfoPrefix = "entity-core/peer/"

// X25519PrivateSize is the X25519 private-key seed length (32 bytes per RFC 7748).
const X25519PrivateSize = 32

// X25519PublicSize is the X25519 public-key length.
const X25519PublicSize = 32

// PeerEncryptInput pins the per-encryption inputs.
type PeerEncryptInput struct {
	// RecipientPubkey is the 32-byte X25519 public key as published in the
	// recipient's system/encryption-pubkey.public_key field.
	RecipientPubkey []byte

	// RecipientPubkeyHash is content_hash(system/encryption-pubkey) —
	// the F-GO-1 uniform-across-tiers binding. The caller resolves this
	// from the recipient namespace per §4.4; this primitive just consumes it.
	RecipientPubkeyHash hash.Hash

	// Plaintext is the raw bytes to encrypt — typically an inner entity's
	// ECF encoding; the caller chooses the framing.
	Plaintext []byte

	// Nonce, if non-empty, pins the AEAD nonce (KAT determinism). Empty →
	// freshly-random 24-byte nonce per §5.3.
	Nonce []byte

	// EphemeralPrivateSeed, if non-empty, pins the sender ephemeral X25519
	// private key (KAT determinism). Empty → freshly-random per §7.3 step 2.
	EphemeralPrivateSeed []byte
}

// PeerEncrypt produces a §7.2 peer-mode wrapper. Sender authentication
// (§7.4 system/signature at invariant pointer) is a SEPARATE step
// performed by the handler / caller layer once the wrapper's
// content_hash is known.
func PeerEncrypt(in PeerEncryptInput) (types.EncryptedData, error) {
	if len(in.RecipientPubkey) != X25519PublicSize {
		return types.EncryptedData{}, fmt.Errorf("%s: X25519 recipient pubkey must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PublicSize, len(in.RecipientPubkey))
	}
	if in.RecipientPubkeyHash.IsZero() {
		return types.EncryptedData{}, fmt.Errorf("%s: recipient_key hash required",
			types.EncryptionErrInvalidWrapper)
	}

	encKeyType := types.EncKeyTypeX25519
	aeadID := types.AEADIDXChaCha20Poly1305
	kdfID := types.KDFIDHKDFSHA256
	if err := PeerModeSuiteAllowed(encKeyType, aeadID, kdfID); err != nil {
		return types.EncryptedData{}, err
	}

	nonce := in.Nonce
	if len(nonce) == 0 {
		n, err := RandomNonce()
		if err != nil {
			return types.EncryptedData{}, err
		}
		nonce = n
	}
	if len(nonce) != AEADNonceSize {
		return types.EncryptedData{}, fmt.Errorf("%s: peer-mode nonce must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADNonceSize, len(nonce))
	}

	// Ephemeral X25519 keypair.
	ephPriv, ephPub, err := generateOrLoadX25519(in.EphemeralPrivateSeed)
	if err != nil {
		return types.EncryptedData{}, err
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(in.RecipientPubkey)
	if err != nil {
		return types.EncryptedData{}, fmt.Errorf("%s: invalid recipient X25519 pubkey: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	sharedSecret, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return types.EncryptedData{}, fmt.Errorf("%s: ECDH failed: %w",
			types.EncryptionErrInvalidWrapper, err)
	}

	aeadKey, err := peerDeriveAEADKey(sharedSecret, nonce, in.RecipientPubkeyHash)
	if err != nil {
		return types.EncryptedData{}, err
	}

	aad, err := PeerAAD(encKeyType, aeadID, kdfID, nonce, in.RecipientPubkeyHash, ephPub)
	if err != nil {
		return types.EncryptedData{}, err
	}
	ct, err := XChaChaEncrypt(aeadKey, nonce, aad, in.Plaintext)
	if err != nil {
		return types.EncryptedData{}, err
	}

	return types.EncryptedData{
		Mode:         types.EncryptionModePeer,
		EncKeyType:   uint(encKeyType),
		AEADID:       uint(aeadID),
		KDFID:        uint(kdfID),
		Nonce:        nonce,
		Ciphertext:   ct,
		EphemeralKey: ephPub,
		RecipientKey: in.RecipientPubkeyHash,
	}, nil
}

// PeerDecryptInput pins the per-decryption inputs.
type PeerDecryptInput struct {
	Wrapper       types.EncryptedData
	RecipientPriv []byte // 32-byte X25519 private (recipient-side)
}

// PeerDecrypt verifies + decrypts the peer-mode wrapper. The caller is
// responsible for matching Wrapper.RecipientKey against locally-held
// pubkey entities to find the corresponding private — this primitive
// just consumes the private once selected. Sender-signature verification
// (§7.4) is a separate step at the handler layer.
func PeerDecrypt(in PeerDecryptInput) ([]byte, error) {
	w := in.Wrapper
	if w.Mode != types.EncryptionModePeer {
		return nil, fmt.Errorf("%s: wrapper mode %q is not peer",
			types.EncryptionErrInvalidWrapper, w.Mode)
	}
	encKeyType := byte(w.EncKeyType)
	aeadID := byte(w.AEADID)
	kdfID := byte(w.KDFID)
	if err := PeerModeSuiteAllowed(encKeyType, aeadID, kdfID); err != nil {
		return nil, err
	}
	if len(in.RecipientPriv) != X25519PrivateSize {
		return nil, fmt.Errorf("%s: X25519 recipient priv must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PrivateSize, len(in.RecipientPriv))
	}
	if len(w.EphemeralKey) != X25519PublicSize {
		return nil, fmt.Errorf("%s: peer-mode ephemeral_key must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PublicSize, len(w.EphemeralKey))
	}

	priv, err := ecdh.X25519().NewPrivateKey(in.RecipientPriv)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid recipient priv: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(w.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid sender ephemeral_key: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	sharedSecret, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%s: ECDH failed: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	aeadKey, err := peerDeriveAEADKey(sharedSecret, w.Nonce, w.RecipientKey)
	if err != nil {
		return nil, err
	}
	aad, err := PeerAAD(encKeyType, aeadID, kdfID, w.Nonce, w.RecipientKey, w.EphemeralKey)
	if err != nil {
		return nil, err
	}
	return XChaChaDecrypt(aeadKey, w.Nonce, aad, w.Ciphertext)
}

// peerDeriveAEADKey runs the §7.3 step-4 HKDF derivation with the
// F-GO-1 uniform-across-tiers recipient_pubkey_hash bound as info.
func peerDeriveAEADKey(sharedSecret, nonce []byte, recipientPubkeyHash hash.Hash) ([]byte, error) {
	info := append([]byte(peerInfoPrefix), recipientPubkeyHash.Bytes()...)
	return HKDFSHA256(sharedSecret, nonce, info, AEADKeySize)
}

// generateOrLoadX25519 returns a usable X25519 keypair, generating fresh
// random bytes when seed is empty.
func generateOrLoadX25519(seed []byte) (*ecdh.PrivateKey, []byte, error) {
	if len(seed) == 0 {
		raw := make([]byte, X25519PrivateSize)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("random X25519 priv: %w", err)
		}
		seed = raw
	}
	if len(seed) != X25519PrivateSize {
		return nil, nil, fmt.Errorf("%s: X25519 priv seed must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PrivateSize, len(seed))
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 NewPrivateKey: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ComputePubkeyHash hashes a system/encryption-pubkey data shape to its
// canonical content_hash under the peer-wide default content_hash_format
// (SHA-256 floor; SHA-384 when active per v7.69 §4.5a). Helper for
// callers building KAT vectors or wiring §4.4 resolution against
// locally-constructed pubkey entities.
func ComputePubkeyHash(data types.EncryptionPubkeyData) (hash.Hash, error) {
	rawData, err := ecf.Encode(data)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode pubkey data: %w", err)
	}
	return hash.Compute(types.TypeEncryptionPubkey, rawData)
}
