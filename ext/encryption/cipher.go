package encryption

import (
	"crypto/rand"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/types"

	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20-Poly1305 AEAD per §3.2 entry 0x01 (v1 floor).
//
// 256-bit key, 192-bit nonce, 128-bit tag. RFC 8439 + XSalsa20 nonce
// extension. Safe under random nonces — collision probability ≈ 2⁻⁹⁶
// after 2⁴⁸ messages per key (§5.3 birthday-bound calc).

// AEADKeySize is the XChaCha20-Poly1305 key length in bytes.
const AEADKeySize = chacha20poly1305.KeySize

// AEADNonceSize is the XChaCha20-Poly1305 nonce length in bytes.
const AEADNonceSize = chacha20poly1305.NonceSizeX

// AEADOverhead is the Poly1305 tag length in bytes (appended to ciphertext).
const AEADOverhead = chacha20poly1305.Overhead

// XChaChaEncrypt produces ciphertext||tag for the given key+nonce+AAD.
// Returns an unsupported-suite error if the key/nonce lengths are wrong.
func XChaChaEncrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 requires %d-byte key, got %d",
			types.EncryptionErrUnsupportedSuite, AEADKeySize, len(key))
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 requires %d-byte nonce, got %d",
			types.EncryptionErrUnsupportedSuite, AEADNonceSize, len(nonce))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 init: %w",
			types.EncryptionErrUnsupportedSuite, err)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// XChaChaDecrypt verifies + decrypts ciphertext||tag. On tag failure it
// returns the §15 encryption_aead_failed error code in the error string.
func XChaChaDecrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 requires %d-byte key, got %d",
			types.EncryptionErrUnsupportedSuite, AEADKeySize, len(key))
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 requires %d-byte nonce, got %d",
			types.EncryptionErrUnsupportedSuite, AEADNonceSize, len(nonce))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%s: XChaCha20-Poly1305 init: %w",
			types.EncryptionErrUnsupportedSuite, err)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%s: AEAD tag verification failed: %w",
			types.EncryptionErrAEADFailed, err)
	}
	return pt, nil
}

// RandomNonce returns AEADNonceSize cryptographically random bytes for use
// as an XChaCha20-Poly1305 nonce.
func RandomNonce() ([]byte, error) {
	b := make([]byte, AEADNonceSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random nonce: %w", err)
	}
	return b, nil
}

// RandomKey returns AEADKeySize cryptographically random bytes. Used by
// group mode to mint a fresh group_aead_key per encrypted entity.
func RandomKey() ([]byte, error) {
	b := make([]byte, AEADKeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random key: %w", err)
	}
	return b, nil
}
