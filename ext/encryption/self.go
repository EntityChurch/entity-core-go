package encryption

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/types"
)

// §6 mode=self — at-rest storage encryption with key derived from a local
// secret. PRIMARY in v1.0.
//
// Derivation per §6.2:
//
//	kek      = Argon2id(passphrase, kdf_salt, version=0x13, m, t, p, output_len=32)
//	aead_key = HKDF-SHA-256(ikm=kek, salt=nonce, info=utf8("entity-core/self/")||utf8(key_id), L=32)
//
// AAD per §5.2 (8 keys, all-keys-present, F2-4 binds kdf_salt+kdf_params).
// Nonce + kdf_salt are random per §6.3; both are stored in the outer entity
// for receiver-side re-derivation.

// selfInfoPrefix is the §6.2 ASCII prefix bound into HKDF info. No
// separator, no NUL byte between prefix and key_id (F-GO-9).
const selfInfoPrefix = "entity-core/self/"

// SelfEncryptParams pins the per-encryption inputs that the spec marks
// random for §6.3 but that callers want to override for KAT vectors.
// Zero-value Nonce/KDFSalt → freshly generated; non-empty → used as-is.
// Params zero → DefaultKDFParams.
type SelfEncryptParams struct {
	Nonce   []byte
	KDFSalt []byte
	Params  types.KDFParams
}

// SelfEncrypt produces a §6.1 self-mode wrapper for the given plaintext
// bytes under (passphrase, key_id, params). Plaintext is the raw bytes
// to encrypt — typically the ECF encoding of an inner entity; the caller
// chooses the framing.
func SelfEncrypt(passphrase []byte, keyID string, plaintext []byte, p SelfEncryptParams) (types.EncryptedData, error) {
	if keyID == "" {
		return types.EncryptedData{}, fmt.Errorf("%s: self-mode key_id required",
			types.EncryptionErrInvalidWrapper)
	}
	params := p.Params
	if params.Argon2Version == 0 && params.MemoryCost == 0 && params.TimeCost == 0 {
		params = DefaultKDFParams()
	}
	nonce := p.Nonce
	if len(nonce) == 0 {
		n, err := RandomNonce()
		if err != nil {
			return types.EncryptedData{}, err
		}
		nonce = n
	}
	if len(nonce) != AEADNonceSize {
		return types.EncryptedData{}, fmt.Errorf("%s: self-mode nonce must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADNonceSize, len(nonce))
	}
	kdfSalt := p.KDFSalt
	if len(kdfSalt) == 0 {
		s, err := RandomSalt()
		if err != nil {
			return types.EncryptedData{}, err
		}
		kdfSalt = s
	}

	// v1 floor: XChaCha20-Poly1305 + HKDF-SHA-256.
	aeadID := types.AEADIDXChaCha20Poly1305
	kdfID := types.KDFIDHKDFSHA256
	if err := SelfModeSuiteAllowed(aeadID, kdfID); err != nil {
		return types.EncryptedData{}, err
	}

	aeadKey, err := selfDeriveAEADKey(passphrase, keyID, nonce, kdfSalt, params)
	if err != nil {
		return types.EncryptedData{}, err
	}

	aad, err := SelfAAD(aeadID, kdfID, nonce, kdfSalt, params)
	if err != nil {
		return types.EncryptedData{}, err
	}
	ct, err := XChaChaEncrypt(aeadKey, nonce, aad, plaintext)
	if err != nil {
		return types.EncryptedData{}, err
	}

	return types.EncryptedData{
		Mode:       types.EncryptionModeSelf,
		EncKeyType: 0,
		AEADID:     uint(aeadID),
		KDFID:      uint(kdfID),
		Nonce:      nonce,
		Ciphertext: ct,
		KeyID:      keyID,
		KDFSalt:    kdfSalt,
		KDFParams:  &params,
	}, nil
}

// SelfDecrypt verifies + decrypts the self-mode wrapper using passphrase
// resolution by key_id. Returns the plaintext on success or an
// encryption_aead_failed-flavored error on tag failure (wrong passphrase,
// tampered AAD, tampered ciphertext).
func SelfDecrypt(passphrase []byte, ed types.EncryptedData) ([]byte, error) {
	if ed.Mode != types.EncryptionModeSelf {
		return nil, fmt.Errorf("%s: wrapper mode %q is not self",
			types.EncryptionErrInvalidWrapper, ed.Mode)
	}
	if ed.KDFParams == nil {
		return nil, fmt.Errorf("%s: self-mode wrapper missing kdf_params",
			types.EncryptionErrInvalidWrapper)
	}
	aeadID := byte(ed.AEADID)
	kdfID := byte(ed.KDFID)
	if err := SelfModeSuiteAllowed(aeadID, kdfID); err != nil {
		return nil, err
	}
	if ed.KeyID == "" {
		return nil, fmt.Errorf("%s: self-mode wrapper missing key_id",
			types.EncryptionErrInvalidWrapper)
	}

	aeadKey, err := selfDeriveAEADKey(passphrase, ed.KeyID, ed.Nonce, ed.KDFSalt, *ed.KDFParams)
	if err != nil {
		return nil, err
	}
	aad, err := SelfAAD(aeadID, kdfID, ed.Nonce, ed.KDFSalt, *ed.KDFParams)
	if err != nil {
		return nil, err
	}
	return XChaChaDecrypt(aeadKey, ed.Nonce, aad, ed.Ciphertext)
}

// selfDeriveAEADKey runs the §6.2 derivation chain
// passphrase → Argon2id → HKDF-SHA-256 → 32-byte AEAD key.
func selfDeriveAEADKey(passphrase []byte, keyID string, nonce, kdfSalt []byte, params types.KDFParams) ([]byte, error) {
	kek, err := Argon2idKey(passphrase, kdfSalt, params)
	if err != nil {
		return nil, err
	}
	info := []byte(selfInfoPrefix + keyID)
	return HKDFSHA256(kek, nonce, info, AEADKeySize)
}
