package encryption

import (
	"crypto/sha256"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §5.2 AAD builders. All four shapes are deterministic ECF (RFC 8949 §4.2
// length-first) maps with fixed key sets per mode — the all-keys-present
// discipline closes the v7.67 Phase-2 byte-pin trap (omitted vs
// present-empty divergence). Empty-bytes keys are emitted as zero-length
// byte strings, NOT omitted, NOT null. Cohort byte-equality across Go +
// Rust + Python depends on this.

// emptyBytes is the canonical encoding-input for the all-keys-present
// empty-bytes slots ("recipient_key": empty in self / group-outer).
// CBOR encodes a non-nil zero-length []byte as major-type-2 length-0.
var emptyBytes = []byte{}

// SelfAAD builds the §5.2 self-mode 8-key AAD bytes:
//
//	{mode, enc_key_type, aead_id, kdf_id, nonce, kdf_salt, kdf_params, recipient_key}
//
// v2.4 F2-4 expanded this from 6 to 8 keys by binding kdf_salt + kdf_params
// (mirroring §9.2 backup); v2.3 Go prototype hex is superseded by this
// shape. enc_key_type is always 0 for self mode.
func SelfAAD(aeadID, kdfID byte, nonce, kdfSalt []byte, params types.KDFParams) ([]byte, error) {
	m := map[string]interface{}{
		"mode":          types.EncryptionModeSelf,
		"enc_key_type":  uint(0),
		"aead_id":       uint(aeadID),
		"kdf_id":        uint(kdfID),
		"nonce":         nonce,
		"kdf_salt":      kdfSalt,
		"kdf_params":    params,
		"recipient_key": emptyBytes,
	}
	b, err := ecf.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("%s: encode self AAD: %w", types.EncryptionErrInvalidWrapper, err)
	}
	return b, nil
}

// PeerAAD builds the §5.2 peer-mode 7-key AAD bytes:
//
//	{mode, enc_key_type, aead_id, kdf_id, nonce, recipient_key, ephemeral_key}
//
// recipient_key is the inner system/encryption-pubkey content_hash —
// uniform at every tier per F-GO-1. Hash is ECF-encoded as a CBOR byte
// string via hash.Hash's own MarshalCBOR (33 bytes: algorithm || digest).
func PeerAAD(encKeyType, aeadID, kdfID byte, nonce []byte, recipientKey hash.Hash, ephemeralKey []byte) ([]byte, error) {
	m := map[string]interface{}{
		"mode":          types.EncryptionModePeer,
		"enc_key_type":  uint(encKeyType),
		"aead_id":       uint(aeadID),
		"kdf_id":        uint(kdfID),
		"nonce":         nonce,
		"recipient_key": recipientKey,
		"ephemeral_key": ephemeralKey,
	}
	b, err := ecf.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("%s: encode peer AAD: %w", types.EncryptionErrInvalidWrapper, err)
	}
	return b, nil
}

// GroupOuterAAD builds the §5.2 group-outer 7-key AAD bytes:
//
//	{mode, enc_key_type=0, aead_id, kdf_id, nonce, commitment, recipient_key=∅}
//
// commitment = SHA-256(group_aead_key) is the F2-1 key-commitment that
// closes the invisible-salamanders class: only the single committed key
// opens the outer ciphertext, so a malicious author cannot equivocate
// (produce one signed outer ciphertext opening to divergent plaintexts
// under different per-member-wrapped keys).
func GroupOuterAAD(aeadID, kdfID byte, nonce []byte, groupAEADKey []byte) ([]byte, error) {
	commitment := sha256.Sum256(groupAEADKey)
	m := map[string]interface{}{
		"mode":          types.EncryptionModeGroup,
		"enc_key_type":  uint(0),
		"aead_id":       uint(aeadID),
		"kdf_id":        uint(kdfID),
		"nonce":         nonce,
		"commitment":    commitment[:],
		"recipient_key": emptyBytes,
	}
	b, err := ecf.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("%s: encode group-outer AAD: %w", types.EncryptionErrInvalidWrapper, err)
	}
	return b, nil
}

// GroupWrapAAD builds the §5.2 group-per-wrap 7-key AAD bytes:
//
//	{mode="group-wrap", enc_key_type, aead_id, kdf_id, nonce, recipient_key, ephemeral_key}
//
// F2-2 domain separation: the mode label "group-wrap" (NOT "peer") makes
// a lifted wrap blob fail to verify as a standalone peer-mode message,
// closing the replay-as-peer-message gap from v2.3.
func GroupWrapAAD(encKeyType, aeadID, kdfID byte, wrapNonce []byte, memberKey hash.Hash, ephemeralKey []byte) ([]byte, error) {
	m := map[string]interface{}{
		"mode":          types.EncryptionAADModeGroupWrap,
		"enc_key_type":  uint(encKeyType),
		"aead_id":       uint(aeadID),
		"kdf_id":        uint(kdfID),
		"nonce":         wrapNonce,
		"recipient_key": memberKey,
		"ephemeral_key": ephemeralKey,
	}
	b, err := ecf.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("%s: encode group-wrap AAD: %w", types.EncryptionErrInvalidWrapper, err)
	}
	return b, nil
}
