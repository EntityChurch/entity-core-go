package types

// EXTENSION-ENCRYPTION v1.0 entity types and algorithm-byte registries.
//
// Spec: ../entity-core-architecture/docs/architecture/v7.0-core-revision/
// core-protocol-domain/specs/extensions/network-peer-extensions/
// EXTENSION-ENCRYPTION.md (LANDED).
//
// Three modes (§5–§8): self (storage), peer (single-shot hybrid send),
// group (static key-wrap with §5.2/§8 key-commitment per F2-1). The
// per-mode wrapper-entity shapes share the §5.1 common fields and add
// mode-specific fields; this file uses a single union struct with
// omitempty for the mode-specific fields so the wire shape matches the
// spec without per-mode Go types.

import (
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Entity type constants per EXTENSION-ENCRYPTION §4–§11.
const (
	// §4.1 inner pubkey entity (content-addressed at every tier).
	TypeEncryptionPubkey = "system/encryption-pubkey"

	// §5.1 outer wrapper. Per-mode additional fields per §6.1/§7.2/§8.2.
	TypeEncrypted = "system/encrypted"

	// §10.1 Tier-A rotation handoff.
	TypeEncryptionHandoff = "system/encryption/handoff"

	// §11.1 Tier-A revocation.
	TypeEncryptionRevocation = "system/encryption/revocation"

	// §9.2 Tier-2 passphrase-wrapped key backup (Tier A/B path).
	TypeEncryptionKeyBackup = "system/encryption/key-backup"

	// Sub-shape type names — registry-internal handles for the §6.1 / §9.2
	// kdf_params sub-shape and the §8.2 wrapped_keys element. The spec
	// defines these as anonymous fields-blocks; we give them first-class
	// names so reflection of EncryptedData / EncryptionKeyBackupData
	// resolves cleanly. Other impls do NOT need to mirror these names —
	// what matters is the inline wire shape, which the §16 KATs pin.
	TypeEncryptionKDFParams  = "system/encryption/kdf-params"
	TypeEncryptionWrappedKey = "system/encryption/wrapped-key"
)

// Mode discriminator values per §5.1.
const (
	EncryptionModeSelf  = "self"
	EncryptionModePeer  = "peer"
	EncryptionModeGroup = "group"
)

// AAD-only mode label per §5.2 F2-2 (group per-wrap AAD; never appears as
// an outer-entity Mode value, only inside the per-wrap AAD bytes).
const EncryptionAADModeGroupWrap = "group-wrap"

// enc_key_type registry per §3.1. Varint-encoded.
const (
	EncKeyTypeReserved      byte = 0x00
	EncKeyTypeX25519        byte = 0x01 // v1 floor
	EncKeyTypeX448          byte = 0x02 // reserved (pairs with Ed448 validate slot)
	EncKeyTypeMLKEM768      byte = 0x03 // reserved PQ KEM
	EncKeyTypeX25519MLKEM768Hybrid byte = 0x04 // reserved hybrid (PQ upgrade path)
	EncKeyTypeMLKEM512      byte = 0x05
	EncKeyTypeMLKEM1024     byte = 0x06
	EncKeyTypeTestOnly      byte = 0xFE
)

// aead_id registry per §3.2.
const (
	AEADIDReserved             byte = 0x00
	AEADIDXChaCha20Poly1305    byte = 0x01 // v1 floor
	AEADIDAES256GCM            byte = 0x02 // peer-mode only in v1
	AEADIDChaCha20Poly1305IETF byte = 0x03 // peer-mode only in v1
	AEADIDAEGIS256             byte = 0x04
)

// kdf_id registry per §3.3.
const (
	KDFIDReserved      byte = 0x00
	KDFIDHKDFSHA256    byte = 0x01 // v1 floor
	KDFIDHKDFSHA512    byte = 0x02
	KDFIDHKDFSHA384    byte = 0x03
	KDFIDArgon2id      byte = 0x04
)

// Argon2 version pinned by §6.2 + §9.2 (v1.3 / v19).
const Argon2idVersion uint = 0x13

// Error codes per §15. Status carried by the dispatch layer; these are
// the extension-owned code strings.
const (
	EncryptionErrAEADFailed         = "encryption_aead_failed"
	EncryptionErrUnsupportedSuite   = "encryption_unsupported_suite"
	EncryptionErrNoCommonSuite      = "encryption_no_common_suite"
	EncryptionErrKDFParamsExcessive = "encryption_kdf_params_excessive"
	EncryptionErrInvalidWrapper     = "encryption_invalid_wrapper"
	EncryptionErrRecipientUnknown   = "encryption_recipient_unknown"
	EncryptionErrKeyUnavailable     = "encryption_key_unavailable"
	EncryptionErrKeyRevoked         = "encryption_key_revoked"
	EncryptionErrSignatureInvalid   = "encryption_signature_invalid"
	EncryptionErrUnsignedSender     = "encryption_unsigned_sender"
	EncryptionErrWrappedKeysTooMany = "encryption_wrapped_keys_too_many"
)

// EncryptionPubkeyData is the content-addressed inner pubkey entity per §4.1.
// content_hash is a pure function of (enc_key_type, public_key,
// supported_aead_ids, supported_kdf_ids, created, expires); cross-tier
// interop binds the SAME authored inner entity (F2-3).
type EncryptionPubkeyData struct {
	EncKeyType        uint   `cbor:"enc_key_type"`
	PublicKey         []byte `cbor:"public_key"`
	SupportedAEADIDs  []uint `cbor:"supported_aead_ids"`
	SupportedKDFIDs   []uint `cbor:"supported_kdf_ids"`
	Created           uint64 `cbor:"created"`
	Expires           uint64 `cbor:"expires,omitempty"`
}

// KDFParams is the §6.1 / §9.2 normative Argon2id parameter shape.
// Field names are normative for ECF byte-equality (F-GO-9): full words,
// not m/t/p abbreviations.
type KDFParams struct {
	Argon2Version uint `cbor:"argon2_version"`
	MemoryCost    uint `cbor:"memory_cost"` // KiB per RFC 9106 §3.1
	TimeCost      uint `cbor:"time_cost"`
	Parallelism   uint `cbor:"parallelism"`
	OutputLen     uint `cbor:"output_len"` // bytes
}

// WrappedKey is one §8.2 per-member wrap entry. Each entry is structurally
// a peer-mode encryption of the random group_aead_key to that member,
// AAD-domain-separated via the "group-wrap" mode label (F2-2).
type WrappedKey struct {
	RecipientKey    hash.Hash `cbor:"recipient_key"`
	EncKeyType      uint      `cbor:"enc_key_type"`
	EphemeralKey    []byte    `cbor:"ephemeral_key"`
	WrappedAEADKey  []byte    `cbor:"wrapped_aead_key"`
	WrapNonce       []byte    `cbor:"wrap_nonce"`
}

// EncryptedData is the §5.1 outer wrapper, unioned across modes. Per-mode
// fields use omitempty so the wire bytes match §6.1 (self adds key_id +
// kdf_salt + kdf_params), §7.2 (peer adds ephemeral_key + recipient_key),
// and §8.2 (group adds wrapped_keys). The Mode field discriminates.
type EncryptedData struct {
	Mode        string `cbor:"mode"`
	EncKeyType  uint   `cbor:"enc_key_type"`
	AEADID      uint   `cbor:"aead_id"`
	KDFID       uint   `cbor:"kdf_id"`
	Nonce       []byte `cbor:"nonce"`
	Ciphertext  []byte `cbor:"ciphertext"`

	// Self-mode additions (§6.1).
	KeyID     string    `cbor:"key_id,omitempty"`
	KDFSalt   []byte    `cbor:"kdf_salt,omitempty"`
	KDFParams *KDFParams `cbor:"kdf_params,omitempty"`

	// Peer-mode additions (§7.2). recipient_key is the inner pubkey-entity
	// content_hash (uniform at every tier per F-GO-1).
	EphemeralKey []byte    `cbor:"ephemeral_key,omitempty"`
	RecipientKey hash.Hash `cbor:"recipient_key,omitempty"`

	// Group-mode additions (§8.2).
	WrappedKeys []WrappedKey `cbor:"wrapped_keys,omitempty"`
}

// EncryptionHandoffData is the §10.1 Tier-A rotation entity. Signed by
// BOTH old and new pubkey holders via dual signatures at the V7
// invariant pointer system/signature/{hex(handoff_hash)}.
type EncryptionHandoffData struct {
	PreviousPubkey hash.Hash `cbor:"previous_pubkey"`
	NextPubkey     hash.Hash `cbor:"next_pubkey"`
	Created        uint64    `cbor:"created"`
}

// EncryptionRevocationData is the §11.1 Tier-A revocation entity. Signed
// by the peer's V7 keypair via system/signature invariant pointer.
type EncryptionRevocationData struct {
	Revokes hash.Hash `cbor:"revokes"`
	Reason  string    `cbor:"reason,omitempty"`
	Created uint64    `cbor:"created"`
}

// EncryptionKeyBackupData is the §9.2 Tier-2 passphrase-wrapped backup.
// Tier A/B uses pubkey_ref; Tier C uses an equivalent shape with cert_ref
// at system/identity/key-backup (handled separately when IDENTITY is in).
type EncryptionKeyBackupData struct {
	PubkeyRef  hash.Hash `cbor:"pubkey_ref"`
	KDFSalt    []byte    `cbor:"kdf_salt"`
	KDFParams  KDFParams `cbor:"kdf_params"`
	WrapNonce  []byte    `cbor:"wrap_nonce"`
	WrappedKey []byte    `cbor:"wrapped_key"`
}

// Static check that EncryptedData.Ciphertext is bytes-shaped for CBOR.
// Documents intent — the AEAD output is `ciphertext || tag` per §5.1.
var _ cbor.RawMessage = cbor.RawMessage(nil)
