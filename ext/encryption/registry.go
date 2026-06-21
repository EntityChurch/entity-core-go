package encryption

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/types"
)

// algorithm-byte name maps. These are debug/log labels; the wire is the
// byte itself per §3.

var encKeyTypeNames = map[byte]string{
	types.EncKeyTypeReserved:               "reserved",
	types.EncKeyTypeX25519:                 "X25519",
	types.EncKeyTypeX448:                   "X448",
	types.EncKeyTypeMLKEM768:               "ML-KEM-768",
	types.EncKeyTypeX25519MLKEM768Hybrid:   "X25519+ML-KEM-768",
	types.EncKeyTypeMLKEM512:               "ML-KEM-512",
	types.EncKeyTypeMLKEM1024:              "ML-KEM-1024",
	types.EncKeyTypeTestOnly:               "test-only",
}

var aeadIDNames = map[byte]string{
	types.AEADIDReserved:             "reserved",
	types.AEADIDXChaCha20Poly1305:    "XChaCha20-Poly1305",
	types.AEADIDAES256GCM:            "AES-256-GCM",
	types.AEADIDChaCha20Poly1305IETF: "ChaCha20-Poly1305-IETF",
	types.AEADIDAEGIS256:             "AEGIS-256",
}

var kdfIDNames = map[byte]string{
	types.KDFIDReserved:   "reserved",
	types.KDFIDHKDFSHA256: "HKDF-SHA-256",
	types.KDFIDHKDFSHA512: "HKDF-SHA-512",
	types.KDFIDHKDFSHA384: "HKDF-SHA-384",
	types.KDFIDArgon2id:   "Argon2id",
}

// EncKeyTypeName returns a human label for a registry byte; "unknown(0xNN)"
// for unregistered slots.
func EncKeyTypeName(b byte) string {
	if n, ok := encKeyTypeNames[b]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%02x)", b)
}

// AEADIDName returns a human label for a registry byte.
func AEADIDName(b byte) string {
	if n, ok := aeadIDNames[b]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%02x)", b)
}

// KDFIDName returns a human label for a registry byte.
func KDFIDName(b byte) string {
	if n, ok := kdfIDNames[b]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%02x)", b)
}

// SelfModeSuiteAllowed reports whether (aead_id, kdf_id) are allowed in
// self mode for v1 per §5.3. AEADs with 96-bit nonces are forbidden in
// self/group because a stable key + random 96-bit nonce risks collision.
func SelfModeSuiteAllowed(aeadID, kdfID byte) error {
	switch aeadID {
	case types.AEADIDXChaCha20Poly1305:
		// OK — 192-bit nonce safe under random sampling.
	case types.AEADIDAES256GCM, types.AEADIDChaCha20Poly1305IETF:
		return fmt.Errorf("%s: AEAD 0x%02x forbidden in self mode (96-bit nonce + stable key risks collision)",
			types.EncryptionErrUnsupportedSuite, aeadID)
	default:
		return fmt.Errorf("%s: AEAD 0x%02x not allowed in self mode for v1",
			types.EncryptionErrUnsupportedSuite, aeadID)
	}
	switch kdfID {
	case types.KDFIDHKDFSHA256:
		// OK — v1 floor.
	default:
		return fmt.Errorf("%s: KDF 0x%02x not allowed in self mode for v1",
			types.EncryptionErrUnsupportedSuite, kdfID)
	}
	return nil
}

// GroupModeSuiteAllowed mirrors SelfModeSuiteAllowed — same restrictions
// (the outer key is a stable random group_aead_key for the lifetime of
// the encrypted entity, so the nonce-reuse hazard applies identically).
func GroupModeSuiteAllowed(aeadID, kdfID byte) error {
	if err := SelfModeSuiteAllowed(aeadID, kdfID); err != nil {
		return err
	}
	return nil
}

// PeerModeSuiteAllowed reports whether the (enc_key_type, aead_id,
// kdf_id) triple is supported by this impl in peer mode for v1.
// XChaCha20-Poly1305 + HKDF-SHA-256 + X25519 is the v1 floor; AES-GCM
// and ChaCha20-IETF are allowed (per-message ephemeral key avoids
// nonce-reuse).
func PeerModeSuiteAllowed(encKeyType, aeadID, kdfID byte) error {
	switch encKeyType {
	case types.EncKeyTypeX25519:
		// OK — v1 floor.
	default:
		return fmt.Errorf("%s: enc_key_type 0x%02x not supported in peer mode for v1",
			types.EncryptionErrUnsupportedSuite, encKeyType)
	}
	switch aeadID {
	case types.AEADIDXChaCha20Poly1305:
		// OK.
	default:
		// AES-GCM / IETF-ChaCha20 are spec-allowed but not v1-impl-required.
		return fmt.Errorf("%s: AEAD 0x%02x not supported in peer mode for v1",
			types.EncryptionErrUnsupportedSuite, aeadID)
	}
	switch kdfID {
	case types.KDFIDHKDFSHA256:
		// OK.
	default:
		return fmt.Errorf("%s: KDF 0x%02x not supported in peer mode for v1",
			types.EncryptionErrUnsupportedSuite, kdfID)
	}
	return nil
}

// IntersectSuite picks the first (aead_id, kdf_id) triple that both sender
// and recipient advertise, per §3.4. Returns errNoCommonSuite if empty.
// Order is "first match in recipient's advertised order that sender also
// supports" — the recipient drives the preference.
func IntersectSuite(
	recipientAEAD, recipientKDF []uint,
	senderAEAD, senderKDF []uint,
) (aeadID, kdfID byte, err error) {
	senderAEADSet := make(map[uint]bool, len(senderAEAD))
	for _, v := range senderAEAD {
		senderAEADSet[v] = true
	}
	senderKDFSet := make(map[uint]bool, len(senderKDF))
	for _, v := range senderKDF {
		senderKDFSet[v] = true
	}
	for _, a := range recipientAEAD {
		if !senderAEADSet[a] {
			continue
		}
		for _, k := range recipientKDF {
			if !senderKDFSet[k] {
				continue
			}
			return byte(a), byte(k), nil
		}
	}
	return 0, 0, fmt.Errorf("%s: no common (aead_id, kdf_id) in recipient and sender advertised suites",
		types.EncryptionErrNoCommonSuite)
}
