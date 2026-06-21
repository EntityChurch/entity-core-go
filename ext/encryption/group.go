package encryption

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §8 mode=group — static key-wrap for a fixed member set (≤256 default).
// Best-effort in v1.0.
//
// Construction (§8.3):
//
//	group_aead_key := random 32 bytes
//	commitment     := SHA-256(group_aead_key)                              (F2-1)
//	outer_AAD      := GroupOuterAAD(... commitment ...)                    (§5.2 7-key)
//	ciphertext     := AEAD(group_aead_key, outer_nonce, outer_AAD, inner)
//	for each member M:
//	    fresh per-wrap ephemeral keypair + per-wrap nonce
//	    wrap_AAD          := GroupWrapAAD(... M.pubkey_hash ... ephem ...) (§5.2 7-key, mode="group-wrap" — F2-2)
//	    wrap_aead_key     := HKDF(ECDH(eph_priv, M.pubkey), wrap_nonce, "entity-core/peer/"||M.pubkey_hash.Bytes())
//	    wrapped_aead_key  := AEAD(wrap_aead_key, wrap_nonce, wrap_AAD, group_aead_key)
//
// Per-wrap derivation re-uses the §7.3 peer-mode HKDF info exactly
// (peerInfoPrefix + recipient_pubkey_hash.Bytes()) — same key schedule
// as a stand-alone peer-mode message except for the AAD label, which
// domain-separates a lifted wrap from a replayable peer-mode message.
//
// F2-1 key-commitment closes the invisible-salamanders class: a lying
// author cannot equivocate one signed outer ciphertext into divergent
// plaintexts under different per-member wrapped keys because the AAD's
// commitment binds the single group_aead_key and any other reconstruction
// gets a different AAD → AEAD.Open fails.

// GroupMaxMembers is the §8.6 default ceiling for wrapped_keys entries.
const GroupMaxMembers = 256

// GroupMember pins the per-member encryption-target inputs.
type GroupMember struct {
	Pubkey     []byte    // 32-byte X25519 public
	PubkeyHash hash.Hash // content_hash(system/encryption-pubkey) per F-GO-1

	// EphemeralPrivateSeed pins the per-wrap ephemeral seed for KAT
	// determinism. Empty → freshly-random per §8.3.
	EphemeralPrivateSeed []byte

	// WrapNonce pins the per-wrap nonce for KAT determinism. Empty →
	// freshly-random.
	WrapNonce []byte
}

// GroupEncryptInput pins per-encryption inputs.
type GroupEncryptInput struct {
	Members   []GroupMember
	Plaintext []byte

	// OuterNonce pins the outer-ciphertext nonce. Empty → random.
	OuterNonce []byte

	// GroupAEADKey pins the random 32-byte group_aead_key for KAT
	// determinism. Empty → freshly-random per §8.3.
	GroupAEADKey []byte
}

// GroupEncrypt produces a §8.2 group-mode wrapper. Sender authentication
// (§7.4 single signature over the outer entity) is the handler layer's
// job.
func GroupEncrypt(in GroupEncryptInput) (types.EncryptedData, error) {
	if len(in.Members) == 0 {
		return types.EncryptedData{}, fmt.Errorf("%s: group encrypt requires at least one member",
			types.EncryptionErrInvalidWrapper)
	}
	if len(in.Members) > GroupMaxMembers {
		return types.EncryptedData{}, fmt.Errorf("%s: group has %d members, ceiling %d (§8.6)",
			types.EncryptionErrWrappedKeysTooMany, len(in.Members), GroupMaxMembers)
	}

	aeadID := types.AEADIDXChaCha20Poly1305
	kdfID := types.KDFIDHKDFSHA256
	if err := GroupModeSuiteAllowed(aeadID, kdfID); err != nil {
		return types.EncryptedData{}, err
	}

	groupKey := in.GroupAEADKey
	if len(groupKey) == 0 {
		k, err := RandomKey()
		if err != nil {
			return types.EncryptedData{}, err
		}
		groupKey = k
	}
	if len(groupKey) != AEADKeySize {
		return types.EncryptedData{}, fmt.Errorf("%s: group_aead_key must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADKeySize, len(groupKey))
	}

	outerNonce := in.OuterNonce
	if len(outerNonce) == 0 {
		n, err := RandomNonce()
		if err != nil {
			return types.EncryptedData{}, err
		}
		outerNonce = n
	}
	if len(outerNonce) != AEADNonceSize {
		return types.EncryptedData{}, fmt.Errorf("%s: group outer nonce must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADNonceSize, len(outerNonce))
	}

	outerAAD, err := GroupOuterAAD(aeadID, kdfID, outerNonce, groupKey)
	if err != nil {
		return types.EncryptedData{}, err
	}
	outerCT, err := XChaChaEncrypt(groupKey, outerNonce, outerAAD, in.Plaintext)
	if err != nil {
		return types.EncryptedData{}, err
	}

	wraps := make([]types.WrappedKey, 0, len(in.Members))
	for i, m := range in.Members {
		w, err := wrapForMember(m, groupKey, aeadID, kdfID)
		if err != nil {
			return types.EncryptedData{}, fmt.Errorf("wrap for member[%d]: %w", i, err)
		}
		wraps = append(wraps, w)
	}

	return types.EncryptedData{
		Mode:        types.EncryptionModeGroup,
		EncKeyType:  0, // outer level — group_aead_key is symmetric
		AEADID:      uint(aeadID),
		KDFID:       uint(kdfID),
		Nonce:       outerNonce,
		Ciphertext:  outerCT,
		WrappedKeys: wraps,
	}, nil
}

// GroupDecryptInput pins per-decryption inputs.
type GroupDecryptInput struct {
	Wrapper types.EncryptedData

	// MyPubkeyHash is the receiver's own pubkey-entity content_hash, used
	// to locate which wrapped_keys entry to open.
	MyPubkeyHash hash.Hash

	// MyPriv is the receiver's 32-byte X25519 private corresponding to
	// MyPubkeyHash.
	MyPriv []byte
}

// GroupDecrypt scans wrapped_keys for the receiver's entry, recovers
// group_aead_key via the §5.2 group-wrap AAD path, reconstructs the
// outer AAD with commitment = SHA-256(group_aead_key) (F2-1), and
// AEAD-decrypts the outer ciphertext. If the author equivocated under
// the invisible-salamanders class, the reconstructed-AAD AEAD.Open
// fails with encryption_aead_failed.
func GroupDecrypt(in GroupDecryptInput) ([]byte, error) {
	w := in.Wrapper
	if w.Mode != types.EncryptionModeGroup {
		return nil, fmt.Errorf("%s: wrapper mode %q is not group",
			types.EncryptionErrInvalidWrapper, w.Mode)
	}
	if len(in.MyPriv) != X25519PrivateSize {
		return nil, fmt.Errorf("%s: X25519 priv must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PrivateSize, len(in.MyPriv))
	}
	aeadID := byte(w.AEADID)
	kdfID := byte(w.KDFID)
	if err := GroupModeSuiteAllowed(aeadID, kdfID); err != nil {
		return nil, err
	}

	var groupKey []byte
	for _, wk := range w.WrappedKeys {
		if wk.RecipientKey != in.MyPubkeyHash {
			continue
		}
		gk, err := unwrapMember(wk, in.MyPriv, aeadID, kdfID)
		if err != nil {
			return nil, err
		}
		groupKey = gk
		break
	}
	if groupKey == nil {
		return nil, fmt.Errorf("%s: no wrapped_keys entry matches my pubkey_hash",
			types.EncryptionErrRecipientUnknown)
	}

	outerAAD, err := GroupOuterAAD(aeadID, kdfID, w.Nonce, groupKey)
	if err != nil {
		return nil, err
	}
	return XChaChaDecrypt(groupKey, w.Nonce, outerAAD, w.Ciphertext)
}

// wrapForMember runs the §8.3 step-5 per-member wrap: peer-mode-shaped
// hybrid encryption to the member, with AAD domain-separated by the
// "group-wrap" mode label.
func wrapForMember(m GroupMember, groupKey []byte, aeadID, kdfID byte) (types.WrappedKey, error) {
	if len(m.Pubkey) != X25519PublicSize {
		return types.WrappedKey{}, fmt.Errorf("%s: member X25519 pubkey must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, X25519PublicSize, len(m.Pubkey))
	}
	if m.PubkeyHash.IsZero() {
		return types.WrappedKey{}, fmt.Errorf("%s: member pubkey_hash required",
			types.EncryptionErrInvalidWrapper)
	}
	ephPriv, ephPub, err := generateOrLoadX25519(m.EphemeralPrivateSeed)
	if err != nil {
		return types.WrappedKey{}, err
	}
	wrapNonce := m.WrapNonce
	if len(wrapNonce) == 0 {
		n, err := RandomNonce()
		if err != nil {
			return types.WrappedKey{}, err
		}
		wrapNonce = n
	}
	if len(wrapNonce) != AEADNonceSize {
		return types.WrappedKey{}, fmt.Errorf("%s: wrap_nonce must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADNonceSize, len(wrapNonce))
	}

	memberPub, err := ecdh.X25519().NewPublicKey(m.Pubkey)
	if err != nil {
		return types.WrappedKey{}, fmt.Errorf("%s: invalid member X25519 pubkey: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	sharedSecret, err := ephPriv.ECDH(memberPub)
	if err != nil {
		return types.WrappedKey{}, fmt.Errorf("%s: per-wrap ECDH failed: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	wrapKey, err := peerDeriveAEADKey(sharedSecret, wrapNonce, m.PubkeyHash)
	if err != nil {
		return types.WrappedKey{}, err
	}
	aad, err := GroupWrapAAD(types.EncKeyTypeX25519, aeadID, kdfID, wrapNonce, m.PubkeyHash, ephPub)
	if err != nil {
		return types.WrappedKey{}, err
	}
	wrapped, err := XChaChaEncrypt(wrapKey, wrapNonce, aad, groupKey)
	if err != nil {
		return types.WrappedKey{}, err
	}
	return types.WrappedKey{
		RecipientKey:   m.PubkeyHash,
		EncKeyType:     uint(types.EncKeyTypeX25519),
		EphemeralKey:   ephPub,
		WrappedAEADKey: wrapped,
		WrapNonce:      wrapNonce,
	}, nil
}

// unwrapMember runs the §8.4 step-3 inverse — recover group_aead_key
// from a wrap entry the receiver owns.
func unwrapMember(wk types.WrappedKey, myPriv []byte, aeadID, kdfID byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(myPriv)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid receiver priv: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(wk.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid wrap ephemeral_key: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	sharedSecret, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%s: per-wrap ECDH failed: %w",
			types.EncryptionErrInvalidWrapper, err)
	}
	wrapKey, err := peerDeriveAEADKey(sharedSecret, wk.WrapNonce, wk.RecipientKey)
	if err != nil {
		return nil, err
	}
	aad, err := GroupWrapAAD(byte(wk.EncKeyType), aeadID, kdfID, wk.WrapNonce, wk.RecipientKey, wk.EphemeralKey)
	if err != nil {
		return nil, err
	}
	return XChaChaDecrypt(wrapKey, wk.WrapNonce, aad, wk.WrappedAEADKey)
}

// Commitment returns SHA-256(groupAEADKey) — the F2-1 binding emitted
// into the §5.2 group-outer AAD. Exported for tests / debugging only.
func Commitment(groupAEADKey []byte) []byte {
	sum := sha256.Sum256(groupAEADKey)
	return sum[:]
}
