package encryption

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-ENCRYPTION §8.5 — group lifecycle (add / remove).
//
// **Add member.** Publish a new system/encrypted superseding the old
// (via EXTENSION-REVISION at the handler layer). The group_aead_key
// does NOT change; existing members re-use the same key. Only the
// wrapped_keys list grows by one entry. Existing members are
// unaffected; the new member's wrap binds the same group_aead_key
// under their own pubkey-hash + ephemeral.
//
// **Remove member (re-key).** Generate a fresh group_aead_key,
// re-encrypt the inner plaintext, re-wrap for the remaining members.
// The removed member retains the OLD key and can still open OLD
// entities — this is forward secrecy at the group-snapshot level, not
// at the message level (spec §8.5 honest framing). The new outer
// ciphertext is bound by a fresh F2-1 commitment to the new key, so the
// commitment property is preserved across the re-key (the removed
// member's reconstructed AAD diverges from what was sealed).

// GroupAddMember produces a new system/encrypted wrapper that extends
// the given outer entity with one additional member wrap. Inputs:
//
//   existing      — the prior wrapper (mode=group). Outer ciphertext,
//                   nonce, AEAD/KDF id, and existing wraps are reused
//                   verbatim.
//   groupAEADKey  — the symmetric outer key. Caller (an existing
//                   member) recovered this by unwrapping their own
//                   slot via GroupDecrypt's per-wrap path; this
//                   primitive does not re-derive it.
//   newMember     — the X25519 pubkey + hash of the member being
//                   added, plus optional pinned wrap nonce / ephemeral
//                   seed for KAT determinism.
//
// The output's wrapped_keys is existing.WrappedKeys || [new_wrap].
// The outer ciphertext + nonce do not change; only the wrap list
// grows. The new entity's content_hash will differ from `existing`
// solely because wrapped_keys differs.
func GroupAddMember(
	existing types.EncryptedData,
	groupAEADKey []byte,
	newMember GroupMember,
) (types.EncryptedData, error) {
	if existing.Mode != types.EncryptionModeGroup {
		return types.EncryptedData{}, fmt.Errorf("%s: GroupAddMember requires mode=group, got %q",
			types.EncryptionErrInvalidWrapper, existing.Mode)
	}
	if len(groupAEADKey) != AEADKeySize {
		return types.EncryptedData{}, fmt.Errorf("%s: group_aead_key must be %d bytes, got %d",
			types.EncryptionErrInvalidWrapper, AEADKeySize, len(groupAEADKey))
	}
	if len(existing.WrappedKeys)+1 > GroupMaxMembers {
		return types.EncryptedData{}, fmt.Errorf("%s: adding a member would exceed §8.6 ceiling %d",
			types.EncryptionErrWrappedKeysTooMany, GroupMaxMembers)
	}

	aeadID := byte(existing.AEADID)
	kdfID := byte(existing.KDFID)
	if err := GroupModeSuiteAllowed(aeadID, kdfID); err != nil {
		return types.EncryptedData{}, err
	}

	wrap, err := wrapForMember(newMember, groupAEADKey, aeadID, kdfID)
	if err != nil {
		return types.EncryptedData{}, fmt.Errorf("wrap for new member: %w", err)
	}

	out := existing
	out.WrappedKeys = make([]types.WrappedKey, 0, len(existing.WrappedKeys)+1)
	out.WrappedKeys = append(out.WrappedKeys, existing.WrappedKeys...)
	out.WrappedKeys = append(out.WrappedKeys, wrap)
	return out, nil
}

// GroupRekey produces a fresh system/encrypted wrapper for `members`
// over `plaintext` under a NEW group_aead_key. This is the §8.5
// "remove member" primitive: callers pass the remaining-member list
// (the removed member is absent), the plaintext is re-encrypted, and
// the F2-1 commitment is recomputed against the new key. The new
// entity is structurally a fresh GroupEncrypt with a new key + new
// nonce — there is no continuity with the prior outer ciphertext.
//
// Pin newGroupAEADKey + newOuterNonce for KAT determinism; leave empty
// for fresh randomness.
func GroupRekey(
	plaintext []byte,
	members []GroupMember,
	newGroupAEADKey []byte,
	newOuterNonce []byte,
) (types.EncryptedData, error) {
	return GroupEncrypt(GroupEncryptInput{
		Members:      members,
		Plaintext:    plaintext,
		OuterNonce:   newOuterNonce,
		GroupAEADKey: newGroupAEADKey,
	})
}
