package encryption

import (
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Tier-A recipient resolution helpers per EXTENSION-ENCRYPTION §4.4 / §10 /
// §11. A sender starts with an initial encryption-pubkey hash (resolved
// from the recipient's namespace) and MUST honor two policy steps before
// binding it:
//
//   1. Revocation supersedes everything. If the pubkey is named in any
//      system/encryption/revocation entity the sender holds, the send is
//      refused with encryption_key_revoked (§7.5 step 2 / §11 / §15).
//      A sender does NOT silently redirect to a successor — the
//      caller asked for a specific key; that key is dead.
//
//   2. Handoff walks the chain. If the pubkey has been superseded by a
//      system/encryption/handoff (previous → next) AND is NOT revoked, a
//      sender that wants the live key for the same identity SHOULD follow
//      the chain to the latest non-revoked successor (§4.4 / §10).
//
// These helpers operate on already-decoded entity data; the listing /
// fetch path is the caller's concern (validate-peer's cert_lifecycle
// uses tree:listing).

// ErrEncryptionKeyRevoked carries the §15 encryption_key_revoked error
// code. Sender-side resolution returns this when the requested pubkey
// hash appears in the revocation set.
var ErrEncryptionKeyRevoked = errors.New(types.EncryptionErrKeyRevoked)

// IsPubkeyRevoked reports whether any of the provided revocation entities
// names the given pubkey hash as its target.
func IsPubkeyRevoked(pubkey hash.Hash, revocations []types.EncryptionRevocationData) bool {
	for _, rv := range revocations {
		if rv.Revokes == pubkey {
			return true
		}
	}
	return false
}

// NextInHandoffChain returns the next pubkey hash that supersedes the
// given one per §10, or (zero, false) if no handoff names it as
// `previous_pubkey`. Multiple handoffs with the same `previous_pubkey`
// is malformed (Tier-A handoff is single-occupant); first match wins.
func NextInHandoffChain(pubkey hash.Hash, handoffs []types.EncryptionHandoffData) (hash.Hash, bool) {
	for _, ho := range handoffs {
		if ho.PreviousPubkey == pubkey {
			return ho.NextPubkey, true
		}
	}
	return hash.Hash{}, false
}

// ResolveCurrentRecipient walks the §10 handoff chain from the given
// initial pubkey hash, stopping at the first hash that has no successor.
// At every step (including the initial input) it consults the revocation
// set: a revoked pubkey terminates resolution with ErrEncryptionKeyRevoked
// per §11 / §15. The terminal non-revoked hash is the recipient_key the
// sender SHOULD bind into AAD + HKDF info per §7.3.
//
// Chain cycles are bounded by the number of handoff entries; a longer
// walk implies a malformed input and returns an error rather than
// looping.
func ResolveCurrentRecipient(
	initial hash.Hash,
	revocations []types.EncryptionRevocationData,
	handoffs []types.EncryptionHandoffData,
) (hash.Hash, error) {
	if IsPubkeyRevoked(initial, revocations) {
		return hash.Hash{}, fmt.Errorf("%w: requested pubkey %s is revoked", ErrEncryptionKeyRevoked, initial)
	}
	current := initial
	for steps := 0; steps <= len(handoffs); steps++ {
		next, ok := NextInHandoffChain(current, handoffs)
		if !ok {
			return current, nil
		}
		if IsPubkeyRevoked(next, revocations) {
			return hash.Hash{}, fmt.Errorf("%w: handoff target %s is revoked", ErrEncryptionKeyRevoked, next)
		}
		current = next
	}
	return hash.Hash{}, fmt.Errorf("ResolveCurrentRecipient: handoff chain exceeded %d steps (cycle?)", len(handoffs))
}
