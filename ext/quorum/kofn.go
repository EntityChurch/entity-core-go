package quorum

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// VerifyKOfNSignatures returns true iff at least `threshold` distinct
// signers from `signerSet` produced valid signatures targeting `entityHash`
// per §4.1. Defensive dedupe: each signer counted at most once. Each
// candidate signature is located via the V7 invariant pointer pattern
// (delegated to ext/attestation.VerifySpecificSigner).
//
// SignedBy is the set of constituents whose signatures were verified;
// useful diagnostically when valid is false (shows which constituents
// failed to sign).
func VerifyKOfNSignatures(
	cs store.ContentStore,
	li store.LocationIndex,
	entityHash hash.Hash,
	signerSet []hash.Hash,
	threshold uint64,
) (signedBy []hash.Hash, valid bool) {
	if threshold == 0 {
		return nil, false
	}
	seen := make(map[hash.Hash]struct{}, len(signerSet))
	signedBy = make([]hash.Hash, 0, len(signerSet))
	for _, candidate := range signerSet {
		if _, dup := seen[candidate]; dup {
			continue
		}
		if !attestation.VerifySpecificSigner(cs, li, entityHash, candidate) {
			continue
		}
		seen[candidate] = struct{}{}
		signedBy = append(signedBy, candidate)
		if uint64(len(signedBy)) >= threshold {
			return signedBy, true
		}
	}
	return signedBy, uint64(len(signedBy)) >= threshold
}
