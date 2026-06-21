package identity

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/quorum"
)

// makeIdentityResolvedResolver returns a SignerResolver for the
// "identity-resolved" mode per §6.1. Given an identity reference
// (treated as the trusts_quorum hash for the referenced identity), walks
// the cert graph to the top-level controller live at asOf and returns its
// peer hash.
//
// Honors the asOf parameter per EXTENSION-QUORUM v1.1 §5.2: when asOf is
// 0 the resolver returns the current controller; otherwise it returns the
// controller live at asOf. This enables mid-flight signing across a
// controller rotation in group quorums — a quorum-update signed before
// the rotation validates against the prior controller.
//
// The deterministic tie-break across multi-controller deployments uses
// lowest content_hash per §3.2's resolve_controller_for_grants algorithm.
func makeIdentityResolvedResolver(att *attestation.Handler) quorum.SignerResolver {
	return func(ctx context.Context, identityRef hash.Hash, cs store.ContentStore, li store.LocationIndex, asOf uint64) (hash.Hash, error) {
		_ = ctx // identity-resolved doesn't currently recurse through CurrentSignerSetCtx; ctx carries state for resolver chains that do.
		quorumID := identityRef
		ix := att.Index()
		// Find live (at asOf) top-level controller certs whose attesting==quorum_id.
		// Per v3.3 SI-13, the predicate uses IdentityConfersFunction so
		// rotation-handoff / rotation-recovery attestations that inherit the
		// controller function from their target_cert are also included as
		// chain-walk candidates.
		candidates := attestation.FindAttestationsBy(cs, ix, quorumID, func(_ hash.Hash, a types.AttestationData) bool {
			return IdentityConfersFunction(cs, a, types.FunctionController)
		})
		var live []attestation.AttestationRef
		for _, c := range candidates {
			if attestation.IsAttestationLive(cs, li, ix, c.Hash, c.Data, asOf) {
				live = append(live, c)
			}
		}
		if len(live) == 0 {
			return hash.Hash{}, fmt.Errorf("identity_not_found_or_no_controller: %s", quorumID)
		}
		// Multi-controller deterministic tie-break: lowest content_hash.
		best := live[0]
		for _, c := range live[1:] {
			if hashLess(c.Hash, best.Hash) {
				best = c
			}
		}
		return best.Data.Attested, nil
	}
}

// hashLess provides deterministic ordering for tie-break per §3.2 (lowest
// content_hash). Replicated here to avoid exporting from the substrate.
func hashLess(a, b hash.Hash) bool {
	ab := a.Bytes()
	bb := b.Bytes()
	for i := 0; i < len(ab) && i < len(bb); i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return len(ab) < len(bb)
}
