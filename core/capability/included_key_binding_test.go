package capability

import (
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestVerifyChain_RejectsMisKeyedIncluded pins the VerifyChain half of the
// map-key-binding fix (core-rust routed 2026-09-13). VerifyChain resolves the
// chain granter and each link's signer identity BY HASH out of `included`, so a
// mis-keyed entry substitutes an attacker's key under a victim's identity hash.
// This is the site rust flagged hardest, because the §7a.2a presented-authority
// arm calls VerifyChain directly with a hand-merged bundle (bypassing the
// envelope receive path), and that arm deliberately relaxes root-trust.
//
// Teeth: the honest, correctly-keyed map MUST verify (positive control); the
// same map with ONE mis-keyed entry MUST be refused — so the refusal is
// attributable to the binding, not to a broken chain. RED if VerifyChain's
// entity.VerifyIncludedKeyBinding guard is removed.
func TestVerifyChain_RejectsMisKeyedIncluded(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()
	attackerKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()
	attackerIdentity, _ := attackerKP.IdentityEntity()

	// Root cap granted by the local peer to the remote peer.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: capSig,
	}.ToEntity()

	honest := map[hash.Hash]entity.Entity{
		localIdentity.ContentHash:  localIdentity,
		remoteIdentity.ContentHash: remoteIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
	}

	// Positive control: correctly keyed → verifies.
	if err := VerifyChain(capEntity, honest, localKP.PeerID()); err != nil {
		t.Fatalf("positive control failed — a correctly-keyed valid chain must verify: %v", err)
	}

	// Mis-key ONE entry: the attacker's identity filed under the remote
	// (grantee) hash. Everything else is byte-identical to the honest map.
	forged := map[hash.Hash]entity.Entity{
		localIdentity.ContentHash:  localIdentity,
		remoteIdentity.ContentHash: attackerIdentity, // <-- substitution
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
	}
	err := VerifyChain(capEntity, forged, localKP.PeerID())
	if err == nil {
		t.Fatalf("mis-keyed included map ACCEPTED — the map-key binding is not enforced in VerifyChain")
	}
	if !errors.Is(err, ecerrors.ErrCapabilityDenied) {
		t.Fatalf("expected ErrCapabilityDenied for a mis-keyed included map, got: %v", err)
	}
}
