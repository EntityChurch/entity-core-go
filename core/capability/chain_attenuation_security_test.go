package capability

import (
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// These tests pin the cross-impl capability-chain security findings F2/F3/F4
// (SECURITY-FINDINGS-CHAIN-ATTENUATION-CROSS-IMPL). Each was a Go
// divergence from §5.2/§5.5/§5.6 that produced a §5.10 verdict split with
// Rust/Python. They are the unit-level companions to the validate-peer
// chain/attenuation probes.

// F2 — operation excludes MUST be honored at the permission check (§5.2/§5.6).
// A grant {operations: {include: ["*"], exclude: ["delete"]}} permits any op
// EXCEPT delete. Before the fix Go consulted Operations.Include only.
func TestOperationExcludeHonored_F2(t *testing.T) {
	pid := testPeerID
	cap := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"delete"}},
			},
		},
	}

	if !CheckPermission(types.ExecuteData{Operation: "get"}, cap, "system/tree", pid, pid) {
		t.Fatal("F2: get must be permitted (included, not excluded)")
	}
	if CheckPermission(types.ExecuteData{Operation: "delete"}, cap, "system/tree", pid, pid) {
		t.Fatal("F2: delete must be DENIED by Operations.Exclude")
	}

	// Same gate on the Level-2 path permission path (CheckPathPermission).
	if !CheckPathPermission("get", "system/tree/foo", cap, "system/tree", pid, pid) {
		t.Fatal("F2: get path access must be permitted")
	}
	if CheckPathPermission("delete", "system/tree/foo", cap, "system/tree", pid, pid) {
		t.Fatal("F2: delete path access must be DENIED by Operations.Exclude")
	}
}

// F4 — a child grant MUST inherit the parent's excludes (§5.6). A child that
// drops a parent exclude is NOT properly attenuated (it re-opens a denied
// region).
func TestParentExcludeInheritance_F4(t *testing.T) {
	pid := testPeerID
	parent := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}, Exclude: []string{"system/tree/secret/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}

	// Child drops the parent's exclude → escalation → NOT attenuated.
	dropExclude := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if IsAttenuated(dropExclude, parent, pid, pid) {
		t.Fatal("F4: child dropping the parent's resource exclude must NOT be attenuated")
	}

	// Child that carries the same exclude → attenuated.
	keepExclude := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}, Exclude: []string{"system/tree/secret/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if !IsAttenuated(keepExclude, parent, pid, pid) {
		t.Fatal("F4: child preserving the parent's exclude must be attenuated")
	}

	// Child with a BROADER exclude (covers the parent's) → still attenuated.
	broaderExclude := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}, Exclude: []string{"system/tree/secret/*", "system/tree/private/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
	if !IsAttenuated(broaderExclude, parent, pid, pid) {
		t.Fatal("F4: child with a superset of the parent's excludes must be attenuated")
	}

	// Operation-dimension exclude inheritance: parent excludes op "delete";
	// child that drops it must not be attenuated.
	parentOpExcl := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}, Exclude: []string{"delete"}},
		}},
	}
	childDropOpExcl := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
	}
	if IsAttenuated(childDropOpExcl, parentOpExcl, pid, pid) {
		t.Fatal("F4: child dropping the parent's operation exclude must NOT be attenuated")
	}
}

// signCap signs capEntity with kp and returns the signature entity.
func signCap(t *testing.T, kp crypto.Keypair, capEntity entity.Entity, signer hash.Hash) entity.Entity {
	t.Helper()
	sig := kp.Sign(capEntity.ContentHash.Bytes())
	sigEntity, err := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    signer,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return sigEntity
}

// F3 — every link in a delegation chain MUST be within its validity window,
// not just the leaf (§5.5). An expired (or not-yet-valid) link MUST fail
// VerifyChain.
func TestPerLinkTemporalValidity_F3(t *testing.T) {
	now := uint64(time.Now().UnixMilli())

	// Case 1: expired ROOT link.
	t.Run("expired_root", func(t *testing.T) {
		localKP, _ := crypto.Generate()
		granteeKP, _ := crypto.Generate()
		localIdentity, _ := localKP.IdentityEntity()
		granteeIdentity, _ := granteeKP.IdentityEntity()
		expired := now - 60_000
		capData := types.CapabilityTokenData{
			Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
			Granter:   types.SingleSigGranter(localIdentity.ContentHash),
			Grantee:   granteeIdentity.ContentHash,
			CreatedAt: now - 120_000,
			ExpiresAt: &expired,
		}
		capEntity, _ := capData.ToEntity()
		sigEntity := signCap(t, localKP, capEntity, localIdentity.ContentHash)
		included := map[hash.Hash]entity.Entity{
			localIdentity.ContentHash:   localIdentity,
			granteeIdentity.ContentHash: granteeIdentity,
			sigEntity.ContentHash:       sigEntity,
		}
		if err := VerifyChain(capEntity, included, localKP.PeerID()); err == nil {
			t.Fatal("F3: expired root link must fail VerifyChain")
		}
	})

	// Case 2: 2-link chain with an expired INTERMEDIATE link. The leaf is
	// within its window; only the parent is expired. Pre-fix this verified.
	t.Run("expired_intermediate", func(t *testing.T) {
		localKP, _ := crypto.Generate()
		midKP, _ := crypto.Generate()
		leafKP, _ := crypto.Generate()
		localIdentity, _ := localKP.IdentityEntity()
		midIdentity, _ := midKP.IdentityEntity()
		leafIdentity, _ := leafKP.IdentityEntity()

		expired := now - 60_000
		future := now + 3_600_000

		// Root/intermediate: granter = local peer, grantee = mid, EXPIRED.
		rootData := types.CapabilityTokenData{
			Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
			Granter:   types.SingleSigGranter(localIdentity.ContentHash),
			Grantee:   midIdentity.ContentHash,
			CreatedAt: now - 120_000,
			ExpiresAt: &expired,
		}
		rootEntity, _ := rootData.ToEntity()
		rootSig := signCap(t, localKP, rootEntity, localIdentity.ContentHash)

		// Leaf: granter = mid, grantee = leaf, still valid, parent = root.
		leafData := types.CapabilityTokenData{
			Grants:    []types.GrantEntry{{Handlers: types.CapabilityScope{Include: []string{"*"}}, Resources: types.CapabilityScope{Include: []string{"*"}}, Operations: types.CapabilityScope{Include: []string{"get"}}}},
			Granter:   types.SingleSigGranter(midIdentity.ContentHash),
			Grantee:   leafIdentity.ContentHash,
			Parent:    &rootEntity.ContentHash,
			CreatedAt: now - 1000,
			ExpiresAt: &future,
		}
		leafEntity, _ := leafData.ToEntity()
		leafSig := signCap(t, midKP, leafEntity, midIdentity.ContentHash)

		included := map[hash.Hash]entity.Entity{
			localIdentity.ContentHash: localIdentity,
			midIdentity.ContentHash:   midIdentity,
			leafIdentity.ContentHash:  leafIdentity,
			rootEntity.ContentHash:    rootEntity,
			rootSig.ContentHash:       rootSig,
			leafSig.ContentHash:       leafSig,
		}
		if err := VerifyChain(leafEntity, included, localKP.PeerID()); err == nil {
			t.Fatal("F3: expired intermediate link must fail VerifyChain even when the leaf is valid")
		}
	})
}
