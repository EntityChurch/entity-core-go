package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// makeCP1Cap constructs a cap-token entity with the given granter/grantee/parent.
func makeCP1Cap(t *testing.T, cs store.ContentStore, granter, grantee hash.Hash, parent *hash.Hash) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"put"}},
			},
		},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		Parent:    parent,
		CreatedAt: 1000,
	}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(ent); err != nil {
		t.Fatal(err)
	}
	return ent
}

func makeApplyWithLiteralCap(t *testing.T, cs store.ContentStore, capEntityHash hash.Hash) entity.Entity {
	t.Helper()
	// compute/literal whose value is the cap entity's content hash bytes.
	capLit := mustE(types.ComputeLiteralData{Value: capEntityHash.Bytes()}.ToEntity())
	capLitHash, _ := cs.Put(capLit)
	// compute/literal for the resource (F5 requires resource alongside capability).
	resLit := mustE(types.ComputeLiteralData{Value: "/peer/data"}.ToEntity())
	resLitHash, _ := cs.Put(resLit)
	apply := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "put",
		Resource:   resLitHash,
		Capability: capLitHash,
	}.ToEntity())
	cs.Put(apply)
	return apply
}

func TestCP1AdversaryCapRejected(t *testing.T) {
	// Compute install §10 row 8: installer is non-admin; static literal
	// compute/apply.capability points at admin's cap. R1 rejects.
	cs := store.NewMemoryContentStore()
	advKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	advID, _ := advKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	cs.Put(advID)
	cs.Put(adminID)

	adminCap := makeCP1Cap(t, cs, adminID.ContentHash, adminID.ContentHash, nil)
	apply := makeApplyWithLiteralCap(t, cs, adminCap.ContentHash)

	cfg := auditConfig{
		Installer: advID.ContentHash,
		Resolve:   capability.IncludedResolver(map[hash.Hash]entity.Entity{adminCap.ContentHash: adminCap}),
	}
	result := auditSubgraph(apply, cs, "", "", cfg)
	if result.Err == nil {
		t.Fatal("expected audit error for adversary referencing admin cap")
	}
	if result.Err.Code != "embedded_cap_unauthorized" {
		t.Fatalf("expected embedded_cap_unauthorized, got %q", result.Err.Code)
	}
	if result.Err.Status != 403 {
		t.Fatalf("expected status 403, got %d", result.Err.Status)
	}
}

func TestCP1InstallerSelfIssuedAccepted(t *testing.T) {
	// Installer is the granter of the embedded cap → R1 passes.
	cs := store.NewMemoryContentStore()
	installerKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	installerID, _ := installerKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()
	cs.Put(installerID)
	cs.Put(handlerID)

	cap := makeCP1Cap(t, cs, installerID.ContentHash, handlerID.ContentHash, nil)
	apply := makeApplyWithLiteralCap(t, cs, cap.ContentHash)

	cfg := auditConfig{
		Installer: installerID.ContentHash,
		Resolve:   capability.IncludedResolver(map[hash.Hash]entity.Entity{cap.ContentHash: cap}),
	}
	result := auditSubgraph(apply, cs, "", "", cfg)
	if result.Err != nil {
		t.Fatalf("unexpected audit error: %v", result.Err.Code+": "+result.Err.Message)
	}
	if len(result.EmbeddedCaps) != 1 {
		t.Fatalf("expected 1 embedded cap collected, got %d", len(result.EmbeddedCaps))
	}
}

func TestCP1DynamicCapDeferred(t *testing.T) {
	// Capability is a compute/lookup/scope (not a literal) → CP1 skipped,
	// runtime dual-check applies. Audit completes normally.
	cs := store.NewMemoryContentStore()
	installerKP, _ := crypto.Generate()
	installerID, _ := installerKP.IdentityEntity()
	cs.Put(installerID)

	dynCap := mustE(types.ComputeLookupScopeData{Name: "caller_capability"}.ToEntity())
	dynCapHash, _ := cs.Put(dynCap)
	resLit := mustE(types.ComputeLiteralData{Value: "/peer/data"}.ToEntity())
	resLitHash, _ := cs.Put(resLit)
	apply := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "put",
		Resource:   resLitHash,
		Capability: dynCapHash,
	}.ToEntity())
	cs.Put(apply)

	cfg := auditConfig{
		Installer: installerID.ContentHash,
		Resolve:   capability.IncludedResolver(map[hash.Hash]entity.Entity{}),
	}
	result := auditSubgraph(apply, cs, "", "", cfg)
	if result.Err != nil {
		t.Fatalf("unexpected audit error: %v", result.Err.Code)
	}
	if len(result.EmbeddedCaps) != 0 {
		t.Fatal("dynamic capability must not collect into EmbeddedCaps")
	}
}

func TestCP1ChainUnreachable(t *testing.T) {
	// Literal points at a cap whose parent isn't in store or resolver. The
	// helper returns ErrChainUnreachable; audit surfaces 404 chain_unreachable.
	cs := store.NewMemoryContentStore()
	installerKP, _ := crypto.Generate()
	otherKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	installerID, _ := installerKP.IdentityEntity()
	otherID, _ := otherKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()
	cs.Put(installerID)
	cs.Put(otherID)
	cs.Put(handlerID)

	missingParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		missingParent.Digest[i] = byte(i + 1)
	}
	leaf := makeCP1Cap(t, cs, otherID.ContentHash, handlerID.ContentHash, &missingParent)
	apply := makeApplyWithLiteralCap(t, cs, leaf.ContentHash)

	cfg := auditConfig{
		Installer: installerID.ContentHash,
		Resolve: func(h hash.Hash) (entity.Entity, bool) {
			// Resolver lookups: the leaf is in the store; the missing parent isn't.
			return cs.Get(h)
		},
	}
	result := auditSubgraph(apply, cs, "", "", cfg)
	if result.Err == nil {
		t.Fatal("expected audit error for unreachable chain")
	}
	if result.Err.Code != "chain_unreachable" {
		t.Fatalf("expected chain_unreachable, got %q", result.Err.Code)
	}
	if result.Err.Status != 404 {
		t.Fatalf("expected status 404, got %d", result.Err.Status)
	}
}

func TestCP1AttenuatedChainAccepted(t *testing.T) {
	// 2-level chain: root issued by other to installer, leaf issued by
	// installer to compute-handler. Installer is leaf granter → R1 passes.
	cs := store.NewMemoryContentStore()
	installerKP, _ := crypto.Generate()
	otherKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	installerID, _ := installerKP.IdentityEntity()
	otherID, _ := otherKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()
	cs.Put(installerID)
	cs.Put(otherID)
	cs.Put(handlerID)

	root := makeCP1Cap(t, cs, otherID.ContentHash, installerID.ContentHash, nil)
	rootHash := root.ContentHash
	leaf := makeCP1Cap(t, cs, installerID.ContentHash, handlerID.ContentHash, &rootHash)
	apply := makeApplyWithLiteralCap(t, cs, leaf.ContentHash)

	cfg := auditConfig{
		Installer: installerID.ContentHash,
		Resolve: func(h hash.Hash) (entity.Entity, bool) {
			return cs.Get(h)
		},
	}
	result := auditSubgraph(apply, cs, "", "", cfg)
	if result.Err != nil {
		t.Fatalf("unexpected audit error: %v", result.Err.Code+": "+result.Err.Message)
	}
}

func TestCP1NoInstallerSkipsCheck(t *testing.T) {
	// Backwards-compat: when auditConfig.Installer is zero, CP1 is skipped
	// entirely (used by tests that don't care about identity).
	cs := store.NewMemoryContentStore()
	advKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	advID, _ := advKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	cs.Put(advID)
	cs.Put(adminID)

	adminCap := makeCP1Cap(t, cs, adminID.ContentHash, adminID.ContentHash, nil)
	apply := makeApplyWithLiteralCap(t, cs, adminCap.ContentHash)

	// Empty config — no installer threaded.
	result := auditSubgraph(apply, cs, "", "", auditConfig{})
	if result.Err != nil {
		t.Fatalf("CP1 should be skipped when installer is zero, but got error: %v", result.Err)
	}
}
