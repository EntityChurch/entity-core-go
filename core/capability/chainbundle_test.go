package capability

import (
	"encoding/hex"
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// putCap builds + stores a cap, plus the granter's signature bound at the
// V7 invariant pointer path (mirroring envelope_ingest), so CollectChainBundle
// can resolve it the same way a real verifier would.
func putCap(t *testing.T, cs store.ContentStore, li store.LocationIndex,
	signerKP crypto.Keypair, signerID entity.Entity, grantee hash.Hash, parent *hash.Hash) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Operations: types.CapabilityScope{Include: []string{"put"}}}},
		Granter:   types.SingleSigGranter(signerID.ContentHash),
		Grantee:   grantee,
		Parent:    parent,
		CreatedAt: 1000,
	}
	capEnt, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(capEnt); err != nil {
		t.Fatal(err)
	}
	sigEnt, err := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    signerID.ContentHash,
		Algorithm: "ed25519",
		Signature: signerKP.Sign(capEnt.ContentHash.Bytes()),
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(sigEnt); err != nil {
		t.Fatal(err)
	}
	sd, _ := types.PeerDataFromEntity(signerID)
	sdPID := crypto.PeerIDFromEd25519PublicKey(sd.PublicKey) // v7.65: derive peer_id from pubkey
	path := "/" + string(sdPID) + "/system/signature/" + hex.EncodeToString(capEnt.ContentHash.Bytes())
	if err := li.Set(path, sigEnt.ContentHash); err != nil {
		t.Fatal(err)
	}
	return capEnt
}

// TestCollectChainBundle verifies the G2 dispatch chain-walk + bundle helper
// (§4.3 / §8.1): for a B-rooted chain it returns EVERY entity a remote
// verifier needs — each cap, each granter identity, and each granter's
// signature resolved from the invariant pointer path.
func TestCollectChainBundle(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	bKP, _ := crypto.Generate()
	instKP, _ := crypto.Generate()
	bID, _ := bKP.IdentityEntity()
	instID, _ := instKP.IdentityEntity()
	if _, err := cs.Put(bID); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(instID); err != nil {
		t.Fatal(err)
	}

	// root: B -> installer (B-rooted). leaf: installer -> installer, parent=root.
	root := putCap(t, cs, li, bKP, bID, instID.ContentHash, nil)
	rootHash := root.ContentHash
	leaf := putCap(t, cs, li, instKP, instID, instID.ContentHash, &rootHash)

	bundle, err := CollectChainBundle(leaf, cs, li)
	if err != nil {
		t.Fatalf("CollectChainBundle: %v", err)
	}

	// Must contain: both caps, both granter identities, both signatures.
	mustHave := func(label string, h hash.Hash) {
		if _, ok := bundle[h]; !ok {
			t.Errorf("bundle missing %s (%s)", label, h)
		}
	}
	mustHave("leaf cap", leaf.ContentHash)
	mustHave("root cap", root.ContentHash)
	mustHave("B identity", bID.ContentHash)
	mustHave("installer identity", instID.ContentHash)

	// Two signature entities (one per link) must be present.
	sigCount := 0
	for _, e := range bundle {
		if e.Type == types.TypeSignature {
			sigCount++
		}
	}
	if sigCount != 2 {
		t.Errorf("expected 2 signature entities in bundle (one per link), got %d", sigCount)
	}

	// A verifier reconstructing the chain from ONLY the bundle must succeed:
	// the in-chain check resolves caps + sigs from it.
	found, _, err := CheckCreatorAuthority(leaf, instID.ContentHash,
		IncludedResolver(bundle), IncludedSignatureResolver(bundle))
	if err != nil {
		t.Fatalf("CheckCreatorAuthority over bundle-only: %v", err)
	}
	if !found {
		t.Fatal("installer must be in-chain when verifying from the bundle alone")
	}
}

// TestCollectChainBundleFailsClosedOnUnresolvableIdentity — the inversion of
// what this test used to assert.
//
// It was `TestCollectChainBundleBestEffort`, and it pinned the opposite rule:
// "a link whose signature/identity is not locally resolvable is simply
// omitted … No error, no panic." EXTENSION-CONTINUATION §4.3 (v1.22) makes
// that non-conformant — the bundle MUST carry a `system/peer` identity for
// every granter AND grantee in the chain, and a bundler that cannot resolve
// one MUST fail with `chain_unreachable` rather than dispatch an incomplete
// bundle.
//
// Why the old rule was wrong, recorded because it cost two cycles: the far
// side's verify step 2a resolves every link's grantee and answers 401
// `UnresolvableGrantee` when it cannot. A verifier MUST paired with a
// best-effort bundler is an interop bug by construction — the omission is
// silent here and surfaces there, so the peer that REPORTS the failure looks
// like the peer that CAUSED it. That is exactly how this got routed at
// core-rust twice. Failing at bundle time puts the error where the missing
// entity is.
func TestCollectChainBundleFailsClosedOnUnresolvableIdentity(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	kp, _ := crypto.Generate()
	id, _ := kp.IdentityEntity()
	// Cap present, but NO identity entity and NO bound signature in the store.
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.SingleSigGranter(id.ContentHash),
		Grantee:   id.ContentHash,
		CreatedAt: 1,
	}
	capEnt, _ := capData.ToEntity()
	if _, err := cs.Put(capEnt); err != nil {
		t.Fatal(err)
	}

	bundle, err := CollectChainBundle(capEnt, cs, li)
	if err == nil {
		t.Fatal("bundled a chain whose granter identity is unresolvable — §4.3 requires chain_unreachable at bundle time, not a quiet omission the far side reports as ITS problem")
	}
	if !errors.Is(err, ErrChainUnreachable) {
		t.Fatalf("error must be ErrChainUnreachable so callers can classify it, got: %v", err)
	}
	if bundle != nil {
		t.Fatal("a failed bundle must return nil, not a partial map a caller might dispatch anyway")
	}
}

// The positive control: with the identity present, the same chain bundles
// cleanly. Without this, the test above passes for free the moment
// CollectChainBundle starts erroring on everything.
func TestCollectChainBundleSucceedsWhenIdentityIsResolvable(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	kp, _ := crypto.Generate()
	id, _ := kp.IdentityEntity()
	if _, err := cs.Put(id); err != nil {
		t.Fatal(err)
	}
	capData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{{Operations: types.CapabilityScope{Include: []string{"get"}}}},
		Granter:   types.SingleSigGranter(id.ContentHash),
		Grantee:   id.ContentHash,
		CreatedAt: 1,
	}
	capEnt, _ := capData.ToEntity()
	if _, err := cs.Put(capEnt); err != nil {
		t.Fatal(err)
	}

	bundle, err := CollectChainBundle(capEnt, cs, li)
	if err != nil {
		t.Fatalf("a fully resolvable chain must bundle: %v", err)
	}
	if _, ok := bundle[capEnt.ContentHash]; !ok {
		t.Fatal("the cap must be in the bundle")
	}
	if _, ok := bundle[id.ContentHash]; !ok {
		t.Fatal("the granter/grantee identity must be in the bundle — §4.3 completeness")
	}
}
