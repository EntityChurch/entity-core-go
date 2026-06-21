package capability

import (
	"encoding/hex"
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

// TestCollectChainBundleBestEffort — a link whose signature/identity is not
// locally resolvable is simply omitted; the walk still returns the caps it
// could collect (the verifier fails closed later if it actually needed the
// missing piece). No error, no panic.
func TestCollectChainBundleBestEffort(t *testing.T) {
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
	if err != nil {
		t.Fatalf("best-effort bundle must not error: %v", err)
	}
	if _, ok := bundle[capEnt.ContentHash]; !ok {
		t.Fatal("the resolvable cap must still be in the bundle")
	}
	for _, e := range bundle {
		if e.Type == types.TypeSignature {
			t.Fatal("no signature should be present (none was resolvable)")
		}
	}
}
