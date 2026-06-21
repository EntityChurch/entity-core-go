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

// buildCap constructs a cap entity with the given granter, grantee, and parent.
// Returns the cap entity and a copy of included with the cap added.
func buildCap(t *testing.T, granter hash.Hash, grantee hash.Hash, parent *hash.Hash, included map[hash.Hash]entity.Entity) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		Parent:    parent,
		CreatedAt: 1000,
	}
	capEntity, err := capData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	included[capEntity.ContentHash] = capEntity
	return capEntity
}

// --- CollectAuthorityChain tests ---

func TestCollectChainSingleRoot(t *testing.T) {
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash: localID,
		adminID.ContentHash: adminID,
	}
	root := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)

	chain, err := CollectAuthorityChain(root, IncludedResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected chain of length 1, got %d", len(chain))
	}
	if chain[0].ContentHash != root.ContentHash {
		t.Fatal("chain[0] should be the root cap itself")
	}
}

func TestCollectChainTwoLevels(t *testing.T) {
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash:   localID,
		adminID.ContentHash:   adminID,
		handlerID.ContentHash: handlerID,
	}
	root := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)
	rootHash := root.ContentHash
	leaf := buildCap(t, adminID.ContentHash, handlerID.ContentHash, &rootHash, included)

	chain, err := CollectAuthorityChain(leaf, IncludedResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2, got %d", len(chain))
	}
	// Leaf-to-root order: chain[0] = leaf, chain[1] = root.
	if chain[0].ContentHash != leaf.ContentHash {
		t.Fatal("chain[0] should be the leaf")
	}
	if chain[1].ContentHash != rootHash {
		t.Fatal("chain[1] should be the root")
	}
}

func TestCollectChainUnreachableParent(t *testing.T) {
	adminKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	adminID, _ := adminKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	missingParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		missingParent.Digest[i] = byte(i)
	}

	included := map[hash.Hash]entity.Entity{
		adminID.ContentHash:   adminID,
		handlerID.ContentHash: handlerID,
	}
	leaf := buildCap(t, adminID.ContentHash, handlerID.ContentHash, &missingParent, included)

	_, err := CollectAuthorityChain(leaf, IncludedResolver(included))
	if !errors.Is(err, ecerrors.ErrChainUnreachable) {
		t.Fatalf("expected ErrChainUnreachable, got %v", err)
	}
}

func TestCollectChainTooDeep(t *testing.T) {
	// Build a chain of maxChainDepth+2 entries — should hit ChainTooDeep.
	kps := make([]crypto.Keypair, maxChainDepth+3)
	ids := make([]entity.Entity, maxChainDepth+3)
	for i := range kps {
		kp, _ := crypto.Generate()
		id, _ := kp.IdentityEntity()
		kps[i] = kp
		ids[i] = id
	}
	included := map[hash.Hash]entity.Entity{}
	for _, id := range ids {
		included[id.ContentHash] = id
	}

	// Chain: ids[0] is root granter; each subsequent cap chains to the previous.
	// granter[i+1] = grantee[i] (standard delegation).
	prev := buildCap(t, ids[0].ContentHash, ids[1].ContentHash, nil, included)
	for i := 1; i < len(ids)-1; i++ {
		prevHash := prev.ContentHash
		prev = buildCap(t, ids[i].ContentHash, ids[i+1].ContentHash, &prevHash, included)
	}

	_, err := CollectAuthorityChain(prev, IncludedResolver(included))
	if !errors.Is(err, ecerrors.ErrChainTooDeep) {
		t.Fatalf("expected ErrChainTooDeep, got %v", err)
	}
}

// --- CheckCreatorAuthority tests ---
//
// Three outcomes per proposal §3.2:
//   - (true,  chain, nil)              → authorized
//   - (false, chain, nil)              → chain valid but writer absent (403)
//   - (false, nil,   ChainUnreachable) → chain broken (404)

func TestCheckCreatorRootGranterMatch(t *testing.T) {
	// System-handler-equivalent case: writer is the root granter.
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash: localID,
		adminID.ContentHash: adminID,
	}
	cap := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)

	found, chain, err := CheckCreatorAuthority(cap, localID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected local peer to match root granter")
	}
	if len(chain) != 1 {
		t.Fatalf("expected chain of length 1, got %d", len(chain))
	}
}

func TestCheckCreatorGranteeNotInChain(t *testing.T) {
	// Admin is grantee, not granter. R1 rejects.
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash: localID,
		adminID.ContentHash: adminID,
	}
	cap := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)

	found, chain, err := CheckCreatorAuthority(cap, adminID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("admin is grantee, not granter; should not match in authority chain")
	}
	// Chain still returned — caller decides not to persist on found=false.
	if len(chain) != 1 {
		t.Fatalf("expected chain of length 1 even when not found, got %d", len(chain))
	}
}

func TestCheckCreatorAdversaryRejected(t *testing.T) {
	// Finding 3: adversary references admin cap; not in chain.
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	advKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	advID, _ := advKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash: localID,
		adminID.ContentHash: adminID,
		advID.ContentHash:   advID,
	}
	cap := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)

	found, _, err := CheckCreatorAuthority(cap, advID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("adversary is not in admin cap's chain; expected reject")
	}
}

func TestCheckCreatorWriterIsLeafGranter(t *testing.T) {
	// Re-attenuation pattern: writer is leaf granter. Walk reaches root,
	// finds writer, returns true. Full chain returned for persistence.
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash:   localID,
		adminID.ContentHash:   adminID,
		handlerID.ContentHash: handlerID,
	}
	root := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)
	rootHash := root.ContentHash
	leaf := buildCap(t, adminID.ContentHash, handlerID.ContentHash, &rootHash, included)

	found, chain, err := CheckCreatorAuthority(leaf, adminID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected admin (leaf granter) to match")
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2, got %d", len(chain))
	}
}

func TestCheckCreatorChainUnreachableTakesPrecedence(t *testing.T) {
	// THIS IS THE KEY VECTOR — writer matches the leaf granter, but the
	// parent is unreachable. Pre-amendment behavior: short-circuit returns
	// true, parent reachability never checked. Post-amendment: the walker
	// errors on unreachable parent BEFORE identity matching runs.
	//
	// Mirrors the failing §10 r1_install_chain_unreachable vector across
	// Go, Rust, and Python in PROPOSAL-COHERENT-CAPABILITY-AUTHORITY.
	writerKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	writerID, _ := writerKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	missingParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	for i := 0; i < hash.SHA256DigestSize; i++ {
		missingParent.Digest[i] = byte(0xAB ^ i)
	}

	included := map[hash.Hash]entity.Entity{
		writerID.ContentHash:  writerID,
		handlerID.ContentHash: handlerID,
	}
	// Writer IS the leaf granter — the case the old short-circuit silently
	// permitted. The unified walker walks to root regardless.
	leaf := buildCap(t, writerID.ContentHash, handlerID.ContentHash, &missingParent, included)

	found, chain, err := CheckCreatorAuthority(leaf, writerID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if !errors.Is(err, ecerrors.ErrChainUnreachable) {
		t.Fatalf("expected ErrChainUnreachable to take precedence over identity match, got %v", err)
	}
	if found {
		t.Fatal("found must be false when chain is unreachable")
	}
	if chain != nil {
		t.Fatal("chain must be nil when error is returned (don't return partial chains)")
	}
}

func TestCheckCreatorNotInChainStillReturnsChain(t *testing.T) {
	// On found=false (chain valid, identity absent), the chain is still
	// returned so callers can inspect it for diagnostic purposes — but the
	// caller MUST NOT persist it. This test pins the contract.
	localKP, _ := crypto.Generate()
	adminKP, _ := crypto.Generate()
	advKP, _ := crypto.Generate()
	handlerKP, _ := crypto.Generate()
	localID, _ := localKP.IdentityEntity()
	adminID, _ := adminKP.IdentityEntity()
	advID, _ := advKP.IdentityEntity()
	handlerID, _ := handlerKP.IdentityEntity()

	included := map[hash.Hash]entity.Entity{
		localID.ContentHash:   localID,
		adminID.ContentHash:   adminID,
		advID.ContentHash:     advID,
		handlerID.ContentHash: handlerID,
	}
	root := buildCap(t, localID.ContentHash, adminID.ContentHash, nil, included)
	rootHash := root.ContentHash
	leaf := buildCap(t, adminID.ContentHash, handlerID.ContentHash, &rootHash, included)

	found, chain, err := CheckCreatorAuthority(leaf, advID.ContentHash, IncludedResolver(included), IncludedSignatureResolver(included))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("adversary not in chain")
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2 returned to caller, got %d", len(chain))
	}
}
