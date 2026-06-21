// Tests for CapTokenScope — Amendment 5 §5A: serve_scope as a literal
// capability token, evaluated by the same cap evaluator the live-EXECUTE
// surface uses (capability.CheckPathPermission). The published cap IS the
// authorization context — no synthetic connection cap, no second ACL
// machinery.

package httplive_test

import (
	"context"
	"encoding/hex"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/httplive"
)

// makeCapAllowGetOnPattern produces a CapabilityTokenData granting `get` on
// a single resource pattern under the given handler. Both granter and
// grantee are zero-padded but non-zero peer-ids so ValidateStructure is
// happy; for the path-permission check those identities don't drive the
// outcome.
func makeCapAllowGetOnPattern(t *testing.T, handler, pattern string, granterID, granteeID crypto.PeerID) types.CapabilityTokenData {
	t.Helper()
	// Build a single-sig granter from a deterministic non-zero hash.
	granterHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	granterHash.Digest[0] = 0x42
	granteeHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	granteeHash.Digest[0] = 1
	return types.CapabilityTokenData{
		Granter:   types.SingleSigGranter(granterHash),
		Grantee:   granteeHash,
		CreatedAt: 1,
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{handler}},
				Resources:  types.CapabilityScope{Include: []string{pattern}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
	}
}

func TestCapTokenScope_InScopePath_GrantsAllowedPath(t *testing.T) {
	local := crypto.PeerID(testPeerID)
	granter := crypto.PeerID(testPeerID) // same peer grants its own serve_scope
	cap := makeCapAllowGetOnPattern(t, "system/tree", "system/content/public/*", granter, local)

	scope := httplive.CapTokenScope{
		Cap:            cap,
		HandlerPattern: "system/tree",
		LocalPeerID:    local,
		GranterPeerID:  granter,
	}

	ok, err := scope.InScopePath(context.Background(), "system/content/public/welcome")
	if err != nil {
		t.Fatalf("InScopePath: %v", err)
	}
	if !ok {
		t.Errorf("expected allowed path to be in scope")
	}
}

func TestCapTokenScope_InScopePath_DeniesPathNotInCap(t *testing.T) {
	local := crypto.PeerID(testPeerID)
	granter := crypto.PeerID(testPeerID)
	cap := makeCapAllowGetOnPattern(t, "system/tree", "system/content/public/*", granter, local)

	scope := httplive.CapTokenScope{
		Cap:            cap,
		HandlerPattern: "system/tree",
		LocalPeerID:    local,
		GranterPeerID:  granter,
	}

	// A path the cap doesn't cover.
	ok, err := scope.InScopePath(context.Background(), "system/other/private")
	if err != nil {
		t.Fatalf("InScopePath: %v", err)
	}
	if ok {
		t.Errorf("expected unrelated path to be OUT of scope")
	}
}

func TestCapTokenScope_InScope_RequiresBothSubstrateAndCap(t *testing.T) {
	local := crypto.PeerID(testPeerID)
	granter := crypto.PeerID(testPeerID)
	cap := makeCapAllowGetOnPattern(t, "system/tree", "system/content/public/*", granter, local)

	// Seed an index with a §6.4.2 Hash Tree Presence binding under
	// system/content/public/<hex>; CapTokenScope.InScope should return true
	// only when BOTH the substrate binding exists AND the cap permits get
	// on it.
	idx := store.NewMemoryLocationIndex()
	cs := store.NewMemoryContentStore()
	scope := httplive.CapTokenScope{
		Cap:              cap,
		HandlerPattern:   "system/tree",
		LocalPeerID:      local,
		GranterPeerID:    granter,
		ContentNamespace: "system/content/public",
		Index:            idx,
	}

	payload := []byte("for cap-scope test")
	h := putChunk(t, cs, payload)
	bindingPath := "system/content/public/" + hex.EncodeToString(h.Bytes())

	// Neither substrate nor binding yet → out of scope.
	ok, err := scope.InScope(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("hash without binding should be out of scope")
	}

	// Add the §6.4.2 binding — now substrate is satisfied AND the cap
	// permits get on `system/content/public/*` so it should pass.
	if err := idx.Set(bindingPath, h); err != nil {
		t.Fatalf("idx.Set: %v", err)
	}
	ok, err = scope.InScope(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("hash with binding under granted cap pattern should be IN scope")
	}

	// Replace the cap with one that grants a DIFFERENT pattern — substrate
	// is fine but the cap denies → out of scope.
	scope.Cap = makeCapAllowGetOnPattern(t, "system/tree", "system/other/*", granter, local)
	ok, err = scope.InScope(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("hash with binding but cap denies the path should be OUT of scope")
	}
}
