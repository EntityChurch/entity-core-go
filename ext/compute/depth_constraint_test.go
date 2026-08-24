package compute

// EXTENSION-COMPUTE §5.2: `depth = compute_depth_limit`, where
// compute_depth_limit comes from the capability's grant-level
// constraints["system/compute"]["max_compute_depth"] (ENTITY-CORE-PROTOCOL §5 —
// `constraints` is a GRANT-level narrowing field, grants[].constraints).
//
// This path was UNREACHABLE until 2026-08-22: initBudget read the token's
// top-level `constraints`, which no conformant capability carries (the token has
// no such field — constraints live on the grant entries). So a depth constraint
// reached the evaluator nowhere, and the depth-sensitive conformance vectors
// (e.g. CV-9a) could not be driven over the wire — they ran at the peer default
// and produced a different boundary than the in-process eval. These tests carry
// the teeth the wire drive needs: a grant-level max_compute_depth MUST lower the
// budget depth, and its absence MUST leave the default.

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func hashOfString(t *testing.T, s string) hash.Hash {
	t.Helper()
	raw, err := ecf.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	h, err := hash.Compute("primitive/text", raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// computeConstraintGrant builds a grant entry whose constraints carry the given
// compute limits under the "system/compute" key — the exact shape the corpus
// wire driver mints. A zero value for either limit omits it.
func computeConstraintGrant(t *testing.T, maxOps, maxDepth int) *types.GrantEntry {
	t.Helper()
	compute := map[string]interface{}{}
	if maxOps > 0 {
		compute["max_compute_operations"] = uint64(maxOps)
	}
	if maxDepth > 0 {
		compute["max_compute_depth"] = uint64(maxDepth)
	}
	raw, err := ecf.Encode(map[string]interface{}{"system/compute": compute})
	if err != nil {
		t.Fatal(err)
	}
	return &types.GrantEntry{
		Handlers:    types.CapabilityScope{Include: []string{"system/compute"}},
		Operations:  types.CapabilityScope{Include: []string{"eval"}},
		Constraints: cbor.RawMessage(raw),
	}
}

func TestGrantConstraintLowersDepth(t *testing.T) {
	g := computeConstraintGrant(t, 0, 24)
	ops, depth := computeConstraintsOfGrant(g)
	if depth != 24 {
		t.Errorf("computeConstraintsOfGrant depth = %d, want 24 (grant-level max_compute_depth)", depth)
	}
	if ops != 0 {
		t.Errorf("computeConstraintsOfGrant ops = %d, want 0 (no ops constraint set)", ops)
	}

	// End to end through initBudget: the matching grant is the authorization-
	// correct source, and a depth of 24 (< the 1024 default) MUST win.
	hctx := &handler.HandlerContext{MatchingGrant: g}
	b := initBudget(hctx, entity.Entity{})
	if b.Depth != 24 {
		t.Errorf("initBudget depth = %d, want 24 — grant-level max_compute_depth must reach the evaluator (§5.2)", b.Depth)
	}
}

// The mutation: strip the constraint and the default MUST stand. If this passed
// at 24 it would mean the depth came from somewhere other than the grant, and
// the positive test above would prove nothing.
func TestGrantWithoutConstraintKeepsDefaultDepth(t *testing.T) {
	g := &types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{"system/compute"}},
		Operations: types.CapabilityScope{Include: []string{"eval"}},
	}
	if _, depth := computeConstraintsOfGrant(g); depth != 0 {
		t.Errorf("a grant with no constraints reported depth %d, want 0", depth)
	}
	b := initBudget(&handler.HandlerContext{MatchingGrant: g}, entity.Entity{})
	if b.Depth != DefaultMaxDepth {
		t.Errorf("initBudget depth = %d, want the default %d when no constraint is present", b.Depth, DefaultMaxDepth)
	}
}

// The token-scan variant (handler-grant ceiling + reactive path) reads the same
// limits out of a whole capability token, taking the tightest across grants.
func TestTokenConstraintScanFindsTightestDepth(t *testing.T) {
	loose := *computeConstraintGrant(t, 0, 512)
	tight := *computeConstraintGrant(t, 0, 24)
	// A grant that constrains a DIFFERENT handler namespace must contribute
	// nothing to the compute depth — the scan keys on "system/compute" only.
	otherRaw, err := ecf.Encode(map[string]interface{}{"system/inbox": map[string]interface{}{"max_size": uint64(8)}})
	if err != nil {
		t.Fatal(err)
	}
	unrelated := types.GrantEntry{
		Handlers:    types.CapabilityScope{Include: []string{"system/inbox"}},
		Constraints: cbor.RawMessage(otherRaw),
	}
	td := types.CapabilityTokenData{
		Grants:  []types.GrantEntry{unrelated, loose, tight},
		Granter: types.SingleSigGranter(hashOfString(t, "granter")),
		Grantee: hashOfString(t, "grantee"),
	}
	tokenEnt, err := td.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if _, depth := computeConstraintsOfToken(tokenEnt); depth != 24 {
		t.Errorf("computeConstraintsOfToken depth = %d, want the tightest (24) across grants", depth)
	}
}
