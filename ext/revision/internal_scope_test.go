package revision

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestManifestInternalScopeAuthorizesCrossPeerFetch is the teeth for the E1
// cross-peer fix (workbench-go tracker row 15). Under 0.8.2.19 the executing
// handler's grant gates Dimension 4 (peers) of an outbound sub-dispatch, and
// the default self-grant leaves peers absent → local-only. `system/revision:pull`
// dispatches `system/revision:fetch` at a FOREIGN peer, so the revision handler
// declares an InternalScope whose second entry carries a peers-wildcard for the
// fetch operations. This test drives that grant through the real Dimension-4
// check.
//
// Mutation witness: drop InternalScope entry 2 (the cross-peer fetch entry) and
// the cross-peer-fetch assertion flips to refused — which is exactly the E1
// breakage this fix closes. The narrow-scope control (a cross-peer COMMIT is
// refused) reddens if entry 2 is widened to all operations.
func TestManifestInternalScopeAuthorizesCrossPeerFetch(t *testing.T) {
	localKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate local: %v", err)
	}
	foreignKP, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate foreign: %v", err)
	}
	local := localKP.PeerID()
	foreign := string(foreignKP.PeerID())

	scope := (&Handler{}).Manifest().InternalScope
	if len(scope) < 2 {
		t.Fatalf("revision manifest must declare an InternalScope with a cross-peer fetch entry; got %d entries", len(scope))
	}
	cap := types.CapabilityTokenData{Grants: scope}

	foreignURI := "entity://" + foreign + "/system/revision"

	// THE FIX: an outbound `fetch` to a FOREIGN peer is authorized by the
	// handler grant's peers-wildcard entry.
	fetch := types.ExecuteData{URI: foreignURI, Operation: "fetch"}
	if !capability.CheckPermission(fetch, cap, "system/revision", local, local) {
		t.Fatal("revision handler grant must authorize an outbound cross-peer `fetch` (E1 Dimension 4); " +
			"it was refused — the pull orchestration cannot reach a foreign peer")
	}
	fetchEnts := types.ExecuteData{URI: foreignURI, Operation: "fetch-entities"}
	if !capability.CheckPermission(fetchEnts, cap, "system/revision", local, local) {
		t.Fatal("revision handler grant must authorize an outbound cross-peer `fetch-entities`")
	}

	// NARROW-SCOPE CONTROL: the cross-peer entry is scoped to fetch/fetch-entities
	// only. A cross-peer `commit` (a foreign write op the pull flow never makes)
	// must be REFUSED — proving entry 2 is a narrow reach, not a blanket
	// cross-peer widening. (Reddens if entry 2's operations are widened to "*".)
	crossCommit := types.ExecuteData{URI: foreignURI, Operation: "commit"}
	if capability.CheckPermission(crossCommit, cap, "system/revision", local, local) {
		t.Fatal("the cross-peer entry must NOT authorize a foreign `commit` — it is scoped to fetch/fetch-entities")
	}

	// LOCAL-AUTHORITY CONTROL: entry 1 reproduces the default self-grant, so a
	// LOCAL dispatch of any revision op is still authorized (no regression to
	// the local authority the default gave).
	localCommit := types.ExecuteData{URI: "entity://" + string(local) + "/system/revision", Operation: "commit"}
	if !capability.CheckPermission(localCommit, cap, "system/revision", local, local) {
		t.Fatal("local authority must be preserved: a local `commit` is refused — InternalScope entry 1 did not reproduce the default self-grant")
	}
}
