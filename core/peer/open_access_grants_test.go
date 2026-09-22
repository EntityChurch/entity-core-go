package peer

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestOpenAccessGrantsCoversForeignPeer is the teeth for workbench-go tracker
// row 16. Under 0.8.2.19 E1 the peers dimension is checked on outbound
// sub-dispatch, and an ABSENT peers field defaults to {include:[local]}. So a
// development "open access" grant that omits peers is local-only for cross-peer
// dispatch — every cross-peer suite that runs under it silently loses the peers
// dimension. The general entry now carries an explicit peers wildcard.
//
// Mutation witness: set the general entry's Peers back to nil and the
// cross-peer assertion flips to refused.
func TestOpenAccessGrantsCoversForeignPeer(t *testing.T) {
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

	cap := types.CapabilityTokenData{Grants: OpenAccessGrants()}

	// An open-access grant must authorize a dispatch to a FOREIGN peer on all
	// four dimensions — it is a declared wildcard.
	foreignExec := types.ExecuteData{URI: "entity://" + foreign + "/system/tree", Operation: "get"}
	if !capability.CheckPermission(foreignExec, cap, "system/tree", local, local) {
		t.Fatal("OpenAccessGrants must authorize a cross-peer dispatch (E1 Dimension 4); " +
			"it was refused — the general grant has no peers wildcard")
	}

	// Control: local dispatch still authorized (no regression).
	localExec := types.ExecuteData{URI: "entity://" + string(local) + "/system/tree", Operation: "put"}
	if !capability.CheckPermission(localExec, cap, "system/tree", local, local) {
		t.Fatal("OpenAccessGrants must still authorize a local dispatch")
	}
}
