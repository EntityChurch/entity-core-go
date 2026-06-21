package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"
)

// addCrossPeerRoleIA8 wires the multi-peer IA8 fleet-wide sweep test
// (EXTENSION-ROLE v1.6 §6.5) into the convergence runner. Two peers
// A and B; both have a role + assignment for the same target peer X.
// When A excludes X, the exclusion entity propagates to B and B's
// IA8 sync hook MUST sweep B's local role-derived subtree for X.
//
// The propagation mechanism in production is tree-sync (continuation-
// based subscription replication writes entities into the destination
// peer's tree at matching paths, triggering OnTreeChange). For test
// directness we bypass the sync layer and TreePut the exclusion
// entity onto B at the same path — this triggers OnTreeChange on B
// the same way tree-sync would, isolating the IA8 invariant from
// the orthogonal sync-delivery mechanism (which is already tested
// elsewhere in the convergence category).
//
// Per the architecture-team revised sequence (Tier 4), this is the
// real cross-peer test that complements TV-RD-18's in-process
// simulation.
func addCrossPeerRoleIA8(r *CheckRunner, ctx context.Context, a, b *PeerClient, suffix string) {
	r.Declare("role_ia8_cross_peer_setup", "ROLE v1.6 §6.5 IA8 (multi-peer)")
	r.Declare("role_ia8_cross_peer_propagated_sweep", "ROLE v1.6 §6.5 IA8 (multi-peer)")

	ctxName := "validate/role-ia8-multi/" + suffix
	roleName := "reader"
	// X is the validate-peer client's identity hash — the same identity
	// is connected to both A and B, so it's the assignee on both.
	xHash := a.IdentityEntity().ContentHash

	r.Run("role_ia8_cross_peer_setup", func() CheckOutcome {
		// Build SDK clients for both peers.
		sdkA := rolesdk.NewClient(a)
		sdkB := rolesdk.NewClient(b)

		// Define the same role on both A and B (independent peer trees).
		roleGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := sdkA.Define(ctx, ctxName, roleName, roleGrants, nil); err != nil {
			return FailCheck("define on A: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define on A returned %d", status))
		}
		if status, _, err := sdkB.Define(ctx, ctxName, roleName, roleGrants, nil); err != nil {
			return FailCheck("define on B: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define on B returned %d", status))
		}

		// Assign X to the role on both peers. Each :assign issues a
		// role-derived cap at the local peer's role-derived subtree.
		statusA, asnA, err := sdkA.Assign(ctx, ctxName, xHash, roleName)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("assign on A: status=%d err=%v", statusA, err))
		}
		statusB, asnB, err := sdkB.Assign(ctx, ctxName, xHash, roleName)
		if err != nil || statusB != 200 {
			return FailCheck(fmt.Sprintf("assign on B: status=%d err=%v", statusB, err))
		}
		if len(asnA.DerivedTokens) != 1 || len(asnB.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 cap each, got A=%d B=%d",
				len(asnA.DerivedTokens), len(asnB.DerivedTokens)))
		}

		// Sanity: both caps are bound at their respective tree paths.
		capPathA := role.RoleDerivedTokenPath(ctxName, xHash, asnA.DerivedTokens[0])
		capPathB := role.RoleDerivedTokenPath(ctxName, xHash, asnB.DerivedTokens[0])
		if _, _, err := a.TreeGet(ctx, capPathA); err != nil {
			return FailCheck(fmt.Sprintf("A's role-derived cap missing pre-test: %v", err))
		}
		if _, _, err := b.TreeGet(ctx, capPathB); err != nil {
			return FailCheck(fmt.Sprintf("B's role-derived cap missing pre-test: %v", err))
		}

		r.Store("role_ia8_capPathA", capPathA)
		r.Store("role_ia8_capPathB", capPathB)
		r.Store("role_ia8_ctxName", ctxName)
		return PassCheck("multi-peer setup: role + assignment on A and B; both peers hold role-derived caps for X")
	})

	r.Run("role_ia8_cross_peer_propagated_sweep", func() CheckOutcome {
		if out, ok := r.Require("role_ia8_cross_peer_setup"); !ok {
			return out
		}
		ctxName := r.Load("role_ia8_ctxName").(string)
		capPathA := r.Load("role_ia8_capPathA").(string)
		capPathB := r.Load("role_ia8_capPathB").(string)

		// 1. Exclude X on A. A's local layer-1 sweep fires; A's role-
		//    derived cap for X is removed from A's tree.
		sdkA := rolesdk.NewClient(a)
		exclStatus, _, err := sdkA.Exclude(ctx, ctxName, xHash)
		if err != nil || exclStatus != 200 {
			return FailCheck(fmt.Sprintf("exclude on A: status=%d err=%v", exclStatus, err))
		}
		// A's cap should be gone.
		if _, _, err := a.TreeGet(ctx, capPathA); err == nil {
			return FailCheck("A's role-derived cap still present after :exclude — A's local layer-1 sweep failed")
		}

		// 2. Read A's exclusion entity (the freshly-bound one).
		exclPath := role.ExclusionPath(ctxName, xHash)
		exclEnt, _, err := a.TreeGet(ctx, exclPath)
		if err != nil {
			return FailCheck("read exclusion entity from A: " + err.Error())
		}
		if exclEnt.Type != types.TypeRoleExclusion {
			return FailCheck(fmt.Sprintf("exclusion entity type = %q, want %q", exclEnt.Type, types.TypeRoleExclusion))
		}

		// 3. Propagate the exclusion entity to B by writing it directly
		//    at the same path. In production this is what the tree-sync
		//    layer does (continuation-based subscription replication
		//    fetches the entity from A and puts it on B at the matching
		//    path). For test isolation we do the put directly so the
		//    test focuses on the IA8 invariant on B.
		if _, err := b.TreePut(ctx, exclPath, exclEnt); err != nil {
			return FailCheck("propagate exclusion to B via tree:put: " + err.Error())
		}

		// 4. Wait for B's IA8 sync hook to sweep its role-derived
		//    subtree for X. The OnTreeChange hook runs synchronously
		//    on the put, so a single subsequent TreeGet should see
		//    the cap gone — but allow a small poll window for any
		//    asynchronous index updates.
		var stillBound bool
		for i := 0; i < 25; i++ {
			if _, _, err := b.TreeGet(ctx, capPathB); err != nil {
				stillBound = false
				break
			}
			stillBound = true
			time.Sleep(40 * time.Millisecond)
		}
		if stillBound {
			return FailCheck("§6.5 IA8 BYPASSED on B: exclusion entity propagated to B but B's role-derived cap for X was NOT swept. The OnTreeChange hook on B did not fire layer-1 cleanup; fleet-wide exclusion is broken — peers in the fleet would keep issuing/holding caps for an excluded peer.")
		}
		return PassCheck("TV-RD-MULTI-IA8: exclusion entity propagated A→B; B's IA8 sync hook fired layer-1 sweep on B's local role-derived subtree (§6.5 fleet-wide enforcement verified across peer boundary)")
	})

	// =====================================================================
	// SEC-4 — pre-sync window: stale cap on B before exclusion propagates
	// =====================================================================
	r.Declare("role_sec_4_pre_sync_window", "ROLE v1.6 §6.5 propagation timing")
	r.Run("role_sec_4_pre_sync_window", func() CheckOutcome {
		ctxName := "validate/role-sec4/" + suffix
		roleName := "reader"
		sdkA := rolesdk.NewClient(a)
		sdkB := rolesdk.NewClient(b)

		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := sdkA.Define(ctx, ctxName, roleName, grants, nil); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("define A: status=%d err=%v", status, err))
		}
		if status, _, err := sdkB.Define(ctx, ctxName, roleName, grants, nil); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("define B: status=%d err=%v", status, err))
		}

		_, asnA, err := sdkA.Assign(ctx, ctxName, xHash, roleName)
		if err != nil {
			return FailCheck("assign A: " + err.Error())
		}
		_, asnB, err := sdkB.Assign(ctx, ctxName, xHash, roleName)
		if err != nil {
			return FailCheck("assign B: " + err.Error())
		}

		capPathA := role.RoleDerivedTokenPath(ctxName, xHash, asnA.DerivedTokens[0])
		capPathB := role.RoleDerivedTokenPath(ctxName, xHash, asnB.DerivedTokens[0])

		// Exclude on A only — do NOT propagate to B yet. This models the
		// pre-sync window: A's exclusion fired, B hasn't seen the entity.
		if status, _, err := sdkA.Exclude(ctx, ctxName, xHash); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("exclude A: status=%d err=%v", status, err))
		}

		// A's cap MUST be gone (local sweep ran).
		if _, _, err := a.TreeGet(ctx, capPathA); err == nil {
			return FailCheck("A's cap survived local exclude — A's layer-1 sweep failed")
		}

		// B's cap MUST still be present (no propagation yet). This documents
		// the eventual-consistency window: until the exclusion entity reaches
		// B, B continues serving its locally-issued cap. Per spec §6.5
		// "Propagation latency depends on sync topology."
		if _, _, err := b.TreeGet(ctx, capPathB); err != nil {
			return FailCheck(fmt.Sprintf("SEC-4 unexpected: B's cap was already swept before propagation (%v) — implies cross-peer state coupling that the spec doesn't define. The pre-sync window is supposed to leave B's local state untouched until exclusion entity arrives.", err))
		}

		// Now propagate by reading A's exclusion entity and writing it on B.
		exclPath := role.ExclusionPath(ctxName, xHash)
		exclEnt, _, err := a.TreeGet(ctx, exclPath)
		if err != nil {
			return FailCheck("read exclusion from A: " + err.Error())
		}
		if _, err := b.TreePut(ctx, exclPath, exclEnt); err != nil {
			return FailCheck("propagate exclusion to B: " + err.Error())
		}

		// Post-propagation: B's cap must be swept too (IA8 hook fired).
		if _, _, err := b.TreeGet(ctx, capPathB); err == nil {
			return FailCheck("post-propagation: B's cap STILL present — IA8 hook didn't fire on synced exclusion (regression of role_ia8_cross_peer_propagated_sweep)")
		}
		return PassCheck("SEC-4: pre-sync window confirmed (B served cap until exclusion entity arrived); post-sync IA8 fired correctly. Documents the eventual-consistency contract.")
	})

	// =====================================================================
	// SEC-11 — cross-peer role-def divergence: same context+name, different grants
	// =====================================================================
	r.Declare("role_sec_11_role_def_divergence", "ROLE v1.6 §1 cross-peer definition independence")
	r.Run("role_sec_11_role_def_divergence", func() CheckOutcome {
		ctxName := "validate/role-sec11/" + suffix
		roleName := "reader"
		sdkA := rolesdk.NewClient(a)
		sdkB := rolesdk.NewClient(b)

		// A's definition: get/list on shared/{ctx}/work/*
		grantsA := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/work/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}}
		// B's definition (same role name, DIFFERENT grants): get only on shared/{ctx}/team/*
		grantsB := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/team/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := sdkA.Define(ctx, ctxName, roleName, grantsA, nil); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("define A: status=%d err=%v", status, err))
		}
		if status, _, err := sdkB.Define(ctx, ctxName, roleName, grantsB, nil); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("define B: status=%d err=%v", status, err))
		}

		// Each peer assigns X to "their" version of the role.
		_, asnA, err := sdkA.Assign(ctx, ctxName, xHash, roleName)
		if err != nil {
			return FailCheck("assign A: " + err.Error())
		}
		_, asnB, err := sdkB.Assign(ctx, ctxName, xHash, roleName)
		if err != nil {
			return FailCheck("assign B: " + err.Error())
		}

		// Read both caps and verify they have DIFFERENT grants.
		capEntA, _, err := a.TreeGet(ctx, role.RoleDerivedTokenPath(ctxName, xHash, asnA.DerivedTokens[0]))
		if err != nil {
			return FailCheck("read A's cap: " + err.Error())
		}
		capEntB, _, err := b.TreeGet(ctx, role.RoleDerivedTokenPath(ctxName, xHash, asnB.DerivedTokens[0]))
		if err != nil {
			return FailCheck("read B's cap: " + err.Error())
		}
		tokA, _ := types.CapabilityTokenDataFromEntity(capEntA)
		tokB, _ := types.CapabilityTokenDataFromEntity(capEntB)

		if len(tokA.Grants) != 1 || len(tokB.Grants) != 1 {
			return FailCheck(fmt.Sprintf("expected single-grant caps, got A=%d B=%d", len(tokA.Grants), len(tokB.Grants)))
		}
		// The grants MUST differ (we defined them differently).
		aResources := tokA.Grants[0].Resources.Include
		bResources := tokB.Grants[0].Resources.Include
		if len(aResources) == 0 || len(bResources) == 0 {
			return FailCheck("missing Resources.Include in derived caps")
		}
		if aResources[0] == bResources[0] {
			return FailCheck(fmt.Sprintf("SEC-11 unexpected: A and B's derived caps have IDENTICAL resources (%q) despite divergent role definitions. Role definitions are supposed to be local; cross-peer agreement is out-of-band.", aResources[0]))
		}
		return PassCheck(fmt.Sprintf("SEC-11: cross-peer role-def divergence is observable. A's cap → %q (work), B's cap → %q (team). Confirms: definitions are local; cross-peer agreement is out-of-band per §1 (group-extension territory, not role's).", aResources[0], bResources[0]))
	})

	// =====================================================================
	// INT-2 — multi-device chain visibility via tree-sync (assignment entity propagation)
	// =====================================================================
	r.Declare("role_int_2_assignment_propagation", "GUIDE-ROLE §14 multi-device deployment")
	r.Run("role_int_2_assignment_propagation", func() CheckOutcome {
		ctxName := "validate/role-int2/" + suffix
		roleName := "reader"
		sdkA := rolesdk.NewClient(a)

		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := sdkA.Define(ctx, ctxName, roleName, grants, nil); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("define A: status=%d err=%v", status, err))
		}
		_, asnA, err := sdkA.Assign(ctx, ctxName, xHash, roleName)
		if err != nil {
			return FailCheck("assign A: " + err.Error())
		}

		// In production: A and B are sibling app peers under the same
		// operator. Tree-sync mirrors A's `system/role/{ctx}/assignment/*`
		// to B (subscribed to that prefix). Here we propagate the
		// assignment entity manually to model the post-sync state.
		asnPath := role.AssignmentPath(ctxName, xHash, roleName)
		asnEnt, _, err := a.TreeGet(ctx, asnPath)
		if err != nil {
			return FailCheck("read assignment from A: " + err.Error())
		}
		if _, err := b.TreePut(ctx, asnPath, asnEnt); err != nil {
			return FailCheck("propagate assignment to B: " + err.Error())
		}

		// B now has the assignment entity. Verify content matches A's.
		bAsnEnt, _, err := b.TreeGet(ctx, asnPath)
		if err != nil {
			return FailCheck("read assignment from B post-sync: " + err.Error())
		}
		if bAsnEnt.ContentHash != asnEnt.ContentHash {
			return FailCheck(fmt.Sprintf("INT-2 BREACH: assignment entity hash differs across A and B post-sync. A=%v, B=%v. Tree-sync must preserve content-hash identity.", asnEnt.ContentHash, bAsnEnt.ContentHash))
		}

		// The cap that A issued (DerivedTokens[0]) is at A's tree but the
		// linkage entity at derived-tokens/{X}/{role} would be at A as
		// well. B has the assignment but no cap yet — that's correct;
		// each peer issues its own caps independently. The shared state
		// is the assignment ENTITY, not the issued caps.
		capPathA := role.RoleDerivedTokenPath(ctxName, xHash, asnA.DerivedTokens[0])
		if _, _, err := a.TreeGet(ctx, capPathA); err != nil {
			return FailCheck("A's cap should still be bound: " + err.Error())
		}
		// B should NOT have A's cap (caps are per-peer).
		if _, _, err := b.TreeGet(ctx, capPathA); err == nil {
			return FailCheck("INT-2 unexpected: B has A's role-derived cap. Caps are issued per-peer; only the assignment entity is shared.")
		}
		return PassCheck("INT-2: assignment entity propagated A→B with content-hash identity preserved; per-peer cap independence maintained. Multi-device deployment shape (§14.1 + §3.5) verified.")
	})
}
