package validate

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"

	identitysdk "go.entitychurch.org/entity-core-go/ext/identity/sdk"
)

// catBehavioralRole drives the EXTENSION-ROLE v1.6 behavioral test
// vectors over the wire against a remote peer. The wire-conformance
// `role` category (see role.go) only checks handler manifests + type
// registrations; this category exercises the actual operations and
// invariants landed by PROPOSAL-ROLE-V1.5-SPEC-FIXES (the v1.5 → v1.6
// amendment batch).
//
// Coverage:
//
//	TV-RD-1  define-then-assign happy path: assignment entity binds,
//	         role-derived cap is issued at the R4 storage path, and
//	         the linkage entity (SI-5, new in v1.6) is bound at the
//	         sibling derived-tokens/ subtree.
//	TV-RD-2  reserved role name rejected (400 invalid_role_name) — R10
//	         covers "assignment", "excluded", "derived-tokens".
//	TV-RD-3  role definition missing (404 role_not_found).
//	TV-RD-4  excluded peer cannot be assigned (403 assignee_excluded;
//	         §4.3 step 4b layer-2 exclusion check).
//	TV-RD-5  exclude sweeps role-derived caps (§6.1 layer-1 token
//	         revocation). After exclude, the cap path is unbound.
//	TV-RD-6  hex path encoding (SI-1): the assignment path's peer-id
//	         segment is 66 lowercase hex characters starting with "00",
//	         NOT the Base58 PeerID.
//
// All tests use the validate-peer client's own identity (recovered from
// IdentityEntity()) as both the role-extension caller AND the assignee,
// which sidesteps synthesizing a peer entity the remote may not have
// locally. The remote peer issues the cap with grantee = client's
// identity-entity hash per SI-8; this is observable structurally
// without driving cap-chain verification.
const catBehavioralRole = "behavioral_role"

func runBehavioralRole(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catBehavioralRole)

	r.Declare("tv_rd_1_define_and_assign", "ROLE v1.6 §4.3 + §5.1 + SI-5")
	r.Declare("tv_rd_2_reserved_role_name", "ROLE v1.6 §3.2 R10")
	r.Declare("tv_rd_3_role_not_found", "ROLE v1.6 §4.3 step 5")
	r.Declare("tv_rd_4_assignee_excluded", "ROLE v1.6 §4.3 step 4b / R7 layer 2")
	r.Declare("tv_rd_5_exclude_sweeps_caps", "ROLE v1.6 §6.1 R7 layer 1")
	r.Declare("tv_rd_6_hex_path_encoding", "ROLE v1.6 §3.1 SI-1")
	r.Declare("tv_rd_7_re_derive_cascade", "ROLE v1.6 §5.5 IA9 / SI-6")
	r.Declare("tv_rd_8_re_derive_empty_set", "ROLE v1.6 §4.2 SI-14")
	r.Declare("tv_rd_9_unassign_single_role", "ROLE v1.6 §4.4 IA12 / SI-5")
	r.Declare("tv_rd_10_multi_role_isolation", "ROLE v1.6 §2.2 R6 + SI-5")
	r.Declare("tv_rd_11_unexclude_no_auto_restore", "ROLE v1.6 §6.4 + R7 L1")
	r.Declare("tv_rd_12_define_auto_re_derive", "ROLE v1.6 §8.2 IA11 + §5.5")
	r.Declare("tv_rd_13_selector_path_mismatch", "ROLE v1.6 §4.2 SI-25")
	r.Declare("tv_rd_14_malformed_path", "ROLE v1.6 §4.2 path decomposition")
	r.Declare("tv_rd_15_rl2_negative_narrow_cap", "ROLE v1.6 §4.3 step 5 / §8 IA10")
	r.Declare("tv_rd_16_layer3_not_on_system_tree", "ROLE v1.6 §7.4 / GUIDE §13.2")
	r.Declare("tv_rd_17_unassign_all_roles_form", "ROLE v1.6 §4.4 IA12 + R6")
	r.Declare("tv_rd_18_ia8_fleet_wide_sweep", "ROLE v1.6 §6.5 IA8 / GUIDE §13.7")
	r.Declare("tv_rd_19_si15_skipped_grantees", "ROLE v1.6 §5.5 SI-15")
	r.Declare("tv_rd_20_cap_chain_structure", "GUIDE-ROLE §4.2 + §10")
	r.Declare("tv_rd_21_cap_signature_valid", "ROLE v1.6 §5.1 + V7 §5.5")
	r.Declare("tv_rd_nil_expiry_strict_chain", "V7 v7.39 §5.6 nil-vs-finite (strict)")
	r.Declare("tv_rd_caller_expiry_inheritance", "ROLE v2.0 §5.3 MIN_DEFINED caller bound")
	r.Declare("tv_rd_delegate_sdk_shape", "ROLE v1.6 §5.6 IA22 (SDK shape; impl 501 expected)")
	r.Declare("tv_rd_24_delegate_locality_wire", "ROLE v1.6 §5.6 SI-19 (wire-call locality enforcement)")
	r.Declare("tv_rd_configure_sdk_shape", "IDENTITY v3.2 §6.1 (SDK shape; full ceremony fixture deferred)")
	r.Declare("tv_rv_1_14_delegate_grant_required", "VALIDATION-PROFILE-ROLE TV-RV-1.14 / PR-8.2 (cap-coverage at dispatch)")
	r.Declare("tv_rv_1_15_concurrent_assign_lww", "VALIDATION-PROFILE-ROLE TV-RV-1.15 / RR-4 (concurrent :assign LWW)")

	idHash := client.IdentityEntity().ContentHash
	idHex := hex.EncodeToString(idHash.Bytes())

	// Session-unique suffix on all test context paths. Without this, a
	// validate-peer re-run against the same peer hits state from prior
	// runs (existing role definitions, lingering assignments), and
	// V7 content-addressing collisions on identical-grant-and-timestamp
	// caps become observable as flaky failures (TV-RD-7 in particular —
	// re-derive against same-grants-same-millisecond produces caps with
	// hashes equal to prior runs', so the "T_new bound" assertion sees
	// stale paths). Each session uses its own suffix to guarantee a
	// fresh namespace.
	sessionSuffix := fmt.Sprintf("/%d", nowSessionMs())
	ctxBase := func(testID string) string {
		return "validate/role/" + testID + sessionSuffix
	}

	// roleURI returns the URI for system/role on the remote peer.
	roleURI := fmt.Sprintf("entity://%s/system/role", client.RemotePeerID())

	// callRole is a thin helper: send EXECUTE to system/role:<op> with the
	// given resource path + params; return (status, result-entity-or-empty,
	// error). All role ops use path-as-resource per V7 §3.2.
	callRole := func(op, path string, params entity.Entity) (uint, entity.Entity, error) {
		resource := &types.ResourceTarget{Targets: []string{path}}
		respEnv, _, sendErr := client.SendExecute(ctx, roleURI, op, params, resource)
		if sendErr != nil {
			return 0, entity.Entity{}, sendErr
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return 0, entity.Entity{}, fmt.Errorf("decode response: %w", decErr)
		}
		var resultEnt entity.Entity
		if len(respData.Result) > 0 {
			if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
				return respData.Status, entity.Entity{}, fmt.Errorf("decode result: %w", err)
			}
		}
		return respData.Status, resultEnt, nil
	}

	// roleSDK is the role SDK client — every typed wrapper below is a
	// thin pass-through to it. The validate-peer harness is the SDK's
	// first consumer; if the SDK changes shape, these wrappers absorb
	// the diff so the test bodies don't have to.
	roleSDK := rolesdk.NewClient(client)

	// defineRole writes a role definition with simple grants — covers
	// system/tree get/list on a test path. RL2 succeeds because the
	// validate-peer client has open-access wildcard grants.
	defineRole := func(context_, roleName string) (uint, error) {
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}}
		status, _, err := roleSDK.Define(ctx, context_, roleName, grants, nil)
		return status, err
	}

	// assignRole assigns idHash (the validate-peer client) to the named
	// role within the named context.
	assignRole := func(context_, roleName string) (uint, types.RoleAssignResultData, error) {
		return roleSDK.Assign(ctx, context_, idHash, roleName)
	}

	// excludePeer writes an exclusion entity at the resource path.
	excludePeer := func(context_ string, peerHash hash.Hash) (uint, error) {
		status, _, err := roleSDK.Exclude(ctx, context_, peerHash)
		return status, err
	}

	// unexcludePeer removes the exclusion entity at the resource path.
	unexcludePeer := func(context_ string, peerHash hash.Hash) (uint, error) {
		status, _, err := roleSDK.Unexclude(ctx, context_, peerHash)
		return status, err
	}

	// unassignRole removes the assignment entity for the given (peer, role)
	// in `context`. If roleName is empty, removes ALL roles for the peer
	// in the context (per §4.4 unassign-all form).
	unassignRole := func(context_ string, peerHash hash.Hash, roleName string) (uint, types.RoleUnassignResultData, error) {
		return roleSDK.Unassign(ctx, context_, peerHash, roleName)
	}

	// reDeriveRole drives system/role:re-derive against the role
	// definition path. Returns (status, result, err).
	reDeriveRole := func(context_, roleName string) (uint, types.RoleReDeriveResultData, error) {
		return roleSDK.ReDerive(ctx, context_, roleName)
	}

	// defineRoleWithGrants is the explicit-grants variant of defineRole;
	// used by tests that want to specify exactly what the role authorizes
	// (e.g., to verify re-derive emits a NEW cap with new grants).
	defineRoleWithGrants := func(context_, roleName string, grants []types.GrantEntry) (uint, types.RoleDefineResultData, error) {
		return roleSDK.Define(ctx, context_, roleName, grants, nil)
	}

	// treeGetExists checks whether a binding exists at `path` on the
	// remote peer via system/tree:get (returns true on 200, false on 404).
	treeGetExists := func(path string) (bool, error) {
		_, _, err := client.TreeGet(ctx, path)
		if err != nil {
			// Distinguish "not bound" from real errors. The TreeGet
			// helper returns errors with "status 404" on miss.
			if errStr := err.Error(); errStr != "" {
				if contains404(errStr) {
					return false, nil
				}
			}
			return false, err
		}
		return true, nil
	}

	// --- TV-RD-1 ---------------------------------------------------------
	r.Run("tv_rd_1_define_and_assign", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-1")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d (want 200)", status))
		}

		status, result, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("assign returned status %d (want 200)", status))
		}
		if len(result.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 derived token, got %d", len(result.DerivedTokens)))
		}

		// Verify the assignment entity binding exists.
		asnPath := role.AssignmentPath(ctxName, idHash, roleName)
		bound, err := treeGetExists(asnPath)
		if err != nil {
			return FailCheck("tree:get assignment: " + err.Error())
		}
		if !bound {
			return FailCheck("assignment entity not bound at " + asnPath)
		}

		// Verify the role-derived cap binding exists.
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, result.DerivedTokens[0])
		bound, err = treeGetExists(capPath)
		if err != nil {
			return FailCheck("tree:get cap: " + err.Error())
		}
		if !bound {
			return FailCheck("role-derived cap not bound at " + capPath)
		}

		// Verify the linkage entity (SI-5, new in v1.6) at the sibling
		// derived-tokens/ subtree.
		linkPath := role.DerivedTokenLinkPath(ctxName, idHash, roleName)
		bound, err = treeGetExists(linkPath)
		if err != nil {
			return FailCheck("tree:get linkage: " + err.Error())
		}
		if !bound {
			return FailCheck("v1.6 SI-5 linkage entity not bound at " + linkPath +
				" — impl may be missing the linkage write in :assign")
		}
		return PassCheck("TV-RD-1: define + assign produces assignment, cap, AND linkage entity (SI-5)")
	})

	// --- TV-RD-2 ---------------------------------------------------------
	r.Run("tv_rd_2_reserved_role_name", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-2")

		// Try to assign a role named "assignment" — reserved per R10.
		// Path-parsing-wise the role name segment lands at
		// system/role/{ctx}/assignment/{peer_hex}/assignment, which
		// happens to parse but the role name == reserved name. Some
		// impls might reject at parse-time; some at role-name check.
		// Either way the test verifies a 400-class rejection.
		req := types.RoleAssignRequestData{Role: "assignment"}
		ent, _ := req.ToEntity()
		path := role.AssignmentPath(ctxName, idHash, "assignment")
		status, _, err := callRole("assign", path, ent)
		if err != nil {
			return FailCheck("assign with reserved name: " + err.Error())
		}
		if status >= 200 && status < 300 {
			return FailCheck(fmt.Sprintf("expected 4xx for reserved role name, got %d", status))
		}
		if status < 400 || status >= 500 {
			return FailCheck(fmt.Sprintf("expected 400-class rejection, got %d", status))
		}
		return PassCheck(fmt.Sprintf("TV-RD-2: reserved role name 'assignment' rejected (status %d)", status))
	})

	// --- TV-RD-3 ---------------------------------------------------------
	r.Run("tv_rd_3_role_not_found", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-3")
		// Skip define; assign should fail with 404.
		status, _, err := assignRole(ctxName, "nonexistent-role")
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if status == 404 {
			return PassCheck("TV-RD-3: assign of undefined role correctly returned 404")
		}
		return FailCheck(fmt.Sprintf("expected 404 for missing role definition, got %d", status))
	})

	// --- TV-RD-4 ---------------------------------------------------------
	r.Run("tv_rd_4_assignee_excluded", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-4")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d", status))
		}

		// Exclude the would-be assignee FIRST.
		status, err := excludePeer(ctxName, idHash)
		if err != nil {
			return FailCheck("exclude: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("exclude returned status %d (want 200)", status))
		}

		// Now try to assign — should be rejected with 403.
		assignStatus, _, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign-after-exclude: " + err.Error())
		}
		if assignStatus == 403 {
			return PassCheck("TV-RD-4: assign of excluded peer correctly returned 403 (R7 layer 2)")
		}
		return FailCheck(fmt.Sprintf("expected 403 assignee_excluded, got %d", assignStatus))
	})

	// --- TV-RD-5 ---------------------------------------------------------
	r.Run("tv_rd_5_exclude_sweeps_caps", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-5")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d", status))
		}

		_, result, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if len(result.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("assign produced %d caps, expected 1", len(result.DerivedTokens)))
		}
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, result.DerivedTokens[0])

		// Verify cap is bound BEFORE exclude.
		bound, err := treeGetExists(capPath)
		if err != nil {
			return FailCheck("pre-exclude tree:get: " + err.Error())
		}
		if !bound {
			return FailCheck("cap not bound after assign — fixture broken")
		}

		// Exclude the peer.
		status, err := excludePeer(ctxName, idHash)
		if err != nil {
			return FailCheck("exclude: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("exclude returned status %d", status))
		}

		// Verify cap is GONE (layer-1 sweep per §6.1).
		bound, err = treeGetExists(capPath)
		if err != nil {
			return FailCheck("post-exclude tree:get: " + err.Error())
		}
		if bound {
			return FailCheck("cap STILL bound after exclude at " + capPath +
				" — R7 layer-1 token sweep did not run; SI-7 broad-sweep ruling not applied")
		}
		return PassCheck("TV-RD-5: exclude correctly swept role-derived cap (R7 layer 1)")
	})

	// --- TV-RD-6 ---------------------------------------------------------
	r.Run("tv_rd_6_hex_path_encoding", func() CheckOutcome {
		// Verify the hex form: lowercase hex of (1-byte algorithm + N-byte
		// digest) per V7 §3.5 invariant pointer convention; role v1.6 SI-1.
		// Width is format-relative: SHA-256 = 33 bytes / 66 hex; SHA-384 =
		// 49 bytes / 98 hex. The leading byte must match the active format.
		digestBytes := len(idHash.EffectiveDigest())
		expectedHexLen := 2 + digestBytes*2
		expectedAlgHex := fmt.Sprintf("%02x", idHash.Algorithm)
		if len(idHex) != expectedHexLen {
			return FailCheck(fmt.Sprintf("local identity hex has %d chars, expected %d (alg 0x%s, %d-byte hash)", len(idHex), expectedHexLen, expectedAlgHex, 1+digestBytes))
		}
		if idHex[:2] != expectedAlgHex {
			return FailCheck(fmt.Sprintf("local identity hex starts with %q, expected algorithm byte %q", idHex[:2], expectedAlgHex))
		}

		// Drive an assignment and confirm the parsed path's peer-id
		// segment matches the expected hex form. The remote peer would
		// reject any other encoding (e.g., Base58) at path-parse time
		// per the v1.6 ParseAssignmentPath grammar.
		ctxName := ctxBase("tv-rd-6")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d", status))
		}

		status, result, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("assign returned status %d — peer may not accept hex path segment", status))
		}

		// The result echoes the assignment path; verify it contains the hex form.
		if !pathContains(result.AssignmentPath, idHex) {
			return FailCheck(fmt.Sprintf("assignment_path %q missing peer-id hex segment %q",
				result.AssignmentPath, idHex))
		}
		return PassCheck("TV-RD-6: assignment path uses lowercase hex encoding for peer-id segment (SI-1)")
	})

	// --- TV-RD-7 ---------------------------------------------------------
	// Re-derive cascade: define + assign produces cap T_old; re-derive
	// issues T_new per §5.5 IA9 issue-first ordering. Verifies cascade
	// reaches existing assignees and reports counts.
	//
	// Note on V7 content-addressing: when re-derive runs against a
	// definition whose grants haven't changed AND CreatedAt collapses
	// to the same millisecond, T_new's content_hash equals T_old's —
	// V7 caps are content-addressed; identical authority + identical
	// metadata produces identical entities. In that case T_new IS
	// T_old (by hash equality), and the cap path remains bound. The
	// cascade still ran (re_derived_count > 0); the wire result is
	// just "the cap is the same entity."
	//
	// To actually observe distinct hashes, exercise the case where the
	// definition mutated between assign and re-derive (TV-RD-12 covers
	// the auto-cascade path). This TV verifies the explicit re-derive
	// op behaves correctly under both same-hash and distinct-hash
	// outcomes.
	r.Run("tv_rd_7_re_derive_cascade", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-7")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d", status))
		}

		_, asnResult, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck("expected 1 derived token after assign")
		}
		oldCapHash := asnResult.DerivedTokens[0]

		// Drive re-derive against the existing assignment.
		status, redrive, err := reDeriveRole(ctxName, roleName)
		if err != nil {
			return FailCheck("re-derive: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("re-derive returned status %d", status))
		}
		if redrive.ReDerivedCount < 1 {
			return FailCheck(fmt.Sprintf("re-derive count = %d, expected at least 1 — cascade did not reach assignee",
				redrive.ReDerivedCount))
		}
		if len(redrive.NewTokenHashes) < 1 {
			return FailCheck("re-derive produced no new token hashes — cascade did not issue T_new")
		}
		newCapHash := redrive.NewTokenHashes[0]

		// Verify T_new exists at its path (regardless of whether it
		// equals T_old's hash).
		newCapPath := role.RoleDerivedTokenPath(ctxName, idHash, newCapHash)
		bound, err := treeGetExists(newCapPath)
		if err != nil {
			return FailCheck("tree:get T_new: " + err.Error())
		}
		if !bound {
			return FailCheck("T_new not bound at " + newCapPath + " — re-derive did not persist the new cap")
		}

		if newCapHash == oldCapHash {
			// Content-addressing collapse: same grants + same timestamp
			// → same entity. Cap remains bound. Cascade observably ran
			// (count>0, new_token_hashes populated); no separate "T_old
			// revocation" needs to fire because T_old IS T_new.
			return PassCheck(fmt.Sprintf(
				"TV-RD-7: re-derive cascade ran (count=%d); T_new == T_old by content-addressing (V7 collapse — identical authority + timestamp)",
				redrive.ReDerivedCount))
		}

		// Distinct hashes — verify T_old is GONE (issue-first order).
		oldCapPath := role.RoleDerivedTokenPath(ctxName, idHash, oldCapHash)
		bound, err = treeGetExists(oldCapPath)
		if err != nil {
			return FailCheck("tree:get T_old: " + err.Error())
		}
		if bound {
			return FailCheck("T_old still bound after re-derive at " + oldCapPath +
				" — old cap not revoked; issue-first ordered cascade is incomplete")
		}
		return PassCheck(fmt.Sprintf(
			"TV-RD-7: re-derive cascade re-issued %d distinct cap(s); T_new bound, T_old revoked (issue-first order)",
			redrive.ReDerivedCount))
	})

	// --- TV-RD-8 ---------------------------------------------------------
	// Re-derive against a role with zero assignments — return 200 with
	// re_derived_count: 0 per SI-14 (cascade is a valid no-op).
	r.Run("tv_rd_8_re_derive_empty_set", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-8")
		roleName := "reader"

		// Define but DON'T assign anyone.
		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned status %d", status))
		}

		status, redrive, err := reDeriveRole(ctxName, roleName)
		if err != nil {
			return FailCheck("re-derive: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("expected 200 for empty re-derive, got %d", status))
		}
		if redrive.ReDerivedCount != 0 {
			return FailCheck(fmt.Sprintf("expected re_derived_count: 0 for empty role, got %d", redrive.ReDerivedCount))
		}
		if len(redrive.NewTokenHashes) != 0 {
			return FailCheck(fmt.Sprintf("expected empty new_token_hashes for no-assignment re-derive, got %d entries",
				len(redrive.NewTokenHashes)))
		}
		return PassCheck("TV-RD-8: re-derive on role with no assignees returns 200 with count=0 (SI-14)")
	})

	// --- TV-RD-9 ---------------------------------------------------------
	// Unassign single (peer, role): linkage entity for THAT role goes
	// away, cap goes away, but other roles for the same peer in the
	// same context are unaffected.
	r.Run("tv_rd_9_unassign_single_role", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-9")

		// Define two roles with DIFFERENT grants so the resulting caps
		// are distinct entities. (Identical grants + same-millisecond
		// timestamps collapse via V7 content-addressing — see TV-RD-7
		// and TV-RD-10 for the full discussion.)
		readerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		writerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "put"}},
		}}
		if status, _, err := defineRoleWithGrants(ctxName, "reader", readerGrants); err != nil {
			return FailCheck("define reader: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define reader returned %d", status))
		}
		if status, _, err := defineRoleWithGrants(ctxName, "writer", writerGrants); err != nil {
			return FailCheck("define writer: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define writer returned %d", status))
		}

		// Assign both.
		_, readerAsn, err := assignRole(ctxName, "reader")
		if err != nil {
			return FailCheck("assign reader: " + err.Error())
		}
		_, writerAsn, err := assignRole(ctxName, "writer")
		if err != nil {
			return FailCheck("assign writer: " + err.Error())
		}

		// Unassign only "reader".
		status, unassignResult, err := unassignRole(ctxName, idHash, "reader")
		if err != nil {
			return FailCheck("unassign reader: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("unassign reader returned %d", status))
		}
		_ = unassignResult

		// Reader assignment, linkage, cap should be gone.
		if bound, _ := treeGetExists(role.AssignmentPath(ctxName, idHash, "reader")); bound {
			return FailCheck("reader assignment still bound after unassign")
		}
		if bound, _ := treeGetExists(role.DerivedTokenLinkPath(ctxName, idHash, "reader")); bound {
			return FailCheck("reader linkage entity still bound — SI-5 cleanup did not run")
		}
		readerCapPath := role.RoleDerivedTokenPath(ctxName, idHash, readerAsn.DerivedTokens[0])
		if bound, _ := treeGetExists(readerCapPath); bound {
			return FailCheck("reader cap still bound after unassign — IA12 sweep did not run")
		}

		// Writer assignment, linkage, cap should ALL still exist.
		if bound, _ := treeGetExists(role.AssignmentPath(ctxName, idHash, "writer")); !bound {
			return FailCheck("writer assignment was incorrectly removed")
		}
		if bound, _ := treeGetExists(role.DerivedTokenLinkPath(ctxName, idHash, "writer")); !bound {
			return FailCheck("writer linkage entity was incorrectly removed — unassign cross-contamination")
		}
		writerCapPath := role.RoleDerivedTokenPath(ctxName, idHash, writerAsn.DerivedTokens[0])
		if bound, _ := treeGetExists(writerCapPath); !bound {
			return FailCheck("writer cap was incorrectly swept — IA12 sweep was over-broad")
		}
		return PassCheck("TV-RD-9: unassign(reader) cleanly removed reader's binding/linkage/cap; writer untouched (per-role isolation)")
	})

	// --- TV-RD-10 --------------------------------------------------------
	// Multi-role per (peer, context) — R6: a peer holds two roles in
	// the same context concurrently. Each role must produce a distinct
	// assignment entity, a distinct linkage entity, AND a distinct cap.
	// Roles are defined with DIFFERENT grants so the resulting caps are
	// also distinct entities (V7 content-addressing collapses identical
	// caps; the test exercises the typical case where role authorities
	// genuinely differ).
	r.Run("tv_rd_10_multi_role_isolation", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-10")

		readerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		writerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "put"}},
		}}
		if status, _, err := defineRoleWithGrants(ctxName, "reader", readerGrants); err != nil {
			return FailCheck("define reader: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define reader returned %d", status))
		}
		if status, _, err := defineRoleWithGrants(ctxName, "writer", writerGrants); err != nil {
			return FailCheck("define writer: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define writer returned %d", status))
		}

		_, r1, err := assignRole(ctxName, "reader")
		if err != nil {
			return FailCheck("assign reader: " + err.Error())
		}
		_, r2, err := assignRole(ctxName, "writer")
		if err != nil {
			return FailCheck("assign writer: " + err.Error())
		}

		// Distinct grants → distinct caps.
		if r1.DerivedTokens[0] == r2.DerivedTokens[0] {
			return FailCheck("expected distinct cap hashes for distinct grants — got the same hash, meaning grants were NOT actually different (or template resolution collapsed them)")
		}

		// Both assignments + linkages + caps must coexist independently.
		for _, rn := range []string{"reader", "writer"} {
			if bound, _ := treeGetExists(role.AssignmentPath(ctxName, idHash, rn)); !bound {
				return FailCheck(rn + " assignment not bound")
			}
			if bound, _ := treeGetExists(role.DerivedTokenLinkPath(ctxName, idHash, rn)); !bound {
				return FailCheck(rn + " linkage entity not bound — SI-5 multi-role write missing")
			}
		}
		// Both caps bound at their distinct paths.
		readerCapPath := role.RoleDerivedTokenPath(ctxName, idHash, r1.DerivedTokens[0])
		writerCapPath := role.RoleDerivedTokenPath(ctxName, idHash, r2.DerivedTokens[0])
		if bound, _ := treeGetExists(readerCapPath); !bound {
			return FailCheck("reader cap not bound at " + readerCapPath)
		}
		if bound, _ := treeGetExists(writerCapPath); !bound {
			return FailCheck("writer cap not bound at " + writerCapPath)
		}
		return PassCheck("TV-RD-10: multi-role per (peer, context) — distinct caps for reader/writer; assignments, linkages, and caps all coexist (R6)")
	})

	// --- TV-RD-11 --------------------------------------------------------
	// Unexclude does NOT auto-restore previously-revoked caps (§6.4).
	// After exclude, the cap is gone (sweep). After unexclude, the cap
	// is STILL gone — re-assignment is required to mint a new one.
	r.Run("tv_rd_11_unexclude_no_auto_restore", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-11")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		_, asn, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		oldCapPath := role.RoleDerivedTokenPath(ctxName, idHash, asn.DerivedTokens[0])

		if status, err := excludePeer(ctxName, idHash); err != nil {
			return FailCheck("exclude: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("exclude returned %d", status))
		}

		// Cap must be gone after exclude (sanity check; covered by TV-RD-5).
		if bound, _ := treeGetExists(oldCapPath); bound {
			return FailCheck("cap not swept by exclude — TV-RD-5 regression")
		}

		// Unexclude.
		if status, err := unexcludePeer(ctxName, idHash); err != nil {
			return FailCheck("unexclude: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("unexclude returned %d", status))
		}

		// Cap MUST still be gone after unexclude — caps are not auto-
		// restored. §6.4: "Removing the exclusion entity does NOT
		// auto-restore role-derived tokens (they were deleted)."
		if bound, _ := treeGetExists(oldCapPath); bound {
			return FailCheck("cap was AUTO-RESTORED after unexclude — §6.4 violation; this is a security regression (excluded peer regains caps without re-attestation)")
		}
		// Verify the assignee CAN be re-assigned (sanity: unexclude works).
		_, reassign, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("re-assign after unexclude: " + err.Error())
		}
		newCapPath := role.RoleDerivedTokenPath(ctxName, idHash, reassign.DerivedTokens[0])
		if bound, _ := treeGetExists(newCapPath); !bound {
			return FailCheck("re-assignment after unexclude failed to issue cap")
		}
		return PassCheck("TV-RD-11: unexclude does NOT auto-restore caps; re-assignment required (§6.4 fail-closed)")
	})

	// --- TV-RD-12 --------------------------------------------------------
	// Define triggers re-derive cascade automatically per §8.2 IA11:
	// when a role definition mutates and assignments exist, the handler
	// re-issues caps for all assignees. This test creates an assignment
	// under definition v1, mutates the definition (re-define same name
	// with different grants), and verifies the result reports a non-zero
	// re_derived_count.
	r.Run("tv_rd_12_define_auto_re_derive", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-12")
		roleName := "reader"

		// Define v1.
		v1 := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := defineRoleWithGrants(ctxName, roleName, v1); err != nil {
			return FailCheck("define v1: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define v1 returned %d", status))
		}

		// Assign so the cascade has someone to re-derive for.
		if _, _, err := assignRole(ctxName, roleName); err != nil {
			return FailCheck("assign: " + err.Error())
		}

		// Define v2 — same role, different grants. Per IA11 / §8.2 the
		// handler MUST trigger re-derive cascade.
		v2 := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test-v2/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}}
		status, defResult, err := defineRoleWithGrants(ctxName, roleName, v2)
		if err != nil {
			return FailCheck("define v2: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("define v2 returned %d", status))
		}
		if defResult.ReDerivedCount < 1 {
			return FailCheck(fmt.Sprintf("define-result.re_derived_count = %d; expected ≥1 — define did NOT trigger cascade per §8.2 IA11",
				defResult.ReDerivedCount))
		}
		return PassCheck(fmt.Sprintf(
			"TV-RD-12: define on existing role triggered re-derive cascade automatically (count=%d, §8.2 IA11)",
			defResult.ReDerivedCount))
	})

	// --- TV-RD-13 --------------------------------------------------------
	// Selector vs path consistency (SI-25): when both the resource path
	// and params.role carry a role-name selector, they MUST agree;
	// mismatch is rejected with 400 invalid_request.
	r.Run("tv_rd_13_selector_path_mismatch", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-13")
		pathRole := "reader"
		paramRole := "writer" // mismatch on purpose

		if status, err := defineRole(ctxName, pathRole); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}

		// Build assign request with mismatched role.
		req := types.RoleAssignRequestData{Role: paramRole}
		ent, _ := req.ToEntity()
		path := role.AssignmentPath(ctxName, idHash, pathRole)
		status, _, err := callRole("assign", path, ent)
		if err != nil {
			return FailCheck("assign with mismatch: " + err.Error())
		}
		if status >= 200 && status < 300 {
			return FailCheck(fmt.Sprintf("expected 4xx for selector/path mismatch, got %d", status))
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("expected 400 invalid_request for SI-25 mismatch, got %d", status))
		}
		return PassCheck("TV-RD-13: params.role / path role mismatch returns 400 (SI-25)")
	})

	// callRoleWithCap is the cap-override variant of callRole — sends
	// the EXECUTE under a custom (typically narrower) capability instead
	// of the connection default. Used by RL2 negative tests.
	callRoleWithCap := func(op, path string, params entity.Entity, customCap, customCapSig entity.Entity) (uint, entity.Entity, error) {
		resource := &types.ResourceTarget{Targets: []string{path}}
		respEnv, _, sendErr := client.SendExecuteWithCap(ctx, roleURI, op, params, resource, customCap, customCapSig, nil)
		if sendErr != nil {
			return 0, entity.Entity{}, sendErr
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return 0, entity.Entity{}, fmt.Errorf("decode response: %w", decErr)
		}
		var resultEnt entity.Entity
		if len(respData.Result) > 0 {
			if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
				return respData.Status, entity.Entity{}, fmt.Errorf("decode result: %w", err)
			}
		}
		return respData.Status, resultEnt, nil
	}

	// --- TV-RD-14 --------------------------------------------------------
	// Malformed assignment path: not under system/role; missing assignment/
	// segment; truncated. All return 400 malformed_resource.
	r.Run("tv_rd_14_malformed_path", func() CheckOutcome {
		req := types.RoleAssignRequestData{Role: "reader"}
		ent, _ := req.ToEntity()

		// Wrong root.
		status, _, err := callRole("assign", "system/foo/admin/assignment/abc/reader", ent)
		if err != nil {
			return FailCheck("call wrong-root path: " + err.Error())
		}
		if status >= 200 && status < 300 {
			return FailCheck(fmt.Sprintf("wrong root accepted with status %d", status))
		}

		// Truncated — no assignment segment.
		status, _, err = callRole("assign", "system/role/admin/reader", ent)
		if err != nil {
			return FailCheck("call truncated path: " + err.Error())
		}
		if status >= 200 && status < 300 {
			return FailCheck(fmt.Sprintf("truncated path accepted with status %d", status))
		}

		// Bad peer-id segment (not hex).
		status, _, err = callRole("assign", "system/role/admin/assignment/Z123/reader", ent)
		if err != nil {
			return FailCheck("call non-hex path: " + err.Error())
		}
		if status >= 200 && status < 300 {
			return FailCheck(fmt.Sprintf("non-hex peer-id accepted with status %d — v1.6 SI-1 expects hex", status))
		}
		return PassCheck("TV-RD-14: malformed paths (wrong root, truncated, non-hex peer-id) all rejected with 4xx")
	})

	// --- TV-RD-15 --------------------------------------------------------
	// RL2 enforcement (security-critical, GUIDE §8 + §13.5): a caller
	// with a NARROWER cap cannot define a role whose grants exceed the
	// cap's authority. The handler returns 403 assigner_authority_insufficient
	// and the role definition is NOT persisted.
	//
	// Setup:
	//   1. Mint a narrow self-cap chained from the open-access connection
	//      cap. Narrow scope: handlers=[system/role], operations=[define],
	//      resources=[system/role/{ctx}/safe-role]. (Just enough to call
	//      :define on ONE specific path.)
	//   2. Try to define a role with grants that exceed the narrow cap
	//      (e.g., grants targeting system/tree:put on shared/{ctx}/*).
	//   3. Expect 403 assigner_authority_insufficient.
	//
	// This is the load-bearing security invariant: without RL2, anyone
	// who can call :define could mint role-derived caps with arbitrary
	// scope. With RL2 fail-closed (IA10), the handler refuses.
	r.Run("tv_rd_15_rl2_negative_narrow_cap", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-15")
		roleName := "safe-role"
		definePath := role.RoleDefinitionPath(ctxName, roleName)

		// Mint a narrow self-cap: the client wields a cap whose grantee
		// is the client (so the remote accepts it as the EXECUTE author's
		// authority). The narrow grant authorizes system/role:define
		// ONLY on this specific role-definition path. It does NOT cover
		// system/tree:put anywhere — so when :define checks RL2, the
		// proposed grants exceed the narrow cap and RL2 fails closed.
		narrowCap, narrowCapSig, err := client.CreateDispatchCapabilityWithGrants(
			[]types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
				Resources:  types.CapabilityScope{Include: []string{definePath}},
				Operations: types.CapabilityScope{Include: []string{"define"}},
			}},
		)
		if err != nil {
			return FailCheck("mint narrow cap: " + err.Error())
		}

		// Try to define a role whose grants include system/tree:put
		// scope — strictly broader than the narrow cap covers.
		req := types.RoleDefineRequestData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"put"}},
			}},
		}
		ent, _ := req.ToEntity()

		status, _, err := callRoleWithCap("define", definePath, ent, narrowCap, narrowCapSig)
		if err != nil {
			return FailCheck("define under narrow cap: " + err.Error())
		}
		if status == 200 {
			return FailCheck("RL2 BYPASSED — narrow cap was allowed to mint a broader role definition. SECURITY REGRESSION: §8 IA10 fail-closed not enforced over the wire.")
		}
		if status != 403 {
			return FailCheck(fmt.Sprintf("expected 403 assigner_authority_insufficient (RL2 fail-closed); got %d", status))
		}

		// Verify the role definition was NOT persisted.
		bound, _ := treeGetExists(definePath)
		if bound {
			return FailCheck("role definition was persisted despite RL2 rejection — §8 IA10 partial-write violation; this would let low-authority callers leave traces of attempted privilege escalation")
		}
		return PassCheck("TV-RD-15: RL2 enforcement — narrow cap rejected with 403; role definition NOT persisted (fail-closed per IA10)")
	})

	// --- TV-RD-16 --------------------------------------------------------
	// Layer-3 exclusion is opt-in per handler; system/tree explicitly
	// does NOT check exclusion (per GUIDE §13.2 / §7.4). This means an
	// excluded peer can still use NON-role-derived caps against system/tree.
	// Test: assign a role; exclude (which sweeps role-derived caps); verify
	// system/tree:get with the connection's open-access (non-role-derived)
	// cap STILL succeeds.
	//
	// The honest-scoping test. Documented antipattern: assuming exclusion
	// is universal denial. The reality is exclusion deletes role-derived
	// tokens (layer 1) and blocks new derivation (layer 2); it does NOT
	// touch caps held outside the role-derived storage path.
	r.Run("tv_rd_16_layer3_not_on_system_tree", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-16")

		// Sanity: tree:get on a stable path works before any setup.
		preExist, err := treeGetExists("system/handler/system/role")
		if err != nil {
			return FailCheck("pre-setup tree:get sanity: " + err.Error())
		}
		if !preExist {
			return FailCheck("system/handler/system/role not bound on remote — fixture broken")
		}

		// Exclude the validate-peer client.
		if status, err := excludePeer(ctxName, idHash); err != nil {
			return FailCheck("exclude: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("exclude returned %d", status))
		}

		// AFTER exclude, tree:get on a non-role path MUST still succeed.
		// The connection cap is open-access (not role-derived); layer 3
		// is opt-in and system/tree does not opt in.
		bound, err := treeGetExists("system/handler/system/role")
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"post-exclude tree:get failed: %s — this would mean exclusion is being applied at the system/tree layer, "+
					"which violates the honest three-layer scoping (GUIDE §13.2: 'the generic system/tree handler does NOT' check exclusion)",
				err.Error()))
		}
		if !bound {
			return FailCheck("post-exclude tree:get unbound the path — exclusion incorrectly affected non-role state")
		}
		return PassCheck("TV-RD-16: layer-3 exclusion not applied to system/tree — non-role cap survives exclude (honest scoping per §7.4)")
	})

	// --- TV-RD-17 --------------------------------------------------------
	// Unassign all-roles-for-peer form (§4.4): when the resource path
	// omits the trailing /{role_name} segment, unassign removes EVERY
	// assignment for the peer in that context. Tests that:
	//   - All assignment entities for the peer are gone.
	//   - All linkage entities for the peer are gone.
	//   - All role-derived caps for the peer in the context are revoked.
	r.Run("tv_rd_17_unassign_all_roles_form", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-17")

		// Define + assign two distinct roles.
		readerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		writerGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "put"}},
		}}
		if status, _, err := defineRoleWithGrants(ctxName, "reader", readerGrants); err != nil {
			return FailCheck("define reader: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define reader returned %d", status))
		}
		if status, _, err := defineRoleWithGrants(ctxName, "writer", writerGrants); err != nil {
			return FailCheck("define writer: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define writer returned %d", status))
		}
		_, r1, err := assignRole(ctxName, "reader")
		if err != nil {
			return FailCheck("assign reader: " + err.Error())
		}
		_, r2, err := assignRole(ctxName, "writer")
		if err != nil {
			return FailCheck("assign writer: " + err.Error())
		}

		// Unassign with NO role segment — the all-roles-for-peer form.
		status, _, err := unassignRole(ctxName, idHash, "")
		if err != nil {
			return FailCheck("unassign all-roles: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("unassign all-roles returned %d (want 200)", status))
		}

		// Both assignments gone.
		for _, rn := range []string{"reader", "writer"} {
			if bound, _ := treeGetExists(role.AssignmentPath(ctxName, idHash, rn)); bound {
				return FailCheck(rn + " assignment still bound after unassign-all")
			}
			if bound, _ := treeGetExists(role.DerivedTokenLinkPath(ctxName, idHash, rn)); bound {
				return FailCheck(rn + " linkage still bound after unassign-all")
			}
		}
		// Both caps gone.
		for _, capHash := range []hash.Hash{r1.DerivedTokens[0], r2.DerivedTokens[0]} {
			capPath := role.RoleDerivedTokenPath(ctxName, idHash, capHash)
			if bound, _ := treeGetExists(capPath); bound {
				return FailCheck("cap still bound at " + capPath + " after unassign-all-roles")
			}
		}
		return PassCheck("TV-RD-17: unassign all-roles form removed both assignments + linkages + caps for the peer in context")
	})

	// --- TV-RD-18 --------------------------------------------------------
	// IA8 fleet-wide reactive sweep (§6.5, GUIDE §13.7): when an
	// exclusion entity arrives at a runtime peer via tree-sync (not
	// via the local handler's :exclude op), the peer's OnTreeChange
	// hook MUST sweep its local role-derived subtree for that peer in
	// that context. This is what makes layer-1 fleet-wide rather than
	// "the issuing peer's tokens are revoked."
	//
	// Single-peer simulation: we drive an exclusion entity directly via
	// system/tree:put (bypassing system/role:exclude). This simulates
	// the sync-arrival case — to the OnTreeChange hook, a tree-mutation
	// event from sync looks identical to one from a local tree:put. The
	// hook MUST observe the entity, recognize it as system/role/exclusion,
	// and trigger the broad sweep per SI-7 (delete every cap at the
	// role-derived subtree on this peer).
	//
	// Real cross-peer propagation is validated by the subscription
	// category; this test isolates the hook behavior, which is the
	// load-bearing IA8 invariant.
	//
	// SECURITY NOTE: §13.7 antipattern. If the IA8 hook is missing or
	// only fires on handler-driven excludes, then peer A excluding Bob
	// does NOT actually clean up Bob's caps on peer B — and an attacker
	// holding Bob's keypair could continue using B's locally-bound caps
	// across the propagation window. This test is the cross-impl
	// canary for "fleet-wide actually works."
	r.Run("tv_rd_18_ia8_fleet_wide_sweep", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-18")
		roleName := "reader"

		// Set up: define + assign so a cap exists in the local subtree.
		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		_, asn, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, asn.DerivedTokens[0])

		bound, err := treeGetExists(capPath)
		if err != nil {
			return FailCheck("pre-sync tree:get: " + err.Error())
		}
		if !bound {
			return FailCheck("cap not bound after assign — fixture broken")
		}

		// Construct an exclusion entity that mimics what the role
		// handler would produce. The entity type matters because the
		// IA8 hook validates `ent.Type == TypeRoleExclusion` before
		// running the sweep — a malformed type wouldn't trigger.
		exclData := types.RoleExclusionData{
			ExcludedBy: idHash,
			ExcludedAt: uint64(time.Now().UnixMilli()),
			Reason:     "tv-rd-18 simulated sync arrival",
		}
		exclEnt, err := exclData.ToEntity()
		if err != nil {
			return FailCheck("encode exclusion entity: " + err.Error())
		}

		// Drive a system/tree:put directly to the exclusion path.
		// This bypasses system/role:exclude (which would do its own
		// inline sweep) and exercises ONLY the OnTreeChange hook path.
		exclPath := role.ExclusionPath(ctxName, idHash)
		if _, err := client.TreePut(ctx, exclPath, exclEnt); err != nil {
			return FailCheck(fmt.Sprintf(
				"tree:put exclusion entity: %s — note: per §13.2, granting raw tree:put on exclusion paths is a deployment antipattern, but the open-access test fixture allows it specifically to exercise the IA8 sync-arrival path without a multi-peer setup",
				err.Error()))
		}

		// Verify the exclusion entity bound (sanity).
		if bound, _ := treeGetExists(exclPath); !bound {
			return FailCheck("exclusion entity not bound at " + exclPath + " after tree:put — the impl may be rejecting direct writes to the exclusion subtree (which is allowed by SI-10 but surfaces here)")
		}

		// The OnTreeChange hook should now have fired and swept the
		// local role-derived subtree. Verify the cap is gone.
		bound, err = treeGetExists(capPath)
		if err != nil {
			return FailCheck("post-sync tree:get: " + err.Error())
		}
		if bound {
			return FailCheck(fmt.Sprintf(
				"CAP STILL BOUND at %s after exclusion entity was written via tree:put. "+
					"The IA8 sync-hook sweep did NOT run. Per §6.5 IA8: a runtime peer that "+
					"receives an exclusion entity via tree-sync MUST sweep its local role-derived "+
					"subtree. This is a fleet-wide enforcement gap — peer-A excluding Bob would "+
					"leave Bob's caps live on this peer until they expire or are independently "+
					"revoked, which is the exact attack window §13.7 + GUIDE §14.4 warn about.",
				capPath))
		}
		return PassCheck("TV-RD-18: IA8 fleet-wide sweep ran on simulated sync-arrival — exclusion entity bound via tree:put triggered OnTreeChange and swept the local role-derived subtree (§6.5)")
	})

	// --- TV-RD-19 --------------------------------------------------------
	// SI-15 skipped_grantees: when re-derive cascade visits an assignee
	// whose resolved grants exceed the caller's authority, that assignee
	// is skipped (retains T_old) and reported in skipped_grantees;
	// remaining assignees continue normally.
	//
	// Setup uses templated role grants (`{peer_id}` template resolves
	// per-assignee), two assignees with different identity hashes, and
	// a narrow caller cap that covers ONE assignee's resolved scope but
	// not the other's.
	//
	// Steps:
	//   1. Define role with grants: handlers=[system/tree], resources=[users/{peer_id}/*],
	//      operations=[get]. Templated.
	//   2. Assign role to P1 (the validate-peer client's own identity)
	//      under wide cap.
	//   3. Assign role to P2 (synthesized fake identity) under wide cap.
	//   4. Mint a NARROW cap with two grant entries:
	//        a. handlers=[system/role], operations=[re-derive], resources=[role-def-path]
	//           (authorizes the dispatch).
	//        b. handlers=[system/tree], operations=[get], resources=[users/P1_HEX/*]
	//           (covers P1's resolved grants; does NOT cover P2's).
	//   5. Drive re-derive under the narrow cap.
	//   6. Verify result:
	//        - re_derived_count == 1 (P1 re-derived; P2 skipped)
	//        - skipped_grantees contains P2's hash
	//        - skipped_grantees does NOT contain P1's hash
	//
	// Why this matters: SI-15 is the partial-cascade safety property.
	// Without skip-and-continue, RL2-failure-mid-cascade would either
	// abort the whole re-derive (leaving earlier ordered-write pairs
	// half-applied) or mint partial tokens (security regression). The
	// skip-and-report design preserves cascade integrity for covered
	// assignees while surfacing the gap for uncovered ones.
	r.Run("tv_rd_19_si15_skipped_grantees", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-19")
		roleName := "user-reader"
		roleDefPath := role.RoleDefinitionPath(ctxName, roleName)

		// P2 is a synthesized peer hash — same shape as a real identity-
		// entity hash (33 bytes, format 0x00). Used only for the assignment
		// path's peer_id segment; the cap is never actually wielded.
		var p2Bytes [33]byte
		p2Bytes[0] = hash.AlgorithmSHA256
		for i := 1; i < 33; i++ {
			p2Bytes[i] = byte(0x42)
		}
		p2Hash, err := hash.FromBytes(p2Bytes[:])
		if err != nil {
			return FailCheck("synthesize P2 hash: " + err.Error())
		}
		if p2Hash == idHash {
			return FailCheck("P2 collides with client identity — fixture broken")
		}

		// Step 1: define role with templated grants.
		// §PR-8: when the role-derived cap is later wielded by the validator,
		// its templated grants are resolved per-assignee. Use the explicit
		// server-namespace form so the resolved peer-relative pattern lines
		// up with the connection-cap authority (server's namespace), not the
		// validator's. Without this prefix the RL2 attenuation check at
		// re-derive time fails because the templated pattern canonicalizes
		// to /{validator}/users/... instead of /{server}/users/...
		templatedGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"/" + string(client.RemotePeerID()) + "/users/{peer_id}/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if status, _, err := defineRoleWithGrants(ctxName, roleName, templatedGrants); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}

		// Step 2: assign to P1 (under wide cap) — succeeds.
		if _, _, err := assignRole(ctxName, roleName); err != nil {
			return FailCheck("assign P1: " + err.Error())
		}

		// Step 3: assign to P2 (synthesized) under wide cap.
		// Build the assign call manually — assignRole helper assigns
		// to idHash by construction; here we want a different assignee.
		p2Hex := role.HashHex(p2Hash)
		p2AsnPath := role.AssignmentPath(ctxName, p2Hash, roleName)
		p2AsnReq := types.RoleAssignRequestData{Role: roleName}
		p2Ent, _ := p2AsnReq.ToEntity()
		if status, _, err := callRole("assign", p2AsnPath, p2Ent); err != nil {
			return FailCheck("assign P2: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("assign P2 returned %d (expected 200)", status))
		}

		// Step 4: mint narrow cap.
		// Resolved grant for P1: users/{idHex}/*
		// Resolved grant for P2: users/{p2Hex}/*
		// Narrow cap covers P1's resolved scope only.
		// §PR-8: the validator signs this cap (granter = validator), so
		// peer-relative patterns canonicalize against the validator's
		// peer_id. Use explicit server-namespace form for the resource
		// patterns so the delegated cap stays within the connection cap's
		// authority on the server's namespace.
		serverPrefix := "/" + string(client.RemotePeerID()) + "/"
		narrowGrants := []types.GrantEntry{
			// Authorize the dispatch.
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
				Resources:  types.CapabilityScope{Include: []string{serverPrefix + roleDefPath}},
				Operations: types.CapabilityScope{Include: []string{"re-derive"}},
			},
			// Cover P1's resolved grants (RL2 will pass for P1).
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{serverPrefix + "users/" + idHex + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		}
		narrowCap, narrowCapSig, err := client.CreateDispatchCapabilityWithGrants(narrowGrants)
		if err != nil {
			return FailCheck("mint narrow cap: " + err.Error())
		}

		// Step 5: drive re-derive under the narrow cap.
		req := types.RoleReDeriveRequestData{Role: roleName}
		reqEnt, _ := req.ToEntity()
		status, resultEnt, err := callRoleWithCap("re-derive", roleDefPath, reqEnt, narrowCap, narrowCapSig)
		if err != nil {
			return FailCheck("re-derive under narrow cap: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("re-derive returned %d (want 200 with skipped_grantees)", status))
		}

		result, decErr := types.RoleReDeriveResultDataFromEntity(resultEnt)
		if decErr != nil {
			return FailCheck("decode re-derive result: " + decErr.Error())
		}

		// Step 6: verify.
		if result.ReDerivedCount != 1 {
			return FailCheck(fmt.Sprintf(
				"re_derived_count = %d (expected 1 — P1 covered, P2 skipped)", result.ReDerivedCount))
		}
		if len(result.SkippedGrantees) != 1 {
			return FailCheck(fmt.Sprintf(
				"skipped_grantees has %d entries (expected 1 — only P2 should skip). "+
					"This means SI-15 reporting is missing or the cascade isn't applying RL2 per-assignee — "+
					"see GUIDE §8 + spec §5.5 for the per-assignee coverage check requirement.",
				len(result.SkippedGrantees)))
		}
		// The one skipped grantee must be P2.
		if result.SkippedGrantees[0] != p2Hash {
			gotHex := role.HashHex(result.SkippedGrantees[0])
			if result.SkippedGrantees[0] == idHash {
				return FailCheck("SECURITY: P1 (the covered assignee) was reported as skipped — RL2 is rejecting the COVERED assignee, which would mean the cascade fails for legit assignees. Got: P1=" + idHex + " in skipped_grantees.")
			}
			return FailCheck(fmt.Sprintf("skipped_grantees[0] = %s, expected P2=%s", gotHex, p2Hex))
		}
		return PassCheck("TV-RD-19: SI-15 skipped_grantees — re-derive under narrow cap re-derived P1 (covered) and reported P2 (uncovered) in skipped_grantees per §5.5 partial-cascade rule")
	})

	// --- TV-RD-20 --------------------------------------------------------
	// Cap-chain structure (Role v2.0 PR-1 + GUIDE-ROLE §4.2 + §10): the
	// role-derived cap has the shape mandated by EXTENSION-ROLE v2.0:
	//
	//   - granter = the runtime peer that signed (= the remote peer's
	//     identity hash for our test fixture; in identity-aware
	//     deployments it would still be the runtime peer, NOT the
	//     operator key — see GUIDE §4.2 + §10.2)
	//   - parent  = nil (ROOT CAP per Role v2.0 §5.1; symmetric with
	//     startup-time L0 derivation per §4.5)
	//   - grantee = the assignee's identity hash (per SI-8)
	//
	// Verifying these structural properties pins the v2.0 contract.
	// §10.2 op-key rotation invariance is now structural — the cap has
	// no chain link above itself that could possibly reference Op.
	r.Run("tv_rd_20_cap_chain_structure", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-20")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		_, asn, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		capHash := asn.DerivedTokens[0]
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, capHash)

		// Fetch the cap entity from the remote.
		capEnt, _, err := client.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("tree:get cap: " + err.Error())
		}
		if capEnt.Type != types.TypeCapToken {
			return FailCheck(fmt.Sprintf("cap entity type = %q, expected %q",
				capEnt.Type, types.TypeCapToken))
		}
		tok, err := types.CapabilityTokenDataFromEntity(capEnt)
		if err != nil {
			return FailCheck("decode cap: " + err.Error())
		}

		// granter MUST be the remote peer's identity (the runtime peer
		// that signed). NOT the validate-peer client (would be the
		// "operator" in a configured deployment).
		granter, ok := tok.Granter.SingleHash()
		if !ok {
			return FailCheck("cap granter is not single-sig — role-derived caps MUST be single-sig per §5.1")
		}
		// We don't know the remote's identity-entity hash directly via the
		// connection cap, so we use the cap's own granter — the assertion
		// is that it's NOT the client's identity (which would mean the
		// cap was signed by the assigner instead of the runtime peer; that
		// would be the §10.2 anti-pattern).
		if granter == idHash {
			return FailCheck("CHAIN-SHAPE BUG: cap granter == client identity. Per §4.2 + §10.2, role-derived caps' granter MUST be the RUNTIME PEER that signed, NOT the assigning identity. Operator-key-rotation invariant depends on this.")
		}

		// Role v2.0 PR-1: parent MUST be nil (root cap). Role-derived
		// caps are structurally symmetric with startup-time L0 caps —
		// both are root caps. The pre-v2.0 parent-as-handler-grant model
		// is removed; chain validation terminates at the role-derived
		// cap itself.
		if tok.Parent != nil {
			return FailCheck("Role v2.0 §5.1 VIOLATION: cap parent is set; role-derived caps MUST be ROOT CAPS (parent: nil) under v2.0. The pre-v2.0 parent-as-handler-grant model was removed in PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-1.")
		}

		// grantee MUST equal the assignee's identity hash (per SI-8 + §5.1).
		if tok.Grantee != idHash {
			return FailCheck(fmt.Sprintf(
				"cap grantee = %s, expected client identity = %s — SI-8 says grantee MUST equal the assignee's identity-entity content_hash (read from path segment, not invented)",
				role.HashHex(tok.Grantee), idHex))
		}
		return PassCheck("TV-RD-20: cap chain structure correct — granter=runtime-peer (not operator), parent=nil (root cap per Role v2.0 §5.1), grantee=assignee identity (per §4.2 + SI-8 + v2.0)")
	})

	// --- TV-RD-21 --------------------------------------------------------
	// Cap signature validity (§5.1 + V7 §5.5): after :assign, the role-
	// derived cap is signed by the granter's keypair. The signature is
	// bound at {capPath}/signature (V7 sibling-relative). Verify:
	//   - signature entity exists at {capPath}/signature
	//   - signature.target == cap.content_hash
	//   - signature.signer == cap.granter
	//   - signature.algorithm == "ed25519"
	//
	// We don't verify the actual Ed25519 cryptographic signature here
	// (would need the granter's public key, which is in their identity
	// entity). The role-extension category's authenticate flow already
	// proves connection-cap signatures are valid; this test focuses on
	// the structural hookup of role-derived cap signatures.
	r.Run("tv_rd_21_cap_signature_valid", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-21")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		_, asn, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		capHash := asn.DerivedTokens[0]
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, capHash)

		capEnt, _, err := client.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("tree:get cap: " + err.Error())
		}
		// v7.44 §3.5: a role-derived cap is a transportable authority-chain
		// root (ROLE PR-1), so its signature MUST be discoverable at the V7
		// INVARIANT POINTER PATH /{signer}/system/signature/{target_hex} —
		// not only the extension-private {capPath}/signature sibling. The
		// sibling-only assertion this check used to make was false green
		// (it validated ROLE's divergent convention, masking that a
		// role-derived-rooted cross-peer chain is untransportable). The
		// conformance gate is the invariant path; the extension MAY also
		// keep the sibling for its own bookkeeping (v7.44 permits "MAY
		// additionally").
		invSigPath := "/" + string(client.RemotePeerID()) + "/system/signature/" + hex.EncodeToString(capHash.Bytes())
		sigEnt, _, err := client.TreeGet(ctx, invSigPath)
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"tree:get cap signature at the V7 invariant pointer path %s: %s — role-derived caps are transportable chain roots; V7 v7.44 §3.5 REQUIRES the signature discoverable here so cross-peer transport/verify can find it. (Binding only at the extension-private {capPath}/signature is the v7.44 non-conformance this corrected check now catches.)",
				invSigPath, err.Error()))
		}
		if sigEnt.Type != types.TypeSignature {
			return FailCheck(fmt.Sprintf(
				"signature entity type = %q, expected %q",
				sigEnt.Type, types.TypeSignature))
		}
		sig, err := types.SignatureDataFromEntity(sigEnt)
		if err != nil {
			return FailCheck("decode signature: " + err.Error())
		}

		// signature.target MUST equal cap.content_hash.
		if sig.Target != capEnt.ContentHash {
			return FailCheck(fmt.Sprintf(
				"signature target = %s, expected cap content_hash = %s — signature is bound to the wrong target",
				role.HashHex(sig.Target), role.HashHex(capEnt.ContentHash)))
		}
		// signature.signer MUST equal cap.granter (single-sig).
		tok, err := types.CapabilityTokenDataFromEntity(capEnt)
		if err != nil {
			return FailCheck("decode cap: " + err.Error())
		}
		granter, ok := tok.Granter.SingleHash()
		if !ok {
			return FailCheck("cap granter is not single-sig (handled in TV-RD-20)")
		}
		if sig.Signer != granter {
			return FailCheck(fmt.Sprintf(
				"signature signer = %s, expected cap granter = %s — signer/granter mismatch breaks chain validation",
				role.HashHex(sig.Signer), role.HashHex(granter)))
		}
		if _, ok := crypto.KeyTypeByte(sig.Algorithm); !ok {
			return FailCheck(fmt.Sprintf(
				"signature algorithm = %q, expected one of {\"ed25519\", \"ed448\"} (v7.67 §3 crypto-agility)",
				sig.Algorithm))
		}
		if len(sig.Signature) == 0 {
			return FailCheck("signature bytes are empty — cap not actually signed")
		}
		return PassCheck(fmt.Sprintf("TV-RD-21: cap signature discoverable at the V7 §3.5 invariant pointer path /{signer}/system/signature/{target_hex} (v7.44 conformant), target/signer match cap, algorithm=%q, non-empty bytes (§5.1 + V7 §5.5 + v7.44 §3.5)", sig.Algorithm))
	})

	// --- TV-RD-NIL-EXPIRY ------------------------------------------------
	// V7 v7.39 §5.6 strict nil-vs-finite: a child cap with ExpiresAt=nil
	// chained from a parent with finite ExpiresAt MUST be rejected by
	// chain validation (IsAttenuated returns false). Per the architecture-
	// team ruling, the §5.6 pseudocode is normative; the prose
	// summary that left it ambiguous is now patched in v7.39.
	//
	// Setup (3-link chain, independent of connection-cap expiry shape):
	//   1. Mint INTERMEDIATE cap with finite expiry, parent = connection.
	//   2. Mint CHILD cap with nil expiry, parent = INTERMEDIATE.
	//   3. Send EXECUTE with CHILD; include INTERMEDIATE + sig in extras
	//      so the chain walker can resolve them.
	//   4. Expect chain-validation rejection (the (CHILD, INTERMEDIATE)
	//      attenuation step calls IsAttenuated; child nil + parent finite
	//      → false → 403).
	//
	// Adversarial intent: any peer that ACCEPTS this is non-conformant —
	// it would let callers laundry-shorten parent expiry by minting an
	// "infinite" grandchild, defeating the intermediate's bound.
	r.Run("tv_rd_nil_expiry_strict_chain", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-nil-expiry")
		roleName := "victim-role"
		definePath := role.RoleDefinitionPath(ctxName, roleName)

		broadGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}}

		// 1. Intermediate: finite expiry, parent = connection cap.
		intermediateExp := uint64(time.Now().Add(1 * time.Hour).UnixMilli())
		intermediate, intermediateSig, err := client.CreateDispatchCapabilityWithGrantsExpiry(broadGrants, &intermediateExp)
		if err != nil {
			return FailCheck("mint intermediate finite-expiry cap: " + err.Error())
		}

		// 2. Child: nil expiry, parent = intermediate.
		child, childSig, err := client.CreateChainedCap(intermediate, broadGrants, nil)
		if err != nil {
			return FailCheck("mint nil-expiry child cap: " + err.Error())
		}

		// 3. Include intermediate + its signature so chain walk can find them.
		extras := map[hash.Hash]entity.Entity{
			intermediate.ContentHash:    intermediate,
			intermediateSig.ContentHash: intermediateSig,
		}

		req := types.RoleDefineRequestData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		ent, _ := req.ToEntity()
		resource := &types.ResourceTarget{Targets: []string{definePath}}
		respEnv, _, sendErr := client.SendExecuteWithCap(ctx, roleURI, "define", ent, resource, child, childSig, extras)
		if sendErr != nil {
			return PassCheck(fmt.Sprintf("TV-RD-NIL-EXPIRY: nil-expiry grandchild rejected at transport (%s) — V7 v7.39 §5.6 strict enforced", sendErr.Error()))
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return FailCheck("decode response: " + decErr.Error())
		}
		if respData.Status == 200 {
			return FailCheck("V7 §5.6 BYPASSED — nil-expiry child against finite-expiry parent was accepted. Per v7.39 the pseudocode at §5.6 line 2047 is normative: child.expires_at=null with parent.expires_at!=null MUST return false. Accepting laundry-shortens parent's expiration bound.")
		}
		if respData.Status < 400 || respData.Status >= 500 {
			return FailCheck(fmt.Sprintf("expected 4xx chain-validation rejection, got %d", respData.Status))
		}
		return PassCheck(fmt.Sprintf("TV-RD-NIL-EXPIRY: nil-expiry grandchild against finite-expiry intermediate rejected (status %d) — V7 v7.39 §5.6 strict pseudocode enforced", respData.Status))
	})

	// --- TV-RD-CALLER-EXPIRY ---------------------------------------------
	// EXTENSION-ROLE v2.0 §5.3 MIN_DEFINED: when a role has no TTL in
	// metadata and the parent grant has no finite expiry of its own, the
	// minted role-derived cap MUST inherit the caller capability's expiry
	// as the upper bound. Per the architecture-team ruling,
	// this is the typical-case bound for identity-aware deployments where
	// the operational key is the caller and its cap is finite (refresh
	// hygiene).
	//
	// Setup:
	//   1. Mint a self-cap with broad grants and an EXPLICIT finite expiry
	//      (slightly under the connection cap's expiry, so it's the
	//      tightest bound of the three sources).
	//   2. Define + assign under this cap.
	//   3. Read back the role-derived cap.
	//   4. Verify cap.ExpiresAt is non-nil and ≤ caller cap's expiry.
	r.Run("tv_rd_caller_expiry_inheritance", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-caller-expiry")
		roleName := "reader"

		// Caller cap expires 1 hour from now — independent of connection-cap
		// shape. This is the tightest finite source in MIN_DEFINED for this
		// flow (no role TTL, no finite parent constraint in open-access).
		callerExp := uint64(time.Now().Add(1 * time.Hour).UnixMilli())

		// Broad grants so RL2 passes; the test isolates expiry inheritance.
		// §PR-8: child cap is validator-signed; use explicit server-namespace
		// resource form so the delegated child stays within the connection
		// cap's authority (bare "*" → /{validator}/* which is disjoint).
		serverWildcard := "/" + string(client.RemotePeerID()) + "/*"
		callerCap, callerCapSig, err := client.CreateDispatchCapabilityWithGrantsExpiry(
			[]types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{serverWildcard}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
			&callerExp,
		)
		if err != nil {
			return FailCheck("mint caller cap: " + err.Error())
		}

		// Define the role under the caller cap.
		definePath := role.RoleDefinitionPath(ctxName, roleName)
		// §PR-8: the role-definition grants get attenuated against the caller
		// cap (granter=validator) via RL2. Both sides canonicalize against
		// the caller's granter — so peer-relative patterns canonicalize to
		// /{validator}/... and don't fit under the caller cap's /{server}/*.
		// Use explicit server-namespace form so RL2 attenuation passes.
		defReq := types.RoleDefineRequestData{
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"/" + string(client.RemotePeerID()) + "/system/validate/role-test/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		defEnt, _ := defReq.ToEntity()
		if status, _, err := callRoleWithCap("define", definePath, defEnt, callerCap, callerCapSig); err != nil {
			return FailCheck("define under caller cap: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define under caller cap returned %d (want 200; RL2 may be rejecting broad caller cap)", status))
		}

		// Assign self under the caller cap.
		asnPath := role.AssignmentPath(ctxName, idHash, roleName)
		asnReq := types.RoleAssignRequestData{Role: roleName}
		asnEnt, _ := asnReq.ToEntity()
		status, resultEnt, err := callRoleWithCap("assign", asnPath, asnEnt, callerCap, callerCapSig)
		if err != nil {
			return FailCheck("assign under caller cap: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("assign under caller cap returned %d (want 200)", status))
		}
		asnResult, err := types.RoleAssignResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode assign result: " + err.Error())
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 derived token, got %d", len(asnResult.DerivedTokens)))
		}

		// Read back the role-derived cap and inspect its expiry.
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, asnResult.DerivedTokens[0])
		capEnt, _, err := client.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("tree:get role-derived cap: " + err.Error())
		}
		tok, err := types.CapabilityTokenDataFromEntity(capEnt)
		if err != nil {
			return FailCheck("decode role-derived cap: " + err.Error())
		}
		if tok.ExpiresAt == nil {
			return FailCheck("§5.3 v2.0 BYPASSED — role-derived cap has nil ExpiresAt despite finite caller-cap expiry. The MIN_DEFINED(parent, role.ttl, caller_cap) bound is not being applied; minted cap escapes the caller's expiration.")
		}
		if *tok.ExpiresAt > callerExp {
			return FailCheck(fmt.Sprintf("§5.3 v2.0 violation — role-derived cap expires at %d, caller cap expires at %d; minted cap MUST NOT outlive caller cap (RL2 + V7 §5.6)", *tok.ExpiresAt, callerExp))
		}
		return PassCheck(fmt.Sprintf("TV-RD-CALLER-EXPIRY: role-derived cap inherits caller-cap expiry (cap.expires_at=%d ≤ caller.expires_at=%d) — §5.3 v2.0 MIN_DEFINED bound enforced", *tok.ExpiresAt, callerExp))
	})

	// --- TV-RD-DELEGATE-SHAPE --------------------------------------------
	// Exercises the role SDK's Delegate(...) signature against the live
	// peer. Three plausible outcomes for a wire-caller (validate-peer
	// connects with its own identity, distinct from the remote peer's):
	//
	//   - 501 not_implemented              → PASS (impl deferred; old)
	//   - 400 delegator_must_be_local_peer → PASS (impl landed AND
	//     SI-19 locality enforced; expected for wire calls because the
	//     EXECUTE author (validate-peer client) != local_peer_id (the
	//     remote peer running the handler))
	//   - 200 success                      → PASS (impl landed AND the
	//     deployment happens to allow the wire-caller to be local —
	//     unusual, but valid)
	//   - any other status                 → FAIL (SDK shape drift or
	//     regression in pre-locality validation)
	//
	// Functional testing of the happy path lives in Go unit tests
	// (ext/role/*_test.go) where hctx.Author == hctx.LocalPeerID can be
	// constructed directly. Cross-impl convergence on the happy path is
	// via shared post-state contracts (cap shape at role-derived path).
	r.Run("tv_rd_delegate_sdk_shape", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-delegate-shape")
		roleName := "reader"

		// Set up: define + assign a role to self, so the delegator
		// (self) plausibly holds it. The delegate target is a synthetic
		// hash — the test only verifies the dispatch wiring; gap on
		// :delegate impl prevents end-to-end success today regardless.
		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		if status, _, err := assignRole(ctxName, roleName); err != nil {
			return FailCheck("assign: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("assign returned %d", status))
		}

		// Pin delegator to self for the assignment-path resource form.
		roleSDK.SetDelegator(idHash)

		// Synthetic delegate target — distinct from idHash.
		flipped := idHash.Bytes()
		flipped[len(flipped)-1] ^= 0xff
		delegateHash, fbErr := hash.FromBytes(flipped)
		if fbErr != nil {
			return FailCheck("synthesize delegate hash failed: " + fbErr.Error())
		}

		// Literal scope (no template variables — SI-20).
		scope := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}

		status, _, err := roleSDK.Delegate(ctx, ctxName, roleName, delegateHash, scope, nil)
		if err != nil {
			return FailCheck("delegate SDK call: " + err.Error())
		}
		switch {
		case status == 200:
			return PassCheck("TV-RD-DELEGATE-SHAPE: SDK Delegate succeeded end-to-end (200) — impl landed AND deployment allows wire-caller as local")
		case status == 400:
			return PassCheck("TV-RD-DELEGATE-SHAPE: SDK shape verified; impl landed AND SI-19 locality enforced (400 — expected for wire calls where author != local_peer_id). Functional happy-path testing lives in Go unit tests.")
		case status == 501:
			return PassCheck("TV-RD-DELEGATE-SHAPE: SDK shape verified — handler returns 501 (impl deferred, role v1.6 §5.6 IA22). When impl lands this auto-flips to 400 (locality) or 200 (success).")
		case status > 400 && status < 500:
			return FailCheck(fmt.Sprintf("delegate returned %d — expected 200 (success), 400 (SI-19 locality enforced for wire), or 501 (impl gap). Other 4xx suggests the SDK shape has drifted from spec or pre-locality validation regressed", status))
		default:
			return FailCheck(fmt.Sprintf("delegate returned unexpected status %d", status))
		}
	})

	// --- TV-RD-24 (delegate locality-enforcement wire test) --------------
	// Per SI-19, `:delegate` MUST run on the delegator's own runtime peer.
	// validate-peer always connects with an identity distinct from the
	// remote peer's, so the EXECUTE author (validate-peer client) ≠
	// local_peer_id (the remote peer running the handler). The handler
	// MUST reject with 400 + subcode `delegator_must_be_local_peer`.
	//
	// This is the cross-impl convergence assertion for delegate at the
	// wire level: every conformant impl returns the same subcode for
	// this case. Functional happy-path coverage lives in unit tests
	// (see ext/role/ops_delegate_test.go).
	r.Run("tv_rd_24_delegate_locality_wire", func() CheckOutcome {
		ctxName := ctxBase("tv-rd-24")
		roleName := "reader"

		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}
		if status, _, err := assignRole(ctxName, roleName); err != nil {
			return FailCheck("assign: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("assign returned %d", status))
		}

		// Synthetic delegate hash distinct from idHash.
		flipped := idHash.Bytes()
		flipped[len(flipped)-1] ^= 0xff
		delegateHash, fbErr := hash.FromBytes(flipped)
		if fbErr != nil {
			return FailCheck("synthesize delegate hash: " + fbErr.Error())
		}

		body := types.RoleDelegateRequestData{
			Delegate: delegateHash,
			Context:  ctxName,
			Role:     roleName,
			Scope: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		bodyEnt, err := body.ToEntity()
		if err != nil {
			return FailCheck("encode body: " + err.Error())
		}
		// Bypass the SDK so we can read the raw response and decode the
		// error subcode for cross-impl convergence assertion.
		resource := &types.ResourceTarget{Targets: []string{role.AssignmentPath(ctxName, idHash, roleName)}}
		respEnv, _, sendErr := client.SendExecute(ctx, roleURI, "delegate", bodyEnt, resource)
		if sendErr != nil {
			return FailCheck("send execute: " + sendErr.Error())
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return FailCheck("decode response: " + decErr.Error())
		}
		if respData.Status == 501 {
			return PassCheck("TV-RD-24: peer returns 501 (impl gap) — locality subcode not yet observable; will tighten when impl lands")
		}
		if respData.Status != 400 {
			return FailCheck(fmt.Sprintf("expected 400 (SI-19 locality), got %d — wire-callers from a different identity MUST be rejected with 400 delegator_must_be_local_peer", respData.Status))
		}
		code, err := decodeResultErrorCode(respData)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode error subcode: %s — peer responded 400 but error envelope is malformed", err.Error()))
		}
		if code != "delegator_must_be_local_peer" {
			return FailCheck(fmt.Sprintf("subcode = %q; cross-impl contract requires \"delegator_must_be_local_peer\" for SI-19 violations", code))
		}
		return PassCheck("TV-RD-24: SI-19 locality enforced over wire — 400 delegator_must_be_local_peer (cross-impl subcode contract)")
	})

	// --- TV-RD-CONFIGURE-SDK-SHAPE ---------------------------------------
	// Exercises the identity SDK's Configure(...) signature against the
	// live peer. This does NOT drive a full configure ceremony — that
	// requires real quorum + controller-cert attestations as setup, which
	// is a substantial Tier-3 fixture (deferred). What this TV verifies:
	//
	//   1. The identity SDK encodes the request, dispatches it, and
	//      decodes the response without wire-protocol errors.
	//   2. The handler responds with a sensible status — 200 if a
	//      ceremony already ran on the peer, or 4xx with an identity-
	//      specific error subcode if substrate prerequisites are missing.
	//
	// The acceptable outcomes mirror the delegate-shape pattern: any
	// well-formed response (including the expected validation 4xx) PASSes;
	// 0/5xx/transport errors FAIL because they indicate SDK wiring drift.
	r.Run("tv_rd_configure_sdk_shape", func() CheckOutcome {
		idSDK := identitysdk.NewClient(client)

		// Minimal-shape request. TrustsQuorum is a zero hash —
		// substrate will reject because no such quorum exists; that's
		// expected. The point is to exercise the SDK wiring.
		req := types.IdentityConfigureRequestData{
			TrustsQuorum: hash.Hash{},
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
				Resources:  types.CapabilityScope{Include: []string{"system/role/*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		status, _, err := idSDK.Configure(ctx, req)
		if err != nil {
			return FailCheck(fmt.Sprintf("identity SDK Configure transport/decode error: %s — SDK wiring is broken", err.Error()))
		}
		if status == 0 {
			return FailCheck("identity SDK Configure returned status=0 — no response decoded")
		}
		if status >= 500 && status != 501 {
			return FailCheck(fmt.Sprintf("identity SDK Configure returned %d — 5xx (other than 501) indicates the handler crashed", status))
		}
		// 200 (already configured), 400/403/404 (validation/auth gaps with
		// our minimal request), 501 (not implemented) — all acceptable.
		return PassCheck(fmt.Sprintf("TV-RD-CONFIGURE-SDK-SHAPE: identity SDK wiring works; handler returned %d (full ceremony test deferred to Tier-3 fixture work)", status))
	})

	// --- TV-RV-1.14 ------------------------------------------------------
	// VALIDATION-PROFILE-ROLE TV-RV-1.14: :delegate rejected at the V7
	// §5.2 dispatch layer (check_permission) when the presented cap does
	// NOT authorize system/role:delegate on the assignment subtree.
	// Closes PR-8.2 / TV-RD-DELEGATE-GRANT-REQUIRED.
	//
	// Setup: define a role whose grants do NOT include system/role:delegate.
	// Assign self → role-derived cap T_B is minted with grants drawn from
	// the role definition (so T_B doesn't authorize delegate either).
	//
	// Action: send EXECUTE op="delegate" presenting T_B as the caller cap.
	// The role-derived cap's grantee == the validate-peer client's identity
	// (per SI-8), so protocol-layer auth passes (cap.grantee == author).
	// Dispatch's check_permission then runs against T_B's grants vs the
	// requested op (system/role:delegate on the assignment path) — and
	// rejects with 403 BEFORE the handler runs (and BEFORE SI-19 locality
	// fires — which is the whole point of PR-8.2: pull the authorization
	// up to the dispatch layer so the handler doesn't need an internal
	// recheck).
	//
	// Adversarial intent: any peer that lets this through (returns 200 OR
	// returns 400/403 with a *handler-internal* subcode like
	// delegator_must_be_local_peer) is non-conformant — it would mean the
	// cap-coverage check isn't running at dispatch.
	r.Run("tv_rv_1_14_delegate_grant_required", func() CheckOutcome {
		ctxName := ctxBase("tv-rv-1-14")
		roleName := "no-delegate-role"

		// Define a role with operational grants but NO system/role:delegate.
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/validate/role-test/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}}
		statusD, _, err := defineRoleWithGrants(ctxName, roleName, grants)
		if err != nil {
			return FailCheck("define: " + err.Error())
		}
		if statusD != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", statusD))
		}

		// Assign self → role-derived cap T_B (grantee = client identity).
		_, asn, err := assignRole(ctxName, roleName)
		if err != nil {
			return FailCheck("assign: " + err.Error())
		}
		if len(asn.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("assign produced %d caps, expected 1", len(asn.DerivedTokens)))
		}
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, asn.DerivedTokens[0])
		capEnt, _, err := client.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("read role-derived cap: " + err.Error())
		}
		// V7 §3.5 invariant pointer path — sole signature location for
		// role-derived caps (signer = validated peer per ROLE v2.0 PR-1).
		capSigPath := types.InvariantSignaturePath(string(client.RemotePeerID()), asn.DerivedTokens[0])
		capSigEnt, _, err := client.TreeGet(ctx, capSigPath)
		if err != nil {
			return FailCheck("read role-derived cap sig: " + err.Error())
		}

		// Synthetic delegate target distinct from idHash.
		flipped := idHash.Bytes()
		flipped[len(flipped)-1] ^= 0xff
		delegateHash, fbErr := hash.FromBytes(flipped)
		if fbErr != nil {
			return FailCheck("synthesize delegate hash: " + fbErr.Error())
		}

		// Build :delegate body. Scope is irrelevant — dispatch rejects
		// before scope is examined.
		body := types.RoleDelegateRequestData{
			Delegate: delegateHash,
			Context:  ctxName,
			Role:     roleName,
			Scope: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		bodyEnt, err := body.ToEntity()
		if err != nil {
			return FailCheck("encode delegate body: " + err.Error())
		}

		// Send EXECUTE op="delegate" with T_B as the presented cap.
		resource := &types.ResourceTarget{Targets: []string{role.AssignmentPath(ctxName, idHash, roleName)}}
		respEnv, _, sendErr := client.SendExecuteWithCap(ctx, roleURI, "delegate", bodyEnt, resource, capEnt, capSigEnt, nil)
		if sendErr != nil {
			return FailCheck("send execute with T_B: " + sendErr.Error())
		}
		respData, decErr := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if decErr != nil {
			return FailCheck("decode response: " + decErr.Error())
		}

		// Expect 403 capability_denied at dispatch. Some impls may report
		// 401 unauthorized for cap-coverage failures; either is acceptable
		// as long as the rejection is a CAP-coverage one (NOT a handler-
		// internal subcode like delegator_must_be_local_peer, which would
		// indicate the dispatch check let the call through).
		if respData.Status == 200 {
			return FailCheck("PR-8.2 VIOLATION: :delegate returned 200 with a presented cap that doesn't authorize system/role:delegate. Dispatch's check_permission MUST reject before the handler runs (V7 §5.2).")
		}
		if respData.Status != 403 && respData.Status != 401 {
			return FailCheck(fmt.Sprintf("expected 403 (or 401) capability denied at dispatch, got %d — PR-8.2 says cap coverage is checked BEFORE handler dispatch", respData.Status))
		}
		// If we can decode an error subcode, the rejection MUST NOT be
		// delegator_must_be_local_peer — that subcode comes from the
		// handler's SI-19 check, which means dispatch let the call
		// through (which is exactly what PR-8.2 forbids).
		code, codeErr := decodeResultErrorCode(respData)
		if codeErr == nil && code == "delegator_must_be_local_peer" {
			return FailCheck("PR-8.2 VIOLATION: rejection subcode is delegator_must_be_local_peer (handler's SI-19 check). The cap-coverage check at dispatch should have fired FIRST and produced a capability_denied / unauthorized rejection.")
		}
		return PassCheck(fmt.Sprintf("TV-RV-1.14: PR-8.2 dispatch enforces cap coverage — :delegate rejected with status=%d code=%q before handler dispatch (cap doesn't authorize system/role:delegate)", respData.Status, code))
	})

	// --- TV-RV-1.15 ------------------------------------------------------
	// VALIDATION-PROFILE-ROLE TV-RV-1.15 / RR-4: concurrent :assign
	// converges to last-writer-wins on tree CAS. Two operational keys
	// invoking :assign for the same (peer, role) MUST both pass RL2
	// (caller cap covers role's grants), and the post-state has exactly
	// one assignment entity bound at the assignment path. Linkage / cap /
	// signature triples MAY transiently exist for both writers; cleanup
	// converges as the second writer's tree:put completes.
	//
	// Critically, impls MUST NOT serialize across operational keys —
	// concurrent calls from different operational keys both proceed in
	// parallel and rely on tree-CAS to converge. This is observable here
	// only as "doesn't deadlock / both responses come back"; the LWW
	// invariant we CAN check post-hoc is "exactly one assignment entity".
	//
	// We approximate "two operational keys" by issuing two parallel
	// :assign requests from the same validate-peer client (same key, same
	// connection). The handler-side concurrency model is what's being
	// tested — receiving two in-flight EXECUTEs for the same (peer, role)
	// without coupling them.
	r.Run("tv_rv_1_15_concurrent_assign_lww", func() CheckOutcome {
		ctxName := ctxBase("tv-rv-1-15")
		roleName := "concurrent-role"

		// Define the role first.
		if status, err := defineRole(ctxName, roleName); err != nil {
			return FailCheck("define: " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("define returned %d", status))
		}

		// Fire two :assign calls in parallel.
		type result struct {
			status uint
			res    types.RoleAssignResultData
			err    error
		}
		ch := make(chan result, 2)
		for i := 0; i < 2; i++ {
			go func() {
				status, res, err := assignRole(ctxName, roleName)
				ch <- result{status, res, err}
			}()
		}
		var results [2]result
		for i := 0; i < 2; i++ {
			results[i] = <-ch
		}

		// Both calls MUST succeed (both pass RL2; the role's grants are
		// covered by the validate-peer connection cap's open-access
		// wildcard). If one fails, that's an over-serialization bug.
		for i, rs := range results {
			if rs.err != nil {
				return FailCheck(fmt.Sprintf("concurrent assign %d errored: %v — RR-4 says both calls succeed (no cross-key serialization)", i, rs.err))
			}
			if rs.status != 200 {
				return FailCheck(fmt.Sprintf("concurrent assign %d returned status %d (want 200) — RR-4 says both pass RL2 in parallel", i, rs.status))
			}
		}

		// Post-state: exactly one assignment entity bound at the
		// assignment path. Tree CAS converges to the last writer.
		asnPath := role.AssignmentPath(ctxName, idHash, roleName)
		asnEnt, _, err := client.TreeGet(ctx, asnPath)
		if err != nil {
			return FailCheck("post-state read assignment: " + err.Error())
		}
		if asnEnt.Type != types.TypeRoleAssignment {
			return FailCheck(fmt.Sprintf("post-state assignment entity type = %q, expected %q", asnEnt.Type, types.TypeRoleAssignment))
		}

		// The two calls produced (potentially) two derived cap hashes.
		// Both could be bound transiently; eventually the tree converges
		// to the LWW assignment + its derived cap. We check that AT LEAST
		// the LWW-survivor is present — rather than asserting exactly one
		// of the two, which races with cleanup ordering (see profile
		// open-question §6.3).
		survivors := 0
		for _, rs := range results {
			if len(rs.res.DerivedTokens) != 1 {
				continue
			}
			capPath := role.RoleDerivedTokenPath(ctxName, idHash, rs.res.DerivedTokens[0])
			bound, err := treeGetExists(capPath)
			if err != nil {
				return FailCheck("post-state cap probe: " + err.Error())
			}
			if bound {
				survivors++
			}
		}
		if survivors == 0 {
			return FailCheck("RR-4 VIOLATION: post-state has zero role-derived caps bound after two successful concurrent :assign calls — both writers' caps were swept (cleanup over-aggressive)")
		}
		return PassCheck(fmt.Sprintf("TV-RV-1.15 / RR-4: two concurrent :assign(B,role) both returned 200 (no cross-key serialization), post-state has exactly one assignment entity at %s and %d/%d derived caps bound (LWW; transient overlap is profile-acceptable)", asnPath, survivors, len(results)))
	})

	return r.Results()
}

// nowSessionMs returns the current Unix millisecond timestamp as a
// session identifier. Used to guarantee unique context paths across
// validate-peer invocations against the same long-running peer.
func nowSessionMs() int64 {
	return time.Now().UnixMilli()
}

// contains404 reports whether an error string contains a 404 marker —
// the TreeGet helper signals "not found" via "status 404" / "not_found"
// in the error text.
func contains404(s string) bool {
	for i := 0; i < len(s)-2; i++ {
		if s[i] == '4' && s[i+1] == '0' && s[i+2] == '4' {
			return true
		}
	}
	return false
}

// pathContains is a thin wrapper around strings.Contains used to keep
// the test assertions readable without importing strings into this file.
func pathContains(path, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(path); i++ {
		if path[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
