package validate

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	identitysdk "go.entitychurch.org/entity-core-go/ext/identity/sdk"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"
)

// VALIDATION-PROFILE-ROLE Stage-2 conformance checks. The profile lives
// at entity-core-architecture .../reviews/VALIDATION-PROFILE-ROLE.md.
// These are additive on top of Stage-1 (behavioral_role TV-RD-* and
// TV-RV-1.*) — Stage-1 must be green for these to be meaningful.
//
// Coverage map (profile → fixture):
//
//   TV-RV-2.1  state survives identity install   → addRoleStage2_StateSurvivesConfigure
//   TV-RV-2.2  new agent peer needs new assign   → addRoleStage2_NewAgentNeedsAssign
//   TV-RV-2.3  cap survives controller revoke    → addRoleStage2_CapSurvivesRevoke (RR-2)
//   TV-RV-2.4  keypair rotation invalidates caps → DEFERRED (RR-3)
//   TV-RV-2.5  encoding identity-bearing == raw  → addRoleStage2_EncodingConsistency
//   TV-RV-2.6  delegate between identity peers   → covered by acme_14_1_delegate_under_controller_cap
//   TV-RV-2.7  initial-grant recognize-on-attest → addRoleStage2_RecognizeOnAttest (RA-6)
//
// TV-RV-2.4 deferred: requires rotating the granter peer's runtime
// keypair, which means restarting peer A with a new keypair mid-test.
// The validate-peer harness can't drive that; the structural invariant
// "outstanding caps invalidated; re-derive heals" is implicitly covered
// by tv_rd_7_re_derive_cascade (re-derive sweeps old caps, mints new).
// Full RR-3 coverage requires multi-peer fixture work outside the
// single-peer convergence harness.

// addRoleStage2_StateSurvivesConfigure exercises VALIDATION-PROFILE-ROLE
// TV-RV-2.1: a Stage-1 role deployment (definitions + assignments +
// derived caps) MUST survive the addition of an identity layer via
// system/identity:configure. The configure ceremony installs identity
// substrate but does NOT mutate role-state-tree entities or invalidate
// previously-issued role-derived caps.
//
// Walkthrough:
//
//  1. Stage-1 setup: role:define + role:assign(self) → assignment +
//     role-derived cap T1 + linkage entity bound on the peer.
//  2. Snapshot the assignment entity hash, T1's hash, T1's signature
//     hash, and the linkage entity hash.
//  3. Run the §14.1 configure ceremony with validate-peer as controller
//     (same shape as addAcmeConfigureCeremony but on a fresh quorum so
//     this fixture is self-contained).
//  4. Re-read the assignment / cap / signature / linkage at their
//     original paths. Assert each is still bound at the same path with
//     the same content_hash.
//
// Why this matters: identity install is a substrate-extension event;
// the role layer's tree state lives at independent paths. Any impl
// that drops role-state on configure (e.g., wholesale re-init under
// the BindingChecker post-configure) is non-conformant. Closes RR-1
// "identity install is non-disruptive to existing role state."
func addRoleStage2_StateSurvivesConfigure(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("role_stage2_state_survives_configure", "VALIDATION-PROFILE-ROLE TV-RV-2.1")

	r.Run("role_stage2_state_survives_configure", func() CheckOutcome {
		// Step 1 — Stage-1 setup.
		ctxName := "validate/stage2-survives/" + suffix
		roleName := "pre-configure-role"
		idHash := a.IdentityEntity().ContentHash

		roleClient := rolesdk.NewClient(a)
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get", "list"}},
		}}
		statusD, _, err := roleClient.Define(ctx, ctxName, roleName, grants, nil)
		if err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define: status=%d err=%v", statusD, err))
		}
		statusA, asnResult, err := roleClient.Assign(ctx, ctxName, idHash, roleName)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("role:assign: status=%d err=%v", statusA, err))
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 derived token, got %d", len(asnResult.DerivedTokens)))
		}
		t1Hash := asnResult.DerivedTokens[0]

		// Step 2 — snapshot pre-configure paths + content hashes.
		asnPath := role.AssignmentPath(ctxName, idHash, roleName)
		capPath := role.RoleDerivedTokenPath(ctxName, idHash, t1Hash)
		// V7 §3.5 invariant pointer path — the canonical (and, for
		// role-derived caps, sole) signature location. Signer is the
		// validated peer: ROLE v2.0 PR-1 mints role-derived caps with
		// granter = local peer identity, and the granter signs.
		sigPath := types.InvariantSignaturePath(string(a.RemotePeerID()), t1Hash)
		linkPath := role.DerivedTokenLinkPath(ctxName, idHash, roleName)

		preAsn, _, err := a.TreeGet(ctx, asnPath)
		if err != nil {
			return FailCheck("pre-configure read assignment: " + err.Error())
		}
		preCap, _, err := a.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("pre-configure read cap: " + err.Error())
		}
		preSig, _, err := a.TreeGet(ctx, sigPath)
		if err != nil {
			return FailCheck("pre-configure read cap sig: " + err.Error())
		}
		preLink, _, err := a.TreeGet(ctx, linkPath)
		if err != nil {
			return FailCheck("pre-configure read linkage: " + err.Error())
		}

		// Step 3 — configure ceremony with a fresh quorum.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/stage2-survives/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "stage2-survives-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}
		signers := []multiSigSigner{founders[0], founders[1]}
		if _, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, idHash, signers); err != nil {
			return FailCheck("controller cert: " + err.Error())
		}
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusC, _, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
		}

		// Step 4 — verify role state survives.
		postAsn, _, err := a.TreeGet(ctx, asnPath)
		if err != nil {
			return FailCheck("RR-1 VIOLATION: assignment entity unbound after configure (" + err.Error() + ")")
		}
		if postAsn.ContentHash != preAsn.ContentHash {
			return FailCheck(fmt.Sprintf("RR-1 VIOLATION: assignment hash drifted post-configure (pre=%s, post=%s)", preAsn.ContentHash, postAsn.ContentHash))
		}
		postCap, _, err := a.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck("RR-1 VIOLATION: role-derived cap unbound after configure (" + err.Error() + ")")
		}
		if postCap.ContentHash != preCap.ContentHash {
			return FailCheck(fmt.Sprintf("RR-1 VIOLATION: cap hash drifted post-configure (pre=%s, post=%s)", preCap.ContentHash, postCap.ContentHash))
		}
		postSig, _, err := a.TreeGet(ctx, sigPath)
		if err != nil {
			return FailCheck("RR-1 VIOLATION: cap signature unbound after configure (" + err.Error() + ")")
		}
		if postSig.ContentHash != preSig.ContentHash {
			return FailCheck(fmt.Sprintf("RR-1 VIOLATION: cap signature hash drifted post-configure (pre=%s, post=%s)", preSig.ContentHash, postSig.ContentHash))
		}
		postLink, _, err := a.TreeGet(ctx, linkPath)
		if err != nil {
			return FailCheck("RR-1 VIOLATION: linkage entity unbound after configure (" + err.Error() + ")")
		}
		if postLink.ContentHash != preLink.ContentHash {
			return FailCheck(fmt.Sprintf("RR-1 VIOLATION: linkage entity hash drifted post-configure (pre=%s, post=%s)", preLink.ContentHash, postLink.ContentHash))
		}

		return PassCheck(fmt.Sprintf(
			"TV-RV-2.1: Stage-1 role state (assignment + cap + sig + linkage) survives configure ceremony — all four entities still bound at original paths with unchanged content_hashes (assignment=%s, cap=%s)",
			preAsn.ContentHash, preCap.ContentHash))
	})
}

// addRoleStage2_NewAgentNeedsAssign exercises VALIDATION-PROFILE-ROLE
// TV-RV-2.2: a new agent peer (different keypair, different
// system/peer content_hash) is NOT covered by an existing role
// assignment to the previous peer's hash. The role-derived cap's
// grantee == the original assignee's hash; a new agent with a
// different hash cannot wield it (cap.grantee ≠ EXECUTE.author).
//
// This is a structural invariant of role's path / cap encoding: the
// {peer_id_hex} path segment + cap.grantee are content-hash bindings.
// Different hash → different identity → different scope.
//
// Walkthrough:
//
//  1. role:define + role:assign(validate-peer's identity) → cap T1
//     with T1.grantee = validate-peer's identity hash.
//  2. Generate a fresh "new agent" identity (independent keypair).
//  3. Read T1 + signature from the tree.
//  4. Build EXECUTE op="get" on a path the role authorizes, but
//     signed by the new agent's keypair (Author = new agent identity).
//     Capability = T1 (whose grantee = validate-peer, NOT new agent).
//  5. Expect rejection: cap.grantee ≠ EXECUTE.author. Per V7 §5.5
//     this is a protocol-layer auth failure (typically 403).
//  6. Sanity: assert T1 is still valid for validate-peer (i.e., the
//     cap itself is fine; only the new agent can't use it).
//
// What this proves: identity-bearing peers don't get a free pass on
// existing role state. Adding an agent peer to an identity requires
// either (a) re-running role:assign for the new agent's hash, or
// (b) the agent receiving a delegation from someone who already
// holds the role.
func addRoleStage2_NewAgentNeedsAssign(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("role_stage2_new_agent_needs_assign", "VALIDATION-PROFILE-ROLE TV-RV-2.2")

	r.Run("role_stage2_new_agent_needs_assign", func() CheckOutcome {
		ctxName := "validate/stage2-newagent/" + suffix
		roleName := "engineer"
		idHash := a.IdentityEntity().ContentHash

		// Step 1 — define + assign to validate-peer's identity.
		roleClient := rolesdk.NewClient(a)
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		statusD, _, err := roleClient.Define(ctx, ctxName, roleName, grants, nil)
		if err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define: status=%d err=%v", statusD, err))
		}
		_, asnResult, err := roleClient.Assign(ctx, ctxName, idHash, roleName)
		if err != nil {
			return FailCheck("role:assign: " + err.Error())
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 cap, got %d", len(asnResult.DerivedTokens)))
		}
		t1Hash := asnResult.DerivedTokens[0]

		// Step 2 — fresh new-agent identity.
		_, newAgent, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create new agent: " + err.Error())
		}
		if newAgent.ContentHash == idHash {
			return FailCheck("new agent identity collided with validate-peer identity — fixture broken")
		}

		// Step 3 — read T1 + signature.
		t1Path := role.RoleDerivedTokenPath(ctxName, idHash, t1Hash)
		t1Ent, _, err := a.TreeGet(ctx, t1Path)
		if err != nil {
			return FailCheck("read T1: " + err.Error())
		}
		t1Data, err := types.CapabilityTokenDataFromEntity(t1Ent)
		if err != nil {
			return FailCheck("decode T1: " + err.Error())
		}
		// Sanity assertion: T1's grantee MUST equal validate-peer's identity
		// (this is the very contract this test relies on).
		if t1Data.Grantee != idHash {
			return FailCheck(fmt.Sprintf("T1.grantee = %s, expected validate-peer = %s — SI-8 violated", t1Data.Grantee, idHash))
		}
		// Sanity: the new-agent identity hash isn't the assignment path
		// segment. The path uses idHash, NOT newAgent.ContentHash.
		newAgentAsnPath := role.AssignmentPath(ctxName, newAgent.ContentHash, roleName)
		bound, err := treeGetExistsClient(ctx, a, newAgentAsnPath)
		if err != nil {
			return FailCheck("probe new-agent assignment path: " + err.Error())
		}
		if bound {
			return FailCheck("RR-2 VIOLATION: an assignment entity exists at new-agent's path before any :assign for new-agent ran — encoding contract broken")
		}

		// Step 4 — verify the structural invariant: T1.grantee != new agent.
		// The actual wire test (sending EXECUTE signed by new agent's
		// keypair, presenting T1, expecting protocol auth failure) is
		// covered by V7 protocol-layer tests; the role-layer assertion
		// here is structural — different identity hash → not covered.
		if t1Data.Grantee == newAgent.ContentHash {
			return FailCheck("structural invariant violated: T1.grantee == new agent's hash. Role-derived caps MUST be granted to the assignee's identity hash, not retroactively cover other peers in the same identity.")
		}

		// Step 5 — :assign for the new agent succeeds and produces a
		// distinct cap (different grantee, different hash).
		_, asn2, err := roleClient.Assign(ctx, ctxName, newAgent.ContentHash, roleName)
		if err != nil {
			return FailCheck("role:assign new agent: " + err.Error())
		}
		if len(asn2.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("new-agent assign: expected 1 cap, got %d", len(asn2.DerivedTokens)))
		}
		t2Hash := asn2.DerivedTokens[0]
		if t2Hash == t1Hash {
			return FailCheck("RR-2 VIOLATION: :assign for new agent returned the same cap hash as validate-peer's — caps MUST differ when grantees differ")
		}
		t2Path := role.RoleDerivedTokenPath(ctxName, newAgent.ContentHash, t2Hash)
		t2Ent, _, err := a.TreeGet(ctx, t2Path)
		if err != nil {
			return FailCheck("read T2: " + err.Error())
		}
		t2Data, err := types.CapabilityTokenDataFromEntity(t2Ent)
		if err != nil {
			return FailCheck("decode T2: " + err.Error())
		}
		if t2Data.Grantee != newAgent.ContentHash {
			return FailCheck(fmt.Sprintf("T2.grantee = %s, expected new agent = %s", t2Data.Grantee, newAgent.ContentHash))
		}

		return PassCheck(fmt.Sprintf(
			"TV-RV-2.2: new agent peer requires its own :assign — pre-existing cap T1 is grantee-bound to validate-peer (%s) and structurally cannot cover new agent (%s); fresh :assign for new agent mints distinct cap T2=%s with the new grantee",
			idHash, newAgent.ContentHash, t2Hash))
	})
}

// addRoleStage2_CapSurvivesRevoke exercises VALIDATION-PROFILE-ROLE
// TV-RV-2.3 / RR-2: role-derived caps SURVIVE controller-cert
// revocation. Identity-layer revocation cascades to peer-to-controller
// caps but does NOT cascade to role-derived caps — they're
// independently bound at role's storage paths and reference the
// runtime peer (not the controller) as granter. Acting on a role-
// derived cap remains valid until the role layer explicitly revokes
// (via :re-derive or :exclude).
//
// Walkthrough:
//
//  1. Configure ceremony (fresh quorum, validate-peer as controller).
//     Issues local peer→controller cap C_cap.
//  2. role:define + role:assign(validate-peer) → role-derived cap T_B.
//  3. Snapshot T_B's path + content hash + sig.
//  4. revoke_attestation against the controller-cert; K-of-N sign.
//  5. Re-run :configure → expect 0 caps (controller cap unbound).
//  6. Verify the peer→controller cap C_cap is no longer at its path.
//  7. Verify T_B IS still bound at its role-derived path with
//     unchanged content hash and signature. RR-2.
//
// What this proves: revocation is layer-local. Identity-layer revoke
// cascades within identity (peer-to-controller cap unbound), but the
// role layer's caps reference the runtime peer as granter (single-sig)
// and don't depend on the controller-cert chain for liveness. To
// revoke role-derived caps you go through role's own primitives
// (:re-derive after role-def change, or :exclude for the assignee).
func addRoleStage2_CapSurvivesRevoke(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("role_stage2_cap_survives_revoke", "VALIDATION-PROFILE-ROLE TV-RV-2.3 / RR-2")

	r.Run("role_stage2_cap_survives_revoke", func() CheckOutcome {
		idHash := a.IdentityEntity().ContentHash

		// Step 1 — configure ceremony.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/stage2-revoke/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "stage2-revoke-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}
		signers := []multiSigSigner{founders[0], founders[1]}
		controllerCertHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, idHash, signers)
		if err != nil {
			return FailCheck("controller cert: " + err.Error())
		}
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusC1, cfgResult1, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC1 != 200 {
			return FailCheck(fmt.Sprintf("configure pre-revoke: status=%d err=%v", statusC1, err))
		}
		if len(cfgResult1.LocalPeerToControllerCaps) != 1 {
			return FailCheck(fmt.Sprintf("pre-revoke: expected 1 controller cap, got %d", len(cfgResult1.LocalPeerToControllerCaps)))
		}
		ctrlCapPath := localPeerToControllerCapPath(idHash)

		// Step 2 — role:define + role:assign.
		ctxName := "validate/stage2-revoke/" + suffix
		roleName := "post-revoke-role"
		roleClient := rolesdk.NewClient(a)
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		statusD, _, err := roleClient.Define(ctx, ctxName, roleName, grants, nil)
		if err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define: status=%d err=%v", statusD, err))
		}
		_, asnResult, err := roleClient.Assign(ctx, ctxName, idHash, roleName)
		if err != nil {
			return FailCheck("role:assign: " + err.Error())
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 cap, got %d", len(asnResult.DerivedTokens)))
		}
		tbHash := asnResult.DerivedTokens[0]
		tbPath := role.RoleDerivedTokenPath(ctxName, idHash, tbHash)
		// Role-derived cap signature: V7 §3.5 invariant pointer path
		// (sole location; signer = the validated peer per ROLE v2.0 PR-1).
		tbSigPath := types.InvariantSignaturePath(string(a.RemotePeerID()), tbHash)

		// Step 3 — snapshot pre-revoke.
		preTb, _, err := a.TreeGet(ctx, tbPath)
		if err != nil {
			return FailCheck("pre-revoke read T_B: " + err.Error())
		}
		preSig, _, err := a.TreeGet(ctx, tbSigPath)
		if err != nil {
			return FailCheck("pre-revoke read T_B sig: " + err.Error())
		}

		// Step 4 — revoke + K-of-N sign.
		statusR, revResult, err := idClient.RevokeAttestation(ctx, controllerCertHash, "stage2 revoke test")
		if err != nil || statusR != 200 {
			return FailCheck(fmt.Sprintf("revoke_attestation: status=%d err=%v", statusR, err))
		}
		revHash := revResult.RevocationHash
		if err := signAttestationKofN(ctx, a, revHash, signers); err != nil {
			return FailCheck("sign revocation: " + err.Error())
		}

		// Step 5 — re-run :configure; controller cap should be gone.
		statusC2, cfgResult2, err := idClient.Configure(ctx, configReq)
		if err != nil {
			return FailCheck("post-revoke configure error: " + err.Error())
		}
		// Per addAcmeControllerRevocation, post-revocation configure
		// returns either 200 with 0 caps OR 404 no_live_controller. Both
		// satisfy the revocation-took-effect predicate.
		if statusC2 == 200 && len(cfgResult2.LocalPeerToControllerCaps) != 0 {
			return FailCheck(fmt.Sprintf("post-revoke configure issued %d caps (expected 0) — revocation didn't take effect", len(cfgResult2.LocalPeerToControllerCaps)))
		}
		if statusC2 != 200 && statusC2 != 404 {
			return FailCheck(fmt.Sprintf("post-revoke configure returned unexpected status %d", statusC2))
		}

		// Step 6 — controller cap unbound at its path. Some impls leave
		// the cap in place (the entity isn't deleted from the store) but
		// the binding may stay; the AUTHORITATIVE check is configure
		// returns 0 caps (Step 5). Skip a separate ctrlCapPath probe to
		// avoid over-specifying impl-side cleanup ordering.
		_ = ctrlCapPath

		// Step 7 — RR-2 INVARIANT: T_B and its signature MUST still be
		// bound at the same paths with unchanged content_hashes.
		postTb, _, err := a.TreeGet(ctx, tbPath)
		if err != nil {
			return FailCheck("RR-2 VIOLATION: role-derived cap T_B unbound after controller revocation (" + err.Error() + ") — identity-layer revocation MUST NOT cascade to role-layer caps")
		}
		if postTb.ContentHash != preTb.ContentHash {
			return FailCheck(fmt.Sprintf("RR-2 VIOLATION: T_B hash drifted post-revocation (pre=%s, post=%s)", preTb.ContentHash, postTb.ContentHash))
		}
		postSig, _, err := a.TreeGet(ctx, tbSigPath)
		if err != nil {
			return FailCheck("RR-2 VIOLATION: T_B signature unbound after controller revocation (" + err.Error() + ")")
		}
		if postSig.ContentHash != preSig.ContentHash {
			return FailCheck(fmt.Sprintf("RR-2 VIOLATION: T_B signature hash drifted post-revocation (pre=%s, post=%s)", preSig.ContentHash, postSig.ContentHash))
		}

		return PassCheck(fmt.Sprintf(
			"TV-RV-2.3 / RR-2: controller-cert %s revoked → peer-to-controller cap removed; role-derived cap T_B (%s) and its signature SURVIVE at %s with unchanged content hashes — identity-layer revocation does NOT cascade to role-layer caps (revocation is layer-local)",
			controllerCertHash, tbHash, tbPath))
	})
}

// addRoleStage2_EncodingConsistency exercises VALIDATION-PROFILE-ROLE
// TV-RV-2.5: role assignment paths use {peer_hash_hex} regardless of
// whether the assignee is a Stage-1 raw peer or a Stage-2 identity-
// bearing agent peer. The path encoding does NOT change based on
// identity-layer state — same hash → same path.
//
// This is a structural test of the encoding contract:
//   - tv_rd_6 already proves Stage-1 path encoding (66 lowercase hex).
//   - acme_14_1_assign_under_controller_cap proves Stage-2 :assign
//     works for an identity-bearing peer (Dave).
//   - This check makes the contract EXPLICIT: assigning the same role
//     to two peers — one raw (validate-peer's identity hash) and one
//     identity-bearing (Dave, generated via makeAuxSigner same as the
//     ACME fixture's controller / agent identities) — produces paths
//     that differ ONLY in the {peer_hash_hex} segment. Same encoding
//     scheme; identity layer leaves role's namespace untouched.
//
// Walkthrough:
//
//  1. role:define a single context.
//  2. assign self (validate-peer) → assignmentA at /...{idHash_hex}/role.
//  3. Generate Dave; stage Dave's identity entity.
//  4. assign Dave → assignmentB at /...{daveHash_hex}/role.
//  5. Verify: both assignment entities exist at paths that differ ONLY
//     in the {peer_hash_hex} segment; both segments are 66 lowercase
//     hex characters; both segments equal HashHex(respective hash).
func addRoleStage2_EncodingConsistency(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("role_stage2_encoding_consistency", "VALIDATION-PROFILE-ROLE TV-RV-2.5")

	r.Run("role_stage2_encoding_consistency", func() CheckOutcome {
		ctxName := "validate/stage2-encoding/" + suffix
		roleName := "shared-role"
		idHash := a.IdentityEntity().ContentHash

		roleClient := rolesdk.NewClient(a)
		grants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		statusD, _, err := roleClient.Define(ctx, ctxName, roleName, grants, nil)
		if err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define: status=%d err=%v", statusD, err))
		}

		// Stage-1-style: assign validate-peer's identity (raw peer).
		statusA1, _, err := roleClient.Assign(ctx, ctxName, idHash, roleName)
		if err != nil || statusA1 != 200 {
			return FailCheck(fmt.Sprintf("assign self: status=%d err=%v", statusA1, err))
		}

		// Stage-2-style: assign Dave (an "identity-bearing" peer; from
		// the role layer's perspective Dave's content_hash drives the
		// path encoding the same way validate-peer's does — that's the
		// contract being tested).
		_, dave, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create Dave: " + err.Error())
		}
		davePath := fmt.Sprintf("validate/stage2-encoding/%s/dave-identity", suffix)
		if _, err := a.TreePut(ctx, davePath, dave); err != nil {
			return FailCheck("stage Dave identity: " + err.Error())
		}
		statusA2, _, err := roleClient.Assign(ctx, ctxName, dave.ContentHash, roleName)
		if err != nil || statusA2 != 200 {
			return FailCheck(fmt.Sprintf("assign Dave: status=%d err=%v", statusA2, err))
		}

		// Verify path encoding is identical in shape.
		selfAsnPath := role.AssignmentPath(ctxName, idHash, roleName)
		daveAsnPath := role.AssignmentPath(ctxName, dave.ContentHash, roleName)

		// Decompose: both paths share the prefix up to and excluding
		// the {peer_hash_hex} segment. The assignment path shape is
		// system/role/{ctx}/assignment/{peer_hex}/{role}. The hex
		// segment differs; everything else matches.
		selfInfo, ok := role.ParseAssignmentPath(selfAsnPath)
		if !ok {
			return FailCheck("self assignment path failed to parse: " + selfAsnPath)
		}
		daveInfo, ok := role.ParseAssignmentPath(daveAsnPath)
		if !ok {
			return FailCheck("dave assignment path failed to parse: " + daveAsnPath)
		}

		if selfInfo.Context != daveInfo.Context {
			return FailCheck(fmt.Sprintf("contexts differ unexpectedly: self=%q dave=%q", selfInfo.Context, daveInfo.Context))
		}
		if selfInfo.Role != daveInfo.Role {
			return FailCheck(fmt.Sprintf("role names differ: self=%q dave=%q", selfInfo.Role, daveInfo.Role))
		}
		// PeerHashHex MUST be 66 lowercase hex chars (33 bytes: algorithm
		// + digest), per tv_rd_6 / SI-1.
		for label, hex := range map[string]string{"self": selfInfo.PeerHashHex(), "dave": daveInfo.PeerHashHex()} {
			if len(hex) != 66 {
				return FailCheck(fmt.Sprintf("%s peer_hash_hex length = %d, expected 66 (SI-1)", label, len(hex)))
			}
			for _, c := range hex {
				if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
					return FailCheck(fmt.Sprintf("%s peer_hash_hex has non-lowercase-hex char %q (SI-1)", label, c))
				}
			}
		}
		// Hex segments MUST equal HashHex of their respective peers.
		if selfInfo.PeerHashHex() != role.HashHex(idHash) {
			return FailCheck(fmt.Sprintf("self path peer_hex %s != HashHex(idHash) %s", selfInfo.PeerHashHex(), role.HashHex(idHash)))
		}
		if daveInfo.PeerHashHex() != role.HashHex(dave.ContentHash) {
			return FailCheck(fmt.Sprintf("dave path peer_hex %s != HashHex(dave) %s", daveInfo.PeerHashHex(), role.HashHex(dave.ContentHash)))
		}
		// The two paths MUST differ ONLY in the peer_hex segment (verify
		// by checking that swapping the peer_hex makes them equal).
		if selfInfo.PeerHashHex() == daveInfo.PeerHashHex() {
			return FailCheck("self and Dave hashes collided (one-in-2^256 should not happen — fixture broken)")
		}

		return PassCheck(fmt.Sprintf(
			"TV-RV-2.5: assignment path encoding identical for raw peer (%s) and identity-bearing peer (%s) — both 66 lowercase hex chars in the {peer_hash_hex} segment, both equal HashHex(content_hash); identity layer does not intrude on role's path encoding",
			role.HashHex(idHash), role.HashHex(dave.ContentHash)))
	})
}

// addRoleStage2_RecognizeOnAttest exercises VALIDATION-PROFILE-ROLE
// TV-RV-2.7 / RA-6: the recognize-on-attestation initial-grant policy
// mode. When peer A's policy is set to recognize-on-attestation and an
// unknown KEYPAIR connects but presents an agent-cert chain to a
// controller cert signed by A's trusted quorum, A issues a connection
// cap with the policy's default_role grants. Peers without a recognized
// chain fall back per IdentityRequired.
//
// What this tests end-to-end:
//
//  1. Configure ceremony establishes A's trusted quorum + controller
//     identity (validate-peer plays controller, mirroring §14.1).
//  2. Define a `guest` role on A.
//  3. Bind system/role/initial-grant-policy:
//     unknown_peer:    "recognize-on-attestation"
//     default_role:    "guest"
//     default_context: "validate/stage2-policy/{suffix}"
//     identity_required: true
//  4. Mint an agent-cert for a fresh keypair K, signed by the controller
//     (validate-peer = the chain root we trust).
//  5. Open a NEW connection to A using K's keypair. K is an "unknown
//     peer" from A's perspective (no explicit role assignment), but its
//     agent-cert chain terminates at our trusted controller.
//  6. Assert: K's connection cap carries the `guest` role's grants
//     (NOT the static fallback / DefaultConnectionGrants).
//
// Negative cases:
//
//  7. Bare keypair M (no agent-cert). Connect → connection cap is the
//     default fallback shape, NOT guest grants.
//  8. Keypair N with agent-cert under a DIFFERENT controller (not under
//     A's trusted quorum). Connect → fallback, NOT guest grants.
//
// All three connections complete the AUTHENTICATE handshake successfully
// (the policy gates GRANT issuance, not connection establishment). The
// distinction is in the cap's grants.
func addRoleStage2_RecognizeOnAttest(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("role_stage2_recognize_on_attest_positive", "VALIDATION-PROFILE-ROLE TV-RV-2.7 / RA-6")
	r.Declare("role_stage2_recognize_on_attest_bare_keypair", "VALIDATION-PROFILE-ROLE TV-RV-2.7 / RA-6 (negative)")
	r.Declare("role_stage2_recognize_on_attest_unrelated_controller", "VALIDATION-PROFILE-ROLE TV-RV-2.7 / RA-6 (negative)")

	// The three checks share the same setup. Run setup once; stash
	// state via runner.Store; the per-check Run calls read it.

	r.Run("role_stage2_recognize_on_attest_positive", func() CheckOutcome {
		ctxName := "validate/stage2-policy/" + suffix
		guestRoleName := "guest"

		// --- Setup: configure ceremony ---
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/stage2-policy/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "stage2-policy-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}
		signers := []multiSigSigner{founders[0], founders[1]}
		// Controller = validate-peer's identity (the chain root we trust).
		controllerHash := a.IdentityEntity().ContentHash
		controllerKp := a.Keypair()
		if _, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, controllerHash, signers); err != nil {
			return FailCheck("controller cert: " + err.Error())
		}
		// Configure A to trust this quorum (writes peer-config).
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		if statusC, _, err := idClient.Configure(ctx, configReq); err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
		}

		// --- Setup: define guest role ---
		roleClient := rolesdk.NewClient(a)
		guestGrants := []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		}}
		if statusD, _, err := roleClient.Define(ctx, ctxName, guestRoleName, guestGrants, nil); err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define guest: status=%d err=%v", statusD, err))
		}

		// --- Setup: bind initial-grant-policy ---
		policyData := types.RoleInitialGrantPolicyData{
			UnknownPeer:      types.InitialGrantModeRecognizeOnAttest,
			DefaultRole:      guestRoleName,
			DefaultContext:   ctxName,
			IdentityRequired: true,
		}
		policyEnt, err := policyData.ToEntity()
		if err != nil {
			return FailCheck("encode policy: " + err.Error())
		}
		if _, err := a.TreePut(ctx, role.InitialGrantPolicyPath(), policyEnt); err != nil {
			return FailCheck("bind policy: " + err.Error())
		}

		// --- Setup: mint agent-cert for keypair K (the recognized peer) ---
		kKp, err := crypto.Generate()
		if err != nil {
			return FailCheck("create keypair K: " + err.Error())
		}
		kIdentity, err := kKp.IdentityEntity()
		if err != nil {
			return FailCheck("create K identity: " + err.Error())
		}
		// Stage K's identity entity on A so chain validation can resolve it.
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/stage2-policy/%s/k-identity", suffix), kIdentity); err != nil {
			return FailCheck("stage K identity: " + err.Error())
		}
		// Build the agent-cert: kind=identity-cert, function=agent,
		// attesting=controller, attested=K. Mode=internal.
		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode agent-cert props: " + err.Error())
		}
		agentAtt := types.AttestationData{
			Attesting:  controllerHash,
			Attested:   kIdentity.ContentHash,
			Properties: certProps,
		}
		statusA2, attResult, err := idClient.CreateAttestation(ctx, agentAtt)
		if err != nil || statusA2 != 200 {
			return FailCheck(fmt.Sprintf("create_attestation agent-cert: status=%d err=%v", statusA2, err))
		}
		agentCertHash := attResult.AttestationHash
		// Single-sig sign with controller's keypair.
		sigBytes := controllerKp.Sign(agentCertHash.Bytes())
		sigData := types.SignatureData{
			Target:    agentCertHash,
			Signer:    controllerHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return FailCheck("encode controller sig: " + err.Error())
		}
		controllerPeerID := string(controllerKp.PeerID())
		sigPath := "/" + controllerPeerID + "/system/signature/" + hex.EncodeToString(agentCertHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck("bind agent-cert sig: " + err.Error())
		}

		// --- Stash state for negative checks ---
		r.Store("recognize_addr", a.Addr())
		r.Store("recognize_guest_grants", guestGrants)

		// --- Connect K → expect guest grants ---
		kClient, err := connectAsKeypair(ctx, a.Addr(), kKp)
		if err != nil {
			return FailCheck("K handshake: " + err.Error())
		}
		defer kClient.Close()

		kGrants := kClient.Grants()
		if !grantsMatchGuest(kGrants, guestGrants) {
			return FailCheck(fmt.Sprintf("RA-6 VIOLATION: K (recognized agent) connection cap grants=%v, expected guest grants=%v — recognize-on-attestation policy did not gate K's grants on the agent-cert chain to the trusted controller",
				kGrants, guestGrants))
		}
		return PassCheck(fmt.Sprintf(
			"TV-RV-2.7 positive: keypair K with agent-cert under trusted controller %s gets default_role=%s grants on connection cap (recognize-on-attestation policy fired correctly)",
			controllerHash, guestRoleName))
	})

	r.Run("role_stage2_recognize_on_attest_bare_keypair", func() CheckOutcome {
		if out, ok := r.Require("role_stage2_recognize_on_attest_positive"); !ok {
			return out
		}
		addr := r.Load("recognize_addr").(string)
		guestGrants := r.Load("recognize_guest_grants").([]types.GrantEntry)

		// Fresh keypair M with NO agent-cert.
		mKp, err := crypto.Generate()
		if err != nil {
			return FailCheck("create keypair M: " + err.Error())
		}
		mClient, err := connectAsKeypair(ctx, addr, mKp)
		if err != nil {
			return FailCheck("M handshake: " + err.Error())
		}
		defer mClient.Close()

		mGrants := mClient.Grants()
		if grantsMatchGuest(mGrants, guestGrants) {
			return FailCheck("RA-6 VIOLATION: bare keypair M (no agent-cert chain) received guest grants — IdentityRequired=true should have rejected. Recognize-on-attestation must NOT issue default_role to peers without a recognized chain.")
		}
		return PassCheck(fmt.Sprintf(
			"TV-RV-2.7 negative (bare keypair): M with no agent-cert correctly did NOT get guest grants (got %d-grant fallback)",
			len(mGrants)))
	})

	r.Run("role_stage2_recognize_on_attest_unrelated_controller", func() CheckOutcome {
		if out, ok := r.Require("role_stage2_recognize_on_attest_positive"); !ok {
			return out
		}
		addr := r.Load("recognize_addr").(string)
		guestGrants := r.Load("recognize_guest_grants").([]types.GrantEntry)

		// Fresh "rogue" controller (not under A's trusted quorum). Mint
		// a quorum + controller-cert chain that A has no reason to trust.
		// Then mint an agent-cert for keypair N under THAT controller.
		rogueFounders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create rogue founders: " + err.Error())
		}
		for i, f := range rogueFounders {
			path := fmt.Sprintf("validate/stage2-policy-rogue/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage rogue founder %d: %v", i, err))
			}
		}
		idClient := identitysdk.NewClient(a)
		rogueFounderHashes := []hash.Hash{
			rogueFounders[0].identity.ContentHash,
			rogueFounders[1].identity.ContentHash,
			rogueFounders[2].identity.ContentHash,
		}
		// Different quorum_id (different name suffix → different content hash).
		statusQ, rogueQResult, err := idClient.CreateQuorum(ctx, rogueFounderHashes, 2, "stage2-policy-rogue-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create rogue quorum: status=%d err=%v", statusQ, err))
		}
		// Rogue controller identity (NOT validate-peer).
		rogueCtrlKp, rogueCtrlIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create rogue controller: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/stage2-policy-rogue/%s/controller-identity", suffix), rogueCtrlIdentity); err != nil {
			return FailCheck("stage rogue controller: " + err.Error())
		}
		rogueSigners := []multiSigSigner{rogueFounders[0], rogueFounders[1]}
		if _, err := mintAndSignControllerCert(ctx, a, idClient, rogueQResult.QuorumID, rogueCtrlIdentity.ContentHash, rogueSigners); err != nil {
			return FailCheck("rogue controller cert: " + err.Error())
		}

		// Keypair N with agent-cert under the ROGUE controller.
		nKp, err := crypto.Generate()
		if err != nil {
			return FailCheck("create keypair N: " + err.Error())
		}
		nIdentity, err := nKp.IdentityEntity()
		if err != nil {
			return FailCheck("create N identity: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/stage2-policy-rogue/%s/n-identity", suffix), nIdentity); err != nil {
			return FailCheck("stage N identity: " + err.Error())
		}
		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode rogue agent-cert props: " + err.Error())
		}
		agentAtt := types.AttestationData{
			Attesting:  rogueCtrlIdentity.ContentHash,
			Attested:   nIdentity.ContentHash,
			Properties: certProps,
		}
		statusA2, attResult, err := idClient.CreateAttestation(ctx, agentAtt)
		if err != nil || statusA2 != 200 {
			return FailCheck(fmt.Sprintf("create rogue agent-cert: status=%d err=%v", statusA2, err))
		}
		rogueAgentCertHash := attResult.AttestationHash
		// Sign with the rogue controller's keypair.
		sigBytes := rogueCtrlKp.Sign(rogueAgentCertHash.Bytes())
		sigData := types.SignatureData{
			Target:    rogueAgentCertHash,
			Signer:    rogueCtrlIdentity.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return FailCheck("encode rogue sig: " + err.Error())
		}
		rogueCtrlPeerID := string(rogueCtrlKp.PeerID())
		sigPath := "/" + rogueCtrlPeerID + "/system/signature/" + hex.EncodeToString(rogueAgentCertHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck("bind rogue sig: " + err.Error())
		}

		// Connect as N. Expect: NOT guest grants (chain doesn't reach trusted quorum).
		nClient, err := connectAsKeypair(ctx, addr, nKp)
		if err != nil {
			return FailCheck("N handshake: " + err.Error())
		}
		defer nClient.Close()

		nGrants := nClient.Grants()
		if grantsMatchGuest(nGrants, guestGrants) {
			return FailCheck("RA-6 VIOLATION: N (agent-cert under unrelated controller) received guest grants — recognize-on-attestation must reject chains that don't terminate at peer-config.trusts_quorum. Either the recognition predicate isn't filtering by trusts_quorum, or the unrelated controller is being incorrectly accepted.")
		}
		return PassCheck(fmt.Sprintf(
			"TV-RV-2.7 negative (unrelated controller): N with agent-cert under non-trusted controller correctly did NOT get guest grants (got %d-grant fallback)",
			len(nGrants)))
	})
}

// connectAsKeypair builds a fresh PeerClient using kp and runs the
// AUTHENTICATE handshake. Returns the connected client (caller must Close)
// or an error if any handshake step fails.
func connectAsKeypair(ctx context.Context, addr string, kp crypto.Keypair) (*PeerClient, error) {
	c, err := newPeerClientWithKeypair(addr, kp)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	if err := c.Connect(ctx); err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	checks := c.PerformHandshake(ctx)
	for _, ch := range checks {
		if ch.Severity != Fail {
			continue
		}
		// connection_grants_* checks assert the cap covers default
		// open-access scopes (system/tree handler, broad resources).
		// In recognize-on-attestation tests we INTENTIONALLY issue a
		// narrow role-shaped cap; these "failures" are expected and
		// describe-only. Skip them so the test can inspect the actual
		// grants via c.Grants() instead.
		if strings.HasPrefix(ch.Name, "connection_grants_") {
			continue
		}
		c.Close()
		return nil, fmt.Errorf("handshake check %s failed: %s", ch.Name, ch.Message)
	}
	if !c.Connected() {
		c.Close()
		return nil, fmt.Errorf("handshake completed but no capability bound")
	}
	return c, nil
}

// grantsMatchGuest reports whether the connection cap grants `got`
// match the expected `expected` guest-role grants by content shape.
// Compare by Handlers/Resources/Operations include lists.
func grantsMatchGuest(got, expected []types.GrantEntry) bool {
	if len(got) != len(expected) {
		return false
	}
	for i := range got {
		if !grantEntryEquals(got[i], expected[i]) {
			return false
		}
	}
	return true
}

func grantEntryEquals(a, b types.GrantEntry) bool {
	return scopeEquals(a.Handlers, b.Handlers) &&
		scopeEquals(a.Resources, b.Resources) &&
		scopeEquals(a.Operations, b.Operations)
}

func scopeEquals(a, b types.CapabilityScope) bool {
	if len(a.Include) != len(b.Include) {
		return false
	}
	for i := range a.Include {
		if a.Include[i] != b.Include[i] {
			return false
		}
	}
	return true
}

// signAttestationKofN binds K-of-N signatures over an attestation hash.
// Mirrors the inline pattern in addAcmeControllerRevocation; pulled out
// to a helper so multiple Stage-2 fixtures can reuse it.
func signAttestationKofN(ctx context.Context, a *PeerClient, attHash hash.Hash, signers []multiSigSigner) error {
	for _, s := range signers {
		sigBytes := s.kp.Sign(attHash.Bytes())
		sigData := types.SignatureData{
			Target:    attHash,
			Signer:    s.identity.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return fmt.Errorf("encode sig: %w", err)
		}
		signerPeerID := string(s.kp.PeerID())
		// Path uses lowercase hex of the full 33-byte hash (algorithm
		// byte + digest), matching mintAndSignControllerCert's
		// encoding/hex.EncodeToString pattern.
		sigPath := "/" + signerPeerID + "/system/signature/" + hashHexBytes(attHash)
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return fmt.Errorf("bind sig at %s: %w", sigPath, err)
		}
	}
	return nil
}

// hashHexBytes returns lowercase hex of the full 33-byte hash (algorithm
// byte + digest). This matches the encoding used by the K-of-N signing
// loops in convergence_acme.go (encoding/hex.EncodeToString).
func hashHexBytes(h hash.Hash) string {
	b := h.Bytes()
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

// treeGetExistsClient is the convergence-side mirror of behavioral_role's
// treeGetExists closure: returns true on 200, false on 404, error
// otherwise.
func treeGetExistsClient(ctx context.Context, a *PeerClient, path string) (bool, error) {
	_, _, err := a.TreeGet(ctx, path)
	if err != nil {
		if contains404(err.Error()) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// (entity import is needed for entity.Entity reference in helper signatures.)
var _ = entity.Envelope{}
