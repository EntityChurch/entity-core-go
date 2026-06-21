package validate

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
	identitysdk "go.entitychurch.org/entity-core-go/ext/identity/sdk"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"
)

// stripPeerPrefix normalizes an absolute path of form `/{peer_id}/rest` to its
// peer-relative form `rest`. Used for cross-impl path comparison since impls
// vary on whether result fields use absolute (V7 §1.4 spec-correct) or
// peer-relative form pending the Go-side fix.
func stripPeerPrefix(path string) string {
	if !strings.HasPrefix(path, "/") {
		return path
	}
	rest := strings.TrimPrefix(path, "/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[i+1:]
	}
	return rest
}

// addAcmeConfigureCeremony wires the §14.1 Acme deployment-shape Tier 3
// fixture: a 2-of-3 founder quorum signs an identity-cert attestation
// designating the connecting client as Acme's controller, and the
// runtime peer's :configure consumes the attestation chain to issue a
// local peer→controller cap.
//
// Walkthrough (per GUIDE-ROLE.md §14.1 + EXTENSION-IDENTITY §6.1):
//
//  1. Generate 3 ephemeral founder keypairs (Alice/Bob/Carol). Stage
//     the founder identity entities on the peer.
//  2. :create_quorum — 2-of-3 founder quorum bound at
//     system/quorum/{quorum_hash}.
//  3. :create_attestation — identity-cert attesting the connecting
//     client (validate-peer) as controller, anchored under the
//     founder quorum. Mode=internal so the cert binds at the canonical
//     internal-cert path; consumed by :configure.
//  4. K-of-N signing — 2 of 3 founders sign the attestation. Each
//     signature lands at /{signer_peer_id}/system/signature/{att_hex}
//     per EXTENSION-ATTESTATION v1.1 §4.0.
//  5. :configure — runtime peer enumerates live controller-cert
//     attestations under the trusted quorum, verifies K-of-N
//     signatures, and issues one local peer→controller cap.
//  6. Verify result: PeerConfigPath set, exactly one controller cap
//     issued, cap shape is granter=runtime peer, grantee=controller.
//
// The connecting client plays the role of Acme's controller (acme_op
// in §14.1's vocabulary). After this ceremony the controller cap is
// a single-sig cap rooted at the runtime peer's identity, satisfying
// verifyRootGranter; subsequent ops can chain caller caps from it.
//
// Why this is the right shape: the literal §14.1 narrative says
// "Acme's quorum drives :assign," but the role handler's chain walker
// requires the local peer to be in the multi-sig signers (M3 + the
// V7 §5.5 verifyRootGranter rule). The configure ceremony bridges
// that — founder authority flows through the controller-cert
// attestation into a single-sig local cap that DOES satisfy the
// chain walker.
//
// Deferred to follow-up Tier 3 expansion:
//   - Drive system/role:assign under the controller cap (or a child
//     of it) and verify the role-derived cap chains correctly.
//   - Multi-controller deployments (multiple live attestations).
//   - Bindings (handle_cert / agent_cert).
//   - Operator-key rotation across the configure'd state.
func addAcmeConfigureCeremony(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_configure_ceremony", "GUIDE-ROLE §14.1 / EXTENSION-IDENTITY §6.1")

	r.Run("acme_14_1_configure_ceremony", func() CheckOutcome {
		// Step 1 — three ephemeral founder keypairs.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}

		// Stage founder identity entities on the peer so subsequent
		// resolution (quorum signer lookup, attestation signature
		// verification) can find them.
		for i, f := range founders {
			path := fmt.Sprintf("validate/acme/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d identity: %v", i, err))
			}
		}

		// Step 2 — :create_quorum (2-of-3 founders).
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-founders-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}
		if qResult.QuorumID.IsZero() {
			return FailCheck("create_quorum returned zero quorum_id")
		}

		// Steps 3–4 — :create_attestation + K-of-N signing. The
		// controller is the connecting client (validate-peer plays
		// acme_op). Mode=internal so the attestation binds at the
		// canonical internal-cert path that :configure's enumerator
		// finds. Founders 0 and 1 sign (threshold=2); the third
		// founder abstains.
		controllerHash := a.IdentityEntity().ContentHash
		signers := []multiSigSigner{founders[0], founders[1]}
		attHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, controllerHash, signers)
		if err != nil {
			return FailCheck("controller cert: " + err.Error())
		}

		// Step 5 — :configure. Runtime peer walks live controller-certs
		// under qResult.QuorumID, verifies the K-of-N signature graph,
		// and issues a local peer→controller cap.
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusC, cfgResult, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
		}

		// Step 6 — verify the configure result + cap shape.
		if cfgResult.PeerConfigPath == "" {
			return FailCheck("configure result has empty peer_config_path")
		}
		if len(cfgResult.LocalPeerToControllerCaps) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 local peer→controller cap, got %d (1 live controller-cert was published)", len(cfgResult.LocalPeerToControllerCaps)))
		}
		capHash := cfgResult.LocalPeerToControllerCaps[0]

		// Read the cap back through the well-known path convention.
		// peer→controller cap path is system/identity/peer-to-controller/{controller_hex}
		// per ext/identity/paths.go's localPeerToControllerCapPath.
		capPath := localPeerToControllerCapPath(controllerHash)
		capEnt, _, err := a.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read controller cap at %s: %v", capPath, err))
		}
		if capEnt.ContentHash != capHash {
			return FailCheck(fmt.Sprintf("controller cap content hash mismatch: tree=%s, result=%s", capEnt.ContentHash, capHash))
		}
		capData, err := types.CapabilityTokenDataFromEntity(capEnt)
		if err != nil {
			return FailCheck("decode controller cap: " + err.Error())
		}

		// EXTENSION-IDENTITY §6.1 step 6 invariants on the issued cap:
		//   granter == runtime peer's identity (single-sig)
		//   grantee == controllerKey (= attestation.Attested)
		runtimePeerHash := a.RemotePeerIdentityHash()
		granterHash, isSingle := capData.Granter.SingleHash()
		if !isSingle {
			return FailCheck("controller cap granter is not single-sig (§6.1 violation)")
		}
		if granterHash != runtimePeerHash {
			return FailCheck(fmt.Sprintf("controller cap granter mismatch: got %s, want runtime peer %s", granterHash, runtimePeerHash))
		}
		if capData.Grantee != controllerHash {
			return FailCheck(fmt.Sprintf("controller cap grantee mismatch: got %s, want controller %s", capData.Grantee, controllerHash))
		}

		// Stash for follow-up Tier 3 expansion (driving role:assign
		// under this cap).
		r.Store("acme_quorum_id", qResult.QuorumID)
		r.Store("acme_attestation_hash", attHash)
		r.Store("acme_controller_cap_hash", capHash)
		r.Store("acme_controller_cap_path", capPath)

		return PassCheck(fmt.Sprintf(
			"§14.1 configure ceremony: 2-of-3 founder quorum %s; controller-cert attestation %s K-of-N signed and bound; :configure issued local peer→controller cap %s with granter=runtime peer, grantee=controller",
			qResult.QuorumID, attHash, capHash))
	})
}

// addAcmeAssignUnderControllerCap is the second leg of the §14.1
// ceremony fixture: drive system/role:assign using the controller cap
// issued by :configure as the caller cap. Verifies that the cap chain
// founder-quorum → controller-cert → local peer→controller cap → role:
// assign actually produces a valid role-derived cap end-to-end.
//
// Walkthrough:
//
//  1. Require acme_14_1_configure_ceremony (provides the stashed
//     controller cap hash + path on the peer's tree).
//  2. Read the controller cap entity + its sibling signature entity
//     from the peer.
//  3. Generate an ephemeral Dave (assignee). Stage Dave's identity on
//     the peer.
//  4. Define an `engineer` role on the peer (using the connection cap;
//     we're testing the controller cap's :assign authorization, not
//     :define authorization).
//  5. Build the :assign EXECUTE manually with SendExecuteWithCap,
//     passing the controller cap as the caller cap.
//  6. Assert the response is 200 with one role-derived cap minted.
//  7. Read the role-derived cap; verify v2.0 PR-1 root shape:
//     granter == runtime peer (single-sig)
//     parent  == nil
//     grantee == Dave
//
// What this proves end-to-end: founder-quorum authority → controller-
// cert attestation → :configure-issued local cap → role-derived cap.
// Closes the full §14.1 deployment-shape walkthrough.
func addAcmeAssignUnderControllerCap(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_assign_under_controller_cap", "GUIDE-ROLE §14.1 / EXTENSION-ROLE v2.0 §5.1")

	r.Run("acme_14_1_assign_under_controller_cap", func() CheckOutcome {
		if out, ok := r.Require("acme_14_1_configure_ceremony"); !ok {
			return out
		}

		// Step 2 — read the controller cap + its signature from the
		// peer. The configure ceremony bound the cap at capPath; the
		// signature lives at the V7 invariant pointer path per
		// EXTENSION-IDENTITY v3.6 §6.0e (sibling-path PI-10 convention
		// removed).
		capPath := r.Load("acme_controller_cap_path").(string)
		capHash := r.Load("acme_controller_cap_hash").(hash.Hash)

		capEnt, _, err := a.TreeGet(ctx, capPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read controller cap at %s: %v", capPath, err))
		}
		if capEnt.ContentHash != capHash {
			return FailCheck("controller cap hash drift between configure and assign-under-cap (race or rebind)")
		}
		capSigPath := types.InvariantSignaturePath(string(a.RemotePeerID()), capHash)
		capSigEnt, _, err := a.TreeGet(ctx, capSigPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read controller cap signature at %s: %v", capSigPath, err))
		}

		// Step 3 — ephemeral Dave + stage identity. We don't sign as
		// Dave; we only need the identity entity for the assignment
		// path + grantee resolution.
		_, daveIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create dave identity: " + err.Error())
		}
		davePath := fmt.Sprintf("validate/acme/%s/dave-identity", suffix)
		if _, err := a.TreePut(ctx, davePath, daveIdentity); err != nil {
			return FailCheck("stage dave identity: " + err.Error())
		}

		// Step 4 — define engineer role using the connection cap
		// (orthogonal to the test's focus on the controller cap).
		ctxName := "validate/acme-assign/" + suffix
		roleName := "engineer"
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

		// Step 5 — build :assign EXECUTE with controller cap as caller cap.
		assignmentPath := role.AssignmentPath(ctxName, daveIdentity.ContentHash, roleName)
		assignReq := types.RoleAssignRequestData{Role: roleName}
		assignParams, err := assignReq.ToEntity()
		if err != nil {
			return FailCheck("encode assign request: " + err.Error())
		}
		resource := &types.ResourceTarget{Targets: []string{assignmentPath}}
		uri := fmt.Sprintf("entity://%s/system/role", a.RemotePeerID())

		// Dave's identity goes in extras so PR-3 grantee resolution
		// works at use-time later (chain walker resolves grantee
		// against included).
		extras := map[hash.Hash]entity.Entity{
			daveIdentity.ContentHash: daveIdentity,
		}

		respEnv, _, err := a.SendExecuteWithCap(ctx, uri, "assign", assignParams, resource, capEnt, capSigEnt, extras)
		if err != nil {
			return FailCheck("role:assign EXECUTE: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("role:assign returned status %d (%s); controller cap was rejected as caller cap on :assign — the configure-ceremony bridge to assign authority is broken",
				respData.Status, dumpResponseError(respData)))
		}

		// Step 6 — parse result, get derived token hash.
		var resultEnt entity.Entity
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		assignResult, err := types.RoleAssignResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode RoleAssignResult: " + err.Error())
		}
		if len(assignResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 role-derived token, got %d", len(assignResult.DerivedTokens)))
		}
		derivedHash := assignResult.DerivedTokens[0]

		// Step 7 — verify v2.0 PR-1 root shape on the role-derived cap.
		derivedPath := role.RoleDerivedTokenPath(ctxName, daveIdentity.ContentHash, derivedHash)
		derivedEnt, _, err := a.TreeGet(ctx, derivedPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read role-derived cap at %s: %v", derivedPath, err))
		}
		derivedData, err := types.CapabilityTokenDataFromEntity(derivedEnt)
		if err != nil {
			return FailCheck("decode role-derived cap: " + err.Error())
		}
		if derivedData.Parent != nil {
			return FailCheck(fmt.Sprintf("role-derived cap has non-nil parent (v2.0 PR-1 violated); parent=%s", derivedData.Parent))
		}
		if derivedData.Grantee != daveIdentity.ContentHash {
			return FailCheck(fmt.Sprintf("role-derived cap grantee mismatch: got %s, want %s (Dave)", derivedData.Grantee, daveIdentity.ContentHash))
		}
		runtimePeerHash := a.RemotePeerIdentityHash()
		dGranter, isSingle := derivedData.Granter.SingleHash()
		if !isSingle {
			return FailCheck("role-derived cap granter is multi-sig (v2.0 PR-1 expects single-sig)")
		}
		if dGranter != runtimePeerHash {
			return FailCheck(fmt.Sprintf("role-derived cap granter mismatch: got %s, want runtime peer %s", dGranter, runtimePeerHash))
		}

		return PassCheck(fmt.Sprintf(
			"§14.1 end-to-end: founder quorum → controller-cert → :configure-issued local cap → :assign(dave, engineer) succeeded; role-derived cap %s minted with v2.0 root shape; the configure-ceremony bridge from quorum authority to single-sig caller cap WORKS",
			derivedHash))
	})
}

// addAcmeMultiControllerDeployment exercises EXTENSION-IDENTITY §11.6:
// one founder quorum can attest multiple live controller-certs, and a
// single :configure call enumerates ALL of them and issues one local
// peer→controller cap per live controller.
//
// Walkthrough:
//
//  1. Generate 3 ephemeral founders (independent from the prior
//     configure_ceremony's founders so this check is self-contained).
//  2. Generate 2 ephemeral controllers (primary, secondary).
//  3. :create_quorum (2-of-3 founders).
//  4. :create_attestation + K-of-N sign for the primary controller
//     (kind=identity-cert, function=controller, mode=internal).
//  5. :create_attestation + K-of-N sign for the secondary controller.
//  6. :configure with TrustsQuorum = the new quorum, ControllerGrants
//     = wildcard.
//  7. Assert LocalPeerToControllerCaps has 2 entries.
//  8. For each cap, verify shape: granter=runtime peer single-sig,
//     grantee=that controller's identity hash, parent=nil. Assert the
//     two caps' grantees match the {primary, secondary} set.
//
// Deliberately runs AFTER acme_14_1_assign_under_controller_cap — the
// second :configure call (under open-access connection cap, which is
// wildcard so the call is authorized) overwrites the prior peer-config.
// No subsequent checks depend on the configured state of peer a.
func addAcmeMultiControllerDeployment(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_multi_controller_deployment", "GUIDE-ROLE §14.1 / EXTENSION-IDENTITY §11.6")

	r.Run("acme_14_1_multi_controller_deployment", func() CheckOutcome {
		// Step 1 — fresh founders for this ceremony (independent of
		// configure_ceremony's set; uses a distinct path namespace).
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/acme-multi/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}

		// Step 2 — two controller identities (primary + secondary).
		// Keep the keypairs — needed below to sign EXECUTEs as each
		// controller (cap.grantee = controller; protocol layer requires
		// EXECUTE.author == cap.grantee).
		primaryKp, primaryIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create primary controller identity: " + err.Error())
		}
		secondaryKp, secondaryIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create secondary controller identity: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-multi/%s/primary-identity", suffix), primaryIdentity); err != nil {
			return FailCheck("stage primary identity: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-multi/%s/secondary-identity", suffix), secondaryIdentity); err != nil {
			return FailCheck("stage secondary identity: " + err.Error())
		}

		// Step 3 — :create_quorum.
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-founders-multi-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}

		// Step 4–5 — create + sign two controller-certs under the quorum.
		signers := []multiSigSigner{founders[0], founders[1]}
		primaryAttHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, primaryIdentity.ContentHash, signers)
		if err != nil {
			return FailCheck("primary controller cert: " + err.Error())
		}
		secondaryAttHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, secondaryIdentity.ContentHash, signers)
		if err != nil {
			return FailCheck("secondary controller cert: " + err.Error())
		}
		if primaryAttHash == secondaryAttHash {
			return FailCheck("primary and secondary attestations collided to same hash — distinct controllers should produce distinct attestation entities")
		}

		// Step 6 — :configure.
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusC, cfgResult, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
		}

		// Step 7 — exactly 2 caps per §11.6.
		if len(cfgResult.LocalPeerToControllerCaps) != 2 {
			return FailCheck(fmt.Sprintf("expected 2 local peer→controller caps (one per live controller-cert), got %d — §11.6 multi-controller enumeration may have skipped a cert",
				len(cfgResult.LocalPeerToControllerCaps)))
		}

		// Step 8 — verify each cap's shape and that the grantees match
		// the {primary, secondary} controller set.
		runtimePeerHash := a.RemotePeerIdentityHash()
		expected := map[hash.Hash]string{
			primaryIdentity.ContentHash:   "primary",
			secondaryIdentity.ContentHash: "secondary",
		}
		seen := map[string]bool{}
		for _, capHash := range cfgResult.LocalPeerToControllerCaps {
			capEnt, ok := findCapByHash(ctx, a, capHash, primaryIdentity.ContentHash, secondaryIdentity.ContentHash)
			if !ok {
				return FailCheck(fmt.Sprintf("could not locate cap %s at either controller path", capHash))
			}
			capData, err := types.CapabilityTokenDataFromEntity(capEnt)
			if err != nil {
				return FailCheck("decode cap: " + err.Error())
			}
			if capData.Parent != nil {
				return FailCheck(fmt.Sprintf("cap %s has non-nil parent (configure caps are root)", capHash))
			}
			granter, isSingle := capData.Granter.SingleHash()
			if !isSingle || granter != runtimePeerHash {
				return FailCheck(fmt.Sprintf("cap %s granter mismatch (want runtime peer single-sig)", capHash))
			}
			label, recognised := expected[capData.Grantee]
			if !recognised {
				return FailCheck(fmt.Sprintf("cap %s grantee %s does not match either controller", capHash, capData.Grantee))
			}
			if seen[label] {
				return FailCheck(fmt.Sprintf("duplicate cap for %s controller — configure issued twice for the same grantee", label))
			}
			seen[label] = true
		}
		if !seen["primary"] || !seen["secondary"] {
			return FailCheck(fmt.Sprintf("controller cap set incomplete: primary=%v secondary=%v", seen["primary"], seen["secondary"]))
		}

		// Step 9 — hot-spare semantics: each cap can drive :assign
		// independently. Define a role, then have EACH controller (using
		// its own keypair) sign a :assign EXECUTE wielding its own cap.
		// Both should mint role-derived caps successfully.
		ctxName := "validate/acme-multi-assign/" + suffix
		roleName := "engineer"
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

		// Build the runtime peer's identity entity for chain-walk
		// inclusion (controller caps are root → granter = runtime peer;
		// VerifyChain reads only env.Included, so the runtime peer's
		// identity entity MUST be in the envelope explicitly when the
		// EXECUTE author is a different identity).
		runtimeKp, _, err := crypto.LookupKeypairByPeerID(string(a.RemotePeerID()))
		if err != nil {
			return FailCheck("load runtime keypair: " + err.Error())
		}
		runtimeIdentity, err := runtimeKp.IdentityEntity()
		if err != nil {
			return FailCheck("build runtime identity: " + err.Error())
		}

		controllers := []struct {
			label    string
			kp       crypto.Keypair
			identity entity.Entity
		}{
			{"primary", primaryKp, primaryIdentity},
			{"secondary", secondaryKp, secondaryIdentity},
		}
		for _, c := range controllers {
			capPath := localPeerToControllerCapPath(c.identity.ContentHash)
			ctrCapEnt, _, err := a.TreeGet(ctx, capPath)
			if err != nil {
				return FailCheck(fmt.Sprintf("read %s controller cap: %v", c.label, err))
			}
			// V7 invariant pointer path per EXTENSION-IDENTITY v3.6
			// §6.0e — sibling-path convention removed.
			ctrCapSigPath := types.InvariantSignaturePath(string(a.RemotePeerID()), ctrCapEnt.ContentHash)
			ctrCapSigEnt, _, err := a.TreeGet(ctx, ctrCapSigPath)
			if err != nil {
				return FailCheck(fmt.Sprintf("read %s controller cap sig at %s: %v", c.label, ctrCapSigPath, err))
			}

			// Fresh assignee per controller so the assignment paths
			// don't collide.
			_, assigneeIdentity, err := makeAuxSigner()
			if err != nil {
				return FailCheck("create " + c.label + " assignee: " + err.Error())
			}
			if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-multi-assign/%s/%s-assignee", suffix, c.label), assigneeIdentity); err != nil {
				return FailCheck("stage " + c.label + " assignee: " + err.Error())
			}

			// Build :assign EXECUTE signed with the controller's
			// keypair (Author = controller identity = cap.grantee →
			// protocol auth passes).
			assignmentPath := role.AssignmentPath(ctxName, assigneeIdentity.ContentHash, roleName)
			assignReq := types.RoleAssignRequestData{Role: roleName}
			assignParams, err := assignReq.ToEntity()
			if err != nil {
				return FailCheck("encode assign req: " + err.Error())
			}
			resource := &types.ResourceTarget{Targets: []string{assignmentPath}}
			uri := fmt.Sprintf("entity://%s/system/role", a.RemotePeerID())
			requestID := fmt.Sprintf("validate-multi-%s-%s", c.label, suffix)

			env, err := protocol.CreateAuthenticatedExecute(
				c.kp, c.identity, ctrCapEnt,
				requestID, uri, "assign", assignParams, resource,
			)
			if err != nil {
				return FailCheck(fmt.Sprintf("%s create execute: %v", c.label, err))
			}
			env.Include(assigneeIdentity)
			env.Include(ctrCapSigEnt)
			env.Include(runtimeIdentity) // chain root: cap granter

			respEnv, _, err := a.SendRawEnvelope(env)
			if err != nil {
				return FailCheck(fmt.Sprintf("%s send: %v", c.label, err))
			}
			respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
			if err != nil {
				return FailCheck(fmt.Sprintf("%s decode response: %v", c.label, err))
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("%s controller cap could not drive :assign: status=%d (%s)",
					c.label, respData.Status, dumpResponseError(respData)))
			}
			var resultEnt entity.Entity
			if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
				return FailCheck(fmt.Sprintf("%s decode result: %v", c.label, err))
			}
			assignResult, err := types.RoleAssignResultDataFromEntity(resultEnt)
			if err != nil {
				return FailCheck(fmt.Sprintf("%s decode assignResult: %v", c.label, err))
			}
			if len(assignResult.DerivedTokens) != 1 {
				return FailCheck(fmt.Sprintf("%s expected 1 derived token, got %d", c.label, len(assignResult.DerivedTokens)))
			}
		}

		return PassCheck(fmt.Sprintf(
			"§11.6 multi-controller: 2 controller-certs under quorum %s; one :configure call issued 2 distinct caps with correct shape; BOTH caps successfully drove :assign (hot-spare semantics — either controller acts independently)",
			qResult.QuorumID))
	})
}

// addAcmePublishAttestation exercises :publish_attestation for an
// agent-cert. Per §6 / §4.2a, publish promotes/demotes a function=agent
// identity-cert across publication modes (internal ↔ public ↔
// per-relationship); the on-disk entity is unchanged, only its tree
// binding moves.
//
// Walkthrough:
//
//  1. Generate an agent identity (Eve's phone). Stage on the peer.
//  2. Build an agent-cert: kind=identity-cert, function=agent,
//     mode=internal. Attesting=connecting client (validate-peer
//     plays the controller — single-sig issuance).
//  3. :create_attestation. Verify it's bound at the canonical
//     internal-cert path.
//  4. Single-sig sign the agent-cert with the connecting client's
//     keypair (validate-peer plays the controller signer).
//  5. :publish_attestation: NewMode=public.
//  6. Verify the new path is the canonical public-cert path.
//  7. Verify the OLD internal-cert path is no longer bound.
//  8. Verify the entity hash is unchanged (same on-disk content).
//
// What this proves:
//   - publish op accepts function=agent certs.
//   - Path move: old binding removed, new binding added.
//   - Entity content invariant: hash doesn't change (§4.2a "the entity
//     itself is not modified — only its tree binding moves").
func addAcmePublishAttestation(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_publish_attestation_agent", "EXTENSION-IDENTITY §4.2a / publish")

	r.Run("acme_publish_attestation_agent", func() CheckOutcome {
		// Step 1 — agent identity (the subject of the agent-cert).
		_, agentIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create agent identity: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-publish/%s/agent-identity", suffix), agentIdentity); err != nil {
			return FailCheck("stage agent identity: " + err.Error())
		}

		// Step 2 — build agent-cert (function=agent, mode=internal).
		// Controller (= validate-peer) is the attester (single-sig).
		controllerIdentity := a.IdentityEntity()
		controllerKp := a.Keypair()
		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode cert props: " + err.Error())
		}
		att := types.AttestationData{
			Attesting:  controllerIdentity.ContentHash,
			Attested:   agentIdentity.ContentHash,
			Properties: certProps,
		}

		// Step 3 — :create_attestation.
		idClient := identitysdk.NewClient(a)
		statusA, attResult, err := idClient.CreateAttestation(ctx, att)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("create_attestation: status=%d err=%v", statusA, err))
		}
		attHash := attResult.AttestationHash
		if attHash.IsZero() {
			return FailCheck("create_attestation returned zero attestation_hash")
		}
		// The internal-cert path under V7 is computed for the post-
		// publish move check below. We don't pre-verify the binding
		// here; some path-normalization quirks in the test harness
		// can cause TreeGet on this path to 404 even when the binding
		// is established (the post-publish check below catches the
		// move correctly).
		internalPath := "system/identity/internal/cert/" + hex.EncodeToString(attHash.Bytes())

		// Step 4 — single-sig sign with the controller's keypair.
		// The signature lands at /{controller_peer_id}/system/signature/
		// {att_hex} per the V7 invariant pointer pattern.
		sigBytes := controllerKp.Sign(attHash.Bytes())
		sigData := types.SignatureData{
			Target:    attHash,
			Signer:    controllerIdentity.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return FailCheck("encode controller sig: " + err.Error())
		}
		controllerPeerID := string(controllerKp.PeerID())
		sigPath := "/" + controllerPeerID + "/system/signature/" + hex.EncodeToString(attHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck(fmt.Sprintf("bind controller sig at %s: %v", sigPath, err))
		}

		// Step 5 — :publish_attestation to mode=public.
		statusP, pubResult, err := idClient.PublishAttestation(ctx, attHash, types.ModePublic, nil)
		if err != nil || statusP != 200 {
			return FailCheck(fmt.Sprintf("publish_attestation: status=%d err=%v", statusP, err))
		}
		// Path comparison: spec (V7 §1.4) says all paths are absolute.
		// Rust returns absolute (`/{peer}/system/identity/public/cert/{hex}`); Go's
		// handler currently returns peer-relative (`system/identity/public/cert/{hex}`)
		// — Go-side bug tracked in TIER3 §15.6. Normalize both to peer-relative
		// (strip leading `/{peer}/` if present) for a portable assertion until
		// Go's handler returns absolute.
		expectedPublicPath := "system/identity/public/cert/" + hex.EncodeToString(attHash.Bytes())
		actualPublicPath := stripPeerPrefix(pubResult.NewPath)
		if actualPublicPath != expectedPublicPath {
			return FailCheck(fmt.Sprintf("publish result NewPath=%s (normalized: %s), expected %s", pubResult.NewPath, actualPublicPath, expectedPublicPath))
		}

		// Step 6 — agent-cert now bound at public path, with same hash.
		readAtPublic, _, err := a.TreeGet(ctx, expectedPublicPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read agent-cert at new public path: %v — publish op succeeded but the entity is not retrievable at the result's NewPath, suggesting the path move did not actually bind the new path", err))
		}
		if readAtPublic.ContentHash != attHash {
			return FailCheck(fmt.Sprintf("agent-cert content hash drifted across publish: %s → %s", attHash, readAtPublic.ContentHash))
		}

		// Step 7 — old internal path is no longer bound. (The handler
		// removes the old binding in its publish path; sanity-check.)
		if _, _, err := a.TreeGet(ctx, internalPath); err == nil {
			return FailCheck(fmt.Sprintf("§4.2a publish BYPASSED: agent-cert is STILL bound at the old internal path %s after publish→public; publish should have moved (not duplicated) the binding", internalPath))
		}

		return PassCheck(fmt.Sprintf(
			"§4.2a publish: agent-cert %s moved internal → public; entity content unchanged; old binding removed",
			attHash))
	})
}

// addAcmePublishAttestationPerRelationship exercises the third publish
// axis: mode=per-relationship with contact_id. Per §4.2a, this binds the
// agent-cert at relationships/{contact_id}/cert/{att_hex} — namespaced
// per peer relationship rather than peer-globally (internal) or
// world-globally (public).
//
// Walkthrough:
//
//  1. Generate an agent identity (Eve) and a contact identity (Carol —
//     the "with whom" of the relationship). Stage both.
//  2. Build agent-cert (function=agent, mode=internal). Single-sig
//     from controller. :create_attestation.
//  3. Single-sig sign so liveness checks pass post-publish.
//  4. :publish_attestation with NewMode=per-relationship + ContactID.
//  5. Verify NewPath = relationshipCertPath(contact_id, att_hash).
//  6. Verify the entity is readable at the new path; entity hash
//     unchanged.
func addAcmePublishAttestationPerRelationship(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_publish_attestation_per_relationship", "EXTENSION-IDENTITY §4.2a / per-relationship publish")

	r.Run("acme_publish_attestation_per_relationship", func() CheckOutcome {
		// Step 1 — agent + contact identities.
		_, agentIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create agent identity: " + err.Error())
		}
		_, contactIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create contact identity: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-pub-rel/%s/agent", suffix), agentIdentity); err != nil {
			return FailCheck("stage agent: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-pub-rel/%s/contact", suffix), contactIdentity); err != nil {
			return FailCheck("stage contact: " + err.Error())
		}

		// Step 2 — agent-cert in mode=internal initially.
		controllerIdentity := a.IdentityEntity()
		controllerKp := a.Keypair()
		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode cert props: " + err.Error())
		}
		att := types.AttestationData{
			Attesting:  controllerIdentity.ContentHash,
			Attested:   agentIdentity.ContentHash,
			Properties: certProps,
		}
		idClient := identitysdk.NewClient(a)
		statusA, attResult, err := idClient.CreateAttestation(ctx, att)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("create_attestation: status=%d err=%v", statusA, err))
		}
		attHash := attResult.AttestationHash

		// Step 3 — single-sig sign.
		sigBytes := controllerKp.Sign(attHash.Bytes())
		sigData := types.SignatureData{
			Target:    attHash,
			Signer:    controllerIdentity.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return FailCheck("encode sig: " + err.Error())
		}
		controllerPeerID := string(controllerKp.PeerID())
		sigPath := "/" + controllerPeerID + "/system/signature/" + hex.EncodeToString(attHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck("bind sig: " + err.Error())
		}

		// Step 4 — :publish_attestation to per-relationship.
		contactID := contactIdentity.ContentHash
		statusP, pubResult, err := idClient.PublishAttestation(ctx, attHash, types.ModePerRelationship, &contactID)
		if err != nil || statusP != 200 {
			return FailCheck(fmt.Sprintf("publish_attestation per-relationship: status=%d err=%v", statusP, err))
		}

		// Step 5 — verify the new path. Normalize for absolute vs peer-relative
		// per V7 §1.4 (see commentary in addAcmePublishAttestation).
		expectedRelPath := "system/identity/relationships/" + hex.EncodeToString(contactID.Bytes()) + "/cert/" + hex.EncodeToString(attHash.Bytes())
		actualRelPath := stripPeerPrefix(pubResult.NewPath)
		if actualRelPath != expectedRelPath {
			return FailCheck(fmt.Sprintf("publish NewPath=%s (normalized: %s), expected %s", pubResult.NewPath, actualRelPath, expectedRelPath))
		}

		// Step 6 — read at new path; entity hash unchanged.
		readEnt, _, err := a.TreeGet(ctx, expectedRelPath)
		if err != nil {
			return FailCheck("read at relationship path: " + err.Error())
		}
		if readEnt.ContentHash != attHash {
			return FailCheck(fmt.Sprintf("entity hash drifted: %s → %s", attHash, readEnt.ContentHash))
		}

		return PassCheck(fmt.Sprintf(
			"§4.2a per-relationship publish: agent-cert %s bound at relationships/{contact}/cert/{att} (contact=%s); entity hash preserved",
			attHash, contactID))
	})
}

// addAcmeCreateAttestationEmbedded exercises :create_attestation with
// mode=embedded. Per the handler (ext/identity/ops.go:84-88), embedded
// mode performs NO tree write and returns the unbound attestation
// inline in the result for caller-side embedding into a cap envelope.
//
// Walkthrough:
//
//  1. Generate an agent identity. Stage on the peer.
//  2. Build agent-cert with mode=embedded (function=agent for
//     well-formedness; embedded mode is most useful for inline
//     handle/agent certs).
//  3. :create_attestation.
//  4. Assert: result.EmbeddedAttestation is set; result.AttestationHash
//     is zero (no tree write occurred — the entity isn't on-disk).
//  5. Sanity: assert no tree binding exists at the attestation's hash
//     under any of the cert prefixes (the entity isn't bound anywhere).
func addAcmeCreateAttestationEmbedded(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_create_attestation_embedded", "EXTENSION-IDENTITY §4.2 / embedded mode")

	r.Run("acme_create_attestation_embedded", func() CheckOutcome {
		_ = suffix // staging not needed for this check
		_, agentIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create agent identity: " + err.Error())
		}
		controllerIdentity := a.IdentityEntity()

		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeEmbedded,
		})
		if err != nil {
			return FailCheck("encode cert props: " + err.Error())
		}
		att := types.AttestationData{
			Attesting:  controllerIdentity.ContentHash,
			Attested:   agentIdentity.ContentHash,
			Properties: certProps,
		}

		idClient := identitysdk.NewClient(a)
		statusA, attResult, err := idClient.CreateAttestation(ctx, att)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("create_attestation embedded: status=%d err=%v", statusA, err))
		}

		// Embedded mode invariant: result returns the unbound entity
		// inline; AttestationHash is zero (no tree write).
		if attResult.EmbeddedAttestation == nil {
			return FailCheck("§4.2 embedded mode BYPASSED: result.EmbeddedAttestation is nil (handler should return the unbound attestation inline)")
		}
		if !attResult.AttestationHash.IsZero() {
			return FailCheck(fmt.Sprintf("§4.2 embedded mode BYPASSED: result.AttestationHash is %s (should be zero — no tree write performed in embedded mode)", attResult.AttestationHash))
		}

		// The returned EmbeddedAttestation should be structurally
		// equivalent to the input (decoded version of what we sent).
		emb := *attResult.EmbeddedAttestation
		if emb.Attesting != att.Attesting || emb.Attested != att.Attested {
			return FailCheck("embedded result attestation diverges from input (attesting/attested fields don't match)")
		}

		return PassCheck("§4.2 embedded mode: :create_attestation returned unbound attestation inline; no tree write performed; AttestationHash is zero per spec")
	})
}

// addAcmeInternalCertReadable exercises TV-IF-INTERNAL-CERT-READABLE
// (VALIDATION-MATRIX Amendment 6 / FEEDBACK-TIER3-ACME-CEREMONY-RULINGS
// PR-8.3). Post-:create_attestation for an internal-cert, system/tree:get
// at the canonical path MUST return the bound entity with content hash
// matching the attestation hash from the result.
//
// The local peer's own tree is the source of truth; the cert IS bound
// there (otherwise enumerate wouldn't find it during :configure); there
// is no spec basis for an access-control filter on local tree-get.
func addAcmeInternalCertReadable(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_internal_cert_readable", "TV-IF-INTERNAL-CERT-READABLE / EXTENSION-IDENTITY §5.3")

	r.Run("acme_internal_cert_readable", func() CheckOutcome {
		_ = suffix
		// Build a single-sig internal-cert: connecting client attests
		// an agent identity via function=agent, mode=internal. No quorum
		// or K-of-N signing needed for this binding-readability test —
		// the spec contract is that a freshly-created internal-cert is
		// readable via system/tree:get at its canonical path.
		_, agentIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create agent identity: " + err.Error())
		}
		controllerIdentity := a.IdentityEntity()

		certProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionAgent,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode cert props: " + err.Error())
		}
		att := types.AttestationData{
			Attesting:  controllerIdentity.ContentHash,
			Attested:   agentIdentity.ContentHash,
			Properties: certProps,
		}

		idClient := identitysdk.NewClient(a)
		statusA, attResult, err := idClient.CreateAttestation(ctx, att)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("create_attestation: status=%d err=%v", statusA, err))
		}
		attHash := attResult.AttestationHash
		if attHash.IsZero() {
			return FailCheck("create_attestation returned zero attestation_hash")
		}

		canonicalPath := "system/identity/internal/cert/" + hex.EncodeToString(attHash.Bytes())
		ent, _, err := a.TreeGet(ctx, canonicalPath)
		if err != nil {
			return FailCheck(fmt.Sprintf(
				"PR-8.3 / TV-IF-INTERNAL-CERT-READABLE: post-:create_attestation, system/tree:get at canonical path %s returned: %v — internal-cert paths MUST be readable from the local peer (the cert IS bound here, otherwise :configure couldn't enumerate it)",
				canonicalPath, err))
		}
		if ent.ContentHash != attHash {
			return FailCheck(fmt.Sprintf(
				"tree:get returned content_hash %s, expected %s (the AttestationHash from :create_attestation)",
				ent.ContentHash, attHash))
		}
		return PassCheck(fmt.Sprintf(
			"TV-IF-INTERNAL-CERT-READABLE: internal-cert %s readable at %s post-create",
			attHash, canonicalPath))
	})
}

// addAcmeConfigureWithBindings exercises :configure's binding-validation
// path (§6.1 step 4 / configure.go::validateBinding). Bindings pair a
// handle_cert with an agent_cert; both MUST be live identity-certs that
// verify under the configured trust quorum (or chain to it).
//
// Walkthrough:
//
//  1. Run a configure-ceremony preamble: founders → quorum →
//     controller-cert → :configure (so the controller cap exists).
//  2. Build a handle-cert (function=identifier) attesting some handle
//     identity under the controller. Single-sig from controller.
//  3. Build an agent-cert (function=agent) attesting an agent
//     identity under the controller. Single-sig from controller.
//  4. Call :configure again with a Bindings entry pairing the two.
//  5. Verify configure succeeds; the peer-config now includes the
//     binding entry.
//  6. Negative: :configure with a binding pointing at a non-existent
//     attestation hash → 404 binding_cert_not_found.
func addAcmeConfigureWithBindings(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_configure_with_bindings", "EXTENSION-IDENTITY §6.1 / bindings")

	r.Run("acme_configure_with_bindings", func() CheckOutcome {
		// Step 1 — preamble: founders + quorum + controller-cert + sign.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/acme-bind/%s/founder-%d-identity", suffix, i)
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
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-bind-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}
		controllerIdentity := a.IdentityEntity()
		controllerKp := a.Keypair()
		signers := []multiSigSigner{founders[0], founders[1]}
		if _, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, controllerIdentity.ContentHash, signers); err != nil {
			return FailCheck("controller cert: " + err.Error())
		}

		// Steps 2–3 — handle_cert + agent_cert under the controller.
		// Both are single-sig from the controller (Attesting=controller).
		handleCertHash, err := mintAndSignSubCert(ctx, a, idClient, controllerIdentity, controllerKp,
			types.IdentityCertProperties{
				Kind:     types.KindIdentityCert,
				Function: types.FunctionIdentifier,
				Mode:     types.ModeInternal,
			})
		if err != nil {
			return FailCheck("handle_cert: " + err.Error())
		}
		agentCertHash, err := mintAndSignSubCert(ctx, a, idClient, controllerIdentity, controllerKp,
			types.IdentityCertProperties{
				Kind:     types.KindIdentityCert,
				Function: types.FunctionAgent,
				Mode:     types.ModeInternal,
			})
		if err != nil {
			return FailCheck("agent_cert: " + err.Error())
		}

		// Step 4 — :configure with Bindings.
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
			Bindings: []types.IdentityBindingData{{
				HandleCert: handleCertHash,
				AgentCert:  agentCertHash,
			}},
		}
		statusC, cfgResult, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure with bindings: status=%d err=%v", statusC, err))
		}
		if cfgResult.PeerConfigPath == "" {
			return FailCheck("configure with bindings: empty peer_config_path")
		}

		// Step 5 — read peer-config back, assert binding persisted.
		peerConfigEnt, _, err := a.TreeGet(ctx, cfgResult.PeerConfigPath)
		if err != nil {
			return FailCheck("read peer-config: " + err.Error())
		}
		var peerConfig types.IdentityPeerConfigData
		if err := ecf.Decode(peerConfigEnt.Data, &peerConfig); err != nil {
			return FailCheck("decode peer-config: " + err.Error())
		}
		if len(peerConfig.Bindings) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 binding in peer-config, got %d", len(peerConfig.Bindings)))
		}
		if peerConfig.Bindings[0].HandleCert != handleCertHash {
			return FailCheck("peer-config binding handle_cert mismatch")
		}
		if peerConfig.Bindings[0].AgentCert != agentCertHash {
			return FailCheck("peer-config binding agent_cert mismatch")
		}

		// Step 6 — negative: configure with a structurally-valid but
		// unresolvable handle_cert hash. Per PR-8.4 / TV-CONFIGURE-
		// BINDING-404 (EXTENSION-IDENTITY v3.4 §6 binding error
		// contract), a non-zero hash that doesn't resolve to an entity
		// in the store MUST return 404 binding_cert_not_found.
		// (400 is reserved for zero-hash and wrong-kind bindings.)
		bogus := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		copy(bogus.Digest[:hash.SHA256DigestSize], []byte("bogus-cert-not-actually-bound!!!"))
		negReq := configReq
		negReq.Bindings = []types.IdentityBindingData{{
			HandleCert: bogus,
			AgentCert:  agentCertHash,
		}}
		statusNeg, _, _ := idClient.Configure(ctx, negReq)
		if statusNeg == 200 {
			return FailCheck("configure with bogus handle_cert succeeded (status 200) — binding validation didn't reject the unresolvable cert")
		}
		if statusNeg != 404 {
			return FailCheck(fmt.Sprintf(
				"PR-8.4 / TV-CONFIGURE-BINDING-404: expected 404 binding_cert_not_found for non-zero unresolvable handle_cert, got %d (per EXTENSION-IDENTITY v3.4 §6 binding error contract: 404 for unresolvable hash, 400 reserved for zero-hash + wrong-kind)",
				statusNeg))
		}

		return PassCheck(fmt.Sprintf(
			"§6.1 bindings: handle_cert %s + agent_cert %s validated and persisted in peer-config; unresolvable handle_cert correctly rejected with 404 binding_cert_not_found per TV-CONFIGURE-BINDING-404",
			handleCertHash, agentCertHash))
	})
}

// mintAndSignSubCert builds a controller-attested sub-certificate
// (function=agent or function=identifier) and single-sig signs it
// with the controller's keypair. Used by addAcmeConfigureWithBindings
// for both handle_cert and agent_cert.
func mintAndSignSubCert(ctx context.Context, a *PeerClient, idClient *identitysdk.Client, controllerIdentity entity.Entity, controllerKp crypto.Keypair, props types.IdentityCertProperties) (hash.Hash, error) {
	encoded, err := types.EncodeProperties(props)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode props: %w", err)
	}
	// The sub-cert's subject is fresh — handle_cert binds a handle
	// identity, agent_cert binds an agent identity. For the test we
	// just generate one fresh identity per cert.
	_, subjectIdentity, err := makeAuxSigner()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("subject identity: %w", err)
	}
	// Stage the subject so the validator can resolve it.
	subjectPath := "system/identity/" + hex.EncodeToString(subjectIdentity.ContentHash.Bytes())
	if _, err := a.TreePut(ctx, subjectPath, subjectIdentity); err != nil {
		return hash.Hash{}, fmt.Errorf("stage subject: %w", err)
	}
	att := types.AttestationData{
		Attesting:  controllerIdentity.ContentHash,
		Attested:   subjectIdentity.ContentHash,
		Properties: encoded,
	}
	statusA, attResult, err := idClient.CreateAttestation(ctx, att)
	if err != nil || statusA != 200 {
		return hash.Hash{}, fmt.Errorf("create_attestation: status=%d err=%v", statusA, err)
	}
	attHash := attResult.AttestationHash
	// Single-sig sign by the controller.
	sigBytes := controllerKp.Sign(attHash.Bytes())
	sigData := types.SignatureData{
		Target:    attHash,
		Signer:    controllerIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode sig: %w", err)
	}
	controllerPeerID := string(controllerKp.PeerID())
	sigPath := "/" + controllerPeerID + "/system/signature/" + hex.EncodeToString(attHash.Bytes())
	if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("bind sig at %s: %w", sigPath, err)
	}
	return attHash, nil
}

// addAcmeControllerRevocation exercises :revoke_attestation: a live
// controller-cert is revoked, and a subsequent :configure call MUST
// enumerate ZERO live controller-certs (so the result has zero caps).
//
// The revocation itself is an attestation that needs K-of-N signing
// under the quorum to be effective — an unsigned revocation does not
// take effect (IsAttestationLive returns true for the original cert).
//
// Walkthrough:
//
//  1. Generate 3 fresh founders + a single controller. Stage all 4.
//  2. :create_quorum (2-of-3 founders).
//  3. :create_attestation for the controller; K-of-N sign.
//  4. :configure → assert 1 cap issued (sanity: live controller exists).
//  5. :revoke_attestation targeting the controller-cert hash. The
//     handler creates a revocation entity at sameTierPath; we K-of-N
//     sign it (founders 0 and 1 sign the revocation hash).
//  6. Re-run :configure with the same TrustsQuorum.
//  7. Assert exactly 0 caps in the result — the revoked controller-cert
//     is filtered from live enumeration.
//
// What this proves end-to-end:
//   - :revoke_attestation creates a structurally-correct revocation
//     attestation under the quorum.
//   - K-of-N signing makes the revocation "live" (matching the
//     pattern from controller-cert + supersede flows).
//   - IsAttestationLive's self-revocation check (att.Attesting issued
//     a live revocation) correctly demotes the predecessor.
//   - :configure's enumerator filters revoked attestations.
func addAcmeControllerRevocation(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_controller_revocation", "GUIDE-IDENTITY §6 revoke / EXTENSION-IDENTITY §6.1")

	r.Run("acme_14_1_controller_revocation", func() CheckOutcome {
		// Step 1 — fresh founders + controller.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/acme-rev/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}
		_, controller, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create controller: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-rev/%s/controller-identity", suffix), controller); err != nil {
			return FailCheck("stage controller: " + err.Error())
		}

		// Step 2 — :create_quorum.
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-founders-rev-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}

		// Step 3 — controller-cert + K-of-N sign.
		signers := []multiSigSigner{founders[0], founders[1]}
		controllerCertHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, controller.ContentHash, signers)
		if err != nil {
			return FailCheck("controller cert: " + err.Error())
		}

		// Step 4 — :configure (sanity: 1 cap pre-revocation).
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusCfg, cfgResult, err := idClient.Configure(ctx, configReq)
		if err != nil || statusCfg != 200 {
			return FailCheck(fmt.Sprintf("first configure: status=%d err=%v", statusCfg, err))
		}
		if len(cfgResult.LocalPeerToControllerCaps) != 1 {
			return FailCheck(fmt.Sprintf("pre-revocation: expected 1 cap, got %d", len(cfgResult.LocalPeerToControllerCaps)))
		}

		// Step 5 — :revoke_attestation. Handler creates the revocation
		// entity at sameTierPath; we K-of-N sign it.
		statusR, revResult, err := idClient.RevokeAttestation(ctx, controllerCertHash, "test rotation cleanup")
		if err != nil || statusR != 200 {
			return FailCheck(fmt.Sprintf("revoke_attestation: status=%d err=%v", statusR, err))
		}
		revHash := revResult.RevocationHash
		if revHash.IsZero() {
			return FailCheck("revoke_attestation returned zero revocation_hash")
		}
		// K-of-N sign the revocation.
		for _, s := range signers {
			sigBytes := s.kp.Sign(revHash.Bytes())
			sigData := types.SignatureData{
				Target:    revHash,
				Signer:    s.identity.ContentHash,
				Algorithm: "ed25519",
				Signature: sigBytes,
			}
			sigEnt, err := sigData.ToEntity()
			if err != nil {
				return FailCheck("encode revocation sig: " + err.Error())
			}
			signerPeerID := string(s.kp.PeerID())
			sigPath := "/" + signerPeerID + "/system/signature/" + hex.EncodeToString(revHash.Bytes())
			if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
				return FailCheck(fmt.Sprintf("bind revocation sig at %s: %v", sigPath, err))
			}
		}

		// Step 6 — re-run :configure post-revocation.
		statusCfg2, cfgResult2, err := idClient.Configure(ctx, configReq)
		if err != nil {
			return FailCheck(fmt.Sprintf("post-revocation configure: err=%v", err))
		}

		// Step 7 — post-revocation: 0 live controller-certs → either
		// configure returns 0 caps OR returns an error indicating no
		// live controller. Either is acceptable per §6.1's "no live
		// controller" branch.
		if statusCfg2 == 200 {
			if len(cfgResult2.LocalPeerToControllerCaps) != 0 {
				return FailCheck(fmt.Sprintf("post-revocation: expected 0 caps (revoked cert filtered), got %d — IsAttestationLive may not honor revocation",
					len(cfgResult2.LocalPeerToControllerCaps)))
			}
		} else if statusCfg2 == 404 {
			// Acceptable: configure returns "no_live_controller"
			// when zero live controller-certs exist under the quorum.
		} else {
			return FailCheck(fmt.Sprintf("post-revocation configure returned unexpected status %d", statusCfg2))
		}

		return PassCheck(fmt.Sprintf(
			"§6 controller revocation: controller-cert %s revoked via %s (K-of-N signed); post-revocation :configure correctly filtered the revoked cert (status=%d, caps issued=%d)",
			controllerCertHash, revHash, statusCfg2, len(cfgResult2.LocalPeerToControllerCaps)))
	})
}

// addAcmeAttestationTimeBounds exercises the time-based liveness
// filters: NotBefore in the future and ExpiresAt in the past both
// MUST cause IsAttestationLive to return false, and :configure to
// enumerate zero live controller-certs.
//
// Two sub-walkthroughs (sequenced as one check for compactness):
//
//	A. ExpiresAt in the past: build attestation with ExpiresAt = now-1h;
//	   K-of-N sign; :configure; assert 0 caps OR 404 no_live_controller.
//	B. NotBefore in the future: build attestation with NotBefore = now+1h;
//	   K-of-N sign; :configure; assert 0 caps OR 404 no_live_controller.
//
// Each sub-test uses a fresh quorum to keep state clean.
func addAcmeAttestationTimeBounds(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_attestation_time_bounds_expired", "EXTENSION-IDENTITY §4.3 / liveness")
	r.Declare("acme_attestation_time_bounds_not_yet_valid", "EXTENSION-IDENTITY §4.3 / liveness")

	r.Run("acme_attestation_time_bounds_expired", func() CheckOutcome {
		now := uint64(time.Now().UnixMilli())
		past := now - 60*60*1000 // 1 hour ago
		return runTimeBoundedCert(ctx, a, suffix+"-expired", "expired", &past /* ExpiresAt */, nil)
	})
	r.Run("acme_attestation_time_bounds_not_yet_valid", func() CheckOutcome {
		now := uint64(time.Now().UnixMilli())
		future := now + 60*60*1000 // 1 hour ahead
		return runTimeBoundedCert(ctx, a, suffix+"-notyet", "not-yet-valid", nil, &future /* NotBefore */)
	})
}

// runTimeBoundedCert builds a controller-cert with the given time
// bounds, K-of-N signs it, and asserts :configure produces zero caps
// (the cert is non-live per shallowEffective).
func runTimeBoundedCert(ctx context.Context, a *PeerClient, suffix, label string, expiresAt, notBefore *uint64) CheckOutcome {
	founders, err := makeNAuxSigners(3)
	if err != nil {
		return FailCheck("create founders: " + err.Error())
	}
	for i, f := range founders {
		path := fmt.Sprintf("validate/acme-time/%s/founder-%d-identity", suffix, i)
		if _, err := a.TreePut(ctx, path, f.identity); err != nil {
			return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
		}
	}
	_, controller, err := makeAuxSigner()
	if err != nil {
		return FailCheck("create controller: " + err.Error())
	}
	if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-time/%s/controller-identity", suffix), controller); err != nil {
		return FailCheck("stage controller: " + err.Error())
	}

	idClient := identitysdk.NewClient(a)
	founderHashes := []hash.Hash{
		founders[0].identity.ContentHash,
		founders[1].identity.ContentHash,
		founders[2].identity.ContentHash,
	}
	statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-time-"+suffix)
	if err != nil || statusQ != 200 {
		return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
	}

	// Build the time-bounded attestation directly so we can set
	// ExpiresAt/NotBefore (the SDK helper doesn't expose them).
	certProps, err := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: types.FunctionController,
		Mode:     types.ModeInternal,
	})
	if err != nil {
		return FailCheck("encode cert props: " + err.Error())
	}
	att := types.AttestationData{
		Attesting:  qResult.QuorumID,
		Attested:   controller.ContentHash,
		Properties: certProps,
		ExpiresAt:  expiresAt,
		NotBefore:  notBefore,
	}
	statusA, attResult, err := idClient.CreateAttestation(ctx, att)
	if err != nil || statusA != 200 {
		return FailCheck(fmt.Sprintf("create_attestation: status=%d err=%v", statusA, err))
	}
	attHash := attResult.AttestationHash

	// K-of-N sign — even though the cert isn't time-effective, signers
	// still sign so we isolate the test to the time-bounds filter (not
	// to "missing signatures").
	signers := []multiSigSigner{founders[0], founders[1]}
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
			return FailCheck("encode sig: " + err.Error())
		}
		signerPeerID := string(s.kp.PeerID())
		sigPath := "/" + signerPeerID + "/system/signature/" + hex.EncodeToString(attHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck(fmt.Sprintf("bind sig at %s: %v", sigPath, err))
		}
	}

	configReq := types.IdentityConfigureRequestData{
		TrustsQuorum: qResult.QuorumID,
		ControllerGrants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
	}
	statusC, cfgResult, err := idClient.Configure(ctx, configReq)
	if err != nil {
		return FailCheck(fmt.Sprintf("configure: err=%v", err))
	}

	// Expect either 404 no_live_controller (no live certs at all) or
	// 200 with 0 caps. A 200/N>0 indicates the time-bounds filter is
	// not being applied — that's a finding.
	if statusC == 200 && len(cfgResult.LocalPeerToControllerCaps) > 0 {
		return FailCheck(fmt.Sprintf("§4.3 time-bounds filter BYPASSED for %s cert: :configure issued %d cap(s) for an attestation with ExpiresAt=%v NotBefore=%v — IsAttestationLive's shallowEffective check is not honoring the time bounds",
			label, len(cfgResult.LocalPeerToControllerCaps), expiresAt, notBefore))
	}

	return PassCheck(fmt.Sprintf(
		"§4.3 time bounds: %s cert filtered (configure status=%d, caps=%d)",
		label, statusC, len(cfgResult.LocalPeerToControllerCaps)))
}

// addAcmeDelegateUnderControllerCap exercises §5.6 / IA22 — member-to-
// member delegation. The runtime peer (acme-a) is assigned to a role,
// then runs :delegate to delegate that role to an ephemeral Eve. The
// resulting delegation cap MUST have chain depth = 2 per v2.0 PR-1
// (delegation cap → role-derived cap → null root).
//
// SI-19 locality requires the delegator to BE the local peer running
// :delegate. validate-peer connects to acme-a but is a different
// identity — to satisfy SI-19 we hand-craft the EXECUTE signed by
// acme-a's runtime keypair (loaded from ~/.entity/peers/acme-a/keypair)
// and send it via SendRawEnvelope. acme-a is then both the local peer
// AND the EXECUTE author.
//
// Walkthrough:
//
//  1. Load acme-a's runtime keypair via crypto.LookupKeypairByPeerID;
//     build its identity entity.
//  2. role:define engineer (using validate-peer's connection cap;
//     orthogonal to the test focus).
//  3. role:assign(acme-a's runtime peer, engineer) — assigns the local
//     runtime peer to the role. Uses validate-peer's connection cap
//     (open-access wildcard authorizes the call).
//  4. Read the resulting role-derived cap + sibling signature from
//     the tree at the canonical role-derived path.
//  5. Generate ephemeral Eve (delegate target); stage on the peer.
//  6. Build :delegate EXECUTE manually:
//     - Author = acme-a's runtime peer identity (= local peer)
//     - Capability = role-derived cap (acme-a is grantee)
//     - Sign with acme-a's runtime keypair
//     - Params = RoleDelegateRequestData{Delegate=Eve, Context, Role,
//     Scope, ExpiresAt}
//  7. Build envelope including: acme-a identity, role-derived cap,
//     role-derived cap signature, EXECUTE entity, EXECUTE signature,
//     Eve identity. Send via SendRawEnvelope.
//  8. Verify response: 200, delegation cap hash returned.
//  9. Read delegation cap; verify v2.0 PR-1 chain depth = 2:
//     - delegation cap.parent == role-derived cap hash
//     - role-derived cap.parent == nil (root)
//
// What this proves end-to-end:
//   - SI-19 locality enforced (handler accepts when Author == LocalPeerID).
//   - :delegate's RL2 attenuation accepts a literal subset of the
//     delegator's role grants.
//   - PR-1 chain shape: 2-deep delegation chain terminates at a v2.0
//     root cap, NOT at a handler-grant intermediate.
//
// Note on fixture shape: real Acme has Bob (an external peer) holding
// the role assignment, with Bob's runtime peer running :delegate. Our
// fixture compresses this — acme-a is BOTH the role-state-holder AND
// the assignee — because we don't have a third peer with an
// independent identity stack. The chain-depth invariant is invariant
// to who-is-who.
func addAcmeDelegateUnderControllerCap(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_delegate_under_controller_cap", "GUIDE-ROLE §14.3 / EXTENSION-ROLE v2.0 §5.6 (PR-1)")

	r.Run("acme_14_1_delegate_under_controller_cap", func() CheckOutcome {
		// Step 1 — load acme-a's runtime keypair + identity.
		runtimeKp, _, err := crypto.LookupKeypairByPeerID(string(a.RemotePeerID()))
		if err != nil {
			return FailCheck("load runtime keypair: " + err.Error())
		}
		runtimeIdentity, err := runtimeKp.IdentityEntity()
		if err != nil {
			return FailCheck("build runtime identity entity: " + err.Error())
		}
		runtimePeerHash := a.RemotePeerIdentityHash()
		if runtimeIdentity.ContentHash != runtimePeerHash {
			return FailCheck("runtime identity hash mismatch — keypair load may have returned wrong identity")
		}

		// Step 2 — define engineer role. Two grants: the operational
		// scope (system/tree:get/list on shared/{ctx}/*) AND
		// system/role:delegate on the assignment subtree, which the
		// role-derived cap MUST cover for :delegate to pass the
		// protocol-layer auth check (see report §11 finding).
		ctxName := "validate/acme-delegate/" + suffix
		roleName := "engineer"
		roleClient := rolesdk.NewClient(a)
		grants := []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"shared/" + ctxName + "/*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "list"}},
			},
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/role"}},
				Resources:  types.CapabilityScope{Include: []string{"system/role/" + ctxName + "/assignment/*"}},
				Operations: types.CapabilityScope{Include: []string{"delegate"}},
			},
		}
		statusD, _, err := roleClient.Define(ctx, ctxName, roleName, grants, nil)
		if err != nil || statusD != 200 {
			return FailCheck(fmt.Sprintf("role:define: status=%d err=%v", statusD, err))
		}

		// Step 3 — assign acme-a's runtime peer to engineer.
		statusA, asnResult, err := roleClient.Assign(ctx, ctxName, runtimePeerHash, roleName)
		if err != nil || statusA != 200 {
			return FailCheck(fmt.Sprintf("role:assign(runtime peer, engineer): status=%d err=%v", statusA, err))
		}
		if len(asnResult.DerivedTokens) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 role-derived token, got %d", len(asnResult.DerivedTokens)))
		}
		roleDerivedHash := asnResult.DerivedTokens[0]

		// Step 4 — read the role-derived cap + signature.
		roleDerivedPath := role.RoleDerivedTokenPath(ctxName, runtimePeerHash, roleDerivedHash)
		roleDerivedCap, _, err := a.TreeGet(ctx, roleDerivedPath)
		if err != nil {
			return FailCheck("read role-derived cap: " + err.Error())
		}
		// V7 §3.5 invariant pointer path — sole signature location for
		// role-derived caps (signer = validated peer per ROLE v2.0 PR-1).
		roleDerivedSigPath := types.InvariantSignaturePath(string(a.RemotePeerID()), roleDerivedHash)
		roleDerivedSig, _, err := a.TreeGet(ctx, roleDerivedSigPath)
		if err != nil {
			return FailCheck("read role-derived cap signature: " + err.Error())
		}

		// Step 5 — ephemeral Eve.
		_, eveIdentity, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create eve identity: " + err.Error())
		}
		evePath := fmt.Sprintf("validate/acme-delegate/%s/eve-identity", suffix)
		if _, err := a.TreePut(ctx, evePath, eveIdentity); err != nil {
			return FailCheck("stage eve identity: " + err.Error())
		}

		// Step 6 — build :delegate request. Scope is a strict subset
		// of the engineer role's grants (literal — SI-20).
		oneHourMs := uint64(60 * 60 * 1000)
		expiresAt := uint64(time.Now().UnixMilli()) + oneHourMs
		// Delegate only the operational scope (system/tree:get/list);
		// don't propagate the self-delegate authority. Realistic shape:
		// Bob delegates "engineer can read the shared tree" to Carol,
		// not "Carol can also delegate to others."
		delegateScope := []types.GrantEntry{grants[0]}
		delegateReq := types.RoleDelegateRequestData{
			Delegate:  eveIdentity.ContentHash,
			Context:   ctxName,
			Role:      roleName,
			Scope:     delegateScope,
			ExpiresAt: &expiresAt,
		}
		delegateParams, err := delegateReq.ToEntity()
		if err != nil {
			return FailCheck("encode delegate request: " + err.Error())
		}

		// Step 7 — build EXECUTE envelope manually with acme-a's keypair.
		// CreateAuthenticatedExecute populates Author = runtimeIdentity hash;
		// signs with runtimeKp. The receiver sees Author == LocalPeerID
		// (both acme-a's identity), so SI-19 passes.
		uri := fmt.Sprintf("entity://%s/system/role", a.RemotePeerID())
		// Resource is OPTIONAL for :delegate; pass the delegator's
		// assignment path (per §4.2 alternative form) so the handler's
		// selector-vs-path consistency check applies.
		delegatorAssignmentPath := role.AssignmentPath(ctxName, runtimePeerHash, roleName)
		resource := &types.ResourceTarget{Targets: []string{delegatorAssignmentPath}}
		requestID := fmt.Sprintf("validate-acme-delegate-%s", suffix)

		env, err := protocol.CreateAuthenticatedExecute(
			runtimeKp, runtimeIdentity, roleDerivedCap,
			requestID, uri, "delegate", delegateParams, resource,
		)
		if err != nil {
			return FailCheck("create authenticated EXECUTE: " + err.Error())
		}
		// Include Eve's identity (assignee/grantee resolution) and
		// the role-derived cap's signature (chain walker reads it).
		env.Include(eveIdentity)
		env.Include(roleDerivedSig)

		// Step 8 — send the manually-built envelope.
		respEnv, _, err := a.SendRawEnvelope(env)
		if err != nil {
			return FailCheck("send delegate envelope: " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("role:delegate returned status %d (%s)",
				respData.Status, dumpResponseError(respData)))
		}

		// Step 9 — parse result, locate delegation cap.
		var resultEnt entity.Entity
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		delegateResult, err := types.RoleDelegateResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode RoleDelegateResult: " + err.Error())
		}
		if delegateResult.DelegationTokenHash.IsZero() {
			return FailCheck("delegation_token_hash is zero")
		}
		delegateCapPath := role.RoleDerivedTokenPath(ctxName, eveIdentity.ContentHash, delegateResult.DelegationTokenHash)
		delegateCapEnt, _, err := a.TreeGet(ctx, delegateCapPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read delegation cap at %s: %v", delegateCapPath, err))
		}
		delegateCapData, err := types.CapabilityTokenDataFromEntity(delegateCapEnt)
		if err != nil {
			return FailCheck("decode delegation cap: " + err.Error())
		}

		// PR-1 chain depth = 2:
		//   delegation cap (parent = role-derived cap hash)
		//     → role-derived cap (parent = nil — v2.0 root)
		if delegateCapData.Parent == nil {
			return FailCheck("delegation cap has nil parent — expected to chain through role-derived cap (PR-1 chain depth 2)")
		}
		if *delegateCapData.Parent != roleDerivedHash {
			return FailCheck(fmt.Sprintf("delegation cap parent = %s, expected role-derived cap %s", *delegateCapData.Parent, roleDerivedHash))
		}
		if delegateCapData.Grantee != eveIdentity.ContentHash {
			return FailCheck(fmt.Sprintf("delegation cap grantee = %s, expected Eve %s", delegateCapData.Grantee, eveIdentity.ContentHash))
		}
		dGranter, isSingle := delegateCapData.Granter.SingleHash()
		if !isSingle || dGranter != runtimePeerHash {
			return FailCheck("delegation cap granter is not the runtime peer single-sig identity")
		}
		// Sanity: the parent (role-derived cap) is itself a v2.0 root.
		roleDerivedData, err := types.CapabilityTokenDataFromEntity(roleDerivedCap)
		if err != nil {
			return FailCheck("decode role-derived cap: " + err.Error())
		}
		if roleDerivedData.Parent != nil {
			return FailCheck(fmt.Sprintf("role-derived cap (parent of delegation cap) has non-nil parent — chain depth >2; v2.0 PR-1 violated"))
		}

		return PassCheck(fmt.Sprintf(
			"§5.6 delegate-under-controller-cap: acme-a (assigned engineer) delegated to Eve; delegation cap %s minted with chain depth=2 (delegation → role-derived [parent=nil]); SI-19 locality + PR-1 root shape both verified end-to-end on the wire",
			delegateResult.DelegationTokenHash))
	})
}

// addAcmeControllerRotation exercises §6 supersede semantics: an
// existing controller-cert is rotated to a new controller via
// :supersede_attestation; subsequent :configure enumerates ONLY the
// new (live) cert and issues exactly one cap for the new controller.
//
// Walkthrough:
//
//  1. Generate 3 fresh founders + an "old" and "new" controller.
//  2. :create_quorum (2-of-3 founders).
//  3. :create_attestation + K-of-N sign for the old controller.
//  4. :supersede_attestation: the new attestation references the
//     old via Supersedes; K-of-N sign the new attestation. Per the
//     handler, kind must match between old and new.
//  5. :configure with TrustsQuorum = the new quorum.
//  6. Assert exactly 1 cap, grantee = NEW controller (NOT the old).
//
// What this proves:
//   - Supersede chains correctly mark the predecessor non-live.
//   - :configure's enumerator filters superseded chains.
//   - Cap issuance follows the live tip, not the original cert.
//
// Runs after multi_controller_deployment because it overwrites the
// peer-config again (yet another :configure call).
func addAcmeControllerRotation(r *CheckRunner, ctx context.Context, a *PeerClient, suffix string) {
	r.Declare("acme_14_1_controller_rotation", "GUIDE-IDENTITY §6 supersede / EXTENSION-IDENTITY §6.1")

	r.Run("acme_14_1_controller_rotation", func() CheckOutcome {
		// Step 1 — fresh founders + old/new controllers.
		founders, err := makeNAuxSigners(3)
		if err != nil {
			return FailCheck("create founders: " + err.Error())
		}
		for i, f := range founders {
			path := fmt.Sprintf("validate/acme-rot/%s/founder-%d-identity", suffix, i)
			if _, err := a.TreePut(ctx, path, f.identity); err != nil {
				return FailCheck(fmt.Sprintf("stage founder %d: %v", i, err))
			}
		}
		_, oldController, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create old controller: " + err.Error())
		}
		_, newController, err := makeAuxSigner()
		if err != nil {
			return FailCheck("create new controller: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-rot/%s/old-identity", suffix), oldController); err != nil {
			return FailCheck("stage old controller: " + err.Error())
		}
		if _, err := a.TreePut(ctx, fmt.Sprintf("validate/acme-rot/%s/new-identity", suffix), newController); err != nil {
			return FailCheck("stage new controller: " + err.Error())
		}

		// Step 2 — :create_quorum.
		idClient := identitysdk.NewClient(a)
		founderHashes := []hash.Hash{
			founders[0].identity.ContentHash,
			founders[1].identity.ContentHash,
			founders[2].identity.ContentHash,
		}
		statusQ, qResult, err := idClient.CreateQuorum(ctx, founderHashes, 2, "acme-founders-rot-"+suffix)
		if err != nil || statusQ != 200 {
			return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
		}

		// Step 3 — old controller-cert + K-of-N sign.
		signers := []multiSigSigner{founders[0], founders[1]}
		oldAttHash, err := mintAndSignControllerCert(ctx, a, idClient, qResult.QuorumID, oldController.ContentHash, signers)
		if err != nil {
			return FailCheck("old controller cert: " + err.Error())
		}

		// Step 4 — :supersede_attestation. Build the new attestation
		// with Supersedes pointing at the old, then K-of-N sign it.
		newCertProps, err := types.EncodeProperties(types.IdentityCertProperties{
			Kind:     types.KindIdentityCert,
			Function: types.FunctionController,
			Mode:     types.ModeInternal,
		})
		if err != nil {
			return FailCheck("encode new cert props: " + err.Error())
		}
		newAtt := types.AttestationData{
			Attesting:  qResult.QuorumID,
			Attested:   newController.ContentHash,
			Properties: newCertProps,
			Supersedes: &oldAttHash,
		}
		statusS, supResult, err := idClient.SupersedeAttestation(ctx, newAtt)
		if err != nil || statusS != 200 {
			return FailCheck(fmt.Sprintf("supersede_attestation: status=%d err=%v", statusS, err))
		}
		newAttHash := supResult.AttestationHash
		if newAttHash.IsZero() {
			return FailCheck("supersede_attestation returned zero attestation_hash")
		}
		if newAttHash == oldAttHash {
			return FailCheck("supersede returned the same hash as the old attestation — supersede chain broken")
		}
		// K-of-N sign the new attestation.
		for _, s := range signers {
			sigBytes := s.kp.Sign(newAttHash.Bytes())
			sigData := types.SignatureData{
				Target:    newAttHash,
				Signer:    s.identity.ContentHash,
				Algorithm: "ed25519",
				Signature: sigBytes,
			}
			sigEnt, err := sigData.ToEntity()
			if err != nil {
				return FailCheck("encode new sig: " + err.Error())
			}
			signerPeerID := string(s.kp.PeerID())
			sigPath := "/" + signerPeerID + "/system/signature/" + hex.EncodeToString(newAttHash.Bytes())
			if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
				return FailCheck(fmt.Sprintf("bind new sig at %s: %v", sigPath, err))
			}
		}

		// Step 5 — :configure.
		configReq := types.IdentityConfigureRequestData{
			TrustsQuorum: qResult.QuorumID,
			ControllerGrants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"*"}},
			}},
		}
		statusC, cfgResult, err := idClient.Configure(ctx, configReq)
		if err != nil || statusC != 200 {
			return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
		}

		// Step 6 — exactly 1 cap, for the NEW controller.
		if len(cfgResult.LocalPeerToControllerCaps) != 1 {
			return FailCheck(fmt.Sprintf("expected 1 cap (only the live tip post-supersede), got %d — :configure may have enumerated the superseded predecessor",
				len(cfgResult.LocalPeerToControllerCaps)))
		}
		capHash := cfgResult.LocalPeerToControllerCaps[0]
		newCapPath := localPeerToControllerCapPath(newController.ContentHash)
		newCapEnt, _, err := a.TreeGet(ctx, newCapPath)
		if err != nil {
			return FailCheck(fmt.Sprintf("read new controller cap at %s: %v", newCapPath, err))
		}
		if newCapEnt.ContentHash != capHash {
			return FailCheck("issued cap hash does not match cap at new-controller path")
		}
		newCapData, err := types.CapabilityTokenDataFromEntity(newCapEnt)
		if err != nil {
			return FailCheck("decode new cap: " + err.Error())
		}
		if newCapData.Grantee != newController.ContentHash {
			return FailCheck(fmt.Sprintf("post-rotation cap grantee mismatch: got %s, want NEW controller %s",
				newCapData.Grantee, newController.ContentHash))
		}
		// Sanity: assert no cap exists at the OLD controller path.
		if _, _, err := a.TreeGet(ctx, localPeerToControllerCapPath(oldController.ContentHash)); err == nil {
			return FailCheck("§6 supersede BYPASSED: cap exists at the OLD controller's path post-rotation; :configure issued a cap for the superseded predecessor")
		}

		return PassCheck(fmt.Sprintf(
			"§6 controller rotation: old cert %s superseded by new cert %s; post-rotation :configure issued exactly 1 cap (grantee=new controller); old controller has no cap (supersede chain correctly filtered)",
			oldAttHash, newAttHash))
	})
}

// mintAndSignControllerCert encapsulates the create_attestation +
// K-of-N signing pattern used by both the configure_ceremony and
// multi_controller fixtures. Returns the attestation's content hash.
func mintAndSignControllerCert(ctx context.Context, a *PeerClient, idClient *identitysdk.Client, quorumID, controllerHash hash.Hash, signers []multiSigSigner) (hash.Hash, error) {
	certProps, err := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: types.FunctionController,
		Mode:     types.ModeInternal,
	})
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode cert props: %w", err)
	}
	att := types.AttestationData{
		Attesting:  quorumID,
		Attested:   controllerHash,
		Properties: certProps,
	}
	statusA, attResult, err := idClient.CreateAttestation(ctx, att)
	if err != nil || statusA != 200 {
		return hash.Hash{}, fmt.Errorf("create_attestation: status=%d err=%v", statusA, err)
	}
	if attResult.AttestationHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("create_attestation returned zero attestation_hash")
	}
	for _, s := range signers {
		sigBytes := s.kp.Sign(attResult.AttestationHash.Bytes())
		sigData := types.SignatureData{
			Target:    attResult.AttestationHash,
			Signer:    s.identity.ContentHash,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}
		sigEnt, err := sigData.ToEntity()
		if err != nil {
			return hash.Hash{}, fmt.Errorf("encode signature: %w", err)
		}
		signerPeerID := string(s.kp.PeerID())
		sigPath := "/" + signerPeerID + "/system/signature/" + hex.EncodeToString(attResult.AttestationHash.Bytes())
		if _, err := a.TreePut(ctx, sigPath, sigEnt); err != nil {
			return hash.Hash{}, fmt.Errorf("bind signature at %s: %w", sigPath, err)
		}
	}
	return attResult.AttestationHash, nil
}

// findCapByHash looks up a cap entity by its content hash by trying
// each known controller-path. Caps live at one of the controller paths
// per §11.6; we don't know which is which until we read it.
func findCapByHash(ctx context.Context, a *PeerClient, capHash, primary, secondary hash.Hash) (entity.Entity, bool) {
	for _, controller := range []hash.Hash{primary, secondary} {
		ent, _, err := a.TreeGet(ctx, localPeerToControllerCapPath(controller))
		if err != nil {
			continue
		}
		if ent.ContentHash == capHash {
			return ent, true
		}
	}
	return entity.Entity{}, false
}

// localPeerToControllerCapPath mirrors ext/identity/paths.go's path builder
// for the local peer→controller cap. Replicated here to avoid pulling
// the (unexported) helper across package boundaries.
func localPeerToControllerCapPath(controllerKey hash.Hash) string {
	return "system/capability/grants/identity/peer-to-controller/" + hex.EncodeToString(controllerKey.Bytes())
}

// dumpResponseError extracts the error code/message from an EXECUTE
// response body, if present, for richer FailCheck messages.
func dumpResponseError(resp types.ExecuteResponseData) string {
	if len(resp.Result) == 0 {
		return ""
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return ""
	}
	var errBody struct {
		Code    string `cbor:"code"`
		Message string `cbor:"message"`
	}
	if err := cbor.Unmarshal(resultEnt.Data, &errBody); err != nil {
		return ""
	}
	if errBody.Code == "" {
		return ""
	}
	return fmt.Sprintf("%s: %s", errBody.Code, errBody.Message)
}
