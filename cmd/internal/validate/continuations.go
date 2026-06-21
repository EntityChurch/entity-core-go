package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/role"
	rolesdk "go.entitychurch.org/entity-core-go/ext/role/sdk"

	"github.com/fxamacker/cbor/v2"
)

const catContinuations = "continuations"

// installContinuationFromData creates an attenuated dispatch capability
// scoped to the continuation's target/operation/resource and calls
// system/continuation:install. The validator's identity is the granter on
// the dispatch cap so R1 chain-root passes (proposal §3, FEEDBACK §1.6).
//
// Tests that previously did `TreePut(path, contEntity)` migrate to this
// helper. Tests deliberately probing the legacy direct-`tree:put` path
// (e.g., the W9 negative test for missing dispatch_capability) keep
// using TreePut directly.
func installContinuationFromData(ctx context.Context, client *PeerClient, path string, cont types.ContinuationData) error {
	handlerPattern := handlerFromTargetURI(cont.Target)
	// V7 v7.73 §PR-8: bare "*" canonicalizes to /{granter_pid}/* — the
	// validator's namespace, NOT the verifier's. Default to /*/* (cross-
	// peer wildcard, no §PR-8 canonicalization) so the dispatch-time scope
	// check matches against any peer's namespace, not just the granter's.
	resources := []string{"/*/*"}
	if cont.Resource != nil && len(cont.Resource.Targets) > 0 {
		resources = cont.Resource.Targets
	}
	dispatchCap, dispatchSig, err := client.CreateDispatchCapability(
		[]string{handlerPattern}, resources, []string{cont.Operation},
	)
	if err != nil {
		return fmt.Errorf("create dispatch cap: %w", err)
	}
	cont.DispatchCapability = dispatchCap.ContentHash
	contEnt, err := cont.ToEntity()
	if err != nil {
		return fmt.Errorf("build continuation entity: %w", err)
	}
	extras := map[hash.Hash]entity.Entity{
		dispatchCap.ContentHash: dispatchCap,
		dispatchSig.ContentHash: dispatchSig,
	}
	env, _, err := client.SendInstall(ctx, path, contEnt, extras)
	if err != nil {
		return fmt.Errorf("send install: %w", err)
	}
	respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
	if respData.Status != 200 {
		return fmt.Errorf("install returned status %d", respData.Status)
	}
	if err := assertContinuationInstallResult(respData); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// assertContinuationInstallResult typed-decodes a system/continuation:install
// result and asserts the minimum invariant: the Path field is present and
// non-empty. Cross-impl wire-shape regressions in the install-result envelope
// (missing path key, path emitted as null/empty) would otherwise sail past
// the status check. Bare-minimum guard — callers needing stricter checks
// (e.g. exact path match) can do them on top.
func assertContinuationInstallResult(resp types.ExecuteResponseData) error {
	var result types.ContinuationInstallResultData
	inner, err := decodeResultData(resp, &result)
	if err != nil {
		return fmt.Errorf("decode install result: %w", err)
	}
	if inner.Type != types.TypeContinuationInstallResult {
		return fmt.Errorf("install result type=%q (expected %q)", inner.Type, types.TypeContinuationInstallResult)
	}
	if result.Path == "" {
		return fmt.Errorf("install result has empty path")
	}
	return nil
}

// dispatchCapOperations returns the operation set a cross-peer
// dispatch_capability must grant for a continuation whose dispatched
// EXECUTE targets (handlerPattern, contOp).
//
// The continuation op authorizes the request itself, but the target
// handler ALSO runs a Level-2 capability check against the *underlying
// data operation* it performs — which, for system/tree, is NOT the
// continuation op name (verified core/tree/operations.go):
//
//	extract / snapshot  read entities  -> Level-2 "get"  (operations.go:112/374)
//	merge               writes entities -> Level-2 "put"  (operations.go:268)
//
// A dispatch_capability scoped to only the continuation op passes
// request auth ("auth ok") but then fails the handler's internal check
// (403 capability_denied "insufficient capability for extract prefix").
// This is the precise cause of the psync/filesync 0/N cross-peer sync
// failures: once §6.8 stopped silent escalation to the broad connection
// cap, the scoped dispatch_capability became the only authority — and it
// omitted the get/put the tree handler enforces internally. Granting the
// underlying op alongside the continuation op is minimal and correct
// (an extract continuation legitimately reads; a merge legitimately
// writes); it does not widen the resource/handler scope.
func dispatchCapOperations(handlerPattern, contOp string) []string {
	ops := []string{contOp}
	if handlerPattern == "system/tree" {
		switch contOp {
		case "extract", "snapshot":
			ops = append(ops, "get")
		case "merge":
			ops = append(ops, "put")
		}
	}
	return ops
}

// InstallCrossPeerContinuation installs `cont` on peer `a` with a CONFORMANT
// cross-peer dispatch_capability per EXTENSION-CONTINUATION v1.11 §4.2 case 3:
// B-rooted (parent = the cap the target peer `b` conferred on the installer
// at connect — (i)), installer in-chain as the re-attenuation leaf granter
// ((ii)), and granted to peer A — the dispatching host peer that authors the
// dispatched EXECUTE ((iii)). The cap is scoped to the continuation's own
// handler / operation / resource. The full chain travels in the install
// envelope so peer A's ingest binds the signatures at the V7 invariant
// pointer path and the install handler persists the chain (§3.2 step 5),
// which is exactly what CollectChainBundle transports at advance (§4.3).
//
// This is the migration target for every cross-peer continuation that used
// the legacy self-rooted `a.CapEntity()` pattern (which only ever worked via
// the silent escalation the §6.8/§4.2-case-3 consumer now correctly closes).
// Use ONLY for cross-peer continuations (Target = entity://<remote-peer>/…);
// local continuations are unaffected by the consumer and need no change.
func InstallCrossPeerContinuation(ctx context.Context, a, b *PeerClient, installPath string, cont types.ContinuationData) error {
	handlerPattern := handlerFromTargetURI(cont.Target)
	peerBID := string(b.RemotePeerID())
	// V7 v7.73 §PR-8 (granter-aware cap-resource canonicalization): cap
	// resource patterns canonicalize against the granter's peer_id, not
	// the verifier's. The leaf cap here is signed by the validator (the
	// installer), so peer-relative patterns would canonicalize to
	// /{validator}/... — wrong namespace. Canonicalize each pattern to
	// absolute /{peerBID}/... form so the cap explicitly authorizes paths
	// in target peer B's namespace regardless of who signs the leaf.
	canonicalize := func(t string) string {
		if strings.HasPrefix(t, "/") {
			return t
		}
		return "/" + peerBID + "/" + t
	}
	resources := []string{"/" + peerBID + "/*"}
	if cont.Resource != nil && len(cont.Resource.Targets) > 0 {
		// Scope to the continuation's own target(s). Include a subtree
		// wildcard alongside each literal: prefix operations (tree.extract
		// / tree.merge over `prefix/`) authorize against paths UNDER the
		// prefix, so a literal-only scope is too narrow (B → 403); exact
		// operations (get/receive) still match the literal. Stays scoped to
		// the legitimate target's subtree — the c3 negative control uses a
		// disjoint prefix, so it remains correctly denied.
		resources = nil
		for _, t := range cont.Resource.Targets {
			canon := canonicalize(t)
			resources = append(resources, canon)
			if !strings.HasSuffix(canon, "*") {
				resources = append(resources, strings.TrimSuffix(canon, "/")+"/*")
			}
		}
	}
	grant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{handlerPattern}},
		Resources:  types.CapabilityScope{Include: resources},
		Operations: types.CapabilityScope{Include: dispatchCapOperations(handlerPattern, cont.Operation)},
	}
	scopedCap, scopedSig, err := b.CreateChainedCapGrantedTo(b.CapEntity(), []types.GrantEntry{grant}, a.RemotePeerIdentityHash(), nil)
	if err != nil {
		return fmt.Errorf("mint B-rooted dispatch_capability: %w", err)
	}
	cont.DispatchCapability = scopedCap.ContentHash
	contEnt, err := cont.ToEntity()
	if err != nil {
		return fmt.Errorf("build continuation entity: %w", err)
	}
	extras := map[hash.Hash]entity.Entity{}
	for h, e := range b.AuthenticateResponseEnv.Included {
		extras[h] = e
	}
	extras[scopedCap.ContentHash] = scopedCap
	extras[scopedSig.ContentHash] = scopedSig
	vid := a.IdentityEntity()
	extras[vid.ContentHash] = vid
	bcap := b.CapEntity()
	extras[bcap.ContentHash] = bcap
	env, _, err := a.SendInstall(ctx, installPath, contEnt, extras)
	if err != nil {
		return fmt.Errorf("install cross-peer continuation: %w", err)
	}
	rd, _ := types.ExecuteResponseDataFromEntity(env.Root)
	if rd.Status != 200 {
		return fmt.Errorf("install cross-peer continuation returned status %d", rd.Status)
	}
	if err := assertContinuationInstallResult(rd); err != nil {
		return fmt.Errorf("install cross-peer continuation %s: %w", installPath, err)
	}
	return nil
}

// InstallCrossPeerContinuationScoped is the three-identity, scoped-grant
// conformance path for EXTENSION-CONTINUATION v1.11 §4.2 case 3.
//
// Unlike InstallCrossPeerContinuation (which works only because the shared
// validate identity is connected to both peers), this models the three
// distinct principals the spec requires, reusing the role infrastructure for
// the operator's B-conferred scoped grant — no shared identity, no
// --debug open-access dependency:
//
//   - peer A (`a`): the dispatching host peer; the dispatch_capability's
//     grantee (= the EXECUTE author) — §4.2 case 3 (iii).
//   - peer B (`b`): the remote target; a scoped role is Defined+Assigned to
//     the operator here, so B issues a B-rooted role-derived cap — the
//     chain root (i).
//   - operator (`operatorKP`/`operatorID`): a DISTINCT non-peer identity;
//     the in-chain leaf granter (ii) that re-attenuates B's role-derived
//     cap into the dispatch_capability and is the continuation writer.
//
// `a` is also used as the admin transport that Defines/Assigns the role on
// B and installs on A (it holds admin authority via its connection); the
// authority that actually gates the dispatch is the operator's role-derived
// chain, not `a`'s connection cap.
func InstallCrossPeerContinuationScoped(ctx context.Context, a, b *PeerClient, operatorKP crypto.Keypair, operatorID entity.Entity, installPath string, cont types.ContinuationData) error {
	handlerPattern := handlerFromTargetURI(cont.Target)
	peerBID := string(b.RemotePeerID())
	// V7 v7.73 §PR-8: cap resources canonicalize against granter; force
	// absolute /{peerBID}/... so authorization names B's namespace
	// regardless of which identity actually signs the leaf cap.
	canonicalize := func(t string) string {
		if strings.HasPrefix(t, "/") {
			return t
		}
		return "/" + peerBID + "/" + t
	}
	resources := []string{"/" + peerBID + "/*"}
	if cont.Resource != nil && len(cont.Resource.Targets) > 0 {
		resources = nil
		for _, t := range cont.Resource.Targets {
			canon := canonicalize(t)
			resources = append(resources, canon)
			if !strings.HasSuffix(canon, "*") {
				resources = append(resources, strings.TrimSuffix(canon, "/")+"/*")
			}
		}
	}
	grant := types.GrantEntry{
		Handlers:   types.CapabilityScope{Include: []string{handlerPattern}},
		Resources:  types.CapabilityScope{Include: resources},
		Operations: types.CapabilityScope{Include: dispatchCapOperations(handlerPattern, cont.Operation)},
	}

	// Scoped role on B, assigned to the OPERATOR → B issues a B-rooted,
	// scoped, operator-targeted role-derived cap (the operator's "B-conferred
	// authority"; real and scoped, not --debug open-access).
	ctxName := "validate/xpeer-cont/" + strings.NewReplacer("/", "-", "*", "x").Replace(installPath) +
		fmt.Sprintf("-%d", time.Now().UnixNano())
	const roleName = "dispatcher"
	sdkB := rolesdk.NewClient(b)
	if st, _, err := sdkB.Define(ctx, ctxName, roleName, []types.GrantEntry{grant}, nil); err != nil {
		return fmt.Errorf("role define on B: %w", err)
	} else if st != 200 {
		return fmt.Errorf("role define on B returned status %d", st)
	}
	st, asn, err := sdkB.Assign(ctx, ctxName, operatorID.ContentHash, roleName)
	if err != nil {
		return fmt.Errorf("role assign on B: %w", err)
	}
	if st != 200 || len(asn.DerivedTokens) != 1 {
		return fmt.Errorf("role assign on B: status=%d derived_tokens=%d", st, len(asn.DerivedTokens))
	}
	rdPath := role.RoleDerivedTokenPath(ctxName, operatorID.ContentHash, asn.DerivedTokens[0])
	rdCap, _, err := b.TreeGet(ctx, rdPath)
	if err != nil {
		return fmt.Errorf("read B role-derived cap: %w", err)
	}

	// Operator re-attenuates B's role-derived cap into the dispatch_cap:
	// parent = role-derived (B-rooted), granter = operator (in-chain leaf),
	// grantee = peer A (the dispatching host / EXECUTE author).
	capEnt, sigEnt, err := capability.MintReattenuated(
		operatorKP, operatorID, a.RemotePeerIdentityHash(), rdCap,
		[]types.GrantEntry{grant}, uint64(time.Now().UnixMilli()), nil)
	if err != nil {
		return fmt.Errorf("operator re-attenuate: %w", err)
	}

	cont.DispatchCapability = capEnt.ContentHash
	contEnt, err := cont.ToEntity()
	if err != nil {
		return fmt.Errorf("build continuation entity: %w", err)
	}

	// Full chain at install (§3.2 step 5 / §4.3): the re-attenuated cap +
	// sig, B's role-derived cap (B issued it → resolves its own ancestry),
	// the operator identity, plus whatever B/A sent at connect (identities,
	// signatures). Ingest binds signatures; install persists the chain.
	extras := map[hash.Hash]entity.Entity{}
	for h, e := range b.AuthenticateResponseEnv.Included {
		extras[h] = e
	}
	for h, e := range a.AuthenticateResponseEnv.Included {
		if _, ok := extras[h]; !ok {
			extras[h] = e
		}
	}
	extras[rdCap.ContentHash] = rdCap
	extras[capEnt.ContentHash] = capEnt
	extras[sigEnt.ContentHash] = sigEnt
	extras[operatorID.ContentHash] = operatorID

	env, _, err := a.SendInstall(ctx, installPath, contEnt, extras)
	if err != nil {
		return fmt.Errorf("install on A: %w", err)
	}
	rd, _ := types.ExecuteResponseDataFromEntity(env.Root)
	if rd.Status != 200 {
		return fmt.Errorf("install on A returned status %d", rd.Status)
	}
	if err := assertContinuationInstallResult(rd); err != nil {
		return fmt.Errorf("install on A %s: %w", installPath, err)
	}
	return nil
}

// installJoinFromData is the join-continuation counterpart to
// installContinuationFromData.
func installJoinFromData(ctx context.Context, client *PeerClient, path string, join types.ContinuationJoinData) error {
	handlerPattern := handlerFromTargetURI(join.Target)
	resources := []string{"*"}
	if join.Resource != nil && len(join.Resource.Targets) > 0 {
		resources = join.Resource.Targets
	}
	dispatchCap, dispatchSig, err := client.CreateDispatchCapability(
		[]string{handlerPattern}, resources, []string{join.Operation},
	)
	if err != nil {
		return fmt.Errorf("create dispatch cap: %w", err)
	}
	join.DispatchCapability = dispatchCap.ContentHash
	joinEnt, err := join.ToEntity()
	if err != nil {
		return fmt.Errorf("build join entity: %w", err)
	}
	extras := map[hash.Hash]entity.Entity{
		dispatchCap.ContentHash: dispatchCap,
		dispatchSig.ContentHash: dispatchSig,
	}
	env, _, err := client.SendInstall(ctx, path, joinEnt, extras)
	if err != nil {
		return fmt.Errorf("send install: %w", err)
	}
	respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
	if respData.Status != 200 {
		return fmt.Errorf("install returned status %d", respData.Status)
	}
	if err := assertContinuationInstallResult(respData); err != nil {
		return fmt.Errorf("install join %s: %w", path, err)
	}
	return nil
}

// handlerFromTargetURI extracts the handler pattern from an entity URI.
// "entity://peer/system/inbox" → "system/inbox". Returns the input unchanged
// for non-URI targets.
func handlerFromTargetURI(target string) string {
	if !strings.HasPrefix(target, "entity://") {
		return target
	}
	rest := strings.TrimPrefix(target, "entity://")
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return ""
	}
	return rest[idx+1:]
}

// runContinuations validates the continuation extension against a remote peer.
func runContinuations(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catContinuations)

	// --- Declare all checks ---

	// Step 1: Handler manifests
	r.Declare("inbox_handler_present", "INBOX §2")
	r.Declare("continuation_handler_present", "CONTINUATION §3.6")
	r.Declare("continuation_handler_ops_advance", "CONTINUATION §3.3")
	r.Declare("continuation_handler_ops_resume", "CONTINUATION §3.6")
	r.Declare("continuation_handler_ops_abandon", "CONTINUATION §3.6")

	// Step 2: Continuation types
	r.Declare("type_system/continuation", "CONTINUATION §2")
	r.Declare("type_system/continuation/transform", "CONTINUATION §2")
	r.Declare("type_system/continuation/join", "CONTINUATION §2")
	r.Declare("type_system/continuation/suspended", "CONTINUATION §2")
	r.Declare("type_system/continuation/resume-request", "CONTINUATION §2")
	r.Declare("type_system/continuation/abandon-request", "CONTINUATION §2")
	r.Declare("type_system/continuation/advance-request", "CONTINUATION §2")

	// Step 3: Forward continuation advancement
	r.Declare("forward_write_continuation", "CONTINUATION §3.3")
	r.Declare("forward_deliver", "CONTINUATION §3.3")
	r.Declare("forward_target_received", "CONTINUATION §3.4")
	r.Declare("forward_target_roundtrip", "CONTINUATION §3.4")
	r.Declare("forward_remaining_executions_delete", "CONTINUATION §3.4")

	// Step 4: Backward compatibility
	r.Declare("backward_compat_deliver", "INBOX §3")
	r.Declare("backward_compat_stored", "INBOX §3")

	// Step 5: Suspended resume and abandon
	r.Declare("resume_write_suspended", "CONTINUATION §3.7")
	r.Declare("resume_dispatch", "CONTINUATION §3.7")
	r.Declare("resume_deletes_suspended", "CONTINUATION §3.7")
	r.Declare("abandon_write_suspended", "CONTINUATION §3.7")
	r.Declare("abandon_dispatch", "CONTINUATION §3.7")
	r.Declare("abandon_deletes_entity", "CONTINUATION §3.7")

	// Step 6: Advance operation (direct)
	r.Declare("advance_write_continuation", "CONTINUATION §3.3")
	r.Declare("advance_dispatch", "CONTINUATION §3.3")
	r.Declare("advance_target_received", "CONTINUATION §3.4")
	r.Declare("advance_consumed", "CONTINUATION §3.4")

	// Step 7: Dispatch modes
	r.Declare("dispatch_passthrough", "CONTINUATION §3.3")
	r.Declare("dispatch_inject", "CONTINUATION §3.3")
	r.Declare("dispatch_trigger", "CONTINUATION §3.3")
	r.Declare("dispatch_invalid_rejected", "CONTINUATION §3.3")

	// Step 8: remaining_executions lifecycle
	r.Declare("remaining_countdown_first", "CONTINUATION §3.4")
	r.Declare("remaining_countdown_second", "CONTINUATION §3.4")
	r.Declare("remaining_countdown_exhausted", "CONTINUATION §3.4")
	r.Declare("remaining_standing_advance_1", "CONTINUATION §3.4")
	r.Declare("remaining_standing_advance_2", "CONTINUATION §3.4")
	r.Declare("remaining_standing_persists", "CONTINUATION §3.4")

	// Step 9: on_error routing
	r.Declare("onerror_setup", "CONTINUATION §3.5")
	r.Declare("onerror_advance", "CONTINUATION §3.5")
	r.Declare("onerror_routed", "CONTINUATION §3.5")
	r.Declare("no_onerror_marker_bound", "CONTINUATION §3.4 (v1.13 / I-8)")

	// Step 10: result_transform
	r.Declare("transform_extract", "CONTINUATION §3.5")
	r.Declare("transform_select", "CONTINUATION §3.5")
	r.Declare("transform_ops_apply", "CONTINUATION §2.2")
	r.Declare("transform_ops_unknown_rejected", "CONTINUATION §2.2 / §8.1")
	r.Declare("deref_included_resolves", "CONTINUATION §2.2 v1.17")
	r.Declare("deref_included_miss_noop", "CONTINUATION §2.2 v1.17")
	r.Declare("request_side_included_preserved", "V7 §3.3 v7.51")

	// Step 11: Join continuation
	r.Declare("join_write", "CONTINUATION §3.6")
	r.Declare("join_slot_a", "CONTINUATION §3.6")
	r.Declare("join_slot_b_dispatch", "CONTINUATION §3.6")
	r.Declare("join_target_received", "CONTINUATION §3.6")
	r.Declare("join_unexpected_slot", "CONTINUATION §3.6")
	r.Declare("join_direct_rejected", "CONTINUATION §3.6")

	// Step 12: W9 — dispatch_capability enforcement
	r.Declare("w9_rejected", "W9 §3.5")

	// PROPOSAL-COHERENT-CAPABILITY-AUTHORITY §10 conformance vectors.
	r.Declare("r1_install_writer_self_issued_accepted", "COHERENT-CAP §10")
	r.Declare("r1_install_adversary_rejected", "COHERENT-CAP §10")
	r.Declare("r1_install_join_adversary_rejected", "COHERENT-CAP §10")
	r.Declare("r1_install_chain_unreachable", "COHERENT-CAP §2")

	// --- Pre-step: Ensure the client's capability entity is stored on the remote
	// peer's content store. Continuations reference it via dispatch_capability
	// (W9), so the continuation handler must be able to resolve the hash.
	if !client.CapEntity().ContentHash.IsZero() {
		client.TreePut(ctx, "system/validate/dispatch-cap-store", client.CapEntity())
	}

	// --- Step 1: Handler manifests ---

	r.Run("inbox_handler_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/inbox")
		if err != nil {
			return FailCheck("failed to fetch inbox handler manifest: " + err.Error())
		}
		return PassCheck(fmt.Sprintf("inbox handler manifest present (type: %s)", ent.Type))
	})

	r.Run("continuation_handler_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/continuation")
		if err != nil {
			return FailCheck("failed to fetch continuation handler manifest: " + err.Error())
		}
		handlerData, decErr := types.HandlerInterfaceDataFromEntity(ent)
		if decErr != nil {
			return PassCheck(fmt.Sprintf("continuation handler manifest present (type: %s) but could not decode operations", ent.Type))
		}
		r.Store("continuation_handler_data", handlerData)
		return PassCheck(fmt.Sprintf("continuation handler manifest present (type: %s)", ent.Type))
	})

	for _, op := range []string{"advance", "resume", "abandon"} {
		op := op
		r.Run("continuation_handler_ops_"+op, func() CheckOutcome {
			if out, ok := r.Require("continuation_handler_present"); !ok {
				return out
			}
			handlerData := r.Load("continuation_handler_data")
			if handlerData == nil {
				return SkipCheck("handler manifest could not be decoded — cannot verify operations")
			}
			hd := handlerData.(types.HandlerInterfaceData)
			if _, exists := hd.Operations[op]; !exists {
				return FailCheck("continuation handler missing '" + op + "' operation")
			}
			return PassCheck("continuation handler has '" + op + "' operation")
		})
	}

	// --- Step 2: Continuation types ---

	contTypes := []struct {
		name    string
		typeRef string
	}{
		{"system/continuation", types.TypeContinuation},
		{"system/continuation/transform", types.TypeContinuationTransform},
		{"system/continuation/join", types.TypeContinuationJoin},
		{"system/continuation/suspended", types.TypeContinuationSuspended},
		{"system/continuation/resume-request", types.TypeContinuationResumeRequest},
		{"system/continuation/abandon-request", types.TypeContinuationAbandonRequest},
		{"system/continuation/advance-request", types.TypeContinuationAdvanceRequest},
	}
	for _, ct := range contTypes {
		ct := ct
		r.Run("type_"+ct.name, func() CheckOutcome {
			typePath := "system/type/" + ct.typeRef
			_, _, err := client.TreeGet(ctx, typePath)
			if err != nil {
				return FailCheck(fmt.Sprintf("type %s not registered: %v", ct.typeRef, err))
			}
			return PassCheck(fmt.Sprintf("type %s registered", ct.typeRef))
		})
	}

	// --- Step 3: Forward continuation advancement ---

	r.Run("forward_write_continuation", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		inboxPath := "system/inbox/validate-cont-forward"
		targetInboxPath := "system/inbox/validate-cont-target"

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetInboxPath}},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, inboxPath, cont); err != nil {
			return FailCheck("failed to install continuation: " + err.Error())
		}
		return PassCheck("forward continuation installed at " + inboxPath)
	})

	r.Run("forward_deliver", func() CheckOutcome {
		if out, ok := r.Require("forward_write_continuation"); !ok {
			return out
		}
		peerID := string(client.RemotePeerID())
		inboxPath := "system/inbox/validate-cont-forward"

		resultData, _ := ecf.Encode(map[string]interface{}{
			"forwarded": true,
			"timestamp": time.Now().UnixMilli(),
		})

		messageEntity, err := entity.NewEntity("primitive/any", cbor.RawMessage(resultData))
		if err != nil {
			return FailCheck("failed to create message entity: " + err.Error())
		}

		inboxURI := fmt.Sprintf("entity://%s/%s", peerID, inboxPath)
		resource := &types.ResourceTarget{Targets: []string{inboxPath}}
		env, _, err := client.SendExecute(ctx, inboxURI, "receive", messageEntity, resource)
		if err != nil {
			return FailCheck("failed to deliver to inbox: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("failed to decode delivery response: " + err.Error())
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("delivery returned status %d (expected 200)", respData.Status))
		}
		return PassCheck("delivery to continuation returned 200 (advancement acknowledged)")
	})

	r.Run("forward_target_received", func() CheckOutcome {
		if out, ok := r.Require("forward_deliver"); !ok {
			return out
		}
		targetInboxPath := "system/inbox/validate-cont-target"

		time.Sleep(100 * time.Millisecond)
		entries := []string{}
		listing, _, listErr := client.TreeListing(ctx, targetInboxPath+"/")
		if listErr == nil {
			for k := range listing {
				entries = append(entries, k)
			}
		}
		if len(entries) > 0 {
			r.Store("forward_target_listing", listing)
			r.Store("forward_target_inbox_path", targetInboxPath)
			return PassCheck(fmt.Sprintf("forward continuation result stored at target (%d entries)", len(entries)))
		}
		return WarnCheck("target inbox path has no entries (dispatch may have failed internally)")
	})

	r.Run("forward_target_roundtrip", func() CheckOutcome {
		if out, ok := r.Require("forward_target_received"); !ok {
			return out
		}
		listing := r.Load("forward_target_listing")
		if listing == nil {
			return SkipCheck("no listing data from forward_target_received")
		}
		targetInboxPath := r.Load("forward_target_inbox_path").(string)
		listingMap := listing.(map[string]interface{})

		fetchFailed := 0
		var firstErr string
		for k := range listingMap {
			p := targetInboxPath + "/" + k
			_, _, getErr := client.TreeGet(ctx, p)
			if getErr != nil {
				fetchFailed++
				if firstErr == "" {
					firstErr = fmt.Sprintf("listed forwarded entry %q not fetchable: %v", p, getErr)
				}
			}
		}
		if fetchFailed > 0 {
			return FailCheck(firstErr)
		}
		return PassCheck(fmt.Sprintf("all %d forwarded entries individually fetchable", len(listingMap)))
	})

	r.Run("forward_remaining_executions_delete", func() CheckOutcome {
		if out, ok := r.Require("forward_deliver"); !ok {
			return out
		}
		inboxPath := "system/inbox/validate-cont-forward"

		_, _, getErr := client.TreeGet(ctx, inboxPath)
		if getErr != nil {
			return PassCheck("continuation deleted after remaining_executions=1")
		}
		return WarnCheck("continuation still exists after remaining_executions=1 (may be implementation-defined)")
	})

	// Forward continuation cleanup.
	cleanupPath("system/inbox/validate-cont-forward", ctx, client)
	cleanupPath("system/inbox/validate-cont-target", ctx, client)

	// --- Step 4: Backward compatibility ---

	r.Run("backward_compat_deliver", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		inboxPath := "system/inbox/validate-cont-compat"

		messageData, _ := ecf.Encode(map[string]interface{}{"compat": true})
		messageEntity, err := entity.NewEntity("primitive/any", cbor.RawMessage(messageData))
		if err != nil {
			return FailCheck("failed to create message entity: " + err.Error())
		}

		inboxURI := fmt.Sprintf("entity://%s/%s", peerID, inboxPath)
		resource := &types.ResourceTarget{Targets: []string{inboxPath}}
		env, _, err := client.SendExecute(ctx, inboxURI, "receive", messageEntity, resource)
		if err != nil {
			return FailCheck("failed to receive: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err == nil && respData.Status == 200 {
			return PassCheck("receive without continuation returned 200")
		}
		status := uint(0)
		if err == nil {
			status = respData.Status
		}
		return FailCheck(fmt.Sprintf("receive returned status %d", status))
	})

	r.Run("backward_compat_stored", func() CheckOutcome {
		if out, ok := r.Require("backward_compat_deliver"); !ok {
			return out
		}
		inboxPath := "system/inbox/validate-cont-compat"

		time.Sleep(100 * time.Millisecond)
		listing, _, listErr := client.TreeListing(ctx, inboxPath+"/")
		if listErr == nil && len(listing) > 0 {
			// Store listing for cleanup.
			r.Store("backward_compat_listing", listing)
			return PassCheck(fmt.Sprintf("message stored at %s/ (mailbox mode, %d entries)", inboxPath, len(listing)))
		}
		return FailCheck(fmt.Sprintf("message not stored at %s/ (mailbox mode)", inboxPath))
	})

	// Backward compat cleanup.
	if listing := r.Load("backward_compat_listing"); listing != nil {
		for k := range listing.(map[string]interface{}) {
			cleanupPath("system/inbox/validate-cont-compat/"+k, ctx, client)
		}
	}

	// --- Step 5: Suspended resume and abandon ---

	r.Run("resume_write_suspended", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		suspendedPath := "system/continuation/suspended/validate-resume"
		targetGetPath := "system/validate/cont-test/resumed"

		// Pre-populate the target path so the GET succeeds.
		markerData, _ := ecf.Encode(map[string]interface{}{"resumed": true})
		markerEntity, _ := entity.NewEntity("system/validate/cont-test-marker", cbor.RawMessage(markerData))
		client.TreePut(ctx, targetGetPath, markerEntity)

		getReqData := types.GetRequestData{Mode: "entity"}
		paramsRaw, _ := ecf.Encode(getReqData)

		suspended := types.ContinuationSuspendedData{
			Target:      fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation:   "get",
			Resource:    &types.ResourceTarget{Targets: []string{targetGetPath}},
			Params:      cbor.RawMessage(paramsRaw),
			Reason:      "validation_test",
			ChainID:     "validate-chain-1",
			SuspendedAt: uint64(time.Now().UnixMilli()),
		}
		suspendedEntity, err := suspended.ToEntity()
		if err != nil {
			return FailCheck("failed to create suspended entity: " + err.Error())
		}

		_, err = client.TreePut(ctx, suspendedPath, suspendedEntity)
		if err != nil {
			return FailCheck("failed to write suspended entity: " + err.Error())
		}
		return PassCheck("suspended continuation written at " + suspendedPath)
	})

	r.Run("resume_dispatch", func() CheckOutcome {
		if out, ok := r.Require("resume_write_suspended"); !ok {
			return out
		}
		peerID := string(client.RemotePeerID())
		suspendedPath := "system/continuation/suspended/validate-resume"

		resumeReq := types.ContinuationResumeRequestData{}
		resumeEntity, err := resumeReq.ToEntity()
		if err != nil {
			return FailCheck("failed to create resume request: " + err.Error())
		}

		contURI := fmt.Sprintf("entity://%s/system/continuation", peerID)
		resource := &types.ResourceTarget{Targets: []string{suspendedPath}}
		env, _, err := client.SendExecute(ctx, contURI, "resume", resumeEntity, resource)
		if err != nil {
			return FailCheck("resume failed: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err == nil && respData.Status == 200 {
			return PassCheck("resume returned 200")
		}
		status := uint(0)
		if err == nil {
			status = respData.Status
		}
		return FailCheck(fmt.Sprintf("resume returned status %d", status))
	})

	r.Run("resume_deletes_suspended", func() CheckOutcome {
		if out, ok := r.Require("resume_dispatch"); !ok {
			return out
		}
		suspendedPath := "system/continuation/suspended/validate-resume"

		_, _, getErr := client.TreeGet(ctx, suspendedPath)
		if getErr != nil {
			return PassCheck("suspended entity deleted after resume")
		}
		return FailCheck("suspended entity still exists after resume")
	})

	// Resume cleanup.
	cleanupPath("system/continuation/suspended/validate-resume", ctx, client)
	cleanupPath("system/validate/cont-test/resumed", ctx, client)

	r.Run("abandon_write_suspended", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		suspendedPath := "system/continuation/suspended/validate-abandon"

		suspended := types.ContinuationSuspendedData{
			Target:      fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation:   "put",
			Reason:      "validation_test_abandon",
			ChainID:     "validate-chain-2",
			SuspendedAt: uint64(time.Now().UnixMilli()),
		}
		suspendedEntity, err := suspended.ToEntity()
		if err != nil {
			return FailCheck("failed to create suspended entity: " + err.Error())
		}

		_, err = client.TreePut(ctx, suspendedPath, suspendedEntity)
		if err != nil {
			return FailCheck("failed to write suspended entity: " + err.Error())
		}
		return PassCheck("suspended continuation written at " + suspendedPath)
	})

	r.Run("abandon_dispatch", func() CheckOutcome {
		if out, ok := r.Require("abandon_write_suspended"); !ok {
			return out
		}
		peerID := string(client.RemotePeerID())
		suspendedPath := "system/continuation/suspended/validate-abandon"

		abandonReq := types.ContinuationAbandonRequestData{}
		abandonEntity, err := abandonReq.ToEntity()
		if err != nil {
			return FailCheck("failed to create abandon request: " + err.Error())
		}

		contURI := fmt.Sprintf("entity://%s/system/continuation", peerID)
		resource := &types.ResourceTarget{Targets: []string{suspendedPath}}
		env, _, err := client.SendExecute(ctx, contURI, "abandon", abandonEntity, resource)
		if err != nil {
			return FailCheck("abandon failed: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err == nil && respData.Status == 200 {
			return PassCheck("abandon returned 200")
		}
		status := uint(0)
		if err == nil {
			status = respData.Status
		}
		return FailCheck(fmt.Sprintf("abandon returned status %d", status))
	})

	r.Run("abandon_deletes_entity", func() CheckOutcome {
		if out, ok := r.Require("abandon_dispatch"); !ok {
			return out
		}
		suspendedPath := "system/continuation/suspended/validate-abandon"

		_, _, getErr := client.TreeGet(ctx, suspendedPath)
		if getErr != nil {
			return PassCheck("suspended entity deleted after abandon")
		}
		return FailCheck("suspended entity still exists after abandon")
	})

	// --- Step 6: Advance operation (direct) ---

	r.Run("advance_write_continuation", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-advance-direct"
		targetPath := "system/inbox/validate-advance-target"

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install continuation: " + err.Error())
		}
		return PassCheck("continuation installed at " + contPath)
	})

	r.Run("advance_dispatch", func() CheckOutcome {
		if out, ok := r.Require("advance_write_continuation"); !ok {
			return out
		}
		contPath := "system/inbox/validate-advance-direct"

		resultData, _ := ecf.Encode(map[string]interface{}{"advanced_directly": true})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed: " + err.Error())
		}

		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err == nil && respData.Status == 200 {
			return PassCheck("advance returned 200")
		}
		status := uint(0)
		if err == nil {
			status = respData.Status
		}
		return FailCheck(fmt.Sprintf("advance returned status %d (expected 200)", status))
	})

	r.Run("advance_target_received", func() CheckOutcome {
		if out, ok := r.Require("advance_dispatch"); !ok {
			return out
		}
		targetPath := "system/inbox/validate-advance-target"

		time.Sleep(100 * time.Millisecond)
		entries, _, listErr := client.TreeListing(ctx, targetPath+"/")
		if listErr == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("advance result forwarded to target (%d entries)", len(entries)))
		}
		return WarnCheck("target inbox has no entries after advance")
	})

	r.Run("advance_consumed", func() CheckOutcome {
		if out, ok := r.Require("advance_dispatch"); !ok {
			return out
		}
		contPath := "system/inbox/validate-advance-direct"

		_, _, getErr := client.TreeGet(ctx, contPath)
		if getErr != nil {
			return PassCheck("continuation deleted after advance (remaining_executions=1)")
		}
		return WarnCheck("continuation still exists after advance")
	})

	// Advance cleanup.
	cleanupPath("system/inbox/validate-advance-direct", ctx, client)
	cleanupPath("system/inbox/validate-advance-target", ctx, client)

	// --- Step 7: Dispatch modes ---

	r.Run("dispatch_passthrough", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-dispatch-passthrough"
		targetPath := "system/inbox/validate-dispatch-target-passthrough"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install pass-through continuation: " + err.Error())
		}

		resultData, _ := ecf.Encode(map[string]interface{}{"value": 42})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status == 200 {
			return PassCheck("pass-through dispatch returned 200 (result forwarded as-is)")
		}
		return FailCheck(fmt.Sprintf("pass-through dispatch returned status %d", respData.Status))
	})

	r.Run("dispatch_inject", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-dispatch-inject"
		targetPath := "system/inbox/validate-dispatch-target-inject"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		paramsRaw, _ := ecf.Encode(map[string]interface{}{"base": "value"})
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			Params:              cbor.RawMessage(paramsRaw),
			ResultField:         "injected",
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install inject continuation: " + err.Error())
		}

		resultData, _ := ecf.Encode(map[string]interface{}{"data": 123})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status == 200 {
			return PassCheck("inject dispatch returned 200 (result injected into params)")
		}
		return FailCheck(fmt.Sprintf("inject dispatch returned status %d", respData.Status))
	})

	r.Run("dispatch_trigger", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-dispatch-trigger"
		targetPath := "system/inbox/validate-dispatch-target-trigger"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		paramsRaw, _ := ecf.Encode(map[string]interface{}{"fixed": true})
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			Params:              cbor.RawMessage(paramsRaw),
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install trigger continuation: " + err.Error())
		}

		resultData, _ := ecf.Encode(map[string]interface{}{"ignored": true})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status == 200 {
			return PassCheck("trigger dispatch returned 200 (fixed params sent, result ignored)")
		}
		return FailCheck(fmt.Sprintf("trigger dispatch returned status %d", respData.Status))
	})

	r.Run("dispatch_invalid_rejected", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-dispatch-invalid"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath("system/inbox/validate-dispatch-target-invalid", ctx, client)

		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{"system/inbox/validate-dispatch-target-invalid"}},
			ResultField:         "x",
			RemainingExecutions: nil,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install invalid continuation: " + err.Error())
		}

		resultData, _ := ecf.Encode(map[string]interface{}{"any": true})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return WarnCheck("advance send error: " + err.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status >= 400 {
			return PassCheck(fmt.Sprintf("result_field without params rejected with status %d", respData.Status))
		}
		return FailCheck(fmt.Sprintf("result_field without params returned status %d (expected >= 400)", respData.Status))
	})

	// --- Step 8: remaining_executions lifecycle ---

	r.Run("remaining_countdown_first", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-remaining-countdown"
		targetPath := "system/inbox/validate-remaining-countdown-target"

		remExec := uint64(2)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install countdown continuation: " + err.Error())
		}

		result1, _ := ecf.Encode(map[string]interface{}{"seq": 1})
		env1, _, err1 := client.SendAdvance(ctx, contPath, cbor.RawMessage(result1), nil)
		if err1 != nil {
			return FailCheck("first advance failed: " + err1.Error())
		}
		resp1, _ := types.ExecuteResponseDataFromEntity(env1.Root)
		if resp1.Status == 200 {
			return PassCheck("first advance returned 200 (remaining_executions: 2 → 1)")
		}
		return FailCheck(fmt.Sprintf("first advance returned status %d", resp1.Status))
	})

	r.Run("remaining_countdown_second", func() CheckOutcome {
		if out, ok := r.Require("remaining_countdown_first"); !ok {
			return out
		}
		contPath := "system/inbox/validate-remaining-countdown"

		result2, _ := ecf.Encode(map[string]interface{}{"seq": 2})
		env2, _, err2 := client.SendAdvance(ctx, contPath, cbor.RawMessage(result2), nil)
		if err2 != nil {
			return FailCheck("second advance failed: " + err2.Error())
		}
		resp2, _ := types.ExecuteResponseDataFromEntity(env2.Root)
		if resp2.Status == 200 {
			return PassCheck("second advance returned 200 (remaining_executions: 1 → 0)")
		}
		return FailCheck(fmt.Sprintf("second advance returned status %d", resp2.Status))
	})

	r.Run("remaining_countdown_exhausted", func() CheckOutcome {
		if out, ok := r.Require("remaining_countdown_second"); !ok {
			return out
		}
		contPath := "system/inbox/validate-remaining-countdown"

		time.Sleep(50 * time.Millisecond)
		_, _, getErr := client.TreeGet(ctx, contPath)
		if getErr != nil {
			return PassCheck("continuation deleted after remaining_executions exhausted")
		}
		return FailCheck("continuation still exists after remaining_executions=2 fully consumed")
	})

	// Countdown cleanup.
	cleanupPath("system/inbox/validate-remaining-countdown", ctx, client)
	cleanupPath("system/inbox/validate-remaining-countdown-target", ctx, client)

	r.Run("remaining_standing_advance_1", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-remaining-standing"
		targetPath := "system/inbox/validate-remaining-standing-target"

		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			RemainingExecutions: nil, // nil = unlimited/standing
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install standing continuation: " + err.Error())
		}

		result, _ := ecf.Encode(map[string]interface{}{"seq": 1})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(result), nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("standing advance #1 failed: %v", err))
		}
		resp, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if resp.Status == 200 {
			return PassCheck("standing advance #1 returned 200")
		}
		return FailCheck(fmt.Sprintf("standing advance #1 returned status %d", resp.Status))
	})

	r.Run("remaining_standing_advance_2", func() CheckOutcome {
		if out, ok := r.Require("remaining_standing_advance_1"); !ok {
			return out
		}
		contPath := "system/inbox/validate-remaining-standing"

		result, _ := ecf.Encode(map[string]interface{}{"seq": 2})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(result), nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("standing advance #2 failed: %v", err))
		}
		resp, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if resp.Status == 200 {
			return PassCheck("standing advance #2 returned 200")
		}
		return FailCheck(fmt.Sprintf("standing advance #2 returned status %d", resp.Status))
	})

	r.Run("remaining_standing_persists", func() CheckOutcome {
		if out, ok := r.Require("remaining_standing_advance_1"); !ok {
			return out
		}
		contPath := "system/inbox/validate-remaining-standing"

		_, _, getErr := client.TreeGet(ctx, contPath)
		if getErr == nil {
			return PassCheck("standing continuation still exists after multiple advances")
		}
		return FailCheck("standing continuation was deleted despite nil remaining_executions")
	})

	// Standing cleanup.
	cleanupPath("system/inbox/validate-remaining-standing", ctx, client)
	cleanupPath("system/inbox/validate-remaining-standing-target", ctx, client)

	// --- Step 9: on_error routing ---

	r.Run("onerror_setup", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-onerror-cont"
		targetPath := "system/inbox/validate-onerror-target"
		errorSinkPath := "system/inbox/validate-onerror-sink"

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation: "receive",
			Resource:  &types.ResourceTarget{Targets: []string{targetPath}},
			OnError: &types.DeliverySpec{
				URI:       fmt.Sprintf("entity://%s/%s", peerID, errorSinkPath),
				Operation: "receive",
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install on_error continuation: " + err.Error())
		}
		return PassCheck("continuation with on_error installed")
	})

	r.Run("onerror_advance", func() CheckOutcome {
		if out, ok := r.Require("onerror_setup"); !ok {
			return out
		}
		contPath := "system/inbox/validate-onerror-cont"

		resultData, _ := ecf.Encode(map[string]interface{}{"error": "something failed"})
		errStatus := uint(500)
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), &errStatus)
		if err != nil {
			return FailCheck("advance with error status failed: " + err.Error())
		}

		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status == 200 {
			return PassCheck("advance with error status returned 200 (error routed)")
		}
		return WarnCheck(fmt.Sprintf("advance with error status returned %d", respData.Status))
	})

	r.Run("onerror_routed", func() CheckOutcome {
		if out, ok := r.Require("onerror_advance"); !ok {
			return out
		}
		errorSinkPath := "system/inbox/validate-onerror-sink"

		time.Sleep(200 * time.Millisecond)
		entries, _, listErr := client.TreeListing(ctx, errorSinkPath+"/")
		if listErr == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("error routed to on_error sink (%d entries at %s/)", len(entries), errorSinkPath))
		}
		return WarnCheck("no entries at error sink (on_error routing may not be implemented)")
	})

	// On-error cleanup.
	cleanupPath("system/inbox/validate-onerror-cont", ctx, client)
	cleanupPath("system/inbox/validate-onerror-sink", ctx, client)
	cleanupPath("system/inbox/validate-onerror-target", ctx, client)

	// --- Step 9b: v1.13 / I-8 — no-on_error forward dispatch non-2xx ---
	//
	// EXTENSION-CONTINUATION v1.13 §3.4 (v1.16 per-reason path): when a
	// forward continuation has no on_error and the dispatched target
	// returns a handler-level non-2xx, SHOULD-bind an observability marker
	// at system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason}
	// with type system/runtime/chain-error-lost and
	// reason="forward_dispatch_non2xx".
	// The marker is informational — MUST NOT trigger advancement/retry/any
	// reactive behavior. remaining_executions decrements normally; the
	// dispatch is classified as a COMPLETED forward dispatch per v1.10.
	r.Run("no_onerror_marker_bound", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-no-onerror-cont"
		defer cleanupPath(contPath, ctx, client)
		// Pre-clean the lost-error sink so we observe only this advance's
		// emission (the sink is shared across advances; idempotent re-binds
		// would otherwise survive earlier tests in the same run).
		sinkPrefix := "system/runtime/chain-errors/lost/"
		beforeEntries, _, _ := client.TreeListing(ctx, sinkPrefix)

		// Use an operation the system/tree handler will reject (400
		// unknown_operation) so the dispatch lands with a handler-level
		// non-2xx — exactly the v1.13 trigger condition. The dispatch_cap
		// is scoped to this specific operation, so the dispatch reaches
		// the target handler before failing (cap-check is upstream of
		// the handler's unknown-op rejection).
		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation:           "no_such_op_for_v113_probe",
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return WarnCheck("install failed (v1.13 unobservable on this peer): " + err.Error())
		}

		resultData, _ := ecf.Encode(map[string]interface{}{"payload": "v1.13-probe"})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed: " + err.Error())
		}
		// v1.10 guard: a delivered non-2xx is a COMPLETED forward dispatch.
		// Advance MUST still return 200 {advanced:true}.
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("v1.10 drift: advance status=%d, want 200 (handler non-2xx is a completed forward dispatch)", respData.Status))
		}

		// Walk the chain-errors/lost/{chain_id}/{step_index}/{reason}/{marker_hash}
		// subtree (v1.20 path scheme: 4 segments under sinkPrefix) for a
		// freshly bound chain-error-lost entity. The path's exact chain_id
		// and step_index vary across impls but the leaf is always a
		// content-addressed marker hash, so we recurse to a fixed depth
		// rather than predict the intermediate segments.
		var marker types.ChainErrorLostData
		var markerPath string
		found := false
		// Recurse to depth 4 (chain / step / reason / marker_hash). Each
		// level may have multiple siblings; first matching ChainErrorLost
		// entity wins. Polling — most impls bind synchronously, but tree-
		// event fan-out could surface the listing slightly delayed.
		var walk func(prefix string, depth int) bool
		walk = func(prefix string, depth int) bool {
			if depth == 0 {
				if _, was := beforeEntries[prefix]; was {
					return false
				}
				ent, _, gerr := client.TreeGet(ctx, prefix)
				if gerr != nil {
					return false
				}
				if ent.Type != types.TypeChainErrorLost {
					return false
				}
				var md types.ChainErrorLostData
				if derr := ecf.Decode(ent.Data, &md); derr != nil {
					return false
				}
				marker = md
				markerPath = prefix
				return true
			}
			entries, _, err := client.TreeListing(ctx, prefix+"/")
			if err != nil {
				return false
			}
			for seg := range entries {
				if walk(prefix+"/"+seg, depth-1) {
					return true
				}
			}
			return false
		}
		for i := 0; i < 10 && !found; i++ {
			entries, _, _ := client.TreeListing(ctx, sinkPrefix)
			for chainSeg := range entries {
				if walk(sinkPrefix+chainSeg, 3) {
					found = true
					break
				}
			}
			if !found {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !found {
			return WarnCheck("no chain-error-lost marker observed under " + sinkPrefix + " (v1.13 is SHOULD-bind — peer may not yet have absorbed the amendment)")
		}
		// v1.19 §3.10.5: {reason} IS result.data.code verbatim. The catch-
		// all ChainErrorLostReasonForwardDispatchNon2xx (v1.13) was
		// superseded by the verbatim-code rule. Accept any non-empty
		// reason — the marker exists and carries a code from the dispatch
		// failure, which is the SHOULD-bind conformance.
		if marker.Reason == "" {
			return FailCheck(fmt.Sprintf("marker at %s has empty reason (v1.19 §3.10.5 requires {reason}=result.data.code verbatim)", markerPath))
		}
		return PassCheck(fmt.Sprintf("v1.13/v1.19 marker bound at %s (reason=%s status=%d)", markerPath, marker.Reason, marker.OriginalStatus))
	})

	// --- Step 10: result_transform ---

	// transform_extract / transform_select — rebuilt as side-effect
	// readbacks (were status-200-only, structurally blind: advanceForward
	// discards the dispatched response per v1.10 §3.4, so 200 cannot
	// distinguish "applied the transform" from "ignored it"). Same pattern
	// as transform_ops_apply: the transform narrows/builds a value, the
	// dispatch is steered to a path via resource_extract, the dispatch cap
	// is scoped only to that post-transform prefix, and the path is
	// TreeListing'd as the sole oracle. A peer that doesn't apply the
	// transform navigates `target`/`dst` against the un-narrowed value →
	// nil → static fallback (a wildcard, not a real path) → nothing under
	// the observable prefix → FAIL.
	r.Run("transform_extract", func() CheckOutcome {
		contPath := "system/inbox/validate-transform-extract"
		prefix := "system/validate/extract-mirror"
		landed := prefix + "/leaf-9"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(landed, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/inbox", string(client.RemotePeerID())),
			Operation: "receive",
			Resource:  &types.ResourceTarget{Targets: []string{prefix + "/*"}},
			ResultTransform: &types.ContinuationTransformData{
				Extract:         "wrap",
				ResourceExtract: "target",
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install extract continuation: " + err.Error())
		}
		// extract "wrap" -> {target: landed}; resource_extract "target"
		// steers the dispatched receive to `landed`. Without extract,
		// navigate(value,"target") on the full result is nil -> static
		// wildcard fallback -> nothing lands under `landed`.
		resultData, _ := ecf.Encode(map[string]interface{}{
			"wrap":  map[string]interface{}{"target": landed},
			"noise": "ignored",
		})
		if _, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil); err != nil {
			return FailCheck("advance with extract transform failed: " + err.Error())
		}
		if entries, _, err := client.TreeListing(ctx, landed+"/"); err == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("extract applied end-to-end: receive landed under %s", landed))
		}
		return FailCheck(fmt.Sprintf("extract NOT observable: nothing under %s — `extract` not applied (value not narrowed, so resource_extract could not resolve `target`)", landed))
	})

	r.Run("transform_select", func() CheckOutcome {
		contPath := "system/inbox/validate-transform-select"
		prefix := "system/validate/select-mirror"
		landed := prefix + "/leaf-3"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(landed, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/inbox", string(client.RemotePeerID())),
			Operation: "receive",
			Resource:  &types.ResourceTarget{Targets: []string{prefix + "/*"}},
			ResultTransform: &types.ContinuationTransformData{
				Select:          map[string]string{"dst": "info.path"},
				ResourceExtract: "dst",
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install select continuation: " + err.Error())
		}
		// select builds {dst: landed} from info.path; resource_extract
		// "dst" steers the receive there. Without select,
		// navigate(value,"dst") on the full result is nil -> static
		// wildcard fallback -> nothing lands.
		resultData, _ := ecf.Encode(map[string]interface{}{
			"info":    map[string]interface{}{"path": landed},
			"metrics": map[string]interface{}{"score": 95},
		})
		if _, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil); err != nil {
			return FailCheck("advance with select transform failed: " + err.Error())
		}
		if entries, _, err := client.TreeListing(ctx, landed+"/"); err == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("select applied end-to-end: receive landed under %s", landed))
		}
		return FailCheck(fmt.Sprintf("select NOT observable: nothing under %s — `select` not applied (selected map not produced, so resource_extract could not resolve `dst`)", landed))
	})

	// transform_ops (EXTENSION-CONTINUATION v1.9 G1, §2.2). Conformant-now:
	// the bounded field-op set is spec-pinned and not gated on the V-1
	// proof. Two checks: ops actually run end-to-end (a side-effect
	// readback — NOT a status-200 check; forward advance returns 200
	// regardless of the dispatched EXECUTE's outcome, so a 200-only check
	// cannot distinguish "applied the op" from "ignored the unknown
	// field"), and an unrecognized op is rejected fail-closed at install
	// (the §8.1 MUST — never silently skipped).
	r.Run("transform_ops_apply", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-transform-ops"
		// The continuation rewrites the dispatched receive path via
		// strip_prefix+prepend, then resource_extract drives the dispatch
		// to that rewritten path. inbox.receive (no continuation there)
		// stores the message under {rewritten}/… — observable. If the peer
		// ignores transform_ops, the path stays at the source and the
		// rewritten prefix is empty. The dispatch cap is scoped to the
		// rewritten prefix so a non-applying peer is also auth-denied at
		// the source path — the readback is the sole oracle either way.
		rewrittenPrefix := "system/validate/tops-mirror"
		rewrittenPath := rewrittenPrefix + "/item-7"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(rewrittenPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation: "receive",
			// Static fallback + cap scope (installContinuationFromData
			// scopes the auto-cap to these): only the rewritten prefix.
			Resource: &types.ResourceTarget{Targets: []string{rewrittenPrefix + "/*"}},
			ResultTransform: &types.ContinuationTransformData{
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "strip_prefix", Field: "dst", Prefix: "raw/in/"},
					{Op: "prepend", Field: "dst", Literal: rewrittenPrefix + "/"},
				},
				ResourceExtract: "dst",
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("failed to install transform_ops continuation: " + err.Error())
		}
		// dst "raw/in/item-7" --strip_prefix--> "item-7" --prepend-->
		// "system/validate/tops-mirror/item-7" == rewrittenPath.
		resultData, _ := ecf.Encode(map[string]interface{}{
			"dst":     "raw/in/item-7",
			"payload": "transform-ops-probe",
		})
		if _, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil); err != nil {
			return FailCheck("advance with transform_ops failed: " + err.Error())
		}
		// The oracle: did the message land at the OPS-REWRITTEN path?
		entries, _, err := client.TreeListing(ctx, rewrittenPath+"/")
		if err == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("transform_ops applied end-to-end: receive landed under %s (strip_prefix+prepend ran, resource_extract used the rewritten value)", rewrittenPath))
		}
		// Diagnose: did it land at the un-rewritten source path instead?
		if src, _, e2 := client.TreeListing(ctx, "raw/in/item-7/"); e2 == nil && len(src) > 0 {
			return FailCheck("transform_ops NOT applied: the message landed at the source path raw/in/item-7 (ops field ignored — path was not rewritten)")
		}
		return FailCheck(fmt.Sprintf("transform_ops NOT observable: nothing under the rewritten prefix %s (ops not applied, or resource_extract not honored)", rewrittenPath))
	})

	r.Run("transform_ops_unknown_rejected", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/continuation/validate-transform-ops-unknown"
		defer cleanupPath(contPath, ctx, client)

		dispatchCap, dispatchSig, err := client.CreateDispatchCapability(
			[]string{"system/inbox"},
			[]string{"system/inbox/validate-tops-unknown-target"},
			[]string{"receive"},
		)
		if err != nil {
			return FailCheck("create dispatch cap: " + err.Error())
		}
		contEnt, err := types.ContinuationData{
			Target:             fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:          "receive",
			Resource:           &types.ResourceTarget{Targets: []string{"system/inbox/validate-tops-unknown-target"}},
			DispatchCapability: dispatchCap.ContentHash,
			ResultTransform: &types.ContinuationTransformData{
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "exec_shell", Field: "x"}, // not in the closed §2.2 op set
				},
			},
		}.ToEntity()
		if err != nil {
			return FailCheck("build continuation entity: " + err.Error())
		}
		extras := map[hash.Hash]entity.Entity{
			dispatchCap.ContentHash: dispatchCap,
			dispatchSig.ContentHash: dispatchSig,
		}
		env, _, sendErr := client.SendInstall(ctx, contPath, contEnt, extras)
		if sendErr != nil {
			return FailCheck("send install: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		// The §2.2/§8.1 MUST is "rejected at install (fail-closed), never
		// silently skipped" — that is what is asserted. Success = the op was
		// silently accepted/skipped = the actual violation.
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf("install with unrecognized transform_ops op MUST be rejected fail-closed (§2.2/§8.1); got success status=%d (op silently skipped)", respData.Status))
		}
		if respData.Status < 400 || respData.Status >= 500 {
			return FailCheck(fmt.Sprintf("install rejected but with non-4xx status=%d; expected a 4xx client rejection (fail-closed)", respData.Status))
		}
		code, derr := decodeResultErrorCode(respData)
		if derr != nil {
			return FailCheck(fmt.Sprintf("install rejected status=%d but error code unreadable: %v", respData.Status, derr))
		}
		// v1.10 PINS the code: EXTENSION-CONTINUATION §2.2 + §8.1 —
		// "reject ... with status 400 unknown_transform_op (the error-code
		// string is pinned for cross-impl conformance assertions)". Was a
		// WARN while unpinned; now a hard FAIL — a divergent code is a v1.10
		// non-conformance, not cosmetic.
		if respData.Status == 400 && code == "unknown_transform_op" {
			return PassCheck("install with unrecognized transform_ops op rejected 400 unknown_transform_op (fail-closed, v1.10-pinned)")
		}
		return FailCheck(fmt.Sprintf("fail-closed correctly (status=%d, op not silently skipped) but error code=%q — v1.10 §2.2/§8.1 PINS this to `400 unknown_transform_op` for cross-impl agreement; divergent spelling is non-conformant", respData.Status, code))
	})

	// EXTENSION-CONTINUATION v1.17 §2.2 deref_included diagnostic checks.
	// The op resolves m[field] (a system/hash) to the entity at that hash
	// in the envelope's `included` map. Closes the plain-continuation-chain
	// gap in the convergent-mirror recipe (DOUBTS §9b). Two checks: the op
	// actually resolves end-to-end (the resolved entity reaches the
	// dispatched target), and a miss is a no-op (per the §2.2 best-effort
	// totality contract — never an error). End-to-end coverage of the
	// recipe lives in the multi-peer convergent_mirror category; these
	// pinpoint feature presence on a single peer as Rust/Python land v1.17.
	r.Run("deref_included_resolves", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-deref-included"
		targetPath := "system/validate/deref-included/resolved"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation: "put",
			Resource:  &types.ResourceTarget{Targets: []string{targetPath}},
			ResultTransform: &types.ContinuationTransformData{
				Select: map[string]string{
					"entity": "hash", // pick advance.result.hash → put.entity (still a hash ref)
				},
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "deref_included", Field: "entity"}, // hash → entity bytes via envelope.included
				},
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("install deref_included continuation: " + err.Error())
		}

		// Build a probe entity; this is what we expect deref_included to
		// resolve from the envelope's included map and what tree:put binds.
		probeData, _ := ecf.Encode(map[string]string{"v": "deref-included-probe"})
		probe, err := entity.NewEntity("system/validate/deref-probe", cbor.RawMessage(probeData))
		if err != nil {
			return FailCheck("build probe entity: " + err.Error())
		}

		// Advance result: {hash: <probe.hash>}. The included extras carry
		// the probe entity keyed by its content hash.
		resultPayload, _ := ecf.Encode(map[string]interface{}{
			"hash": probe.ContentHash,
		})
		extras := map[hash.Hash]entity.Entity{
			probe.ContentHash: probe,
		}
		env, _, err := client.SendAdvanceWithIncluded(ctx, contPath, cbor.RawMessage(resultPayload), nil, extras)
		if err != nil {
			return FailCheck("advance with included extras: " + err.Error())
		}
		if respData, _ := types.ExecuteResponseDataFromEntity(env.Root); respData.Status != 200 {
			return FailCheck(fmt.Sprintf("advance returned status %d (expected 200)", respData.Status))
		}

		// Observe: the dispatched tree:put bound the resolved entity at
		// targetPath. Hash equality is the deref_included oracle —
		// anything other than probe.ContentHash means the op was not
		// applied (or applied but discarded the resolved bytes).
		bound, _, err := client.TreeGet(ctx, targetPath)
		if err != nil {
			return FailCheck("tree:get at target path failed (dispatched put did not bind): " + err.Error())
		}
		if bound.ContentHash != probe.ContentHash {
			return FailCheck(fmt.Sprintf("target binding hash=%s but probe hash=%s — deref_included did not resolve the hash to the included entity",
				bound.ContentHash, probe.ContentHash))
		}
		return PassCheck("deref_included resolved hash to included entity end-to-end (target bound with probe hash)")
	})

	r.Run("deref_included_miss_noop", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-deref-included-miss"
		targetPath := "system/validate/deref-included/miss"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation: "put",
			Resource:  &types.ResourceTarget{Targets: []string{targetPath}},
			ResultTransform: &types.ContinuationTransformData{
				Select: map[string]string{"entity": "hash"},
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "deref_included", Field: "entity"},
				},
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("install deref_included continuation: " + err.Error())
		}

		// Build a probe entity but DON'T pass it in included extras. The
		// hash will appear unresolved at deref_included time → no-op per
		// §2.2 best-effort totality.
		probeData, _ := ecf.Encode(map[string]string{"v": "miss-probe"})
		probe, err := entity.NewEntity("system/validate/deref-probe", cbor.RawMessage(probeData))
		if err != nil {
			return FailCheck("build probe entity: " + err.Error())
		}
		resultPayload, _ := ecf.Encode(map[string]interface{}{
			"hash": probe.ContentHash,
		})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultPayload), nil)
		if err != nil {
			return FailCheck("advance without included: " + err.Error())
		}
		// The advance itself must succeed — the transform is best-effort
		// total; an unresolved hash is a documented no-op, never an error.
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("advance returned status %d (expected 200; deref_included miss MUST be a no-op per §2.2)", respData.Status))
		}
		// Diagnostic-only secondary observation: target should NOT have a
		// binding matching the probe (the dispatched tree:put received the
		// raw hash bytes, not the entity, so the bind either failed or
		// bound something unrelated). We don't fail on this — the §2.2
		// contract is about advance status, not downstream outcome.
		return PassCheck("deref_included miss handled as no-op (advance returned 200; §2.2 best-effort totality preserved)")
	})

	// V7 §3.3 v7.51 request-side envelope-`included` preservation:
	// the EXECUTE envelope's `included` map MUST be preserved across
	// every dispatch surface so handlers and downstream continuations
	// resolve bundled hash-refs consistently. The DOUBTS §7 bug was
	// Go's DispatchLocalEnvelope dropping `included` before remote
	// dispatch — single-peer can't exercise that exact wire boundary,
	// but the surface chain wire-EXECUTE → handler → continuation
	// engine → transform IS observable here.
	//
	// Topology: install a deref_included-bearing continuation at an
	// inbox path. Trigger it via inbox.receive (NOT via a direct
	// advance EXECUTE — that's the deref_included_resolves surface).
	// The wire envelope's included must travel: wire → inbox.receive
	// hctx → engine.transform.applyTransformOpsWithIncluded. If any
	// hop drops it, deref_included sees an empty included and no-ops,
	// the dispatched tree:put binds the raw hash bytes (not the
	// resolved entity), and the target binding hash diverges from the
	// probe hash. Pinpoints "which surface is dropping included" for
	// Rust/Python triage as they land v7.51.
	r.Run("request_side_included_preserved", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/inbox/validate-v751-preserve"
		targetPath := "system/validate/v751-preserve/resolved"
		defer cleanupPath(contPath, ctx, client)
		defer cleanupPath(targetPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/tree", peerID),
			Operation: "put",
			Resource:  &types.ResourceTarget{Targets: []string{targetPath}},
			ResultTransform: &types.ContinuationTransformData{
				Select: map[string]string{"entity": "hash"},
				TransformOps: []types.ContinuationTransformOpData{
					{Op: "deref_included", Field: "entity"},
				},
			},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("install continuation: " + err.Error())
		}

		probeData, _ := ecf.Encode(map[string]string{"v": "v751-preserve-probe"})
		probe, err := entity.NewEntity("system/validate/v751-probe", cbor.RawMessage(probeData))
		if err != nil {
			return FailCheck("build probe entity: " + err.Error())
		}

		// The message itself carries {hash: probeHash} so the
		// continuation's Select picks `hash` for entity and the
		// deref_included op looks it up from the wire envelope's
		// included. The probe is bundled in included extras — exactly
		// the v3.14 include_payload shape, but driven here without a
		// subscription so the surface under test is isolated.
		msgPayload, _ := ecf.Encode(map[string]interface{}{
			"hash": probe.ContentHash,
		})
		msgEntity, err := entity.NewEntity("system/validate/v751-msg", cbor.RawMessage(msgPayload))
		if err != nil {
			return FailCheck("build message entity: " + err.Error())
		}

		inboxURI := fmt.Sprintf("entity://%s/%s", peerID, contPath)
		resource := &types.ResourceTarget{Targets: []string{contPath}}
		extras := map[hash.Hash]entity.Entity{
			probe.ContentHash: probe,
		}
		env, _, sendErr := client.SendExecuteWithIncluded(ctx, inboxURI, "receive", msgEntity, resource, extras)
		if sendErr != nil {
			return FailCheck("send inbox.receive: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("inbox.receive returned status %d (expected 200)", respData.Status))
		}

		// Async continuation may take a beat to fire. Poll briefly.
		deadline := time.Now().Add(3 * time.Second)
		var lastErr string
		var bound entity.Entity
		for time.Now().Before(deadline) {
			b, _, err := client.TreeGet(ctx, targetPath)
			if err == nil {
				bound = b
				break
			}
			lastErr = err.Error()
			time.Sleep(50 * time.Millisecond)
		}
		if bound.ContentHash.IsZero() {
			return FailCheck("target path not bound after 3s — continuation did not fire or dispatched tree:put failed (last get error: " + lastErr + ")")
		}
		if bound.ContentHash != probe.ContentHash {
			return FailCheck(fmt.Sprintf(
				"target binding hash=%s but probe hash=%s — wire envelope's included was NOT preserved across the inbox.receive → continuation engine boundary (deref_included saw empty included and no-op'd, so the dispatched put bound the raw hash bytes instead of the resolved entity)",
				bound.ContentHash, probe.ContentHash))
		}
		return PassCheck("wire envelope's included preserved across inbox.receive → continuation engine → transform (deref_included resolved end-to-end)")
	})

	// --- Step 11: Join continuation ---

	r.Run("join_write", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		joinPath := "system/inbox/validate-join-test"
		targetPath := "system/inbox/validate-join-target"

		remExec := uint64(1)
		join := types.ContinuationJoinData{
			Expected:            []string{"slot-a", "slot-b"},
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{targetPath}},
			RemainingExecutions: &remExec,
		}
		if err := installJoinFromData(ctx, client, joinPath, join); err != nil {
			return FailCheck("failed to install join continuation: " + err.Error())
		}
		return PassCheck("join continuation installed with expected=[slot-a, slot-b]")
	})

	r.Run("join_slot_a", func() CheckOutcome {
		if out, ok := r.Require("join_write"); !ok {
			return out
		}
		joinPath := "system/inbox/validate-join-test"
		slotAPath := joinPath + "/slot-a"

		resultA, _ := ecf.Encode(map[string]interface{}{"from": "a"})
		envA, _, errA := client.SendAdvance(ctx, slotAPath, cbor.RawMessage(resultA), nil)
		if errA != nil {
			return FailCheck("advance slot-a failed: " + errA.Error())
		}
		respA, _ := types.ExecuteResponseDataFromEntity(envA.Root)
		if respA.Status == 200 {
			return PassCheck("slot-a advance returned 200 (partial accumulation)")
		}
		return FailCheck(fmt.Sprintf("slot-a advance returned status %d", respA.Status))
	})

	r.Run("join_slot_b_dispatch", func() CheckOutcome {
		if out, ok := r.Require("join_slot_a"); !ok {
			return out
		}
		joinPath := "system/inbox/validate-join-test"
		slotBPath := joinPath + "/slot-b"

		resultB, _ := ecf.Encode(map[string]interface{}{"from": "b"})
		envB, _, errB := client.SendAdvance(ctx, slotBPath, cbor.RawMessage(resultB), nil)
		if errB != nil {
			return FailCheck("advance slot-b failed: " + errB.Error())
		}
		respB, _ := types.ExecuteResponseDataFromEntity(envB.Root)
		if respB.Status == 200 {
			return PassCheck("slot-b advance returned 200 (join complete → dispatch triggered)")
		}
		return FailCheck(fmt.Sprintf("slot-b advance returned status %d", respB.Status))
	})

	r.Run("join_target_received", func() CheckOutcome {
		if out, ok := r.Require("join_slot_b_dispatch"); !ok {
			return out
		}
		targetPath := "system/inbox/validate-join-target"

		time.Sleep(200 * time.Millisecond)
		entries, _, listErr := client.TreeListing(ctx, targetPath+"/")
		if listErr == nil && len(entries) > 0 {
			return PassCheck(fmt.Sprintf("join result forwarded to target (%d entries)", len(entries)))
		}
		return WarnCheck("target inbox has no entries after join completion")
	})

	r.Run("join_unexpected_slot", func() CheckOutcome {
		if out, ok := r.Require("join_write"); !ok {
			return out
		}
		peerID := string(client.RemotePeerID())
		joinPath := "system/inbox/validate-join-test"
		targetPath := "system/inbox/validate-join-target"

		// Re-create the join for error testing if it was consumed. If the
		// join is still present from a prior advance the install op will
		// short-circuit on the existing entity; tests don't require this
		// to succeed before the slot-z probe below.
		join2 := types.ContinuationJoinData{
			Expected:  []string{"slot-x", "slot-y"},
			Target:    fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation: "receive",
			Resource:  &types.ResourceTarget{Targets: []string{targetPath}},
		}
		_ = installJoinFromData(ctx, client, joinPath, join2)

		slotBadPath := joinPath + "/slot-z"
		resultBad, _ := ecf.Encode(map[string]interface{}{"from": "z"})
		envBad, _, errBad := client.SendAdvance(ctx, slotBadPath, cbor.RawMessage(resultBad), nil)
		if errBad != nil {
			return WarnCheck("unexpected slot advance: send error: " + errBad.Error())
		}
		respBad, _ := types.ExecuteResponseDataFromEntity(envBad.Root)
		if respBad.Status >= 400 {
			return PassCheck(fmt.Sprintf("unexpected slot rejected with status %d", respBad.Status))
		}
		return FailCheck(fmt.Sprintf("unexpected slot returned status %d (expected >= 400)", respBad.Status))
	})

	r.Run("join_direct_rejected", func() CheckOutcome {
		if out, ok := r.Require("join_unexpected_slot"); !ok {
			return out
		}
		joinPath := "system/inbox/validate-join-test"

		resultDirect, _ := ecf.Encode(map[string]interface{}{"direct": true})
		envDirect, _, errDirect := client.SendAdvance(ctx, joinPath, cbor.RawMessage(resultDirect), nil)
		if errDirect != nil {
			return WarnCheck("direct advance to join path: send error: " + errDirect.Error())
		}
		respDirect, _ := types.ExecuteResponseDataFromEntity(envDirect.Root)
		if respDirect.Status >= 400 {
			return PassCheck(fmt.Sprintf("direct advance to join path rejected with status %d", respDirect.Status))
		}
		return FailCheck(fmt.Sprintf("direct advance to join path returned status %d (expected >= 400)", respDirect.Status))
	})

	// Join cleanup.
	cleanupPath("system/inbox/validate-join-test", ctx, client)
	cleanupPath("system/inbox/validate-join-target", ctx, client)

	// --- Step 12: W9 — dispatch_capability enforcement ---

	r.Run("w9_rejected", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/continuation/validate-w9-no-cap"
		defer cleanupPath(contPath, ctx, client)

		// Write a continuation WITHOUT dispatch_capability.
		cont := types.ContinuationData{
			Target:    fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation: "receive",
			Resource:  &types.ResourceTarget{Targets: []string{"system/inbox/validate-w9-target"}},
			// DispatchCapability intentionally omitted — W9 says this must fail.
		}
		contEntity, err := cont.ToEntity()
		if err != nil {
			return FailCheck("failed to create continuation entity: " + err.Error())
		}
		if _, err := client.TreePut(ctx, contPath, contEntity); err != nil {
			return FailCheck("failed to write continuation: " + err.Error())
		}

		// Advance directly via continuation handler — should be rejected with 400.
		resultData, _ := ecf.Encode(map[string]interface{}{"test": "w9"})
		env, _, err := client.SendAdvance(ctx, contPath, cbor.RawMessage(resultData), nil)
		if err != nil {
			return FailCheck("advance failed to send: " + err.Error())
		}
		resp, _ := types.ExecuteResponseDataFromEntity(env.Root)
		if resp.Status == 400 {
			return PassCheck("continuation without dispatch_capability correctly rejected (400)")
		}
		if resp.Status >= 400 {
			return PassCheck(fmt.Sprintf("continuation without dispatch_capability rejected (status %d)", resp.Status))
		}
		return FailCheck(fmt.Sprintf("continuation without dispatch_capability should fail, got status %d (W9: no silent escalation)", resp.Status))
	})

	// --- Step 13: PROPOSAL-COHERENT-CAPABILITY-AUTHORITY R1 conformance ---

	// Row from §10: self-issued cap (writer is granter chain) → 200.
	r.Run("r1_install_writer_self_issued_accepted", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/continuation/validate-r1-self"
		defer cleanupPath(contPath, ctx, client)

		remExec := uint64(1)
		cont := types.ContinuationData{
			Target:              fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:           "receive",
			Resource:            &types.ResourceTarget{Targets: []string{"system/inbox/validate-r1-target"}},
			RemainingExecutions: &remExec,
		}
		if err := installContinuationFromData(ctx, client, contPath, cont); err != nil {
			return FailCheck("install with self-issued cap should succeed: " + err.Error())
		}
		return PassCheck("install accepted with writer-issued dispatch_capability (R1 chain-root pass)")
	})

	// Row from §10: adversary references a cap whose granter chain doesn't
	// include the writer → 403 embedded_cap_unauthorized. Closes Finding 3.
	r.Run("r1_install_adversary_rejected", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/continuation/validate-r1-adversary"
		defer cleanupPath(contPath, ctx, client)

		foreignCap, foreignSig, foreignID, err := client.ForeignCapability(
			[]string{"system/inbox"},
			[]string{"system/inbox/validate-r1-adv-target"},
			[]string{"receive"},
		)
		if err != nil {
			return FailCheck("build foreign cap: " + err.Error())
		}

		contEnt, err := types.ContinuationData{
			Target:             fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:          "receive",
			Resource:           &types.ResourceTarget{Targets: []string{"system/inbox/validate-r1-adv-target"}},
			DispatchCapability: foreignCap.ContentHash,
		}.ToEntity()
		if err != nil {
			return FailCheck("build continuation entity: " + err.Error())
		}
		extras := map[hash.Hash]entity.Entity{
			foreignCap.ContentHash: foreignCap,
			foreignSig.ContentHash: foreignSig,
			foreignID.ContentHash:  foreignID,
		}
		env, _, sendErr := client.SendInstall(ctx, contPath, contEnt, extras)
		if sendErr != nil {
			return FailCheck("send install: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		return requireEmbeddedCapUnauthorized(respData, "continuation install with foreign dispatch_capability")
	})

	// Row 10 from §10: same as above but for join continuation.
	r.Run("r1_install_join_adversary_rejected", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		joinPath := "system/continuation/validate-r1-join-adversary"
		defer cleanupPath(joinPath, ctx, client)

		foreignCap, foreignSig, foreignID, err := client.ForeignCapability(
			[]string{"system/inbox"},
			[]string{"system/inbox/validate-r1-join-adv-target"},
			[]string{"receive"},
		)
		if err != nil {
			return FailCheck("build foreign cap: " + err.Error())
		}

		joinEnt, err := types.ContinuationJoinData{
			Expected:           []string{"a", "b"},
			Target:             fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:          "receive",
			Resource:           &types.ResourceTarget{Targets: []string{"system/inbox/validate-r1-join-adv-target"}},
			DispatchCapability: foreignCap.ContentHash,
		}.ToEntity()
		if err != nil {
			return FailCheck("build join entity: " + err.Error())
		}
		extras := map[hash.Hash]entity.Entity{
			foreignCap.ContentHash: foreignCap,
			foreignSig.ContentHash: foreignSig,
			foreignID.ContentHash:  foreignID,
		}
		env, _, sendErr := client.SendInstall(ctx, joinPath, joinEnt, extras)
		if sendErr != nil {
			return FailCheck("send install: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		return requireEmbeddedCapUnauthorized(respData, "join continuation install with foreign dispatch_capability")
	})

	// Row from §10: dispatch_capability references a cap whose parent isn't
	// in envelope or store → 404 chain_unreachable.
	r.Run("r1_install_chain_unreachable", func() CheckOutcome {
		peerID := string(client.RemotePeerID())
		contPath := "system/continuation/validate-r1-unreach"
		defer cleanupPath(contPath, ctx, client)

		// Build a leaf cap whose parent points at a hash that's not in the envelope.
		bogusParent := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		for i := 0; i < hash.SHA256DigestSize; i++ {
			bogusParent.Digest[i] = byte(0xAB ^ i)
		}
		now := uint64(time.Now().UnixMilli())
		expires := now + uint64(time.Hour.Milliseconds())
		leafData := types.CapabilityTokenData{
			Grants: []types.GrantEntry{
				{
					Handlers:   types.CapabilityScope{Include: []string{"system/inbox"}},
					Resources:  types.CapabilityScope{Include: []string{"system/inbox/validate-r1-unreach-target"}},
					Operations: types.CapabilityScope{Include: []string{"receive"}},
				},
			},
			Granter:   types.SingleSigGranter(client.IdentityEntity().ContentHash),
			Grantee:   client.IdentityEntity().ContentHash,
			Parent:    &bogusParent,
			CreatedAt: now,
			ExpiresAt: &expires,
		}
		leaf, err := leafData.ToEntity()
		if err != nil {
			return FailCheck("build leaf cap: " + err.Error())
		}

		contEnt, err := types.ContinuationData{
			Target:             fmt.Sprintf("entity://%s/system/inbox", peerID),
			Operation:          "receive",
			Resource:           &types.ResourceTarget{Targets: []string{"system/inbox/validate-r1-unreach-target"}},
			DispatchCapability: leaf.ContentHash,
		}.ToEntity()
		if err != nil {
			return FailCheck("build continuation entity: " + err.Error())
		}
		extras := map[hash.Hash]entity.Entity{leaf.ContentHash: leaf}
		env, _, sendErr := client.SendInstall(ctx, contPath, contEnt, extras)
		if sendErr != nil {
			return FailCheck("send install: " + sendErr.Error())
		}
		respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
		// Per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE the unified walker errors
		// with ChainUnreachable BEFORE identity matching, so the install MUST
		// surface 404 chain_unreachable. Any other status — including 200,
		// 403, or 500 — indicates the implementation is short-circuiting on
		// identity match and missing the reachability check.
		if respData.Status != 404 {
			return FailCheck(fmt.Sprintf(
				"install with unreachable parent should return 404 chain_unreachable, got status %d (likely cause: chain walker short-circuits on identity match before checking reachability)",
				respData.Status))
		}
		return PassCheck("install rejected with 404 when dispatch_capability chain not fully reachable")
	})

	return r.Results()
}
