// Category: registry_issuer. Probes the EXTENSION-REGISTRY §6a.9 LIVE
// registration surface — the WRITE side of peer-issued (`register-request` /
// `revoke-request` / `renew-request`) and the §6a.9.1 issuer-policy admission
// that gates it.
//
// This is the counterpart to the `peer_issued` category, which covers the READ
// path (resolve / verify against a static fixture registry). Until 2026-08-10
// the write path had ZERO coverage while being fully built — `peer-manager`
// had no `--issuer-policy-mode` passthrough, so no check could start the
// surface even if one had existed. The absence read as "covered."
// (GUIDE-CONFORMANCE §5.2b — a rule the suite cannot reach is not a rule the
// suite has measured.)
//
// HOW ALL THREE MODES ARE REACHED AGAINST ONE PEER. A peer is started in one
// mode, but §6a.9.1 makes the policy a `system/registry/issuer-policy` ENTITY
// ("registry-local config"), and the Issuer resolves it store-first — the
// stored entity wins over the CLI fallback. So each mode is driven by writing
// the policy entity, which is the spec's own model of policy management
// (§6a.9.1 gates it with `system/capability/registry-manage-issuer-policy`)
// and additionally exercises that store-wins precedence.
//
// WHAT EACH CHECK ASSERTS, AND WHY THE NEGATIVE HALVES ARE THE POINT. A
// status-only assertion measures almost nothing here: `manual` returning 202
// while quietly publishing the binding anyway would pass a status check and be
// a total failure of the mode. So the queueing and rejecting modes assert what
// did NOT happen — no binding resolvable afterwards — not merely the code.
package validate

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
)

const catRegistryIssuer = "registry_issuer"

// issuerURI is the dispatch target for the §6a.9 handler.
func issuerURI(peerID string) string {
	return "entity://" + peerID + "/" + peerissued.IssuerHandlerPattern
}

// runRegistryIssuer drives the §6a.9 write surface against the target peer.
// The peer MUST have been started with --issuer-policy-mode (any mode) so the
// handler is registered; the checks then set the policy they need.
func runRegistryIssuer(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catRegistryIssuer)
	peerID := string(client.RemotePeerID())
	uri := issuerURI(peerID)

	r.Declare("surface_registered", "§6a.9 — the peer-issued issuer handler is reachable (peer started with an issuer policy); an unregistered handler is the default-off posture, not a failure of the peer, but it means nothing below is measured")
	r.Declare("policy_open_grants", "§6a.9.1 mode=open — a layer-1-valid request is signed and published; the binding resolves afterwards")
	r.Declare("policy_allowlist_grants_listed", "§6a.9.1 mode=allowlist — a target_peer_id IN the allowlist is admitted")
	r.Declare("policy_allowlist_rejects_unlisted", "§6a.9.1 mode=allowlist — a target_peer_id NOT in the allowlist MUST be refused 403 not_entitled")
	r.Declare("policy_allowlist_unlisted_publishes_nothing", "§6a.9.1 — the negative half: a refused request MUST NOT leave a resolvable binding behind (a 403 that published anyway would pass a status-only check)")
	r.Declare("policy_manual_queues", "§6a.9.1 mode=manual — the request is accepted for review as 202 pending_review, NOT signed")
	r.Declare("policy_manual_publishes_nothing", "§6a.9.1 — the negative half of manual, and the one that matters: a 202 that quietly published the binding would satisfy a status-only assertion while defeating the entire mode")
	r.Declare("name_constraints_rejects_nonmatching", "§6a.9.1 — a name outside the policy's name_constraints glob MUST be refused 403 not_entitled")
	r.Declare("layer1_unsigned_request_rejected", "§6a.9 layer 1 — a register-request with no system/signature at its invariant pointer MUST be refused; ownership proof is the floor beneath every policy mode")
	r.Declare("revoke_request_publishes_revocation", "§6a.9 — revoke-request MUST publish a verifying revocation at the by-target index, which is the §2.1 step-4 signal a resolver excludes the binding on. Revocation is ADDITIVE: the immutable binding and its by-name pointer stay put.")
	r.Declare("renew_request_accepted", "§6a.9 — renew-request extends an existing binding's expiry")
	r.Declare("unknown_operation_rejected", "§6a.9 — an operation the issuer does not implement MUST be refused, not silently accepted")
	r.Declare("set_issuer_policy_round_trip", "§6a.9.2 — set-issuer-policy stores the policy and get-issuer-policy returns it as written. Before this ruling the capability system/capability/registry-manage-issuer-policy named an act the corpus never defined, and a client had nothing to call")
	r.Declare("set_issuer_policy_replaces_whole", "§6a.9.2 [MUST] — set replaces the policy WHOLE; an absent optional field means *unset*, not *unchanged*. A merge would make the result depend on write order, which two peers cannot reconstruct")
	r.Declare("set_issuer_policy_domain_control_rejected", "§6a.9.2 — mode \"domain-control\" MUST be refused 400 unsupported_mode and NOT stored, rather than arming a mode the issuer cannot enforce. The negative half is checked too: a 400 that stored anyway passes a status-only assertion")
	r.Declare("get_issuer_policy_unset_404", "§6a.9.2 — unset is not a mode: with no policy stored, get MUST answer 404 not_found and MUST NOT synthesize a default `open`, which would silently turn a curated registry into a first-come-first-serve one")

	// --- surface reachability -------------------------------------------

	// Probe with a deliberately malformed request: any response at all proves
	// the handler is registered. A "no such handler" answer means the peer was
	// started without an issuer policy and NOTHING below is measured — that is
	// reported once, loudly, rather than as a dozen confusing failures.
	probeStatus, probeCode, probeErr := issuerDispatch(ctx, client, uri, peerissued.OpRegisterRequest, mustCreateEntity(types.TypeRegistryRegisterRequest, map[string]any{}))

	// The surface is default-off by design (§6a.9 — a common peer is not a
	// registry), so an unarmed peer is not a failing peer. Skip the CATEGORY
	// with an actionable reason rather than emitting a dozen failures that all
	// mean "you did not start a registry". validate-complete.sh always arms
	// it, so this skip does not occur in the gate — where a skip counts as a
	// failure (ADR-0012) precisely so an unmeasured surface cannot hide here.
	//
	// BUILD-STATE NOTE (go 2026-08-10, §6a.9.2 ratified at arch ed3de7a): the
	// skip reason below describes arming as a python-only affordance. That was
	// true when written and is now the pre-ratification world — §6a.9.2 makes
	// `set-issuer-policy` the specified arming path for all three impls, so the
	// right reading of a missing handler is "not started as a registry," not
	// "this impl has no way to arm." Re-read rust and py before repeating
	// either clause; it decays on their schedule, not ours.
	if probeErr == nil && isHandlerMissing(probeStatus, probeCode) {
		return skipCategory(catRegistryIssuer, fmt.Sprintf(
			"peer has no %s handler (probe answered %d/%q) — the §6a.9 write surface is default-off. Start the peer with --issuer-policy-mode (peer-manager forwards it for Go peers). Per §6a.9.2 a peer MAY also be armed over the wire via `set-issuer-policy`, which is the cross-impl path now that the operation is ratified",
			peerissued.IssuerHandlerPattern, probeStatus, probeCode))
	}

	r.Run("surface_registered", func() CheckOutcome {
		if probeErr != nil {
			return FailCheck("dispatch to " + peerissued.IssuerHandlerPattern + ": " + probeErr.Error())
		}
		return PassCheck(fmt.Sprintf("issuer handler reachable (malformed probe answered %d/%q)", probeStatus, probeCode))
	})

	surfaceLive := probeErr == nil
	gate := func(fn func() CheckOutcome) func() CheckOutcome {
		return func() CheckOutcome {
			if !surfaceLive {
				return FailCheck("issuer handler not reachable — see surface_registered")
			}
			return fn()
		}
	}

	// --- mode: open -------------------------------------------------------

	r.Run("policy_open_grants", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("open")
		status, code, err := issuerRegister(ctx, client, uri, name)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("mode=open register-request → %d/%q, want 200 (a layer-1-valid request is signed first-come-first-serve)", status, code))
		}
		bound, err := issuerNameResolves(ctx, client, name)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if !bound {
			return FailCheck("mode=open returned 200 but no binding is bound at " + types.PeerIssuedByNamePath(name) + " — the registry claimed to issue and did not")
		}
		return PassCheck("mode=open signed + published the binding, and it resolves")
	}))

	// --- mode: allowlist --------------------------------------------------

	selfPeerID := string(client.LocalPeerID())

	r.Run("policy_allowlist_grants_listed", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{
			Mode:      types.IssuerPolicyModeAllowlist,
			Allowlist: []string{selfPeerID},
		}); out != nil {
			return *out
		}
		name := issuerName("allowed")
		status, code, err := issuerRegister(ctx, client, uri, name)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("allowlisted target → %d/%q, want 200", status, code))
		}
		return PassCheck("allowlisted target_peer_id admitted")
	}))

	// The refusal arm needs the validator OUT of the allowlist. It cannot be
	// driven by naming a different target_peer_id: layer 1 would reject that
	// first (401, no ownership proof), and the check would pass for the wrong
	// reason — measuring the signature floor instead of the admission gate.
	unlistedName := issuerName("unlisted")
	r.Run("policy_allowlist_rejects_unlisted", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{
			Mode:      types.IssuerPolicyModeAllowlist,
			Allowlist: []string{"2KotherPeerNotThisValidator"},
		}); out != nil {
			return *out
		}
		status, code, err := issuerRegister(ctx, client, uri, unlistedName)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status == 401 {
			return FailCheck("got 401 — layer-1 ownership proof failed, so this measured the signature floor, not the allowlist gate")
		}
		if status != 403 || code != types.RegistryErrNotEntitled {
			return FailCheck(fmt.Sprintf("unlisted target → %d/%q, want 403/%s", status, code, types.RegistryErrNotEntitled))
		}
		return PassCheck("unlisted target_peer_id refused 403 not_entitled")
	}))

	r.Run("policy_allowlist_unlisted_publishes_nothing", gate(func() CheckOutcome {
		if out, ok := r.Require("policy_allowlist_rejects_unlisted"); !ok {
			return out
		}
		bound, err := issuerNameResolves(ctx, client, unlistedName)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if bound {
			return FailCheck("a 403 not_entitled request left a resolvable binding at " + types.PeerIssuedByNamePath(unlistedName) + " — the refusal was cosmetic")
		}
		return PassCheck("refused request published nothing")
	}))

	// --- mode: manual -----------------------------------------------------

	manualName := issuerName("manual")
	r.Run("policy_manual_queues", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual}); out != nil {
			return *out
		}
		status, code, err := issuerRegister(ctx, client, uri, manualName)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 202 {
			return FailCheck(fmt.Sprintf("mode=manual → %d/%q, want 202 pending_review", status, code))
		}
		return PassCheck("mode=manual queued the request as 202 pending_review")
	}))

	r.Run("policy_manual_publishes_nothing", gate(func() CheckOutcome {
		if out, ok := r.Require("policy_manual_queues"); !ok {
			return out
		}
		bound, err := issuerNameResolves(ctx, client, manualName)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if bound {
			return FailCheck("mode=manual returned 202 pending_review AND published a binding at " + types.PeerIssuedByNamePath(manualName) + " — operator review is bypassed; the mode does nothing")
		}
		return PassCheck("mode=manual published nothing pending review")
	}))

	// --- name_constraints -------------------------------------------------

	r.Run("name_constraints_rejects_nonmatching", gate(func() CheckOutcome {
		glob := "*.lab"
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{
			Mode:            types.IssuerPolicyModeOpen,
			NameConstraints: &glob,
		}); out != nil {
			return *out
		}
		status, code, err := issuerRegister(ctx, client, uri, issuerName("nomatch")+".example")
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 403 || code != types.RegistryErrNotEntitled {
			return FailCheck(fmt.Sprintf("name outside name_constraints %q → %d/%q, want 403/%s", glob, status, code, types.RegistryErrNotEntitled))
		}
		return PassCheck("name outside name_constraints refused 403 not_entitled")
	}))

	// --- layer 1 ----------------------------------------------------------

	r.Run("layer1_unsigned_request_rejected", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		// Build the request but deliberately do NOT publish its signature.
		reqEnt, err := buildRegisterRequest(client, issuerName("unsigned"))
		if err != nil {
			return FailCheck("build register-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpRegisterRequest, reqEnt)
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if status == 200 {
			return FailCheck("an UNSIGNED register-request was issued a binding — §6a.9 layer 1 is not enforced, so anyone can claim any name for any peer")
		}
		if status != 401 {
			return FailCheck(fmt.Sprintf("unsigned request → %d/%q, want 401 (ownership proof missing)", status, code))
		}
		return PassCheck("unsigned register-request refused 401")
	}))

	// --- revoke / renew ---------------------------------------------------

	r.Run("revoke_request_publishes_revocation", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("revoke")
		status, code, bindingHash, err := issuerRegisterBound(ctx, client, uri, name)
		if err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("setup: register %q → %d/%q err=%v", name, status, code, err))
		}
		revEnt, err := types.RegistryRevokeRequestData{BindingHash: bindingHash}.ToEntity()
		if err != nil {
			return FailCheck("build revoke-request: " + err.Error())
		}
		revStatus, revCode, err := issuerDispatch(ctx, client, uri, peerissued.OpRevokeRequest, revEnt)
		if err != nil {
			return FailCheck("revoke-request: " + err.Error())
		}
		if revStatus != 200 && revStatus != 202 {
			return FailCheck(fmt.Sprintf("revoke-request → %d/%q, want 200 or 202", revStatus, revCode))
		}
		// The observable is the BY-TARGET REVOCATION INDEX, not the
		// disappearance of the by-name pointer. §6a.9 revocation is additive:
		// the binding entity and its by-name pointer are immutable and stay
		// put; what changes is that a §2.1 step-4 resolver finds a verifying
		// revocation at by-target and excludes the binding. Asserting that the
		// name stops resolving in the REGISTRY's own tree asserts a deletion
		// the model never performs — this check failed for exactly that reason
		// before being corrected.
		revPath := types.PeerIssuedRevocationByTargetPath(bindingHash)
		revoked, err := issuerPathBound(ctx, client, revPath)
		if err != nil {
			return FailCheck("read back revocation by-target index: " + err.Error())
		}
		if !revoked {
			return FailCheck(fmt.Sprintf("revoke-request answered %d but nothing is bound at %s — a revocation that publishes no revocation is invisible to every resolver", revStatus, revPath))
		}
		return PassCheck("revoke-request published a revocation at the by-target index (the read path's §2.1 step-4 exclusion signal)")
	}))

	r.Run("renew_request_accepted", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("renew")
		status, code, bindingHash, err := issuerRegisterBound(ctx, client, uri, name)
		if err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("setup: register %q → %d/%q err=%v", name, status, code, err))
		}
		renewEnt, err := types.RegistryRenewRequestData{
			BindingHash: bindingHash,
			Nonce:       issuerNonce(),
			IssuedAt:    uint64(time.Now().UnixMilli()),
		}.ToEntity()
		if err != nil {
			return FailCheck("build renew-request: " + err.Error())
		}
		renewStatus, renewCode, err := issuerDispatch(ctx, client, uri, peerissued.OpRenewRequest, renewEnt)
		if err != nil {
			return FailCheck("renew-request: " + err.Error())
		}
		if renewStatus != 200 && renewStatus != 202 {
			return FailCheck(fmt.Sprintf("renew-request → %d/%q, want 200 or 202", renewStatus, renewCode))
		}
		bound, err := issuerNameResolves(ctx, client, name)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if !bound {
			return FailCheck("renew-request answered " + fmt.Sprint(renewStatus) + " but the binding no longer resolves — renew MUST extend, not drop")
		}
		return PassCheck(fmt.Sprintf("renew-request accepted (%d) and the binding still resolves", renewStatus))
	}))

	r.Run("unknown_operation_rejected", gate(func() CheckOutcome {
		status, code, err := issuerDispatch(ctx, client, uri, "definitely-not-an-issuer-op",
			mustCreateEntity(types.TypeRegistryRegisterRequest, map[string]any{}))
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if status < 400 {
			return FailCheck(fmt.Sprintf("unknown operation answered %d/%q — an unimplemented op MUST be refused", status, code))
		}
		return PassCheck(fmt.Sprintf("unknown operation refused %d/%q", status, code))
	}))

	// --- §6a.9.2 policy management ---------------------------------------
	//
	// Run LAST and deliberately so: these rewrite the issuer-policy entity,
	// including removing it, and every check above selects its mode by
	// writing that same entity. Ordering them earlier would hand the mode
	// checks a policy they did not set.

	r.Run("set_issuer_policy_round_trip", gate(func() CheckOutcome {
		ttl := uint64(3_600_000)
		want := types.IssuerPolicyData{
			Mode:       types.IssuerPolicyModeAllowlist,
			Allowlist:  []string{string(client.LocalPeerID())},
			DefaultTTL: &ttl,
		}
		ent, err := want.ToEntity()
		if err != nil {
			return FailCheck("build issuer-policy: " + err.Error())
		}
		setStatus, setCode, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, ent)
		if err != nil {
			return FailCheck("set-issuer-policy dispatch: " + err.Error())
		}
		if setStatus != 200 {
			return FailCheck(fmt.Sprintf("set-issuer-policy answered %d/%q (want 200) — §6a.9.2 ratified this operation", setStatus, setCode))
		}
		getStatus, getCode, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpGetIssuerPolicy, issuerNoParams())
		if err != nil {
			return FailCheck("get-issuer-policy dispatch: " + err.Error())
		}
		if getStatus != 200 {
			return FailCheck(fmt.Sprintf("get-issuer-policy answered %d/%q after a successful set (want 200)", getStatus, getCode))
		}
		got, err := issuerPolicyFromResponse(resp)
		if err != nil {
			return FailCheck("decode returned policy: " + err.Error())
		}
		if got.Mode != want.Mode {
			return FailCheck(fmt.Sprintf("get returned mode %q, set wrote %q — §6a.9.2 output is the stored policy as written", got.Mode, want.Mode))
		}
		if got.DefaultTTL == nil || *got.DefaultTTL != ttl {
			return FailCheck("get lost default_ttl — the round-trip is not returning the policy as written")
		}
		return PassCheck(fmt.Sprintf("set-issuer-policy (%s) round-trips through get-issuer-policy", want.Mode))
	}))

	r.Run("set_issuer_policy_replaces_whole", gate(func() CheckOutcome {
		// Previous check left mode=allowlist WITH default_ttl and a
		// non-empty allowlist. Write mode=open carrying neither.
		bare, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}.ToEntity()
		if err != nil {
			return FailCheck("build issuer-policy: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, bare)
		if err != nil {
			return FailCheck("set-issuer-policy dispatch: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("set-issuer-policy answered %d/%q (want 200)", status, code))
		}
		getStatus, _, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpGetIssuerPolicy, issuerNoParams())
		if err != nil || getStatus != 200 {
			return FailCheck(fmt.Sprintf("get-issuer-policy after replace answered %d (err=%v)", getStatus, err))
		}
		got, err := issuerPolicyFromResponse(resp)
		if err != nil {
			return FailCheck("decode returned policy: " + err.Error())
		}
		if len(got.Allowlist) != 0 {
			return FailCheck(fmt.Sprintf("allowlist %v survived a whole-replace — §6a.9.2 [MUST] an absent optional field is *unset*, not *unchanged*; this is merge semantics", got.Allowlist))
		}
		if got.DefaultTTL != nil {
			return FailCheck(fmt.Sprintf("default_ttl %d survived a whole-replace — this is merge semantics", *got.DefaultTTL))
		}
		return PassCheck("set-issuer-policy replaces the policy whole; absent optional fields are unset")
	}))

	r.Run("set_issuer_policy_domain_control_rejected", gate(func() CheckOutcome {
		ent, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeDomainControl}.ToEntity()
		if err != nil {
			return FailCheck("build issuer-policy: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, ent)
		if err != nil {
			return FailCheck("set-issuer-policy dispatch: " + err.Error())
		}
		if status != 400 || code != types.RegistryErrUnsupportedMode {
			return FailCheck(fmt.Sprintf("domain-control set answered %d/%q — §6a.9.2 requires 400/%q, refusing to store a policy it cannot enforce", status, code, types.RegistryErrUnsupportedMode))
		}
		// The negative half: refusing must not have armed it anyway.
		getStatus, _, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpGetIssuerPolicy, issuerNoParams())
		if err != nil {
			return FailCheck("get-issuer-policy after rejection: " + err.Error())
		}
		if getStatus == 200 {
			if got, derr := issuerPolicyFromResponse(resp); derr == nil && got.Mode == types.IssuerPolicyModeDomainControl {
				return FailCheck("domain-control was refused 400 but stored anyway — a status-only check would have passed this")
			}
		}
		return PassCheck(fmt.Sprintf("domain-control refused %d/%q and not stored", status, code))
	}))

	r.Run("get_issuer_policy_unset_404", gate(func() CheckOutcome {
		// Destructive by necessity — "unset" is only observable with the
		// entity gone. Runs last in the category and re-arms afterwards so a
		// long-lived peer is left usable.
		if _, err := client.TreeRemove(ctx, types.IssuerPolicyStoragePath); err != nil {
			return SkipCheck("cannot remove the issuer-policy entity to observe the unset state: " + err.Error())
		}
		status, code, _, err := issuerDispatchFull(ctx, client, uri, peerissued.OpGetIssuerPolicy, issuerNoParams())
		// Re-arm before judging, so a failure does not also leave the peer
		// disarmed for whatever runs next.
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		if err != nil {
			return FailCheck("get-issuer-policy dispatch: " + err.Error())
		}
		if status == 200 {
			return FailCheck("get-issuer-policy answered 200 with no policy stored — §6a.9.2 forbids synthesizing a default `open`, which silently turns a curated registry into first-come-first-serve")
		}
		if status != 404 || code != types.RegistryErrNotFound {
			return FailCheck(fmt.Sprintf("get-issuer-policy on an unset registry answered %d/%q — §6a.9.2 requires 404/%q", status, code, types.RegistryErrNotFound))
		}
		return PassCheck("get-issuer-policy returns 404 not_found when unset; unset is not a mode")
	}))

	return r.Results()
}

// --- helpers ------------------------------------------------------------

// issuerNoParams is the params entity for §6a.9.2's `get-issuer-policy`,
// which takes no input.
//
// "No input" still needs an entity on the wire: an EXECUTE carries a params
// entity, and a zero-value one is refused 400 invalid_params before it ever
// reaches the handler. The cohort convention for an input-less operation is
// an empty `primitive/map` — the same shape clockExecute sends for
// `system/clock:now`. Learned from a live peer; the unit tests call Handle
// directly and never cross the envelope layer, so they could not see it.
func issuerNoParams() entity.Entity {
	raw, _ := ecf.Encode(map[string]interface{}{})
	ent, _ := entity.NewEntity("primitive/map", cbor.RawMessage(raw))
	return ent
}

// issuerPolicyFromResponse decodes the §6a.9.2 get/set result body into an
// IssuerPolicyData. The EXECUTE_RESPONSE `result` is a CBOR-encoded entity,
// so this is a two-step decode: envelope result → entity → policy data.
func issuerPolicyFromResponse(resp types.ExecuteResponseData) (types.IssuerPolicyData, error) {
	var ent entity.Entity
	if err := ecf.Decode(resp.Result, &ent); err != nil {
		return types.IssuerPolicyData{}, fmt.Errorf("decode result entity: %w", err)
	}
	if ent.Type != types.TypeRegistryIssuerPolicy {
		return types.IssuerPolicyData{}, fmt.Errorf("result type is %q, want %q", ent.Type, types.TypeRegistryIssuerPolicy)
	}
	return types.IssuerPolicyDataFromEntity(ent)
}

// issuerNameCounter keeps each check on its own name. Checks sharing one name
// is the trap the peer_issued fixture loader already refuses: a later check
// then measures an earlier check's leftovers (409 name_taken) instead of the
// policy arm it meant to probe.
var issuerNameCounter int

// issuerRunTag makes names unique per VALIDATOR RUN, not just per check.
// Registry bindings are durable, so a second run against the same long-lived
// peer would otherwise collide with its own first run and report 409
// name_taken — which reads as a peer refusing a valid registration when in
// fact the harness re-used a name it had already claimed. The gate starts
// fresh peers and would never have caught this.
var issuerRunTag = fmt.Sprintf("%x", time.Now().UnixNano())

// issuerNonce returns a fresh anti-replay nonce.
//
// Deliberately random, not derived from the clock. A nonce built from
// milliseconds-since-epoch plus a per-run counter is NOT a nonce: two runs
// landing in the same millisecond produce identical bytes and the registry
// correctly answers 409 replay_detected — which then reads as a peer bug. The
// category is fast enough (single-digit ms) that this fired routinely.
func issuerNonce() []byte {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		// crypto/rand does not fail in practice; fall back to something
		// unique-per-run rather than silently reusing a constant.
		binary.BigEndian.PutUint64(n, uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(n[8:], uint64(issuerNameCounter))
	}
	return n
}

func issuerName(kind string) string {
	issuerNameCounter++
	return fmt.Sprintf("vi-%s-%s-%d.lab", kind, issuerRunTag, issuerNameCounter)
}

// isHandlerMissing distinguishes "the issuer is not registered" from "the
// issuer refused this request". Only the former invalidates the category.
func isHandlerMissing(status uint, code string) bool {
	return status == 404 || code == "handler_not_found" || code == "not_found" || code == "unknown_handler"
}

// setIssuerPolicy writes the §6a.9.1 policy entity into the registry's tree.
// The Issuer resolves policy store-first, so this is what selects the mode
// under test. Returns nil on success, or a ready-made failing outcome.
func setIssuerPolicy(ctx context.Context, client *PeerClient, policy types.IssuerPolicyData) *CheckOutcome {
	ent, err := policy.ToEntity()
	if err != nil {
		out := FailCheck("build issuer-policy entity: " + err.Error())
		return &out
	}
	if _, err := client.TreePut(ctx, types.IssuerPolicyStoragePath, ent); err != nil {
		out := FailCheck(fmt.Sprintf("publish issuer-policy (mode=%s) at %s: %v", policy.Mode, types.IssuerPolicyStoragePath, err))
		return &out
	}
	return nil
}

// buildRegisterRequest constructs the §6a.9 request entity naming this
// validator as target_peer_id. It does NOT publish the ownership proof — see
// issuerRegister for the signed path.
func buildRegisterRequest(client *PeerClient, name string) (entity.Entity, error) {
	return types.RegistryRegisterRequestData{
		Name:         name,
		TargetPeerID: string(client.LocalPeerID()),
		Nonce:        issuerNonce(),
		IssuedAt:     uint64(time.Now().UnixMilli()),
	}.ToEntity()
}

// publishOwnershipProof signs `reqEnt`'s content_hash with the validator's key
// and binds the signature at the V7 §3.5 invariant pointer in the REGISTRY's
// tree, which is where §6a.9 layer 1 looks for it.
func publishOwnershipProof(ctx context.Context, client *PeerClient, reqEnt entity.Entity) error {
	signerHash, err := types.ComputePeerIdentityHashFromPeerID(client.LocalPeerID())
	if err != nil {
		return fmt.Errorf("compute validator identity hash: %w", err)
	}
	sigEnt, err := types.SignatureData{
		Target:    reqEnt.ContentHash,
		Signer:    signerHash,
		Algorithm: "ed25519",
		Signature: client.Keypair().Sign(reqEnt.ContentHash.Bytes()),
	}.ToEntity()
	if err != nil {
		return fmt.Errorf("build signature entity: %w", err)
	}
	if _, err := client.TreePut(ctx, types.LocalSignaturePath(reqEnt.ContentHash), sigEnt); err != nil {
		return fmt.Errorf("publish ownership proof: %w", err)
	}
	return nil
}

// issuerRegister runs the full happy-path shape: build, prove ownership,
// dispatch. Returns the issuer's status + error code.
func issuerRegister(ctx context.Context, client *PeerClient, uri, name string) (uint, string, error) {
	reqEnt, err := buildRegisterRequest(client, name)
	if err != nil {
		return 0, "", fmt.Errorf("build request: %w", err)
	}
	if err := publishOwnershipProof(ctx, client, reqEnt); err != nil {
		return 0, "", err
	}
	return issuerDispatch(ctx, client, uri, peerissued.OpRegisterRequest, reqEnt)
}

// issuerRegisterBound is issuerRegister plus the binding hash the registry
// minted, which revoke-request and renew-request address the binding BY —
// neither takes a name (§6a.9: `binding_hash`, not `name`).
func issuerRegisterBound(ctx context.Context, client *PeerClient, uri, name string) (uint, string, hash.Hash, error) {
	reqEnt, err := buildRegisterRequest(client, name)
	if err != nil {
		return 0, "", hash.Hash{}, fmt.Errorf("build request: %w", err)
	}
	if err := publishOwnershipProof(ctx, client, reqEnt); err != nil {
		return 0, "", hash.Hash{}, err
	}
	status, code, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpRegisterRequest, reqEnt)
	if err != nil || status != 200 {
		return status, code, hash.Hash{}, err
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return status, code, hash.Hash{}, fmt.Errorf("decode bind result: %w", err)
	}
	bindResult, err := types.LocalNameBindResultDataFromEntity(resultEnt)
	if err != nil {
		return status, code, hash.Hash{}, fmt.Errorf("decode binding_hash: %w", err)
	}
	return status, code, bindResult.BindingHash, nil
}

// issuerDispatch sends one EXECUTE to the issuer handler and extracts the
// status + error code.
func issuerDispatch(ctx context.Context, client *PeerClient, uri, op string, params entity.Entity) (uint, string, error) {
	status, code, _, err := issuerDispatchFull(ctx, client, uri, op, params)
	return status, code, err
}

// issuerDispatchFull additionally returns the decoded response so a caller can
// read the result body (e.g. the minted binding_hash).
func issuerDispatchFull(ctx context.Context, client *PeerClient, uri, op string, params entity.Entity) (uint, string, types.ExecuteResponseData, error) {
	respEnv, _, err := client.SendExecute(ctx, uri, op, params, nil)
	if err != nil {
		return 0, "", types.ExecuteResponseData{}, err
	}
	return extractStatusAndCode(respEnv)
}

// issuerNameResolves reports whether the registry currently binds `name` in
// its by-name index — the observable that distinguishes "issued" from
// "claimed to issue", and the one every negative half asserts against.
//
// Deliberately not routed through client.TreeGet: that folds a 404 into a
// generic error, and "the name is absent" is exactly the signal here, so it
// must be told apart from a transport failure. A 404 is the answer, not a
// problem; anything else unexpected is surfaced as an error so an unreadable
// tree cannot masquerade as a passing negative assertion.
func issuerNameResolves(ctx context.Context, client *PeerClient, name string) (bool, error) {
	return issuerPathBound(ctx, client, types.PeerIssuedByNamePath(name))
}

// issuerPathBound reports whether the registry's tree binds `path`.
func issuerPathBound(ctx context.Context, client *PeerClient, path string) (bool, error) {
	params, resource, err := tree.CreateGetRequest(path, "entity")
	if err != nil {
		return false, fmt.Errorf("create tree get: %w", err)
	}
	respEnv, _, err := client.SendExecute(ctx, "entity://"+string(client.RemotePeerID())+"/system/tree", "get", params, resource)
	if err != nil {
		return false, err
	}
	status, code, _, err := extractStatusAndCode(respEnv)
	if err != nil {
		return false, err
	}
	switch {
	case status == 200:
		return true, nil
	case status == 404:
		return false, nil
	default:
		return false, fmt.Errorf("tree get %q → %d/%q (neither bound nor absent)", path, status, code)
	}
}
