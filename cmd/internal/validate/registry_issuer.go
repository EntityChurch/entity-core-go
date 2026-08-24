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
	"sort"
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

	r.Declare("surface_registered", "EXTENSION-REGISTRY §6a.9 — the peer-issued issuer handler is reachable (peer started with an issuer policy); an unregistered handler is the default-off posture, not a failure of the peer, but it means nothing below is measured")
	r.Declare("policy_open_grants", "EXTENSION-REGISTRY §6a.9.1 mode=open — a layer-1-valid request is signed and published; the binding resolves afterwards")
	r.Declare("register_result_status_bound", "EXTENSION-REGISTRY §6a.9 — the 200 row answers `register-result { status: \"bound\", binding_hash }`: its OWN result type, the pinned discriminator value, and the hash REQUIRED on that branch. The success branch was the unmeasured one — three impls quietly agreed on an under-specified shape while the 202's visible disagreement got all the scrutiny")
	r.Declare("name_taken_on_second_register", "EXTENSION-REGISTRY §6a.9 — the third row of the pinned status table: a name already bound in this registry MUST be refused 409 name_taken, and the refusal MUST leave the first binding intact")
	r.Declare("policy_allowlist_grants_listed", "EXTENSION-REGISTRY §6a.9.1 mode=allowlist — a target_peer_id IN the allowlist is admitted")
	r.Declare("policy_allowlist_rejects_unlisted", "EXTENSION-REGISTRY §6a.9.1 mode=allowlist — a target_peer_id NOT in the allowlist MUST be refused 403 not_entitled")
	r.Declare("policy_allowlist_unlisted_publishes_nothing", "EXTENSION-REGISTRY §6a.9.1 — the negative half: a refused request MUST NOT leave a resolvable binding behind (a 403 that published anyway would pass a status-only check)")
	r.Declare("policy_manual_queues", "EXTENSION-REGISTRY §6a.9.1 mode=manual — the request is accepted for review as 202 pending_review, NOT signed")
	r.Declare("policy_manual_publishes_nothing", "EXTENSION-REGISTRY §6a.9.1 — the negative half of manual, and the one that matters: a 202 that quietly published the binding would satisfy a status-only assertion while defeating the entire mode")
	r.Declare("pending_handle_resolves", "EXTENSION-REGISTRY §6a.9.3 REG-PENDING-HANDLE-1 [RULED 2026-08-13] — the 202's pending_hash MUST RESOLVE to a system/registry/pending-binding with status pending_review. Until v1.3 this was unassertable: pending_hash was a MUST naming an entity with no schema, so a handle that named nothing fetchable was indistinguishable from a conformant one")
	r.Declare("pending_pointer_resolves", "EXTENSION-REGISTRY §6a.9.3 — the by-request pointer at pending/by-request/{target_peer_id}/{name} MUST resolve to the same body, so a requester that no longer holds the 202 can still poll its own queued request")
	r.Declare("pending_supersession_replaces_head", "EXTENSION-REGISTRY §6a.9.3 [MUST] — one pending head per (target_peer_id, name): a repeat request supersedes rather than enqueuing a duplicate. Retries carry a fresh nonce by construction, so without this an operator's queue fills with copies of one intent")
	r.Declare("pending_deny_leaves_head_and_publishes_nothing", "EXTENSION-REGISTRY §6a.9.3 REG-PENDING-DECIDE-1 (deny half) — deny MUST publish nothing AND leave a `denied` head reachable through the pointer. Deny is not a delete: a requester polling a vanished pointer cannot distinguish denied from never-received, which is a silent drop. A deny that silently issued returns an identical body, so the publishes-nothing half is the only one that can see it")
	r.Declare("pending_second_decision_rejected", "EXTENSION-REGISTRY §6a.9.3 — a second decision on a decided head MUST answer 409 already_decided. The dangerous failure is a 200: approving an already-denied request overturns the operator's refusal by retry, and re-approving mints a second binding for one request")
	r.Declare("pending_approve_issues_and_leaves_head", "EXTENSION-REGISTRY §6a.9.3 REG-PENDING-DECIDE-1 (approve half) — approve issues a binding that resolves BY NAME and leaves an `approved` head carrying its binding_hash")
	r.Declare("pending_decide_unknown_handle_404", "EXTENSION-REGISTRY §6a.9.3 — a pending_hash naming no stored pending-binding MUST answer 404 not_found. Probed with a well-formed body the registry never minted, not a random hash: a peer that rejects garbage but accepts a plausible unminted entity has the weaker check")
	r.Declare("name_constraints_rejects_nonmatching", "EXTENSION-REGISTRY §6a.9.1 — a name outside the policy's name_constraints glob MUST be refused 403 not_entitled")
	r.Declare("layer1_unsigned_request_rejected", "EXTENSION-REGISTRY §6a.9 layer 1 — a register-request with no system/signature at its invariant pointer MUST be refused; ownership proof is the floor beneath every policy mode")
	r.Declare("revoke_request_publishes_revocation", "EXTENSION-REGISTRY §6a.9 — revoke-request MUST publish a verifying revocation at the by-target index, which is the §2.1 step-4 signal a resolver excludes the binding on. Revocation is ADDITIVE: the immutable binding and its by-name pointer stay put.")
	r.Declare("renew_request_accepted", "EXTENSION-REGISTRY §6a.9 — renew-request extends an existing binding's expiry")
	r.Declare("register_ttl_clamped_to_max", "EXTENSION-REGISTRY §6a.9 v1.11 REG-TTL-CLAMP-1 (register) — a register-request carrying requested_ttl above the policy max_ttl is CLAMPED not refused: 200, and the issued binding carries exactly max_ttl. Asserted on the binding's value, since a refusing peer also returns non-200 and is otherwise indistinguishable")
	r.Declare("renew_ttl_clamped_to_max", "EXTENSION-REGISTRY §6a.9 v1.11 REG-TTL-CLAMP-1 (renew) — a renew carrying ttl above max_ttl is likewise clamped: 200/202, successor carries exactly max_ttl")
	r.Declare("layer1_unsigned_revoke_rejected", "EXTENSION-REGISTRY §6a.9 REG-REVOKE-PROOF-1 [added 2026-08-11] — revoke-request is \"Signed by target_peer_id or the operator\". An unsigned revoke MUST be refused: revocation is monotonic and cannot be undone, so an unauthenticated one is a permanent denial-of-name against any binding in the registry")
	r.Declare("layer1_unsigned_renew_rejected", "EXTENSION-REGISTRY §6a.9 REG-RENEW-PROOF-1 [added 2026-08-11] — renew-request is \"Signed by target_peer_id (layer-1)\". Replay defense is not authorization: it stops a CAPTURED request being re-run while leaving a fresh unsigned one accepted")
	r.Declare("unknown_operation_rejected", "EXTENSION-REGISTRY §6a.9 — an operation the issuer does not implement MUST be refused, not silently accepted")
	r.Declare("set_issuer_policy_round_trip", "EXTENSION-REGISTRY §6a.9.2 — set-issuer-policy stores the policy and get-issuer-policy returns it as written. Before this ruling the capability system/capability/registry-manage-issuer-policy named an act the corpus never defined, and a client had nothing to call")
	r.Declare("set_issuer_policy_replaces_whole", "EXTENSION-REGISTRY §6a.9.2 [MUST] — set replaces the policy WHOLE; an absent optional field means *unset*, not *unchanged*. A merge would make the result depend on write order, which two peers cannot reconstruct")
	r.Declare("set_issuer_policy_domain_control_rejected", "EXTENSION-REGISTRY §6a.9.2 — mode \"domain-control\" MUST be refused 400 unsupported_mode and NOT stored, rather than arming a mode the issuer cannot enforce. The negative half is checked too: a 400 that stored anyway passes a status-only assertion")
	r.Declare("set_issuer_policy_null_default_ttl_rejected", "EXTENSION-REGISTRY §6a.9.2 CAP registry D11 (arch 2026-08-18) — a live-registration policy with default_ttl=null can only mint null-ttl bindings, which CAP D3 makes unresolvable; set-issuer-policy MUST refuse it 400 and NOT store it, the same move as domain-control. Owed by py/rust; go implements it")
	r.Declare("set_issuer_policy_max_ttl_ceiling", "EXTENSION-REGISTRY §6a.9 v1.11 REG-TTL-CEILING-1 — set-issuer-policy MUST reject a live policy whose max_ttl is absent (400) and one whose default_ttl exceeds max_ttl (400); control: both present with default_ttl <= max_ttl is accepted 200. Same trigger and site as the default_ttl gate. Owed by py/rust; go implements it")
	r.Declare("get_issuer_policy_unset_404", "EXTENSION-REGISTRY §6a.9.2 — unset is not a mode: with no policy stored, get MUST answer 404 not_found and MUST NOT synthesize a default `open`, which would silently turn a curated registry into a first-come-first-serve one")

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

	// R-7 (2026-08-13). §6a.9's 200 row pins BOTH halves of the result —
	// `status: "bound"` and `binding_hash` — and nothing asserted either.
	//
	// WHY THIS WAS MISSED, and it is not the same miss as R-6. `policy_open_grants`
	// above is a real check: it drives mode=open, requires 200, and reads the
	// binding back. What it never does is open the RESULT BODY. So the
	// discriminator field the whole §6a.9 ruling turns on was unmeasured on the
	// success branch, and Go shipped `status: "registered"` against a spec that
	// pins `"bound"` — a live cross-peer MUST divergence that passed every gate
	// in every run, while the constant's own comment claimed to implement §6a.9.
	//
	// **Found by `entity-core-rust`, applying the same ruling, not by us.** Their
	// observation is worth keeping verbatim: the three-way analysis all happened
	// on the 202 because that is where the visible disagreement was, and *"the
	// branch where all three quietly agreed on an under-specified shape got no
	// scrutiny."* A divergence is found where implementations disagree loudly;
	// this class hides where they agree.
	r.Run("register_result_status_bound", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("bound")
		status, code, resp, _, err := issuerRegisterResp(ctx, client, uri, name)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("mode=open register-request → %d/%q, want 200", status, code))
		}
		if len(resp.Result) == 0 {
			return FailCheck("200 carried no result body — §6a.9 pins register-result { status, binding_hash } on the success branch")
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
			return FailCheck("undecodable result entity: " + err.Error())
		}
		if resultEnt.Type != types.TypeRegistryRegisterResult {
			return FailCheck(fmt.Sprintf("200 result is %q, want %q — §6a.9 gives register-request its OWN result type on both branches (borrowing another operation's shape is what the ruling retired)",
				resultEnt.Type, types.TypeRegistryRegisterResult))
		}
		var d types.RegistryRegisterResultData
		if err := ecf.Decode(resultEnt.Data, &d); err != nil {
			return FailCheck("undecodable register-result data: " + err.Error())
		}
		if d.Status != types.RegisterStatusBound {
			return FailCheck(fmt.Sprintf("200 register-result status is %q, want %q — §6a.9 pins the discriminator on the success branch, and an impl-local spelling makes the outcome unreadable cross-peer",
				d.Status, types.RegisterStatusBound))
		}
		if d.BindingHash == nil || d.BindingHash.IsZero() {
			return FailCheck("200 register-result carries status=bound with no binding_hash — §6a.9 makes it REQUIRED on that branch, and without it the caller has no handle to the thing just issued")
		}
		return PassCheck(fmt.Sprintf("200 answers register-result{status=%q, binding_hash=%s}", d.Status, d.BindingHash.String()))
	}))

	// --- the name_taken row ------------------------------------------------

	// R-6 (2026-08-12 c). §6a.9's status table has four rows; three were
	// checked and this one had NO check at all — not a half-assertion, an
	// absent one. Go implements it (`applyAdmission` → by-name index →
	// 409/name_taken, ext/registry/peerissued/register.go), so the gap was
	// invisible from inside: the behaviour was right and nothing measured it.
	// That is the §5.2b shape one level up from the extractor finding — the
	// audit that catches a half-checked row will not catch an unchecked one,
	// because there is no failure string to notice.
	//
	// Driven in `open` mode deliberately: the row is an issuance-time name
	// collision, not an admission decision, so a mode that admits everything
	// isolates it. Both registers name the SAME target (this validator), so
	// layer 1 passes on both and the 409 cannot be a mis-read 401.
	r.Run("name_taken_on_second_register", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("taken")
		status, code, err := issuerRegister(ctx, client, uri, name)
		if err != nil {
			return FailCheck("first register-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("first register-request → %d/%q, want 200 in mode=open — the collision cannot be measured without a binding to collide with", status, code))
		}
		status, code, err = issuerRegister(ctx, client, uri, name)
		if err != nil {
			return FailCheck("second register-request: " + err.Error())
		}
		if status == 401 {
			return FailCheck(fmt.Sprintf("second register-request → 401/%q — layer 1 refused a request it accepted moments earlier, so this measured the signature floor rather than the name collision", code))
		}
		if status != 409 || code != types.RegistryErrNameTaken {
			return FailCheck(fmt.Sprintf("re-registering an already-bound name → %d/%q, want 409/%s (§6a.9 pins the row as status AND code)", status, code, types.RegistryErrNameTaken))
		}
		// The negative half. A registry that answers 409 and then rebinds
		// (or unbinds) the name has made the refusal cosmetic — and a
		// status+code assertion alone would pass.
		bound, err := issuerNameResolves(ctx, client, name)
		if err != nil {
			return FailCheck("read back by-name binding after the refusal: " + err.Error())
		}
		if !bound {
			return FailCheck("409 name_taken left NOTHING bound at " + types.PeerIssuedByNamePath(name) + " — the refused request destroyed the binding it collided with")
		}
		return PassCheck("second register on a bound name refused 409/name_taken; the first binding survives")
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
	// Captured by policy_manual_queues and consumed by the §6a.9.3 rows
	// below. They Require() that check, so an unset value is unreachable.
	var manualPendingHash hash.Hash
	r.Run("policy_manual_queues", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual}); out != nil {
			return *out
		}
		status, code, resp, requestHash, err := issuerRegisterResp(ctx, client, uri, manualName)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 202 {
			return FailCheck(fmt.Sprintf("mode=manual → %d/%q, want 202 pending_review", status, code))
		}
		// R-5 audit (2026-08-12): this row is the §6a.9 status table's
		// `202 | pending_review`, and it was asserting the status while
		// NAMING the code in its own failure message — the same half-check
		// that hid py's layer-1 divergence, one pinned row over. Arch named
		// the three layer-1 rows; this one they did not, and the audit is
		// what found it.
		//
		// THE CARRIER: the RESULT FIELD, and measurement is what settled it
		// (2026-08-12 c). This assertion originally read the value out of an
		// ERROR-shaped body, because that is what Go emitted —
		// NewErrorResponse(202, "pending_review", ...) — and because §6a.9's
		// table lists the value under a column headed `Code`. Running the
		// other two peers showed both answering with a SUCCESS-shaped result
		// carrying `status: "pending_review"`, which is also what §6a.9's own
		// pseudocode says (`on queue: status "pending_review"`).
		//
		// THE ARGUMENT IS THE DESIGN, NOT THE HEAD COUNT. An earlier draft of
		// this comment justified the change as "two of three plus the
		// pseudocode" — a vote, and GUIDE-CONFORMANCE §4 forbids exactly that:
		// all three differing is the SPEC-AMBIGUITY row, whose resolution is
		// "tighten the spec in the same pass", and the split row says in so
		// many words *spec arbitrates; do not vote*. This repo already states
		// the rule correctly in three other places (ext/network/nattype_test
		// .go, cmd/internal/compute-corpus/crossbless.go and its README).
		//
		// The change stands on reasons that would hold if BOTH siblings had
		// done the opposite: system/protocol/error denotes a FAILED operation,
		// 202 denotes an accepted-and-pending one, so emitting an error entity
		// on a 2xx forces a client to decide whether to branch on the status
		// or on the result type — the two disagree by construction. And the
		// 200 borrowed local-name's bind-result, a DIFFERENT operation's type,
		// because the payload happened to match: a result type is part of an
		// operation's contract, and coupling two contracts on payload
		// coincidence breaks the moment either grows a field.
		//
		// Still routed to arch as an ambiguity to TIGHTEN (§4's prescribed
		// resolution), not as a fait accompli — spec-issues/2026-08-12-c.
		//
		// So the FIELD passes and the error code is the outlier — the reverse
		// of what this check asserted this morning. The error-code carrier
		// still WARNs rather than FAILs: no cohort member emits it now, and a
		// peer that does is answering a plain reading of the ratified table.
		//
		// The VALUE is asserted in both cases; absent in both still FAILs. And
		// the check below is why the tolerance exists at all — a 202 that
		// quietly published the binding defeats the entire mode, and gating it
		// on a carrier disagreement left that unmeasured against py while
		// looking like rigor.
		field, carrier := pendingReviewFromResult(resp)
		switch {
		case field == registryPendingReview:
			// RULED 2026-08-12 (d): pending_hash names the STORED PENDING
			// ENTITY, not the request. Asserted as an inequality rather than
			// by fetching, and that is not laziness — §6a.9.3's approval
			// protocol is specified nowhere, so no path convention exists to
			// fetch a queued request at. What IS checkable against any peer
			// is arch's own reasoning: a handle the client computed before it
			// dispatched is not a handle. If it equals the request hash the
			// peer has returned the client its own input.
			ph, ok := pendingHashFromResult(resp)
			switch {
			case !ok:
				// Name the RULED carrier, not just the observed one. The
				// parenthetical used to carry `carrier` alone, which reads as
				// though the observed shape were the required shape — and the
				// first peer to hit this message returns
				// `system/protocol/status`, the type arch rejected on structure
				// (a carrier with room for neither binding_hash nor a poll
				// handle moves the divergence one field down). A failure
				// message that names the wrong target is a wrong bug report.
				return FailCheck("mode=manual queued as 202 but returned no pending_hash — §6a.9 ruling 2026-08-12 (arch 81e73ae): the queued request MUST come back with a handle, in a " +
					types.TypeRegistryRegisterResult + " carrying {status, pending_hash}. Observed carrier: " + carrier)
			case ph == requestHash:
				return FailCheck("mode=manual returned pending_hash equal to the register-request's own content_hash — that is the value the requester already held before dispatching, so it names nothing fetchable and is not a handle (ruled 2026-08-12 d)")
			}
			manualPendingHash = ph
			return PassCheck("mode=manual queued as 202 with " + registryPendingReview + " in the result field (" + carrier + "), pending_hash distinct from the request")
		case code == registryPendingReview:
			return WarnCheck(fmt.Sprintf("mode=manual queued as 202 carrying %q as an ERROR CODE on a success status — §6a.9's table heading invites this, but its pseudocode and every cohort member write a result field (spec-issues/2026-08-12-c)", registryPendingReview))
		default:
			return FailCheck(fmt.Sprintf("mode=manual answered 202 but no carrier holds %q — error-code was %q, result body was %s", registryPendingReview, code, carrier))
		}
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

	// --- §6a.9.3 the manual-approval path (RULED 2026-08-13) --------------
	//
	// REG-PENDING-HANDLE-1's RESOLVABILITY half and REG-PENDING-DECIDE-1.
	// Until v1.3 these could not be written: `pending_hash` was a MUST naming
	// an entity with no schema, so the strongest thing assertable was that
	// the handle differed from the request's own hash (above). A handle that
	// names nothing fetchable was indistinguishable from a conformant one.
	//
	// EXPECT THESE TO FAIL AGAINST SIBLINGS, and that is the honest signal,
	// not a probe bug: the ruling's own status line says UNBUILT IN ALL THREE
	// (rust withheld pending_hash pending the schema; py built against the
	// reserved section, storing `system/registry/register-pending` at a
	// different prefix and removing the head on approve). Do NOT soften these
	// to WARN to keep a cross-peer run green — a WARN is invisible in a green
	// run, which is the exact failure mode this category was corrected for
	// twice this month.

	r.Run("pending_handle_resolves", gate(func() CheckOutcome {
		if out, ok := r.Require("policy_manual_queues"); !ok {
			return out
		}
		bodyPath := types.PendingBindingPath(manualPendingHash)
		ent, _, err := client.TreeGet(ctx, bodyPath)
		if err != nil {
			return FailCheck("the 202's pending_hash does not resolve: tree:get " + bodyPath +
				" → " + err.Error() + " — §6a.9.3 stores the queued request at that path, and a" +
				" handle naming nothing fetchable is not a handle (ruled 2026-08-12 d, schema 2026-08-13)")
		}
		if ent.Type != types.TypeRegistryPendingBinding {
			return FailCheck(fmt.Sprintf("pending_hash resolves to type %q, want %q (§6a.9.3)",
				ent.Type, types.TypeRegistryPendingBinding))
		}
		pb, err := types.PendingBindingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode pending-binding: " + err.Error())
		}
		if pb.Status != types.PendingStatusPendingReview {
			return FailCheck(fmt.Sprintf("queued pending-binding status is %q, want %q",
				pb.Status, types.PendingStatusPendingReview))
		}
		if pb.Name != manualName {
			return FailCheck(fmt.Sprintf("pending-binding names %q, the request asked for %q", pb.Name, manualName))
		}
		if pb.BindingHash != nil {
			return FailCheck("a pending_review head carries binding_hash — that field is REQUIRED on \"approved\" and absent otherwise, so a peer setting it here has issued something or is mis-shaping the entity")
		}
		return PassCheck("pending_hash resolves to a " + types.TypeRegistryPendingBinding +
			" with status " + types.PendingStatusPendingReview)
	}))

	r.Run("pending_pointer_resolves", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_handle_resolves"); !ok {
			return out
		}
		ptr := types.PendingBindingByRequestPath(string(client.LocalPeerID()), manualName)
		ent, _, err := client.TreeGet(ctx, ptr)
		if err != nil {
			return FailCheck("no by-request pointer at " + ptr + ": " + err.Error() +
				" — §6a.9.3 requires it precisely so a requester that no longer holds the 202" +
				" can still poll its own queued request")
		}
		if ent.ContentHash != manualPendingHash {
			return FailCheck(fmt.Sprintf("by-request pointer resolves to %s but the 202 handed back %s"+
				" — the pointer MUST name the current head",
				types.PeerIdentityHashHex(ent.ContentHash), types.PeerIdentityHashHex(manualPendingHash)))
		}
		return PassCheck("by-request pointer at " + ptr + " resolves to the same body the 202 named")
	}))

	// Supersession, measured before any decision is taken — a second request
	// for the same (target_peer_id, name) MUST replace the head rather than
	// enqueue a duplicate. Retries carry a fresh nonce by construction, so
	// without this rule an operator's queue fills with copies of one intent.
	r.Run("pending_supersession_replaces_head", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_pointer_resolves"); !ok {
			return out
		}
		// Vary a SCHEMA-CARRIED field, per §6a.9.3 R4 [RULED 2026-08-14].
		// This vector used to send a byte-identical repeat and then assert
		// the pending_hash CHANGED — two defects in one: a pending-binding
		// carries no nonce, so two identical requests inside one millisecond
		// encode identically and content-address to ONE body. That collapse
		// is correct ("one head, one hash"), so the old assertion FAILed a
		// conformant peer on timing, and the vector was unobservable when it
		// did not. core-rust reported the fragility; arch ruled the collapse
		// intended and made varying a carried field the obligation.
		supersedingTTL := uint64(7_200_000)
		status, code, resp, _, err := issuerRegisterRespTTL(ctx, client, uri, manualName, &supersedingTTL)
		if err != nil {
			return FailCheck("superseding register-request: " + err.Error())
		}
		if status != 202 {
			return FailCheck(fmt.Sprintf("a repeat request for a name already pending answered %d/%q,"+
				" want 202 — the queue is not a reservation and a pending head is not a binding", status, code))
		}
		newPH, ok := pendingHashFromResult(resp)
		if !ok {
			return FailCheck("superseding request returned no pending_hash")
		}
		// NOT asserted: newPH != manualPendingHash. §6a.9.3 R4 forbids using
		// "the pending_hash changed" as the supersession signal. The signal
		// is the POINTER, and the body it names.
		ptr := types.PendingBindingByRequestPath(string(client.LocalPeerID()), manualName)
		ent, _, err := client.TreeGet(ctx, ptr)
		if err != nil {
			return FailCheck("by-request pointer vanished after supersession: " + err.Error())
		}
		if ent.ContentHash != newPH {
			return FailCheck("by-request pointer still names the superseded head — §6a.9.3 [MUST]: one pending head per (target_peer_id, name)")
		}
		// The observable that replaces the hash-inequality check: the body the
		// pointer now names MUST carry the superseding request's terms. This
		// is what "the head was replaced" actually means, and unlike a hash
		// comparison it cannot pass by accident of clock resolution.
		pend, perr := types.PendingBindingDataFromEntity(ent)
		if perr != nil {
			return FailCheck("by-request pointer resolves to something that is not a pending-binding: " + perr.Error())
		}
		if pend.RequestedTTL == nil || *pend.RequestedTTL != supersedingTTL {
			got := "absent"
			if pend.RequestedTTL != nil {
				got = fmt.Sprintf("%d", *pend.RequestedTTL)
			}
			return FailCheck(fmt.Sprintf("the head names requested_ttl=%s but the superseding request sent %d"+
				" — the pointer moved to a body that is not the superseding one", got, supersedingTTL))
		}
		manualPendingHash = newPH
		return PassCheck("a repeat request superseded the head; the pointer names a body carrying the superseding terms")
	}))

	// REG-PENDING-DECIDE-1, deny half. Run FIRST and on the name already in
	// the queue: deny is the half an outcome-only check cannot see, because a
	// deny that silently issued returns the same shape.
	r.Run("pending_deny_leaves_head_and_publishes_nothing", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_supersession_replaces_head"); !ok {
			return out
		}
		reason := "conformance probe — deny path"
		params, err := types.RegistryDecisionRequestData{
			PendingHash: manualPendingHash,
			Reason:      &reason,
		}.ToDenyEntity()
		if err != nil {
			return FailCheck("encode deny-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpDenyRequest, params)
		if err != nil {
			return FailCheck("deny-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("deny-request → %d/%q, want 200 (§6a.9.3 operations table)", status, code))
		}
		// The load-bearing half: nothing was signed.
		bound, err := issuerNameResolves(ctx, client, manualName)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if bound {
			return FailCheck("deny-request published a binding at " + types.PeerIssuedByNamePath(manualName) +
				" — a deny that silently issues passes an outcome-only check, which is why this half exists")
		}
		// Deny is not a delete: the head persists so a poller can tell
		// "denied" from "never received".
		ptr := types.PendingBindingByRequestPath(string(client.LocalPeerID()), manualName)
		ent, _, err := client.TreeGet(ctx, ptr)
		if err != nil {
			return FailCheck("deny removed the by-request pointer (" + ptr + "): " + err.Error() +
				" — §6a.9.3 [MUST]: a requester polling a vanished pointer cannot distinguish denied" +
				" from never-received, which is a silent drop")
		}
		pb, err := types.PendingBindingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode denied head: " + err.Error())
		}
		if pb.Status != types.PendingStatusDenied {
			return FailCheck(fmt.Sprintf("head after deny has status %q, want %q", pb.Status, types.PendingStatusDenied))
		}
		manualPendingHash = ent.ContentHash
		return PassCheck("deny left a " + types.PendingStatusDenied + " head reachable through the pointer and published nothing")
	}))

	r.Run("pending_second_decision_rejected", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_deny_leaves_head_and_publishes_nothing"); !ok {
			return out
		}
		params, err := types.RegistryDecisionRequestData{PendingHash: manualPendingHash}.ToApproveEntity()
		if err != nil {
			return FailCheck("encode approve-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpApproveRequest, params)
		if err != nil {
			return FailCheck("approve-request on a decided head: " + err.Error())
		}
		if status != 409 {
			// Named explicitly because the dangerous failure here is a 200:
			// approving an already-denied request mints a binding the
			// operator refused.
			return FailCheck(fmt.Sprintf("approving an already-denied request → %d/%q, want 409 already_decided"+
				" — approve and deny are not idempotent-by-replay, and a 200 here means the operator's"+
				" refusal was overturned by a retry", status, code))
		}
		// Asserted as status AND code, per §6a.9's own conformance MUST: a
		// check of a pinned row that reads only the status scores the
		// contract's weaker half and reports green on a divergence.
		if code != types.RegistryErrAlreadyDecided {
			return FailCheck(fmt.Sprintf("second decision answered 409 %q, §6a.9.3 pins %q",
				code, types.RegistryErrAlreadyDecided))
		}
		bound, err := issuerNameResolves(ctx, client, manualName)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if bound {
			return FailCheck("the refused second decision published a binding anyway")
		}
		return PassCheck("a second decision on a decided head → 409 already_decided, nothing published")
	}))

	// REG-PENDING-DECIDE-1, approve half — on its own name, because the one
	// above is now permanently denied.
	approveName := issuerName("approve")
	r.Run("pending_approve_issues_and_leaves_head", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_handle_resolves"); !ok {
			return out
		}
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeManual}); out != nil {
			return *out
		}
		status, code, resp, _, err := issuerRegisterResp(ctx, client, uri, approveName)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 202 {
			return FailCheck(fmt.Sprintf("mode=manual → %d/%q, want 202", status, code))
		}
		ph, ok := pendingHashFromResult(resp)
		if !ok {
			return FailCheck("202 returned no pending_hash")
		}
		params, err := types.RegistryDecisionRequestData{PendingHash: ph}.ToApproveEntity()
		if err != nil {
			return FailCheck("encode approve-request: " + err.Error())
		}
		status, code, aResp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpApproveRequest, params)
		if err != nil {
			return FailCheck("approve-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("approve-request → %d/%q, want 200 with register-result {status: bound, binding_hash}", status, code))
		}
		if s, desc := pendingReviewFromResult(aResp); s != types.RegisterStatusBound {
			return FailCheck(fmt.Sprintf("approve-request result status is %q, want %q (%s)",
				s, types.RegisterStatusBound, desc))
		}
		// It actually issued.
		bound, err := issuerNameResolves(ctx, client, approveName)
		if err != nil {
			return FailCheck("read back by-name binding: " + err.Error())
		}
		if !bound {
			return FailCheck("approve-request answered 200 bound but " + types.PeerIssuedByNamePath(approveName) +
				" does not resolve — the approval issued nothing")
		}
		// And left an `approved` head carrying the binding it issued.
		ptr := types.PendingBindingByRequestPath(string(client.LocalPeerID()), approveName)
		ent, _, err := client.TreeGet(ctx, ptr)
		if err != nil {
			return FailCheck("approve removed the by-request pointer (" + ptr + "): " + err.Error() +
				" — §6a.9.3 keeps the head so the outcome stays pollable")
		}
		pb, err := types.PendingBindingDataFromEntity(ent)
		if err != nil {
			return FailCheck("decode approved head: " + err.Error())
		}
		if pb.Status != types.PendingStatusApproved {
			return FailCheck(fmt.Sprintf("head after approve has status %q, want %q", pb.Status, types.PendingStatusApproved))
		}
		if pb.BindingHash == nil {
			return FailCheck("approved head carries no binding_hash — REQUIRED on \"approved\" (§6a.9.3)")
		}
		return PassCheck("approve issued a resolvable binding and left an " + types.PendingStatusApproved +
			" head carrying its binding_hash")
	}))

	r.Run("pending_decide_unknown_handle_404", gate(func() CheckOutcome {
		if out, ok := r.Require("pending_handle_resolves"); !ok {
			return out
		}
		// A well-formed pending-binding this registry never minted. Not a
		// random hash: a peer that 404s on garbage but accepts a plausible
		// unminted body has the weaker check, and this is the shape that
		// distinguishes them.
		unminted, err := types.PendingBindingData{
			Name:         issuerName("never-queued"),
			TargetPeerID: string(client.LocalPeerID()),
			QueuedAt:     uint64(time.Now().UnixMilli()),
			Status:       types.PendingStatusPendingReview,
		}.ToEntity()
		if err != nil {
			return FailCheck("encode unminted pending-binding: " + err.Error())
		}
		params, err := types.RegistryDecisionRequestData{PendingHash: unminted.ContentHash}.ToApproveEntity()
		if err != nil {
			return FailCheck("encode approve-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpApproveRequest, params)
		if err != nil {
			return FailCheck("approve-request: " + err.Error())
		}
		if status != 404 {
			return FailCheck(fmt.Sprintf("approving a pending_hash the registry never stored → %d/%q,"+
				" want 404 not_found (§6a.9.3)", status, code))
		}
		if code != types.RegistryErrNotFound {
			return FailCheck(fmt.Sprintf("404 answered code %q, §6a.9.3 pins %q", code, types.RegistryErrNotFound))
		}
		return PassCheck("a pending_hash naming no stored pending-binding → 404 not_found")
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

	// See requirePinnedCode — every layer-1 row below asserts status AND code.
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
		if out := requirePinnedCode(code, "unsigned register-request"); out != nil {
			return *out
		}
		return PassCheck("unsigned register-request refused 401/signature_invalid")
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
		// §6a.9: revoke is "Signed by target_peer_id or the operator."
		// This check used to dispatch with NO proof and assert 200/202,
		// which made it a check that a peer passes by NOT authorizing —
		// a correctly-implemented peer failed here. Prove ownership.
		if err := publishOwnershipProof(ctx, client, revEnt); err != nil {
			return FailCheck("publish ownership proof for revoke-request: " + err.Error())
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
		// §6a.9: renew is "Signed by target_peer_id (layer-1)." Same
		// defect as revoke above — replay defense is not authorization,
		// and asserting acceptance without proof scored the absence of it.
		if err := publishOwnershipProof(ctx, client, renewEnt); err != nil {
			return FailCheck("publish ownership proof for renew-request: " + err.Error())
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

	// REG-TTL-CLAMP-1 (register half) — REGISTRY §6a.9, v1.11. A register-request
	// carrying requested_ttl ABOVE the policy max_ttl is CLAMPED, not refused: the
	// call returns 200 and the issued binding carries EXACTLY max_ttl. Asserted on
	// the binding's value, not the status — a peer that refuses instead of clamping
	// also returns non-200 and would be indistinguishable on status alone.
	r.Run("register_ttl_clamped_to_max", gate(func() CheckOutcome {
		defTTL := uint64(1_000)
		maxTTL := uint64(10_000)
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{
			Mode: types.IssuerPolicyModeOpen, DefaultTTL: &defTTL, MaxTTL: &maxTTL,
		}); out != nil {
			return *out
		}
		name := issuerName("clamp-reg")
		above := uint64(999_999_999)
		status, code, resp, _, err := issuerRegisterRespTTL(ctx, client, uri, name, &above)
		if err != nil {
			return FailCheck("register-request: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("register above the ceiling → %d/%q, want 200 (CLAMP, not refuse) — v1.11 clamps rather than billing a request for a policy it cannot read", status, code))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
			return FailCheck("decode bind result: " + err.Error())
		}
		bindRes, err := types.LocalNameBindResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode binding_hash: " + err.Error())
		}
		gotTTL, err := issuerBindingTTL(ctx, client, bindRes.BindingHash)
		if err != nil {
			return FailCheck("read back issued binding: " + err.Error())
		}
		if gotTTL == nil || *gotTTL != maxTTL {
			return FailCheck(fmt.Sprintf("issued binding ttl = %v, want clamped to max_ttl %d (requested %d) — the ceiling was not applied", gotTTL, maxTTL, above))
		}
		return PassCheck(fmt.Sprintf("register above the ceiling accepted 200 and the binding carries exactly max_ttl (%d), not the requested %d", maxTTL, above))
	}))

	// REG-TTL-CLAMP-1 (renew half) — a renew carrying ttl above max_ttl is likewise
	// clamped: 200/202 and the successor carries exactly max_ttl.
	r.Run("renew_ttl_clamped_to_max", gate(func() CheckOutcome {
		defTTL := uint64(1_000)
		maxTTL := uint64(10_000)
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{
			Mode: types.IssuerPolicyModeOpen, DefaultTTL: &defTTL, MaxTTL: &maxTTL,
		}); out != nil {
			return *out
		}
		name := issuerName("clamp-renew")
		status, code, bindingHash, err := issuerRegisterBound(ctx, client, uri, name)
		if err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("setup: register %q → %d/%q err=%v", name, status, code, err))
		}
		above := uint64(999_999_999)
		renewEnt, err := types.RegistryRenewRequestData{
			BindingHash: bindingHash, TTL: &above, Nonce: issuerNonce(), IssuedAt: uint64(time.Now().UnixMilli()),
		}.ToEntity()
		if err != nil {
			return FailCheck("build renew-request: " + err.Error())
		}
		if err := publishOwnershipProof(ctx, client, renewEnt); err != nil {
			return FailCheck("publish ownership proof: " + err.Error())
		}
		rStatus, rCode, rResp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpRenewRequest, renewEnt)
		if err != nil {
			return FailCheck("renew-request: " + err.Error())
		}
		if rStatus != 200 && rStatus != 202 {
			return FailCheck(fmt.Sprintf("renew above the ceiling → %d/%q, want 200/202 (CLAMP, not refuse)", rStatus, rCode))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(rResp.Result, &resultEnt); err != nil {
			return FailCheck("decode renew result: " + err.Error())
		}
		bindRes, err := types.LocalNameBindResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode successor binding_hash: " + err.Error())
		}
		gotTTL, err := issuerBindingTTL(ctx, client, bindRes.BindingHash)
		if err != nil {
			return FailCheck("read back successor binding: " + err.Error())
		}
		if gotTTL == nil || *gotTTL != maxTTL {
			return FailCheck(fmt.Sprintf("successor ttl = %v, want clamped to max_ttl %d (requested %d)", gotTTL, maxTTL, above))
		}
		return PassCheck(fmt.Sprintf("renew above the ceiling accepted and the successor carries exactly max_ttl (%d)", maxTTL))
	}))

	// The two negative halves. These are the checks whose absence let an
	// unauthenticated revocation path ship green: the positive checks above
	// asserted only that revoke/renew were ACCEPTED, so a peer that skipped
	// authorization entirely scored better than one that enforced it.
	r.Run("layer1_unsigned_revoke_rejected", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("unsigned-revoke")
		status, code, bindingHash, err := issuerRegisterBound(ctx, client, uri, name)
		if err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("setup: register %q → %d/%q err=%v", name, status, code, err))
		}
		revEnt, err := types.RegistryRevokeRequestData{BindingHash: bindingHash}.ToEntity()
		if err != nil {
			return FailCheck("build revoke-request: " + err.Error())
		}
		// Deliberately publish NO ownership proof.
		revStatus, revCode, err := issuerDispatch(ctx, client, uri, peerissued.OpRevokeRequest, revEnt)
		if err != nil {
			return FailCheck("revoke-request: " + err.Error())
		}
		if revStatus == 200 || revStatus == 202 {
			return FailCheck("an UNSIGNED revoke-request was accepted — any peer that can reach this registry can permanently revoke any binding in it")
		}
		if revStatus != 401 {
			return FailCheck(fmt.Sprintf("unsigned revoke-request → %d/%q, want 401 (ownership proof missing)", revStatus, revCode))
		}
		if out := requirePinnedCode(revCode, "unsigned revoke-request"); out != nil {
			return *out
		}
		// Status alone is not enough: a 401 that revoked anyway is worse
		// than an honest 200, because it reports refusal while acting.
		revPath := types.PeerIssuedRevocationByTargetPath(bindingHash)
		revoked, err := issuerPathBound(ctx, client, revPath)
		if err != nil {
			return FailCheck("read back revocation by-target index: " + err.Error())
		}
		if revoked {
			return FailCheck("unsigned revoke-request answered 401 but published a revocation at " + revPath + " anyway")
		}
		return PassCheck("unsigned revoke-request refused 401 and published nothing")
	}))

	r.Run("layer1_unsigned_renew_rejected", gate(func() CheckOutcome {
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		name := issuerName("unsigned-renew")
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
		// Deliberately publish NO ownership proof.
		renewStatus, renewCode, err := issuerDispatch(ctx, client, uri, peerissued.OpRenewRequest, renewEnt)
		if err != nil {
			return FailCheck("renew-request: " + err.Error())
		}
		if renewStatus == 200 || renewStatus == 202 {
			return FailCheck("an UNSIGNED renew-request was accepted — any peer can extend any binding's life past its registrant's intended lapse")
		}
		if renewStatus != 401 {
			return FailCheck(fmt.Sprintf("unsigned renew-request → %d/%q, want 401 (ownership proof missing)", renewStatus, renewCode))
		}
		if out := requirePinnedCode(renewCode, "unsigned renew-request"); out != nil {
			return *out
		}
		return PassCheck("unsigned renew-request refused 401/signature_invalid")
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
		maxTTL := uint64(86_400_000)
		want := types.IssuerPolicyData{
			Mode:       types.IssuerPolicyModeAllowlist,
			Allowlist:  []string{string(client.LocalPeerID())},
			DefaultTTL: &ttl,
			MaxTTL:     &maxTTL, // v1.11: REQUIRED on a live policy dispatched through set-issuer-policy
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
		if got.MaxTTL == nil || *got.MaxTTL != maxTTL {
			return FailCheck("get lost max_ttl — the round-trip is not returning the policy as written (v1.11)")
		}
		return PassCheck(fmt.Sprintf("set-issuer-policy (%s) round-trips through get-issuer-policy", want.Mode))
	}))

	r.Run("set_issuer_policy_replaces_whole", gate(func() CheckOutcome {
		// Previous check left mode=allowlist WITH default_ttl=3_600_000 and a
		// non-empty allowlist. Write mode=open dropping the allowlist and carrying
		// a DIFFERENT default_ttl. CAP registry D11 makes default_ttl mandatory for
		// a live policy, so it can no longer be the "cleared optional field" — the
		// whole-replace property is shown by the allowlist clearing AND the
		// default_ttl taking the new value (a merge would keep the old allowlist or
		// the old ttl).
		replTTL := uint64(7_200_000)
		replMaxTTL := uint64(86_400_000)
		bare, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &replTTL, MaxTTL: &replMaxTTL}.ToEntity()
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
		if got.DefaultTTL == nil || *got.DefaultTTL != replTTL {
			return FailCheck(fmt.Sprintf("default_ttl not replaced whole: got %v want %d — a merge would keep the prior value", got.DefaultTTL, replTTL))
		}
		return PassCheck("set-issuer-policy replaces the policy whole; the allowlist cleared and default_ttl took the new value")
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

	r.Run("set_issuer_policy_null_default_ttl_rejected", gate(func() CheckOutcome {
		// CAP registry D11: a live-registration policy with no default_ttl can
		// only mint null-ttl bindings (a request omitting requested_ttl resolves
		// to null), which D3 makes unresolvable. set-issuer-policy MUST refuse it
		// 400 and store nothing — §6a.9.2's domain-control move, the party whose
		// field is missing (the operator) is exactly who set-issuer-policy speaks
		// for. An open policy carrying no default_ttl.
		ent, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}.ToEntity()
		if err != nil {
			return FailCheck("build issuer-policy: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, ent)
		if err != nil {
			return FailCheck("set-issuer-policy dispatch: " + err.Error())
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("set-issuer-policy accepted a live policy with null default_ttl (%d/%q) — CAP registry D11 requires 400: such a policy can only mint null-ttl bindings, unresolvable per D3, and the missing field is the operator's to supply here", status, code))
		}
		// Negative half: the rejected policy must not have overwritten the stored
		// (valid) one. A conformant peer still returns a policy carrying a
		// default_ttl; a peer that stored the null-ttl one returns default_ttl=null.
		getStatus, _, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpGetIssuerPolicy, issuerNoParams())
		if err != nil {
			return FailCheck("get-issuer-policy after rejection: " + err.Error())
		}
		if getStatus == 200 {
			if got, derr := issuerPolicyFromResponse(resp); derr == nil && got.DefaultTTL == nil {
				return FailCheck("a null-default_ttl policy was refused 400 but stored anyway (get returns default_ttl=null) — a status-only check would have passed this")
			}
		}
		// Re-arm a valid policy so nothing downstream inherits a rejected write.
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		return PassCheck(fmt.Sprintf("live policy with null default_ttl refused %d/%q and not stored — CAP registry D11", status, code))
	}))

	// REG-TTL-CEILING-1 (REGISTRY §6a.9, v1.11) — set-issuer-policy MUST reject a
	// live policy whose max_ttl is absent (400) and one whose default_ttl exceeds
	// max_ttl (400); the control is a policy with both, default_ttl <= max_ttl,
	// accepted 200. Same trigger and site as the default_ttl gate: it is the
	// operator's field, and this is where the missing value is supplied.
	r.Run("set_issuer_policy_max_ttl_ceiling", gate(func() CheckOutcome {
		def := uint64(3_600_000)
		big := uint64(7_200_000)
		small := uint64(1_800_000)

		// (1) live mode, default_ttl present but max_ttl ABSENT → 400.
		absent, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &def}.ToEntity()
		if err != nil {
			return FailCheck("build policy: " + err.Error())
		}
		if status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, absent); err != nil {
			return FailCheck("set-issuer-policy (absent max_ttl): " + err.Error())
		} else if status != 400 {
			return FailCheck(fmt.Sprintf("live policy with absent max_ttl → %d/%q, want 400 — v1.11 makes max_ttl REQUIRED on a live policy", status, code))
		}

		// (2) default_ttl > max_ttl → 400.
		inverted, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &big, MaxTTL: &small}.ToEntity()
		if err != nil {
			return FailCheck("build policy: " + err.Error())
		}
		if status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, inverted); err != nil {
			return FailCheck("set-issuer-policy (default>max): " + err.Error())
		} else if status != 400 {
			return FailCheck(fmt.Sprintf("policy with default_ttl > max_ttl → %d/%q, want 400", status, code))
		}

		// (3) control — both present, default_ttl <= max_ttl → 200.
		ok, err := types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen, DefaultTTL: &def, MaxTTL: &big}.ToEntity()
		if err != nil {
			return FailCheck("build policy: " + err.Error())
		}
		if status, code, err := issuerDispatch(ctx, client, uri, peerissued.OpSetIssuerPolicy, ok); err != nil {
			return FailCheck("set-issuer-policy (control): " + err.Error())
		} else if status != 200 {
			return FailCheck(fmt.Sprintf("control policy (default_ttl <= max_ttl) → %d/%q, want 200", status, code))
		}

		// Re-arm a valid policy so nothing downstream inherits this one.
		if out := setIssuerPolicy(ctx, client, types.IssuerPolicyData{Mode: types.IssuerPolicyModeOpen}); out != nil {
			return *out
		}
		return PassCheck("set-issuer-policy enforces the max_ttl ceiling: absent → 400, default_ttl > max_ttl → 400, both valid → 200 (REG-TTL-CEILING-1)")
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
// The type is `primitive/any`, NOT `primitive/map`.
//
// This sent `primitive/map` and was caught by arch reviewing the instrument,
// not by any run: core §3.2 has pinned the empty-params shape as a
// `primitive/any` entity whose data is canonical CBOR `a0` since it was
// written, and a strictly-conformant handler SHOULD reject a mismatched
// params *type* with `400 unexpected_params`. Go accepted `primitive/map`
// leniently, so go-on-go passed and the defect would have surfaced as a
// rust/py FAIL on `get_issuer_policy_unset_404` — a sibling bug that was
// really ours.
//
// The comment this replaced called `primitive/map` a "cohort convention,
// learned from a live peer." The convention was in the spec; what the live
// peer taught was Go's own leniency.
func issuerNoParams() entity.Entity {
	raw, _ := ecf.Encode(map[string]interface{}{})
	ent, _ := entity.NewEntity("primitive/any", cbor.RawMessage(raw))
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
	// CAP registry D11/D12 (arch ROUTING-2026-08-18-d §1): a live-registration
	// policy MUST define default_ttl, else a register omitting requested_ttl
	// resolves to a null ttl and the issuer fails closed (403 policy_rejected).
	// This helper seeds via tree:put (bypassing D11's set-issuer-policy gate), so
	// default a ttl here for the positive register-flow checks; the D11/D12
	// conformance behaviour is exercised explicitly by
	// set_issuer_policy_null_default_ttl_rejected.
	if policy.DefaultTTL == nil {
		d := uint64(1_000_000_000)
		policy.DefaultTTL = &d
	}
	// REGISTRY v1.11: a live policy MUST also carry max_ttl (the issuer-side
	// ceiling). This helper seeds via tree:put (bypassing set-issuer-policy's
	// REG-TTL-CEILING-1 gate), so default a max here for the positive
	// register-flow checks — well above default_ttl so it never clamps the
	// bindings those checks assert on. The ceiling/clamp behaviour is exercised
	// explicitly by set_issuer_policy_null_max_ttl_rejected and register_ttl_clamped.
	if policy.MaxTTL == nil {
		m := uint64(100_000_000_000)
		policy.MaxTTL = &m
	}
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
	return buildRegisterRequestTTL(client, name, nil)
}

// buildRegisterRequestTTL builds a register-request carrying an explicit
// `requested_ttl`, the SCHEMA-CARRIED field the supersession vector varies.
//
// §6a.9.3 R4 [RULED 2026-08-14]: a pending-binding carries no nonce, so two
// retries of one intent inside a single millisecond encode identically and
// content-address to ONE body. That collapse is correct and intended — one
// head, one hash — so a supersession vector MUST vary a field the schema
// carries (`requested_ttl` / `transports`), never the nonce, and no
// implementation may use "the `pending_hash` changed" as its supersession
// signal.
func buildRegisterRequestTTL(client *PeerClient, name string, ttl *uint64) (entity.Entity, error) {
	return types.RegistryRegisterRequestData{
		Name:         name,
		TargetPeerID: string(client.LocalPeerID()),
		RequestedTTL: ttl,
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

// issuerRegisterResp is issuerRegister with the full response kept, for the
// one row whose value may ride in the RESULT body rather than as an error
// code (§6a.9's 202 — see policy_manual_queues).
func issuerRegisterRespTTL(ctx context.Context, client *PeerClient, uri, name string, ttl *uint64) (uint, string, types.ExecuteResponseData, hash.Hash, error) {
	reqEnt, err := buildRegisterRequestTTL(client, name, ttl)
	if err != nil {
		return 0, "", types.ExecuteResponseData{}, hash.Hash{}, fmt.Errorf("build request: %w", err)
	}
	if err := publishOwnershipProof(ctx, client, reqEnt); err != nil {
		return 0, "", types.ExecuteResponseData{}, hash.Hash{}, err
	}
	status, code, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpRegisterRequest, reqEnt)
	return status, code, resp, reqEnt.ContentHash, err
}

func issuerRegisterResp(ctx context.Context, client *PeerClient, uri, name string) (uint, string, types.ExecuteResponseData, hash.Hash, error) {
	reqEnt, err := buildRegisterRequest(client, name)
	if err != nil {
		return 0, "", types.ExecuteResponseData{}, hash.Hash{}, fmt.Errorf("build request: %w", err)
	}
	if err := publishOwnershipProof(ctx, client, reqEnt); err != nil {
		return 0, "", types.ExecuteResponseData{}, hash.Hash{}, err
	}
	status, code, resp, err := issuerDispatchFull(ctx, client, uri, peerissued.OpRegisterRequest, reqEnt)
	return status, code, resp, reqEnt.ContentHash, err
}

// pendingHashFromResult reads `pending_hash` out of a 202's result body.
func pendingHashFromResult(resp types.ExecuteResponseData) (hash.Hash, bool) {
	if len(resp.Result) == 0 {
		return hash.Hash{}, false
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return hash.Hash{}, false
	}
	var d types.RegistryRegisterResultData
	if err := ecf.Decode(resultEnt.Data, &d); err != nil || d.PendingHash == nil {
		return hash.Hash{}, false
	}
	return *d.PendingHash, true
}

// pendingReviewFromResult reads a `status` field out of a SUCCESS-shaped
// result body — the second carrier §6a.9's 202 row is answered with in the
// cohort. Returns the value and a human description of what was actually
// there, so a failure message can name the shape instead of just reporting
// an empty string (which is how a carrier mismatch reads as a missing value).
func pendingReviewFromResult(resp types.ExecuteResponseData) (string, string) {
	if len(resp.Result) == 0 {
		return "", "empty"
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return "", "undecodable result entity: " + err.Error()
	}
	var raw map[string]interface{}
	if err := cbor.Unmarshal(resultEnt.Data, &raw); err != nil {
		return "", fmt.Sprintf("type=%q, data not a map", resultEnt.Type)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	desc := fmt.Sprintf("type=%q, fields=%v", resultEnt.Type, keys)
	if v, ok := raw["status"]; ok {
		if s, ok := v.(string); ok {
			return s, desc
		}
	}
	return "", desc
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
// registryPendingReview is the §6a.9 manual-mode row's code. Kept here rather
// than in core/types because it is a RESPONSE code the validator asserts
// against any peer, not a value this implementation emits from a constant —
// pinning it locally keeps the assertion honest if Go's own naming drifts.
const registryPendingReview = "pending_review"

// requirePinnedCode asserts the §6a.9 layer-1 refusal `code`, not merely the
// status. Returns nil when the code is right.
//
// WHY THIS EXISTS, stated so the next author does not re-introduce it. The
// three layer-1 rows asserted `status != 401` and nothing else — while holding
// the code in a variable and using it only to decorate failure messages. Two
// rows away in the same file, the layer-2 rows asserted
// `status != 403 || code != not_entitled`: the same file checking the whole
// contract in one place and half of it in another.
//
// That half-check let `entity-core-py` answer `401 proof_failed` at all three
// sites through a full cohort cycle without any instrument seeing it — and it
// is why architecture ratified the row on a *false* rationale ("three
// implementations converged"), since the only evidence anyone had was three
// green suites that were not looking. Arch retracted the rationale in place and
// ruled `[MUST]`: a check of a pinned status-table row asserts the CODE.
//
// The generalizable form, which is R-5 and is an audit every impl owes: a
// status is a class, a code is the contract. Asserting the class and calling it
// conformance is the §5.2b shape — absent coverage reading as covered.
func requirePinnedCode(code, what string) *CheckOutcome {
	if code == types.RegistryErrSignatureInvalid {
		return nil
	}
	out := FailCheck(fmt.Sprintf(
		"%s refused 401 but with code %q, want %q — EXTENSION-REGISTRY §6a.9 pins the layer-1 row as 401/signature_invalid [MUST, ruled 2026-08-12]. The status alone is a class; the code is the contract, and a status-only assertion is what let this diverge across a full cohort cycle unseen",
		what, code, types.RegistryErrSignatureInvalid))
	return &out
}

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

// issuerBindingTTL reads the ttl off a published binding, by its hash — the
// observable REG-TTL-CLAMP-1 asserts on. The binding is served at its storage
// path; a peer that clamped writes the clamped value here (it is signed), and a
// peer that ignored the ceiling writes the requested one.
func issuerBindingTTL(ctx context.Context, client *PeerClient, bindingHash hash.Hash) (*uint64, error) {
	ent, _, err := client.TreeGet(ctx, types.BindingStoragePath(bindingHash))
	if err != nil {
		return nil, err
	}
	bd, err := types.BindingDataFromEntity(ent)
	if err != nil {
		return nil, fmt.Errorf("decode binding: %w", err)
	}
	return bd.TTL, nil
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
