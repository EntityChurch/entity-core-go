package identity

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// handleCreateQuorum delegates to EXTENSION-QUORUM:create. Returns the new
// quorum_id. Per §6 / §3.1: the quorum entity is structural and is not
// itself signed; authorization for :create is per coherent-capability §8.
func (h *Handler) handleCreateQuorum(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	_, q, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	body, err := types.IdentityCreateQuorumRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode IdentityCreateQuorumRequest: "+err.Error())
	}
	innerReq := types.QuorumCreateRequestData{QuorumData: body.QuorumData}
	innerEnt, err := innerReq.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	innerHReq := &handler.Request{
		Path:      "system/quorum",
		Operation: "create",
		Params:    innerEnt,
		Context:   hctx,
	}
	resp, err := q.Handle(ctx, innerHReq)
	if err != nil {
		return resp, err
	}
	if resp.Status != 200 {
		return resp, nil
	}
	innerResult, err := types.QuorumCreateResultDataFromEntity(resp.Result)
	if err != nil {
		return handler.NewErrorResponse(500, "decode_failed",
			"decode QuorumCreateResult: "+err.Error())
	}
	return handler.NewResponse(200, types.TypeIdentityCreateQuorumResult,
		types.IdentityCreateQuorumResultData{QuorumID: innerResult.QuorumID})
}

// handleCreateAttestation produces an identity-context system/attestation
// per PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-4 (3 ordered phases):
//
//	Phase 1: validate_inputs — structural invariants + per-function
//	         valid-modes table (PI-11). On invalid mode/function combo:
//	         400 invalid_mode_for_function with diagnostic envelope.
//	Phase 2: compose_substrate_attestation — substrate's att.Create
//	         performs structural validation, supersedes-existence check,
//	         entity encoding, and tree binding. attesting/attested
//	         round-trip byte-equivalent through the call (P-4').
//	Phase 3: per-mode dispatch — embedded mode returns unbound entity
//	         (zero attestation_hash); bound modes return non-zero hash
//	         and absolute path.
func (h *Handler) handleCreateAttestation(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	att, q, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	body, err := types.IdentityCreateAttestationRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode IdentityCreateAttestationRequest: "+err.Error())
	}
	a := body.AttestationData

	// Phase 1a: structural invariants.
	if err := validateIdentityCreateStructure(a); err != nil {
		return handler.NewErrorResponse(400, "invalid_attestation", err.Error())
	}

	// Phase 1b: per-function valid-modes (PI-11). Only applies to
	// identity-cert kinds; other kinds (rotation, retirement, revocation)
	// don't carry properties.mode and are exempt.
	if a.Kind() == types.KindIdentityCert {
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return handler.NewErrorResponse(400, "invalid_attestation",
				"decode identity-cert properties: "+err.Error())
		}
		_ = q // q used to determine top-level vs sub-controller via quorum lookup.
		attestingIsQuorum := quorumIsQuorumID(hctx.Store, hctx.LocationIndex, a.Attesting)
		if !modeAllowedForFunction(props.Mode, props.Function, attestingIsQuorum) {
			validModes := validModesForFunction(props.Function, attestingIsQuorum)
			return handler.NewErrorResponse(400, "invalid_mode_for_function",
				fmt.Sprintf("function=%s mode=%s not in valid_modes=%v (attesting_is_quorum=%t)",
					props.Function, props.Mode, validModes, attestingIsQuorum))
		}
	}

	// Phase 2 + 3: substrate compose + per-mode dispatch.
	path, embedded, err := derivePathForIdentity(a, hctx.Store)
	if err != nil {
		return handler.NewErrorResponse(400, "path_derivation_failed", err.Error())
	}
	if embedded {
		// embedded mode: zero attestation_hash signals not-bound; the
		// caller embeds the entity directly into its envelope.
		return handler.NewResponse(200, types.TypeIdentityCreateAttestationResult,
			types.IdentityCreateAttestationResultData{EmbeddedAttestation: &a})
	}
	attHash, err := att.Create(hctx, path, a)
	if err != nil {
		return handler.NewErrorResponse(400, "create_failed", err.Error())
	}
	return handler.NewResponse(200, types.TypeIdentityCreateAttestationResult,
		types.IdentityCreateAttestationResultData{AttestationHash: attHash})
}

// quorumIsQuorumID is a thin shim over quorum.IsQuorumID that locally
// imports just the namespace bit needed in ops.go (avoids a wider
// quorum-package dependency import for one call).
func quorumIsQuorumID(cs store.ContentStore, li store.LocationIndex, h hash.Hash) bool {
	if h.IsZero() {
		return false
	}
	// Lookup via the quorum path convention; quorum entities bind at
	// system/quorum/{q_hex}.
	ent, ok := cs.Get(h)
	if !ok {
		return false
	}
	return ent.Type == types.TypeQuorum
}

// rebindKinds is the normative property list of identity-context kinds
// where supersession may legitimately rebind attesting/attested per
// PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-1. Identity-cert rotation
// changes both attesting (new controller) and attested (new keypair); the
// strict-by-design substrate :supersede (which preserves attesting/attested)
// would block this, so PI-1 directs identity to call substrate :create
// directly with explicit supersedes for these kinds. Future identity-context
// kinds requiring the same treatment are added here via spec amendment.
var rebindKinds = map[string]struct{}{
	types.KindIdentityCert: {},
}

// handleSupersedeAttestation produces a successor identity-context
// attestation per §6 / PI-1.
//
// For kinds in rebindKinds (identity-cert): caller-supplied attesting/
// attested are honored; substrate :create is invoked directly with explicit
// supersedes — this enables controller rotation where both fields legitimately
// change.
//
// For other identity-context kinds (rotation-handoff, rotation-recovery,
// retirement): substrate :supersede semantics apply — predecessor's
// attesting/attested are preserved, and any caller-supplied values that
// differ are rejected as a structural violation.
func (h *Handler) handleSupersedeAttestation(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	att, _, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	body, err := types.IdentitySupersedeAttestationRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode IdentitySupersedeAttestationRequest: "+err.Error())
	}
	newAtt := body.AttestationData
	if newAtt.Supersedes == nil || newAtt.Supersedes.IsZero() {
		return handler.NewErrorResponse(400, "invalid_supersedes",
			"new_attestation.supersedes is required")
	}
	prevRef, err := loadAttestationRef(hctx.Store, *newAtt.Supersedes)
	if err != nil {
		return handler.NewErrorResponse(404, "previous_not_found", err.Error())
	}
	if prevRef.Data.Kind() != newAtt.Kind() {
		return handler.NewErrorResponse(400, "kind_mismatch",
			fmt.Sprintf("supersede crosses kinds: prev=%s new=%s", prevRef.Data.Kind(), newAtt.Kind()))
	}

	// PI-1 branch: REBIND_KINDS allow caller-supplied attesting/attested;
	// other identity-context kinds preserve predecessor's per substrate
	// :supersede semantics. Reject mismatches loudly rather than silently
	// rewriting — the caller asked for a specific shape.
	if _, rebind := rebindKinds[newAtt.Kind()]; !rebind {
		if newAtt.Attesting != prevRef.Data.Attesting {
			return handler.NewErrorResponse(400, "supersede_attesting_mismatch",
				fmt.Sprintf("kind=%s requires preserved attesting; predecessor=%s new=%s",
					newAtt.Kind(), prevRef.Data.Attesting, newAtt.Attesting))
		}
		if newAtt.Attested != prevRef.Data.Attested {
			return handler.NewErrorResponse(400, "supersede_attested_mismatch",
				fmt.Sprintf("kind=%s requires preserved attested; predecessor=%s new=%s",
					newAtt.Kind(), prevRef.Data.Attested, newAtt.Attested))
		}
	}

	if err := validateIdentityCreateStructure(newAtt); err != nil {
		return handler.NewErrorResponse(400, "invalid_attestation", err.Error())
	}
	path, embedded, err := derivePathForIdentity(newAtt, hctx.Store)
	if err != nil {
		return handler.NewErrorResponse(400, "path_derivation_failed", err.Error())
	}
	if embedded {
		return handler.NewErrorResponse(400, "embedded_supersede",
			"embedded mode cannot be superseded (no tree path to bind successor)")
	}
	attHash, err := att.Create(hctx, path, newAtt)
	if err != nil {
		return handler.NewErrorResponse(400, "create_failed", err.Error())
	}
	return handler.NewResponse(200, types.TypeIdentitySupersedeAttestationResult,
		types.IdentitySupersedeAttestationResultData{AttestationHash: attHash})
}

// handleRevokeAttestation produces a revocation attestation targeting an
// identity-context attestation per §6.
func (h *Handler) handleRevokeAttestation(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	att, _, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	body, err := types.IdentityRevokeAttestationRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode IdentityRevokeAttestationRequest: "+err.Error())
	}
	target, err := loadAttestationRef(hctx.Store, body.TargetHash)
	if err != nil {
		return handler.NewErrorResponse(404, "target_not_found", err.Error())
	}
	if !isIdentityKind(target.Data.Kind()) {
		return handler.NewErrorResponse(400, "not_identity_attestation",
			"target is not an identity-context attestation")
	}
	terminate := IdentityIsQuorumLink(hctx.Store, hctx.LocationIndex)
	find := attestation.DefaultFindAuthorizing(hctx.Store, hctx.LocationIndex, att.Index(), 0)
	chain, ok := attestation.WalkAttestingChain(target.Hash, target.Data, terminate, find, 0)
	if !ok || len(chain) == 0 {
		return handler.NewErrorResponse(400, "chain_to_quorum_not_found",
			"target's chain does not terminate at a known quorum")
	}
	quorumID := chain[len(chain)-1].Data.Attesting

	props, err := types.EncodeProperties(types.RevocationProperties{
		Kind:   types.KindRevocation,
		Reason: body.Reason,
	})
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	revAtt := types.AttestationData{
		Attesting:  quorumID,
		Attested:   body.TargetHash,
		Properties: props,
	}
	revEnt, err := revAtt.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_failed", err.Error())
	}
	// Revocation lives at the same audience tier as its target. Lifecycle
	// events targeting an identity-cert use sameTierPath. Revocations
	// targeting a non-cert lifecycle event walk to the underlying cert
	// for tier resolution.
	tierTarget, err := resolveTierTarget(target.Data, hctx.Store)
	if err != nil {
		return handler.NewErrorResponse(400, "tier_resolution_failed", err.Error())
	}
	path, err := sameTierPath(tierTarget, revEnt.ContentHash)
	if err != nil {
		return handler.NewErrorResponse(400, "path_derivation_failed", err.Error())
	}
	revHash, err := att.Create(hctx, path, revAtt)
	if err != nil {
		return handler.NewErrorResponse(400, "create_failed", err.Error())
	}

	// PI-13 (Rev 3): cascade cap cleanup. After a successful revoke of an
	// identity-cert (function=controller), walk the local peer→controller
	// caps and unbind any whose grantee matches the revoked controller's
	// `attested`. The matching cap signature at the V7 invariant pointer
	// path (/{local_peer_id}/system/signature/{cap_hex}) MUST be unbound
	// alongside per EXTENSION-IDENTITY v3.6 §6.0e. (The pre-v3.6 sibling
	// path {cap_path}/signature is also opportunistically unbound below
	// to clean up legacy data — no-op on caps issued post-v3.6.) On
	// partial failure emit a PI-5 recovery_signal event so the controller
	// can complete the cleanup.
	//
	// Convergence framing per the proposal: this is the ideal-state
	// behavior; peers that have not yet observed the revocation will
	// cascade locally when the revocation arrives via sync.
	if target.Data.Kind() == types.KindIdentityCert {
		cascadeCapCleanupOnRevoke(hctx, target.Data.Attested)
	}

	return handler.NewResponse(200, types.TypeIdentityRevokeAttestationResult,
		types.IdentityRevokeAttestationResultData{RevocationHash: revHash})
}

// cascadeCapCleanupOnRevoke unbinds local peer→controller caps whose
// grantee matches `revokedAttested`, plus their sibling signature
// entities. PI-13 (Rev 3). Partial failure emits a recovery_signal
// controller-event so the controller can complete the cleanup
// (tree:put({cap_path}, null) to clear stragglers).
func cascadeCapCleanupOnRevoke(hctx *handler.HandlerContext, revokedAttested hash.Hash) {
	if revokedAttested.IsZero() {
		return
	}
	entries := hctx.LocationIndex.List(localPeerToControllerCapPrefix + "/")
	var unboundFailures int
	for _, entry := range entries {
		// Skip sibling signature entries; they're handled per-cap below.
		if endsWithSignatureSuffix(entry.Path) {
			continue
		}
		capEnt, ok := hctx.Store.Get(entry.Hash)
		if !ok {
			continue
		}
		capData, err := types.CapabilityTokenDataFromEntity(capEnt)
		if err != nil {
			continue
		}
		if capData.Grantee != revokedAttested {
			continue
		}
		// Unbind the cap entity and its V7 invariant-pointer signature
		// binding (keyed by cap hash; a different subtree, removed
		// explicitly so revocation leaves no resolvable signature for the
		// revoked cap). Also sweep the legacy sibling-signature path
		// ({cap_path}/signature) for backward compatibility with caps
		// minted before EXTENSION-IDENTITY v3.6 removed that convention —
		// no-op on caps issued post-v3.6.
		if _, ok, _ := hctx.TreeRemove(entry.Path, "revoke_attestation-cascade-cap"); !ok {
			unboundFailures++
		}
		hctx.TreeRemove(entry.Path+"/signature", "revoke_attestation-cascade-sig-legacy")
		hctx.TreeRemove(types.InvariantSignaturePath(hctx.LocalPeerID.String(), entry.Hash), "revoke_attestation-cascade-invariant-sig")
	}
	if unboundFailures > 0 {
		_, _, _ = emitControllerEvent(
			hctx,
			types.EventSubkindRecoverySignal,
			HandlerIDRevokeCapCleanup,
			revokedAttested,
			types.KindRevocation,
			"cap_cleanup_partial",
			fmt.Sprintf("%d cap entries failed to unbind under prefix %s; controller intervention needed",
				unboundFailures, localPeerToControllerCapPrefix),
		)
	}
}

// endsWithSignatureSuffix reports whether path ends with "/signature".
// Used to skip sibling signature entries during cap cleanup so the cap
// entity is iterated first; the matching signature is then removed via
// {cap_path}/signature.
func endsWithSignatureSuffix(path string) bool {
	return len(path) >= len("/signature") && path[len(path)-len("/signature"):] == "/signature"
}

// handlePublishAttestation promotes/demotes a kind=identity-cert
// function=agent attestation across publication modes per §6 / §4.2a.
func (h *Handler) handlePublishAttestation(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	body, err := types.IdentityPublishAttestationRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode IdentityPublishAttestationRequest: "+err.Error())
	}
	if !isValidMode(body.NewMode) {
		return handler.NewErrorResponse(400, "invalid_mode", body.NewMode)
	}
	if body.NewMode == types.ModePerRelationship && (body.ContactID == nil || body.ContactID.IsZero()) {
		return handler.NewErrorResponse(400, "missing_contact_id",
			"per-relationship mode requires contact_id")
	}
	target, err := loadAttestationRef(hctx.Store, body.AttestationHash)
	if err != nil {
		return handler.NewErrorResponse(404, "attestation_not_found", err.Error())
	}
	if target.Data.Kind() != types.KindIdentityCert {
		return handler.NewErrorResponse(400, "not_identity_cert",
			"publish_attestation only applies to identity-cert kinds")
	}
	var props types.IdentityCertProperties
	if err := types.DecodeProperties(target.Data.Properties, &props); err != nil {
		return handler.NewErrorResponse(400, "properties_decode", err.Error())
	}
	if props.Function != types.FunctionAgent {
		return handler.NewErrorResponse(400, "not_agent",
			"publish_attestation only applies to function=agent certs")
	}

	// Phase 2: compute_paths. Both old_path and new_path are derived; the
	// new_path's hash segment MUST equal target.Hash (content-hash invariant
	// under move). Both paths returned in absolute form per V7 §1.4 / PI-3.
	oldPath, err := canonicalCertPath(target.Data)
	if err != nil {
		return handler.NewErrorResponse(400, "old_path_derivation", err.Error())
	}
	newPath := ""
	switch body.NewMode {
	case types.ModeInternal:
		newPath = internalCertPath(target.Hash)
	case types.ModePublic:
		newPath = publicCertPath(target.Hash)
	case types.ModePerRelationship:
		newPath = relationshipCertPath(*body.ContactID, target.Hash)
	case types.ModeEmbedded:
		return handler.NewErrorResponse(400, "publish_to_embedded",
			"cannot publish to embedded mode (no tree path)")
	}

	// Phase 3: MOVE with tombstone-style recovery (PI-3 Rev 3 / Go feedback
	// option B). bind(new) first — on failure, old binding remains intact
	// and there's no inconsistent state; surface error to caller. unbind(old)
	// second — on failure SHOULD retry once; on retry failure emit a
	// recovery_signal controller-event (PI-5) at
	// system/identity/events/.../publish_attestation/{att_hash}/{event_hash}
	// so the controller can complete the move via tree:put(old_path, null).
	if oldPath == newPath {
		// No-op move (mode unchanged or path coincides).
		return handler.NewResponse(200, types.TypeIdentityPublishAttestationResult,
			types.IdentityPublishAttestationResultData{NewPath: newPath})
	}

	// 3a. Bind at new path.
	if _, err := hctx.TreeSet(newPath, target.Hash, "publish_attestation-new"); err != nil {
		return handler.NewErrorResponse(500, "storage_error", "bind at new path: "+err.Error())
	}

	// 3b. Unbind old path (skip when there is no old binding).
	if oldPath != "" {
		if _, ok, _ := hctx.TreeRemove(oldPath, "publish_attestation-old"); !ok {
			// Retry once.
			if _, ok2, _ := hctx.TreeRemove(oldPath, "publish_attestation-old"); !ok2 {
				// Final failure — orphaned binding. Emit recovery_signal so
				// the controller can complete the move (tree:put(old, null))
				// or a clearing event records resolution.
				_, _, _ = emitControllerEvent(
					hctx,
					types.EventSubkindRecoverySignal,
					HandlerIDPublishMoveRebind,
					target.Hash,
					target.Data.Kind(),
					"unbind_old_path_failed",
					"old_path="+oldPath+" remained bound after retry; entity also bound at new_path="+newPath,
				)
			}
		}
	}

	return handler.NewResponse(200, types.TypeIdentityPublishAttestationResult,
		types.IdentityPublishAttestationResultData{NewPath: newPath})
}

// handleProcessAttestation is the convergence point for any identity-
// context attestation entering the local tree at the named subtrees per
// EXTENSION-IDENTITY v3.3 §6.3 (SI-10). Three phases:
//
//	Phase 1 — validate via IdentityVerifyCert.
//	Phase 2a — fail-closed unbind on validation failure (return error).
//	Phase 2b — side-effect dispatch (deterministic per kind).
//	Phase 3 — quorum-publish caching (handled by quorum's sync hook for
//	          system/quorum/{q}/event/... arrivals; identity caches the
//	          contacts/{handle}/quorum-publish entry when published_handle
//	          is set on a quorum-publish that targets a contact identity).
//
// Side-effect failures are best-effort + logged; the attestation stays
// tree-bound (validation succeeded; side-effect failure is recoverable;
// post-state is "validated; partial side-effect application; needs
// operator intervention"). Re-running process_attestation on the same
// attestation is idempotent for validation and SHOULD be idempotent for
// side effects (ops are designed to be re-runnable).
func (h *Handler) handleProcessAttestation(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	att, q, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	path := ""
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		path = hctx.Resource.Targets[0]
	}
	if path == "" {
		return handler.NewErrorResponse(400, "missing_resource_path",
			"process_attestation requires a resource target path")
	}
	entHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return handler.NewErrorResponse(404, "path_not_bound", path)
	}
	ent, ok := hctx.Store.Get(entHash)
	if !ok || ent.Type != types.TypeAttestation {
		return handler.NewErrorResponse(400, "not_an_attestation", path)
	}
	a, err := types.AttestationDataFromEntity(ent)
	if err != nil {
		return handler.NewErrorResponse(400, "decode_failed", err.Error())
	}
	if !isIdentityKind(a.Kind()) {
		// Non-identity kind that slipped through (e.g., a quorum-publish
		// arriving at an identity-cert path by mistake). Best-effort no-op.
		return &handler.Response{Status: 200}, nil
	}

	// Phase 1 — validate.
	if err := IdentityVerifyCert(hctx.Store, hctx.LocationIndex, att.Index(), q, entHash, a); err != nil {
		// Phase 2a — fail-closed unbind (cross-peer arrivals only per
		// PR-8.3 / §6.3 — sync_hook filters out local-create ops via
		// isInternalProcessAttestationOp before reaching here).
		hctx.TreeRemove(path, "process_attestation-failed")
		return handler.NewErrorResponse(403, "verify_failed", err.Error())
	}

	// Phase 2 — dispatch side-effects per (kind, function). Each handler
	// runs independently — failure of one MUST NOT propagate to others.
	failures := h.applyProcessAttestationSideEffects(hctx, entHash, a)

	// Phase 3 — emit FAILURE controller-events (PI-5 Rev 3). v2 ships
	// FAILURE-only; informational events on success are out of scope.
	for _, f := range failures {
		_, _, _ = emitControllerEvent(hctx, f.subkind, f.handlerID, entHash, a.Kind(), f.errCode, f.errDetail)
	}

	return &handler.Response{Status: 200}, nil
}

// sideEffectFailure captures one phase-2 handler's failure for emission as
// a phase-3 controller-event. subkind is recovery_signal when the failure
// left orphaned/inconsistent state; failure_observation when post-state is
// consistent.
type sideEffectFailure struct {
	subkind   string
	handlerID string
	errCode   string
	errDetail string
}

// applyProcessAttestationSideEffects runs the per-kind side-effect
// dispatch per §6.3 Phase 2 (PI-5 Rev 3). Each handler runs independently
// — a failure in one MUST NOT propagate to others. Returns the list of
// failures for phase-3 controller-event emission.
func (h *Handler) applyProcessAttestationSideEffects(
	hctx *handler.HandlerContext,
	attHash hash.Hash,
	a types.AttestationData,
) []sideEffectFailure {
	var failures []sideEffectFailure
	switch a.Kind() {
	case types.KindIdentityCert:
		// Per-function dispatch (agent / controller / identifier). The
		// real wiring for local cap issuance lives in the configure flow;
		// process_attestation is the convergence path for cross-peer
		// arrivals where the local peer doesn't hold the keypair to act
		// on the cert. No phase-2 handler runs here in v2 — informational
		// success events are out of scope, and there's no failure path
		// without a side-effect to fail.

	case types.KindIdentityRotationHandoff:
		// Dual-sig handoff — the new key chains via attesting back to
		// the prior cert. No additional caches to update; chain walks
		// already include handoffs via IdentityConfersFunction (SI-13).

	case types.KindIdentityRotationRecovery:
		// Compromise-recovery — the handle cache for old_handle was
		// already validated in IdentityVerifyCert via §9.4 fail-closed.
		// Update the handle cache to point at the new attested key.
		var props types.IdentityRotationRecoveryProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			failures = append(failures, sideEffectFailure{
				subkind:   types.EventSubkindFailureObservation,
				handlerID: HandlerIDUpdateHandleCacheTo,
				errCode:   "properties_decode", errDetail: err.Error(),
			})
		} else if props.OldHandle != nil && !props.OldHandle.IsZero() {
			if oldEntry, ok := hctx.LocationIndex.Get(contactsQuorumPublishPath(*props.OldHandle)); ok {
				hctx.LocationIndex.Set(contactsQuorumPublishPath(a.Attested), oldEntry)
				hctx.LocationIndex.Remove(contactsQuorumPublishPath(*props.OldHandle))
			}
		}

	case types.KindIdentityRetirement:
		// Retirement — revoke local caps issued for the retired peer.
		// On partial failure (target resolves but cap removal raises),
		// emit recovery_signal: the cap-cleanup didn't complete and the
		// controller may need to intervene.
		var props types.IdentityRetirementProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			failures = append(failures, sideEffectFailure{
				subkind:   types.EventSubkindFailureObservation,
				handlerID: HandlerIDRevokeLocalCaps,
				errCode:   "properties_decode", errDetail: err.Error(),
			})
			break
		}
		if props.TargetCert.IsZero() {
			break
		}
		targetEnt, ok := hctx.Store.Get(props.TargetCert)
		if !ok {
			failures = append(failures, sideEffectFailure{
				subkind:   types.EventSubkindFailureObservation,
				handlerID: HandlerIDRevokeLocalCaps,
				errCode:   "target_cert_not_found",
				errDetail: props.TargetCert.String(),
			})
			break
		}
		targetData, err := types.AttestationDataFromEntity(targetEnt)
		if err != nil {
			failures = append(failures, sideEffectFailure{
				subkind:   types.EventSubkindFailureObservation,
				handlerID: HandlerIDRevokeLocalCaps,
				errCode:   "target_decode", errDetail: err.Error(),
			})
			break
		}
		hctx.TreeRemove(localPeerToControllerCapPath(targetData.Attested), "process_attestation-revoke-cap")

	case types.KindRevocation:
		// Authority-revocation already verified in IdentityVerifyCert.
		// Liveness flips via FindRevocationsFor + IsAttestationLive on
		// the next query. No phase-2 work required in v2.
	}
	return failures
}

// validateIdentityCreateStructure enforces structural invariants for
// identity-context create requests per §3.3 / §4.x.
func validateIdentityCreateStructure(a types.AttestationData) error {
	if a.Attesting.IsZero() {
		return errString("attesting must be non-zero")
	}
	if a.Attested.IsZero() {
		return errString("attested must be non-zero")
	}
	switch a.Kind() {
	case types.KindIdentityCert:
		var props types.IdentityCertProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return errString("decode identity-cert properties: " + err.Error())
		}
		if !isValidFunction(props.Function) {
			return errString("invalid function: " + props.Function)
		}
		if !isValidMode(props.Mode) {
			return errString("invalid mode: " + props.Mode)
		}
		if props.Mode == types.ModePerRelationship && (props.ContactID == nil || props.ContactID.IsZero()) {
			return errString("per-relationship mode requires contact_id")
		}
		if props.Mode != types.ModePerRelationship && props.ContactID != nil && !props.ContactID.IsZero() {
			return errString("contact_id is forbidden outside per-relationship mode")
		}
	case types.KindIdentityRotationHandoff:
		var props types.IdentityRotationHandoffProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return errString("decode handoff properties: " + err.Error())
		}
		if props.TargetCert.IsZero() {
			return errString("identity-rotation-handoff requires target_cert")
		}
	case types.KindIdentityRotationRecovery:
		var props types.IdentityRotationRecoveryProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return errString("decode recovery properties: " + err.Error())
		}
		if props.TargetCert.IsZero() {
			return errString("identity-rotation-recovery requires target_cert")
		}
	case types.KindIdentityRetirement:
		var props types.IdentityRetirementProperties
		if err := types.DecodeProperties(a.Properties, &props); err != nil {
			return errString("decode retirement properties: " + err.Error())
		}
		if props.TargetCert.IsZero() {
			return errString("identity-retirement requires target_cert")
		}
	default:
		return errString("unknown identity-context kind: " + a.Kind())
	}
	return nil
}

// derivePathForIdentity selects the canonical storage path for an
// identity-context attestation per §5.3. Identity-cert paths come from
// canonicalCertPath; lifecycle-event paths come from sameTierPath against
// the resolved target cert. Returns embedded=true (with empty path) for
// identity-cert mode=embedded.
func derivePathForIdentity(a types.AttestationData, cs store.ContentStore) (path string, embedded bool, err error) {
	switch a.Kind() {
	case types.KindIdentityCert:
		p, err := canonicalCertPath(a)
		if err != nil {
			return "", false, err
		}
		if p == "" {
			return "", true, nil
		}
		return p, false, nil
	case types.KindIdentityRotationHandoff,
		types.KindIdentityRotationRecovery,
		types.KindIdentityRetirement:
		var common struct {
			TargetCert hash.Hash `cbor:"target_cert"`
		}
		if err := types.DecodeProperties(a.Properties, &common); err != nil {
			return "", false, fmt.Errorf("decode lifecycle target_cert: %w", err)
		}
		if common.TargetCert.IsZero() {
			return "", false, errString("lifecycle event requires target_cert")
		}
		target, err := loadAttestationRef(cs, common.TargetCert)
		if err != nil {
			return "", false, fmt.Errorf("target cert lookup: %w", err)
		}
		ent, err := a.ToEntity()
		if err != nil {
			return "", false, err
		}
		p, err := sameTierPath(target.Data, ent.ContentHash)
		if err != nil {
			return "", false, err
		}
		return p, false, nil
	default:
		return "", false, errString("unsupported kind for create: " + a.Kind())
	}
}

// resolveTierTarget walks from a (possibly lifecycle-event) attestation
// down to the underlying identity-cert that determines its audience tier.
// For an identity-cert, returns a itself. For a lifecycle event, decodes
// target_cert and returns the cert it references.
func resolveTierTarget(a types.AttestationData, cs store.ContentStore) (types.AttestationData, error) {
	if a.Kind() == types.KindIdentityCert {
		return a, nil
	}
	var common struct {
		TargetCert hash.Hash `cbor:"target_cert"`
	}
	if err := types.DecodeProperties(a.Properties, &common); err != nil {
		return types.AttestationData{}, err
	}
	if common.TargetCert.IsZero() {
		return types.AttestationData{}, errString("missing target_cert")
	}
	ref, err := loadAttestationRef(cs, common.TargetCert)
	if err != nil {
		return types.AttestationData{}, err
	}
	return ref.Data, nil
}
