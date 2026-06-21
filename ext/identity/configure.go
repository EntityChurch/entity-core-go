package identity

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/quorum"
)

// configureWriter abstracts the difference between L0 startup writes
// (direct cs.Put + li.Set) and dispatch-time writes (hctx.Store.Put +
// hctx.TreeSet, which propagates MutationContext to sync hooks).
type configureWriter interface {
	put(ent entity.Entity, path, op string) (hash.Hash, error)
	remove(path, op string) (hash.Hash, bool)
}

type startupWriter struct {
	cs store.ContentStore
	li store.LocationIndex
}

func (w *startupWriter) put(ent entity.Entity, path, op string) (hash.Hash, error) {
	h, err := w.cs.Put(ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("put %s: %w", path, err)
	}
	if err := w.li.Set(path, h); err != nil {
		return hash.Hash{}, fmt.Errorf("bind %s: %w", path, err)
	}
	return h, nil
}

func (w *startupWriter) remove(path, op string) (hash.Hash, bool) {
	return w.li.Remove(path)
}

type hctxWriter struct {
	hctx *handler.HandlerContext
}

func (w *hctxWriter) put(ent entity.Entity, path, op string) (hash.Hash, error) {
	h, err := w.hctx.Store.Put(ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("put %s: %w", path, err)
	}
	if _, err := w.hctx.TreeSet(path, h, op); err != nil {
		return hash.Hash{}, fmt.Errorf("bind %s: %w", path, err)
	}
	return h, nil
}

func (w *hctxWriter) remove(path, op string) (hash.Hash, bool) {
	h, ok, _ := w.hctx.TreeRemove(path, op)
	return h, ok
}

// Startup is the L0 entry point for the first configure on a fresh peer
// (§6.9, §12.5). Runs configure logic directly against the peer's store
// and location index without dispatch authorization — peer-owner authority,
// since no peer-config or peer→controller cap exists yet.
//
// Conformance is observable via post-state, not wire trace: after Startup
// returns successfully, the tree contains peer-config and one local peer→
// controller cap per live top-level controller cert.
//
// Terminology note (PI-7 Rev 3 disambiguation): "Startup" here is the
// identity-layer authority-bootstrapping period (when no cap chain is yet
// provisioned) — DISTINCT from V7's "bootstrap types" terminology (V7 §2,
// the type-registration table loaded at peer instantiation). The two
// concepts overlap in time (both happen at peer initialization) but
// address different surfaces: V7 bootstrap types are the type-system
// foundation; identity startup is the authority-chain provisioning period.
// V7's "bootstrap types" terminology is slated for future cleanup but is
// out of scope for this round.
func Startup(
	ctx context.Context,
	cs store.ContentStore,
	li store.LocationIndex,
	att *attestation.Handler,
	q *quorum.Handler,
	kp crypto.Keypair,
	localIdentity entity.Entity,
	req types.IdentityConfigureRequestData,
) (types.IdentityConfigureResultData, error) {
	w := &startupWriter{cs: cs, li: li}
	return runConfigure(ctx, cs, li, w, att, q, kp, localIdentity, req)
}

// handleConfigure is the post-startup dispatch path (§6.1). The
// dispatcher authorizes the call via the caller's local peer→controller
// cap; this method runs the same configure logic that Startup runs but
// writes through hctx so sync hooks observe the changes.
func (h *Handler) handleConfigure(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}
	att, q, errResp := h.substrate()
	if errResp != nil {
		return errResp, nil
	}
	kp, identityEnt, errResp := h.authority()
	if errResp != nil {
		return errResp, nil
	}

	var params types.IdentityConfigureRequestData
	if err := ecf.Decode(req.Params.Data, &params); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode configure-request: "+err.Error())
	}

	w := &hctxWriter{hctx: hctx}
	result, err := runConfigure(ctx, hctx.Store, hctx.LocationIndex, w, att, q, kp, identityEnt, params)
	if err != nil {
		return errorFromConfigureErr(err)
	}
	return handler.NewResponse(200, types.TypeIdentityConfigureResult, result)
}

// runConfigure implements §6.1 configure semantics in the 5-phase ordered
// pseudocode of PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-2 (Rev 3). Phases
// execute in order; failure at phase N short-circuits subsequent phases.
//
//	Phase 1: validate_inputs (purely structural)
//	Phase 2: enumerate_live_controller_certs + binding-chain liveness check
//	Phase 3: verify_each_controller_cert
//	Phase 4: issue_local_caps
//	Phase 5: register_bindings (persist peer_config)
//
// Empty bindings is a valid configure shape — phase 1 passes, phases 2-4
// execute (caps issued for live controllers), phase 5 persists peer_config
// with bindings: [].
func runConfigure(
	ctx context.Context,
	cs store.ContentStore,
	li store.LocationIndex,
	w configureWriter,
	att *attestation.Handler,
	q *quorum.Handler,
	kp crypto.Keypair,
	localIdentity entity.Entity,
	params types.IdentityConfigureRequestData,
) (types.IdentityConfigureResultData, error) {
	// Phase 1: validate_inputs (structural — does NOT reference phase 2 output).
	if !quorum.IsQuorumID(cs, li, params.TrustsQuorum) {
		return zeroResult(), &configureErr{code: 404, kind: "quorum_not_found",
			msg: "quorum entity not found: " + params.TrustsQuorum.String()}
	}
	for i, b := range params.Bindings {
		if err := validateBindingStructure(cs, b); err != nil {
			if ce, ok := err.(*configureErr); ok {
				ce.msg = fmt.Sprintf("bindings[%d]: %s", i, ce.msg)
				return zeroResult(), ce
			}
			return zeroResult(), err
		}
	}

	// Phase 2: enumerate live controllers, then post-enumeration binding-
	// liveness check (per Rev 3 phase-ordering fix).
	live := enumerateLiveControllerCerts(cs, li, att.Index(), q, params.TrustsQuorum)
	if len(live) == 0 {
		return zeroResult(), &configureErr{code: 404, kind: "no_live_controller",
			msg: "no live top-level controller cert under quorum " + params.TrustsQuorum.String()}
	}
	for i, b := range params.Bindings {
		if err := validateBindingControllerLive(cs, att.Index(), b, live); err != nil {
			if ce, ok := err.(*configureErr); ok {
				ce.msg = fmt.Sprintf("bindings[%d]: %s", i, ce.msg)
				return zeroResult(), ce
			}
			return zeroResult(), err
		}
	}

	// Phase 3: verify each live controller cert (K-of-N for top-level,
	// signature-chain for sub-controllers via IdentityVerifyCert).
	for _, c := range live {
		if err := IdentityVerifyCert(cs, li, att.Index(), q, c.Hash, c.Data); err != nil {
			return zeroResult(), &configureErr{code: 403, kind: "controller_invalid",
				msg: err.Error()}
		}
	}

	// Phase 4: issue one local peer→controller cap per distinct verified
	// controller key (PI-9 cap path + PI-10 sibling signature). `live` carries
	// one entry per attestation, so a K-of-N quorum produces K entries that
	// share the same Attested key; without dedupe Phase 4 mints K caps all
	// bound at localPeerToControllerCapPath(controllerKey), only the last
	// survives in the location index, and the prior K-1 caps + their
	// signatures orphan in the content store on every restart. Caps are
	// issued BEFORE peer-config so a phase-4 failure leaves no peer-config
	// persisted.
	seen := make(map[hash.Hash]struct{}, len(live))
	caps := make([]hash.Hash, 0, len(live))
	for _, c := range live {
		controllerKey := c.Data.Attested
		if _, dup := seen[controllerKey]; dup {
			continue
		}
		seen[controllerKey] = struct{}{}
		capHash, err := issueLocalPeerToControllerCap(w, kp, localIdentity, controllerKey, params.ControllerGrants)
		if err != nil {
			return zeroResult(), &configureErr{code: 500, kind: "controller_cap_issue", msg: err.Error()}
		}
		caps = append(caps, capHash)
	}

	// Phase 5: register_bindings — persist peer-config last.
	pc := types.IdentityPeerConfigData{
		TrustsQuorum:     params.TrustsQuorum,
		ControllerGrants: params.ControllerGrants,
		Bindings:         params.Bindings,
	}
	pcEnt, err := pc.ToEntity()
	if err != nil {
		return zeroResult(), &configureErr{code: 500, kind: "peer_config_build", msg: err.Error()}
	}
	if _, err := w.put(pcEnt, identityPeerConfigPath, "configure-peer-config"); err != nil {
		return zeroResult(), &configureErr{code: 500, kind: "peer_config_write", msg: err.Error()}
	}

	return types.IdentityConfigureResultData{
		PeerConfigPath:            identityPeerConfigPath,
		LocalPeerToControllerCaps: caps,
	}, nil
}

// enumerateLiveControllerCerts returns all live top-level identity-cert
// (function=controller) attestations under the given quorum. Per v3.3
// SI-13 the predicate uses IdentityConfersFunction so handoff/recovery
// attestations that inherit the controller function from their target_cert
// are included; retirements terminate.
func enumerateLiveControllerCerts(
	cs store.ContentStore,
	li store.LocationIndex,
	ix *attestation.Index,
	q *quorum.Handler,
	quorumID hash.Hash,
) []attestation.AttestationRef {
	candidates := attestation.FindAttestationsBy(cs, ix, quorumID, func(_ hash.Hash, a types.AttestationData) bool {
		return IdentityConfersFunction(cs, a, types.FunctionController)
	})
	var live []attestation.AttestationRef
	for _, c := range candidates {
		if attestation.IsAttestationLive(cs, li, ix, c.Hash, c.Data, 0) {
			live = append(live, c)
		}
	}
	return live
}

// validateBindingStructure runs PI-2 phase-1 binding checks: non-zero
// hashes, attestations resolve, kind/function shape matches expected.
// Pure structural — does NOT reference phase 2 enumeration output.
//
// Per §6.1: handle_cert MUST be function=controller (3-key default) or
// function=identifier (4-key advanced); agent_cert MUST be function=agent.
func validateBindingStructure(cs store.ContentStore, b types.IdentityBindingData) error {
	if b.HandleCert.IsZero() {
		return &configureErr{code: 400, kind: "binding_missing_handle_cert",
			msg: "binding.handle_cert is required"}
	}
	if b.AgentCert.IsZero() {
		return &configureErr{code: 400, kind: "binding_missing_agent_cert",
			msg: "binding.agent_cert is required"}
	}
	handleRef, err := loadAttestationRef(cs, b.HandleCert)
	if err != nil {
		return &configureErr{code: 404, kind: "binding_cert_not_found",
			msg: "handle_cert: " + err.Error()}
	}
	if handleRef.Data.Kind() != types.KindIdentityCert {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "handle_cert is not an identity-cert"}
	}
	var handleProps types.IdentityCertProperties
	if err := types.DecodeProperties(handleRef.Data.Properties, &handleProps); err != nil {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "handle_cert properties decode: " + err.Error()}
	}
	if handleProps.Function != types.FunctionController && handleProps.Function != types.FunctionIdentifier {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "handle_cert function must be controller or identifier, got " + handleProps.Function}
	}
	agentRef, err := loadAttestationRef(cs, b.AgentCert)
	if err != nil {
		return &configureErr{code: 404, kind: "binding_cert_not_found",
			msg: "agent_cert: " + err.Error()}
	}
	if agentRef.Data.Kind() != types.KindIdentityCert {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "agent_cert is not an identity-cert"}
	}
	var agentProps types.IdentityCertProperties
	if err := types.DecodeProperties(agentRef.Data.Properties, &agentProps); err != nil {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "agent_cert properties decode: " + err.Error()}
	}
	if agentProps.Function != types.FunctionAgent {
		return &configureErr{code: 400, kind: "binding_cert_wrong_kind",
			msg: "agent_cert function must be agent, got " + agentProps.Function}
	}
	return nil
}

// validateBindingControllerLive runs PI-2 phase-2 post-enumeration check:
// the binding's agent_cert must chain (via attesting) to a controller in
// the live set. Prevents bindings to retired controllers.
func validateBindingControllerLive(
	cs store.ContentStore,
	ix *attestation.Index,
	b types.IdentityBindingData,
	live []attestation.AttestationRef,
) error {
	agentRef, err := loadAttestationRef(cs, b.AgentCert)
	if err != nil {
		// Phase 1 should have caught this; defensive only.
		return &configureErr{code: 404, kind: "binding_cert_not_found",
			msg: "agent_cert: " + err.Error()}
	}
	liveSet := make(map[hash.Hash]struct{}, len(live))
	for _, c := range live {
		liveSet[c.Hash] = struct{}{}
	}
	// Direct attesting may already point at a live controller (3-key default).
	if _, ok := liveSet[agentRef.Data.Attesting]; ok {
		return nil
	}
	// Sub-controller chain: walk back via attesting. Per spec §5.1
	// "multi-context peers note", we need a custom find that filters by
	// THIS configure's liveSet — DefaultFindAuthorizing's deterministic
	// tie-break can pick a live cert from a different quorum (different
	// identity context) when the same peer is authorized under multiple
	// quorums. We want the cert whose hash is in OUR liveSet.
	if findCertInLiveSetByChain(cs, ix, agentRef.Data.Attesting, liveSet, attestation.DefaultMaxChainDepth) {
		return nil
	}
	return &configureErr{code: 400, kind: "binding_controller_not_live",
		msg: "agent_cert.attesting does not chain to any live controller in the trusted quorum"}
}

// findCertInLiveSetByChain walks attestations targeting peerHash looking
// for one whose hash is in liveSet, then recursively walks each candidate's
// own attesting chain (sub-controller path). Returns true if any path
// terminates in liveSet within maxDepth. Filters by current-context
// liveSet to avoid the "multi-context peers" pitfall: the same peer may
// be authorized under multiple unrelated quorums, and only the cert in
// THIS configure's liveSet is the right authorizing edge.
func findCertInLiveSetByChain(cs store.ContentStore, ix *attestation.Index, peerHash hash.Hash, liveSet map[hash.Hash]struct{}, maxDepth int) bool {
	if maxDepth <= 0 {
		return false
	}
	candidates := attestation.FindAttestationsTargeting(cs, ix, peerHash, nil)
	for _, c := range candidates {
		if _, ok := liveSet[c.Hash]; ok {
			return true
		}
		if findCertInLiveSetByChain(cs, ix, c.Data.Attesting, liveSet, maxDepth-1) {
			return true
		}
	}
	return false
}

// issueLocalPeerToControllerCap issues a single-sig V7 capability token from
// the local agent's keypair authorizing `controllerKey` to act on the
// configured grant scope per §6.1 step 6 / §11.6. Caps are persisted at
// localPeerToControllerCapPath(controllerKey).
func issueLocalPeerToControllerCap(
	w configureWriter,
	kp crypto.Keypair,
	localIdentity entity.Entity,
	controllerKey hash.Hash,
	grants []types.GrantEntry,
) (hash.Hash, error) {
	if controllerKey.IsZero() {
		return hash.Hash{}, fmt.Errorf("controllerKey must be non-zero")
	}
	// CreatedAt fixed at zero so the cap is content-deterministic across
	// re-issues. The local-peer→controller cap has no TTL and is never
	// consulted for time-based validation, so a wall-clock CreatedAt only
	// served to mint a fresh content hash on every configure/re-apply —
	// which on the bundle re-apply path (ApplyIdentityBundle) leaked a cap
	// entity + invariant-pointer signature + a new signature path every
	// restart. Zero matches the self-issued handler-grant convention in
	// core/peer createHandlerGrants, making re-apply an idempotent no-op
	// (same inputs → same hashes → same Puts at the same paths).
	cap := types.CapabilityTokenData{
		Grants:    grants,
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   controllerKey,
		CreatedAt: 0,
	}
	if err := cap.ValidateStructure(); err != nil {
		return hash.Hash{}, err
	}
	capEnt, err := cap.ToEntity()
	if err != nil {
		return hash.Hash{}, err
	}
	capPath := localPeerToControllerCapPath(controllerKey)
	if _, err := w.put(capEnt, capPath, "configure-controller-cap"); err != nil {
		return hash.Hash{}, err
	}
	// Sign the cap and bind ONLY at the V7 invariant pointer path
	// /{granter_peer_id}/system/signature/{cap_content_hash_hex} per
	// EXTENSION-IDENTITY v3.6 §6.0e (and the matching §6.0a Phase 4
	// pseudocode in v3.7). The prior PI-10 sibling-path
	// ({capPath}/signature) convention is removed entirely — discovery
	// walks find chain-participating cap signatures at the invariant
	// pointer (V7 §3.5 v7.44 / §6.2), not at an extension-private sibling.
	// Symmetric to ROLE v2.0 Amendment 3 (CP-3).
	sig := kp.Sign(capEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return hash.Hash{}, err
	}
	idData, err := types.PeerDataFromEntity(localIdentity)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("resolve local peer_id for invariant signature path: %w", err)
	}
	// v7.65 §1.5: peer_id derives from (public_key, key_type).
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return hash.Hash{}, fmt.Errorf("resolve local peer_id: unsupported key_type %q", idData.KeyType)
	}
	localPID, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("derive local peer_id: %w", err)
	}
	if _, err := w.put(sigEnt, types.InvariantSignaturePath(string(localPID), capEnt.ContentHash), "configure-controller-cap-sig-invariant"); err != nil {
		return hash.Hash{}, err
	}
	return capEnt.ContentHash, nil
}

// configureErr is a typed error for configure flow steps. The handler
// translates these into wire-level error responses.
type configureErr struct {
	code uint
	kind string
	msg  string
}

func (e *configureErr) Error() string { return e.kind + ": " + e.msg }

func errorFromConfigureErr(err error) (*handler.Response, error) {
	if ce, ok := err.(*configureErr); ok {
		return handler.NewErrorResponse(ce.code, ce.kind, ce.msg)
	}
	return handler.NewErrorResponse(500, "internal", err.Error())
}

func zeroResult() types.IdentityConfigureResultData {
	return types.IdentityConfigureResultData{}
}
