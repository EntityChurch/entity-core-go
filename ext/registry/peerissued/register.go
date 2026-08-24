// Package peerissued live-registration surface per EXTENSION-REGISTRY §6a.9.
//
// The Backend (peerissued.go) is RECEIVER-side trust logic — it verifies
// bindings that a registry has signed. The Issuer (this file) is the
// REGISTRY-side handler that lets publishers self-register against a
// running registry. They are deliberately decoupled — a peer can run either
// half, both halves, or neither.
//
// Handler operations per §6a.9:
//   - register-request(req) → binding_hash | rejection
//   - revoke-request(binding_hash, reason) → ()
//   - renew-request(binding_hash, ttl) → binding_hash    (supersedes-chain)
//
// Admission per §6a.9.1 — Layer-1 (target_peer_id ownership-proof signature,
// always required) + Layer-2 (issuer-policy: open / allowlist / manual;
// `domain-control` is DEFERRED to the web-native domain-proof co-design and
// MUST be rejected here).
//
// Replay defense: the (target_peer_id, nonce) pair MUST NOT be re-used within
// the configured issued_at window. The Issuer tracks seen nonces in-memory
// and evicts them when their associated request.issued_at falls out of the
// window.

package peerissued

import (
	"context"
	"encoding/hex"
	"fmt"
	"path"
	"reflect"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// IssuerHandlerPattern is the handler-registration pattern carrying the
// three live-registration operations. The receiver-side Backend's resolve
// path stays at the meta-resolver in ext/registry; the registry-side
// operations live here.
const IssuerHandlerPattern = "system/registry/peer-issued"

// Operation names per §6a.9 (the three registration ops) and §6a.9.2 (the
// two policy-management ops).
const (
	OpRegisterRequest = "register-request"
	OpRevokeRequest   = "revoke-request"
	OpRenewRequest    = "renew-request"

	// §6a.9.2, RATIFIED 2026-08-10. Both gated by
	// types.CapRegistryManageIssuerPolicy — they are operator surface, and
	// deliberately absent from RequestBindingSeedGrants().
	OpSetIssuerPolicy = "set-issuer-policy"
	OpGetIssuerPolicy = "get-issuer-policy"
)

// DefaultReplayWindowMillis is the default issued_at window inside which the
// Issuer remembers nonces for replay defense. Ten minutes is the cohort-
// pragmatic default; operators MAY override via WithReplayWindow.
const DefaultReplayWindowMillis uint64 = 10 * 60 * 1000

// IssuerOption configures an Issuer at construction.
type IssuerOption func(*Issuer)

// WithIssuerClock overrides the wall-clock the Issuer uses for replay-window
// math and IssuedAt stamping. Default: real time.UnixMilli().
func WithIssuerClock(c func() uint64) IssuerOption {
	return func(i *Issuer) { i.clock = c }
}

// WithReplayWindow overrides the issued_at window (ms) inside which the
// Issuer enforces nonce uniqueness per target_peer_id.
func WithReplayWindow(ms uint64) IssuerOption {
	return func(i *Issuer) { i.replayWindow = ms }
}

// WithSeedPolicy carries an out-of-band-configured policy (a CLI flag, an
// operator's startup config) so SeedPolicy can write it into the tree once
// the store exists.
//
// §6a.9.2 makes resolution order store-first `[MUST]`, and is explicit that
// out-of-band arming is "a **seed for that entity**, never a parallel source
// consulted at request time." This replaces the former WithFallbackPolicy,
// which was exactly that prohibited parallel source: it was consulted by
// loadPolicy on every request and shadowed nothing, but it meant a peer armed
// by flag had no policy entity in its tree, so get-issuer-policy would have
// reported `not_found` on a registry that was demonstrably running a mode.
func WithSeedPolicy(p types.IssuerPolicyData) IssuerOption {
	return func(i *Issuer) {
		copy := p
		i.seedPolicy = &copy
	}
}

// Issuer is the registry-side handler implementing §6a.9 live registration.
// One Issuer per registry — it is tied to one signing keypair (the
// registry's identity) and signs every binding it issues with that key.
//
// Two construction modes match the entity-peer wiring lifecycle:
//   - NewIssuer(kp, opts...) — tests / standalone use where the keypair is
//     already in hand.
//   - NewIssuerForSetup(opts...) + SetupAuthority(kp) — builder path: the
//     Issuer is registered via peer.WithHandler before peer.Build() runs;
//     SetupAuthority installs the keypair post-build (mirrors the
//     SetupAuthority pattern used by handlers/capability/identity/role).
//
// Handle() rejects requests with 503 "not_ready" if SetupAuthority has not
// yet been called.
type Issuer struct {
	mu             sync.Mutex
	keypair        crypto.Keypair
	signerHash     hash.Hash // content_hash(canonical(system/peer for keypair)) — the SignatureData.Signer value
	ready          bool

	seenNonces   map[string]uint64 // "target_peer_id|hex(nonce)" → request.issued_at
	clock        func() uint64
	replayWindow uint64

	// seedPolicy is the out-of-band-armed policy awaiting a store to be
	// written into (§6a.9.2 store-first). It is NEVER read on the request
	// path — see SeedPolicy and loadPolicy.
	seedPolicy *types.IssuerPolicyData
}

// NewIssuer constructs an Issuer signing under `kp`. The registry's system/peer
// entity is derived from the keypair so the SignatureData.Signer field
// matches the on-wire convention.
func NewIssuer(kp crypto.Keypair, opts ...IssuerOption) (*Issuer, error) {
	i := NewIssuerForSetup(opts...)
	if err := i.SetupAuthority(kp); err != nil {
		return nil, err
	}
	return i, nil
}

// NewIssuerForSetup constructs an unauthorized Issuer ready to be wired
// into a peer builder. SetupAuthority MUST be called before any request
// reaches Handle (typically right after peer.Build).
func NewIssuerForSetup(opts ...IssuerOption) *Issuer {
	i := &Issuer{
		seenNonces:   make(map[string]uint64),
		clock:        defaultClock,
		replayWindow: DefaultReplayWindowMillis,
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// SetupAuthority installs the registry's signing keypair on an Issuer that
// was constructed via NewIssuerForSetup. Safe to call multiple times; the
// last call wins (mirrors handler/identity/role SetupAuthority semantics).
func (i *Issuer) SetupAuthority(kp crypto.Keypair) error {
	identityEnt, err := kp.IdentityEntity()
	if err != nil {
		return fmt.Errorf("peerissued.Issuer.SetupAuthority: build identity entity: %w", err)
	}
	i.mu.Lock()
	i.keypair = kp
	i.signerHash = identityEnt.ContentHash
	i.ready = true
	i.mu.Unlock()
	return nil
}

// Name returns the handler name surfaced in manifests.
func (i *Issuer) Name() string { return "registry-peer-issued" }

// Manifest declares the three live-registration ops + §5.2 default-grant
// scope. Per §6a.9 the registry-issue-binding cap is held internally; the
// public surfaces are register-request (broadly granted under open mode,
// narrow under allowlist) and manage-issuer-policy (operator-only).
func (i *Issuer) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: IssuerHandlerPattern,
		Name:    "registry-peer-issued",
		Operations: map[string]types.HandlerOperationSpec{
			OpRegisterRequest: {
				InputType:  types.TypeRegistryRegisterRequest,
				OutputType: types.TypeRegistryLocalNameBindResult, // reuses {binding_hash} shape
			},
			OpRevokeRequest: {
				InputType: types.TypeRegistryRevokeRequest,
			},
			OpRenewRequest: {
				InputType:  types.TypeRegistryRenewRequest,
				OutputType: types.TypeRegistryLocalNameBindResult,
			},
			// §6a.9.2 — the two policy-management ops. get takes no input.
			OpSetIssuerPolicy: {
				InputType:  types.TypeRegistryIssuerPolicy,
				OutputType: types.TypeRegistryIssuerPolicy,
			},
			OpGetIssuerPolicy: {
				OutputType: types.TypeRegistryIssuerPolicy,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:  types.CapabilityScope{Include: []string{IssuerHandlerPattern}},
				Resources: types.CapabilityScope{Include: []string{IssuerHandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{
					OpRegisterRequest, OpRevokeRequest, OpRenewRequest,
					OpSetIssuerPolicy, OpGetIssuerPolicy,
				}},
			},
		},
	}
}

// RegisterTypes is a no-op — the §6a.9 types are registered centrally in
// core/types.RegisterCoreTypes.
func (i *Issuer) RegisterTypes(r *types.TypeRegistry) {
	_ = reflect.TypeOf
}

// RequestBindingSeedGrants returns the per-publisher GrantEntry slice that
// authorizes external `register-request` calls + the signature write at the
// §5.2 invariant-pointer path the Layer-1 ownership-proof lives at.
//
// Spec mapping (§6a.9):
//
//	"`register-request` is the external surface, gated by
//	 system/capability/registry-request-binding (open → granted broadly;
//	 allowlist → narrow)"
//
// Per-mode installation by the registry operator:
//
//   - open    — peer.SeedPolicyDefault(RequestBindingSeedGrants())
//   - manual  — peer.SeedPolicyDefault(RequestBindingSeedGrants())
//                (request still needs to reach the handler; it queues there)
//   - allowlist — peer.SeedPolicyForPeerID(p, RequestBindingSeedGrants())
//                for each p in the allowlist
//
// The grants are deliberately narrow: only the register-request op and
// only the system/signature/* tree-put for the Layer-1 ownership proof.
// Revoke and renew remain operator-side (the registrant uses out-of-band
// re-registration for now; widening to a `system/capability/registry-
// renew-binding` for registrants is a v1.3 question).
func RequestBindingSeedGrants() []types.GrantEntry {
	return []types.GrantEntry{
		{
			Handlers:   types.CapabilityScope{Include: []string{IssuerHandlerPattern}},
			Resources:  types.CapabilityScope{Include: []string{IssuerHandlerPattern + "/*"}},
			Operations: types.CapabilityScope{Include: []string{OpRegisterRequest}},
		},
		{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/signature/*"}},
			Operations: types.CapabilityScope{Include: []string{"put"}},
		},
	}
}

// Handle dispatches the three live-registration ops.
func (i *Issuer) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	i.mu.Lock()
	ready := i.ready
	i.mu.Unlock()
	if !ready {
		return handler.NewErrorResponse(503, "not_ready",
			IssuerHandlerPattern+": SetupAuthority not called — registry keypair unavailable")
	}
	switch req.Operation {
	case OpRegisterRequest:
		return i.handleRegisterRequest(ctx, req)
	case OpRevokeRequest:
		return i.handleRevokeRequest(ctx, req)
	case OpRenewRequest:
		return i.handleRenewRequest(ctx, req)
	case OpSetIssuerPolicy:
		return i.handleSetIssuerPolicy(ctx, req)
	case OpGetIssuerPolicy:
		return i.handleGetIssuerPolicy(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			IssuerHandlerPattern+" does not support operation: "+req.Operation)
	}
}

// --- register-request ----------------------------------------------------

func (i *Issuer) handleRegisterRequest(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	body, err := types.RegistryRegisterRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode register-request: "+err.Error())
	}
	if body.Name == "" {
		return handler.NewErrorResponse(400, "invalid_request", "register-request requires a non-empty name")
	}
	if body.TargetPeerID == "" {
		return handler.NewErrorResponse(400, "invalid_request", "register-request requires target_peer_id")
	}
	if len(body.Nonce) == 0 {
		return handler.NewErrorResponse(400, "invalid_request", "register-request requires a non-empty nonce")
	}

	// Name-path safety + NFC per §6.3.
	normalized, err := normalizeName(body.Name)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request", err.Error())
	}

	// Layer 1 — ownership-proof signature by target_peer_id, signed over
	// request.content_hash, at the invariant pointer system/signature/{hex}.
	if status, code, msg := i.verifyOwnershipProof(hctx, req.Params, body.TargetPeerID); code != "" {
		return handler.NewErrorResponse(status, code, msg)
	}

	// Replay defense — (target, nonce) pair seen within window → reject.
	// Also reject requests whose issued_at is older than the window (those
	// fall outside what the registry will remember).
	if status, code, msg := i.checkReplay(body.TargetPeerID, body.Nonce, body.IssuedAt); code != "" {
		return handler.NewErrorResponse(status, code, msg)
	}

	// Load issuer-policy — store-only per §6a.9.2. No policy means this is a
	// curated-only registry, not an implicitly-open one.
	policy, armed := i.loadPolicy(hctx)
	if !armed {
		return curatedOnlyResponse(OpRegisterRequest)
	}

	// §6a.9.1 mode "domain-control" is DEFERRED per §6a.10 — v1 rejects.
	// This is the *stored-policy* path and keeps its 501: §6a.9.2's 400
	// unsupported_mode is a requirement on set-issuer-policy, which refuses
	// to store the mode in the first place. A policy that predates that
	// refusal still has to be answered here.
	if policy.Mode == types.IssuerPolicyModeDomainControl {
		return handler.NewErrorResponse(501, "not_implemented",
			"domain-control mode is deferred to the web-native domain-proof co-design (§6a.10)")
	}

	// Layer 2 — admission.
	if status, code, msg := i.applyAdmission(policy, body, normalized); code != "" {
		return handler.NewErrorResponse(status, code, msg)
	}

	// name_taken check — registry's own by-name index.
	pointerPath := types.PeerIssuedByNamePath(normalized)
	if _, exists := hctx.LocationIndex.Get(pointerPath); exists {
		return handler.NewErrorResponse(409, types.RegistryErrNameTaken,
			fmt.Sprintf("name %q is already bound in this registry", normalized))
	}

	// Manual mode: queue (we accept but do not sign). Operator runs the
	// curated CLI to issue the binding after out-of-band review.
	if policy.Mode == types.IssuerPolicyModeManual {
		i.rememberNonce(body.TargetPeerID, body.Nonce, body.IssuedAt)
		return handler.NewErrorResponse(202, "pending_review",
			"request accepted; operator approval required (manual mode)")
	}

	// Open / allowlist (passed admission) → sign + publish.
	ttl := body.RequestedTTL
	if ttl == nil && policy.DefaultTTL != nil {
		v := *policy.DefaultTTL
		ttl = &v
	}
	bindingHash, err := i.issueBinding(hctx, normalized, body.TargetPeerID, body.Transports, ttl)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "issue binding: "+err.Error())
	}

	i.rememberNonce(body.TargetPeerID, body.Nonce, body.IssuedAt)

	return handler.NewResponse(200, types.TypeRegistryLocalNameBindResult,
		types.LocalNameBindResultData{BindingHash: bindingHash})
}

// verifyOwnershipProof is Layer 1: the request MUST carry a signature whose
// signer is the system/peer entity for target_peer_id, signed over the
// request's content_hash. Returns ("", "", "") on success; (status, code,
// message) on rejection.
func (i *Issuer) verifyOwnershipProof(hctx *handler.HandlerContext, reqEnt entity.Entity, targetPeerID string) (uint, string, string) {
	sigPath := types.LocalSignaturePath(reqEnt.ContentHash)
	sigHash, ok := hctx.LocationIndex.Get(sigPath)
	if !ok {
		return 401, types.RegistryErrSignatureInvalid,
			"register-request missing system/signature at " + sigPath
	}
	sigEnt, ok := hctx.Store.Get(sigHash)
	if !ok {
		return 401, types.RegistryErrSignatureInvalid,
			"signature entity at " + sigPath + " is dangling"
	}
	if sigEnt.Type != types.TypeSignature {
		return 401, types.RegistryErrSignatureInvalid,
			"signature entity has wrong type: " + sigEnt.Type
	}
	sd, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return 401, types.RegistryErrSignatureInvalid,
			"decode signature: " + err.Error()
	}
	if sd.Target != reqEnt.ContentHash {
		return 401, types.RegistryErrSignatureInvalid,
			"signature target does not match request content_hash"
	}

	// Reconstruct the canonical system/peer entity for target_peer_id and
	// confirm its content_hash matches sd.Signer. The §6a.9 layer-1 floor:
	// "signed by target_peer_id" means the signer's identity entity hashes
	// to the same content_hash derivable from the peer-id's (public_key,
	// key_type). V1 cohort accepts identity-form peer-ids only (the public
	// key is recoverable from the peer-id alone); SHA-256-form peer-ids
	// would require out-of-band pubkey delivery and are rejected here, in
	// line with `peerissued.New`'s receiver-side stance ([P5] in the
	// cohort-close doubts).
	pubkey, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(targetPeerID))
	if !ok {
		return 401, types.RegistryErrSignatureInvalid,
			"target_peer_id is not an identity-form V7 §1.5 peer-id (SHA-256-form not supported in v1)"
	}
	signerHash, err := types.ComputePeerIdentityHash(pubkey, keyType)
	if err != nil {
		return 401, types.RegistryErrSignatureInvalid,
			"compute canonical peer entity for target_peer_id: " + err.Error()
	}
	if sd.Signer != signerHash {
		return 401, types.RegistryErrSignatureInvalid,
			"signature signer does not match target_peer_id's canonical identity entity"
	}
	if !crypto.Verify(keyType, pubkey, reqEnt.ContentHash.Bytes(), sd.Signature) {
		return 401, types.RegistryErrSignatureInvalid,
			"signature does not verify under target_peer_id's public key"
	}
	return 0, "", ""
}

// checkReplay enforces nonce uniqueness per target_peer_id within the
// configured issued_at window. Requests whose issued_at is older than the
// window are themselves rejected as replays (the window has rolled past
// them).
func (i *Issuer) checkReplay(targetPeerID string, nonce []byte, issuedAt uint64) (uint, string, string) {
	now := i.clock()
	// Reject requests too old to be inside the window.
	if i.replayWindow > 0 && now > i.replayWindow && issuedAt+i.replayWindow < now {
		return 409, types.RegistryErrReplayDetected,
			"request issued_at is older than the replay window"
	}
	key := replayKey(targetPeerID, nonce)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.evictExpiredLocked(now)
	if _, seen := i.seenNonces[key]; seen {
		return 409, types.RegistryErrReplayDetected,
			"nonce already used by target_peer_id within the replay window"
	}
	return 0, "", ""
}

// rememberNonce records (target, nonce) → issued_at so subsequent identical
// (target, nonce) requests inside the window are rejected.
func (i *Issuer) rememberNonce(targetPeerID string, nonce []byte, issuedAt uint64) {
	key := replayKey(targetPeerID, nonce)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.seenNonces[key] = issuedAt
}

func (i *Issuer) evictExpiredLocked(now uint64) {
	if i.replayWindow == 0 || now <= i.replayWindow {
		return
	}
	cutoff := now - i.replayWindow
	for k, ts := range i.seenNonces {
		if ts < cutoff {
			delete(i.seenNonces, k)
		}
	}
}

func replayKey(targetPeerID string, nonce []byte) string {
	return targetPeerID + "|" + hex.EncodeToString(nonce)
}

// applyAdmission runs Layer-2 per §6a.9.1.
func (i *Issuer) applyAdmission(policy types.IssuerPolicyData, body types.RegistryRegisterRequestData, normalized string) (uint, string, string) {
	if policy.NameConstraints != nil && *policy.NameConstraints != "" {
		matched, err := path.Match(*policy.NameConstraints, normalized)
		if err != nil {
			return 500, "internal_error",
				"invalid name_constraints glob: " + err.Error()
		}
		if !matched {
			return 403, types.RegistryErrNotEntitled,
				fmt.Sprintf("name %q does not match issuer-policy name_constraints", normalized)
		}
	}
	switch policy.Mode {
	case types.IssuerPolicyModeOpen, "":
		// Open / unset → no entitlement gate beyond layer-1 + name_constraints.
		return 0, "", ""
	case types.IssuerPolicyModeAllowlist:
		for _, p := range policy.Allowlist {
			if p == body.TargetPeerID {
				return 0, "", ""
			}
		}
		return 403, types.RegistryErrNotEntitled,
			"target_peer_id is not in issuer-policy allowlist"
	case types.IssuerPolicyModeManual:
		// Caller checks for manual separately (returns 202 pending_review);
		// admission itself passes here.
		return 0, "", ""
	default:
		return 400, "invalid_request",
			"unknown issuer-policy mode: " + policy.Mode
	}
}

// --- §6a.9.2 policy management -------------------------------------------

// handleSetIssuerPolicy implements `set-issuer-policy` per §6a.9.2.
//
// Replace-whole `[MUST]`: the stored entity becomes exactly the submitted
// policy. There is deliberately no merge with any previously-stored policy —
// "an absent optional field means *unset*, not *unchanged*; a merge semantics
// would make the resulting policy depend on write order, which two peers
// cannot reconstruct." Implemented by simply writing the input entity, which
// is also what makes the response "the stored policy, as written."
func (i *Issuer) handleSetIssuerPolicy(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			OpSetIssuerPolicy+" requires a store-backed handler context")
	}
	if req.Params.Type != types.TypeRegistryIssuerPolicy {
		return handler.NewErrorResponse(400, "invalid_params",
			fmt.Sprintf("%s expects a %s entity, got %q",
				OpSetIssuerPolicy, types.TypeRegistryIssuerPolicy, req.Params.Type))
	}
	policy, err := types.IssuerPolicyDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"decode issuer-policy: "+err.Error())
	}

	// §6a.9.2: reject domain-control at the door "rather than storing a
	// policy it cannot enforce." This is the difference between refusing to
	// arm and arming into a mode that 501s on every request.
	if policy.Mode == types.IssuerPolicyModeDomainControl {
		return handler.NewErrorResponse(400, types.RegistryErrUnsupportedMode,
			"mode \"domain-control\" is deferred to the web-native domain-proof "+
				"co-design (§6a.9.1/§6a.10) and will not be stored")
	}
	switch policy.Mode {
	case types.IssuerPolicyModeOpen, types.IssuerPolicyModeAllowlist, types.IssuerPolicyModeManual:
		// enforceable
	default:
		return handler.NewErrorResponse(400, types.RegistryErrUnsupportedMode,
			fmt.Sprintf("unknown issuer-policy mode %q (expected open, allowlist or manual)", policy.Mode))
	}
	if policy.Mode == types.IssuerPolicyModeAllowlist && len(policy.Allowlist) == 0 {
		return handler.NewErrorResponse(400, "invalid_params",
			"mode \"allowlist\" requires a non-empty allowlist — an empty one denies every "+
				"request, which is what mode \"manual\" is for")
	}

	// Store the submitted entity verbatim. Re-encoding via ToEntity would
	// author a second entity with the same fields; writing what arrived is
	// what makes the round-trip byte-exact.
	if _, err := hctx.Store.Put(req.Params); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store issuer-policy: "+err.Error())
	}
	if err := hctx.LocationIndex.Set(types.IssuerPolicyStoragePath, req.Params.ContentHash); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"bind issuer-policy: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: req.Params}, nil
}

// handleGetIssuerPolicy implements `get-issuer-policy` per §6a.9.2 — the
// stored policy, or 404 not_found when unset.
//
// It MUST NOT synthesize a default `open`; see loadPolicy.
func (i *Issuer) handleGetIssuerPolicy(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			OpGetIssuerPolicy+" requires a store-backed handler context")
	}
	h, ok := hctx.LocationIndex.Get(types.IssuerPolicyStoragePath)
	if !ok {
		return handler.NewErrorResponse(404, types.RegistryErrNotFound,
			"no issuer-policy is stored (§6a.9.2 — unset is not a mode)")
	}
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return handler.NewErrorResponse(404, types.RegistryErrNotFound,
			"issuer-policy pointer resolves to no entity")
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// ManageIssuerPolicySeedGrants returns the GrantEntry slice authorizing the
// two §6a.9.2 policy-management ops, gated by
// types.CapRegistryManageIssuerPolicy.
//
// Deliberately NOT part of RequestBindingSeedGrants: a publisher that can
// call register-request must not be able to rewrite the policy that admits
// it. Install this only for the registry operator.
func ManageIssuerPolicySeedGrants() []types.GrantEntry {
	return []types.GrantEntry{
		{
			Handlers:   types.CapabilityScope{Include: []string{IssuerHandlerPattern}},
			Resources:  types.CapabilityScope{Include: []string{IssuerHandlerPattern + "/*"}},
			Operations: types.CapabilityScope{Include: []string{OpSetIssuerPolicy, OpGetIssuerPolicy}},
		},
	}
}

// loadPolicy reads the issuer-policy entity from the local store. The store
// is the ONLY source: §6a.9.2 makes resolution order store-first `[MUST]` and
// bars any parallel source at request time.
//
// Returns ok=false when no policy entity is stored. "Unset is not a mode"
// (§6a.9.2) — callers MUST NOT substitute a default, least of all `open`,
// which would silently turn a curated registry into a first-come-first-serve
// one. A decode failure is also ok=false: a policy we cannot read is not a
// policy we may guess at.
func (i *Issuer) loadPolicy(hctx *handler.HandlerContext) (types.IssuerPolicyData, bool) {
	h, ok := hctx.LocationIndex.Get(types.IssuerPolicyStoragePath)
	if !ok {
		return types.IssuerPolicyData{}, false
	}
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return types.IssuerPolicyData{}, false
	}
	p, err := types.IssuerPolicyDataFromEntity(ent)
	if err != nil {
		return types.IssuerPolicyData{}, false
	}
	return p, true
}

// curatedOnlyResponse is what the live-registration ops return when no policy
// entity is stored. §6a.9.2: with no policy the registry "does not run live
// registration at all (§6a.9's handler is unregistered) — it is a conformant
// curated-only registry per §6a.8."
//
// Go registers the handler unconditionally (it is wired pre-Build, before any
// store exists to consult), so the closest conformant behaviour available to
// it is to answer as though the handler were absent: 404. The distinction is
// invisible to a client, which is the point.
func curatedOnlyResponse(op string) (*handler.Response, error) {
	return handler.NewErrorResponse(404, types.RegistryErrNotFound,
		IssuerHandlerPattern+": no issuer-policy is stored — this registry is curated-only "+
			"(§6a.8); "+op+" is not served. Arm it with "+OpSetIssuerPolicy+".")
}

// SeedPolicy writes the out-of-band-armed policy (WithSeedPolicy) into the
// tree at types.IssuerPolicyStoragePath, satisfying §6a.9.2's store-first
// MUST. Call once post-Build, alongside SetupAuthority.
//
// Seeding does NOT overwrite: an operator who has already authored a policy
// entity — or set one via set-issuer-policy on a previous run against a
// persistent store — outranks a flag. The flag arms an unarmed registry; it
// does not silently revert one. No-op when WithSeedPolicy was not used.
func (i *Issuer) SeedPolicy(cs store.ContentStore, li store.LocationIndex) error {
	i.mu.Lock()
	seed := i.seedPolicy
	i.mu.Unlock()
	if seed == nil {
		return nil
	}
	if _, exists := li.Get(types.IssuerPolicyStoragePath); exists {
		return nil
	}
	ent, err := seed.ToEntity()
	if err != nil {
		return fmt.Errorf("peerissued.SeedPolicy: encode issuer-policy: %w", err)
	}
	if _, err := cs.Put(ent); err != nil {
		return fmt.Errorf("peerissued.SeedPolicy: store issuer-policy: %w", err)
	}
	if err := li.Set(types.IssuerPolicyStoragePath, ent.ContentHash); err != nil {
		return fmt.Errorf("peerissued.SeedPolicy: bind issuer-policy: %w", err)
	}
	return nil
}

// issueBinding is the §6a.8 internal sign+publish act, identical in shape to
// what the curated `registry-issue-binding` CLI does — but in-process and
// gated by the §6a.9 admission decision above. Writes three artifacts:
// binding body, signature, by-name pointer.
func (i *Issuer) issueBinding(hctx *handler.HandlerContext, normalizedName, targetPeerID string, transports []hash.Hash, ttl *uint64) (hash.Hash, error) {
	body := types.BindingData{
		Name:         normalizedName,
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: targetPeerID,
		Transports:   transports,
		IssuedAt:     i.clock(),
		TTL:          ttl,
	}
	bindingEnt, err := body.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode binding: %w", err)
	}
	sigBytes := i.keypair.Sign(bindingEnt.ContentHash.Bytes())
	identityEnt, err := i.keypair.IdentityEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("identity entity: %w", err)
	}
	sigData := types.SignatureData{
		Target:    bindingEnt.ContentHash,
		Signer:    identityEnt.ContentHash,
		Algorithm: identityEnt.Type, // surface only; backend verifies via key_type
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode signature: %w", err)
	}
	if _, err := hctx.Store.Put(bindingEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("store binding: %w", err)
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("store signature: %w", err)
	}
	if _, err := hctx.TreeSet(types.BindingStoragePath(bindingEnt.ContentHash), bindingEnt.ContentHash, "peer-issued-register"); err != nil {
		return hash.Hash{}, fmt.Errorf("publish binding body: %w", err)
	}
	if _, err := hctx.TreeSet(types.LocalSignaturePath(bindingEnt.ContentHash), sigEnt.ContentHash, "peer-issued-register"); err != nil {
		return hash.Hash{}, fmt.Errorf("publish signature: %w", err)
	}
	if _, err := hctx.TreeSet(types.PeerIssuedByNamePath(normalizedName), bindingEnt.ContentHash, "peer-issued-register"); err != nil {
		return hash.Hash{}, fmt.Errorf("publish by-name pointer: %w", err)
	}
	return bindingEnt.ContentHash, nil
}

// --- revoke-request ------------------------------------------------------

func (i *Issuer) handleRevokeRequest(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	body, err := types.RegistryRevokeRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode revoke-request: "+err.Error())
	}

	// Look up the binding to confirm it exists + recover its target_peer_id.
	bindingEnt, ok := hctx.Store.Get(body.BindingHash)
	if !ok {
		return handler.NewErrorResponse(404, "not_found",
			"no such binding in this registry")
	}
	if bindingEnt.Type != types.TypeRegistryBinding {
		return handler.NewErrorResponse(400, "invalid_request",
			"binding_hash addresses a non-binding entity")
	}

	rev := types.RevocationData{
		Revokes:   body.BindingHash,
		RevokedAt: i.clock(),
		Reason:    body.Reason,
	}
	revEnt, err := rev.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"encode revocation: "+err.Error())
	}
	sigBytes := i.keypair.Sign(revEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    revEnt.ContentHash,
		Signer:    i.signerHash,
		Algorithm: i.identityType(),
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"encode revocation signature: "+err.Error())
	}
	if _, err := hctx.Store.Put(revEnt); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store revocation: "+err.Error())
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store revocation signature: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.RevocationStoragePath(revEnt.ContentHash), revEnt.ContentHash, "peer-issued-revoke"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"publish revocation body: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.LocalSignaturePath(revEnt.ContentHash), sigEnt.ContentHash, "peer-issued-revoke"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"publish revocation signature: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.PeerIssuedRevocationByTargetPath(body.BindingHash), revEnt.ContentHash, "peer-issued-revoke"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"publish revocation by-target index: "+err.Error())
	}
	return &handler.Response{Status: 200}, nil
}

// --- renew-request -------------------------------------------------------

func (i *Issuer) handleRenewRequest(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	body, err := types.RegistryRenewRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode renew-request: "+err.Error())
	}
	// §6a.9.1 ruling (v1.2): renew is non-idempotent (replay extends expiry),
	// so the same nonce + issued_at + replay-window discipline as register
	// applies. The replay key is keyed off the binding's target_peer_id —
	// that is the identity whose name lapse is being prevented.
	if len(body.Nonce) == 0 {
		return handler.NewErrorResponse(400, "invalid_request",
			"renew-request requires a non-empty nonce")
	}
	bindingEnt, ok := hctx.Store.Get(body.BindingHash)
	if !ok {
		return handler.NewErrorResponse(404, "not_found",
			"no such binding in this registry")
	}
	if bindingEnt.Type != types.TypeRegistryBinding {
		return handler.NewErrorResponse(400, "invalid_request",
			"binding_hash addresses a non-binding entity")
	}
	existing, err := types.BindingDataFromEntity(bindingEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"decode existing binding: "+err.Error())
	}
	if status, code, msg := i.checkReplay(existing.TargetPeerID, body.Nonce, body.IssuedAt); code != "" {
		return handler.NewErrorResponse(status, code, msg)
	}

	// TTL resolution: explicit > issuer-policy default > no expiry.
	var ttlPtr *uint64
	if body.TTL != nil {
		t := *body.TTL
		ttlPtr = &t
	} else if p, armed := i.loadPolicy(hctx); armed && p.DefaultTTL != nil {
		t := *p.DefaultTTL
		ttlPtr = &t
	}

	successor := existing
	prev := body.BindingHash
	successor.Supersedes = &prev
	successor.IssuedAt = i.clock()
	successor.TTL = ttlPtr

	successorEnt, err := successor.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"encode renewal: "+err.Error())
	}
	sigBytes := i.keypair.Sign(successorEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    successorEnt.ContentHash,
		Signer:    i.signerHash,
		Algorithm: i.identityType(),
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"encode renewal signature: "+err.Error())
	}
	if _, err := hctx.Store.Put(successorEnt); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store renewal: "+err.Error())
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store renewal signature: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.BindingStoragePath(successorEnt.ContentHash), successorEnt.ContentHash, "peer-issued-renew"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"publish renewal body: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.LocalSignaturePath(successorEnt.ContentHash), sigEnt.ContentHash, "peer-issued-renew"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"publish renewal signature: "+err.Error())
	}
	if _, err := hctx.TreeSet(types.PeerIssuedByNamePath(existing.Name), successorEnt.ContentHash, "peer-issued-renew"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"update by-name pointer: "+err.Error())
	}
	i.rememberNonce(existing.TargetPeerID, body.Nonce, body.IssuedAt)
	return handler.NewResponse(200, types.TypeRegistryLocalNameBindResult,
		types.LocalNameBindResultData{BindingHash: successorEnt.ContentHash})
}

// identityType returns the surface algorithm string for the registry's key
// — recovered from the identity entity (system/peer/ed25519 etc.). Used as
// SignatureData.Algorithm; the verifier resolves the real key type via the
// signer's PeerData.key_type.
func (i *Issuer) identityType() string {
	ent, err := i.keypair.IdentityEntity()
	if err != nil {
		return ""
	}
	return ent.Type
}

func init() {
	// Keep the time import live regardless of which platform path the
	// build picks (used via defaultClock from peerissued.go).
	_ = time.Now
}
