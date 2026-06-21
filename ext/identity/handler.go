package identity

import (
	"context"
	"reflect"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	"go.entitychurch.org/entity-core-go/ext/quorum"
)

const handlerPattern = "system/identity"

// Handler implements the system/identity handler per EXTENSION-IDENTITY
// v3.2. Provides seven operations — configure, create_quorum,
// create_attestation, supersede_attestation, revoke_attestation,
// publish_attestation, process_attestation — by orchestrating
// EXTENSION-ATTESTATION (signed-graph substrate) and EXTENSION-QUORUM
// (K-of-N node primitive).
//
// Authority (peer keypair + identity entity, used to sign the local peer→
// controller cap during configure) is wired post-construction via
// SetupAuthority. Until then, ops that need to issue caps return 503.
//
// Startup exemption (§6.9, §12.5): the first call to configure on a
// fresh peer happens before peer-config exists and before a local peer→
// controller cap is available. The exported Startup function is the L0
// entry point — it operates directly on the store + location index without
// dispatch authorization. Post-startup, configure calls go through Handle
// and require operational authority via the local peer→controller cap.
type Handler struct {
	mu       sync.RWMutex
	keypair  crypto.Keypair
	identity entity.Entity
	ready    bool

	// cs / li / peerID are wired post-construction via SetupStore.
	cs     store.ContentStore
	li     store.LocationIndex
	peerID crypto.PeerID

	// att and q are wired post-construction via SetupSubstrate. Identity
	// delegates all generic mechanics (signature validation, supersedes
	// chain walks, liveness, K-of-N) to these primitives.
	att *attestation.Handler
	q   *quorum.Handler

	// signingKeys holds keypairs indexed by their identity entity hash. A
	// runtime peer running an identity ceremony (rotation, attestation
	// production) registers the keypairs it has access to here; producer
	// helpers draw from this registry to sign entities on behalf of the
	// corresponding identity. Per §7 default custody, the controller's
	// keypair lives on the local agent's daemon. Quorum constituent keys
	// are typically cold; ceremony tools temporarily import them here.
	signingKeys map[hash.Hash]crypto.Keypair
}

// NewHandler creates a new identity handler.
func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Name() string { return "identity" }

// SetupAuthority wires the peer's signing authority into the identity
// handler. Called after peer construction with the local agent's keypair
// and identity entity. Required before configure can issue local peer→
// controller caps.
func (h *Handler) SetupAuthority(kp crypto.Keypair, identityEnt entity.Entity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keypair = kp
	h.identity = identityEnt
	h.ready = true
}

// SetupStore wires the content store, location index, and local peer ID.
// Called after peer construction alongside SetupAuthority.
func (h *Handler) SetupStore(cs store.ContentStore, li store.LocationIndex, peerID crypto.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
}

// SetupSubstrate wires the attestation and quorum handler dependencies.
// Required before any identity operation that delegates to the substrate
// can run — which is essentially all of them.
//
// SetupSubstrate also registers the "identity-resolved" signer-resolution
// mode against the quorum handler's resolver hook per §6.1. Group
// quorums (and other future consumers) use this mode to reference public
// identities by their trusts_quorum hash.
func (h *Handler) SetupSubstrate(att *attestation.Handler, q *quorum.Handler) error {
	h.mu.Lock()
	h.att = att
	h.q = q
	h.mu.Unlock()
	if q != nil && att != nil {
		if err := q.RegisterResolver(types.SignerResolutionIdentityResolved, makeIdentityResolvedResolver(att)); err != nil {
			return err
		}
	}
	return nil
}

// RegisterSigningKey registers a keypair under its identity entity hash so
// the handler's producer-side helpers can sign entities on behalf of that
// identity. Used by startup / ceremony tools to expose the controller
// keypair (or, transiently, quorum constituents) to the handler.
func (h *Handler) RegisterSigningKey(idHash hash.Hash, kp crypto.Keypair) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.signingKeys == nil {
		h.signingKeys = make(map[hash.Hash]crypto.Keypair)
	}
	h.signingKeys[idHash] = kp
}

// signingKeyFor returns the registered keypair for `idHash`, or
// (zero, false) when no keypair is registered.
func (h *Handler) signingKeyFor(idHash hash.Hash) (crypto.Keypair, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	kp, ok := h.signingKeys[idHash]
	return kp, ok
}

// Manifest returns the handler's self-description per §6. v3.2 retains
// v2.2's seven-operation external surface.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "identity",
		Operations: map[string]types.HandlerOperationSpec{
			"configure": {
				InputType:  types.TypeIdentityConfigureRequest,
				OutputType: types.TypeIdentityConfigureResult,
			},
			"create_quorum": {
				InputType:  types.TypeIdentityCreateQuorumRequest,
				OutputType: types.TypeIdentityCreateQuorumResult,
			},
			"create_attestation": {
				InputType:  types.TypeIdentityCreateAttestationRequest,
				OutputType: types.TypeIdentityCreateAttestationResult,
			},
			"supersede_attestation": {
				InputType:  types.TypeIdentitySupersedeAttestationRequest,
				OutputType: types.TypeIdentitySupersedeAttestationResult,
			},
			"revoke_attestation": {
				InputType:  types.TypeIdentityRevokeAttestationRequest,
				OutputType: types.TypeIdentityRevokeAttestationResult,
			},
			"publish_attestation": {
				InputType:  types.TypeIdentityPublishAttestationRequest,
				OutputType: types.TypeIdentityPublishAttestationResult,
			},
			"process_attestation": {
				// Empty params — path lives in resource.targets per V7 §3.2.
			},
		},
	}
}

// RegisterTypes registers identity-extension types with the type registry.
// v3.2: 1 primary entity type + 1 helper inner type + the handler request/
// result types. Substrate types (system/attestation, system/quorum) are
// registered by their owning extensions.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeIdentityBinding, reflect.TypeOf(types.IdentityBindingData{}))
	r.ReflectType(types.TypeIdentityPeerConfig, reflect.TypeOf(types.IdentityPeerConfigData{}))
	r.ReflectType(types.TypeIdentityEvent, reflect.TypeOf(types.IdentityEventData{}))

	r.ReflectType(types.TypeIdentityConfigureRequest, reflect.TypeOf(types.IdentityConfigureRequestData{}))
	r.ReflectType(types.TypeIdentityConfigureResult, reflect.TypeOf(types.IdentityConfigureResultData{}))
	r.ReflectType(types.TypeIdentityCreateQuorumRequest, reflect.TypeOf(types.IdentityCreateQuorumRequestData{}))
	r.ReflectType(types.TypeIdentityCreateQuorumResult, reflect.TypeOf(types.IdentityCreateQuorumResultData{}))
	r.ReflectType(types.TypeIdentityCreateAttestationRequest, reflect.TypeOf(types.IdentityCreateAttestationRequestData{}))
	r.ReflectType(types.TypeIdentityCreateAttestationResult, reflect.TypeOf(types.IdentityCreateAttestationResultData{}))
	r.ReflectType(types.TypeIdentitySupersedeAttestationRequest, reflect.TypeOf(types.IdentitySupersedeAttestationRequestData{}))
	r.ReflectType(types.TypeIdentitySupersedeAttestationResult, reflect.TypeOf(types.IdentitySupersedeAttestationResultData{}))
	r.ReflectType(types.TypeIdentityRevokeAttestationRequest, reflect.TypeOf(types.IdentityRevokeAttestationRequestData{}))
	r.ReflectType(types.TypeIdentityRevokeAttestationResult, reflect.TypeOf(types.IdentityRevokeAttestationResultData{}))
	r.ReflectType(types.TypeIdentityPublishAttestationRequest, reflect.TypeOf(types.IdentityPublishAttestationRequestData{}))
	r.ReflectType(types.TypeIdentityPublishAttestationResult, reflect.TypeOf(types.IdentityPublishAttestationResultData{}))
}

// Handle dispatches to the appropriate operation. All ops require
// operational authority post-startup; startup-time configure goes
// through the exported Startup function instead.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "configure":
		return h.handleConfigure(ctx, req)
	case "create_quorum":
		return h.handleCreateQuorum(ctx, req)
	case "create_attestation":
		return h.handleCreateAttestation(ctx, req)
	case "supersede_attestation":
		return h.handleSupersedeAttestation(ctx, req)
	case "revoke_attestation":
		return h.handleRevokeAttestation(ctx, req)
	case "publish_attestation":
		return h.handlePublishAttestation(ctx, req)
	case "process_attestation":
		return h.handleProcessAttestation(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/identity does not support operation: "+req.Operation)
	}
}

// authority returns the wired keypair + identity, or 503 if SetupAuthority
// has not been called.
func (h *Handler) authority() (crypto.Keypair, entity.Entity, *handler.Response) {
	h.mu.RLock()
	ready := h.ready
	kp := h.keypair
	id := h.identity
	h.mu.RUnlock()
	if !ready {
		resp, _ := handler.NewErrorResponse(503, "authority_not_ready",
			"identity handler authority not yet wired (SetupAuthority pending)")
		return crypto.Keypair{}, entity.Entity{}, resp
	}
	return kp, id, nil
}

// substrate returns the wired attestation + quorum handler refs, or 503 if
// SetupSubstrate has not been called.
func (h *Handler) substrate() (*attestation.Handler, *quorum.Handler, *handler.Response) {
	h.mu.RLock()
	att := h.att
	q := h.q
	h.mu.RUnlock()
	if att == nil || q == nil {
		resp, _ := handler.NewErrorResponse(503, "substrate_not_ready",
			"identity handler substrate dependencies not wired (SetupSubstrate pending)")
		return nil, nil, resp
	}
	return att, q, nil
}
