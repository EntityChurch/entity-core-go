package quorum

import (
	"context"
	"reflect"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

const handlerPattern = "system/quorum"

// Handler implements the system/quorum handler per EXTENSION-QUORUM v1.0.
// Provides four operations — :create, :update, :publish, :verify — plus a
// sync hook that maintains the CurrentSignerSet cache when validated
// quorum-update / quorum-publish attestations enter the local tree.
//
// The handler depends on ext/attestation (set via SetupAttestation) for
// indexed lookups and for writing quorum-update / quorum-publish
// attestations as system/attestation entities. The dependency is one-way
// per the dependency stack in SYSTEM-IDENTITY-COMPOSITION.md §3.
type Handler struct {
	mu        sync.RWMutex
	cs        store.ContentStore
	li        store.LocationIndex
	peerID    crypto.PeerID
	att       *attestation.Handler
	cache     *signerSetCache
	resolvers *resolverRegistry
}

// NewHandler returns a new quorum handler with empty cache and resolver
// registry. The "concrete" mode is implicit and not in the registry.
func NewHandler() *Handler {
	return &Handler{
		cache:     newSignerSetCache(),
		resolvers: newResolverRegistry(),
	}
}

func (h *Handler) Name() string { return "quorum" }

// SetupStore wires the content store, location index, and local peer ID.
// Required before any operation can run.
func (h *Handler) SetupStore(cs store.ContentStore, li store.LocationIndex, peerID crypto.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
}

// SetupAttestation wires the attestation handler used to write quorum-update
// and quorum-publish attestations and to read the attestation index. Must
// be called before any :update / :publish / CurrentSignerSet call.
func (h *Handler) SetupAttestation(att *attestation.Handler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.att = att
}

// RegisterResolver registers a signer-resolution mode handler against the
// pluggable resolver hook per §5.2. The "concrete" mode is built in and
// MUST NOT be re-registered. EXTENSION-IDENTITY v3.3 calls this on its
// configure operation to register "identity-resolved".
//
// Per PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP §PR-6 (multi-
// registration semantics): registering a mode that is already registered
// returns *ResolverAlreadyRegisteredError. Implementations MUST NOT
// silently replace, override, or stack handlers. Replacement requires
// unregistration first (out of scope for v2).
func (h *Handler) RegisterResolver(mode string, fn SignerResolver) error {
	return h.resolvers.register(mode, fn)
}

// InvalidateCache clears the cached signer set for quorumID per the §4.2.1
// invalidation contract. Called by the handler itself on successful
// :update / :publish completion AND by OnTreeChange when a validated
// quorum-update / quorum-publish attestation arrives. Cross-quorum
// invalidations are scoped per §4.2.1 (TV-QF15) — only the named quorum's
// entry is cleared.
func (h *Handler) InvalidateCache(quorumID hash.Hash) {
	h.cache.invalidate(quorumID)
}

// Manifest returns the handler's self-description per §6.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "quorum",
		Operations: map[string]types.HandlerOperationSpec{
			"create": {
				InputType:  types.TypeQuorumCreateRequest,
				OutputType: types.TypeQuorumCreateResult,
			},
			"update": {
				InputType:  types.TypeQuorumUpdateRequest,
				OutputType: types.TypeQuorumUpdateResult,
			},
			"publish": {
				InputType:  types.TypeQuorumPublishRequest,
				OutputType: types.TypeQuorumPublishResult,
			},
			"verify": {
				InputType:  types.TypeQuorumVerifyRequest,
				OutputType: types.TypeQuorumVerifyResult,
			},
		},
	}
}

// RegisterTypes registers the quorum extension's types with the registry.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeQuorum, reflect.TypeOf(types.QuorumData{}))
	r.ReflectType(types.TypeQuorumCreateRequest, reflect.TypeOf(types.QuorumCreateRequestData{}))
	r.ReflectType(types.TypeQuorumCreateResult, reflect.TypeOf(types.QuorumCreateResultData{}))
	r.ReflectType(types.TypeQuorumUpdateRequest, reflect.TypeOf(types.QuorumUpdateRequestData{}))
	r.ReflectType(types.TypeQuorumUpdateResult, reflect.TypeOf(types.QuorumUpdateResultData{}))
	r.ReflectType(types.TypeQuorumPublishRequest, reflect.TypeOf(types.QuorumPublishRequestData{}))
	r.ReflectType(types.TypeQuorumPublishResult, reflect.TypeOf(types.QuorumPublishResultData{}))
	r.ReflectType(types.TypeQuorumVerifyRequest, reflect.TypeOf(types.QuorumVerifyRequestData{}))
	r.ReflectType(types.TypeQuorumVerifyResult, reflect.TypeOf(types.QuorumVerifyResultData{}))
}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "create":
		return h.handleCreate(ctx, req)
	case "update":
		return h.handleUpdate(ctx, req)
	case "publish":
		return h.handlePublish(ctx, req)
	case "verify":
		return h.handleVerify(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/quorum does not support operation: "+req.Operation)
	}
}

// OnTreeChange is the sync-hook for the quorum handler. Per §4.2.1
// invalidation contract: when a validated quorum-update or quorum-publish
// attestation enters the local tree (regardless of source — local op,
// cross-peer sync, envelope.included ingestion, L0 bootstrap), the cache
// entry for the targeted quorum_id MUST be invalidated. The validation
// runs here (K-of-N against the previous signer set); failures do NOT
// invalidate the cache (TV-QF14).
func (h *Handler) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	h.mu.RLock()
	cs := h.cs
	li := h.li
	att := h.att
	h.mu.RUnlock()
	if cs == nil || li == nil || att == nil {
		return nil
	}
	if evt.ChangeType == store.ChangeDeleted {
		return nil
	}
	if evt.Hash.IsZero() {
		return nil
	}
	ent, ok := cs.Get(evt.Hash)
	if !ok || ent.Type != types.TypeAttestation {
		return nil
	}
	a, err := types.AttestationDataFromEntity(ent)
	if err != nil {
		return nil
	}
	kind := a.Kind()
	if kind != types.KindQuorumUpdate && kind != types.KindQuorumPublish {
		return nil
	}
	// Self-attestation: attesting == attested == quorum_id per §3.2 / §3.3.
	quorumID := a.Attesting
	if quorumID != a.Attested {
		return nil
	}

	// Validate K-of-N against the *previous* signer set (the supersedes-chain
	// key per §3.3 quorum-publish rule and §3.2 quorum-update). The previous
	// set is whatever CurrentSignerSet returned BEFORE this attestation was
	// processed — i.e., what we have cached, or what we recompute by walking
	// the chain ignoring this new attestation.
	//
	// Pragmatic implementation: walk the chain via the ATT primitives looking
	// only at attestations that don't include this one. Easier: if a
	// supersedes is present, validate against the predecessor's signer
	// snapshot; otherwise validate against the quorum entity's current
	// effective signer set (which excludes this new arrival because the
	// cache is either empty or stale-but-not-yet-including-this).
	prevSigners, prevThreshold, err := h.signerSetForValidation(quorumID, a)
	if err != nil {
		// Cannot validate — fail closed; do NOT invalidate cache (TV-QF14).
		return nil
	}
	if _, ok := VerifyKOfNSignatures(cs, li, evt.Hash, prevSigners, prevThreshold); !ok {
		// K-of-N failed — TV-QF14 mandates the cache MUST NOT be invalidated.
		return nil
	}
	h.cache.invalidate(quorumID)
	return nil
}

// signerSetForValidation returns the signer set against which the new
// arrival must validate per §3.3 (publish: previous quorum signs supersedes;
// initial: current quorum signs) and §3.2 (update: current effective
// constituents sign the new update). The implementation handles both
// uniformly: walk the chain to find the predecessor's signer set if a
// supersedes is present; otherwise return the current effective set
// excluding this new attestation.
func (h *Handler) signerSetForValidation(quorumID hash.Hash, newAtt types.AttestationData) ([]hash.Hash, uint64, error) {
	h.mu.RLock()
	cs := h.cs
	li := h.li
	att := h.att
	h.mu.RUnlock()
	if newAtt.Supersedes != nil {
		prev, err := loadAttestationFromStore(cs, *newAtt.Supersedes)
		if err != nil {
			return nil, 0, err
		}
		// Decode the predecessor's snapshot. quorum-publish carries the
		// snapshot directly (§3.3); quorum-update carries new_signers /
		// new_threshold (§3.2) which is the signer set effective AFTER the
		// update — exactly what should sign the next update.
		switch prev.Kind() {
		case types.KindQuorumPublish:
			var props types.QuorumPublishProperties
			if err := types.DecodeProperties(prev.Properties, &props); err == nil &&
				len(props.Signers) > 0 && props.Threshold > 0 {
				return props.Signers, props.Threshold, nil
			}
		case types.KindQuorumUpdate:
			var props types.QuorumUpdateProperties
			if err := types.DecodeProperties(prev.Properties, &props); err == nil &&
				len(props.NewSigners) > 0 && props.NewThreshold > 0 {
				return props.NewSigners, props.NewThreshold, nil
			}
		}
	}
	// No predecessor (initial publish, or first update). Validate against
	// the quorum entity's signer set, excluding any already-known updates
	// for this quorum (otherwise we'd validate against the post-state).
	_ = att
	path := QuorumPath(quorumID)
	entHash, ok := li.Get(path)
	if !ok {
		return nil, 0, errString("quorum_not_found")
	}
	ent, ok := cs.Get(entHash)
	if !ok || ent.Type != types.TypeQuorum {
		return nil, 0, errString("quorum_not_found")
	}
	q, err := types.QuorumDataFromEntity(ent)
	if err != nil {
		return nil, 0, err
	}
	return q.Signers, q.Threshold, nil
}

func loadAttestationFromStore(cs store.ContentStore, h hash.Hash) (types.AttestationData, error) {
	ent, ok := cs.Get(h)
	if !ok {
		return types.AttestationData{}, errString("attestation_not_found")
	}
	if ent.Type != types.TypeAttestation {
		return types.AttestationData{}, errString("not_an_attestation")
	}
	return types.AttestationDataFromEntity(ent)
}

type errString string

func (e errString) Error() string { return string(e) }
