package attestation

import (
	"context"
	"reflect"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

const handlerPattern = "system/attestation"

// Handler implements the system/attestation handler per EXTENSION-ATTESTATION
// v1.0. Provides four operations — :create, :supersede, :revoke, :verify —
// plus a sync hook that maintains the attesting / attested / kind /
// supersedes indexes when system/attestation entities enter the tree from
// any source (local handler write, cross-peer sync, L0 direct write).
type Handler struct {
	mu     sync.RWMutex
	cs     store.ContentStore
	li     store.LocationIndex
	peerID crypto.PeerID
	ix     *Index
}

// NewHandler returns a new attestation handler with an empty index. The
// content store, location index, and local peer ID are wired post-
// construction via SetupStore.
func NewHandler() *Handler {
	return &Handler{ix: NewIndex()}
}

// Name returns the handler name used by the dispatcher and manifest.
func (h *Handler) Name() string { return "attestation" }

// Index exposes the in-memory index so consumer extensions (identity, quorum,
// future VC / reputation / cluster / etc.) can call FindAttestationsTargeting,
// FindAttestationsBy, FindRevocationsFor, FindAttestationsWithSupersedes,
// FindAttestationsWithKind, etc. directly.
func (h *Handler) Index() *Index { return h.ix }

// SetupStore wires the content store, location index, and local peer ID.
// Called after peer construction. Required before any operation can run.
func (h *Handler) SetupStore(cs store.ContentStore, li store.LocationIndex, peerID crypto.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
}

// Manifest returns the handler's self-description per §6.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "attestation",
		Operations: map[string]types.HandlerOperationSpec{
			"create": {
				InputType:  types.TypeAttestationCreateRequest,
				OutputType: types.TypeAttestationCreateResult,
			},
			"supersede": {
				InputType:  types.TypeAttestationSupersedeRequest,
				OutputType: types.TypeAttestationSupersedeResult,
			},
			"revoke": {
				InputType:  types.TypeAttestationRevokeRequest,
				OutputType: types.TypeAttestationRevokeResult,
			},
			"verify": {
				InputType:  types.TypeAttestationVerifyRequest,
				OutputType: types.TypeAttestationVerifyResult,
			},
		},
	}
}

// RegisterTypes registers the attestation extension's types with the
// registry. The system/attestation entity type and the eight handler
// request/result types per core/types/attestation.go.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeAttestation, reflect.TypeOf(types.AttestationData{}))
	r.ReflectType(types.TypeAttestationCreateRequest, reflect.TypeOf(types.AttestationCreateRequestData{}))
	r.ReflectType(types.TypeAttestationCreateResult, reflect.TypeOf(types.AttestationCreateResultData{}))
	r.ReflectType(types.TypeAttestationSupersedeRequest, reflect.TypeOf(types.AttestationSupersedeRequestData{}))
	r.ReflectType(types.TypeAttestationSupersedeResult, reflect.TypeOf(types.AttestationSupersedeResultData{}))
	r.ReflectType(types.TypeAttestationRevokeRequest, reflect.TypeOf(types.AttestationRevokeRequestData{}))
	r.ReflectType(types.TypeAttestationRevokeResult, reflect.TypeOf(types.AttestationRevokeResultData{}))
	r.ReflectType(types.TypeAttestationVerifyRequest, reflect.TypeOf(types.AttestationVerifyRequestData{}))
	r.ReflectType(types.TypeAttestationVerifyResult, reflect.TypeOf(types.AttestationVerifyResultData{}))
}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "create":
		return h.handleCreate(ctx, req)
	case "supersede":
		return h.handleSupersede(ctx, req)
	case "revoke":
		return h.handleRevoke(ctx, req)
	case "verify":
		return h.handleVerify(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/attestation does not support operation: "+req.Operation)
	}
}

// Load scans the location index and rebuilds the in-memory attestation
// graph from system/attestation entities currently bound in the tree.
// Required after restart with a persistent store, where OnTreeChange did
// not see runtime mutations from a prior process. Safe to call multiple
// times — Index.Add is idempotent on (attHash, AttestationData).
//
// Must be called after SetupStore and before any cross-peer dispatch that
// depends on the attestation graph (identity binding checks, role policy
// resolution). See DESIGN-SQLITE-PERSISTENCE.md §4.3.
func (h *Handler) Load() {
	h.mu.RLock()
	cs := h.cs
	li := h.li
	h.mu.RUnlock()
	if cs == nil || li == nil {
		return
	}
	for _, entry := range li.List("") {
		ent, ok := cs.Get(entry.Hash)
		if !ok || ent.Type != types.TypeAttestation {
			continue
		}
		att, err := types.AttestationDataFromEntity(ent)
		if err != nil {
			continue
		}
		h.ix.Add(ent.ContentHash, att)
	}
}

// OnTreeChange is the sync-hook for the attestation handler. It observes
// tree writes, filters to system/attestation entities, and updates the
// in-memory index. Per §5.7 / §9.1 invariant I1, the index MUST reflect
// any new binding before the next find_attestations_* call.
//
// Local handler writes update the index synchronously inside the operation
// (so write-then-read consistency holds within a handler invocation); this
// hook handles the cross-peer-sync and L0-direct-write paths. Adds and
// removes are idempotent on the underlying Index.
func (h *Handler) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	h.mu.RLock()
	cs := h.cs
	h.mu.RUnlock()
	if cs == nil {
		return nil
	}
	switch evt.ChangeType {
	case store.ChangeDeleted:
		// We don't know whether the deleted hash was an attestation without
		// looking up the entity (which is gone). Cheap solution: use the
		// previously-bound hash carried on the event if available; otherwise
		// no-op. Index.Remove is a no-op for non-indexed hashes, so a stray
		// hash here is harmless.
		if !evt.Hash.IsZero() {
			h.ix.Remove(evt.Hash)
		}
		return nil
	case store.ChangeCreated, store.ChangeModified:
		if evt.Hash.IsZero() {
			return nil
		}
		ent, ok := cs.Get(evt.Hash)
		if !ok || ent.Type != types.TypeAttestation {
			return nil
		}
		att, err := types.AttestationDataFromEntity(ent)
		if err != nil {
			return nil
		}
		h.ix.Add(ent.ContentHash, att)
		return nil
	}
	return nil
}

// resourcePath extracts the canonical resource path from the request's
// resource target per V7 §3.2 (path-as-resource). Returns empty if no path
// is present.
func resourcePath(req *handler.Request) string {
	if req.Context == nil {
		return ""
	}
	return req.Context.ExtractResourcePath()
}

// barePath returns the peer-relative path for `absPath`. When the path is
// already peer-relative (no leading "/") it's returned unchanged. When it's
// absolute (`/{peer_id}/...`) the peer_id segment is stripped.
func barePath(absPath string) string {
	if len(absPath) == 0 || absPath[0] != '/' {
		return absPath
	}
	rest := absPath[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i+1:]
		}
	}
	return rest
}

var _ = hash.Hash{} // keep import — used by sibling files via package surface
