// Package discovery implements EXTENSION-DISCOVERY v1.0 — the
// "what peers are out there I don't know?" substrate per
// `../entity-core-architecture/.../EXTENSION-DISCOVERY.md`.
//
// Three handler ops at pattern `system/discovery`:
//
//   - `:scan(backend, filter?)` → ScanResult — hybrid shape per §3.0:
//     immediate snapshot return + establishes/refreshes a watchable browse
//     session at `system/discovery/candidate/{backend}/*`.
//   - `:announce(backend, profile_ref)` → () — advertise self on `backend`.
//   - `:announce-stop(backend, profile_ref)` → () — symmetric stop.
//
// Plus a substrate-level `PromoteSuccessor` primitive — the IDENTIFY hook
// per §2.2. The IDENTIFY *event* fires impl-side (Go names it
// `connState.RemotePeerID` getting populated post-AUTHENTICATE; Rust + Py
// have analogous events); the wire shape is the spec. PromoteSuccessor
// mints + binds the successor candidate, performing the §2.2.1 fail-closed
// identity_hint comparison when non-TOFU.
//
// Backends register themselves via RegisterBackend. v1 ships with mDNS
// (ext/discovery/mdns); §6 staged-growth backends (QR, registry-assisted,
// gossip, DHT) land additively without changing the handler shape.
package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HandlerPattern is the substrate pattern path.
const HandlerPattern = "system/discovery"

// Op identifiers.
const (
	OpScan         = "scan"
	OpAnnounce     = "announce"
	OpAnnounceStop = "announce-stop"
)

// DefaultScanCeiling is the §3.1 per-scan candidate-count ceiling default
// (1024 informative). Operator-configurable via SetScanCeiling.
const DefaultScanCeiling = 1024

// Backend is the per-backend contract — implementations (mdns, qr, etc.)
// provide Scan / Announce / AnnounceStop. The substrate owns the candidate
// entity store + watchable-prefix wiring; backends just surface raw
// observations.
//
// Scan returns the current set of observed candidates as their data
// payloads (not yet entitized); the substrate handles ToEntity + Put +
// TreeSet under CandidatePrefix(Kind()). Backends may stream new
// observations between Scan calls via the observe callback wired by
// SetObserveCallback — the same mechanism feeds the watchable surface
// without each consumer needing to invoke `:scan`.
type Backend interface {
	// Kind returns the backend identifier ("mdns", "qr", etc.) — same
	// string that appears in CandidateData.Backend and CandidatePrefix.
	Kind() string

	// Scan returns the current observed candidates honoring the opaque
	// `filter` argument (backends MAY ignore; §3.3). Returning an error
	// surfaces as a substrate error response, NOT silent empty result
	// (§3.3 MUST NOT silently return zero when filter is unparseable).
	Scan(ctx context.Context, filter map[string]cbor.RawMessage) ([]types.CandidateData, error)

	// Announce starts advertising the local peer on this backend.
	// `profileRef` is the transport-profile path-segment the candidate
	// should dial back at (NETWORK §6.5).
	Announce(ctx context.Context, profileRef string) error

	// AnnounceStop ends an announce session per §3 / §8.1 symmetric
	// lifecycle. Idempotent on already-stopped sessions.
	AnnounceStop(ctx context.Context, profileRef string) error

	// SetObserveCallback installs the substrate's per-candidate hooks so
	// the backend can push add / remove events into the watchable prefix
	// between Scan calls — backing the reactive-default model per §3.0.
	// Called once at backend registration. Backends MAY drop the
	// callbacks (one-shot backends like QR have no streaming surface).
	SetObserveCallback(observe func(types.CandidateData), reap func(candidateHash hash.Hash))
}

// OOBBinder is the seam the peer builder injects via SetupStore. Lets
// ext/discovery write candidates to the tree from observe-callback
// goroutines + PromoteSuccessor without importing core/store directly
// (which would tangle the dependency DAG). Real wiring (entity-peer/
// main.go) passes a small adapter over peer.Store() + peer.LocationIndex().
type OOBBinder interface {
	// Bind materializes `ent` (a candidate entity) into the store and
	// binds it at CandidateStoragePath(backend, ent.ContentHash).
	Bind(backend string, ent entity.Entity) error
	// Reap removes the watchable-prefix binding (live surface) for a
	// departed candidate. The content-store entity is NOT removed —
	// historical chain history is retained per §7's knob.
	Reap(backend string, candidateHash hash.Hash) error
	// Get reads a candidate entity from the store by content_hash. Used
	// by PromoteSuccessor to read the original candidate before minting
	// the successor. Returns false if not found.
	Get(candidateHash hash.Hash) (entity.Entity, bool)
}

// Handler implements the system/discovery substrate.
type Handler struct {
	mu          sync.RWMutex
	backends    map[string]Backend
	scanCeiling int
	binder      OOBBinder
	ready       bool
}

// NewHandler returns a substrate with no backends registered. Wire
// backends via RegisterBackend; wire authority via SetupStore.
func NewHandler() *Handler {
	return &Handler{
		backends:    make(map[string]Backend),
		scanCeiling: DefaultScanCeiling,
	}
}

// Name implements handler.Handler.
func (h *Handler) Name() string { return "discovery" }

// SetScanCeiling overrides the §3.1 per-scan candidate-count ceiling.
func (h *Handler) SetScanCeiling(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n < 1 {
		n = DefaultScanCeiling
	}
	h.scanCeiling = n
}

// RegisterBackend installs a backend. Idempotent: same Kind() replaces.
// The backend's observe callbacks are wired immediately so the watchable
// prefix surface is live the moment a peer-construction registers it.
func (h *Handler) RegisterBackend(b Backend) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.backends[b.Kind()] = b
	b.SetObserveCallback(h.observeCallback(b.Kind()), h.reapCallback(b.Kind()))
}

// Backend returns the backend registered under `kind`.
func (h *Handler) Backend(kind string) (Backend, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	b, ok := h.backends[kind]
	return b, ok
}

// SetupStore wires the OOB binder + marks the substrate ready. Until
// called, ops return 503 — same lifecycle pattern as publishedroot /
// registry. The binder seam keeps core/store out of this package's
// imports (the DAG constraint: handler → store → not ext).
func (h *Handler) SetupStore(b OOBBinder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.binder = b
	h.ready = true
}

// Manifest declares the three substrate ops + internal-scope per §5.2.
// The default-grant on the two caps (discovery-scan + discovery-announce)
// to the local peer per §4.1 is wired by the peer builder's seed-policy,
// NOT by the manifest's internal_scope (which governs handler-internal
// dispatch authority, not user-facing default-grant).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "discovery",
		Operations: map[string]types.HandlerOperationSpec{
			OpScan: {
				InputType:  types.TypeDiscoveryScanRequest,
				OutputType: types.TypeDiscoveryScanResult,
			},
			OpAnnounce: {
				InputType: types.TypeDiscoveryAnnounceRequest,
			},
			OpAnnounceStop: {
				InputType: types.TypeDiscoveryAnnounceStopRequest,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern, HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{OpScan, OpAnnounce, OpAnnounceStop}},
			},
		},
	}
}

// RegisterTypes is a no-op — discovery types register centrally in
// core/types.RegisterCoreTypes (D1).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to scan / announce / announce-stop.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	h.mu.RLock()
	ready := h.ready
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"discovery substrate not yet wired (SetupStore pending)")
	}
	switch req.Operation {
	case OpScan:
		return h.handleScan(ctx, req)
	case OpAnnounce:
		return h.handleAnnounce(ctx, req)
	case OpAnnounceStop:
		return h.handleAnnounceStop(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"system/discovery does not support operation: "+req.Operation)
	}
}

// handleScan dispatches `:scan` — backend lookup, snapshot return, write
// candidates into the watchable prefix, enforce §3.1 ceiling with
// non-silent truncation.
func (h *Handler) handleScan(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var rd types.ScanRequestData
	if err := ecf.Decode(req.Params.Data, &rd); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode scan-request: "+err.Error())
	}
	if rd.Backend == "" {
		return handler.NewErrorResponse(400, "invalid_params",
			"scan-request.backend MUST be set")
	}
	b, ok := h.Backend(rd.Backend)
	if !ok {
		return handler.NewErrorResponse(400, "unknown_backend",
			"discovery backend not registered: "+rd.Backend)
	}

	observed, err := b.Scan(ctx, rd.Filter)
	if err != nil {
		// §3.3: MUST NOT silently return zero candidates when filter is
		// unparseable. Backend error surfaces as substrate 500.
		return handler.NewErrorResponse(500, "backend_error",
			"discovery backend "+rd.Backend+" scan failed: "+err.Error())
	}

	ceiling := h.scanCeilingValue()
	truncated := false
	var overflowCode *string
	if len(observed) > ceiling {
		truncated = true
		c := types.DiscoveryErrScanOverflow
		overflowCode = &c
		// §3.1: remaining candidates are dropped from this scan's snapshot
		// (re-invocation with a filter is the user-driven path forward).
		observed = observed[:ceiling]
	}

	snapshot := make([]hash.Hash, 0, len(observed))
	for _, cd := range observed {
		ent, err := cd.ToEntity()
		if err != nil {
			return handler.NewErrorResponse(500, "internal",
				"failed to materialize candidate entity: "+err.Error())
		}
		if err := h.bindCandidate(req.Context, b.Kind(), ent); err != nil {
			return handler.NewErrorResponse(500, "internal", err.Error())
		}
		snapshot = append(snapshot, ent.ContentHash)
	}

	result := types.ScanResultData{
		Candidates: snapshot,
		Truncated:  truncated,
		Code:       overflowCode,
	}
	return handler.NewResponse(200, types.TypeDiscoveryScanResult, result)
}

func (h *Handler) handleAnnounce(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var rd types.AnnounceRequestData
	if err := ecf.Decode(req.Params.Data, &rd); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode announce-request: "+err.Error())
	}
	if rd.Backend == "" || rd.ProfileRef == "" {
		return handler.NewErrorResponse(400, "invalid_params",
			"announce-request.backend + .profile_ref MUST be set")
	}
	b, ok := h.Backend(rd.Backend)
	if !ok {
		return handler.NewErrorResponse(400, "unknown_backend",
			"discovery backend not registered: "+rd.Backend)
	}
	if err := b.Announce(ctx, rd.ProfileRef); err != nil {
		return handler.NewErrorResponse(500, "backend_error",
			"announce on "+rd.Backend+" failed: "+err.Error())
	}
	return &handler.Response{Status: 200}, nil
}

func (h *Handler) handleAnnounceStop(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var rd types.AnnounceStopRequestData
	if err := ecf.Decode(req.Params.Data, &rd); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode announce-stop-request: "+err.Error())
	}
	if rd.Backend == "" || rd.ProfileRef == "" {
		return handler.NewErrorResponse(400, "invalid_params",
			"announce-stop-request.backend + .profile_ref MUST be set")
	}
	b, ok := h.Backend(rd.Backend)
	if !ok {
		return handler.NewErrorResponse(400, "unknown_backend",
			"discovery backend not registered: "+rd.Backend)
	}
	if err := b.AnnounceStop(ctx, rd.ProfileRef); err != nil {
		return handler.NewErrorResponse(500, "backend_error",
			"announce-stop on "+rd.Backend+" failed: "+err.Error())
	}
	return &handler.Response{Status: 200}, nil
}

func (h *Handler) scanCeilingValue() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.scanCeiling
}

// PromoteSuccessor mints a successor candidate per §2.2 — the IDENTIFY-
// complete hook substrate. Callers (the IDENTIFY-completion path) supply
// the original candidate's hash + the verified peer-id + the actual
// IdentityClaim reconstructed from the IDENTIFY result. The successor
// candidate is bound at the watchable prefix; the original remains in
// place as the observation record.
//
// Fail-closed semantics per §2.2.1 + §8.4 MUST NOT:
//   - If the original candidate's IdentityHint is non-nil, the constructed
//     IdentityClaim's content_hash MUST equal that hint. Mismatch returns
//     an error AND leaves the candidate chain unaltered.
//   - If IdentityHint is nil (TOFU), no compare runs — admission rests on
//     the §2 grant decision alone.
//
// Returns the successor candidate's content_hash on success.
func (h *Handler) PromoteSuccessor(
	originalHash hash.Hash,
	identifiedPeerID string,
	actualClaim types.IdentityClaimData,
) (hash.Hash, error) {
	h.mu.RLock()
	ready := h.ready
	binder := h.binder
	h.mu.RUnlock()
	if !ready || binder == nil {
		return hash.Hash{}, fmt.Errorf("discovery substrate not ready (SetupStore pending)")
	}

	ent, ok := binder.Get(originalHash)
	if !ok {
		return hash.Hash{}, fmt.Errorf("original candidate not found in store: %x", originalHash.Bytes())
	}
	original, err := types.CandidateDataFromEntity(ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("decode original candidate: %w", err)
	}

	if original.IdentityHint != nil {
		claimEnt, err := actualClaim.ToEntity()
		if err != nil {
			return hash.Hash{}, fmt.Errorf("materialize actual identity-claim: %w", err)
		}
		if claimEnt.ContentHash != *original.IdentityHint {
			// §2.2.1 + §8.4: fail-closed. Do NOT mint a successor; do NOT
			// fall back to a soft warning. Caller MUST refuse admission.
			return hash.Hash{}, fmt.Errorf(
				"identity_hint mismatch: candidate advertised %x, IDENTIFY produced %x — admission MUST fail closed per §2.2.1",
				original.IdentityHint.Bytes(), claimEnt.ContentHash.Bytes())
		}
	}

	successor := types.CandidateData{
		PeerID:       identifiedPeerID,
		Backend:      original.Backend,
		ObservedAt:   uint64(time.Now().UnixMilli()),
		EndpointHint: original.EndpointHint, // inherit — same physical observation
		IdentityHint: original.IdentityHint, // preserved for audit
		Supersedes:   &originalHash,
	}
	successorEnt, err := successor.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("materialize successor candidate: %w", err)
	}
	if err := binder.Bind(original.Backend, successorEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("bind successor candidate: %w", err)
	}
	return successorEnt.ContentHash, nil
}

// observeCallback returns a closure backends invoke when a new candidate
// arrives between Scan calls (mDNS announcement, post-query response, etc).
// Per §3.0 reactive-default model.
func (h *Handler) observeCallback(backend string) func(types.CandidateData) {
	return func(cd types.CandidateData) {
		h.mu.RLock()
		binder := h.binder
		h.mu.RUnlock()
		if binder == nil {
			return
		}
		ent, err := cd.ToEntity()
		if err != nil {
			return
		}
		_ = binder.Bind(backend, ent)
	}
}

// reapCallback returns a closure backends invoke when a candidate departs
// (mDNS goodbye record, TTL expiry per §3.0.1). The substrate removes
// the watchable-prefix binding.
func (h *Handler) reapCallback(backend string) func(hash.Hash) {
	return func(candidateHash hash.Hash) {
		h.mu.RLock()
		binder := h.binder
		h.mu.RUnlock()
		if binder == nil {
			return
		}
		_ = binder.Reap(backend, candidateHash)
	}
}

// bindCandidate writes the candidate entity using the in-flight handler
// context (preferred path during :scan / dispatch). Per V7 emit-cascade
// discipline, in-flight TreeSet is preferred over OOB direct writes when
// available so subscribers see the write in cascade order.
func (h *Handler) bindCandidate(hctx *handler.HandlerContext, backend string, ent entity.Entity) error {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		// Synthetic / test-time dispatch with no store. Use OOB binder.
		h.mu.RLock()
		binder := h.binder
		h.mu.RUnlock()
		if binder == nil {
			return fmt.Errorf("bindCandidate: no store wired (SetupStore + HandlerContext both empty)")
		}
		return binder.Bind(backend, ent)
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return fmt.Errorf("store candidate entity: %w", err)
	}
	path := types.CandidateStoragePath(backend, ent.ContentHash)
	if _, err := hctx.TreeSet(path, ent.ContentHash, "discovery-scan-observe"); err != nil {
		return fmt.Errorf("bind candidate at %s: %w", path, err)
	}
	return nil
}

