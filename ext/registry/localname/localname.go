// Package local-name implements the v1 concrete REGISTRY backend per
// EXTENSION-REGISTRY §6. LocalNames are user-assigned local names for peer
// identities; the user IS the trust source (no signature ceremony, no
// authority semantics, no cross-peer sync).
//
// Storage shape per §6.3 (two-layer pattern):
//   - binding body at `system/registry/binding/{binding_hash_hex}` —
//     content-addressed, immutable, shared with §3 universal location.
//   - tree pointer at `system/registry/binding/local-name/{name}` — the
//     live name→hash index; mutable per :bind / :unbind / :update-transports.
//   - supersedes chain is the audit log, walked by hash lookup.
//
// Handler operations per §6.5: bind, unbind, list, update-transports.
// :resolve is exported separately so the meta-resolver in ext/registry can
// dispatch the local-name backend's lookup without crossing the handler
// boundary.
package localname

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/text/unicode/norm"
)

// HandlerPattern is the local-name backend's handler registration pattern.
// The substrate's `system/registry:resolve` op is served by the
// meta-resolver in ext/registry; this pattern carries the four backend-
// specific operations.
const HandlerPattern = "system/registry/local-name"

// Operation names per §6.5.
const (
	OpBind             = "bind"
	OpUnbind           = "unbind"
	OpList             = "list"
	OpUpdateTransports = "update-transports"
)

// Handler implements the §6 local-name backend.
type Handler struct {
	mu     sync.RWMutex
	cs     store.ContentStore
	li     store.LocationIndex
	peerID crypto.PeerID
	clock  func() uint64 // ms-since-epoch; overridable in tests
}

// NewHandler builds a local-name handler. SetupStore wires the store +
// location index post-peer-construction.
func NewHandler() *Handler {
	return &Handler{}
}

// Name returns the handler name surfaced by manifests.
func (h *Handler) Name() string { return "registry-local-name" }

// Kind returns the §2.4.1 backend_kind string the meta-resolver matches
// against resolver-config.resolver_chain[].backend_kind. Pin: "local-name".
func (h *Handler) Kind() string { return types.BackendKindLocalName }

// ID returns this backend's identifier for resolver-config matching.
// v1 is single-store per peer; the local peer's base58 peer-id is the
// natural id, but resolver-config entries with BackendID = "" or "local"
// also match (the meta-resolver's pragmatic default — §6.2).
func (h *Handler) ID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return string(h.peerID)
}

// SetupStore wires the store, location index, and local peer ID. The
// optional `clock` overrides the default wall-clock used to stamp
// `issued_at` on new bindings; pass nil for the default.
func (h *Handler) SetupStore(cs store.ContentStore, li store.LocationIndex, peerID crypto.PeerID, clock func() uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
	if clock != nil {
		h.clock = clock
	} else {
		h.clock = defaultClock
	}
}

func defaultClock() uint64 {
	return uint64(time.Now().UnixMilli())
}

// Manifest declares the four backend ops + their default-grant scope per
// §5.2 ([[feedback_dont_drop_default_grants_implement_them]]: the local
// peer gets the registry-local-name-{bind,unbind,list} caps on first install).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "registry-local-name",
		Operations: map[string]types.HandlerOperationSpec{
			OpBind: {
				InputType:  types.TypeRegistryLocalNameBindRequest,
				OutputType: types.TypeRegistryLocalNameBindResult,
			},
			OpUnbind: {
				InputType: types.TypeRegistryLocalNameUnbindRequest,
			},
			OpList: {
				InputType:  types.TypeRegistryLocalNameListRequest,
				OutputType: types.TypeRegistryLocalNameListResult,
			},
			OpUpdateTransports: {
				InputType:  types.TypeRegistryLocalNameUpdateTransports,
				OutputType: types.TypeRegistryLocalNameBindResult,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{OpBind, OpUnbind, OpList, OpUpdateTransports}},
			},
		},
	}
}

// RegisterTypes is a no-op — local-name types are registered centrally in
// core/types.RegisterCoreTypes (the registry extension's types are
// shared with the meta-resolver and cross-impl tooling).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	_ = reflect.TypeOf // keep import shape consistent with sibling pkgs
}

// Handle dispatches the four backend operations.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case OpBind:
		return h.handleBind(ctx, req)
	case OpUnbind:
		return h.handleUnbind(ctx, req)
	case OpList:
		return h.handleList(ctx, req)
	case OpUpdateTransports:
		return h.handleUpdateTransports(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			HandlerPattern+" does not support operation: "+req.Operation)
	}
}

// --- Handler op implementations ------------------------------------------

func (h *Handler) handleBind(_ context.Context, req *handler.Request) (*handler.Response, error) {
	body, err := types.LocalNameBindRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode local-name bind request: "+err.Error())
	}
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	bindingHash, err := h.Bind(hctx, body.Name, body.TargetPeerID, body.Transports, body.Notes)
	if err != nil {
		return errToResponse(err)
	}
	return handler.NewResponse(200, types.TypeRegistryLocalNameBindResult,
		types.LocalNameBindResultData{BindingHash: bindingHash})
}

func (h *Handler) handleUnbind(_ context.Context, req *handler.Request) (*handler.Response, error) {
	body, err := types.LocalNameUnbindRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode local-name unbind request: "+err.Error())
	}
	hctx := req.Context
	if hctx == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing location index")
	}
	if err := h.Unbind(hctx, body.Name); err != nil {
		return errToResponse(err)
	}
	return &handler.Response{Status: 200}, nil
}

func (h *Handler) handleList(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	entries, err := h.List(hctx)
	if err != nil {
		return errToResponse(err)
	}
	return handler.NewResponse(200, types.TypeRegistryLocalNameListResult,
		types.LocalNameListResultData{Entries: entries})
}

func (h *Handler) handleUpdateTransports(_ context.Context, req *handler.Request) (*handler.Response, error) {
	body, err := types.LocalNameUpdateTransportsRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode local-name update-transports request: "+err.Error())
	}
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}
	bindingHash, err := h.UpdateTransports(hctx, body.Name, body.Transports)
	if err != nil {
		return errToResponse(err)
	}
	return handler.NewResponse(200, types.TypeRegistryLocalNameBindResult,
		types.LocalNameBindResultData{BindingHash: bindingHash})
}

// --- Direct API (used by handler ops, in-process tests, meta-resolver) ---

// Bind creates a new local-name binding for `name` → `targetPeerID`. Implements
// §6.5: NFC + case-fold, name-path safety, supersede-on-rebind (if config
// allows), 409 conflict otherwise, atomic body+pointer write.
func (h *Handler) Bind(hctx *handler.HandlerContext, name, targetPeerID string, transports []hash.Hash, notes *string) (hash.Hash, error) {
	cfg, err := h.loadOrDefaultConfig(hctx)
	if err != nil {
		return hash.Hash{}, err
	}
	normalized, err := normalize(name, cfg.CaseNormalization)
	if err != nil {
		return hash.Hash{}, err
	}
	pointerPath := types.LocalNamePointerPath(normalized)
	existing, hadExisting := hctx.LocationIndex.Get(pointerPath)
	if hadExisting && !cfg.AllowSupersede {
		return hash.Hash{}, &registryError{
			status: 409,
			code:   types.RegistryErrBindAlreadyExists,
			msg:    fmt.Sprintf("local-name %q already bound (allow_supersede=false)", normalized),
		}
	}

	binding := types.BindingData{
		Name:         normalized,
		Kind:         types.BindingKindLocalName,
		TargetPeerID: targetPeerID,
		Transports:   transports,
		IssuedAt:     h.clockOrDefault(),
		Metadata: map[string]cbor.RawMessage{
			"pinned": mustEncode(cfg.DefaultPinned),
		},
	}
	if notes != nil {
		binding.Metadata["notes"] = mustEncode(*notes)
	} else {
		binding.Metadata["notes"] = mustEncode(nilString())
	}
	if hadExisting {
		prev := existing
		binding.Supersedes = &prev
	}

	bindingEnt, err := binding.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode binding: %w", err)
	}
	if _, err := hctx.Store.Put(bindingEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("store binding: %w", err)
	}

	// Two-layer storage atomicity: body first, then pointer. If pointer
	// write fails, the body persists as an orphan (GC sweeps it); the
	// pointer remains pointing at the previous binding. Correctness
	// preserved.
	bodyPath := types.BindingStoragePath(bindingEnt.ContentHash)
	if _, err := hctx.TreeSet(bodyPath, bindingEnt.ContentHash, "local-name-bind"); err != nil {
		return hash.Hash{}, fmt.Errorf("bind body at %s: %w", bodyPath, err)
	}
	if _, err := hctx.TreeSet(pointerPath, bindingEnt.ContentHash, "local-name-bind"); err != nil {
		return hash.Hash{}, fmt.Errorf("bind pointer at %s: %w", pointerPath, err)
	}
	return bindingEnt.ContentHash, nil
}

// Unbind removes a local-name's tree pointer. The binding body remains in
// the content tree as an audit-log entry per §6.5.
func (h *Handler) Unbind(hctx *handler.HandlerContext, name string) error {
	cfg, err := h.loadOrDefaultConfig(hctx)
	if err != nil {
		return err
	}
	normalized, err := normalize(name, cfg.CaseNormalization)
	if err != nil {
		return err
	}
	hctx.TreeRemove(types.LocalNamePointerPath(normalized), "local-name-unbind")
	return nil
}

// List returns one entry per live tree pointer under
// `system/registry/binding/local-name/`, sorted by name (LocationIndex.List
// returns prefix entries sorted ascending).
func (h *Handler) List(hctx *handler.HandlerContext) ([]types.LocalNameListEntry, error) {
	prefix := "system/registry/binding/local-name/"
	entries := hctx.LocationIndex.List(prefix)
	out := make([]types.LocalNameListEntry, 0, len(entries))
	for _, e := range entries {
		// LocationEntry.Path is qualified ("/{peerID}/system/registry/...").
		// Strip back to the bare name.
		bare := barePath(e.Path)
		name := strings.TrimPrefix(bare, prefix)
		if name == bare {
			continue // shouldn't happen
		}
		body, ok := hctx.Store.Get(e.Hash)
		if !ok {
			continue
		}
		bind, err := types.BindingDataFromEntity(body)
		if err != nil {
			continue
		}
		entry := types.LocalNameListEntry{
			Name:         name,
			Hash:         e.Hash,
			TargetPeerID: bind.TargetPeerID,
			Pinned:       extractPinned(bind.Metadata),
		}
		if notes := extractNotes(bind.Metadata); notes != "" {
			entry.Notes = &notes
		}
		out = append(out, entry)
	}
	return out, nil
}

// UpdateTransports issues a successor binding with the same target_peer_id
// and new transports list. Returns the new binding's content_hash.
func (h *Handler) UpdateTransports(hctx *handler.HandlerContext, name string, transports []hash.Hash) (hash.Hash, error) {
	cfg, err := h.loadOrDefaultConfig(hctx)
	if err != nil {
		return hash.Hash{}, err
	}
	normalized, err := normalize(name, cfg.CaseNormalization)
	if err != nil {
		return hash.Hash{}, err
	}
	pointerPath := types.LocalNamePointerPath(normalized)
	existingHash, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		return hash.Hash{}, &registryError{
			status: 404,
			code:   "not_found",
			msg:    fmt.Sprintf("local-name %q not bound — cannot update transports", normalized),
		}
	}
	bodyEnt, ok := hctx.Store.Get(existingHash)
	if !ok {
		return hash.Hash{}, fmt.Errorf("local-name %q pointer dangles", normalized)
	}
	existing, err := types.BindingDataFromEntity(bodyEnt)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("decode existing binding: %w", err)
	}

	successor := existing
	successor.Transports = transports
	successor.IssuedAt = h.clockOrDefault()
	prev := existingHash
	successor.Supersedes = &prev

	bindingEnt, err := successor.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("encode successor binding: %w", err)
	}
	if _, err := hctx.Store.Put(bindingEnt); err != nil {
		return hash.Hash{}, fmt.Errorf("store successor: %w", err)
	}
	bodyPath := types.BindingStoragePath(bindingEnt.ContentHash)
	if _, err := hctx.TreeSet(bodyPath, bindingEnt.ContentHash, "local-name-update-transports"); err != nil {
		return hash.Hash{}, fmt.Errorf("bind successor body: %w", err)
	}
	if _, err := hctx.TreeSet(pointerPath, bindingEnt.ContentHash, "local-name-update-transports"); err != nil {
		return hash.Hash{}, fmt.Errorf("update pointer: %w", err)
	}
	return bindingEnt.ContentHash, nil
}

// Resolve implements §6.5 :resolve for the local-name backend. Returns a
// ResolveResultData with status=resolved (transports MAY be empty) or
// status=not_found. Called by the meta-resolver in ext/registry.
func (h *Handler) Resolve(hctx *handler.HandlerContext, name string) (types.ResolveResultData, error) {
	cfg, err := h.loadOrDefaultConfig(hctx)
	if err != nil {
		return types.ResolveResultData{}, err
	}
	normalized, err := normalize(name, cfg.CaseNormalization)
	if err != nil {
		return types.ResolveResultData{}, err
	}
	pointerPath := types.LocalNamePointerPath(normalized)
	pointer, ok := hctx.LocationIndex.Get(pointerPath)
	if !ok {
		return types.ResolveResultData{Status: types.ResolutionStatusNotFound}, nil
	}
	bodyEnt, ok := hctx.Store.Get(pointer)
	if !ok {
		// Pointer dangles — treat as not_found rather than 500; cohort policy.
		return types.ResolveResultData{Status: types.ResolutionStatusNotFound}, nil
	}
	bind, err := types.BindingDataFromEntity(bodyEnt)
	if err != nil {
		return types.ResolveResultData{}, fmt.Errorf("decode local-name body: %w", err)
	}
	binding := pointer
	return types.ResolveResultData{
		Status:      types.ResolutionStatusResolved,
		Binding:     &binding,
		PeerID:      bind.TargetPeerID,
		Transports:  bind.Transports,
		TrustAnchor: types.TrustAnchorLocalName,
		BackendID:   string(h.peerID),
	}, nil
}

// --- Helpers --------------------------------------------------------------

// loadOrDefaultConfig reads system/registry/local-name-config or returns the
// §6.4 defaults (default_pinned=true, allow_supersede=true, case=none).
//
// Reads fresh on every call — no in-memory cache. The lookup is one
// LocationIndex.Get + one ContentStore.Get; the cost is negligible vs.
// the cache-invalidation complexity of an op-time stale-config read.
// (The cohort review's "operator updates local-name-config → next op sees
// it" test relies on this fresh-read posture.)
func (h *Handler) loadOrDefaultConfig(hctx *handler.HandlerContext) (types.LocalNameConfigData, error) {
	cfg := types.LocalNameConfigData{
		DefaultPinned:     true,
		AllowSupersede:    true,
		CaseNormalization: types.CaseNormalizationNone,
	}
	if hctx != nil && hctx.LocationIndex != nil && hctx.Store != nil {
		if cfgHash, ok := hctx.LocationIndex.Get(types.LocalNameConfigStoragePath); ok {
			if cfgEnt, ok := hctx.Store.Get(cfgHash); ok {
				if loaded, err := types.LocalNameConfigDataFromEntity(cfgEnt); err == nil {
					cfg = loaded
				}
			}
		}
	}
	return cfg, nil
}

func (h *Handler) clockOrDefault() uint64 {
	if h.clock == nil {
		return defaultClock()
	}
	return h.clock()
}

// normalize applies the §6.3 name-path safety + NFC normalization +
// optional case-fold (per local-name-config.case_normalization).
func normalize(name, caseNorm string) (string, error) {
	if !norm.NFC.IsNormalString(name) {
		name = norm.NFC.String(name)
	}
	if err := validateName(name); err != nil {
		return "", err
	}
	if caseNorm == types.CaseNormalizationLower {
		name = strings.ToLower(name)
	}
	return name, nil
}

// validateName enforces §6.3 path safety: no `/`, no control chars
// (U+0000–U+0020 + U+007F).
func validateName(name string) error {
	if name == "" {
		return &registryError{status: 400, code: types.RegistryErrBindInvalidName, msg: "name is empty"}
	}
	for _, r := range name {
		if r == '/' {
			return &registryError{
				status: 400,
				code:   types.RegistryErrBindInvalidName,
				msg:    "name contains '/' (path separator forbidden per §6.3)",
			}
		}
		if (r >= 0x0000 && r <= 0x0020) || r == 0x007F {
			return &registryError{
				status: 400,
				code:   types.RegistryErrBindInvalidName,
				msg:    fmt.Sprintf("name contains control character U+%04X (forbidden per §6.3)", r),
			}
		}
	}
	return nil
}

// registryError is the typed error the REGISTRY domain returns; the
// EXECUTE wrapper converts it to a status-coded Response per §6.5.
type registryError struct {
	status int
	code   string
	msg    string
}

func (e *registryError) Error() string { return e.code + ": " + e.msg }

func errToResponse(err error) (*handler.Response, error) {
	if re, ok := err.(*registryError); ok {
		return handler.NewErrorResponse(uint(re.status), re.code, re.msg)
	}
	return handler.NewErrorResponse(500, "internal_error", err.Error())
}


// mustEncode is the ECF wrapper. Panics on encoding failure — only called
// with primitive values where encoding cannot fail in practice.
func mustEncode(v any) cbor.RawMessage {
	raw, err := ecf.Encode(v)
	if err != nil {
		panic("local-name mustEncode: " + err.Error())
	}
	return cbor.RawMessage(raw)
}

// nilString returns the typed nil-string sentinel for `notes: null` in
// metadata (consumers decode this as null).
func nilString() any {
	var s *string
	return s
}

// extractPinned decodes the metadata["pinned"] bool, defaulting to true.
func extractPinned(meta map[string]cbor.RawMessage) bool {
	raw, ok := meta["pinned"]
	if !ok {
		return true
	}
	var v bool
	if err := ecf.Decode(raw, &v); err != nil {
		return true
	}
	return v
}

// extractNotes decodes the metadata["notes"] string, returning "" for
// nil or missing.
func extractNotes(meta map[string]cbor.RawMessage) string {
	raw, ok := meta["notes"]
	if !ok {
		return ""
	}
	var v *string
	if err := ecf.Decode(raw, &v); err == nil && v != nil {
		return *v
	}
	var s string
	if err := ecf.Decode(raw, &s); err == nil {
		return s
	}
	return ""
}

// barePath returns the peer-relative path for `absPath`. Mirrors the
// helper in ext/attestation/handler.go (kept local to avoid cross-pkg
// dep just for this 10-line function).
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
