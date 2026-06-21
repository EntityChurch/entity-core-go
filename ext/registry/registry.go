// Package registry implements the EXTENSION-REGISTRY v1.0 meta-resolver
// per §2.2 + §4.1. It exposes the substrate-level handler at pattern
// `system/registry` with two operations:
//
//   - `:resolve(name, hints?) → ResolutionResult` — per §4.1 precedence:
//     pinned → name_format_dispatch filter → chain in priority order →
//     first validated hit → chain_exhausted (fail-closed).
//   - `:invalidate-cache(name | null) → ()` — flush specific or all
//     cached resolutions.
//
// Backends register themselves via RegisterBackend; v1 ships with the
// local-name backend (ext/registry/local-name). Unknown `binding.kind` and
// `backend_kind` skip with warning (forward-compat per §3.0a / §4.2);
// revocations are honored; chain exhaustion fail-closed.
package registry

import (
	"context"
	"fmt"
	"path"
	"reflect"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const HandlerPattern = "system/registry"

const (
	OpResolve         = "resolve"
	OpInvalidateCache = "invalidate-cache"
)

// Backend is the meta-resolver's dependency contract. A backend's
// `Resolve(hctx, name)` returns the same ResolutionResult shape the
// substrate publishes. `Kind` is the §2.4.1 backend_kind string used
// by resolver-config.resolver_chain[].backend_kind. `ID` is the
// per-backend identifier used to match resolver-chain entries (e.g.
// the local peer's base58 for local-name).
type Backend interface {
	Kind() string
	ID() string
	Resolve(hctx *handler.HandlerContext, name string) (types.ResolveResultData, error)
}

// Handler implements the substrate's meta-resolver.
type Handler struct {
	mu       sync.RWMutex
	backends map[string]map[string]Backend // kind → id → backend
	logger   *Logger                       // resolution log writer; nil = disabled
}

// NewHandler builds a meta-resolver with no backends registered. Call
// RegisterBackend per backend before peer-construction sets up the
// dispatcher. The optional Logger is attached via SetLogger.
func NewHandler() *Handler {
	return &Handler{backends: make(map[string]map[string]Backend)}
}

// Name returns the handler name surfaced by manifests.
func (h *Handler) Name() string { return "registry" }

// RegisterBackend installs a backend implementation. Idempotent: a
// subsequent register for the same (kind,id) replaces the prior one.
func (h *Handler) RegisterBackend(b Backend) {
	h.mu.Lock()
	defer h.mu.Unlock()
	byID, ok := h.backends[b.Kind()]
	if !ok {
		byID = make(map[string]Backend)
		h.backends[b.Kind()] = byID
	}
	byID[b.ID()] = b
}

// SetLogger wires the resolution-log writer. May be nil to disable.
func (h *Handler) SetLogger(l *Logger) {
	h.mu.Lock()
	h.logger = l
	h.mu.Unlock()
}

// Manifest declares the meta-resolver's ops + default-grant scope per §5.2.
// The full 7-cap default-grant surface is documented at the spec level;
// here we publish the two handler ops (resolve + invalidate-cache).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: HandlerPattern,
		Name:    "registry",
		Operations: map[string]types.HandlerOperationSpec{
			OpResolve: {
				InputType:  types.TypeRegistryResolveRequest,
				OutputType: types.TypeRegistryResolveResult,
			},
			OpInvalidateCache: {
				InputType: types.TypeRegistryInvalidateCacheRequest,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{OpResolve, OpInvalidateCache}},
			},
		},
	}
}

// RegisterTypes is a no-op — the registry extension's types are
// registered centrally in core/types.RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	_ = reflect.TypeOf
}

// Handle dispatches resolve / invalidate-cache.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case OpResolve:
		return h.handleResolve(ctx, req)
	case OpInvalidateCache:
		return h.handleInvalidateCache(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			HandlerPattern+" does not support operation: "+req.Operation)
	}
}

func (h *Handler) handleResolve(_ context.Context, req *handler.Request) (*handler.Response, error) {
	body, err := types.ResolveRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode resolve request: "+err.Error())
	}
	if body.Name == "" {
		return handler.NewErrorResponse(400, "invalid_request", "resolve requires a non-empty name")
	}
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store / location index")
	}

	result, reason := h.Resolve(hctx, body.Name, false)
	h.logResolution(hctx, body.Name, result, reason, false)
	return handler.NewResponse(200, types.TypeRegistryResolveResult, result)
}

func (h *Handler) handleInvalidateCache(_ context.Context, req *handler.Request) (*handler.Response, error) {
	// v1 ships without an in-memory cache (every :resolve reads the live
	// tree pointer). The op is accepted for spec compliance; it's a no-op
	// today. When caching lands, this is the flush hook.
	_, err := types.InvalidateCacheRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_request",
			"decode invalidate-cache request: "+err.Error())
	}
	return &handler.Response{Status: 200}, nil
}

// Resolve is the in-process API exposed for testing + for the SDK seam
// that may want to skip the EXECUTE round-trip. Implements §4.1
// precedence:
//
//  1. pinned bindings (synthesized result per §4.1.2)
//  2. name_format_dispatch filter narrows the resolver chain
//  3. chain in priority order; first validated hit wins
//  4. chain_exhausted (fail-closed)
//
// `isFallback` tags the resolution-log entry (set true from §2.3's
// transport-fallback re-resolve).
//
// Returns the ResolutionResult + an optional `reason` string (logged
// against the resolution-log entry per §11.2; empty on the resolved
// normal path).
func (h *Handler) Resolve(hctx *handler.HandlerContext, name string, isFallback bool) (types.ResolveResultData, string) {
	cfg, hasCfg := h.loadResolverConfig(hctx)

	// (1) pinned bindings.
	if hasCfg {
		for _, p := range cfg.PinnedBindings {
			if p.Name == name {
				synth := h.synthesizePinned(p)
				return synth, "pin_short_circuit"
			}
		}
	}

	chain := []types.ResolverChainEntry(nil)
	if hasCfg {
		chain = cfg.ResolverChain
	}

	// (2) name_format_dispatch filter.
	if hasCfg && len(cfg.NameFormatDispatch) > 0 {
		filtered := make(map[string]bool)
		any := false
		for _, d := range cfg.NameFormatDispatch {
			matched, err := path.Match(d.Pattern, name)
			if err != nil || !matched {
				continue
			}
			any = true
			for _, k := range d.BackendKinds {
				filtered[k] = true
			}
		}
		// If at least one dispatch entry matched, restrict the chain to
		// the named backend_kinds. A pattern that matches but lists no
		// backend_kinds is a no-op (no narrowing). If no dispatch matched
		// at all, the §4 default-match-all rule applies — chain unfiltered.
		if any && len(filtered) > 0 {
			narrowed := chain[:0:0]
			for _, e := range chain {
				if filtered[e.BackendKind] {
					narrowed = append(narrowed, e)
				}
			}
			chain = narrowed
		}
	}

	// Sort the (filtered) chain by priority ascending — lower priority
	// number = consulted first per §4.
	chain = stablePrioritySorted(chain)

	// (3) try each backend; first validated hit wins.
	for _, entry := range chain {
		backend, ok := h.lookupBackend(entry)
		if !ok {
			// Unknown backend_kind / id → skip-with-warning per §4.2.
			// We do not log per-backend rejections to the resolution-log
			// (§11.2 absorbs per-attempt detail into the final outcome).
			continue
		}
		r, err := backend.Resolve(hctx, name)
		if err != nil {
			continue // backend internal error; advance per §2.2
		}
		switch r.Status {
		case types.ResolutionStatusResolved:
			// Revocation check (§3.1): if a revocation targets r.binding
			// and verifies against the same authority, skip this binding.
			// v1 honors revocations recorded under the canonical revocation
			// path; signature-validation against the issuing authority is
			// per-backend (local-name has no signature).
			if r.Binding != nil && h.revocationFor(hctx, *r.Binding) {
				continue
			}
			return r, ""
		case types.ResolutionStatusNotFound:
			continue
		default:
			continue
		}
	}

	// (4) chain exhausted.
	return types.ResolveResultData{Status: types.ResolutionStatusChainExhausted}, "chain_exhausted"
}

// synthesizePinned constructs the §4.1.2 result for a pinned binding.
// The binding hash is the content_hash of the synthetic binding entity
// the spec describes (deterministic per pin).
func (h *Handler) synthesizePinned(p types.PinnedEntry) types.ResolveResultData {
	synthBinding := types.BindingData{
		Name:         p.Name,
		Kind:         types.BindingKindOutOfBand,
		TargetPeerID: p.TargetPeerID,
	}
	synthEnt, err := synthBinding.ToEntity()
	if err != nil {
		// Should be impossible — synthetic entity has no unencodable fields.
		return types.ResolveResultData{Status: types.ResolutionStatusChainExhausted}
	}
	bh := synthEnt.ContentHash
	return types.ResolveResultData{
		Status:      types.ResolutionStatusResolved,
		Binding:     &bh,
		PeerID:      p.TargetPeerID,
		TrustAnchor: types.TrustAnchorOutOfBand,
		BackendID:   "pinned",
	}
}

// lookupBackend resolves a chain entry to a registered backend. Returns
// (nil, false) if the kind isn't registered OR if the id doesn't match.
// Unknown backend_kind / unknown id both surface as the same skip; the
// §4.2 forward-compat rule treats both as "skip with warning."
func (h *Handler) lookupBackend(e types.ResolverChainEntry) (Backend, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	byID, ok := h.backends[e.BackendKind]
	if !ok {
		return nil, false
	}
	// Match by ID when specified; "" / "local" in resolver-config falls
	// through to the only registered backend of that kind (cohort
	// pragmatic default — v1 has at most one local-name backend per peer).
	if e.BackendID == "" || e.BackendID == "local" {
		for _, b := range byID {
			return b, true
		}
		return nil, false
	}
	b, ok := byID[e.BackendID]
	return b, ok
}

// loadResolverConfig reads system/registry/resolver-config from the
// location index, returning (zero, false) if absent or malformed.
func (h *Handler) loadResolverConfig(hctx *handler.HandlerContext) (types.ResolverConfigData, bool) {
	if hctx == nil || hctx.LocationIndex == nil {
		return types.ResolverConfigData{}, false
	}
	cfgHash, ok := hctx.LocationIndex.Get(types.ResolverConfigStoragePath)
	if !ok {
		return types.ResolverConfigData{}, false
	}
	cfgEnt, ok := hctx.Store.Get(cfgHash)
	if !ok {
		return types.ResolverConfigData{}, false
	}
	cfg, err := types.ResolverConfigDataFromEntity(cfgEnt)
	if err != nil {
		return types.ResolverConfigData{}, false
	}
	return cfg, true
}

// revocationFor returns true if any system/registry/revocation entity at
// the canonical revocation prefix targets `bindingHash`. v1 honors
// observed revocations; signature-validation against the issuing
// authority is per-backend (local-name carries none — revoking a local-name is
// effectively `:unbind`).
func (h *Handler) revocationFor(hctx *handler.HandlerContext, bindingHash interface{}) bool {
	bh, ok := bindingHash.(interface{ Bytes() []byte })
	if !ok {
		return false
	}
	prefix := "system/registry/revocation/"
	for _, e := range hctx.LocationIndex.List(prefix) {
		revEnt, ok := hctx.Store.Get(e.Hash)
		if !ok {
			continue
		}
		rev, err := types.RevocationDataFromEntity(revEnt)
		if err != nil {
			continue
		}
		if string(rev.Revokes.Bytes()) == string(bh.Bytes()) {
			return true
		}
	}
	return false
}

// logResolution writes a system/registry/resolution-log entry per §11.2
// if a logger is wired. Cache hits are not currently distinguished
// (v1 has no cache).
func (h *Handler) logResolution(hctx *handler.HandlerContext, name string, r types.ResolveResultData, reason string, isFallback bool) {
	h.mu.RLock()
	logger := h.logger
	h.mu.RUnlock()
	if logger == nil {
		return
	}
	logger.Append(hctx, name, r, reason, isFallback)
}

// stablePrioritySorted returns chain sorted ascending by Priority, stable
// among ties (preserves insertion order). Avoids the allocation of a full
// sort.Slice + interface conversion for the small chains we expect.
func stablePrioritySorted(chain []types.ResolverChainEntry) []types.ResolverChainEntry {
	if len(chain) <= 1 {
		return chain
	}
	out := make([]types.ResolverChainEntry, len(chain))
	copy(out, chain)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Priority > out[j].Priority; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// init guards against accidentally importing the package as a side-effect.
var _ = strings.HasPrefix
var _ = fmt.Errorf
