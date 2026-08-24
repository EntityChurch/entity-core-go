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
	"os"
	"reflect"
	"strings"
	"sync"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

const HandlerPattern = "system/registry"

const (
	OpResolve           = "resolve"
	OpInvalidateCache   = "invalidate-cache"
	OpSetResolverConfig = "set-resolver-config"
	OpGetResolverConfig = "get-resolver-config"
)

// Backend is the meta-resolver's dependency contract. A backend's
// `Resolve(hctx, name, localMaxTTL)` returns the same ResolutionResult shape the
// substrate publishes. `Kind` is the §2.4.1 backend_kind string used
// by resolver-config.resolver_chain[].backend_kind. `ID` is the
// per-backend identifier used to match resolver-chain entries (e.g.
// the local peer's base58 for local-name).
//
// `localMaxTTL` is the resolver-side TTL ceiling for THIS chain entry
// (REGISTRY §6a.9.1, ruled [v1.16]): the durable `resolver_chain[].hints.max_ttl`,
// read fresh from resolver-config at resolution and passed in — NOT a
// construction-time option. The site is durable config read at request time
// precisely because a ceiling baked in at construction applies on a cold boot
// and silently does not on a warm one. Nil = no ceiling for this entry. A
// binding with a ttl is honored for min(ttl, localMaxTTL); a binding with no
// ttl (local-name) takes localMaxTTL as its lifetime; `max_ttl: 0` is undeclared
// (parsed to nil by resolverHintMaxTTL), never an instant-expiry ceiling.
type Backend interface {
	Kind() string
	ID() string
	Resolve(hctx *handler.HandlerContext, name string, localMaxTTL *uint64) (types.ResolveResultData, error)
}

// Handler implements the substrate's meta-resolver.
type Handler struct {
	mu       sync.RWMutex
	backends map[string]map[string]Backend // kind → id → backend
	logger   *Logger                       // resolution log writer; nil = disabled

	// §4.3 / §690 load-side surfacing: a stored resolver-config that violates
	// §4.1 step 2 (an out-of-band seed, or a kind that BECAME transmitting
	// after a vocabulary upgrade) MUST be surfaced as a diagnostic at load —
	// never refused, never normalized, or the operator MAY is deleted. Deduped
	// by content hash so a per-resolve reload does not spam. cfgDiagSink
	// defaults to stderr; SetConfigDiagnosticSink overrides it (tests).
	cfgDiagSink func(string)
	cfgDiagLast string
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

// SetConfigDiagnosticSink overrides the §4.3 load-side diagnostic sink (default
// stderr). Used by tests to observe the surfacing without touching stderr.
func (h *Handler) SetConfigDiagnosticSink(sink func(string)) {
	h.mu.Lock()
	h.cfgDiagSink = sink
	h.mu.Unlock()
}

// surfaceConfigDiagnostic emits the §4.3 / §690 load-side diagnostic for a
// violating stored config, once per distinct config content hash. Never
// refuses, never normalizes — surfacing is the whole obligation at load.
func (h *Handler) surfaceConfigDiagnostic(cfgHashHex string, violations []string) {
	h.mu.Lock()
	if h.cfgDiagLast == cfgHashHex {
		h.mu.Unlock()
		return
	}
	h.cfgDiagLast = cfgHashHex
	sink := h.cfgDiagSink
	h.mu.Unlock()
	msg := "registry: stored resolver-config discloses unscoped names to a " +
		"name-transmitting backend (§4.1 step 2) — honored as written per the " +
		"operator's config, surfaced not refused (§4.3): " + strings.Join(violations, "; ")
	if sink != nil {
		sink(msg)
		return
	}
	fmt.Fprintln(os.Stderr, msg)
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
			OpSetResolverConfig: {
				InputType:  types.TypeRegistrySetResolverConfigRequest,
				OutputType: types.TypeRegistryResolverConfig,
			},
			OpGetResolverConfig: {
				OutputType: types.TypeRegistryResolverConfig,
			},
		},
		InternalScope: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
				Resources:  types.CapabilityScope{Include: []string{HandlerPattern + "/*"}},
				Operations: types.CapabilityScope{Include: []string{OpResolve, OpInvalidateCache, OpSetResolverConfig, OpGetResolverConfig}},
			},
		},
	}
}

// ManageResolverConfigSeedGrants returns the grant carried by a seed-policy
// entry that authorizes the §4.3 [v1.18] resolver-config operations
// (set-resolver-config / get-resolver-config), gated by
// system/capability/registry-configure. Mirrors peerissued's
// ManageIssuerPolicySeedGrants — deliberately its OWN grant, so editing the
// resolver-config is not bundled with :resolve. Not needed for the local
// owner (whose §6.9a self-owner grant already covers `*` on the local
// namespace); this is for deploying the capability to a distinct operator.
func ManageResolverConfigSeedGrants() []types.GrantEntry {
	return []types.GrantEntry{
		{
			Handlers:   types.CapabilityScope{Include: []string{HandlerPattern}},
			Resources:  types.CapabilityScope{Include: []string{HandlerPattern + "/*"}},
			Operations: types.CapabilityScope{Include: []string{OpSetResolverConfig, OpGetResolverConfig}},
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
	case OpSetResolverConfig:
		return h.handleSetResolverConfig(ctx, req)
	case OpGetResolverConfig:
		return h.handleGetResolverConfig(ctx, req)
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

// handleSetResolverConfig implements §4.3 [v1.18]. It validates the WHOLE
// config against §4.1 step 2's name-disclosure MUST before storing (not the
// delta), refuses a violating config 403 policy_rejected with the FULL
// violation list unless the operator's acknowledge_name_disclosure act is
// present, and on refusal writes nothing so a follow-up get returns the prior
// bytes unchanged. The config round-trips byte-exact because the submitted
// entity is stored verbatim. The acknowledgement is a parameter of THIS
// operation, never a field of the config entity — a stored byte cannot be
// bound to an identified capability-gated caller, which is the whole reason
// load-time enforcement could never honor the operator MAY.
func (h *Handler) handleSetResolverConfig(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			OpSetResolverConfig+" requires a store-backed handler context")
	}
	if req.Params.Type != types.TypeRegistrySetResolverConfigRequest {
		return handler.NewErrorResponse(400, "invalid_params",
			fmt.Sprintf("%s expects a %s entity, got %q",
				OpSetResolverConfig, types.TypeRegistrySetResolverConfigRequest, req.Params.Type))
	}
	body, err := types.SetResolverConfigRequestDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"decode set-resolver-config request: "+err.Error())
	}
	cfgEnt := body.Config
	if cfgEnt.Type != types.TypeRegistryResolverConfig {
		return handler.NewErrorResponse(400, "invalid_params",
			fmt.Sprintf("config MUST be a %s entity, got %q",
				types.TypeRegistryResolverConfig, cfgEnt.Type))
	}
	cfg, err := types.ResolverConfigDataFromEntity(cfgEnt)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"decode resolver-config: "+err.Error())
	}

	// §4.1 step 2 write-time MUST [v1.17], gated by the operator MAY [v1.18].
	// The full list, not the first — an operator repairing a chain wants all.
	if violations := disclosureViolations(cfg); len(violations) > 0 && !body.AcknowledgeNameDisclosure {
		return handler.NewErrorResponse(403, types.RegistryErrPolicyRejected,
			"resolver-config would make a name-transmitting backend eligible for an "+
				"unscoped name (§4.1 step 2) — set acknowledge_name_disclosure to store it "+
				"deliberately. Violations: "+strings.Join(violations, "; "))
	}

	// No partial application: store the submitted config entity verbatim
	// (byte-exact round-trip), or — on the acknowledged path — the same. On
	// any refusal above nothing reached here, so the prior bytes stand.
	if _, err := hctx.Store.Put(cfgEnt); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"store resolver-config: "+err.Error())
	}
	if err := hctx.LocationIndex.Set(types.ResolverConfigStoragePath, cfgEnt.ContentHash); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"bind resolver-config: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: cfgEnt}, nil
}

// handleGetResolverConfig returns the stored resolver-config as written, or
// 404 not_found when unset (§4.3; §3.2 empty-params input). It MUST NOT
// synthesize a default — an unset config is not an empty config.
func (h *Handler) handleGetResolverConfig(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error",
			OpGetResolverConfig+" requires a store-backed handler context")
	}
	cfgHash, ok := hctx.LocationIndex.Get(types.ResolverConfigStoragePath)
	if !ok {
		return handler.NewErrorResponse(404, types.RegistryErrNotFound,
			"no resolver-config is stored (§4.3)")
	}
	ent, ok := hctx.Store.Get(cfgHash)
	if !ok {
		return handler.NewErrorResponse(404, types.RegistryErrNotFound,
			"resolver-config pointer resolves to no entity")
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// disclosureViolations reports every way a resolver-config makes a
// name-transmitting backend eligible for an UNSCOPED name — §4.1 step 2's
// [MUST, v1.14], stated at the width of the invariant. It has TWO doors:
//
//  1. any name_format_dispatch rule whose pattern matches unscoped names
//     names a transmitting kind — the catch-all `*` is the usual one, and an
//     unscoped name is the path every bare name takes; and
//  2. an ABSENT/EMPTY name_format_dispatch (the filter is disabled → every
//     kind eligible, no catch-all row to inspect) while a transmitting kind
//     sits in the resolver_chain.
//
// The check is KIND-SCOPED [v1.18, Q1]: door 1 is a property of the rules
// alone, independent of what resolver_chain currently holds — a broad rule
// naming did-web violates even with no did-web chain entry, because a shipped
// artifact's safety must survive a downstream operator later adding that
// backend, an extension the distribution cannot re-review. Returns one
// human-readable string per violation (the operator wants the whole list).
func disclosureViolations(cfg types.ResolverConfigData) []string {
	var out []string
	if len(cfg.NameFormatDispatch) == 0 {
		// Door 2 — filter disabled, every kind eligible for every name.
		for _, e := range cfg.ResolverChain {
			if types.IsNameTransmittingKind(e.BackendKind) {
				out = append(out, fmt.Sprintf(
					"no name_format_dispatch, so the filter is disabled and %q in the "+
						"resolver_chain is eligible for every unscoped name", e.BackendKind))
			}
		}
		return out
	}
	// Door 1 — a broad (unscoped-matching) rule names a transmitting kind.
	for _, rule := range cfg.NameFormatDispatch {
		if !patternMatchesUnscopedName(rule.Pattern) {
			continue
		}
		for _, k := range rule.BackendKinds {
			if types.IsNameTransmittingKind(k) {
				out = append(out, fmt.Sprintf(
					"dispatch pattern %q matches unscoped names and names transmitting "+
						"backend kind %q", rule.Pattern, k))
			}
		}
	}
	return out
}

// patternMatchesUnscopedName reports whether a dispatch pattern can match a
// bare, unscoped name — one a user types with no explicit authority scope
// (contrast the scoped form alice@example.org, §4.1 / §616). Such a pattern,
// if it names a name-transmitting kind, leaks bare handles and typos to a
// third party (§4.1 step 2). It is CONSERVATIVE in the safe direction: a
// pattern that is not confidently a scoped shape is treated as broad
// (browser-rust's is_broad — "calling a broad pattern narrow is what leaks").
//
// A pattern is SCOPED (narrow) iff it requires one of the scope shapes §4.1a
// ships as its non-catch-all rows — the user having stated the authority:
//   - an '@'-authority anywhere      (*@*, *@*.*)     — rows 4,5
//   - a scheme prefix, i.e. a ':'    (did:web:*, did:key:*) — rows 1,2
//   - a dotted literal suffix `*.x`  (*.eth)          — row 3, scheme-typed by suffix
//
// Everything else — the catch-all `*`, a bare-prefix `a*`, a literal name,
// `*.*` — is broad. This classifies §4.1a rows 1–5 narrow and its catch-all
// row 6 broad, which is exactly what keeps the recommended default list
// conformant with the step-2 MUST that lives inside it. The classification is
// a pure function of the pattern text (no resolver_chain input): kind-scoped.
func patternMatchesUnscopedName(pattern string) bool {
	// '@' anywhere → the user names an authority.
	if strings.Contains(pattern, "@") {
		return false
	}
	// ':' anywhere → a scheme-typed prefix (did:web:, did:key:).
	if strings.Contains(pattern, ":") {
		return false
	}
	// `*.<literal>` — a single leading star, then a dotted literal suffix with
	// no further star (e.g. *.eth). `*.*` does NOT qualify (its suffix is a
	// star, not a literal) and stays broad.
	if strings.HasPrefix(pattern, "*.") {
		rest := pattern[len("*."):]
		if rest != "" && !strings.Contains(rest, "*") {
			return false
		}
	}
	return true
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

	// (2) name_format_dispatch filter — §4.1 step 2, eligibility is a pure
	// function of the name [REGISTRY 1.14].
	//
	// eligible_kinds := UNION of backend_kinds over every rule whose pattern
	// matches the name; a chain entry is consulted IFF its backend_kind is in
	// that set. A kind reaches eligibility ONLY by being named — there is no
	// per-backend default and no "match all" for a kind named nowhere (the
	// union is order-free, which is why this list carries no precedence and
	// resolver_chain[].priority carries all of it). Grammar: MatchName (§4.1a,
	// '*'-only; NOT path.Match).
	//
	// An absent/empty dispatch list disables the filter (all kinds eligible)
	// — the ONLY place "no filtering" is correct. Otherwise the chain narrows
	// to the eligible set, and if NOTHING matched that set is EMPTY, so the
	// chain narrows to empty → chain_exhausted (§4.1 step 4, fail-closed).
	// This is NOT "no filtering": letting an unmatched name fall through the
	// whole chain would consult every name-transmitting backend in it — a
	// strictly larger disclosure, arriving by fallthrough. (The old `any`
	// guard implemented the withdrawn per-backend "default to match all"
	// sentence, a category error — rules name backend_kinds, not backends;
	// deleted at 1.14.)
	if hasCfg && len(cfg.NameFormatDispatch) > 0 {
		eligible := make(map[string]bool)
		for _, d := range cfg.NameFormatDispatch {
			if !MatchName(d.Pattern, name) {
				continue
			}
			for _, k := range d.BackendKinds {
				eligible[k] = true
			}
		}
		narrowed := chain[:0:0]
		for _, e := range chain {
			if eligible[e.BackendKind] {
				narrowed = append(narrowed, e)
			}
		}
		chain = narrowed
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
		// Resolver-side TTL ceiling — read the durable per-entry hint FRESH
		// from the resolver-config just loaded (line ~176), never from a
		// construction-time option. This is what makes the ceiling apply on a
		// warm boot as on a cold one (REGISTRY [v1.16], §3 of ROUTING-2026-08-19-d).
		localMax := resolverHintMaxTTL(entry)
		r, err := backend.Resolve(hctx, name, localMax)
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

// resolverHintMaxTTL reads the resolver-side TTL ceiling for one chain entry
// from `resolver_chain[].hints.max_ttl` (ms), the site ruled at REGISTRY
// [v1.16]. `hints` is §4's declared backend-scoped slot (it already carries
// `neg_ttl`), so the key rides there with no change to resolver-config's type
// hash. Returns nil when the hint is absent, undecodable, or ZERO — `max_ttl: 0`
// is UNDECLARED (ruling #2), never an instant-expiry ceiling, since honoring a
// literal 0 would expire every binding on the spot, indistinguishable from a
// bad signature.
func resolverHintMaxTTL(e types.ResolverChainEntry) *uint64 {
	raw, ok := e.Hints["max_ttl"]
	if !ok {
		return nil
	}
	var ms uint64
	if err := ecf.Decode(raw, &ms); err != nil || ms == 0 {
		return nil
	}
	return &ms
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
	// §4.3 / §690: surface (never refuse, never normalize) a stored config that
	// discloses unscoped names — the out-of-band-seed path carries no
	// acknowledgement, and a kind may have become transmitting since write.
	if v := disclosureViolations(cfg); len(v) > 0 {
		h.surfaceConfigDiagnostic(cfgEnt.ContentHash.String(), v)
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

// MatchName is THE registry name matcher — the single grammar every field in
// EXTENSION-REGISTRY that globs a user-facing name uses [REGISTRY 1.15]:
// `name_format_dispatch[].pattern` (§4, closed at 1.13) AND the issuer policy's
// `name_constraints` (§6a.9.1, converged onto it at 1.15). There is ONE matcher
// per registry — both fields glob the same flat name string in the same
// handler, so two matchers over that one domain would diverge silently (they
// sit two subsections apart and each carries a grammar-identical example,
// `*.eth` / `*.lab`, that discriminates nothing). Do NOT add a second.
//
//   - '*' is the ONLY metacharacter. It matches any run of characters,
//     INCLUDING NONE, and it crosses every byte — '/' is not a separator,
//     a name is a flat string with no segment structure.
//   - Every other byte is a literal that matches only itself: '?', '[', ']',
//     '\\', '.', ':', '@', '/' all match themselves. This is the difference
//     from path.Match / filepath.Match / fnmatch, which grant '?' and '[…]'
//     meaning and stop '*' at '/'.
//   - Any number of '*' is permitted ('*@*.*' is three).
//   - The match is anchored at both ends — there is no substring form.
//   - No pattern is invalid: every string is well-formed because every
//     non-'*' byte is a literal, so this never errors and never rejects.
//     (That is the real divergence from EXTENSION-REVISION's four forms,
//     which CAN be violated and need a 400 at write time; this grammar
//     cannot — so neither name_format_dispatch nor name_constraints has any
//     write-time rejection, and name_constraints has no unreachable 5xx arm.)
//
// This is a registry-local matcher — NOT ENTITY-CORE-PROTOCOL §5.4
// (capability.MatchesPattern) and NOT EXTENSION-REVISION's globMatch.
// Conformance: REG-DISPATCH-GRAMMAR-1 (§4), REG-NAME-CONSTRAINTS-GRAMMAR-1 (§6a.9.1).
func MatchName(pattern, name string) bool {
	// Split on '*'; each piece is a literal segment that must appear in
	// order, the first anchored at the start and the last at the end.
	// Standard '*'-only wildcard match: leftmost-greedy needs no backtrack.
	segs := strings.Split(pattern, "*")
	if len(segs) == 1 {
		return pattern == name // no '*' → exact literal match, anchored both ends
	}
	// First segment anchored at the start.
	if !strings.HasPrefix(name, segs[0]) {
		return false
	}
	name = name[len(segs[0]):]
	// Last segment anchored at the end; reserve it so a middle segment
	// cannot consume the bytes the suffix needs.
	last := segs[len(segs)-1]
	if !strings.HasSuffix(name, last) {
		return false
	}
	name = name[:len(name)-len(last)]
	// Middle segments matched in order (empty piece = consecutive '*').
	for _, m := range segs[1 : len(segs)-1] {
		if m == "" {
			continue
		}
		i := strings.Index(name, m)
		if i < 0 {
			return false
		}
		name = name[i+len(m):]
	}
	return true
}

// init guards against accidentally importing the package as a side-effect.
var _ = fmt.Errorf
