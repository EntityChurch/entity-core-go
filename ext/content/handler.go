// Package content implements the system/content handler per
// EXTENSION-CONTENT v3.6.
//
// Owned ops (v3.5 §6):
//   - get    (MAY in §11.3; required when handler installed) — hash-addressed retrieval
//   - ingest (MAY in §11.3; SHOULD when handler installed)   — content-store write
//
// v3.5 normative tightenings vs v3.4:
//
//   - §6.2 / §6.3 — both ops MUST return `path_required` when the EXECUTE
//     carries no `resource` field (path-as-resource per V7 §3.2). The
//     namespace path (e.g. `system/content` for the default namespace, or
//     `system/content/public` for the `public` namespace per §6.4) is the
//     cap-scope resource; the hashes in `params` are operation payload.
//     This reverses the v3.4 posture and lands as a normative tightening,
//     not a deprecation — v3.4 had no shipped impls (§6.3 callout).
//
//   - §4.3 — the 64 KiB inline-include threshold for small content. The
//     handler-mediated access pattern is the load-bearing case (a domain
//     handler returning a content-referencing entity also inlines the
//     chunks when total_size ≤ MIN_CHUNK_SIZE). The system content
//     handler's `get` follows the same convention when it resolves a
//     `system/content/blob` whose total_size is at or below the threshold.
//
//   - §6.6 — blob/chunk persistence by default; no protocol-level delete
//     op for content entities. GC is deferred to EXTENSION-GC.
//
// Descriptors (§2.4 + §5.3) are surfaced as library functions in
// descriptor.go — publication is a tree put at the dual-level invariant
// path, lookup walks the publisher subtree and applies the §5.3 MUST
// integrity check (descriptor.data.content == blob_hash).
package content

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const handlerPattern = "system/content"

// MissResolver is the storage-substitute miss-hook contract per
// STORAGE-SUBSTITUTE-SOURCES §6 (the small CONTENT-side amendment that
// the substitute substrate plugs into). When a hash misses locally,
// handleGet calls MissResolver before declaring the hash missing; a
// Found result is treated as if the entity had been in the local store
// all along.
//
// Per Ruling 4, source_peer_id is NOT a wire field on get-request — the
// resolver pulls it from local context (typically a ctx-key the
// dispatcher sets at request entry). This keeps core CONTENT's wire
// contract untouched (Sketch-B don't-grow-core discipline).
//
// CapDenied propagates the §3-RES.10 / §5.1 "abort the whole get" signal
// to the caller — when a substitute convention handler returns 403, the
// chain does not fall through to "missing"; the get itself returns 403
// so the caller learns they lack authority rather than seeing a spurious
// miss.
type MissResolver interface {
	Resolve(ctx context.Context, hctx *handler.HandlerContext, target hash.Hash) MissResult
}

// MissResult is what MissResolver returns to handleGet's miss branch.
type MissResult struct {
	Found     bool
	Entity    entity.Entity
	CapDenied bool
}

// Option is a functional knob for NewHandler.
type Option func(*Handler)

// WithMissResolver installs a storage-substitute miss-hook. Nil resolver
// preserves the v3.6 behavior exactly — a hash that misses locally goes
// straight to the `missing` array, no chain consultation.
func WithMissResolver(r MissResolver) Option {
	return func(h *Handler) { h.missResolver = r }
}

// Handler implements the system/content handler with get and ingest operations.
type Handler struct {
	missResolver MissResolver
}

// NewHandler creates a new content handler. Without WithMissResolver the
// handler preserves the v3.6 behavior (no substitute chain consultation).
func NewHandler(opts ...Option) *Handler {
	h := &Handler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *Handler) Name() string { return "content" }

// Manifest returns the handler's self-description per §6.1.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "content",
		Operations: map[string]types.HandlerOperationSpec{
			"get":    {InputType: types.TypeContentGetRequest, OutputType: types.TypeContentGetResponse},
			"ingest": {InputType: types.TypeContentIngestRequest, OutputType: types.TypeContentIngestResult},
		},
	}
}

// RegisterTypes registers content-specific request/result types into the
// registry. The §2 entity types (blob, chunk, descriptor) are registered
// by core/types.RegisterCoreTypes — they are always installed (v3.5 §1.1).
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeContentGetRequest, reflect.TypeOf(types.ContentGetRequestData{}))
	r.ReflectType(types.TypeContentIngestRequest, reflect.TypeOf(types.ContentIngestRequestData{}))
	r.ReflectType(types.TypeContentIngestResult, reflect.TypeOf(types.ContentIngestResultData{}))

	// Entity-typed fields (PROPOSAL-ENTITY-FIELD-ANNOTATION §3.4).
	r.OverrideField(types.TypeContentIngestRequest, "entity",
		types.FieldSpec{TypeRef: types.TypeCoreEntity, Optional: true})
}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "get":
		return h.handleGet(ctx, req)
	case "ingest":
		return h.handleIngest(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"content handler does not support operation: "+req.Operation)
	}
}

// requireResource enforces the §6.2/§6.3 path-as-resource MUST: every
// directly-callable content op identifies its namespace resource, even
// when the op's semantic target is hash-shaped. Missing resource returns
// path_required (v3.4 → v3.5 behavior reversal).
func requireResource(hctx *handler.HandlerContext, op string) (*handler.Response, error) {
	if hctx == nil || hctx.Resource == nil || len(hctx.Resource.Targets) == 0 {
		msg := fmt.Sprintf("system/content:%s requires a resource targeting the namespace path (v3.5 §6.2/§6.3)", op)
		return handler.NewErrorResponse(400, "path_required", msg)
	}
	return nil, nil
}

// handleGet retrieves entities from the content store by hash. Per §4.3,
// when a resolved entity is a system/content/blob with total_size at or
// below MIN_CHUNK_SIZE, its chunks are also inline-included in the
// response envelope.
//
// Per CONTENT v3.6 Amendment 1 §6.2 MUST: respects the connection's
// configured frame budget. Entities (and the §4.3 inline-include chunk
// closure that travels atomically with a blob) are added to `included`
// while running ECF size stays within budget; once the next add would
// overflow, that hash and every remaining requested hash move to
// `missing` so the caller can retry. Implementations failing this MUST
// are non-conformant under the `system/content/frame-limit-respected`
// validate-peer behavioral check.
func (h *Handler) handleGet(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store")
	}

	if resp, err := requireResource(hctx, "get"); resp != nil || err != nil {
		return resp, err
	}

	var getReq types.ContentGetRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &getReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode get-request params")
		}
	}

	if len(getReq.Hashes) == 0 {
		return handler.NewErrorResponse(400, "invalid_params", "hashes list is required")
	}

	budget := frameBudget(hctx)

	// Pre-allocate non-nil so CBOR encodes empty arrays rather than null
	// (per V7 §3.3 array-shape contract; receivers expect []hash.Hash).
	found := make([]hash.Hash, 0, len(getReq.Hashes))
	missing := make([]hash.Hash, 0)
	included := make(map[hash.Hash]entity.Entity)

	// Track running ECF size of the included entities. Safety margin
	// reserves space for: response envelope structure + ExecuteResponseData
	// wrapper + ContentGetResponseData found/missing arrays + CBOR
	// framing overhead.
	const safetyMargin uint64 = 64 * 1024
	if budget <= safetyMargin {
		budget = safetyMargin + 1
	}
	limit := budget - safetyMargin
	var running uint64

	for i, hreq := range getReq.Hashes {
		ent, ok := hctx.Store.Get(hreq)
		if !ok && h.missResolver != nil {
			// Storage-substitute miss-hook per STORAGE-SUBSTITUTE-SOURCES §6.
			// Cap-denied propagates out of the get; a successful resolve
			// promotes the hash from missing-bound to found.
			res := h.missResolver.Resolve(ctx, hctx, hreq)
			if res.CapDenied {
				return handler.NewErrorResponse(403, "capability_denied",
					"storage-substitute chain aborted by cap_denied on hash "+hreq.String())
			}
			if res.Found {
				ent = res.Entity
				ok = true
			}
		}
		if !ok {
			missing = append(missing, hreq)
			continue
		}

		// Compute the atomic add-group: the entity plus, for blobs at
		// or below §4.3 inline-include threshold, the chunk closure.
		// §4.3 inline-include is MUST when it fits; either both fit
		// or both go to `missing` so the boundary contract holds.
		group, groupSize, gerr := buildIncludeGroup(hctx, hreq, ent, included)
		if gerr != nil {
			return nil, gerr
		}
		if running+groupSize > limit {
			// Frame budget would overflow — this hash and all
			// remaining go to missing. Per §6.2: "include as many as
			// fit (in request order) and move the remainder to
			// missing."
			missing = append(missing, getReq.Hashes[i:]...)
			break
		}
		for k, v := range group {
			included[k] = v
		}
		running += groupSize
		found = append(found, hreq)
	}

	// Per CONTENT v3.6 §6.2: Found and Missing are spec-literal arrays;
	// fetched entities ride in the outer envelope Included map (3-of-3
	// convergent across Go/Rust/Python post Python's refactor).
	respData := types.ContentGetResponseData{Found: found, Missing: missing}
	resultEntity, err := respData.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: resultEntity, Included: included}, nil
}

// buildIncludeGroup returns the atomic add-group for one resolved hash:
// the entity itself plus, when the entity is a §4.3-qualifying blob,
// every chunk it references. Returns the group as a map and its total
// ECF-encoded size. Excludes entities already in `existing` from the
// size calculation (each chunk is counted once).
func buildIncludeGroup(hctx *handler.HandlerContext, h hash.Hash, ent entity.Entity, existing map[hash.Hash]entity.Entity) (map[hash.Hash]entity.Entity, uint64, error) {
	group := make(map[hash.Hash]entity.Entity)
	var total uint64
	if _, dup := existing[h]; !dup {
		raw, err := ecf.Encode(ent)
		if err != nil {
			return nil, 0, err
		}
		group[h] = ent
		total += uint64(len(raw))
	}
	if ent.Type == types.TypeContentBlob {
		var blob types.ContentBlobData
		if err := ecf.Decode(ent.Data, &blob); err == nil && blob.TotalSize <= types.MinChunkSize {
			for _, ch := range blob.Chunks {
				if _, dup := existing[ch]; dup {
					continue
				}
				if _, dup := group[ch]; dup {
					continue
				}
				chEnt, ok := hctx.Store.Get(ch)
				if !ok {
					continue
				}
				raw, err := ecf.Encode(chEnt)
				if err != nil {
					return nil, 0, err
				}
				group[ch] = chEnt
				total += uint64(len(raw))
			}
		}
	}
	return group, total, nil
}

// frameBudget returns the configured response frame budget for this
// dispatch. Reads ConnectionState.EffectiveFrameBudget when available;
// otherwise falls back to the 16 MiB default per V7 §1.1.4 + Amendment 1
// "consult the connection's configured budget at response-construction
// time, NOT a hardcoded 16 MiB literal."
//
// The structural interface match avoids importing core/protocol from
// the content extension (would create a dependency cycle).
func frameBudget(hctx *handler.HandlerContext) uint64 {
	const defaultBudget uint64 = 16 * 1024 * 1024
	if hctx == nil || hctx.ConnectionState == nil {
		return defaultBudget
	}
	type carrier interface {
		EffectiveFrameBudget() uint64
	}
	if c, ok := hctx.ConnectionState.(carrier); ok {
		return c.EffectiveFrameBudget()
	}
	return defaultBudget
}

// handleIngest stores entities from an envelope or standalone entity into
// the content store. Per §6.3, requires a resource (namespace path) — the
// hashes embedded in params are operation payload, not the cap-scope key.
func (h *Handler) handleIngest(_ context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store")
	}

	if resp, err := requireResource(hctx, "ingest"); resp != nil || err != nil {
		return resp, err
	}

	// Level 2 capability check — ingest requires authorization on the
	// namespace resource. The check uses the resource path the dispatch
	// layer already verified at Level 1.
	if !hctx.CallerCapability.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err == nil {
			granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
			if gerr != nil {
				return handler.NewErrorResponse(403, "capability_denied", "granter unresolvable: "+gerr.Error())
			}
			if !capability.CheckPathPermission("ingest", "", capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
				return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for ingest")
			}
		}
	}

	var ingestReq types.ContentIngestRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &ingestReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode ingest-request params")
		}
	}

	hasEnvelope := ingestReq.Envelope != nil && len(*ingestReq.Envelope) > 0
	hasEntity := ingestReq.Entity != nil && len(*ingestReq.Entity) > 0

	if hasEnvelope && hasEntity {
		return handler.NewErrorResponse(400, "ambiguous_input", "specify envelope or entity, not both")
	}
	if !hasEnvelope && !hasEntity {
		return handler.NewErrorResponse(400, "missing_input", "specify envelope or entity")
	}

	if hasEnvelope {
		return h.ingestEnvelope(hctx, *ingestReq.Envelope)
	}
	return h.ingestEntity(hctx, *ingestReq.Entity)
}

// ingestEnvelope stores all entities from an envelope into the content
// store. Per §6.3, the result includes the original envelope.root inlined
// when present — enables downstream chain steps to navigate the wrapper's
// fields without dereferencing the content store.
func (h *Handler) ingestEnvelope(hctx *handler.HandlerContext, raw cbor.RawMessage) (*handler.Response, error) {
	var env entity.Envelope

	// Try decoding as entity wrapping an envelope first (from continuation chains).
	var ent entity.Entity
	if err := ecf.Decode(raw, &ent); err == nil && ent.Type != "" {
		if err2 := ecf.Decode(ent.Data, &env); err2 != nil {
			return handler.NewErrorResponse(400, "invalid_params",
				fmt.Sprintf("could not decode entity data as envelope: %v", err2))
		}
	} else if err := ecf.Decode(raw, &env); err != nil || env.Root.Type == "" {
		return handler.NewErrorResponse(400, "invalid_params",
			"could not decode envelope")
	}

	namespace := hctx.ExtractResourcePath()
	count := uint64(0)

	var rootHash hash.Hash
	if env.Root.Type != "" {
		h, err := hctx.Store.Put(env.Root)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "failed to store root entity")
		}
		if resp, err := bindHashTreePresence(hctx, namespace, h); resp != nil || err != nil {
			return resp, err
		}
		rootHash = h
		count++
	}

	for _, ent := range env.Included {
		incHash, err := hctx.Store.Put(ent)
		if err != nil {
			return handler.NewErrorResponse(500, "internal_error", "failed to store included entity")
		}
		if resp, err := bindHashTreePresence(hctx, namespace, incHash); resp != nil || err != nil {
			return resp, err
		}
		count++
	}

	// §6.3 root pass-through (also §6.3.1 chain composition).
	result := types.ContentIngestResultData{
		RootHash:      rootHash,
		IngestedCount: count,
	}
	if env.Root.Type != "" {
		rootCopy := env.Root
		result.Root = &rootCopy
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// ingestEntity stores a single entity into the content store.
func (h *Handler) ingestEntity(hctx *handler.HandlerContext, raw cbor.RawMessage) (*handler.Response, error) {
	var ent entity.Entity
	if err := ecf.Decode(raw, &ent); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			fmt.Sprintf("could not decode entity: %v", err))
	}

	storedHash, err := hctx.Store.Put(ent)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "failed to store entity")
	}

	if resp, err := bindHashTreePresence(hctx, hctx.ExtractResourcePath(), storedHash); resp != nil || err != nil {
		return resp, err
	}

	result := types.ContentIngestResultData{
		RootHash:      storedHash,
		IngestedCount: 1,
	}
	resultEntity, err := result.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// bindHashTreePresence wires the CONTENT §6.4.2 Hash Tree Presence
// binding for one stored entity: a tree binding at {namespace}/{hex33(H)}
// → H. This is the existing CONTENT §6.4.1 MUST ("ingest into namespace
// P writes to the content store AND binds at the canonical path in the
// tree") and the predicate that NamespaceScope checks in serving-mode.
//
// **Hex shape**: 66 chars = full content_hash wire form (algorithm byte +
// 32-byte digest) per V7 §3.5 — RULING-SERVING-MODE-CONTENT-BODY-SHAPE
// §5 B. The format-code prefix is the crypto-agility discriminator; the
// earlier 64-hex (digest only) cohort-converged-but-wrong reading drops
// it. Convergent now with the URL/ETag 66-hex on the poll side
// (ext/httplive/poll.go).
//
// namespace is the resource target (e.g. "system/content/public"). A
// caller with no resource target (default namespace) gets a binding
// at "system/content/{hex33(H)}" — the §6.4.2 canonical form for the
// default namespace prefix. An empty namespace short-circuits without
// binding, leaving the legacy single-trust-domain topology (§6.4.1
// opt-in) intact for callers that explicitly want flat-KV semantics.
func bindHashTreePresence(hctx *handler.HandlerContext, namespace string, h hash.Hash) (*handler.Response, error) {
	if namespace == "" || h.IsZero() {
		return nil, nil
	}
	bindingPath := strings.TrimRight(namespace, "/") + "/" + hex.EncodeToString(h.Bytes())
	if _, err := hctx.TreeSet(bindingPath, h, "ingest"); err != nil {
		return handler.NewErrorResponse(500, "internal_error",
			"failed to bind §6.4.2 hash-tree-presence at "+bindingPath+": "+err.Error())
	}
	return nil, nil
}
