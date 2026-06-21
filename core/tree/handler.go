package tree

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const handlerPattern = "system/tree"

// Handler implements the system/tree handler for get and put operations.
type Handler struct {
	// tracker is an optional incremental trie-root tracker. When set, snapshot
	// operations over a tracked prefix return the tracked root directly
	// instead of rebuilding (EXTENSION-TREE v3.8 §3.4).
	tracker *RootTracker
}

// NewHandler creates a new tree handler.
func NewHandler() *Handler {
	return &Handler{}
}

// SetRootTracker enables the snapshot short-circuit for tracked prefixes.
// Safe to leave unset; the handler falls back to a full rebuild.
func (h *Handler) SetRootTracker(t *RootTracker) {
	h.tracker = t
}

func (h *Handler) Name() string { return "tree" }

// Manifest returns the handler's self-description for the system tree.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "tree",
		Operations: map[string]types.HandlerOperationSpec{
			"get":      {InputType: types.TypeTreeGetRequest},
			"put":      {InputType: types.TypeTreePutRequest},
			"snapshot": {InputType: types.TypeTreeSnapshotRequest, OutputType: types.TypeTreeSnapshot},
			"diff":     {InputType: types.TypeTreeDiffRequest, OutputType: types.TypeTreeDiff},
			"merge":    {InputType: types.TypeTreeMergeRequest, OutputType: types.TypeTreeMergeResult},
			"extract":  {InputType: types.TypeTreeExtractRequest, OutputType: types.TypeEnvelope},
		},
	}
}

// RegisterTypes registers tree-specific types into the registry.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeTreeGetRequest, reflect.TypeOf(types.GetRequestData{}))
	r.ReflectType(types.TypeTreePutRequest, reflect.TypeOf(types.PutRequestData{}))
	r.OverrideField(types.TypeTreePutRequest, "entity",
		types.FieldSpec{TypeRef: types.TypeCoreEntity, Optional: true})
	r.ReflectType(types.TypeTreeListing, reflect.TypeOf(types.ListingData{}))
	r.OverrideField(types.TypeTreeListing, "entries",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/tree/listing-entry"}})
	r.OverrideField(types.TypeTreeListing, "path",
		types.FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(types.TypeTreeListing, "next_page",
		types.FieldSpec{TypeRef: "system/hash", Optional: true})

	// Snapshot types.
	r.ReflectType(types.TypeTreeSnapshot, reflect.TypeOf(types.SnapshotData{}))
	r.OverrideField(types.TypeTreeSnapshot, "prefix",
		types.FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(types.TypeTreeSnapshot, "bindings",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/hash"}})
	r.ReflectType(types.TypeTreeSnapshotRequest, reflect.TypeOf(types.SnapshotRequestData{}))
	r.OverrideField(types.TypeTreeSnapshotRequest, "prefix",
		types.FieldSpec{TypeRef: "system/tree/path", Optional: true})

	// Diff types.
	r.ReflectType(types.TypeTreeDiffChange, reflect.TypeOf(types.DiffChangeData{}))
	r.ReflectType(types.TypeTreeDiff, reflect.TypeOf(types.DiffData{}))
	r.OverrideField(types.TypeTreeDiff, "added",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/hash"}})
	r.OverrideField(types.TypeTreeDiff, "removed",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/hash"}})
	r.OverrideField(types.TypeTreeDiff, "changed",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: types.TypeTreeDiffChange}})
	r.ReflectType(types.TypeTreeDiffRequest, reflect.TypeOf(types.DiffRequestData{}))

	// Merge types.
	r.ReflectType(types.TypeTreeMergeConflict, reflect.TypeOf(types.MergeConflictData{}))
	r.ReflectType(types.TypeTreeMergeResult, reflect.TypeOf(types.MergeResultData{}))
	r.OverrideField(types.TypeTreeMergeResult, "conflicts",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: types.TypeTreeMergeConflict}})
	r.ReflectType(types.TypeTreeMergeRequest, reflect.TypeOf(types.MergeRequestData{}))
	r.OverrideField(types.TypeTreeMergeRequest, "source_prefix",
		types.FieldSpec{TypeRef: "system/tree/path", Optional: true})
	r.OverrideField(types.TypeTreeMergeRequest, "target_prefix",
		types.FieldSpec{TypeRef: "system/tree/path", Optional: true})

	// Extract types.
	r.ReflectType(types.TypeTreeExtractRequest, reflect.TypeOf(types.ExtractRequestData{}))
	r.OverrideField(types.TypeTreeExtractRequest, "prefix",
		types.FieldSpec{TypeRef: "system/tree/path"})
	r.OverrideField(types.TypeTreeExtractRequest, "paths",
		types.FieldSpec{ArrayOf: &types.FieldSpec{TypeRef: "system/tree/path"}, Optional: true})

	// Tracking config (EXTENSION-TREE v3.8 §3.4.1a).
	r.ReflectType(types.TypeTreeTrackingConfig, reflect.TypeOf(types.TrackingConfigData{}))
	r.OverrideField(types.TypeTreeTrackingConfig, "prefix",
		types.FieldSpec{TypeRef: "system/tree/path"})
}

func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "get":
		return h.handleGet(ctx, req)
	case "put":
		return h.handlePut(ctx, req)
	case "snapshot":
		return h.handleSnapshot(ctx, req)
	case "diff":
		return h.handleDiff(ctx, req)
	case "merge":
		return h.handleMerge(ctx, req)
	case "extract":
		return h.handleExtract(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation", "tree handler does not support operation: "+req.Operation)
	}
}

func (h *Handler) handleGet(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Decode params.
	var getReq types.GetRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &getReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode get-request params")
		}
	}

	// Path comes from resource target (v7).
	var path string
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		path = hctx.Resource.Targets[0]
	}

	// Level 2 capability check: path-level permission.
	if !hctx.CallerCapability.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err == nil {
			granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
			if gerr != nil {
				return handler.NewErrorResponse(403, "capability_denied", "granter unresolvable: "+gerr.Error())
			}
			if !capability.CheckPathPermission("get", path, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
				return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for path: "+path)
			}
		}
	}

	// Trailing slash or empty path → listing.
	if path == "" || strings.HasSuffix(path, "/") {
		return h.handleListing(hctx.LocationIndex, path, hctx.LocalPeerID, &getReq)
	}

	// Look up path in location index.
	contentHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return handler.NewErrorResponse(404, "not_found", "path not found: "+path)
	}

	mode := getReq.Mode
	if mode == "" {
		mode = "entity"
	}

	switch mode {
	case "entity":
		ent, ok := hctx.Store.Get(contentHash)
		if !ok {
			return handler.NewErrorResponse(404, "not_found", "entity not found for hash: "+contentHash.String())
		}
		return &handler.Response{Status: 200, Result: ent}, nil

	case "hash":
		// Return the hash as a simple entity.
		hashRaw, err := ecf.Encode(map[string]interface{}{
			"content_hash": contentHash.Bytes(),
		})
		if err != nil {
			return nil, err
		}
		hashEntity, err := entity.NewEntity("system/hash", cbor.RawMessage(hashRaw))
		if err != nil {
			return nil, err
		}
		return &handler.Response{Status: 200, Result: hashEntity}, nil

	default:
		return handler.NewErrorResponse(400, "invalid_mode", "unknown mode: "+mode)
	}
}

func (h *Handler) handleListing(idx store.LocationIndex, prefix string, localPeerID crypto.PeerID, getReq *types.GetRequestData) (*handler.Response, error) {
	entries := idx.List(prefix)

	// Group by immediate child name to produce a single-level listing.
	type childInfo struct {
		hash        *hash.Hash
		hasChildren bool
	}
	children := make(map[string]*childInfo)

	// The trim prefix MUST match the absolute form of the listing prefix
	// (V7 §1.4): a peer-relative prefix like "foo/" canonicalizes to
	// "/{localPeerID}/foo/", but an already-absolute prefix like
	// "/{otherPeerID}/foo/" passes through unchanged. Earlier this
	// unconditionally prepended the local peer-id, producing a literal
	// "/{localPeerID}//{otherPeerID}/foo/" that never matched the
	// store's entry paths — so foreign-namespace listings produced
	// either empty results or an empty-string child name (pre-fix bug
	// surfaced by validate-peer's universal_address_space category).
	var qualifiedPrefix string
	if strings.HasPrefix(prefix, "/") {
		qualifiedPrefix = prefix
	} else {
		qualifiedPrefix = store.QualifyPath(string(localPeerID), prefix)
	}
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Path, qualifiedPrefix)
		if rel == "" {
			continue
		}
		slashIdx := strings.Index(rel, "/")
		if slashIdx < 0 {
			// Direct child.
			info, ok := children[rel]
			if !ok {
				info = &childInfo{}
				children[rel] = info
			}
			eh := e.Hash
			info.hash = &eh
		} else {
			// Nested path → parent directory has children.
			name := rel[:slashIdx]
			info, ok := children[name]
			if !ok {
				info = &childInfo{}
				children[name] = info
			}
			info.hasChildren = true
		}
	}

	// V7 §6.3 + v7.72 §9.5a CORE-TREE-DELETE-1: listing omits paths whose
	// binding is a system/deletion-marker. Filter is O(1) per child via
	// IsDeletionMarker (format-relative hash equality, no store I/O).
	// A direct-child binding that IS a marker AND has no nested children
	// drops entirely from the listing; if it still has children, the
	// binding indicator is removed (the entry shows as directory-only).
	for name, info := range children {
		if info.hash == nil {
			continue
		}
		if types.IsDeletionMarker(*info.hash) {
			info.hash = nil
			if !info.hasChildren {
				delete(children, name)
			}
		}
	}

	// Sort child names for stable output.
	names := make([]string, 0, len(children))
	for name := range children {
		names = append(names, name)
	}
	sort.Strings(names)

	total := uint64(len(names))

	// Apply offset and limit.
	offset := uint64(0)
	if getReq.Offset != nil {
		offset = *getReq.Offset
	}
	if offset > uint64(len(names)) {
		names = nil
	} else {
		names = names[offset:]
	}
	if getReq.Limit != nil && uint64(len(names)) > *getReq.Limit {
		names = names[:*getReq.Limit]
	}

	// Build listing entries map with spec-compliant format.
	entryMap := make(map[string]interface{})
	for _, name := range names {
		info := children[name]
		entry := map[string]interface{}{
			"has_children": info.hasChildren,
		}
		if info.hash != nil {
			entry["hash"] = info.hash.Bytes()
		} else {
			entry["hash"] = nil
		}
		entryMap[name] = entry
	}

	listing := types.ListingData{
		Path:    prefix,
		Entries: entryMap,
		Count:   total,
		Offset:  offset,
	}
	listingEntity, err := listing.ToEntity()
	if err != nil {
		return nil, err
	}

	return &handler.Response{Status: 200, Result: listingEntity}, nil
}

func (h *Handler) handlePut(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	var putReq types.PutRequestData
	if len(req.Params.Data) > 0 {
		if err := ecf.Decode(req.Params.Data, &putReq); err != nil {
			return handler.NewErrorResponse(400, "invalid_params", "could not decode put-request params")
		}
	}

	// Path comes from resource target (v7).
	var path string
	if hctx.Resource != nil && len(hctx.Resource.Targets) > 0 {
		path = hctx.Resource.Targets[0]
	}
	if path == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target path is required")
	}
	// V7 §1.4 + v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject paths with
	// control characters (NUL, C0 range, DEL). Caller paths come in any
	// form — absolute, peer-relative, raw — so we validate the
	// character set up-front before qualification touches the store.
	if err := store.ValidatePathChars(path); err != nil {
		return handler.NewErrorResponse(400, "invalid_path", err.Error())
	}

	// Level 2 capability check.
	if !hctx.CallerCapability.ContentHash.IsZero() {
		capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
		if err == nil {
			granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
			if gerr != nil {
				return handler.NewErrorResponse(403, "capability_denied", "granter unresolvable: "+gerr.Error())
			}
			if !capability.CheckPathPermission("put", path, capData, hctx.HandlerPattern, hctx.LocalPeerID, granterPeerID) {
				return handler.NewErrorResponse(403, "capability_denied", "insufficient capability for path: "+path)
			}
		}
	}

	// CAS check (V7 §3.9, PROPOSAL-INCREMENTAL-TRIE-ROOT-TRACKING R8; v7.50
	// CAS-create variant). Three cases when expected_hash is present:
	//   - zero hash: CAS-create — succeed iff path is unbound.
	//   - non-zero hash: succeed iff current binding equals expected_hash.
	//   - absent (nil): unconditional, no check.
	// Applies to both write and remove operations.
	if putReq.ExpectedHash != nil {
		currentHash, bound := hctx.LocationIndex.Get(path)
		if putReq.ExpectedHash.IsZero() {
			// CAS-create: expected absent.
			if bound {
				return handler.NewErrorResponse(409, "hash_mismatch",
					fmt.Sprintf("expected_hash zero (CAS-create) but path is already bound to %s: %s",
						currentHash.String(), path))
			}
		} else {
			// CAS-replace: expected non-zero match.
			if !bound {
				return handler.NewErrorResponse(409, "hash_mismatch",
					"expected_hash set but no binding exists at path: "+path)
			}
			if currentHash != *putReq.ExpectedHash {
				return handler.NewErrorResponse(409, "hash_mismatch",
					fmt.Sprintf("expected_hash %s does not match current binding %s at path %s",
						putReq.ExpectedHash.String(), currentHash.String(), path))
			}
		}
	}

	if len(putReq.Entity) == 0 {
		// Remove binding.
		removed, ok, cascadeResult := hctx.TreeRemove(path, "delete")
		if !ok {
			return handler.NewErrorResponse(404, "not_found", "path not bound: "+path)
		}
		_ = removed
		resultRaw, _ := ecf.Encode(map[string]interface{}{"removed": true})
		resultEntity, _ := entity.NewEntity("system/tree/put-result", cbor.RawMessage(resultRaw))
		if !cascadeResult.IsComplete() {
			return cascadeToPartialResponse(cascadeResult, resultEntity)
		}
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	// Decode the entity to store.
	var ent entity.Entity
	if err := ecf.Decode(putReq.Entity, &ent); err != nil {
		return handler.NewErrorResponse(400, "invalid_entity", fmt.Sprintf("could not decode entity: %v", err))
	}

	// Validate entity hash.
	if err := ent.Validate(); err != nil {
		return handler.NewErrorResponse(400, "invalid_entity", fmt.Sprintf("entity validation failed: %v", err))
	}

	// Store and bind.
	storedHash, err := hctx.Store.Put(ent)
	if err != nil {
		return nil, fmt.Errorf("%w: store put failed: %v", ecerrors.ErrNotFound, err)
	}
	cascadeResult, err := hctx.TreeSet(path, storedHash, "put")
	if err != nil {
		return nil, fmt.Errorf("tree put: bind %q: %w", path, err)
	}

	resultRaw, _ := ecf.Encode(map[string]interface{}{
		"content_hash": storedHash.Bytes(),
	})
	resultEntity, _ := entity.NewEntity("system/tree/put-result", cbor.RawMessage(resultRaw))
	if !cascadeResult.IsComplete() {
		return cascadeToPartialResponse(cascadeResult, resultEntity)
	}
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// cascadeToPartialResponse builds a 207 Multi-Status response from a cascade
// result. The original handler result entity is included in the response's
// Included map so callers can still access the put-result data.
func cascadeToPartialResponse(cr *store.CascadeResult, originalResult entity.Entity) (*handler.Response, error) {
	partial := types.PartialResultData{
		BindingCommitted:   cr.BindingCommitted,
		ConsumersCompleted: cr.Completed,
		ConsumersSkipped:   cr.Skipped,
		CascadeDepth:       cr.CascadeDepth,
	}
	for _, h := range cr.Halted {
		partial.ConsumersHalted = append(partial.ConsumersHalted, types.PartialResultHaltEntry{
			Name: h.Name,
			Error: types.PartialResultError{
				Code:    h.Error.Code,
				Message: h.Error.Message,
			},
		})
	}
	partialEnt, err := partial.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("encoding partial-result: %w", err)
	}
	included := map[hash.Hash]entity.Entity{}
	if !originalResult.ContentHash.IsZero() {
		included[originalResult.ContentHash] = originalResult
	}
	return &handler.Response{
		Status:   handler.StatusMultiStatus,
		Result:   partialEnt,
		Included: included,
	}, nil
}

// Register registers the tree handler with a handler registry.
func Register(reg *handler.Registry) *Handler {
	h := NewHandler()
	reg.Register(handlerPattern, h)
	return h
}

// CreateGetRequest creates a get request entity and resource target for the given path.
func CreateGetRequest(path, mode string) (entity.Entity, *types.ResourceTarget, error) {
	getReq := types.GetRequestData{
		Mode: mode,
	}
	ent, err := getReq.ToEntity()
	if err != nil {
		return entity.Entity{}, nil, err
	}
	return ent, &types.ResourceTarget{Targets: []string{path}}, nil
}

// CreatePutRequest creates a put request entity and resource target.
func CreatePutRequest(path string, ent *entity.Entity) (entity.Entity, *types.ResourceTarget, error) {
	return CreatePutRequestCAS(path, ent, nil)
}

// CreatePutRequestCAS creates a put request with an optional expected_hash
// for compare-and-swap semantics (V7 §3.9).
func CreatePutRequestCAS(path string, ent *entity.Entity, expectedHash *hash.Hash) (entity.Entity, *types.ResourceTarget, error) {
	putReq := types.PutRequestData{ExpectedHash: expectedHash}
	if ent != nil {
		raw, err := ecf.Encode(*ent)
		if err != nil {
			return entity.Entity{}, nil, err
		}
		putReq.Entity = cbor.RawMessage(raw)
	}
	reqEntity, err := putReq.ToEntity()
	if err != nil {
		return entity.Entity{}, nil, err
	}
	return reqEntity, &types.ResourceTarget{Targets: []string{path}}, nil
}
