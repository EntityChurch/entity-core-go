package query

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// queryConstraints holds the resolved constraints for a query request.
type queryConstraints struct {
	Scope      string                 // "tree" (default) or "content_store"
	MaxResults int                    // 0 = use default
	TypeScope  *types.CapabilityScope // nil = no type restriction (tree scope only)
}

const handlerPattern = "system/query"

// Default limits per EXTENSION-QUERY §8.
const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 10000
	MaxFieldFilters   = 16
	MaxInValues       = 100
)

// Handler implements the system/query handler per EXTENSION-QUERY.md v1.0.
type Handler struct {
	typeIdx    store.TypeIndex
	reverseIdx store.ReverseHashIndex
	pathIdx    store.PathLinkIndex
	cs         store.ContentStore
}

// NewHandler creates a query handler backed by the given indexes.
func NewHandler(typeIdx store.TypeIndex, reverseIdx store.ReverseHashIndex, pathIdx store.PathLinkIndex, cs store.ContentStore) *Handler {
	return &Handler{
		typeIdx:    typeIdx,
		reverseIdx: reverseIdx,
		pathIdx:    pathIdx,
		cs:         cs,
	}
}

func (h *Handler) Name() string { return "query" }

// Manifest returns the handler's self-description.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "query",
		Operations: map[string]types.HandlerOperationSpec{
			"find":  {InputType: types.TypeQueryExpression, OutputType: types.TypeQueryResult},
			"count": {InputType: types.TypeQueryExpression, OutputType: "primitive/uint"},
		},
	}
}

// RegisterTypes is a no-op — query types are registered in RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "find":
		return h.handleFind(ctx, req)
	case "count":
		return h.handleCount(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"query handler does not support operation: "+req.Operation)
	}
}

// resolveConstraints decodes query constraints and allowances from the matching
// grant entry. Constraints narrow (max_results, type_scope). Allowances expand
// (scope). Returns safe defaults if fields are absent.
func resolveConstraints(req *handler.Request) queryConstraints {
	hctx := req.Context
	if hctx == nil || hctx.MatchingGrant == nil {
		return queryConstraints{Scope: "tree"}
	}

	c := queryConstraints{Scope: "tree"}

	// Read constraints (narrowing fields).
	if len(hctx.MatchingGrant.Constraints) > 0 {
		var qc types.QueryConstraintsData
		if err := ecf.Decode(hctx.MatchingGrant.Constraints, &qc); err == nil {
			if qc.MaxResults != nil {
				c.MaxResults = int(*qc.MaxResults)
			}
			if qc.TypeScope != nil {
				c.TypeScope = qc.TypeScope
			}
		}
	}

	// Read allowances (expanding fields).
	if len(hctx.MatchingGrant.Allowances) > 0 {
		var qa types.QueryAllowancesData
		if err := ecf.Decode(hctx.MatchingGrant.Allowances, &qa); err == nil {
			if qa.Scope == "content_store" {
				c.Scope = "content_store"
			}
		}
	}

	return c
}

func (h *Handler) handleFind(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	expr, err := h.parseExpression(req)
	if err != nil {
		return err.(*errorResp).response()
	}

	constraints := resolveConstraints(req)

	// Content store scope requires type_scope (QUERY §5.2 step 2).
	if constraints.Scope == "content_store" && constraints.TypeScope == nil {
		return handler.NewErrorResponse(403, "content_store_requires_type_scope",
			"content_store scope requires type_scope on grant constraints")
	}

	// Validate type_filter against type_scope (QUERY §5.2 step 3).
	if constraints.TypeScope != nil && expr.TypeFilter != "" {
		if !matchesScope(expr.TypeFilter, *constraints.TypeScope) {
			return handler.NewErrorResponse(403, "type_not_authorized",
				"type_filter does not match type_scope on grant constraints")
		}
	}

	candidates := h.executeIndexLookups(expr, req.Context.LocalPeerID)
	filtered := h.filterByConstraints(candidates, req, constraints)

	// Sort.
	sortMatches(filtered, expr.OrderBy, expr.Descending != nil && *expr.Descending)

	// Effective limit — grant constraint caps the query limit.
	limit := DefaultQueryLimit
	if expr.Limit != nil && *expr.Limit > 0 {
		limit = int(*expr.Limit)
	}
	if constraints.MaxResults > 0 && constraints.MaxResults < limit {
		limit = constraints.MaxResults
	}
	if limit > MaxQueryLimit {
		limit = MaxQueryLimit
	}

	// Pagination.
	total := uint64(len(filtered))
	start := 0
	if expr.Cursor != "" {
		start, err = decodeCursor(expr.Cursor)
		if err != nil {
			return handler.NewErrorResponse(400, "invalid_cursor", "invalid or expired cursor")
		}
		if start > len(filtered) {
			start = len(filtered)
		}
	}

	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[start:end]
	hasMore := end < len(filtered)

	// Build result.
	result := types.QueryResultData{
		Matches: make([]types.QueryMatchData, len(page)),
		Total:   total,
		HasMore: hasMore,
	}
	for i, m := range page {
		result.Matches[i] = m
	}
	if hasMore {
		result.Cursor = encodeCursor(end)
	}

	resultEntity, respErr := result.ToEntity()
	if respErr != nil {
		return nil, respErr
	}

	// Collect domain entities if requested.
	var included map[hash.Hash]entity.Entity
	if expr.IncludeEntities != nil && *expr.IncludeEntities {
		included = make(map[hash.Hash]entity.Entity)
		for _, m := range page {
			if ent, ok := h.cs.Get(m.Hash); ok {
				included[m.Hash] = ent
			}
		}
	}

	// Wrap in system/envelope: domain entities in inner envelope, protocol envelope stays clean.
	env := entity.Envelope{Root: resultEntity, Included: included}
	envEntity, err := env.ToEntity()
	if err != nil {
		return nil, err
	}
	return &handler.Response{Status: 200, Result: envEntity}, nil
}

func (h *Handler) handleCount(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	expr, err := h.parseExpression(req)
	if err != nil {
		return err.(*errorResp).response()
	}

	constraints := resolveConstraints(req)

	if constraints.Scope == "content_store" && constraints.TypeScope == nil {
		return handler.NewErrorResponse(403, "content_store_requires_type_scope",
			"content_store scope requires type_scope on grant constraints")
	}

	if constraints.TypeScope != nil && expr.TypeFilter != "" {
		if !matchesScope(expr.TypeFilter, *constraints.TypeScope) {
			return handler.NewErrorResponse(403, "type_not_authorized",
				"type_filter does not match type_scope on grant constraints")
		}
	}

	candidates := h.executeIndexLookups(expr, req.Context.LocalPeerID)
	filtered := h.filterByConstraints(candidates, req, constraints)

	count := uint64(len(filtered))
	raw, encErr := ecf.Encode(count)
	if encErr != nil {
		return nil, encErr
	}
	ent, entErr := entity.NewEntity("primitive/uint", cbor.RawMessage(raw))
	if entErr != nil {
		return nil, entErr
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// parseExpression decodes and validates the query expression from request params.
func (h *Handler) parseExpression(req *handler.Request) (*types.QueryExpressionData, error) {
	if len(req.Params.Data) == 0 {
		return nil, &errorResp{400, "empty_query", "no query expression provided"}
	}

	var expr types.QueryExpressionData
	if err := ecf.Decode(req.Params.Data, &expr); err != nil {
		return nil, &errorResp{400, "invalid_params", "could not decode query expression"}
	}

	// Validate: at least one filter must be present.
	if expr.TypeFilter == "" && expr.RefFilter == nil && expr.PathFilter == "" && expr.PathPrefix == "" {
		if len(expr.FieldFilters) == 0 {
			return nil, &errorResp{400, "empty_query", "at least one filter must be specified"}
		}
	}

	// Validate: field_filters requires type_filter.
	if len(expr.FieldFilters) > 0 && expr.TypeFilter == "" {
		return nil, &errorResp{400, "type_filter_required",
			"type_filter is required when field_filters is present"}
	}

	// Validate: field_filters count.
	if len(expr.FieldFilters) > MaxFieldFilters {
		return nil, &errorResp{400, "invalid_params",
			fmt.Sprintf("too many field_filters: %d (max %d)", len(expr.FieldFilters), MaxFieldFilters)}
	}

	return &expr, nil
}

// executeIndexLookups resolves the query against indexes, returning candidate matches.
func (h *Handler) executeIndexLookups(expr *types.QueryExpressionData, localPeerID crypto.PeerID) []types.QueryMatchData {
	var candidates []types.QueryMatchData

	// Strategy: start with the most selective index, then filter.
	switch {
	case expr.RefFilter != nil:
		// Reverse hash index is typically most selective.
		entries := h.reverseIdx.Lookup(*expr.RefFilter)
		for _, e := range entries {
			// Resolve the source entity's hash from the location index.
			// The reverse index stores source_path — we need to find its hash.
			candidates = append(candidates, types.QueryMatchData{
				Path: e.SourcePath,
				Type: e.SourceType,
			})
		}
		// Fill in hashes — we need them for results.
		candidates = h.resolveHashes(candidates, expr)

	case expr.PathFilter != "":
		// Path link index.
		entries := h.pathIdx.Lookup(expr.PathFilter)
		for _, e := range entries {
			candidates = append(candidates, types.QueryMatchData{
				Path: e.SourcePath,
				Type: e.SourceType,
			})
		}
		candidates = h.resolveHashes(candidates, expr)

	case expr.TypeFilter != "":
		// Type index.
		var entries []store.TypeIndexEntry
		if strings.Contains(expr.TypeFilter, "*") {
			entries = h.typeIdx.LookupGlob(expr.TypeFilter)
		} else {
			entries = h.typeIdx.Lookup(expr.TypeFilter)
		}
		for _, e := range entries {
			ent, ok := h.cs.Get(e.Hash)
			if !ok {
				continue
			}
			candidates = append(candidates, types.QueryMatchData{
				Path: e.Path,
				Hash: e.Hash,
				Type: ent.Type,
			})
		}

	case expr.PathPrefix != "":
		// No specific index filter — use type index with glob to get everything,
		// then filter by prefix. This is O(all entities) but the path prefix
		// will narrow results quickly.
		qualifiedPrefix := store.QualifyPath(string(localPeerID), expr.PathPrefix)
		allEntries := h.typeIdx.LookupGlob("*")
		for _, e := range allEntries {
			if strings.HasPrefix(e.Path, qualifiedPrefix) {
				ent, ok := h.cs.Get(e.Hash)
				if !ok {
					continue
				}
				candidates = append(candidates, types.QueryMatchData{
					Path: e.Path,
					Hash: e.Hash,
					Type: ent.Type,
				})
			}
		}
	}

	return candidates
}

// resolveHashes fills in missing Hash fields by looking up paths in the location
// index from the handler context. For candidates from reverse/path-link indexes,
// we have the path but not necessarily the hash.
func (h *Handler) resolveHashes(candidates []types.QueryMatchData, expr *types.QueryExpressionData) []types.QueryMatchData {
	// We can resolve hashes from the type index by looking up matching entries.
	// Since we have the path, find the type index entry for that path.
	resolved := candidates[:0]
	for _, c := range candidates {
		if !c.Hash.IsZero() {
			resolved = append(resolved, c)
			continue
		}
		// Look through the type index entries to find this path.
		// This is an O(n) scan — acceptable for the size of result sets.
		found := false
		if c.Type != "" {
			for _, e := range h.typeIdx.Lookup(c.Type) {
				if e.Path == c.Path {
					c.Hash = e.Hash
					resolved = append(resolved, c)
					found = true
					break
				}
			}
		}
		if !found {
			// Try all types.
			for _, typeName := range h.typeIdx.Types() {
				for _, e := range h.typeIdx.Lookup(typeName) {
					if e.Path == c.Path {
						c.Hash = e.Hash
						c.Type = typeName
						resolved = append(resolved, c)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
	}
	return resolved
}

// filterByConstraints applies remaining filters (type, prefix, field predicates)
// and capability-based filtering per the resolved constraints.
func (h *Handler) filterByConstraints(candidates []types.QueryMatchData, req *handler.Request, constraints queryConstraints) []types.QueryMatchData {
	hctx := req.Context
	expr, _ := h.parseExpression(req)

	var filtered []types.QueryMatchData
	seen := make(map[string]bool) // deduplicate by path

	for _, c := range candidates {
		if c.Path != "" && seen[c.Path] {
			continue
		}

		// Type filter (from expression).
		if expr.TypeFilter != "" && !matchesTypeFilter(c.Type, expr.TypeFilter) {
			continue
		}

		// Path prefix filter (from expression).
		// Qualify the user's bare prefix to match against the qualified paths in the index.
		if expr.PathPrefix != "" {
			qualifiedPrefix := store.QualifyPath(string(hctx.LocalPeerID), expr.PathPrefix)
			if !strings.HasPrefix(c.Path, qualifiedPrefix) {
				continue
			}
		}

		// Field predicates (Level 2 — basic eq/not_eq/in/exists support).
		if len(expr.FieldFilters) > 0 {
			if !h.matchesFieldFilters(c, expr.FieldFilters) {
				continue
			}
		}

		// --- Capability filtering per QUERY §5.2 steps 6a/6b ---

		// 6a: Type scope check (when type_scope is set on constraints).
		if constraints.TypeScope != nil {
			if !matchesScope(c.Type, *constraints.TypeScope) {
				continue // type not authorized — skip silently
			}
		}

		// 6b: Path check — depends on scope.
		if constraints.Scope == "tree" {
			// Tree scope: every result MUST have a path and pass path check.
			if c.Path == "" {
				continue
			}
			if hctx != nil && !hctx.CallerCapability.ContentHash.IsZero() {
				if !checkQueryPathPermission(c.Path, hctx) {
					continue
				}
			}
		} else {
			// Content store scope: path check for entities that HAVE paths,
			// pathless entities authorized by type_scope (checked in 6a).
			if c.Path != "" && hctx != nil && !hctx.CallerCapability.ContentHash.IsZero() {
				if !checkQueryPathPermission(c.Path, hctx) {
					continue
				}
			}
		}

		if c.Path != "" {
			seen[c.Path] = true
		}
		filtered = append(filtered, c)
	}
	return filtered
}

// matchesScope checks if a type name is authorized by a capability scope
// (include/exclude with glob matching). Uses the same pattern matching as
// the core protocol's matches_scope (QUERY §5.2 step 3, 6a).
func matchesScope(typeName string, scope types.CapabilityScope) bool {
	included := false
	for _, pattern := range scope.Include {
		if capability.MatchesPattern(typeName, pattern) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, pattern := range scope.Exclude {
		if capability.MatchesPattern(typeName, pattern) {
			return false
		}
	}
	return true
}

// matchesTypeFilter checks if a type matches a type filter (exact or glob).
func matchesTypeFilter(typeName, filter string) bool {
	if filter == "*" {
		return true
	}
	if strings.HasSuffix(filter, "/*") {
		prefix := filter[:len(filter)-1]
		return strings.HasPrefix(typeName, prefix)
	}
	return typeName == filter
}

// matchesFieldFilters checks if an entity's data satisfies all field predicates.
func (h *Handler) matchesFieldFilters(m types.QueryMatchData, predicates []types.QueryFieldPredicateData) bool {
	ent, ok := h.cs.Get(m.Hash)
	if !ok {
		return false
	}

	// Decode entity data as map.
	var fields map[string]cbor.RawMessage
	if err := cbor.Unmarshal(ent.Data, &fields); err != nil {
		return false
	}

	for _, pred := range predicates {
		raw, exists := fields[pred.Field]
		switch pred.Operator {
		case "exists":
			if !exists {
				return false
			}
		case "eq":
			if !exists || !cborEqual(raw, pred.Value) {
				return false
			}
		case "not_eq":
			if exists && cborEqual(raw, pred.Value) {
				return false
			}
		case "in":
			if !exists || !cborIn(raw, pred.Value) {
				return false
			}
		default:
			// Unknown operator — skip (forward compatibility per §5.2).
		}
	}
	return true
}

// cborEqual checks if two CBOR-encoded values are equal.
func cborEqual(a, b cbor.RawMessage) bool {
	// Decode both to interface{} and compare.
	var va, vb interface{}
	if err := cbor.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := cbor.Unmarshal(b, &vb); err != nil {
		return false
	}
	return fmt.Sprintf("%v", va) == fmt.Sprintf("%v", vb)
}

// cborIn checks if a value is in an array of values.
func cborIn(value, arrayValue cbor.RawMessage) bool {
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(arrayValue, &arr); err != nil {
		return false
	}
	for _, elem := range arr {
		if cborEqual(value, elem) {
			return true
		}
	}
	return false
}

// checkQueryPathPermission does a basic path authorization check.
// Path is qualified ({peerID}/bare). Resource targets are bare.
// Qualify targets before comparing.
func checkQueryPathPermission(path string, hctx *handler.HandlerContext) bool {
	if hctx.Resource != nil {
		for _, target := range hctx.Resource.Targets {
			if target == "*" {
				return true
			}
			qualifiedTarget := store.QualifyPath(string(hctx.LocalPeerID), target)
			if strings.HasPrefix(path, qualifiedTarget) {
				return true
			}
		}
		return false
	}
	// No resource restriction — allow.
	return true
}

// sortMatches sorts matches by path (default) or by order_by field.
func sortMatches(matches []types.QueryMatchData, orderBy string, descending bool) {
	if orderBy == "" || orderBy == "path" {
		sort.Slice(matches, func(i, j int) bool {
			if descending {
				return matches[i].Path > matches[j].Path
			}
			return matches[i].Path < matches[j].Path
		})
		return
	}
	// Custom order_by — would require field decoding. For Level 1, fall back to path.
	sort.Slice(matches, func(i, j int) bool {
		if descending {
			return matches[i].Path > matches[j].Path
		}
		return matches[i].Path < matches[j].Path
	})
}

// Cursor encoding: simple offset-based, base64-encoded.
func encodeCursor(offset int) string {
	return base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodeCursor(cursor string) (int, error) {
	data, err := base64.StdEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(data))
}

// errorResp is used for error flow control in parse/validate.
type errorResp struct {
	status  uint
	code    string
	message string
}

func (e *errorResp) Error() string { return e.message }

func (e *errorResp) response() (*handler.Response, error) {
	return handler.NewErrorResponse(e.status, e.code, e.message)
}
