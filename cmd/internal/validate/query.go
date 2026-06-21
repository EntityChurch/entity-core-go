package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catQuery = "query"

// runQuery validates the query extension against a remote peer.
// This is more involved than most categories because we need to seed test data
// first, then query against it.
func runQuery(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catQuery)

	// --- Declare all checks ---

	// Step 1: Handler manifest.
	r.Declare("handler_manifest_present", "QUERY §5.1")
	r.Declare("handler_manifest_decode", "QUERY §5.1")
	r.Declare("handler_op_find", "QUERY §5.1")
	r.Declare("handler_op_count", "QUERY §5.1")

	// Step 2: Type registration.
	r.Declare("type_expression", "QUERY §4")
	r.Declare("type_field_predicate", "QUERY §4")
	r.Declare("type_result", "QUERY §4")
	r.Declare("type_match", "QUERY §4")
	r.Declare("type_constraints", "QUERY §4")

	// Step 3: Seed test data.
	r.Declare("seed_test_data", "QUERY §5")

	// Step 4: Find by type (exact).
	r.Declare("find_by_type_total", "QUERY §5.2")
	r.Declare("find_by_type_matches", "QUERY §5.2")
	r.Declare("find_by_type_correct", "QUERY §5.2")
	r.Declare("find_by_type_hashes", "QUERY §5.2")
	r.Declare("find_paths_qualified", "QUERY §5.2 / P2")
	r.Declare("find_path_roundtrip", "QUERY §5.2")

	// Step 5: Find by type (glob).
	r.Declare("find_by_type_glob_total", "QUERY §4.1")

	// Step 6: Find by ref_filter.
	r.Declare("find_by_ref_total", "QUERY §2.2")
	r.Declare("find_by_ref_type", "QUERY §2.2")

	// Step 7: Find with path_prefix.
	r.Declare("find_path_prefix_total", "QUERY §4.1")
	r.Declare("find_path_prefix_filter", "QUERY §4.1")

	// Step 8: Count operation.
	r.Declare("count_correct", "QUERY §5.3")

	// Step 9: Pagination.
	r.Declare("pagination_total", "QUERY §4.3")
	r.Declare("pagination_page_size", "QUERY §4.3")
	r.Declare("pagination_has_more", "QUERY §4.3")
	r.Declare("pagination_cursor", "QUERY §4.3")
	r.Declare("pagination_page2_size", "QUERY §4.3")
	r.Declare("pagination_page2_has_more", "QUERY §4.3")

	// Step 10: Include entities.
	r.Declare("include_entities_present", "QUERY §4.3")
	r.Declare("include_entities_hash_match", "QUERY §4.3")

	// Step 11: Error conditions.
	r.Declare("error_empty_query", "QUERY §5.4")
	r.Declare("error_type_filter_required", "QUERY §5.4")

	// Step 12: Invalid operation.
	r.Declare("invalid_op_rejected", "QUERY §5.1")

	// Step 13: Grant constraint inspection + enforcement.
	r.Declare("grant_query_entry", "QUERY §5.5")
	r.Declare("grant_constraints_inspection", "QUERY §5.5")
	r.Declare("grant_allowances_inspection", "QUERY §5.5")
	r.Declare("constraint_system_type_query", "QUERY §5.5")
	r.Declare("constraint_test_type_query", "QUERY §5.5")

	// Step 14: Delegation security.
	r.Declare("deleg_setup", "V7 §5.6")
	r.Declare("deleg_drop_constraint_key", "V7 §5.6")
	r.Declare("deleg_add_allowance_key", "V7 §5.6")
	r.Declare("deleg_change_constraint_value", "V7 §5.6")
	r.Declare("deleg_narrowed_ops_find", "V7 §5.4")
	r.Declare("deleg_narrowed_ops_count", "V7 §5.4")
	r.Declare("deleg_remove_allowance", "V7 §5.6")
	r.Declare("deleg_add_constraint_key", "V7 §5.6")
	r.Declare("deleg_max_results_enforced", "QUERY §5.5")

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/query")
		if err != nil {
			return FailCheck("failed to fetch query handler manifest: " + err.Error())
		}
		r.Store("manifest_entity", ent)
		return PassCheck(fmt.Sprintf("query handler manifest present (type: %s)", ent.Type))
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		handlerData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode handler manifest: " + err.Error())
		}
		r.Store("handler_data", handlerData)

		// Also verify operation types inline.
		if findOp, ok := handlerData.Operations["find"]; ok {
			if findOp.InputType != types.TypeQueryExpression {
				return WarnCheck(fmt.Sprintf("find input type is %q (expected %q)", findOp.InputType, types.TypeQueryExpression))
			}
			if findOp.OutputType != types.TypeQueryResult {
				return WarnCheck(fmt.Sprintf("find output type is %q (expected %q)", findOp.OutputType, types.TypeQueryResult))
			}
		}

		return PassCheck("handler manifest decoded")
	})

	for _, op := range []string{"find", "count"} {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("query handler missing operation: " + op)
			}
			return PassCheck("query handler has operation: " + op)
		})
	}

	// --- Step 2: Type registration ---

	typeChecks := []struct{ name, typPath string }{
		{"expression", "system/type/system/query/expression"},
		{"field_predicate", "system/type/system/query/field-predicate"},
		{"result", "system/type/system/query/result"},
		{"match", "system/type/system/query/match"},
		{"constraints", "system/type/system/query/constraints"},
	}
	for _, tc := range typeChecks {
		tc := tc
		r.Run("type_"+tc.name, func() CheckOutcome {
			_, _, err := client.TreeGet(ctx, tc.typPath)
			if err != nil {
				return FailCheck("query type not registered: " + tc.typPath)
			}
			return PassCheck("query type registered: " + tc.typPath)
		})
	}

	// --- Step 3: Seed test data ---

	r.Run("seed_test_data", func() CheckOutcome {
		seedResult := seedQueryTestData(ctx, client)
		if seedResult.err != nil {
			return FailCheck("failed to seed test data: " + seedResult.err.Error())
		}
		r.Store("seed_result", seedResult)
		return PassCheck(fmt.Sprintf("seeded %d test entities", seedResult.count))
	})

	// --- Step 4: Find by type (exact) ---

	r.Run("find_by_type_total", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		result, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
		})
		if err != nil {
			return FailCheck("find by type failed: " + err.Error())
		}
		r.Store("find_by_type_result", result)
		if result.Total == 3 {
			return PassCheck("find by type 'test/user' returned total=3")
		}
		return FailCheck(fmt.Sprintf("find by type 'test/user' returned total=%d (expected 3)", result.Total))
	})

	r.Run("find_by_type_matches", func() CheckOutcome {
		if out, ok := r.Require("find_by_type_total"); !ok {
			return out
		}
		result := r.Load("find_by_type_result").(types.QueryResultData)
		if uint64(len(result.Matches)) == result.Total {
			return PassCheck("matches count equals total")
		}
		return FailCheck(fmt.Sprintf("matches count %d != total %d", len(result.Matches), result.Total))
	})

	r.Run("find_by_type_correct", func() CheckOutcome {
		if out, ok := r.Require("find_by_type_total"); !ok {
			return out
		}
		result := r.Load("find_by_type_result").(types.QueryResultData)
		if len(result.Matches) == 0 {
			return FailCheck("no matches returned")
		}
		for _, m := range result.Matches {
			if m.Type != "test/user" {
				return FailCheck("some matches have incorrect type")
			}
		}
		return PassCheck("all matches have type 'test/user'")
	})

	r.Run("find_by_type_hashes", func() CheckOutcome {
		if out, ok := r.Require("find_by_type_total"); !ok {
			return out
		}
		result := r.Load("find_by_type_result").(types.QueryResultData)
		if len(result.Matches) == 0 {
			return FailCheck("no matches to check hashes")
		}
		for _, m := range result.Matches {
			if m.Hash.IsZero() {
				return WarnCheck("some matches have zero hashes")
			}
		}
		return PassCheck("all matches have non-zero hashes")
	})

	r.Run("find_paths_qualified", func() CheckOutcome {
		if out, ok := r.Require("find_by_type_total"); !ok {
			return out
		}
		result := r.Load("find_by_type_result").(types.QueryResultData)
		if len(result.Matches) == 0 {
			return FailCheck("no matches to check path qualification")
		}
		for _, m := range result.Matches {
			if m.Path != "" && !store.IsAbsolute(m.Path) && !strings.HasPrefix(m.Path, "entity://") {
				return WarnCheck(fmt.Sprintf("match paths are bare (not qualified) — first: %q", m.Path))
			}
		}
		return PassCheck("all match paths are qualified ({peerID}/path)")
	})

	r.Run("find_path_roundtrip", func() CheckOutcome {
		if out, ok := r.Require("find_by_type_total"); !ok {
			return out
		}
		result := r.Load("find_by_type_result").(types.QueryResultData)
		if len(result.Matches) == 0 {
			return FailCheck("no matches to roundtrip")
		}
		m := result.Matches[0]
		ent, _, err := client.TreeGet(ctx, m.Path)
		if err != nil {
			return FailCheck(fmt.Sprintf("TreeGet with query result path %q failed: %v", m.Path, err))
		}
		if ent.ContentHash != m.Hash {
			return FailCheck(fmt.Sprintf("TreeGet hash mismatch: query returned %x, TreeGet returned %x",
				m.Hash.Digest[:4], ent.ContentHash.Digest[:4]))
		}
		return PassCheck(fmt.Sprintf("TreeGet with query result path %q returns matching entity", m.Path))
	})

	// --- Step 5: Find by type glob ---

	r.Run("find_by_type_glob_total", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		result, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/*",
		})
		if err != nil {
			return FailCheck("find by type glob failed: " + err.Error())
		}
		// We seeded 3 users + 2 orders + 1 doc = 6 test/* entities.
		if result.Total >= 6 {
			return PassCheck(fmt.Sprintf("find by type 'test/*' returned total=%d (>=6 expected)", result.Total))
		}
		return FailCheck(fmt.Sprintf("find by type 'test/*' returned total=%d (expected >=6)", result.Total))
	})

	// --- Step 6: Find by ref_filter ---

	r.Run("find_by_ref_total", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		seed := r.Load("seed_result").(queryTestData)
		result, err := queryFind(ctx, client, types.QueryExpressionData{
			RefFilter: &seed.refHash,
		})
		if err != nil {
			return FailCheck("find by ref_filter failed: " + err.Error())
		}
		r.Store("find_by_ref_result", result)
		if result.Total >= 1 {
			return PassCheck(fmt.Sprintf("find by ref_filter returned total=%d (>=1 expected)", result.Total))
		}
		return FailCheck(fmt.Sprintf("find by ref_filter returned total=%d (expected >=1)", result.Total))
	})

	r.Run("find_by_ref_type", func() CheckOutcome {
		if out, ok := r.Require("find_by_ref_total"); !ok {
			return out
		}
		result := r.Load("find_by_ref_result").(types.QueryResultData)
		if len(result.Matches) == 0 {
			return FailCheck("no matches to verify ref type")
		}
		for _, m := range result.Matches {
			if m.Type == "test/doc" {
				return PassCheck("ref_filter match includes test/doc entity")
			}
		}
		return WarnCheck("ref_filter matches don't include test/doc entity")
	})

	// --- Step 7: Find with path_prefix ---

	r.Run("find_path_prefix_total", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		result, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
			PathPrefix: "system/validate/query/users/",
		})
		if err != nil {
			return FailCheck("find with path_prefix failed: " + err.Error())
		}
		if result.Total == 3 {
			return PassCheck("find with path_prefix 'system/validate/query/users/' returned total=3")
		}
		return FailCheck(fmt.Sprintf("find with path_prefix returned total=%d (expected 3)", result.Total))
	})

	r.Run("find_path_prefix_filter", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		result2, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/*",
			PathPrefix: "system/validate/query/orders/",
		})
		if err != nil {
			return FailCheck("find with path_prefix for orders failed: " + err.Error())
		}
		if result2.Total == 2 {
			return PassCheck("path_prefix correctly narrows to orders (total=2)")
		}
		return FailCheck(fmt.Sprintf("path_prefix for orders returned total=%d (expected 2)", result2.Total))
	})

	// --- Step 8: Count ---

	r.Run("count_correct", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		count, err := queryCount(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
		})
		if err != nil {
			return FailCheck("count failed: " + err.Error())
		}
		if count == 3 {
			return PassCheck("count for 'test/user' returned 3")
		}
		return FailCheck(fmt.Sprintf("count for 'test/user' returned %d (expected 3)", count))
	})

	// --- Step 9: Pagination ---

	r.Run("pagination_total", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		limit := uint64(2)
		result, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
			Limit:      &limit,
		})
		if err != nil {
			return FailCheck("pagination page 1 failed: " + err.Error())
		}
		r.Store("pagination_result", result)
		if result.Total == 3 {
			return PassCheck("pagination total=3 (full result set, not just page)")
		}
		return FailCheck(fmt.Sprintf("pagination total=%d (expected 3)", result.Total))
	})

	r.Run("pagination_page_size", func() CheckOutcome {
		if out, ok := r.Require("pagination_total"); !ok {
			return out
		}
		result := r.Load("pagination_result").(types.QueryResultData)
		if len(result.Matches) == 2 {
			return PassCheck("page 1 has 2 matches (limit=2)")
		}
		return FailCheck(fmt.Sprintf("page 1 has %d matches (expected 2)", len(result.Matches)))
	})

	r.Run("pagination_has_more", func() CheckOutcome {
		if out, ok := r.Require("pagination_total"); !ok {
			return out
		}
		result := r.Load("pagination_result").(types.QueryResultData)
		if result.HasMore {
			return PassCheck("has_more=true on page 1")
		}
		return FailCheck("has_more=false on page 1 (expected true)")
	})

	r.Run("pagination_cursor", func() CheckOutcome {
		if out, ok := r.Require("pagination_total"); !ok {
			return out
		}
		result := r.Load("pagination_result").(types.QueryResultData)
		if result.Cursor == "" {
			return FailCheck("no cursor returned for page 1")
		}
		r.Store("pagination_cursor_value", result.Cursor)
		return PassCheck("cursor returned for page 1")
	})

	r.Run("pagination_page2_size", func() CheckOutcome {
		if out, ok := r.Require("pagination_cursor"); !ok {
			return out
		}
		limit := uint64(2)
		cursor := r.Load("pagination_cursor_value").(string)
		result2, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
			Limit:      &limit,
			Cursor:     cursor,
		})
		if err != nil {
			return FailCheck("pagination page 2 failed: " + err.Error())
		}
		r.Store("pagination_result2", result2)
		if len(result2.Matches) == 1 {
			return PassCheck("page 2 has 1 match (remaining)")
		}
		return FailCheck(fmt.Sprintf("page 2 has %d matches (expected 1)", len(result2.Matches)))
	})

	r.Run("pagination_page2_has_more", func() CheckOutcome {
		if out, ok := r.Require("pagination_page2_size"); !ok {
			return out
		}
		result2 := r.Load("pagination_result2").(types.QueryResultData)
		if !result2.HasMore {
			return PassCheck("has_more=false on last page")
		}
		return FailCheck("has_more=true on last page (expected false)")
	})

	// --- Step 10: Include entities ---

	r.Run("include_entities_present", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		includeEntities := true
		limit := uint64(1)
		result, included, err := queryFindWithIncluded(ctx, client, types.QueryExpressionData{
			TypeFilter:      "test/user",
			Limit:           &limit,
			IncludeEntities: &includeEntities,
		})
		if err != nil {
			return FailCheck("find with include_entities failed: " + err.Error())
		}
		r.Store("include_result", result)
		r.Store("include_included", included)
		if len(result.Matches) > 0 && len(included) > 0 {
			return PassCheck(fmt.Sprintf("included %d entities in response envelope", len(included)))
		}
		if len(result.Matches) > 0 {
			return WarnCheck("no entities included in response (Level 1 may silently ignore include_entities)")
		}
		return FailCheck("no matches returned for include_entities test")
	})

	r.Run("include_entities_hash_match", func() CheckOutcome {
		if out, ok := r.Require("include_entities_present"); !ok {
			return out
		}
		result := r.Load("include_result").(types.QueryResultData)
		included := r.Load("include_included").(map[hash.Hash]entity.Entity)
		if len(result.Matches) == 0 || len(included) == 0 {
			return SkipCheck("no matches or included entities to verify")
		}
		matchHash := result.Matches[0].Hash
		if _, ok := included[matchHash]; ok {
			return PassCheck("included entity hash matches query match")
		}
		return FailCheck("included entity hash does not match query match")
	})

	// --- Step 11: Error conditions ---

	r.Run("error_empty_query", func() CheckOutcome {
		resp, err := queryExecuteRaw(ctx, client, "find", types.QueryExpressionData{})
		if err != nil {
			return PassCheck("empty query caused error (acceptable)")
		}
		if resp.Status == 400 {
			return PassCheck("empty query returned 400")
		}
		return FailCheck(fmt.Sprintf("empty query returned status %d (expected 400)", resp.Status))
	})

	r.Run("error_type_filter_required", func() CheckOutcome {
		valueRaw, _ := ecf.Encode("test")
		resp2, err := queryExecuteRaw(ctx, client, "find", types.QueryExpressionData{
			FieldFilters: []types.QueryFieldPredicateData{
				{Field: "name", Operator: "eq", Value: cbor.RawMessage(valueRaw)},
			},
		})
		if err != nil {
			return PassCheck("field_filters without type_filter caused error (acceptable)")
		}
		if resp2.Status == 400 {
			return PassCheck("field_filters without type_filter returned 400")
		}
		return FailCheck(fmt.Sprintf("field_filters without type_filter returned status %d (expected 400)", resp2.Status))
	})

	// --- Step 12: Invalid operation ---

	r.Run("invalid_op_rejected", func() CheckOutcome {
		resp, err := queryExecuteRaw(ctx, client, "nonexistent_op", types.QueryExpressionData{
			TypeFilter: "test/user",
		})
		if err != nil {
			return PassCheck("invalid operation caused error (acceptable)")
		}
		if resp.Status >= 400 {
			return PassCheck(fmt.Sprintf("invalid operation rejected with status %d", resp.Status))
		}
		return FailCheck(fmt.Sprintf("invalid operation returned status %d (expected >=400)", resp.Status))
	})

	// --- Step 13: Grant constraint inspection + enforcement ---

	r.Run("grant_query_entry", func() CheckOutcome {
		grants := client.Grants()
		queryGrant, hasQueryGrant := findQueryGrant(grants)
		if !hasQueryGrant {
			return FailCheck("no query-specific grant entry — v7.14 requires constraints/allowances on query grants")
		}
		r.Store("query_grant", queryGrant)
		return PassCheck("query-specific grant entry found")
	})

	r.Run("grant_constraints_inspection", func() CheckOutcome {
		if out, ok := r.Require("grant_query_entry"); !ok {
			return out
		}
		queryGrant := r.Load("query_grant").(types.GrantEntry)
		if len(queryGrant.Constraints) == 0 {
			return WarnCheck("query grant has no constraints field — constraint pathway not fully exercised")
		}
		var qc types.QueryConstraintsData
		if err := ecf.Decode(queryGrant.Constraints, &qc); err != nil {
			return WarnCheck("query grant has constraints but could not decode: " + err.Error())
		}
		hasTypeScope := qc.TypeScope != nil
		if hasTypeScope {
			patterns := qc.TypeScope.Include
			return PassCheck(fmt.Sprintf("query grant has constraints: type_scope include patterns: %v", patterns))
		}
		return PassCheck(fmt.Sprintf("query grant has constraints: type_scope=%v", hasTypeScope))
	})

	r.Run("grant_allowances_inspection", func() CheckOutcome {
		if out, ok := r.Require("grant_query_entry"); !ok {
			return out
		}
		queryGrant := r.Load("query_grant").(types.GrantEntry)
		scope := "tree"
		if len(queryGrant.Allowances) > 0 {
			var qa types.QueryAllowancesData
			if err := ecf.Decode(queryGrant.Allowances, &qa); err == nil && qa.Scope != "" {
				scope = qa.Scope
			}
			return PassCheck(fmt.Sprintf("query grant has allowances: scope=%s", scope))
		}
		return PassCheck("no allowances — tree scope (safe default, no content_store expansion)")
	})

	r.Run("constraint_system_type_query", func() CheckOutcome {
		// EXTENSION-QUERY §349, §594: type_filter is exact-match by default
		// (no trailing /* glob, no bare * match-all). Entities of type
		// EXACTLY "system/handler" are bound at top-level handler patterns
		// (e.g. system/tree, system/role) — NOT under system/handler/...
		// (those are system/handler/manifest entities). Prior path_prefix
		// "system/handler/" combined with exact-match type filter excluded
		// every matching entity. Per PROPOSAL-ROLE-V2.0 Amendment 2 PR-9.2.
		sysResult, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "system/handler",
		})
		if err != nil {
			return WarnCheck("could not query system types: " + err.Error())
		}
		if sysResult.Total > 0 {
			return PassCheck(fmt.Sprintf("system type query works through constraint pathway (found %d handlers, exact-match)", sysResult.Total))
		}
		return WarnCheck("system type query returned 0 results (may need path authorization)")
	})

	r.Run("constraint_test_type_query", func() CheckOutcome {
		if out, ok := r.Require("seed_test_data"); !ok {
			return out
		}
		testResult, err := queryFind(ctx, client, types.QueryExpressionData{
			TypeFilter: "test/user",
		})
		if err != nil {
			return FailCheck("test type query failed through constraint pathway: " + err.Error())
		}
		if testResult.Total == 3 {
			return PassCheck("test type query returns correct count through constraint pathway")
		}
		return FailCheck(fmt.Sprintf("test type query returned %d (expected 3) through constraint pathway", testResult.Total))
	})

	// --- Step 14: Delegation security ---

	r.Run("deleg_setup", func() CheckOutcome {
		// Build the parent's constraint/allowance bytes for reuse.
		// These must be byte-identical to what OpenAccessGrants produces.
		parentConstraintRaw, err := ecf.Encode(types.QueryConstraintsData{
			TypeScope: &types.CapabilityScope{Include: []string{"*"}},
		})
		if err != nil {
			return FailCheck("encode parent constraints: " + err.Error())
		}
		parentAllowanceRaw, err := ecf.Encode(types.QueryAllowancesData{
			Scope: "content_store",
		})
		if err != nil {
			return FailCheck("encode parent allowances: " + err.Error())
		}
		r.Store("parent_constraint_raw", parentConstraintRaw)
		r.Store("parent_allowance_raw", parentAllowanceRaw)
		return PassCheck("delegation test parameters encoded")
	})

	// A: Drop constraint key (type_scope) → 403.
	r.Run("deleg_drop_constraint_key", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		return sendDelegatedQueryExpectOutcome(ctx, client,
			types.GrantEntry{
				Handlers:   types.CapabilityScope{Include: []string{"system/query"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"find", "count"}},
				Allowances: cbor.RawMessage(parentAllowanceRaw),
				// NO Constraints — type_scope dropped
			},
			"find", types.QueryExpressionData{TypeFilter: "test/user"},
			403,
			"correctly rejected — constraint key (type_scope) dropped",
			"constraint key drop not caught",
		)
	})

	// B: Add allowance key on tree grant → 403.
	r.Run("deleg_add_allowance_key", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		return sendDelegatedTreeExpect403Outcome(ctx, client,
			types.GrantEntry{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
				Allowances: cbor.RawMessage(parentAllowanceRaw), // NOT in parent's tree grant
			},
			"correctly rejected — allowance key added to tree grant",
			"allowance key addition not caught",
		)
	})

	// C: Change constraint value → 403.
	r.Run("deleg_change_constraint_value", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		narrowedConstraintRaw, _ := ecf.Encode(types.QueryConstraintsData{
			TypeScope: &types.CapabilityScope{Include: []string{"test/user"}},
		})
		return sendDelegatedQueryExpectOutcome(ctx, client,
			types.GrantEntry{
				Handlers:    types.CapabilityScope{Include: []string{"system/query"}},
				Resources:   types.CapabilityScope{Include: []string{"*"}},
				Operations:  types.CapabilityScope{Include: []string{"find", "count"}},
				Constraints: cbor.RawMessage(narrowedConstraintRaw), // different bytes
				Allowances:  cbor.RawMessage(parentAllowanceRaw),
			},
			"find", types.QueryExpressionData{TypeFilter: "test/user"},
			403,
			"correctly rejected — constraint value changed (byte equality)",
			"constraint value change not caught",
		)
	})

	// D: Narrowed operations (find only) → find 200, count 403.
	r.Run("deleg_narrowed_ops_find", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentConstraintRaw := r.Load("parent_constraint_raw").([]byte)
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		// §PR-8: resource patterns canonicalize against the cap granter's
		// peer_id. The child cap is signed by the validator, so bare "*"
		// would canonicalize to /{validator}/* — disjoint from the server's
		// namespace. Use the explicit server-namespace form so the
		// delegated child stays within the connection cap's authority.
		findOnlyGrant := types.GrantEntry{
			Handlers:    types.CapabilityScope{Include: []string{"system/query"}},
			Resources:   types.CapabilityScope{Include: []string{"/" + string(client.RemotePeerID()) + "/*"}},
			Operations:  types.CapabilityScope{Include: []string{"find"}}, // no "count"
			Constraints: cbor.RawMessage(parentConstraintRaw),
			Allowances:  cbor.RawMessage(parentAllowanceRaw),
		}
		return sendDelegatedQueryExpectOutcome(ctx, client,
			findOnlyGrant,
			"find", types.QueryExpressionData{TypeFilter: "test/user"},
			200,
			"find succeeds with narrowed operations grant",
			"find should succeed with find-only grant",
		)
	})

	r.Run("deleg_narrowed_ops_count", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentConstraintRaw := r.Load("parent_constraint_raw").([]byte)
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		findOnlyGrant := types.GrantEntry{
			Handlers:    types.CapabilityScope{Include: []string{"system/query"}},
			Resources:   types.CapabilityScope{Include: []string{"*"}},
			Operations:  types.CapabilityScope{Include: []string{"find"}}, // no "count"
			Constraints: cbor.RawMessage(parentConstraintRaw),
			Allowances:  cbor.RawMessage(parentAllowanceRaw),
		}
		return sendDelegatedQueryExpectOutcome(ctx, client,
			findOnlyGrant,
			"count", types.QueryExpressionData{TypeFilter: "test/user"},
			403,
			"count correctly rejected — operation not in delegated scope",
			"count should be rejected with find-only grant",
		)
	})

	// E: Remove allowance key → valid narrowing, scope becomes tree.
	r.Run("deleg_remove_allowance", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentConstraintRaw := r.Load("parent_constraint_raw").([]byte)
		return sendDelegatedQueryExpectOutcome(ctx, client,
			types.GrantEntry{
				Handlers:    types.CapabilityScope{Include: []string{"system/query"}},
				Resources:   types.CapabilityScope{Include: []string{"*"}},
				Operations:  types.CapabilityScope{Include: []string{"find", "count"}},
				Constraints: cbor.RawMessage(parentConstraintRaw),
				// NO Allowances — removed content_store scope (safe narrowing)
			},
			"find", types.QueryExpressionData{TypeFilter: "test/user"},
			200,
			"query succeeds after removing allowance key (tree scope)",
			"valid delegation (remove allowance) should succeed",
		)
	})

	// F: Add constraint key (max_results) → valid narrowing, results capped.
	r.Run("deleg_add_constraint_key", func() CheckOutcome {
		if out, ok := r.Require("deleg_setup"); !ok {
			return out
		}
		parentAllowanceRaw := r.Load("parent_allowance_raw").([]byte)
		maxResults := uint64(2)
		cappedConstraintRaw, _ := ecf.Encode(types.QueryConstraintsData{
			TypeScope:  &types.CapabilityScope{Include: []string{"*"}},
			MaxResults: &maxResults,
		})
		cappedGrant := types.GrantEntry{
			Handlers: types.CapabilityScope{Include: []string{"system/query"}},
			// §PR-8: child cap granter = validator; explicit server-namespace
			// form keeps the delegated child within the connection cap's
			// authority (bare "*" would canonicalize to /{validator}/*).
			Resources:   types.CapabilityScope{Include: []string{"/" + string(client.RemotePeerID()) + "/*"}},
			Operations:  types.CapabilityScope{Include: []string{"find", "count"}},
			Constraints: cbor.RawMessage(cappedConstraintRaw),
			Allowances:  cbor.RawMessage(parentAllowanceRaw),
		}
		status, result, err := sendDelegatedQuery(ctx, client, cappedGrant, "find",
			types.QueryExpressionData{TypeFilter: "test/user"})
		if err != nil {
			return FailCheck("delegation with added constraint failed: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("expected 200, got %d — adding constraint key should be valid", status))
		}
		r.Store("deleg_capped_result", result)
		return PassCheck("delegation with added constraint key (max_results) accepted")
	})

	r.Run("deleg_max_results_enforced", func() CheckOutcome {
		if out, ok := r.Require("deleg_add_constraint_key"); !ok {
			return out
		}
		result := r.Load("deleg_capped_result")
		if result == nil {
			return SkipCheck("no result from capped delegation")
		}
		qr := result.(*types.QueryResultData)
		if len(qr.Matches) <= 2 {
			return PassCheck(fmt.Sprintf("max_results=2 enforced: got %d matches (3 users available)", len(qr.Matches)))
		}
		return FailCheck(fmt.Sprintf("max_results=2 not enforced: got %d matches", len(qr.Matches)))
	})

	return r.Results()
}

// --- Seed test data ---

type queryTestData struct {
	count   int
	refHash hash.Hash // hash referenced by one of the entities
	err     error
}

func seedQueryTestData(ctx context.Context, client *PeerClient) queryTestData {
	type userData struct {
		Name string `cbor:"name"`
		City string `cbor:"city"`
	}
	type orderData struct {
		Item   string `cbor:"item"`
		Amount uint   `cbor:"amount"`
	}
	type docData struct {
		Title      string    `cbor:"title"`
		ContentRef hash.Hash `cbor:"content_ref"`
	}

	// Create a hash that will be referenced by a doc entity.
	refHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	refHash.Digest[0] = 0xAA
	refHash.Digest[1] = 0xBB
	refHash.Digest[2] = 0xCC

	entities := []struct {
		path     string
		typeName string
		data     interface{}
	}{
		{"system/validate/query/users/alice", "test/user", userData{Name: "Alice", City: "Seattle"}},
		{"system/validate/query/users/bob", "test/user", userData{Name: "Bob", City: "Portland"}},
		{"system/validate/query/users/charlie", "test/user", userData{Name: "Charlie", City: "Seattle"}},
		{"system/validate/query/orders/1", "test/order", orderData{Item: "Widget", Amount: 10}},
		{"system/validate/query/orders/2", "test/order", orderData{Item: "Gadget", Amount: 25}},
		{"system/validate/query/docs/spec", "test/doc", docData{Title: "Spec", ContentRef: refHash}},
	}

	count := 0
	for _, e := range entities {
		ent := mustCreateEntity(e.typeName, e.data)
		_, err := client.TreePut(ctx, e.path, ent)
		if err != nil {
			return queryTestData{err: fmt.Errorf("put %s: %w", e.path, err)}
		}
		count++
	}

	return queryTestData{count: count, refHash: refHash}
}

// --- Client helpers ---

// queryFind sends a find query and decodes the result.
func queryFind(ctx context.Context, client *PeerClient, expr types.QueryExpressionData) (types.QueryResultData, error) {
	resp, err := queryExecuteRaw(ctx, client, "find", expr)
	if err != nil {
		return types.QueryResultData{}, err
	}
	if resp.Status != 200 {
		return types.QueryResultData{}, fmt.Errorf("find returned status %d", resp.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(resp.Result, &resultEntity); err != nil {
		return types.QueryResultData{}, fmt.Errorf("decode result entity: %w", err)
	}

	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(resultEntity)
	if err != nil {
		return types.QueryResultData{}, err
	}

	var result types.QueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return types.QueryResultData{}, fmt.Errorf("decode result data: %w", err)
	}
	return result, nil
}

// queryFindWithIncluded sends a find query and returns both the result and
// any included entities from the response envelope.
func queryFindWithIncluded(ctx context.Context, client *PeerClient, expr types.QueryExpressionData) (types.QueryResultData, map[hash.Hash]entity.Entity, error) {
	paramsEntity, err := makeQueryParams(expr)
	if err != nil {
		return types.QueryResultData{}, nil, err
	}

	uri := fmt.Sprintf("entity://%s/system/query", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, "find", paramsEntity, nil)
	if err != nil {
		return types.QueryResultData{}, nil, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.QueryResultData{}, nil, fmt.Errorf("decode response: %w", err)
	}
	if respData.Status != 200 {
		return types.QueryResultData{}, nil, fmt.Errorf("find returned status %d", respData.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return types.QueryResultData{}, nil, fmt.Errorf("decode result entity: %w", err)
	}

	// Unwrap system/envelope if present.
	inner, envIncluded, err := unwrapResultEnvelope(resultEntity)
	if err != nil {
		return types.QueryResultData{}, nil, err
	}

	var result types.QueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return types.QueryResultData{}, nil, fmt.Errorf("decode result data: %w", err)
	}

	// Domain entities are in the inner envelope's included map.
	// Fall back to protocol envelope's included for non-wrapped peers.
	included := envIncluded
	if included == nil {
		included = env.Included
	}

	return result, included, nil
}

// queryCount sends a count query and returns the count.
func queryCount(ctx context.Context, client *PeerClient, expr types.QueryExpressionData) (uint64, error) {
	resp, err := queryExecuteRaw(ctx, client, "count", expr)
	if err != nil {
		return 0, err
	}
	if resp.Status != 200 {
		return 0, fmt.Errorf("count returned status %d", resp.Status)
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(resp.Result, &resultEntity); err != nil {
		return 0, fmt.Errorf("decode result entity: %w", err)
	}

	var count uint64
	if err := cbor.Unmarshal(resultEntity.Data, &count); err != nil {
		return 0, fmt.Errorf("decode count: %w", err)
	}
	return count, nil
}

// queryExecuteRaw sends a query EXECUTE and returns the raw response.
func queryExecuteRaw(ctx context.Context, client *PeerClient, operation string, expr types.QueryExpressionData) (types.ExecuteResponseData, error) {
	paramsEntity, err := makeQueryParams(expr)
	if err != nil {
		return types.ExecuteResponseData{}, err
	}

	uri := fmt.Sprintf("entity://%s/system/query", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, operation, paramsEntity, nil)
	if err != nil {
		return types.ExecuteResponseData{}, err
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.ExecuteResponseData{}, fmt.Errorf("decode response: %w", err)
	}

	return respData, nil
}

func makeQueryParams(expr types.QueryExpressionData) (entity.Entity, error) {
	raw, err := ecf.Encode(expr)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("encode expression: %w", err)
	}
	return entity.NewEntity(types.TypeQueryExpression, cbor.RawMessage(raw))
}

// --- Grant helpers ---

// findQueryGrant searches the grant entries for one that specifically covers
// system/query handler (not just a wildcard).
func findQueryGrant(grants []types.GrantEntry) (types.GrantEntry, bool) {
	for _, g := range grants {
		for _, h := range g.Handlers.Include {
			if h == "system/query" {
				return g, true
			}
		}
	}
	return types.GrantEntry{}, false
}

// --- Delegation helpers ---

// sendDelegatedQuery creates a delegated capability with the given grant,
// sends a query EXECUTE, and returns the response status and decoded result.
func sendDelegatedQuery(
	ctx context.Context,
	client *PeerClient,
	grant types.GrantEntry,
	operation string,
	expr types.QueryExpressionData,
) (int, *types.QueryResultData, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	tokenData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}

	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return 0, nil, fmt.Errorf("create child cap: %w", err)
	}

	paramsEntity, err := makeQueryParams(expr)
	if err != nil {
		return 0, nil, fmt.Errorf("make params: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/query", client.RemotePeerID())
	env, err := buildDelegatedExecute(client, childCap, childCapSig, uri, operation, paramsEntity, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build execute: %w", err)
	}

	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return 0, nil, fmt.Errorf("send: %w", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, nil, fmt.Errorf("decode response: %w", err)
	}

	if respData.Status != 200 {
		return int(respData.Status), nil, nil
	}

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return 200, nil, fmt.Errorf("decode result entity: %w", err)
	}

	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(resultEntity)
	if err != nil {
		return 200, nil, err
	}

	var result types.QueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return 200, nil, fmt.Errorf("decode result data: %w", err)
	}
	return 200, &result, nil
}

// sendDelegatedQueryExpectOutcome is a convenience wrapper around sendDelegatedQuery
// that returns a CheckOutcome instead of a CheckResult.
func sendDelegatedQueryExpectOutcome(
	ctx context.Context,
	client *PeerClient,
	grant types.GrantEntry,
	operation string,
	expr types.QueryExpressionData,
	expectStatus int,
	passMsg, failMsg string,
) CheckOutcome {
	status, _, err := sendDelegatedQuery(ctx, client, grant, operation, expr)
	if err != nil {
		return FailCheck("delegation test error: " + err.Error())
	}
	if status == expectStatus {
		return PassCheck(passMsg)
	}
	return FailCheck(fmt.Sprintf("expected status %d, got %d — %s", expectStatus, status, failMsg))
}

// sendDelegatedTreeExpect403Outcome creates a delegated capability targeting system/tree,
// sends a tree get, and expects 403. Returns a CheckOutcome.
func sendDelegatedTreeExpect403Outcome(
	ctx context.Context,
	client *PeerClient,
	grant types.GrantEntry,
	passMsg, failMsg string,
) CheckOutcome {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()

	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	tokenData := types.CapabilityTokenData{
		Grants:    []types.GrantEntry{grant},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}

	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return FailCheck("create child cap: " + err.Error())
	}

	params, resource, err := buildSimpleGetParams()
	if err != nil {
		return FailCheck("setup: " + err.Error())
	}

	uri := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
	env, err := buildDelegatedExecute(client, childCap, childCapSig, uri, "get", params, resource)
	if err != nil {
		return FailCheck("build execute: " + err.Error())
	}

	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return FailCheck("peer crashed: " + err.Error())
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return FailCheck("decode: " + err.Error())
	}
	if respData.Status == 403 {
		return PassCheck(passMsg)
	}
	return FailCheck(fmt.Sprintf("expected 403, got %d — %s", respData.Status, failMsg))
}
