package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catHistory = "history"

// runHistory validates the history extension against a remote peer.
func runHistory(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catHistory)

	// --- Declare all checks ---

	// Step 1: Handler manifest.
	r.Declare("handler_manifest_present", "HISTORY §4.1")
	r.Declare("handler_manifest_decode", "HISTORY §4.1")
	r.Declare("handler_op_query", "HISTORY §4.1")
	r.Declare("handler_op_rollback", "HISTORY §4.1")

	// Step 2: Type registration.
	r.Declare("type_transition", "HISTORY §9.2")
	r.Declare("type_config", "HISTORY §9.2")
	r.Declare("type_query_params", "HISTORY §9.2")
	r.Declare("type_query_result", "HISTORY §9.2")
	r.Declare("type_rollback_params", "HISTORY §9.2")
	r.Declare("type_rollback_result", "HISTORY §9.2")

	// Step 3: Put → query → verify transition.
	r.Declare("transition_recorded", "HISTORY §5.1")
	r.Declare("transition_event_created", "HISTORY §2.1")
	r.Declare("transition_hash_matches", "HISTORY §2.1")
	r.Declare("transition_has_timestamp", "HISTORY §9.1")
	r.Declare("first_transition_no_previous", "HISTORY §2.1")
	r.Declare("context_author_present", "HISTORY §2.1")
	r.Declare("context_capability_present", "HISTORY §2.1")
	r.Declare("context_handler_present", "HISTORY §2.1")
	r.Declare("context_operation_present", "HISTORY §2.1")

	// Step 4: Update → verify chain.
	r.Declare("chain_two_transitions", "HISTORY §3.1")
	r.Declare("chain_latest_event_updated", "HISTORY §2.1")
	r.Declare("chain_latest_hash", "HISTORY §2.1")
	r.Declare("chain_previous_hash", "HISTORY §2.1")
	r.Declare("chain_linked", "HISTORY §3.1")
	r.Declare("head_pointer_set", "HISTORY §3.1")

	// Step 5: Query with limit + has_more.
	r.Declare("limit_returns_1", "HISTORY §4.3.1")
	r.Declare("limit_has_more", "HISTORY §4.3.1")

	// Step 6: Query with event filter.
	r.Declare("event_filter_only_created", "HISTORY §4.3.1")

	// Step 7: Rollback.
	r.Declare("rollback_restored_hash", "HISTORY §4.3.2")
	r.Declare("rollback_verify_binding", "HISTORY §4.3.2")
	r.Declare("rollback_new_transition", "HISTORY §4.3.2")

	// Step 8: Rollback rejects invalid hash.
	r.Declare("rollback_invalid_hash_rejected", "HISTORY §7.5")

	// Step 9: F7 structured clock in transitions.
	r.Declare("transition_clock_structured", "HISTORY v1.5 §2 (F7)")

	// Step 10: W6 caller_capability.
	r.Declare("w6_caller_cap_absent", "HISTORY §2.1 W6")

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/history")
		if err != nil {
			return FailCheck("failed to fetch history handler manifest: " + err.Error())
		}
		r.Store("manifest_entity", ent)
		return PassCheck(fmt.Sprintf("history handler manifest present (type: %s)", ent.Type))
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		handlerData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return WarnCheck("could not decode handler manifest: " + err.Error())
		}
		r.Store("handler_data", handlerData)
		return PassCheck("handler manifest decoded")
	})

	for _, op := range []string{"query", "rollback"} {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("history handler missing operation: " + op)
			}
			return PassCheck("history handler has operation: " + op)
		})
	}

	// --- Step 2: Types ---

	typeChecks := []struct{ name, path string }{
		{"transition", "system/type/system/history/transition"},
		{"config", "system/type/system/history/config"},
		{"query_params", "system/type/system/history/query-params"},
		{"query_result", "system/type/system/history/query-result"},
		{"rollback_params", "system/type/system/history/rollback-params"},
		{"rollback_result", "system/type/system/history/rollback-result"},
	}
	for _, tc := range typeChecks {
		tc := tc
		r.Run("type_"+tc.name, func() CheckOutcome {
			_, _, err := client.TreeGet(ctx, tc.path)
			if err != nil {
				return FailCheck("history type not registered: " + tc.path)
			}
			return PassCheck("history type registered: " + tc.path)
		})
	}

	// --- Step 3: Put → query → verify transition ---

	r.Run("transition_recorded", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-record"
		testEnt := makeHistoryTestEntity("record-v1")
		entHash, err := client.TreePut(ctx, testPath, testEnt)
		if err != nil {
			return FailCheck("failed to put test entity: " + err.Error())
		}

		result, err := historyQuery(ctx, client, testPath, nil)
		if err != nil {
			return FailCheck("failed to query history after put: " + err.Error())
		}

		if len(result.Transitions) == 0 {
			return FailCheck("no transitions recorded after put")
		}
		r.Store("record_transitions", result.Transitions)
		r.Store("record_ent_hash", entHash)
		return PassCheck(fmt.Sprintf("transition recorded (%d total)", len(result.Transitions)))
	})

	r.Run("transition_event_created", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Event != "created" {
			return FailCheck(fmt.Sprintf("first transition event=%q (expected created)", t.Event))
		}
		return PassCheck("first transition event=created")
	})

	r.Run("transition_hash_matches", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		entHash := r.Load("record_ent_hash").(hash.Hash)
		if t.Hash != entHash {
			return FailCheck("transition hash does not match put entity hash")
		}
		return PassCheck("transition hash matches put entity hash")
	})

	r.Run("transition_has_timestamp", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Timestamp == 0 {
			return FailCheck("transition missing timestamp")
		}
		return PassCheck(fmt.Sprintf("transition has timestamp=%d", t.Timestamp))
	})

	r.Run("first_transition_no_previous", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if !t.Previous.IsZero() {
			return FailCheck("first transition should have no previous")
		}
		return PassCheck("first transition has no previous (correct for first write)")
	})

	// Execution context fields.

	r.Run("context_author_present", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Author.IsZero() {
			return FailCheck("transition missing author (MUST record author per §9.1)")
		}
		return PassCheck(fmt.Sprintf("transition has author=%s", t.Author))
	})

	r.Run("context_capability_present", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Capability.IsZero() {
			return FailCheck("transition missing capability (MUST record capability per §9.1)")
		}
		return PassCheck(fmt.Sprintf("transition has capability=%s", t.Capability))
	})

	r.Run("context_handler_present", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Handler == "" {
			return WarnCheck("transition missing handler (SHOULD record handler per §9.1)")
		}
		return PassCheck(fmt.Sprintf("transition has handler=%q", t.Handler))
	})

	r.Run("context_operation_present", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if t.Operation == "" {
			return WarnCheck("transition missing operation (SHOULD record operation per §9.1)")
		}
		return PassCheck(fmt.Sprintf("transition has operation=%q", t.Operation))
	})

	// --- Step 9: F7 structured clock ---

	r.Run("transition_clock_structured", func() CheckOutcome {
		if out, ok := r.Require("transition_recorded"); !ok {
			return out
		}
		t := r.Load("record_transitions").([]types.TransitionData)[0]
		if len(t.Clock) == 0 {
			return WarnCheck("transition has no clock field (clock extension may not be present)")
		}

		// Try decoding as a CBOR uint (old format).
		var uintVal uint64
		if err := cbor.Unmarshal([]byte(t.Clock), &uintVal); err == nil {
			return FailCheck(fmt.Sprintf("clock field is a CBOR uint (%d) — should be structured system/clock/state map (F7)", uintVal))
		}

		// Try decoding as a CBOR map (new structured format).
		var mapVal map[string]interface{}
		if err := cbor.Unmarshal([]byte(t.Clock), &mapVal); err != nil {
			return WarnCheck(fmt.Sprintf("clock field is neither uint nor map: %v", err))
		}
		if _, ok := mapVal["mode"]; ok {
			return PassCheck(fmt.Sprintf("clock field is structured map with mode=%v", mapVal["mode"]))
		}
		return WarnCheck("clock field is a map but missing 'mode' key")
	})

	// --- Step 4: Update → verify chain ---

	r.Run("chain_two_transitions", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-chain"

		// Write v1.
		v1Ent := makeHistoryTestEntity("chain-v1")
		v1Hash, err := client.TreePut(ctx, testPath, v1Ent)
		if err != nil {
			return FailCheck("failed to put v1: " + err.Error())
		}

		// Write v2 (update).
		v2Ent := makeHistoryTestEntity("chain-v2")
		v2Hash, err := client.TreePut(ctx, testPath, v2Ent)
		if err != nil {
			return FailCheck("failed to put v2: " + err.Error())
		}

		// Query history.
		result, err := historyQuery(ctx, client, testPath, nil)
		if err != nil {
			return FailCheck("failed to query chain history: " + err.Error())
		}

		if len(result.Transitions) < 2 {
			return FailCheck(fmt.Sprintf("expected at least 2 transitions, got %d", len(result.Transitions)))
		}
		r.Store("chain_transitions", result.Transitions)
		r.Store("chain_v1_hash", v1Hash)
		r.Store("chain_v2_hash", v2Hash)
		r.Store("chain_result", result)
		return PassCheck(fmt.Sprintf("chain has %d transitions", len(result.Transitions)))
	})

	r.Run("chain_latest_event_updated", func() CheckOutcome {
		if out, ok := r.Require("chain_two_transitions"); !ok {
			return out
		}
		latest := r.Load("chain_transitions").([]types.TransitionData)[0]
		if latest.Event != "updated" {
			return FailCheck(fmt.Sprintf("latest event=%q (expected updated)", latest.Event))
		}
		return PassCheck("latest transition event=updated")
	})

	r.Run("chain_latest_hash", func() CheckOutcome {
		if out, ok := r.Require("chain_two_transitions"); !ok {
			return out
		}
		latest := r.Load("chain_transitions").([]types.TransitionData)[0]
		v2Hash := r.Load("chain_v2_hash").(hash.Hash)
		if latest.Hash != v2Hash {
			return FailCheck("latest transition hash does not match v2")
		}
		return PassCheck("latest transition hash matches v2")
	})

	r.Run("chain_previous_hash", func() CheckOutcome {
		if out, ok := r.Require("chain_two_transitions"); !ok {
			return out
		}
		latest := r.Load("chain_transitions").([]types.TransitionData)[0]
		v1Hash := r.Load("chain_v1_hash").(hash.Hash)
		if latest.PreviousHash != v1Hash {
			return FailCheck("latest transition previous_hash does not match v1")
		}
		return PassCheck("latest transition previous_hash matches v1")
	})

	r.Run("chain_linked", func() CheckOutcome {
		if out, ok := r.Require("chain_two_transitions"); !ok {
			return out
		}
		latest := r.Load("chain_transitions").([]types.TransitionData)[0]
		if latest.Previous.IsZero() {
			return FailCheck("latest transition has no previous link")
		}
		return PassCheck("transition chain is linked via previous field")
	})

	r.Run("head_pointer_set", func() CheckOutcome {
		if out, ok := r.Require("chain_two_transitions"); !ok {
			return out
		}
		result := r.Load("chain_result").(types.HistoryQueryResultData)
		if result.Head.IsZero() {
			return FailCheck("head pointer not set in query result")
		}
		return PassCheck("head pointer set in query result")
	})

	// --- Step 5: Query with limit ---

	r.Run("limit_returns_1", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-limit"

		// Write 3 versions.
		for i := 0; i < 3; i++ {
			ent := makeHistoryTestEntity(fmt.Sprintf("limit-v%d", i))
			if _, err := client.TreePut(ctx, testPath, ent); err != nil {
				return FailCheck(fmt.Sprintf("failed to put version %d: %v", i, err))
			}
		}

		// Query with limit 1.
		limit := uint64(1)
		result, err := historyQuery(ctx, client, testPath, &limit)
		if err != nil {
			return FailCheck("failed to query with limit: " + err.Error())
		}

		if len(result.Transitions) != 1 {
			return FailCheck(fmt.Sprintf("limit=1 returned %d transitions (expected 1)", len(result.Transitions)))
		}
		r.Store("limit_result", result)
		return PassCheck("limit=1 returned exactly 1 transition")
	})

	r.Run("limit_has_more", func() CheckOutcome {
		if out, ok := r.Require("limit_returns_1"); !ok {
			return out
		}
		result := r.Load("limit_result").(types.HistoryQueryResultData)
		if !result.HasMore {
			return FailCheck("has_more should be true when limited")
		}
		return PassCheck("has_more=true when more transitions exist")
	})

	// --- Step 6: Query with event filter ---

	r.Run("event_filter_only_created", func() CheckOutcome {
		// Use the chain test path which has a created + updated transition.
		testPath := "system/validate/history-ext/test-chain"

		result, err := historyQueryFiltered(ctx, client, testPath, []string{"created"})
		if err != nil {
			return FailCheck("failed to query with event filter: " + err.Error())
		}

		// Should only have "created" transitions.
		for _, t := range result.Transitions {
			if t.Event != "created" {
				return FailCheck(fmt.Sprintf("event filter returned event=%q (expected only created)", t.Event))
			}
		}

		if len(result.Transitions) == 0 {
			return FailCheck("event filter for created returned no results")
		}
		return PassCheck(fmt.Sprintf("event filter for created returned %d transitions (all correct)", len(result.Transitions)))
	})

	// --- Step 7: Rollback ---

	r.Run("rollback_restored_hash", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-rollback"

		// Write v1 and v2.
		v1Ent := makeHistoryTestEntity("rollback-v1")
		v1Hash, err := client.TreePut(ctx, testPath, v1Ent)
		if err != nil {
			return FailCheck("failed to put v1: " + err.Error())
		}

		v2Ent := makeHistoryTestEntity("rollback-v2")
		_, err = client.TreePut(ctx, testPath, v2Ent)
		if err != nil {
			return FailCheck("failed to put v2: " + err.Error())
		}

		// Rollback to v1.
		rollbackResult, err := historyRollback(ctx, client, testPath, v1Hash)
		if err != nil {
			return FailCheck("failed to execute rollback: " + err.Error())
		}

		if rollbackResult.Restored != v1Hash {
			return FailCheck("rollback result restored hash does not match v1")
		}
		r.Store("rollback_v1_hash", v1Hash)
		r.Store("rollback_path", testPath)
		return PassCheck("rollback restored correct entity hash")
	})

	r.Run("rollback_verify_binding", func() CheckOutcome {
		if out, ok := r.Require("rollback_restored_hash"); !ok {
			return out
		}
		testPath := r.Load("rollback_path").(string)
		v1Hash := r.Load("rollback_v1_hash").(hash.Hash)

		currentEnt, _, err := client.TreeGet(ctx, testPath)
		if err != nil {
			return FailCheck("failed to get path after rollback: " + err.Error())
		}
		if currentEnt.ContentHash != v1Hash {
			return FailCheck("path not restored to v1 after rollback")
		}
		return PassCheck("path restored to v1 after rollback")
	})

	r.Run("rollback_new_transition", func() CheckOutcome {
		if out, ok := r.Require("rollback_restored_hash"); !ok {
			return out
		}
		testPath := r.Load("rollback_path").(string)
		v1Hash := r.Load("rollback_v1_hash").(hash.Hash)

		result, err := historyQuery(ctx, client, testPath, nil)
		if err != nil {
			return FailCheck("failed to query history after rollback: " + err.Error())
		}

		// Should have 3 transitions: rollback (updated) + v2 (updated) + v1 (created).
		if len(result.Transitions) < 3 {
			return FailCheck(fmt.Sprintf("expected 3+ transitions after rollback, got %d", len(result.Transitions)))
		}

		latest := result.Transitions[0]
		if latest.Event != "updated" || latest.Hash != v1Hash {
			return FailCheck("rollback transition not recorded correctly")
		}
		return PassCheck("rollback created new transition in history (event=updated, hash=v1)")
	})

	// --- Step 8: Rollback rejects invalid hash ---

	r.Run("rollback_invalid_hash_rejected", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-rollback"

		fakeHash := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		fakeHash.Digest[0] = 99
		fakeHash.Digest[1] = 98
		fakeHash.Digest[2] = 97
		resp, err := historyRollbackRaw(ctx, client, testPath, fakeHash)
		if err != nil {
			return FailCheck("failed to execute rollback with invalid hash: " + err.Error())
		}

		if resp.Status == 200 {
			return FailCheck("rollback with invalid hash should not return 200")
		}
		return PassCheck(fmt.Sprintf("rollback with invalid hash returned status %d (correctly rejected)", resp.Status))
	})

	// --- Step 9: W6 caller_capability absent ---

	r.Run("w6_caller_cap_absent", func() CheckOutcome {
		testPath := "system/validate/history-ext/test-w6"
		testEnt := makeHistoryTestEntity("w6-test")
		if _, err := client.TreePut(ctx, testPath, testEnt); err != nil {
			return FailCheck("failed to put test entity: " + err.Error())
		}

		result, err := historyQuery(ctx, client, testPath, nil)
		if err != nil {
			return FailCheck("failed to query history: " + err.Error())
		}

		if len(result.Transitions) == 0 {
			return FailCheck("no transitions found")
		}

		t := result.Transitions[0]

		if t.CallerCapability.IsZero() {
			return PassCheck("caller_capability correctly absent for caller-authorized write (redundant with capability)")
		} else if t.CallerCapability == t.Capability {
			return WarnCheck("caller_capability present but equals capability (W6 says omit when redundant)")
		}
		return FailCheck(fmt.Sprintf("caller_capability should be absent for caller-authorized tree put (got %s, capability=%s)", t.CallerCapability, t.Capability))
	})

	return r.Results()
}

// --- Helpers ---

func makeHistoryTestEntity(value string) entity.Entity {
	raw, _ := ecf.Encode(map[string]interface{}{"value": value})
	ent, _ := entity.NewEntity("system/validate/history-test", cbor.RawMessage(raw))
	return ent
}

func historyQuery(ctx context.Context, client *PeerClient, path string, limit *uint64) (types.HistoryQueryResultData, error) {
	params := types.HistoryQueryParamsData{Path: path, Limit: limit}
	return historyQueryFull(ctx, client, params)
}

func historyQueryFiltered(ctx context.Context, client *PeerClient, path string, events []string) (types.HistoryQueryResultData, error) {
	params := types.HistoryQueryParamsData{Path: path, Events: events}
	return historyQueryFull(ctx, client, params)
}

func historyQueryFull(ctx context.Context, client *PeerClient, params types.HistoryQueryParamsData) (types.HistoryQueryResultData, error) {
	paramsEnt, err := params.ToEntity()
	if err != nil {
		return types.HistoryQueryResultData{}, fmt.Errorf("create params entity: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/history", client.RemotePeerID())
	resource := &types.ResourceTarget{Targets: []string{"system/history"}}
	env, _, err := client.SendExecute(ctx, uri, "query", paramsEnt, resource)
	if err != nil {
		return types.HistoryQueryResultData{}, err
	}

	resp, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.HistoryQueryResultData{}, fmt.Errorf("decode response: %w", err)
	}
	if resp.Status != 200 {
		return types.HistoryQueryResultData{}, fmt.Errorf("query returned status %d", resp.Status)
	}

	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return types.HistoryQueryResultData{}, fmt.Errorf("decode result entity: %w", err)
	}

	// Unwrap system/envelope if present.
	inner, _, err := unwrapResultEnvelope(resultEnt)
	if err != nil {
		return types.HistoryQueryResultData{}, err
	}

	var result types.HistoryQueryResultData
	if err := ecf.Decode(inner.Data, &result); err != nil {
		return types.HistoryQueryResultData{}, fmt.Errorf("decode query result data: %w", err)
	}
	return result, nil
}

func historyRollback(ctx context.Context, client *PeerClient, path string, targetHash hash.Hash) (types.HistoryRollbackResultData, error) {
	resp, err := historyRollbackRaw(ctx, client, path, targetHash)
	if err != nil {
		return types.HistoryRollbackResultData{}, err
	}
	if resp.Status != 200 {
		return types.HistoryRollbackResultData{}, fmt.Errorf("rollback returned status %d", resp.Status)
	}

	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		return types.HistoryRollbackResultData{}, fmt.Errorf("decode result entity: %w", err)
	}

	var result types.HistoryRollbackResultData
	if err := ecf.Decode(resultEnt.Data, &result); err != nil {
		return types.HistoryRollbackResultData{}, fmt.Errorf("decode rollback result data: %w", err)
	}
	return result, nil
}

func historyRollbackRaw(ctx context.Context, client *PeerClient, path string, targetHash hash.Hash) (types.ExecuteResponseData, error) {
	params := types.HistoryRollbackParamsData{Path: path, TargetHash: targetHash}
	paramsEnt, err := params.ToEntity()
	if err != nil {
		return types.ExecuteResponseData{}, fmt.Errorf("create params entity: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/history", client.RemotePeerID())
	resource := &types.ResourceTarget{Targets: []string{"system/history", path}}
	env, _, err := client.SendExecute(ctx, uri, "rollback", paramsEnt, resource)
	if err != nil {
		return types.ExecuteResponseData{}, err
	}

	return types.ExecuteResponseDataFromEntity(env.Root)
}
