package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catClock = "clock"

func runClock(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catClock)

	// --- Declare all checks ---

	r.Declare("handler_manifest_present", "CLOCK §4")
	r.Declare("handler_manifest_decode", "CLOCK §4")
	r.Declare("handler_op_now", "CLOCK §4")
	r.Declare("handler_op_compare", "CLOCK §4")
	r.Declare("handler_op_tick", "CLOCK §4")

	r.Declare("type_timestamp", "CLOCK §2")
	r.Declare("type_logical", "CLOCK §2")
	r.Declare("type_vector", "CLOCK §2")
	r.Declare("type_hlc", "CLOCK §2")
	r.Declare("type_state", "CLOCK §2")
	r.Declare("type_compare_result", "CLOCK §2")

	r.Declare("now_status_200", "CLOCK §3.1")
	r.Declare("now_result_type", "CLOCK §3.1")
	r.Declare("now_has_mode", "CLOCK §3.1")
	r.Declare("now_has_value", "CLOCK §3.1")

	r.Declare("compare_ts_encode", "CLOCK §3.2")
	r.Declare("compare_ts_status_200", "CLOCK §3.2")
	r.Declare("compare_ts_result_type", "CLOCK §3.2")
	r.Declare("compare_ts_order", "CLOCK §3.2")

	r.Declare("compare_logical_encode", "CLOCK §3.2")
	r.Declare("compare_logical_status", "CLOCK §3.2")
	r.Declare("compare_logical_order", "CLOCK §3.2")

	r.Declare("advancement", "CLOCK §5")
	r.Declare("invalid_op_rejected", "CLOCK §4")

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/clock")
		if err != nil {
			return FailCheck("failed to fetch clock handler manifest: " + err.Error())
		}
		r.Store("manifest_entity", ent)
		return PassCheck(fmt.Sprintf("clock handler manifest present (type: %s)", ent.Type))
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
		return PassCheck("handler manifest decoded")
	})

	for _, op := range []string{"now", "compare", "tick"} {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("clock handler missing operation: " + op)
			}
			return PassCheck("clock handler has operation: " + op)
		})
	}

	// --- Step 2: Type registration ---

	typeChecks := []struct{ name, path string }{
		{"timestamp", "system/type/system/clock/timestamp"},
		{"logical", "system/type/system/clock/logical"},
		{"vector", "system/type/system/clock/vector"},
		{"hlc", "system/type/system/clock/hlc"},
		{"state", "system/type/system/clock/state"},
		{"compare_result", "system/type/system/clock/compare-result"},
	}
	for _, tc := range typeChecks {
		tc := tc
		r.Run("type_"+tc.name, func() CheckOutcome {
			_, _, err := client.TreeGet(ctx, tc.path)
			if err != nil {
				return FailCheck("clock type not registered: " + tc.path)
			}
			return PassCheck("clock type registered: " + tc.path)
		})
	}

	// --- Step 3: Now operation ---

	r.Run("now_status_200", func() CheckOutcome {
		resp, err := clockExecute(ctx, client, "now", nil)
		if err != nil {
			return FailCheck("failed to execute now: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("now returned status %d (expected 200)", resp.Status))
		}
		r.Store("now_resp", resp)
		return PassCheck("now returned status 200")
	})

	r.Run("now_result_type", func() CheckOutcome {
		if out, ok := r.Require("now_status_200"); !ok {
			return out
		}
		resp := r.Load("now_resp").(types.ExecuteResponseData)
		var resultEntity entity.Entity
		if err := ecf.Decode(resp.Result, &resultEntity); err != nil {
			return FailCheck("failed to decode now result entity: " + err.Error())
		}
		if resultEntity.Type != types.TypeClockState {
			return FailCheck(fmt.Sprintf("now result type is %q (expected %q)", resultEntity.Type, types.TypeClockState))
		}
		r.Store("now_result_entity", resultEntity)
		return PassCheck("now result type is system/clock/state")
	})

	r.Run("now_has_mode", func() CheckOutcome {
		if out, ok := r.Require("now_result_type"); !ok {
			return out
		}
		resultEntity := r.Load("now_result_entity").(entity.Entity)
		stateData, err := types.ClockStateDataFromEntity(resultEntity)
		if err != nil {
			return FailCheck("failed to decode clock state: " + err.Error())
		}
		validModes := map[string]bool{"wall": true, "logical": true, "vector": true, "hlc": true}
		if !validModes[stateData.Mode] {
			return FailCheck(fmt.Sprintf("now mode %q not one of wall/logical/vector/hlc", stateData.Mode))
		}
		r.Store("clock_state", stateData)
		return PassCheck(fmt.Sprintf("now mode=%s", stateData.Mode))
	})

	r.Run("now_has_value", func() CheckOutcome {
		if out, ok := r.Require("now_has_mode"); !ok {
			return out
		}
		stateData := r.Load("clock_state").(types.ClockStateData)
		hasValue := false
		switch stateData.Mode {
		case "wall":
			hasValue = stateData.Timestamp != nil && stateData.Timestamp.Ms > 0
		case "logical":
			hasValue = stateData.Logical != nil
		case "vector":
			hasValue = stateData.Vector != nil
		case "hlc":
			hasValue = stateData.HLC != nil
		}
		if !hasValue {
			return FailCheck(fmt.Sprintf("now missing value for mode=%s", stateData.Mode))
		}
		return PassCheck(fmt.Sprintf("now has value for mode=%s", stateData.Mode))
	})

	// --- Step 4: Compare timestamps ---

	r.Run("compare_ts_encode", func() CheckOutcome {
		now := uint64(time.Now().UnixMilli())
		aData := types.ClockTimestampData{Ms: now - 1000}
		bData := types.ClockTimestampData{Ms: now}
		aRaw, err := ecf.Encode(aData)
		if err != nil {
			return FailCheck("encode a: " + err.Error())
		}
		bRaw, err := ecf.Encode(bData)
		if err != nil {
			return FailCheck("encode b: " + err.Error())
		}
		r.Store("compare_ts_a", cbor.RawMessage(aRaw))
		r.Store("compare_ts_b", cbor.RawMessage(bRaw))
		return PassCheck("timestamp compare params encoded")
	})

	r.Run("compare_ts_status_200", func() CheckOutcome {
		if out, ok := r.Require("compare_ts_encode"); !ok {
			return out
		}
		params := types.ClockCompareParamsData{
			A: r.Load("compare_ts_a").(cbor.RawMessage),
			B: r.Load("compare_ts_b").(cbor.RawMessage),
		}
		resp, err := clockExecute(ctx, client, "compare", params)
		if err != nil {
			return FailCheck("failed to execute compare: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("compare returned status %d (expected 200)", resp.Status))
		}
		r.Store("compare_ts_resp", resp)
		return PassCheck("compare returned status 200")
	})

	r.Run("compare_ts_result_type", func() CheckOutcome {
		if out, ok := r.Require("compare_ts_status_200"); !ok {
			return out
		}
		resp := r.Load("compare_ts_resp").(types.ExecuteResponseData)
		var resultEntity entity.Entity
		if err := ecf.Decode(resp.Result, &resultEntity); err != nil {
			return FailCheck("failed to decode compare result: " + err.Error())
		}
		if resultEntity.Type != types.TypeClockCompareResult {
			return FailCheck(fmt.Sprintf("compare result type is %q (expected %q)", resultEntity.Type, types.TypeClockCompareResult))
		}
		r.Store("compare_ts_result_entity", resultEntity)
		return PassCheck("compare result type is system/clock/compare-result")
	})

	r.Run("compare_ts_order", func() CheckOutcome {
		if out, ok := r.Require("compare_ts_result_type"); !ok {
			return out
		}
		resultEntity := r.Load("compare_ts_result_entity").(entity.Entity)
		var compareResult types.ClockCompareResultData
		if err := ecf.Decode(resultEntity.Data, &compareResult); err != nil {
			return FailCheck("failed to decode compare result data: " + err.Error())
		}
		validOrders := map[string]bool{"before": true, "after": true, "equal": true, "concurrent": true}
		if !validOrders[compareResult.Order] {
			return FailCheck(fmt.Sprintf("compare order %q not one of before/after/equal/concurrent", compareResult.Order))
		}
		if compareResult.Order != "before" {
			return WarnCheck(fmt.Sprintf("compare order=%s (expected 'before' for a<b timestamps)", compareResult.Order))
		}
		return PassCheck("compare order=before (correct for a<b timestamps)")
	})

	// --- Step 5: Compare logical ---

	r.Run("compare_logical_encode", func() CheckOutcome {
		aData := types.ClockLogicalData{Counter: 1}
		bData := types.ClockLogicalData{Counter: 5}
		aRaw, err := ecf.Encode(aData)
		if err != nil {
			return FailCheck("encode a: " + err.Error())
		}
		bRaw, err := ecf.Encode(bData)
		if err != nil {
			return FailCheck("encode b: " + err.Error())
		}
		r.Store("compare_logical_a", cbor.RawMessage(aRaw))
		r.Store("compare_logical_b", cbor.RawMessage(bRaw))
		return PassCheck("logical compare params encoded")
	})

	r.Run("compare_logical_status", func() CheckOutcome {
		if out, ok := r.Require("compare_logical_encode"); !ok {
			return out
		}
		params := types.ClockCompareParamsData{
			A: r.Load("compare_logical_a").(cbor.RawMessage),
			B: r.Load("compare_logical_b").(cbor.RawMessage),
		}
		resp, err := clockExecute(ctx, client, "compare", params)
		if err != nil {
			return FailCheck("failed to execute compare: " + err.Error())
		}
		if resp.Status != 200 {
			return FailCheck(fmt.Sprintf("compare (logical) returned status %d", resp.Status))
		}
		r.Store("compare_logical_resp", resp)
		return PassCheck("compare (logical) returned status 200")
	})

	r.Run("compare_logical_order", func() CheckOutcome {
		if out, ok := r.Require("compare_logical_status"); !ok {
			return out
		}
		resp := r.Load("compare_logical_resp").(types.ExecuteResponseData)
		var resultEntity entity.Entity
		if err := ecf.Decode(resp.Result, &resultEntity); err != nil {
			return FailCheck("failed to decode compare result: " + err.Error())
		}
		var compareResult types.ClockCompareResultData
		if err := ecf.Decode(resultEntity.Data, &compareResult); err != nil {
			return FailCheck("failed to decode compare result data: " + err.Error())
		}
		if compareResult.Order != "before" {
			return FailCheck(fmt.Sprintf("compare logical order=%s (expected 'before' for counter 1 < 5)", compareResult.Order))
		}
		return PassCheck("compare logical order=before (correct for counter 1 < 5)")
	})

	// --- Step 6: Clock advancement ---

	r.Run("advancement", func() CheckOutcome {
		initialResp, err := clockExecute(ctx, client, "now", nil)
		if err != nil || initialResp.Status != 200 {
			return SkipCheck("could not get initial clock state")
		}
		var initialEntity entity.Entity
		if err := ecf.Decode(initialResp.Result, &initialEntity); err != nil {
			return SkipCheck("could not decode initial state")
		}
		initialState, err := types.ClockStateDataFromEntity(initialEntity)
		if err != nil {
			return SkipCheck("could not decode initial state data")
		}

		testEntity := mustCreateEntity("primitive/string", "clock-advancement-test")
		_, putErr := client.TreePut(ctx, "system/validate/clock-test/entity-1", testEntity)
		if putErr != nil {
			return SkipCheck("could not put test entity: " + putErr.Error())
		}

		time.Sleep(200 * time.Millisecond)

		afterResp, err := clockExecute(ctx, client, "now", nil)
		if err != nil || afterResp.Status != 200 {
			return FailCheck("could not get post-advancement clock state")
		}
		var afterEntity entity.Entity
		if err := ecf.Decode(afterResp.Result, &afterEntity); err != nil {
			return FailCheck("could not decode post-advancement state")
		}
		afterState, err := types.ClockStateDataFromEntity(afterEntity)
		if err != nil {
			return FailCheck("could not decode post-advancement state data")
		}

		switch initialState.Mode {
		case "wall":
			if afterState.Timestamp != nil {
				nowMs := uint64(time.Now().UnixMilli())
				if nowMs-afterState.Timestamp.Ms < 5000 {
					return PassCheck("wall clock timestamp is recent")
				}
				return WarnCheck(fmt.Sprintf("wall clock timestamp %d is not recent (now=%d)", afterState.Timestamp.Ms, nowMs))
			}
			return FailCheck("wall mode but no timestamp in state")
		case "logical":
			if initialState.Logical != nil && afterState.Logical != nil {
				if afterState.Logical.Counter > initialState.Logical.Counter {
					return PassCheck(fmt.Sprintf("logical counter advanced: %d -> %d",
						initialState.Logical.Counter, afterState.Logical.Counter))
				}
				return WarnCheck(fmt.Sprintf("logical counter did not advance: %d -> %d (async — may need more time)",
					initialState.Logical.Counter, afterState.Logical.Counter))
			}
			return WarnCheck("could not compare logical counters (nil state)")
		case "vector":
			if afterState.Vector != nil && len(afterState.Vector.Entries) > 0 {
				return PassCheck(fmt.Sprintf("vector clock has %d entries after advancement", len(afterState.Vector.Entries)))
			}
			return WarnCheck("vector clock entries empty after advancement (async — may need more time)")
		case "hlc":
			if afterState.HLC != nil {
				if afterState.HLC.Physical > 0 {
					return PassCheck(fmt.Sprintf("HLC physical=%d after advancement", afterState.HLC.Physical))
				}
				return WarnCheck("HLC physical=0 after advancement")
			}
			return WarnCheck("HLC state nil after advancement")
		default:
			return WarnCheck(fmt.Sprintf("unknown clock mode %q — cannot verify advancement", afterState.Mode))
		}
	})

	// --- Step 7: Invalid operation ---

	r.Run("invalid_op_rejected", func() CheckOutcome {
		resp, err := clockExecute(ctx, client, "nonexistent_op", nil)
		if err != nil {
			return PassCheck("invalid operation caused error (acceptable)")
		}
		if resp.Status >= 400 {
			return PassCheck(fmt.Sprintf("invalid operation rejected with status %d", resp.Status))
		}
		return FailCheck(fmt.Sprintf("invalid operation returned status %d (expected >=400)", resp.Status))
	})

	return r.Results()
}

// clockExecute sends an EXECUTE to the system/clock handler.
func clockExecute(ctx context.Context, client *PeerClient, operation string, params interface{}) (types.ExecuteResponseData, error) {
	var paramsEntity entity.Entity
	var err error

	if params == nil {
		raw, _ := ecf.Encode(map[string]interface{}{})
		paramsEntity, err = entity.NewEntity("primitive/map", cbor.RawMessage(raw))
	} else {
		raw, encErr := ecf.Encode(params)
		if encErr != nil {
			return types.ExecuteResponseData{}, fmt.Errorf("encode params: %w", encErr)
		}
		typeName := "system/clock/" + operation + "-params"
		paramsEntity, err = entity.NewEntity(typeName, cbor.RawMessage(raw))
	}
	if err != nil {
		return types.ExecuteResponseData{}, fmt.Errorf("create params entity: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/system/clock", client.RemotePeerID())
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
