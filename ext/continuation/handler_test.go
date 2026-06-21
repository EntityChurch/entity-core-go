package continuation

import (
	"context"
	"fmt"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func newTestContext() *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:          store.NewMemoryContentStore(),
		LocationIndex:  store.NewMemoryLocationIndex(),
		HandlerPattern: "system/continuation",
		Included:       make(map[hash.Hash]entity.Entity),
	}
}

// testCapHash creates a dummy capability entity, stores it in cs, and returns its content hash.
func testCapHash(t *testing.T, cs store.ContentStore) hash.Hash {
	t.Helper()
	capData, _ := ecf.Encode(map[string]interface{}{"scope": "test"})
	capEnt, _ := entity.NewEntity("system/capability/grant", cbor.RawMessage(capData))
	h, err := cs.Put(capEnt)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func storeSuspended(t *testing.T, hctx *handler.HandlerContext, path string, suspended types.ContinuationSuspendedData) {
	t.Helper()
	ent, err := suspended.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	hctx.LocationIndex.Set(path, h)
}

func storeContinuation(t *testing.T, hctx *handler.HandlerContext, path string, cont types.ContinuationData) {
	t.Helper()
	ent, err := cont.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	hctx.LocationIndex.Set(path, h)
}

func storeJoin(t *testing.T, hctx *handler.HandlerContext, path string, join types.ContinuationJoinData) {
	t.Helper()
	ent, err := join.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatal(err)
	}
	hctx.LocationIndex.Set(path, h)
}

// makeAdvanceRequest creates an advance handler.Request.
func makeAdvanceRequest(t *testing.T, hctx *handler.HandlerContext, path string, status uint, result interface{}) *handler.Request {
	t.Helper()
	resultRaw, err := ecf.Encode(result)
	if err != nil {
		t.Fatal(err)
	}
	statusVal := status
	advReq := types.ContinuationAdvanceRequestData{
		Result: cbor.RawMessage(resultRaw),
		Status: &statusVal,
	}
	params, err := advReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	hctx.Resource = &types.ResourceTarget{Targets: []string{path}}
	return &handler.Request{
		Path:      "system/continuation",
		Operation: "advance",
		Params:    params,
		Context:   hctx,
	}
}

// --- Advance operation tests ---

func TestAdvanceForwardPassThrough(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedURI, executedOp string
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedURI = uri
		executedOp = op
		resultRaw, _ := ecf.Encode(map[string]interface{}{"dispatched": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/my-cb", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/my-cb", 200, map[string]interface{}{"value": "hello"})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if executedURI != "system/tree" {
		t.Fatalf("expected dispatch to system/tree, got %s", executedURI)
	}
	if executedOp != "put" {
		t.Fatalf("expected operation put, got %s", executedOp)
	}
}

func TestAdvanceForwardInject(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedParams entity.Entity
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedParams = params
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	paramsRaw, _ := ecf.Encode(map[string]interface{}{"name": "test"})
	storeContinuation(t, hctx, "system/inbox/inject-cb", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		Params:              cbor.RawMessage(paramsRaw),
		ResultField:         "score",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/inject-cb", 200, 42)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	var decoded map[string]interface{}
	if err := cbor.Unmarshal(executedParams.Data, &decoded); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if decoded["name"] != "test" {
		t.Fatalf("expected name=test, got %v", decoded["name"])
	}
	if decoded["score"] != uint64(42) {
		t.Fatalf("expected score=42, got %v (%T)", decoded["score"], decoded["score"])
	}
}

func TestAdvanceForwardTrigger(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedParams entity.Entity
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedParams = params
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	paramsRaw, _ := ecf.Encode(map[string]interface{}{"action": "cleanup"})
	storeContinuation(t, hctx, "system/inbox/trigger-cb", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		Params:              cbor.RawMessage(paramsRaw),
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/trigger-cb", 200, "ignored")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	var decoded map[string]interface{}
	if err := cbor.Unmarshal(executedParams.Data, &decoded); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if decoded["action"] != "cleanup" {
		t.Fatalf("expected action=cleanup, got %v", decoded["action"])
	}
}

func TestAdvanceInvalidResultFieldWithoutParams(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		t.Fatal("should not dispatch")
		return nil, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/invalid-cb", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		ResultField:         "value",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/invalid-cb", 200, "test")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestAdvanceForwardOnError(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedURI string
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedURI = uri
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/main-cb", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		OnError:             &types.DeliverySpec{URI: "system/tree/error-log", Operation: "put"},
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/main-cb", 500, map[string]interface{}{"error": "boom"})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if executedURI != "system/tree/error-log" {
		t.Fatalf("expected dispatch to error target, got %s", executedURI)
	}
}

// TestAdvanceOnErrorDispatchFailureBindsLostMarker — A.1
// (EXTENSION-CONTINUATION §3.4). When the on_error dispatch itself fails,
// the advance is best-effort (still 200, not propagated) AND an
// informational lost-error marker is bound at
// system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason} with
// the original status/code, the failed delivery URI, the request id, and
// a timestamp. The marker is observational only — no reactive behavior.
//
// CROSS-IMPL PIN GUARD: the marker entity `type` MUST be
// system/runtime/chain-error-lost (v1.10 §3.4) and {step_index} MUST be
// the original request ID (v1.14 §3.4); v1.16 §3.4 further pins the
// per-reason subsegment so distinct reasons coexist. The type, the
// request-ID step segment, and the reason subsegment asserted below are
// that pin; changing any is a cross-impl break.
func TestAdvanceOnErrorDispatchFailureBindsLostMarker(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-42"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-7"}

	// on_error dispatch fails (delivery error) — the hazard A.1 closes.
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		return nil, fmt.Errorf("simulated on_error delivery failure")
	}

	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/main-cb", types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		OnError:            &types.DeliverySpec{URI: "system/tree/error-log", Operation: "put"},
		DispatchCapability: capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/main-cb", 500,
		map[string]interface{}{"code": "boom_code"})
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Best-effort: the lost on_error must NOT propagate as an error.
	if resp.Status != 200 {
		t.Fatalf("on_error failure must be best-effort (200), got %d", resp.Status)
	}

	// v1.20 §3.10.1: markers live at a per-occurrence path with terminal
	// {marker_hash} segment. The A.1 marker carries
	// reason="on_error_dispatch_failed" (Category A internal-engine code,
	// canonical home moved to EXTENSION-CONTINUATION Appendix A as of v1.19).
	prefix := "system/runtime/chain-errors/lost/chain-7/req-42/on_error_dispatch_failed/"
	entries := hctx.LocationIndex.List(prefix)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 lost-error marker under %s, got %d", prefix, len(entries))
	}
	mh := entries[0].Hash
	mEnt, ok := hctx.Store.Get(mh)
	if !ok {
		t.Fatal("marker entity not in store")
	}
	if mEnt.Type != types.TypeChainErrorLost {
		t.Fatalf("marker type: got %s, want %s", mEnt.Type, types.TypeChainErrorLost)
	}
	var md types.ChainErrorLostData
	if err := ecf.Decode(mEnt.Data, &md); err != nil {
		t.Fatalf("decode marker: %v", err)
	}
	if md.OriginalStatus != 500 {
		t.Errorf("OriginalStatus: got %d, want 500", md.OriginalStatus)
	}
	if md.OriginalCode != "boom_code" {
		t.Errorf("OriginalCode: got %q, want %q", md.OriginalCode, "boom_code")
	}
	if md.FailedDeliveryURI != "system/tree/error-log" {
		t.Errorf("FailedDeliveryURI: got %q", md.FailedDeliveryURI)
	}
	if md.OriginalRequestID != "req-42" {
		t.Errorf("OriginalRequestID: got %q, want req-42", md.OriginalRequestID)
	}
	if md.Timestamp == 0 {
		t.Error("Timestamp must be set")
	}
	// v1.19 §3.10.5: A.1 markers carry reason="on_error_dispatch_failed"
	// (Category A engine-internal code, canonical home in Appendix A).
	if md.Reason != types.ChainErrorReasonOnErrorDispatchFailed {
		t.Errorf("Reason: got %q, want %q", md.Reason, types.ChainErrorReasonOnErrorDispatchFailed)
	}
}

// markerBound reports whether the A.1 (on_error_dispatch_failed) lost-error
// marker is bound under the chain-errors/lost sub-purpose for the given
// context. v1.20 §3.10.1: terminal {marker_hash} segment per-occurrence,
// so we check the per-reason prefix for any entries.
func markerBound(hctx *handler.HandlerContext) bool {
	return len(hctx.LocationIndex.List("system/runtime/chain-errors/lost/chain-7/req-42/on_error_dispatch_failed/")) > 0
}

// TestAdvanceOnErrorSuccessNoMarker — negative: when the on_error dispatch
// SUCCEEDS, no lost-error marker is bound (the marker is for *lost* on_error
// delivery only; binding it on success would be a false signal).
func TestAdvanceOnErrorSuccessNoMarker(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-42"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-7"}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		r, _ := ecf.Encode(map[string]interface{}{"ok": true})
		re, _ := entity.NewEntity("primitive/any", cbor.RawMessage(r))
		return &handler.Response{Status: 200, Result: re}, nil
	}
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/main-cb", types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		OnError:            &types.DeliverySpec{URI: "system/tree/error-log", Operation: "put"},
		DispatchCapability: capHash,
	})
	resp, err := h.Handle(context.Background(),
		makeAdvanceRequest(t, hctx, "system/inbox/main-cb", 500, map[string]interface{}{"code": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}
	if markerBound(hctx) {
		t.Fatal("no lost-error marker must be bound when on_error dispatch succeeded")
	}
}

// TestAdvanceOnErrorHandlerErrorBindsMarker — the second failure path: the
// on_error dispatch returns a handler-level error STATUS (>=400) with nil
// transport error. That is also a lost on_error and MUST bind the marker
// (covers the `errResp.Status >= 400` branch, distinct from a transport err).
func TestAdvanceOnErrorHandlerErrorBindsMarker(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-42"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-7"}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		ed, _ := types.ErrorData{Code: "downstream_unavailable"}.ToEntity()
		return &handler.Response{Status: 503, Result: ed}, nil // handler-level failure, nil err
	}
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/main-cb", types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		OnError:            &types.DeliverySpec{URI: "system/tree/error-log", Operation: "put"},
		DispatchCapability: capHash,
	})
	resp, err := h.Handle(context.Background(),
		makeAdvanceRequest(t, hctx, "system/inbox/main-cb", 502, map[string]interface{}{"code": "boom"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("best-effort: expected 200, got %d", resp.Status)
	}
	if !markerBound(hctx) {
		t.Fatal("a handler-level on_error failure (status>=400) MUST bind the lost-error marker")
	}
}

// TestForwardDispatchHandlerNon2xxIsCompleted is the v1.10 §3.4
// "forward-dispatch outcome classification" drift guard + the v1.13 / I-8
// no-on_error lost-error marker behavior. A *delivered* EXECUTE that
// returns a handler-level non-2xx (403/404/500) is a COMPLETED forward
// dispatch (forward = closure invocation, not RPC; the dispatched response
// is not threaded back): remaining_executions decremented, {advanced:true}
// returned, never promoted/suspended/errored. Additionally per v1.13: when
// the continuation has NO on_error and the dispatch returns non-2xx, the
// observability marker MUST be bound at
// system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason} with
// reason="forward_dispatch_non2xx" (same type as the A.1 marker, separate
// per-reason subsegment per v1.16 §3.4).
// The marker is informational — it MUST NOT change the dispatch
// classification above.
func TestForwardDispatchHandlerNon2xxIsCompleted(t *testing.T) {
	for _, hstatus := range []uint{403, 404, 500} {
		t.Run(fmt.Sprintf("handler_%d", hstatus), func(t *testing.T) {
			h := NewHandler()
			hctx := newTestContext()
			hctx.RequestID = "req-1"
			// Delivered EXECUTE; the target handler returns non-2xx with
			// nil transport error (a completed dispatch, not a
			// dispatch_result.error).
			hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
				ed, _ := types.ErrorData{Code: "handler_said_no"}.ToEntity()
				return &handler.Response{Status: hstatus, Result: ed}, nil
			}

			remaining := uint64(1)
			capHash := testCapHash(t, hctx.Store)
			// NO on_error — the silent-burn shape; classification must
			// still be "completed", never suspended/errored.
			storeContinuation(t, hctx, "system/inbox/fwd", types.ContinuationData{
				Target:              "system/tree",
				Operation:           "put",
				RemainingExecutions: &remaining,
				DispatchCapability:  capHash,
			})

			resp, err := h.Handle(context.Background(),
				makeAdvanceRequest(t, hctx, "system/inbox/fwd", 200, "payload"))
			if err != nil {
				t.Fatalf("advance returned a Go error (must not promote handler %d to dispatch_result.error): %v", hstatus, err)
			}
			if resp.Status != 200 {
				t.Fatalf("handler %d: advance status=%d, want 200 ({advanced:true} — not promoted/suspended/errored)", hstatus, resp.Status)
			}
			var res map[string]interface{}
			if e := cbor.Unmarshal(resp.Result.Data, &res); e != nil {
				t.Fatalf("decode advancement result: %v", e)
			}
			if res["advanced"] != true {
				t.Fatalf("handler %d: result=%v, want {advanced:true} (completed forward dispatch)", hstatus, res)
			}
			if res["suspended"] == true {
				t.Fatalf("handler %d: MUST NOT suspend on a delivered handler non-2xx (v1.10 §3.4)", hstatus)
			}
			// remaining_executions decremented (one-shot → continuation gone).
			if hctx.LocationIndex.Has("system/inbox/fwd") {
				t.Fatalf("handler %d: remaining_executions not decremented — completed dispatch MUST decrement", hstatus)
			}
			// v1.19 §3.10.5 + v1.20 §3.10.1: NO on_error + handler-level
			// non-2xx MUST bind an observability lost-error marker at the
			// chain-errors/lost sink with {reason} = result.data.code
			// verbatim (the test's handler emits code="handler_said_no"
			// for all three statuses). The deprecated v1.13 catch-all
			// reason "forward_dispatch_non2xx" is gone; distinct codes
			// now coexist as sibling paths. Each occurrence lands at its
			// own {marker_hash} terminal segment per v1.20.
			prefix := "system/runtime/chain-errors/lost/req-1/req-1/handler_said_no/"
			entries := hctx.LocationIndex.List(prefix)
			if len(entries) != 1 {
				t.Fatalf("handler %d: expected exactly 1 lost-error marker under %s, got %d", hstatus, prefix, len(entries))
			}
			mh := entries[0].Hash
			mEnt, ok := hctx.Store.Get(mh)
			if !ok {
				t.Fatalf("handler %d: marker entity missing from store", hstatus)
			}
			if mEnt.Type != types.TypeChainErrorLost {
				t.Fatalf("handler %d: marker type=%s, want %s", hstatus, mEnt.Type, types.TypeChainErrorLost)
			}
			var md types.ChainErrorLostData
			if e := ecf.Decode(mEnt.Data, &md); e != nil {
				t.Fatalf("handler %d: decode marker: %v", hstatus, e)
			}
			if md.Reason != "handler_said_no" {
				t.Fatalf("handler %d: marker reason=%q, want %q (v1.19 §3.10.5 — reason IS result.data.code)", hstatus, md.Reason, "handler_said_no")
			}
			if md.OriginalStatus != hstatus {
				t.Fatalf("handler %d: marker original_status=%d, want %d", hstatus, md.OriginalStatus, hstatus)
			}
			if md.FailedDeliveryURI != "system/tree" {
				t.Fatalf("handler %d: marker failed_delivery_uri=%q, want system/tree", hstatus, md.FailedDeliveryURI)
			}
		})
	}
}

func TestAdvanceRemainingExecutionsOneShotDeletes(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/oneshot", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/oneshot", 200, "value")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	if hctx.LocationIndex.Has("system/inbox/oneshot") {
		t.Fatal("continuation should have been deleted after one fire")
	}
}

func TestAdvanceStandingContinuation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	dispatchCount := 0
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		dispatchCount++
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	// Standing continuation: nil remaining_executions.
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/standing", types.ContinuationData{
		Target:             "system/tree",
		Operation:          "put",
		DispatchCapability: capHash,
	})

	for i := 0; i < 2; i++ {
		req := makeAdvanceRequest(t, hctx, "system/inbox/standing", 200, "value")
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 {
			t.Fatalf("expected status 200, got %d", resp.Status)
		}
	}

	if dispatchCount != 2 {
		t.Fatalf("expected 2 dispatches, got %d", dispatchCount)
	}
	if !hctx.LocationIndex.Has("system/inbox/standing") {
		t.Fatal("standing continuation should not be deleted")
	}
}

func TestAdvanceResultTransform(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedParams entity.Entity
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedParams = params
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/transform-cb", types.ContinuationData{
		Target:    "system/tree",
		Operation: "put",
		ResultTransform: &types.ContinuationTransformData{
			Extract: "data",
			Select:  map[string]string{"score": "metrics.total"},
		},
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	resultData := map[string]interface{}{
		"data": map[string]interface{}{
			"metrics": map[string]interface{}{
				"total": 99,
			},
		},
	}

	req := makeAdvanceRequest(t, hctx, "system/inbox/transform-cb", 200, resultData)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	var decoded map[string]interface{}
	if err := cbor.Unmarshal(executedParams.Data, &decoded); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if decoded["score"] != uint64(99) {
		t.Fatalf("expected score=99, got %v (%T)", decoded["score"], decoded["score"])
	}
}

func TestAdvanceJoinSlotAccumulation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedOp string
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedOp = op
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeJoin(t, hctx, "system/inbox/join-1", types.ContinuationJoinData{
		Expected:            []string{"left", "right"},
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	// Deliver to "left" slot.
	req1 := makeAdvanceRequest(t, hctx, "system/inbox/join-1/left", 200, "left-value")
	resp, err := h.Handle(context.Background(), req1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if executedOp != "" {
		t.Fatal("should not dispatch before all slots filled")
	}

	req2 := makeAdvanceRequest(t, hctx, "system/inbox/join-1/right", 200, "right-value")
	resp, err = h.Handle(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if executedOp != "put" {
		t.Fatalf("expected dispatch after all slots filled, got op=%q", executedOp)
	}
}

func TestAdvanceJoinUnexpectedSlot(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		t.Fatal("should not dispatch")
		return nil, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeJoin(t, hctx, "system/inbox/join-err", types.ContinuationJoinData{
		Expected:            []string{"a", "b"},
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/join-err/c", 200, "value")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestAdvanceJoinDirectReturns400(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		t.Fatal("should not dispatch")
		return nil, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeJoin(t, hctx, "system/inbox/join-direct", types.ContinuationJoinData{
		Expected:            []string{"a"},
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/join-direct", 200, "value")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestAdvanceJoinStandingReset(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	dispatchCount := 0
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		dispatchCount++
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	capHash := testCapHash(t, hctx.Store)
	storeJoin(t, hctx, "system/inbox/join-standing", types.ContinuationJoinData{
		Expected:           []string{"a"},
		Target:             "system/tree",
		Operation:          "put",
		DispatchCapability: capHash,
		// nil RemainingExecutions = standing
	})

	req1 := makeAdvanceRequest(t, hctx, "system/inbox/join-standing/a", 200, "v1")
	resp, err := h.Handle(context.Background(), req1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("round 1: expected 200, got %d", resp.Status)
	}
	if dispatchCount != 1 {
		t.Fatalf("round 1: expected 1 dispatch, got %d", dispatchCount)
	}

	req2 := makeAdvanceRequest(t, hctx, "system/inbox/join-standing/a", 200, "v2")
	resp, err = h.Handle(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("round 2: expected 200, got %d", resp.Status)
	}
	if dispatchCount != 2 {
		t.Fatalf("round 2: expected 2 dispatches, got %d", dispatchCount)
	}
}

func TestAdvanceDispatchErrorPreservesRemainingExecutions(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		return nil, fmt.Errorf("dispatch failed: target unavailable")
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/error-preserve", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/error-preserve", 200, "value")
	_, err := h.Handle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from failed dispatch")
	}

	if !hctx.LocationIndex.Has("system/inbox/error-preserve") {
		t.Fatal("continuation should not be deleted when dispatch fails")
	}
}

func TestAdvanceNoContinuation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	req := makeAdvanceRequest(t, hctx, "system/inbox/nonexistent", 200, "value")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	// Should return {advanced: false}.
	var result map[string]interface{}
	if err := cbor.Unmarshal(resp.Result.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result["advanced"] != false {
		t.Fatalf("expected advanced=false, got %v", result["advanced"])
	}
}

func TestAdvanceForwardWithResource(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var capturedOpts []handler.ExecuteOption
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		capturedOpts = opts
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	remaining := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	storeContinuation(t, hctx, "system/inbox/with-resource", types.ContinuationData{
		Target:              "system/tree",
		Operation:           "put",
		Resource:            &types.ResourceTarget{Targets: []string{"local/output"}},
		RemainingExecutions: &remaining,
		DispatchCapability:  capHash,
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/with-resource", 200, "data")
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if len(capturedOpts) == 0 {
		t.Fatal("expected execute options with resource")
	}
}

// --- Resume operation tests ---

func TestResumeDispatch(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedURI, executedOp string
	var executedParams entity.Entity
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedURI = uri
		executedOp = op
		executedParams = params
		resultRaw, _ := ecf.Encode(map[string]interface{}{"resumed": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	paramsRaw, _ := ecf.Encode(map[string]interface{}{"key": "value"})
	storeSuspended(t, hctx, "system/continuation/suspended/abc", types.ContinuationSuspendedData{
		Target:         "system/tree",
		Operation:      "put",
		Params:         cbor.RawMessage(paramsRaw),
		Reason:         "ttl_exhausted",
		ChainID:        "chain-1",
		OriginalAuthor: hash.Hash{Algorithm: hash.AlgorithmSHA256},
		SuspendedAt:    1709500000000,
	})

	resumeReq := types.ContinuationResumeRequestData{}
	params, err := resumeReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/abc"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/abc",
		Operation: "resume",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if executedURI != "system/tree" {
		t.Fatalf("expected dispatch to system/tree, got %s", executedURI)
	}
	if executedOp != "put" {
		t.Fatalf("expected operation put, got %s", executedOp)
	}
	if len(executedParams.Data) == 0 {
		t.Fatal("expected non-empty params")
	}

	if hctx.LocationIndex.Has("system/continuation/suspended/abc") {
		t.Fatal("suspended entity should have been deleted")
	}
}

func TestResumeMergeResolution(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var executedParams entity.Entity
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		executedParams = params
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	paramsRaw, _ := ecf.Encode(map[string]interface{}{"name": "original"})
	storeSuspended(t, hctx, "system/continuation/suspended/merge", types.ContinuationSuspendedData{
		Target:         "system/tree",
		Operation:      "put",
		Params:         cbor.RawMessage(paramsRaw),
		Reason:         "needs_input",
		ChainID:        "chain-2",
		OriginalAuthor: hash.Hash{Algorithm: hash.AlgorithmSHA256},
		SuspendedAt:    1709500000000,
	})

	resolutionRaw, _ := ecf.Encode(map[string]interface{}{"choice": "option-a"})
	resumeReq := types.ContinuationResumeRequestData{
		Resolution: cbor.RawMessage(resolutionRaw),
	}
	params, err := resumeReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/merge"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/merge",
		Operation: "resume",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	var decoded map[string]interface{}
	if err := cbor.Unmarshal(executedParams.Data, &decoded); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if decoded["name"] != "original" {
		t.Fatalf("expected name=original, got %v", decoded["name"])
	}
	if decoded["choice"] != "option-a" {
		t.Fatalf("expected choice=option-a, got %v", decoded["choice"])
	}
}

func TestResumeNotFound(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	resumeReq := types.ContinuationResumeRequestData{}
	params, err := resumeReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/missing"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/missing",
		Operation: "resume",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected status 404, got %d", resp.Status)
	}
}

func TestResumeNotSuspended(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	someData, _ := ecf.Encode(map[string]interface{}{"not": "suspended"})
	someEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(someData))
	someHash, _ := hctx.Store.Put(someEntity)
	hctx.LocationIndex.Set("system/continuation/suspended/wrong-type", someHash)

	resumeReq := types.ContinuationResumeRequestData{}
	params, err := resumeReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/wrong-type"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/wrong-type",
		Operation: "resume",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

// --- Abandon operation tests ---

func TestAbandon(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	storeSuspended(t, hctx, "system/continuation/suspended/abandon-me", types.ContinuationSuspendedData{
		Target:         "system/tree",
		Operation:      "put",
		Reason:         "test",
		ChainID:        "chain-x",
		OriginalAuthor: hash.Hash{Algorithm: hash.AlgorithmSHA256},
		SuspendedAt:    1709500000000,
	})

	abandonReq := types.ContinuationAbandonRequestData{}
	params, err := abandonReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/abandon-me"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/abandon-me",
		Operation: "abandon",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	if hctx.LocationIndex.Has("system/continuation/suspended/abandon-me") {
		t.Fatal("entity should have been deleted")
	}
}

func TestAbandonNotFound(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	abandonReq := types.ContinuationAbandonRequestData{}
	params, err := abandonReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/missing"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/missing",
		Operation: "abandon",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected status 404, got %d", resp.Status)
	}
}

func TestAbandonWrongType(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	someData, _ := ecf.Encode(map[string]interface{}{"not": "suspended"})
	someEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(someData))
	someHash, _ := hctx.Store.Put(someEntity)
	hctx.LocationIndex.Set("system/continuation/suspended/wrong-type", someHash)

	abandonReq := types.ContinuationAbandonRequestData{}
	params, err := abandonReq.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/suspended/wrong-type"}}
	req := &handler.Request{
		Path:      "system/continuation/suspended/wrong-type",
		Operation: "abandon",
		Params:    params,
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400 for wrong entity type, got %d", resp.Status)
	}
	if !hctx.LocationIndex.Has("system/continuation/suspended/wrong-type") {
		t.Fatal("entity should not have been deleted")
	}
}

func TestUnknownOperation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Resource = &types.ResourceTarget{Targets: []string{"system/continuation/test"}}

	req := &handler.Request{
		Path:      "system/continuation/test",
		Operation: "invalid",
		Params:    entity.Entity{},
		Context:   hctx,
	}

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestManifest(t *testing.T) {
	h := NewHandler()
	m := h.Manifest()
	if m.Pattern != "system/continuation" {
		t.Fatalf("expected pattern system/continuation, got %s", m.Pattern)
	}
	if m.Name != "continuations" {
		t.Fatalf("expected name continuations, got %s", m.Name)
	}
	if _, ok := m.Operations["advance"]; !ok {
		t.Fatal("missing advance operation")
	}
	if _, ok := m.Operations["resume"]; !ok {
		t.Fatal("missing resume operation")
	}
	if _, ok := m.Operations["abandon"]; !ok {
		t.Fatal("missing abandon operation")
	}
}
