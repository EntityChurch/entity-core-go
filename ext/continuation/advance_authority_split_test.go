package continuation

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestAdvanceAuthoritySplit_AT1234 is the Go oracle for the AT-1..AT-4 vectors
// of VECTOR-SPEC-2026-07-28-standing-model-authority (PROPOSAL-CONTINUATION-
// STANDING-MODEL §3, the fold gate). A standing continuation advances under its
// OWN dispatch_capability; the deliverer-declared reactive_trigger bit selects
// the gate:
//
//   - Reactive (reactive_trigger=true): delivery-driven, advances under the
//     continuation's own dispatch_capability; the trigger MUST NOT be required
//     to hold advance-cap on the continuation path. Accept-path — AT-1/AT-3.
//   - Administrative (reactive_trigger=false): a bare advance EXECUTE, stays
//     capability-gated on the continuation path. Deny-path — AT-2/AT-4.
//
// In Go the reactive_trigger surface is hctx.ReactiveTrigger, set per-dispatch
// via handler.WithReactiveTrigger() (NOT inherited by onward chain dispatches,
// local.go). All four vectors share the setup below; only the caller cap and
// the reactive bit vary.
func TestAdvanceAuthoritySplit_AT1234(t *testing.T) {
	const contPath = "system/inbox/standing-cb"

	// A caller capability that covers the continuation handler scope but is
	// scoped to an UNRELATED resource path — it does not cover `advance` on
	// contPath, so CheckPathCapability denies. Mirrors the cross-peer case
	// where the trigger's cap is a narrow dispatch cap scoped elsewhere.
	callerCapElsewhere := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/continuation"}},
		Resources:  types.CapabilityScope{Include: []string{"system/somewhere-else/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}}

	// setup builds a fresh context with the standing continuation installed and
	// a stubbed Execute that records whether the onward dispatch was reached.
	// callerGrants configures the caller's presented capability; reactive sets
	// the O1 signal (WithReactiveTrigger on the wire).
	setup := func(t *testing.T, callerGrants []types.GrantEntry, reactive bool) (*Handler, *handler.Request, *bool) {
		t.Helper()
		h := NewHandler()
		hctx := newTestContext()
		hctx.LocalPeerID = "peerB"

		hctx.CallerCapability = mustCapEntity(t, hctx.Store, callerGrants)
		// The continuation's OWN stored dispatch_capability — what a reactive
		// advance dispatches under (present + resolvable, per executeDispatch W9).
		dispatchCap := mustCapEntity(t, hctx.Store, []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/tree/*"}},
			Operations: types.CapabilityScope{Include: []string{"put"}},
		}})

		// Standing continuation (remaining_executions: null) — the shape §3
		// is about.
		storeContinuation(t, hctx, contPath, types.ContinuationData{
			Target:             "system/tree",
			Operation:          "put",
			DispatchCapability: dispatchCap.ContentHash,
		})

		dispatched := new(bool)
		hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
			*dispatched = true
			resultRaw, _ := cbor.Marshal(map[string]interface{}{"ok": true})
			resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
			return &handler.Response{Status: 200, Result: resultEntity}, nil
		}

		hctx.ReactiveTrigger = reactive
		req := makeAdvanceRequest(t, hctx, contPath, 200, map[string]interface{}{"value": "hello"})
		return h, req, dispatched
	}

	// assertAdvances is the accept-path assertion shared by AT-1/AT-3.
	assertAdvances := func(t *testing.T, resp *handler.Response, dispatched *bool) {
		t.Helper()
		if resp.Status != 200 {
			t.Fatalf("reactive advance must NOT be gated on the caller's path cap; got %d (code=%q)", resp.Status, errCode(resp))
		}
		if !*dispatched {
			t.Fatal("reactive advance must reach the onward dispatch under the continuation's own dispatch_capability")
		}
		if adv := advancedFlag(resp); adv != true {
			t.Fatalf("expected advanced=true, got %v", adv)
		}
	}

	// assertDenied is the deny-path assertion shared by AT-2/AT-4.
	assertDenied := func(t *testing.T, resp *handler.Response, dispatched *bool) {
		t.Helper()
		if resp.Status != 403 {
			t.Fatalf("administrative advance with a non-covering caller cap must 403; got %d", resp.Status)
		}
		if code := errCode(resp); code != "capability_denied" {
			t.Fatalf("expected code capability_denied, got %q", code)
		}
		if *dispatched {
			t.Fatal("administrative advance must be denied BEFORE the onward dispatch")
		}
	}

	// AT-1 — reactive advance, caller holds NO advance cap on the path: advances
	// under the continuation's own dispatch_capability. Accept-path (a deny-only
	// probe would pass a peer that wrongly over-restricts reactive advances).
	t.Run("AT-1 reactive advances under own authority (no path cap)", func(t *testing.T) {
		h, req, dispatched := setup(t, callerCapElsewhere, true)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		assertAdvances(t, resp, dispatched)
	})

	// AT-2 — administrative advance, caller holds a capability but NOT advance on
	// the continuation path: 403. Proves the administrative path stays path-cap-
	// gated (the split).
	t.Run("AT-2 administrative invoke stays path-cap-gated (403)", func(t *testing.T) {
		h, req, dispatched := setup(t, callerCapElsewhere, false)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		assertDenied(t, resp, dispatched)
	})

	// AT-3 — a reconnecting remote peer triggers a standing (reconnect)
	// continuation reactively with no advance rights on it: advances. The
	// concrete browser-defer acceptance signal. Same accept-path assertion as
	// AT-1 with the reconnect framing (the vector spec lists them separately to
	// pin the reconnect case explicitly).
	t.Run("AT-3 reactive reconnect continuation advances (browser-defer)", func(t *testing.T) {
		h, req, dispatched := setup(t, callerCapElsewhere, true)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		assertAdvances(t, resp, dispatched)
	})

	// AT-4 (O1, fail-closed) — administrative advance, caller presents a
	// capability that grants NOTHING on the continuation path at all: 403,
	// never allowed by omission.
	//
	// FINDING (arch soft-spot #2, reachability): the TRULY-absent caller-cap
	// case (hctx.CallerCapability zero) is structurally UNREACHABLE from the
	// wire — the dispatcher rejects a capability-less EXECUTE at 403
	// capability_not_found (core/protocol/execute.go) and requires the cap to
	// satisfy the system/continuation handler scope (FindMatchingGrant) before
	// handleAdvance runs, so CallerCapability is guaranteed non-zero here. At
	// the handler, CheckPathCapability deliberately no-ops on a zero cap — but
	// that state is the trusted IN-PROCESS operator invocation (used pervasively
	// by local advances), not a wire caller who omitted a cap; forcing it fail-
	// closed would break the local path and change no wire outcome. So the
	// REACHABLE O1 boundary is a wire cap that clears the handler scope but
	// grants nothing on the path — asserted here — which denies via
	// CheckPathCapability. Net: Go's no-op-on-absent and Python's require-present
	// agree on the outcome (deny) for every reachable administrative advance.
	t.Run("AT-4 administrative advance with an empty caller cap denies (O1 fail-closed)", func(t *testing.T) {
		h, req, dispatched := setup(t, []types.GrantEntry{}, false)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		assertDenied(t, resp, dispatched)
	})
}

// errCode decodes the `code` field from an error response's result payload.
func errCode(resp *handler.Response) string {
	if resp == nil || len(resp.Result.Data) == 0 {
		return ""
	}
	var m map[string]interface{}
	if err := cbor.Unmarshal(resp.Result.Data, &m); err != nil {
		return ""
	}
	code, _ := m["code"].(string)
	return code
}

// advancedFlag decodes the `advanced` field from an advancement result.
func advancedFlag(resp *handler.Response) interface{} {
	if resp == nil || len(resp.Result.Data) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := cbor.Unmarshal(resp.Result.Data, &m); err != nil {
		return nil
	}
	return m["advanced"]
}
