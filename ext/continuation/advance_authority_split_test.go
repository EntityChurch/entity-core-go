package continuation

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestAdvanceAuthoritySplit_ReactiveVsAdministrative pins the Q2 ruling of
// PROPOSAL-CONTINUATION-STANDING-MODEL §3: a standing continuation advances
// under its OWN dispatch_capability; a *reactive* trigger (delivery-driven)
// MUST NOT be required to hold advance-cap on the continuation path, while a
// bare *administrative* invoke stays path-cap-gated.
//
// Both cases share the exact same setup — a standing continuation whose caller
// capability does NOT cover its own path (the cross-peer situation: the trigger
// holds only a narrow dispatch cap scoped elsewhere). The ONLY difference is
// hctx.ReactiveTrigger, the O1 signal set by the delivery mechanism
// (WithReactiveTrigger). That single bit selects the gate.
func TestAdvanceAuthoritySplit_ReactiveVsAdministrative(t *testing.T) {
	const contPath = "system/inbox/standing-cb"

	// A caller capability scoped to an UNRELATED path — it does not cover
	// `advance` on contPath, so CheckPathCapability denies. This mirrors the
	// cross-peer case where the trigger's cap is a narrow dispatch cap that
	// does not grant advance rights over the target's own continuation.
	denyingCallerGrants := []types.GrantEntry{{
		Handlers:   types.CapabilityScope{Include: []string{"system/continuation"}},
		Resources:  types.CapabilityScope{Include: []string{"system/somewhere-else/*"}},
		Operations: types.CapabilityScope{Include: []string{"*"}},
	}}

	// setup builds a fresh context with the standing continuation installed and
	// a stubbed Execute that records whether the onward dispatch was reached.
	setup := func(t *testing.T, reactive bool) (*Handler, *handler.Request, *bool) {
		t.Helper()
		h := NewHandler()
		hctx := newTestContext()
		hctx.LocalPeerID = "peerB"

		hctx.CallerCapability = mustCapEntity(t, hctx.Store, denyingCallerGrants)
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

	t.Run("administrative invoke stays path-cap-gated (403)", func(t *testing.T) {
		h, req, dispatched := setup(t, false)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 403 {
			t.Fatalf("administrative advance with a non-covering caller cap must 403; got %d", resp.Status)
		}
		if code := errCode(resp); code != "capability_denied" {
			t.Fatalf("expected code capability_denied, got %q", code)
		}
		if *dispatched {
			t.Fatal("administrative advance must be denied BEFORE the onward dispatch")
		}
	})

	t.Run("reactive trigger advances under own authority (no path cap)", func(t *testing.T) {
		h, req, dispatched := setup(t, true)
		resp, err := h.Handle(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 {
			t.Fatalf("reactive advance must NOT be gated on the caller's path cap; got %d (code=%q)", resp.Status, errCode(resp))
		}
		if !*dispatched {
			t.Fatal("reactive advance must reach the onward dispatch under the continuation's own dispatch_capability")
		}
		if adv := advancedFlag(resp); adv != true {
			t.Fatalf("expected advanced=true, got %v", adv)
		}
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
