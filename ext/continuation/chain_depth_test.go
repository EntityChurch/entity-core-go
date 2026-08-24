package continuation

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-CONTINUATION §3.9: "The counter is incremented on each continuation
// advancement dispatch." The advance is the only site in the tree that
// increments; the dispatch layer owns the ceiling (core/protocol).
//
// This is the half of §3.9 that lives here, and it is load-bearing for the
// step-6 fresh-TTL change (arch ruling 15): once advancement dispatches refill
// ttl every hop, this counter is the ONLY structural brake on a chain that
// dispatches back into its own trigger. If the increment silently stops
// happening, nothing else fails — the loop just stops terminating.
func TestAdvanceDispatchIncrementsChainDepth(t *testing.T) {
	for _, callerDepth := range []uint64{0, 1, 7, 63} {
		h := NewHandler()
		hctx := newTestContext()
		hctx.RequestID = "req-1"
		hctx.ChainDepth = callerDepth

		var gotDepth *uint64
		hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
			gotDepth = handler.ApplyOpts(opts).ChainDepth
			ok, _ := types.ErrorData{Code: "ok"}.ToEntity()
			return &handler.Response{Status: 200, Result: ok}, nil
		}

		remaining := uint64(1)
		capHash := testCapHash(t, hctx.Store)
		storeContinuation(t, hctx, "system/inbox/fwd", types.ContinuationData{
			Target:              "system/tree",
			Operation:           "put",
			RemainingExecutions: &remaining,
			DispatchCapability:  capHash,
		})

		if _, err := h.Handle(context.Background(),
			makeAdvanceRequest(t, hctx, "system/inbox/fwd", 200, "payload")); err != nil {
			t.Fatalf("caller depth %d: advance returned an error: %v", callerDepth, err)
		}

		if gotDepth == nil {
			t.Fatalf("caller depth %d: advancement dispatched with NO chain depth — §3.9's counter is not threaded, so a self-referential chain has no brake",
				callerDepth)
		}
		if *gotDepth != callerDepth+1 {
			t.Errorf("caller depth %d: dispatched at depth %d, want %d (advancement increments by exactly one)",
				callerDepth, *gotDepth, callerDepth+1)
		}
	}
}
