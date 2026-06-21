package revision

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
)

// TestFetchDiff_AllowsCrossPeerDispatch — cross-peer fetch-diff is the
// canonical Form 1 follower pattern (GUIDE-REVISION-AUTO-VERSION §4
// lines 105-108). A blanket "ConnectionState != nil → reject" guard
// (commit a1bb154) was added in error and reverted; this test pins the
// behavior so we don't re-introduce the regression. Cross-peer dispatch
// proceeds; the op returns its normal status (here 404 no_local_state
// because no head is set up).
func TestFetchDiff_AllowsCrossPeerDispatch(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.ConnectionState = struct{}{} // simulate cross-peer arrival

	req := makeRequest(t, hctx, "fetch-diff", types.RevisionFetchDiffParamsData{
		Prefix: "data/",
	})

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status == 400 {
		codeData, _ := types.ErrorDataFromEntity(resp.Result)
		if codeData.Code == "invalid_dispatch" {
			t.Fatalf("blanket cross-peer reject re-introduced — GUIDE-REVISION-AUTO-VERSION §4 Form 1 requires cross-peer fetch-diff")
		}
	}
}

// TestFetchDiff_AllowsLocalDispatch — local dispatch also proceeds.
// Documents that both calling patterns work (receiver-local query +
// follower-pattern cross-peer); the handler reads the executing peer's
// head in both cases.
func TestFetchDiff_AllowsLocalDispatch(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	// ConnectionState is nil — local dispatch.

	req := makeRequest(t, hctx, "fetch-diff", types.RevisionFetchDiffParamsData{
		Prefix: "data/",
	})

	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Expect 404 no_local_state (no head was set up). Just confirm the
	// handler didn't bail with 400 invalid_dispatch.
	if resp.Status == 400 {
		codeData, _ := types.ErrorDataFromEntity(resp.Result)
		if codeData.Code == "invalid_dispatch" {
			t.Fatalf("local dispatch rejected with invalid_dispatch — handler should accept both local and cross-peer")
		}
	}
}
