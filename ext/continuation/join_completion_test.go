package continuation

// PROPOSAL-CONTINUATION-STANDING-MODEL §4 (Facet B) — join completion policy.
//
// §6's directional anchors 3 and 4 are the two that matter here, and both are
// written against the PUBLIC advance path rather than the internals, because
// the thing being claimed is peer behavior:
//
//	anchor 3 — a standing join with completion_deadline_ms/abandon missing one
//	  slot emits a lost marker, resets, and fires clean on the NEXT round.
//	anchor 4 — a delivered-error slot makes the round observably failed rather
//	  than folding an error payload into a boundary entity.
//
// The clock is driven by backdating RoundStartedMs on the stored join rather
// than by sleeping or injecting a fake clock: the deadline arithmetic lives in
// types.ContinuationJoinData.IncompleteRound and takes nowMs explicitly, so a
// backdated round start is the same input a slow round produces, without
// putting a second of wall time in the suite.

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// backdateJoinRound rewrites the stored join's round start to agoMs in the
// past, simulating a round that has been open that long.
func backdateJoinRound(t *testing.T, hctx *handler.HandlerContext, joinPath string, agoMs uint64) {
	t.Helper()
	ent, typ := readEntity(hctx, joinPath)
	if typ != types.TypeContinuationJoin {
		t.Fatalf("backdate: no join at %s (got type %q)", joinPath, typ)
	}
	join, err := types.ContinuationJoinDataFromEntity(ent)
	if err != nil {
		t.Fatalf("backdate: decode join: %v", err)
	}
	if join.RoundStartedMs == nil {
		t.Fatalf("backdate: round not armed at %s — the first slot should have armed it", joinPath)
	}
	started := uint64(time.Now().UnixMilli()) - agoMs
	join.RoundStartedMs = &started
	storeJoin(t, hctx, joinPath, join)
}

// loadJoin reads the join entity back out of the tree.
func loadJoin(t *testing.T, hctx *handler.HandlerContext, joinPath string) types.ContinuationJoinData {
	t.Helper()
	ent, typ := readEntity(hctx, joinPath)
	if typ != types.TypeContinuationJoin {
		t.Fatalf("no join at %s (got type %q)", joinPath, typ)
	}
	join, err := types.ContinuationJoinDataFromEntity(ent)
	if err != nil {
		t.Fatalf("decode join: %v", err)
	}
	return join
}

// lostMarkers decodes every lost marker currently bound.
func lostMarkers(hctx *handler.HandlerContext) []types.ChainErrorLostData {
	var markers []types.ChainErrorLostData
	for _, entry := range hctx.LocationIndex.List("system/runtime/chain-errors/lost/") {
		ent, ok := hctx.Store.Get(entry.Hash)
		if !ok || ent.Type != types.TypeChainErrorLost {
			continue
		}
		var d types.ChainErrorLostData
		if err := ecf.Decode(ent.Data, &d); err != nil {
			continue
		}
		markers = append(markers, d)
	}
	return markers
}

func lostMarkerReasons(hctx *handler.HandlerContext) []string {
	var reasons []string
	for _, m := range lostMarkers(hctx) {
		reasons = append(reasons, m.Reason)
	}
	return reasons
}

// requireMarker returns the single marker carrying `reason`, failing if there
// is not exactly one — §4's requirement is a marker FOR THE ROUND, so a
// duplicate per slot would be its own defect.
func requireMarker(t *testing.T, hctx *handler.HandlerContext, reason string) types.ChainErrorLostData {
	t.Helper()
	var found []types.ChainErrorLostData
	for _, m := range lostMarkers(hctx) {
		if m.Reason == reason {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 %q marker, got %d (all reasons: %v)", reason, len(found), lostMarkerReasons(hctx))
	}
	return found[0]
}

func sameSlots(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestJoinWithoutDeadlineWaitsForever pins the no-silent-change guarantee:
// absent completion_deadline_ms, a join behaves exactly as it did before §4 —
// it accumulates and waits, no round clock, no marker, no reset.
func TestJoinWithoutDeadlineWaitsForever(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		t.Fatal("must not dispatch: the round is one slot short")
		return nil, nil
	}

	capHash := testCapHash(t, hctx.Store)
	storeJoin(t, hctx, "system/inbox/join-forever", types.ContinuationJoinData{
		Expected:           []string{"a", "b"},
		Target:             "system/tree",
		Operation:          "put",
		DispatchCapability: capHash,
		// no CompletionDeadlineMs — wait forever
	})

	req := makeAdvanceRequest(t, hctx, "system/inbox/join-forever/a", 200, "v")
	if _, err := h.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	join := loadJoin(t, hctx, "system/inbox/join-forever")
	if join.RoundStartedMs != nil {
		t.Error("a deadline-less join armed a round clock — the clock must only exist where a deadline can consume it")
	}
	if len(join.Received) != 1 {
		t.Fatalf("expected the slot to accumulate, got received=%v", join.Received)
	}
	if reasons := lostMarkerReasons(hctx); len(reasons) != 0 {
		t.Errorf("a wait-forever join bound markers %v — §4 is opt-in and must not fire without a deadline", reasons)
	}
}

// TestStandingJoinSelfHealsAfterDeadline is §6 anchor 3: a standing join whose
// round blew its deadline one slot short abandons that round with a lost marker
// and then fires CLEAN on the next one. Before §4 the join wedged here
// permanently — it was one slot short forever and could never fire again.
func TestStandingJoinSelfHealsAfterDeadline(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var dispatched []map[string]interface{}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		var decoded map[string]interface{}
		_ = ecf.Decode(params.Data, &decoded)
		dispatched = append(dispatched, decoded)
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	deadline := uint64(50)
	capHash := testCapHash(t, hctx.Store)
	const joinPath = "system/inbox/join-heal"
	storeJoin(t, hctx, joinPath, types.ContinuationJoinData{
		Expected:             []string{"a", "b"},
		Target:               "system/tree",
		Operation:            "put",
		DispatchCapability:   capHash,
		CompletionDeadlineMs: &deadline,
		OnIncomplete:         types.JoinOnIncompleteAbandon,
		// nil RemainingExecutions = standing
	})

	// Round 1: slot "a" arrives, "b" never does.
	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/a", 200, "round1-a")); err != nil {
		t.Fatal(err)
	}
	if len(dispatched) != 0 {
		t.Fatalf("dispatched on an incomplete round: %v", dispatched)
	}
	backdateJoinRound(t, hctx, joinPath, 5_000) // the round has been open 5s against a 50ms budget

	// Round 2 opens: slot "a" arrives again. The dead round must be reaped
	// first, or this slot lands in it and the join stays wedged.
	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/a", 200, "round2-a")); err != nil {
		t.Fatal(err)
	}
	// §4: "emit a lost marker NAMING the missing slots". A marker that records
	// only that a round failed has lost the observation's entire content.
	marker := requireMarker(t, hctx, types.ChainErrorReasonJoinIncomplete)
	if !sameSlots(marker.JoinSlots, []string{"b"}) {
		t.Errorf("marker named slots %v, want [b] — the abandoned round was short exactly b", marker.JoinSlots)
	}
	if marker.JoinPath != joinPath {
		t.Errorf("marker join_path = %q, want %q", marker.JoinPath, joinPath)
	}
	join := loadJoin(t, hctx, joinPath)
	if _, stale := join.Received["b"]; stale {
		t.Error("slot b survived the abandon — the round did not reset")
	}
	if got := len(join.Received); got != 1 {
		t.Fatalf("expected the fresh round to hold exactly the new slot a, got received=%v", join.Received)
	}

	// Round 2 completes: it must fire, and fire with ROUND 2's values only.
	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/b", 200, "round2-b")); err != nil {
		t.Fatal(err)
	}
	if len(dispatched) != 1 {
		t.Fatalf("the next round did not fire clean: %d dispatches", len(dispatched))
	}
	if got := dispatched[0]["a"]; got != "round2-a" {
		t.Errorf("round 2 fired with slot a = %v, want round2-a — a stale slot leaked across the abandon", got)
	}
	if _, leaked := dispatched[0][types.JoinIncompleteField]; leaked {
		t.Error("a COMPLETE round carried an incomplete marker — the success path must be untouched")
	}
}

// TestJoinFirePartialDispatchesWithIncompleteMarker covers the opt-in policy:
// at the deadline the target fires with the partial received plus an explicit
// marker naming what is missing. Never the default — a stitch assuming k
// fragments has to ask for this.
func TestJoinFirePartialDispatchesWithIncompleteMarker(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var dispatched []map[string]interface{}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		var decoded map[string]interface{}
		_ = ecf.Decode(params.Data, &decoded)
		dispatched = append(dispatched, decoded)
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	deadline := uint64(50)
	capHash := testCapHash(t, hctx.Store)
	const joinPath = "system/inbox/join-partial"
	storeJoin(t, hctx, joinPath, types.ContinuationJoinData{
		Expected:             []string{"a", "b", "c"},
		Target:               "system/tree",
		Operation:            "put",
		DispatchCapability:   capHash,
		CompletionDeadlineMs: &deadline,
		OnIncomplete:         types.JoinOnIncompleteFirePartial,
	})

	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/a", 200, "va")); err != nil {
		t.Fatal(err)
	}
	backdateJoinRound(t, hctx, joinPath, 5_000)

	// Any subsequent touch reaps the expired round — here, slot "b" of the next.
	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/b", 200, "vb")); err != nil {
		t.Fatal(err)
	}

	if len(dispatched) != 1 {
		t.Fatalf("fire-partial did not dispatch at the deadline: %d dispatches", len(dispatched))
	}
	// CBOR maps decode as map[interface{}]interface{}; normalizeToStringMap is
	// the same helper the merge path uses.
	marker, ok := normalizeToStringMap(dispatched[0][types.JoinIncompleteField])
	if !ok {
		t.Fatalf("fire-partial dispatched without an %q marker: %v", types.JoinIncompleteField, dispatched[0])
	}
	missing, _ := marker["missing"].([]interface{})
	if len(missing) != 2 || missing[0] != "b" || missing[1] != "c" {
		t.Errorf("incomplete marker missing = %v, want [b c] in expected order", missing)
	}
	if got := dispatched[0]["a"]; got != "va" {
		t.Errorf("fire-partial dropped the slot it DID have: a = %v", got)
	}
}

// TestJoinErrorSlotIsPreservedAndMarked is §6 anchor 4 (mechanism 1). A
// delivered non-2xx FILLS its slot, so the barrier completes and the failure
// would otherwise vanish into the stitch. Two things must hold: the error
// payload reaches the target UNCOERCED (so a determinism-critical target can
// reject it), and the round is observably failed via a lost marker.
func TestJoinErrorSlotIsPreservedAndMarked(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var dispatched map[string]interface{}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		_ = ecf.Decode(params.Data, &dispatched)
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	capHash := testCapHash(t, hctx.Store)
	const joinPath = "system/inbox/join-errslot"
	storeJoin(t, hctx, joinPath, types.ContinuationJoinData{
		Expected:           []string{"good", "bad"},
		Target:             "system/tree",
		Operation:          "put",
		DispatchCapability: capHash,
	})

	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/good", 200, "clean-value")); err != nil {
		t.Fatal(err)
	}
	// The failing slot arrives with a non-2xx status and an error-shaped payload.
	errPayload := map[string]interface{}{"code": "compute_failed", "message": "shard 2 died"}
	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/bad", 500, errPayload)); err != nil {
		t.Fatal(err)
	}

	if dispatched == nil {
		t.Fatal("the barrier did not fire — a delivered error still fills its slot")
	}
	// Passed through as-is, not coerced into boundary bytes.
	bad, ok := normalizeToStringMap(dispatched["bad"])
	if !ok {
		t.Fatalf("error slot was coerced on the way to the target: %#v", dispatched["bad"])
	}
	if bad["code"] != "compute_failed" {
		t.Errorf("error payload lost its shape: %v", bad)
	}
	if got := dispatched["good"]; got != "clean-value" {
		t.Errorf("clean slot was disturbed by its errored sibling: %v", got)
	}
	marker := requireMarker(t, hctx, types.ChainErrorReasonJoinErrorSlot)
	if !sameSlots(marker.JoinSlots, []string{"bad"}) {
		t.Errorf("marker named slots %v, want [bad] — the round is only observably failed if it says WHICH slot errored", marker.JoinSlots)
	}
}

// TestJoinCleanRoundCarriesNoFailureState is the determinism guard: a complete,
// all-good round must assemble exactly the slot values — no round clock, no
// status map, no marker field — so its boundary bytes are identical to the
// serial case and to what this join produced before §4 existed.
func TestJoinCleanRoundCarriesNoFailureState(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	var dispatched map[string]interface{}
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		_ = ecf.Decode(params.Data, &dispatched)
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	deadline := uint64(60_000)
	capHash := testCapHash(t, hctx.Store)
	const joinPath = "system/inbox/join-clean"
	storeJoin(t, hctx, joinPath, types.ContinuationJoinData{
		Expected:             []string{"a", "b"},
		Target:               "system/tree",
		Operation:            "put",
		DispatchCapability:   capHash,
		CompletionDeadlineMs: &deadline,
	})

	for slot, val := range map[string]string{"a": "va", "b": "vb"} {
		if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/"+slot, 200, val)); err != nil {
			t.Fatal(err)
		}
	}

	if len(dispatched) != 2 {
		t.Fatalf("a clean round assembled %d keys, want exactly the 2 slots: %v", len(dispatched), dispatched)
	}
	join := loadJoin(t, hctx, joinPath)
	if join.RoundStartedMs != nil || join.ReceivedStatus != nil || len(join.Received) != 0 {
		t.Errorf("post-fire reset left state behind: round=%v status=%v received=%v — the next round would inherit this round's deadline",
			join.RoundStartedMs, join.ReceivedStatus, join.Received)
	}
	if reasons := lostMarkerReasons(hctx); len(reasons) != 0 {
		t.Errorf("a clean round bound markers %v", reasons)
	}
}

// TestJoinRoundClockArmsOnFirstSlotNotInstall pins the arming choice: a join
// holding zero slots has not started a round, so an idle standing join cannot
// accumulate a deadline it never opened (and cannot emit a marker per deadline
// forever).
func TestJoinRoundClockArmsOnFirstSlotNotInstall(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		resultRaw, _ := ecf.Encode(map[string]interface{}{"ok": true})
		resultEntity, _ := entity.NewEntity("primitive/any", cbor.RawMessage(resultRaw))
		return &handler.Response{Status: 200, Result: resultEntity}, nil
	}

	deadline := uint64(1)
	capHash := testCapHash(t, hctx.Store)
	const joinPath = "system/inbox/join-idle"
	storeJoin(t, hctx, joinPath, types.ContinuationJoinData{
		Expected:             []string{"a", "b"},
		Target:               "system/tree",
		Operation:            "put",
		DispatchCapability:   capHash,
		CompletionDeadlineMs: &deadline,
	})

	// Nothing has arrived. An expired-round check must be a no-op.
	if loadJoin(t, hctx, joinPath).IncompleteRound(uint64(time.Now().UnixMilli()) + 1_000_000) {
		t.Fatal("an untouched join reported an incomplete round — an idle standing join would emit a marker per deadline forever")
	}

	if _, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, joinPath+"/a", 200, "v")); err != nil {
		t.Fatal(err)
	}
	if loadJoin(t, hctx, joinPath).RoundStartedMs == nil {
		t.Fatal("the first slot did not arm the round clock — the deadline can never fire")
	}
}

func TestValidOnIncomplete(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", true}, // absent == abandon
		{types.JoinOnIncompleteAbandon, true},
		{types.JoinOnIncompleteFirePartial, true},
		{"fire_partial", false}, // the plausible typo the install gate exists to catch
		{"ABANDON", false},
		{"drop", false},
	} {
		if got := validOnIncomplete(tc.value); got != tc.want {
			t.Errorf("validOnIncomplete(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// --- install-time gates (STANDING-MODEL §4) ---

// makeJoinWithPolicy builds a join entity carrying a completion policy.
func makeJoinWithPolicy(t *testing.T, dispatchCap hash.Hash, onIncomplete string, deadlineMs *uint64) entity.Entity {
	t.Helper()
	ent, err := types.ContinuationJoinData{
		Expected:             []string{"a", "b"},
		Target:               "/peer/system/tree",
		Operation:            "put",
		DispatchCapability:   dispatchCap,
		OnIncomplete:         onIncomplete,
		CompletionDeadlineMs: deadlineMs,
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

// TestInstallJoinCompletionPolicyGates pins the fail-closed install checks. An
// unrecognized policy must not silently become "abandon", and a policy with no
// deadline must not install as an inert setting the operator believes is live —
// both would be discovered only once a round was already short.
func TestInstallJoinCompletionPolicyGates(t *testing.T) {
	deadline := uint64(1000)
	tests := []struct {
		name         string
		onIncomplete string
		deadline     *uint64
		wantStatus   uint
	}{
		{"abandon with deadline", types.JoinOnIncompleteAbandon, &deadline, 200},
		{"fire-partial with deadline", types.JoinOnIncompleteFirePartial, &deadline, 200},
		{"deadline alone defaults to abandon", "", &deadline, 200},
		{"no policy, no deadline (pre-§4 join)", "", nil, 200},
		{"typo'd policy", "fire_partial", &deadline, 400},
		{"unknown policy", "drop", &deadline, 400},
		{"policy without deadline is inert", types.JoinOnIncompleteAbandon, nil, 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t)
			cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)
			join := makeJoinWithPolicy(t, cap.ContentHash, tc.onIncomplete, tc.deadline)
			resp, err := env.h.handleInstall(context.Background(),
				makeInstallRequest(t, env.hctx, "/peer/system/continuation/join-policy", join))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.Status, tc.wantStatus)
			}
		})
	}
}

// TestInstallJoinClearsInheritedRoundState: a fresh install starts a fresh
// round. A caller supplying round_started_ms or received_status in params must
// not be able to install a join that is already mid-round — or, worse, one
// whose round is already expired at birth.
func TestInstallJoinClearsInheritedRoundState(t *testing.T) {
	env := newInstallEnv(t)
	cap := env.makeCap(t, env.writer.ContentHash, env.handler.ContentHash, nil)

	stale := uint64(1)
	deadline := uint64(1000)
	joinEnt, err := types.ContinuationJoinData{
		Expected:             []string{"a", "b"},
		Target:               "/peer/system/tree",
		Operation:            "put",
		DispatchCapability:   cap.ContentHash,
		CompletionDeadlineMs: &deadline,
		RoundStartedMs:       &stale, // epoch+1ms: already long expired
		ReceivedStatus:       map[string]uint{"a": 500},
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	const path = "/peer/system/continuation/join-stale"
	resp, err := env.h.handleInstall(context.Background(), makeInstallRequest(t, env.hctx, path, joinEnt))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	stored := loadJoin(t, env.hctx, path)
	if stored.RoundStartedMs != nil {
		t.Errorf("install carried a round clock in from params (%v) — the join is expired before its first slot", *stored.RoundStartedMs)
	}
	if stored.ReceivedStatus != nil {
		t.Errorf("install carried per-slot statuses in from params: %v", stored.ReceivedStatus)
	}
}
