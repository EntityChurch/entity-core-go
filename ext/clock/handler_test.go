package clock

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func newTestContext() *handler.HandlerContext {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	return &handler.HandlerContext{
		Store:          cs,
		LocationIndex:  li,
		HandlerPattern: "system/clock",
	}
}

func TestNowWallMode(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	before := uint64(time.Now().UnixMilli())
	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "now",
		Context:   hctx,
	})
	after := uint64(time.Now().UnixMilli())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}
	if resp.Result.Type != types.TypeClockState {
		t.Fatalf("expected type %s, got %s", types.TypeClockState, resp.Result.Type)
	}

	state, err := types.ClockStateDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("failed to decode state: %v", err)
	}
	if state.Mode != "wall" {
		t.Fatalf("expected mode 'wall', got %q", state.Mode)
	}
	if state.Timestamp == nil {
		t.Fatal("expected timestamp in wall mode")
	}
	if state.Timestamp.Ms < before || state.Timestamp.Ms > after {
		t.Fatalf("timestamp %d not in range [%d, %d]", state.Timestamp.Ms, before, after)
	}
	if state.Logical != nil {
		t.Fatal("logical clock should be nil in wall mode")
	}
}

func TestNowLogicalMode(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Set config to logical mode.
	configData := types.ClockConfigData{Mode: "logical"}
	storeEntity(t, hctx, "system/clock/config", types.TypeClockConfig, configData)

	// Store a logical clock value.
	logicalData := types.ClockLogicalData{Counter: 42}
	storeEntity(t, hctx, "system/clock/logical", types.TypeClockLogical, logicalData)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "now",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := types.ClockStateDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("failed to decode state: %v", err)
	}
	if state.Mode != "logical" {
		t.Fatalf("expected mode 'logical', got %q", state.Mode)
	}
	if state.Timestamp == nil {
		t.Fatal("expected timestamp (wall_clock defaults to true)")
	}
	if state.Logical == nil {
		t.Fatal("expected logical clock")
	}
	if state.Logical.Counter != 42 {
		t.Fatalf("expected counter 42, got %d", state.Logical.Counter)
	}
}

func TestNowVectorMode(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	configData := types.ClockConfigData{Mode: "vector"}
	storeEntity(t, hctx, "system/clock/config", types.TypeClockConfig, configData)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "now",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := types.ClockStateDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("failed to decode state: %v", err)
	}
	if state.Mode != "vector" {
		t.Fatalf("expected mode 'vector', got %q", state.Mode)
	}
	if state.Logical == nil {
		t.Fatal("expected logical clock in vector mode")
	}
	if state.Vector == nil {
		t.Fatal("expected vector clock")
	}
}

func TestNowHLCMode(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	configData := types.ClockConfigData{Mode: "hlc"}
	storeEntity(t, hctx, "system/clock/config", types.TypeClockConfig, configData)

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "now",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := types.ClockStateDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("failed to decode state: %v", err)
	}
	if state.Mode != "hlc" {
		t.Fatalf("expected mode 'hlc', got %q", state.Mode)
	}
	if state.Logical == nil {
		t.Fatal("expected logical clock in hlc mode")
	}
	if state.HLC == nil {
		t.Fatal("expected HLC clock")
	}
	if state.HLC.Physical == 0 {
		t.Fatal("expected non-zero HLC physical")
	}
}

func TestCompareTimestamps(t *testing.T) {
	tests := []struct {
		name string
		a, b types.ClockTimestampData
		want string
	}{
		{"before", types.ClockTimestampData{Ms: 1000}, types.ClockTimestampData{Ms: 2000}, "before"},
		{"after", types.ClockTimestampData{Ms: 2000}, types.ClockTimestampData{Ms: 1000}, "after"},
		{"equal", types.ClockTimestampData{Ms: 1000}, types.ClockTimestampData{Ms: 1000}, "equal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareTimestamps(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCompareLogical(t *testing.T) {
	tests := []struct {
		name string
		a, b types.ClockLogicalData
		want string
	}{
		{"before", types.ClockLogicalData{Counter: 1}, types.ClockLogicalData{Counter: 2}, "before"},
		{"after", types.ClockLogicalData{Counter: 5}, types.ClockLogicalData{Counter: 3}, "after"},
		{"equal", types.ClockLogicalData{Counter: 7}, types.ClockLogicalData{Counter: 7}, "equal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareLogical(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCompareVector(t *testing.T) {
	tests := []struct {
		name string
		a, b types.ClockVectorData
		want string
	}{
		{
			"before",
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 2, "B": 3}},
			"before",
		},
		{
			"after",
			types.ClockVectorData{Entries: map[string]uint64{"A": 3, "B": 4}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			"after",
		},
		{
			"equal",
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			"equal",
		},
		{
			"concurrent",
			types.ClockVectorData{Entries: map[string]uint64{"A": 2, "B": 1}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			"concurrent",
		},
		{
			"missing_entry_before",
			types.ClockVectorData{Entries: map[string]uint64{"A": 1}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
			"before",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVector(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCompareHLC(t *testing.T) {
	peerA := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	peerB := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x02})}

	tests := []struct {
		name string
		a, b types.ClockHLCData
		want string
	}{
		{"physical_before", types.ClockHLCData{Physical: 1000}, types.ClockHLCData{Physical: 2000}, "before"},
		{"physical_after", types.ClockHLCData{Physical: 2000}, types.ClockHLCData{Physical: 1000}, "after"},
		{"logical_before", types.ClockHLCData{Physical: 1000, Logical: 1}, types.ClockHLCData{Physical: 1000, Logical: 2}, "before"},
		{"logical_after", types.ClockHLCData{Physical: 1000, Logical: 3}, types.ClockHLCData{Physical: 1000, Logical: 1}, "after"},
		{"peer_tiebreak", types.ClockHLCData{Physical: 1000, Logical: 1, Peer: peerA}, types.ClockHLCData{Physical: 1000, Logical: 1, Peer: peerB}, "before"},
		{"equal", types.ClockHLCData{Physical: 1000, Logical: 1, Peer: peerA}, types.ClockHLCData{Physical: 1000, Logical: 1, Peer: peerA}, "equal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareHLC(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestCompareOperation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	// Compare two timestamps via the handler.
	aRaw, _ := ecf.Encode(types.ClockTimestampData{Ms: 1000})
	bRaw, _ := ecf.Encode(types.ClockTimestampData{Ms: 2000})
	params := types.ClockCompareParamsData{
		A: cbor.RawMessage(aRaw),
		B: cbor.RawMessage(bRaw),
	}
	paramsRaw, _ := ecf.Encode(params)
	paramsEnt, _ := entity.NewEntity(types.TypeClockCompareParams, cbor.RawMessage(paramsRaw))

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "compare",
		Params:    paramsEnt,
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected status 200, got %d", resp.Status)
	}

	var result types.ClockCompareResultData
	if err := ecf.Decode(resp.Result.Data, &result); err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}
	if result.Order != "before" {
		t.Fatalf("expected 'before', got %q", result.Order)
	}
}

func TestCompareOperationAllTypes(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	doCompare := func(t *testing.T, a, b interface{}) string {
		t.Helper()
		aRaw, _ := ecf.Encode(a)
		bRaw, _ := ecf.Encode(b)
		params := types.ClockCompareParamsData{
			A: cbor.RawMessage(aRaw),
			B: cbor.RawMessage(bRaw),
		}
		paramsRaw, _ := ecf.Encode(params)
		paramsEnt, _ := entity.NewEntity(types.TypeClockCompareParams, cbor.RawMessage(paramsRaw))
		resp, err := h.Handle(context.Background(), &handler.Request{
			Operation: "compare",
			Params:    paramsEnt,
			Context:   hctx,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status != 200 {
			t.Fatalf("expected status 200, got %d", resp.Status)
		}
		var result types.ClockCompareResultData
		if err := ecf.Decode(resp.Result.Data, &result); err != nil {
			t.Fatalf("failed to decode result: %v", err)
		}
		return result.Order
	}

	t.Run("logical", func(t *testing.T) {
		order := doCompare(t,
			types.ClockLogicalData{Counter: 5},
			types.ClockLogicalData{Counter: 10},
		)
		if order != "before" {
			t.Fatalf("expected 'before', got %q", order)
		}
	})

	t.Run("vector_concurrent", func(t *testing.T) {
		order := doCompare(t,
			types.ClockVectorData{Entries: map[string]uint64{"A": 2, "B": 1}},
			types.ClockVectorData{Entries: map[string]uint64{"A": 1, "B": 2}},
		)
		if order != "concurrent" {
			t.Fatalf("expected 'concurrent', got %q", order)
		}
	})

	t.Run("hlc", func(t *testing.T) {
		order := doCompare(t,
			types.ClockHLCData{Physical: 2000, Logical: 0},
			types.ClockHLCData{Physical: 1000, Logical: 5},
		)
		if order != "after" {
			t.Fatalf("expected 'after', got %q", order)
		}
	})
}

func TestHLCLocalEvent(t *testing.T) {
	peer := hash.Hash{Digest: hash.ExtendDigest([32]byte{0xAA})}

	// Initial HLC — physical should advance to wall clock.
	current := types.ClockHLCData{Physical: 0, Logical: 0, Peer: peer}
	result := hlcLocalEvent(current, peer)

	if result.Physical == 0 {
		t.Fatal("expected non-zero physical")
	}
	if result.Logical != 0 {
		t.Fatalf("expected logical 0 (physical advanced), got %d", result.Logical)
	}

	// Same physical — logical should increment.
	result2 := hlcLocalEvent(result, peer)
	if result2.Physical != result.Physical {
		// Could happen if wall clock advanced between calls, which is fine.
		if result2.Logical != 0 {
			t.Fatalf("physical advanced but logical not reset: %d", result2.Logical)
		}
	} else {
		if result2.Logical != result.Logical+1 {
			t.Fatalf("expected logical %d, got %d", result.Logical+1, result2.Logical)
		}
	}
}

func TestAdvancementLogical(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	configData := types.ClockConfigData{Mode: "logical"}
	raw, _ := ecf.Encode(configData)
	ent, _ := entity.NewEntity(types.TypeClockConfig, cbor.RawMessage(raw))
	ch, _ := cs.Put(ent)
	li.Set("system/clock/config", ch)

	h := NewHandler()
	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	peerHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h.SetupAdvancement(cs, li, testPeerID, peerHash, nil)

	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/user/data/foo", ChangeType: store.ChangeCreated})
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/user/data/bar", ChangeType: store.ChangeModified})
	// Clock path — should be skipped.
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/system/clock/logical", ChangeType: store.ChangeModified})

	lh, ok := li.Get("system/clock/logical")
	if !ok {
		t.Fatal("expected logical clock in tree")
	}
	logEnt, ok := cs.Get(lh)
	if !ok {
		t.Fatal("expected logical clock entity in store")
	}
	logData, err := types.ClockLogicalDataFromEntity(logEnt)
	if err != nil {
		t.Fatalf("failed to decode logical: %v", err)
	}
	if logData.Counter != 2 {
		t.Fatalf("expected counter 2, got %d", logData.Counter)
	}
}

func TestAdvancementVector(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	configData := types.ClockConfigData{Mode: "vector"}
	raw, _ := ecf.Encode(configData)
	ent, _ := entity.NewEntity(types.TypeClockConfig, cbor.RawMessage(raw))
	ch, _ := cs.Put(ent)
	li.Set("system/clock/config", ch)

	h := NewHandler()
	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	peerHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h.SetupAdvancement(cs, li, testPeerID, peerHash, nil)

	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/user/data/foo", ChangeType: store.ChangeCreated})

	// Check logical clock.
	lh, ok := li.Get("system/clock/logical")
	if !ok {
		t.Fatal("expected logical clock")
	}
	logEnt, ok := cs.Get(lh)
	if !ok {
		t.Fatal("expected logical entity")
	}
	logData, _ := types.ClockLogicalDataFromEntity(logEnt)
	if logData.Counter != 1 {
		t.Fatalf("expected logical counter 1, got %d", logData.Counter)
	}

	// Check vector clock.
	vh, ok := li.Get("system/clock/vector")
	if !ok {
		t.Fatal("expected vector clock")
	}
	vecEnt, ok := cs.Get(vh)
	if !ok {
		t.Fatal("expected vector entity")
	}
	vecData, _ := types.ClockVectorDataFromEntity(vecEnt)
	if vecData.Entries == nil {
		t.Fatal("expected non-nil entries")
	}
	if vecData.Entries[testPeerID] != 1 {
		t.Fatalf("expected vector entry for %s = 1, got %d", testPeerID, vecData.Entries[testPeerID])
	}
}

func TestAdvancementSkipsClockEnginePaths(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	configData := types.ClockConfigData{Mode: "logical"}
	raw, _ := ecf.Encode(configData)
	ent, _ := entity.NewEntity(types.TypeClockConfig, cbor.RawMessage(raw))
	ch, _ := cs.Put(ent)
	li.Set("system/clock/config", ch)

	h := NewHandler()
	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	peerHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h.SetupAdvancement(cs, li, testPeerID, peerHash, nil)

	// Engine state paths are guarded — should NOT advance the clock.
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/system/clock/logical", ChangeType: store.ChangeModified})
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/system/clock/vector", ChangeType: store.ChangeModified})
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/system/clock/hlc", ChangeType: store.ChangeModified})

	// No advancement should have happened from engine path events.
	lh, ok := li.Get("system/clock/logical")
	if ok {
		if logEnt, ok := cs.Get(lh); ok {
			logData, _ := types.ClockLogicalDataFromEntity(logEnt)
			if logData.Counter != 0 {
				t.Fatalf("expected counter 0 (engine paths should not advance), got %d", logData.Counter)
			}
		}
	}

	// Config path changes SHOULD advance the clock (G-1, SYSTEM-COMPOSITION §6.1).
	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/system/clock/config", ChangeType: store.ChangeModified})

	lh, ok = li.Get("system/clock/logical")
	if !ok {
		t.Fatal("expected logical clock to exist after config change")
	}
	logEnt, ok := cs.Get(lh)
	if !ok {
		t.Fatal("expected logical clock entity in store")
	}
	logData, _ := types.ClockLogicalDataFromEntity(logEnt)
	if logData.Counter != 1 {
		t.Fatalf("expected counter 1 (config change should advance), got %d", logData.Counter)
	}
}

func TestAdvancementIncludesDeletes(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	configData := types.ClockConfigData{Mode: "logical"}
	raw, _ := ecf.Encode(configData)
	ent, _ := entity.NewEntity(types.TypeClockConfig, cbor.RawMessage(raw))
	ch, _ := cs.Put(ent)
	li.Set("system/clock/config", ch)

	h := NewHandler()
	const testPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	peerHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h.SetupAdvancement(cs, li, testPeerID, peerHash, nil)

	h.OnTreeChange(store.TreeChangeEvent{Path: "/" + testPeerID + "/user/data/foo", ChangeType: store.ChangeDeleted})

	lh, ok := li.Get("system/clock/logical")
	if !ok {
		t.Fatal("expected logical clock entity after delete event")
	}
	logEnt, ok := cs.Get(lh)
	if !ok {
		t.Fatal("expected logical clock entity in store")
	}
	logData, _ := types.ClockLogicalDataFromEntity(logEnt)
	if logData.Counter != 1 {
		t.Fatalf("expected counter 1 after delete, got %d", logData.Counter)
	}
}

func TestAdvancementIncludesRemotePeerEvents(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	configData := types.ClockConfigData{Mode: "logical"}
	raw, _ := ecf.Encode(configData)
	ent, _ := entity.NewEntity(types.TypeClockConfig, cbor.RawMessage(raw))
	ch, _ := cs.Put(ent)
	li.Set("system/clock/config", ch)

	h := NewHandler()
	const localPeerID = "TestPeer1234567890abcdefghijklmnopqrstuvwxyz01"
	const remotePeerID = "RemotePeer234567890abcdefghijklmnopqrstuvwxy02"
	peerHash := hash.Hash{Digest: hash.ExtendDigest([32]byte{0x01})}
	h.SetupAdvancement(cs, li, localPeerID, peerHash, nil)

	h.OnTreeChange(store.TreeChangeEvent{Path: localPeerID + "/user/data/foo", ChangeType: store.ChangeCreated})
	h.OnTreeChange(store.TreeChangeEvent{Path: remotePeerID + "/user/data/baz", ChangeType: store.ChangeCreated})
	h.OnTreeChange(store.TreeChangeEvent{Path: localPeerID + "/user/data/bar", ChangeType: store.ChangeCreated})

	lh, ok := li.Get("system/clock/logical")
	if !ok {
		t.Fatal("expected logical clock in tree")
	}
	logEnt, ok := cs.Get(lh)
	if !ok {
		t.Fatal("expected logical clock entity in store")
	}
	logData, err := types.ClockLogicalDataFromEntity(logEnt)
	if err != nil {
		t.Fatalf("failed to decode logical: %v", err)
	}
	// All three events (local + remote + local) should advance counter to 3.
	if logData.Counter != 3 {
		t.Fatalf("expected counter 3 (all events including remote advance clock), got %d", logData.Counter)
	}
}

func TestUnknownOperation(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "unknown",
		Context:   hctx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != 400 {
		t.Fatalf("expected status 400, got %d", resp.Status)
	}
}

func TestManifest(t *testing.T) {
	h := NewHandler()
	m := h.Manifest()

	if m.Pattern != "system/clock" {
		t.Fatalf("expected pattern 'system/clock', got %q", m.Pattern)
	}
	if m.Name != "clock" {
		t.Fatalf("expected name 'clock', got %q", m.Name)
	}
	ops := m.Operations
	for _, op := range []string{"now", "compare", "tick"} {
		if _, ok := ops[op]; !ok {
			t.Fatalf("expected operation %q in manifest", op)
		}
	}
}

func TestPruneVectorEntries(t *testing.T) {
	entries := make(map[string]uint64)
	for i := 0; i < types.MaxVectorEntries+5; i++ {
		entries[string(rune('A'+i))] = uint64(i)
	}
	pruneVectorEntries(entries)
	if len(entries) > types.MaxVectorEntries {
		t.Fatalf("expected at most %d entries, got %d", types.MaxVectorEntries, len(entries))
	}
}

// --- Test helpers ---

func storeEntity(t *testing.T, hctx *handler.HandlerContext, path, typeName string, data interface{}) {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatalf("encode %s: %v", typeName, err)
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("create entity %s: %v", typeName, err)
	}
	h, err := hctx.Store.Put(ent)
	if err != nil {
		t.Fatalf("store %s: %v", typeName, err)
	}
	hctx.LocationIndex.Set(path, h)
}
