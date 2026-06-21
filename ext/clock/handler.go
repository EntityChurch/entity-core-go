// Package clock implements the system/clock handler per EXTENSION-CLOCK.md.
//
// The clock extension provides wall-clock timestamps, logical clocks, vector
// clocks, and hybrid logical clocks. It supports three operations:
//   - now:     returns the current clock state
//   - compare: compares two clock values
//   - tick:    creates a subscription for periodic clock events (delegates to subscription handler)
//
// Clock advancement on tree writes is handled by the OnTreeChange sync
// hook (wired via SetupAdvancement), which observes tree change events and
// increments the appropriate clock.
package clock

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const handlerPattern = "system/clock"

// Handler implements the system/clock handler.
type Handler struct {
	mu     sync.Mutex
	logger *log.Logger

	// Set by SetupAdvancement for clock increment on tree writes.
	cs       store.ContentStore
	li       store.LocationIndex
	peerID   string                 // peer ID string (Base58) for vector clock map key
	peerHash hash.Hash              // content hash of local peer's identity entity (HLC peer field)
	bgCtx    *store.MutationContext // background context for advancement writes
}

// NewHandler creates a new clock handler.
func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Name() string { return "clock" }

// Manifest returns the handler's self-description.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "clock",
		Operations: map[string]types.HandlerOperationSpec{
			"now":     {OutputType: types.TypeClockState},
			"compare": {InputType: types.TypeClockCompareParams, OutputType: types.TypeClockCompareResult},
			"tick":    {InputType: types.TypeSubscriptionRequest},
		},
	}
}

// RegisterTypes is a no-op — clock types are registered in RegisterCoreTypes.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "now":
		return h.handleNow(ctx, req)
	case "compare":
		return h.handleCompare(ctx, req)
	case "tick":
		return h.handleTick(ctx, req)
	default:
		resp, _ := handler.NewErrorResponse(400, "unknown_operation",
			"clock handler does not support operation: "+req.Operation)
		return resp, nil
	}
}

// handleNow returns the current clock state (§3.2).
func (h *Handler) handleNow(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	config := loadConfig(hctx.Store, hctx.LocationIndex)
	state := readClockState(config, hctx.Store, hctx.LocationIndex)

	return handler.NewResponse(200, types.TypeClockState, state)
}

// handleCompare compares two clock values (§3.3).
func (h *Handler) handleCompare(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	params, err := types.ClockCompareParamsDataFromEntity(req.Params)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "failed to decode compare params: "+err.Error())
	}

	order, err := compareClocks(params.A, params.B)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "failed to compare clocks: "+err.Error())
	}

	return handler.NewResponse(200, types.TypeClockCompareResult, types.ClockCompareResultData{
		Order: order,
	})
}

// handleTick delegates to the subscription handler (§3.4).
func (h *Handler) handleTick(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	// Tick creates a subscription on system/clock/tick/latest.
	// Delegate to subscription handler via hctx.Execute.
	hctx := req.Context
	if hctx == nil || hctx.Execute == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing execution context")
	}

	resp, err := hctx.Execute(ctx, "system/subscription", "subscribe", req.Params,
		handler.WithResource(&types.ResourceTarget{
			Targets: []string{"system/clock/tick/*"},
		}),
	)
	if err != nil {
		return handler.NewErrorResponse(500, "internal_error", "failed to delegate tick subscription: "+err.Error())
	}
	return resp, nil
}

// SetupAdvancement configures the clock handler for synchronous advancement
// as a named sync hook on the emit pipeline (SYSTEM-COMPOSITION §2.2, position 2).
// Call after peer construction to wire in store, location index, and peer identity.
func (h *Handler) SetupAdvancement(
	cs store.ContentStore, li store.LocationIndex, peerID string, peerIdentityHash hash.Hash, logger *log.Logger) {
	var capHash hash.Hash
	if gh, ok := li.Get("system/capability/grants/" + handlerPattern); ok {
		capHash = gh
	}

	h.mu.Lock()
	h.cs = cs
	h.li = li
	h.peerID = peerID
	h.peerHash = peerIdentityHash
	h.logger = logger
	h.bgCtx = &store.MutationContext{
		AuthorHash:     peerIdentityHash,
		CapabilityHash: capHash,
		HandlerPattern: handlerPattern,
		Operation:      "advance",
	}
	h.mu.Unlock()
}

// OnTreeChange is the sync hook callback for the emit pipeline. Registered as
// "clock/advancement" at position 2 (after query, before history).
// After advancing, populates evt.Context.Clock with the current structured
// clock state so downstream consumers (history at position 4) can read it.
func (h *Handler) OnTreeChange(evt store.TreeChangeEvent) *store.ConsumerResult {
	_, barePath := store.SplitNamespace(evt.Path)
	if isClockEnginePath(barePath) {
		return nil
	}
	h.advanceClock()

	// Populate the execution context with the current structured clock state (F6).
	if evt.Context != nil && h.cs != nil && h.li != nil {
		config := loadConfig(h.cs, h.li)
		state := readClockState(config, h.cs, h.li)
		if raw, err := ecf.Encode(state); err == nil {
			evt.Context.Clock = raw
			evt.Context.ClockType = types.TypeClockState
		}
	}
	return nil
}

// advanceClock implements the clock advancement algorithm (§4.2).
func (h *Handler) advanceClock() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.cs == nil || h.li == nil {
		return
	}

	config := loadConfig(h.cs, h.li)
	mode := config.Mode

	if mode == "wall" {
		// Wall mode: no tree state to update.
		return
	}

	// All non-wall modes use a logical clock.
	var currentLogical types.ClockLogicalData
	if lh, ok := h.li.Get("system/clock/logical"); ok {
		if ent, ok := h.cs.Get(lh); ok {
			if d, err := types.ClockLogicalDataFromEntity(ent); err == nil {
				currentLogical = d
			}
		}
	}

	newCounter := currentLogical.Counter + 1
	newLogical := types.ClockLogicalData{Counter: newCounter}
	if err := h.storeClockEntity("system/clock/logical", newLogical); err != nil {
		h.logf("clock: failed to store logical clock: %v", err)
		return
	}

	if mode == "vector" {
		var currentVector types.ClockVectorData
		if vh, ok := h.li.Get("system/clock/vector"); ok {
			if ent, ok := h.cs.Get(vh); ok {
				if d, err := types.ClockVectorDataFromEntity(ent); err == nil {
					currentVector = d
				}
			}
		}
		if currentVector.Entries == nil {
			currentVector.Entries = make(map[string]uint64)
		}
		currentVector.Entries[h.peerID] = newCounter
		// Prune if exceeds max entries.
		if len(currentVector.Entries) > types.MaxVectorEntries {
			pruneVectorEntries(currentVector.Entries)
		}
		if err := h.storeClockEntity("system/clock/vector", currentVector); err != nil {
			h.logf("clock: failed to store vector clock: %v", err)
		}
	}

	if mode == "hlc" {
		var currentHLC types.ClockHLCData
		if hh, ok := h.li.Get("system/clock/hlc"); ok {
			if ent, ok := h.cs.Get(hh); ok {
				if d, err := types.ClockHLCDataFromEntity(ent); err == nil {
					currentHLC = d
				}
			}
		}
		newHLC := hlcLocalEvent(currentHLC, h.peerHash)
		if err := h.storeClockEntity("system/clock/hlc", newHLC); err != nil {
			h.logf("clock: failed to store HLC: %v", err)
		}
	}
}

// storeClockEntity encodes data as an entity and stores it in the content store
// and location index at the given path.
func (h *Handler) storeClockEntity(path string, data interface{}) error {
	var typeName string
	switch data.(type) {
	case types.ClockLogicalData:
		typeName = types.TypeClockLogical
	case types.ClockVectorData:
		typeName = types.TypeClockVector
	case types.ClockHLCData:
		typeName = types.TypeClockHLC
	default:
		typeName = "primitive/any"
	}

	raw, err := ecf.Encode(data)
	if err != nil {
		return err
	}
	ent, err := entity.NewEntity(typeName, cbor.RawMessage(raw))
	if err != nil {
		return err
	}
	eh, err := h.cs.Put(ent)
	if err != nil {
		return err
	}
	var setErr error
	if cw, ok := h.li.(store.ContextualWriter); ok && h.bgCtx != nil {
		_, setErr = cw.SetWithContext(path, eh, h.bgCtx)
	} else {
		setErr = h.li.Set(path, eh)
	}
	if setErr != nil {
		return fmt.Errorf("clock: bind %s: %w", path, setErr)
	}
	return nil
}

func (h *Handler) logf(format string, args ...any) {
	if h.logger != nil {
		h.logger.Printf(format, args...)
	}
}

// --- Clock state reading ---

// loadConfig reads the clock config from the tree, or returns default config.
func loadConfig(cs store.ContentStore, li store.LocationIndex) types.ClockConfigData {
	h, ok := li.Get("system/clock/config")
	if !ok {
		return types.ClockConfigData{Mode: types.DefaultClockMode}
	}
	ent, ok := cs.Get(h)
	if !ok {
		return types.ClockConfigData{Mode: types.DefaultClockMode}
	}
	d, err := types.ClockConfigDataFromEntity(ent)
	if err != nil {
		return types.ClockConfigData{Mode: types.DefaultClockMode}
	}
	return d
}

// readClockState reads the current clock state based on config (§3.2).
func readClockState(config types.ClockConfigData, cs store.ContentStore, li store.LocationIndex) types.ClockStateData {
	state := types.ClockStateData{Mode: config.Mode}

	// Include wall-clock timestamp for wall mode or when wall_clock != false.
	if config.Mode == "wall" || config.WallClock == nil || *config.WallClock {
		state.Timestamp = &types.ClockTimestampData{
			Ms: uint64(time.Now().UnixMilli()),
		}
	}

	switch config.Mode {
	case "logical":
		state.Logical = readLogical(cs, li)
	case "vector":
		state.Logical = readLogical(cs, li)
		state.Vector = readVector(cs, li)
	case "hlc":
		state.Logical = readLogical(cs, li)
		state.HLC = readHLC(cs, li)
	}

	return state
}

func readLogical(cs store.ContentStore, li store.LocationIndex) *types.ClockLogicalData {
	h, ok := li.Get("system/clock/logical")
	if !ok {
		return &types.ClockLogicalData{Counter: 0}
	}
	ent, ok := cs.Get(h)
	if !ok {
		return &types.ClockLogicalData{Counter: 0}
	}
	d, err := types.ClockLogicalDataFromEntity(ent)
	if err != nil {
		return &types.ClockLogicalData{Counter: 0}
	}
	return &d
}

func readVector(cs store.ContentStore, li store.LocationIndex) *types.ClockVectorData {
	h, ok := li.Get("system/clock/vector")
	if !ok {
		return &types.ClockVectorData{Entries: map[string]uint64{}}
	}
	ent, ok := cs.Get(h)
	if !ok {
		return &types.ClockVectorData{Entries: map[string]uint64{}}
	}
	d, err := types.ClockVectorDataFromEntity(ent)
	if err != nil {
		return &types.ClockVectorData{Entries: map[string]uint64{}}
	}
	return &d
}

func readHLC(cs store.ContentStore, li store.LocationIndex) *types.ClockHLCData {
	h, ok := li.Get("system/clock/hlc")
	if !ok {
		now := uint64(time.Now().UnixMilli())
		return &types.ClockHLCData{Physical: now, Logical: 0}
	}
	ent, ok := cs.Get(h)
	if !ok {
		now := uint64(time.Now().UnixMilli())
		return &types.ClockHLCData{Physical: now, Logical: 0}
	}
	d, err := types.ClockHLCDataFromEntity(ent)
	if err != nil {
		now := uint64(time.Now().UnixMilli())
		return &types.ClockHLCData{Physical: now, Logical: 0}
	}
	return &d
}

// --- Clock algorithms ---

// hlcLocalEvent advances the HLC for a local event (§6.2).
func hlcLocalEvent(current types.ClockHLCData, peerHash hash.Hash) types.ClockHLCData {
	wall := uint64(time.Now().UnixMilli())
	newPhysical := wall
	if current.Physical > newPhysical {
		newPhysical = current.Physical
	}

	var newLogical uint64
	if newPhysical == current.Physical {
		newLogical = current.Logical + 1
	} else {
		newLogical = 0
	}

	return types.ClockHLCData{
		Physical: newPhysical,
		Logical:  newLogical,
		Peer:     peerHash,
	}
}

// compareClocks determines the ordering of two clock values (§6.4).
// Both values must be the same clock type.
func compareClocks(a, b cbor.RawMessage) (string, error) {
	clockType, err := detectClockType(a)
	if err != nil {
		return "", err
	}

	switch clockType {
	case "timestamp":
		var ta, tb types.ClockTimestampData
		if err := ecf.Decode(a, &ta); err != nil {
			return "", fmt.Errorf("decode timestamp a: %w", err)
		}
		if err := ecf.Decode(b, &tb); err != nil {
			return "", fmt.Errorf("decode timestamp b: %w", err)
		}
		return compareTimestamps(ta, tb), nil

	case "logical":
		var la, lb types.ClockLogicalData
		if err := ecf.Decode(a, &la); err != nil {
			return "", fmt.Errorf("decode logical a: %w", err)
		}
		if err := ecf.Decode(b, &lb); err != nil {
			return "", fmt.Errorf("decode logical b: %w", err)
		}
		return compareLogical(la, lb), nil

	case "vector":
		var va, vb types.ClockVectorData
		if err := ecf.Decode(a, &va); err != nil {
			return "", fmt.Errorf("decode vector a: %w", err)
		}
		if err := ecf.Decode(b, &vb); err != nil {
			return "", fmt.Errorf("decode vector b: %w", err)
		}
		return compareVector(va, vb), nil

	case "hlc":
		var ha, hb types.ClockHLCData
		if err := ecf.Decode(a, &ha); err != nil {
			return "", fmt.Errorf("decode hlc a: %w", err)
		}
		if err := ecf.Decode(b, &hb); err != nil {
			return "", fmt.Errorf("decode hlc b: %w", err)
		}
		return compareHLC(ha, hb), nil

	default:
		return "", fmt.Errorf("unsupported clock type: %s", clockType)
	}
}

// detectClockType inspects CBOR map keys to determine the clock type.
// Each clock type has a unique distinguishing key:
//   - "entries"  → vector
//   - "physical" → hlc
//   - "ms"       → timestamp
//   - "counter"  → logical
func detectClockType(raw cbor.RawMessage) (string, error) {
	var m map[string]interface{}
	if err := ecf.Decode(raw, &m); err != nil {
		return "", fmt.Errorf("decode clock value: %w", err)
	}
	if _, ok := m["entries"]; ok {
		return "vector", nil
	}
	if _, ok := m["physical"]; ok {
		return "hlc", nil
	}
	if _, ok := m["ms"]; ok {
		return "timestamp", nil
	}
	if _, ok := m["counter"]; ok {
		return "logical", nil
	}
	return "", fmt.Errorf("unable to determine clock type from keys")
}

// compareTimestamps compares two timestamps (§6.4.1).
func compareTimestamps(a, b types.ClockTimestampData) string {
	if a.Ms < b.Ms {
		return "before"
	}
	if a.Ms > b.Ms {
		return "after"
	}
	return "equal"
}

// compareLogical compares two logical clocks (§6.4.2).
func compareLogical(a, b types.ClockLogicalData) string {
	if a.Counter < b.Counter {
		return "before"
	}
	if a.Counter > b.Counter {
		return "after"
	}
	return "equal"
}

// compareVector compares two vector clocks (§6.4.3).
func compareVector(a, b types.ClockVectorData) string {
	allPeers := make(map[string]struct{})
	for k := range a.Entries {
		allPeers[k] = struct{}{}
	}
	for k := range b.Entries {
		allPeers[k] = struct{}{}
	}

	aLeqB := true
	bLeqA := true
	equal := true

	for peer := range allPeers {
		aVal := a.Entries[peer] // 0 if missing
		bVal := b.Entries[peer]
		if aVal > bVal {
			aLeqB = false
			equal = false
		}
		if bVal > aVal {
			bLeqA = false
			equal = false
		}
	}

	if equal {
		return "equal"
	}
	if aLeqB {
		return "before"
	}
	if bLeqA {
		return "after"
	}
	return "concurrent"
}

// compareHLC compares two hybrid logical clocks (§6.4.4).
func compareHLC(a, b types.ClockHLCData) string {
	if a.Physical < b.Physical {
		return "before"
	}
	if a.Physical > b.Physical {
		return "after"
	}
	if a.Logical < b.Logical {
		return "before"
	}
	if a.Logical > b.Logical {
		return "after"
	}
	// Peer identity tiebreaker — compare hash bytes.
	cmp := bytes.Compare(a.Peer.Bytes(), b.Peer.Bytes())
	if cmp < 0 {
		return "before"
	}
	if cmp > 0 {
		return "after"
	}
	return "equal"
}

// isClockEnginePath returns true for clock engine output paths that must be guarded
// to prevent recursive advancement. Config paths are NOT guarded.
func isClockEnginePath(barePath string) bool {
	return barePath == "system/clock/logical" ||
		barePath == "system/clock/vector" ||
		barePath == "system/clock/hlc"
}

// pruneVectorEntries removes the entry with the lowest counter when max entries is exceeded.
func pruneVectorEntries(entries map[string]uint64) {
	for len(entries) > types.MaxVectorEntries {
		var minKey string
		var minVal uint64 = ^uint64(0)
		for k, v := range entries {
			if v < minVal {
				minVal = v
				minKey = k
			}
		}
		delete(entries, minKey)
	}
}
