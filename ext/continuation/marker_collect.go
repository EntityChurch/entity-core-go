package continuation

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
)

// Chain-error marker collection is implemented in core/protocol, where BOTH
// binders can reach it without a backward DAG edge: the continuation handler
// binds `lost` markers (here) and the dispatcher binds `rejected` markers (in
// core/protocol), and the dispatcher sits below ext in the DAG. See
// core/protocol/chainerror_collect.go for why it lives there. This file keeps
// only the handler-side integration — the throttle and the WithMarkerRetention
// deploy default — and re-exports the shared names so existing referrers and the
// v1.23 §3.4 A.1 config-key surface (system/config/chain-errors → retention_ms)
// stay stable at this package.
const (
	// DefaultMarkerRetentionMs is the v1.23 §3.4 A.1 suggested default: 24 hours.
	DefaultMarkerRetentionMs = protocol.DefaultMarkerRetentionMs
	// RetainMarkersForever (0) disables collection — the operator who wants the
	// full event log keeps it. The MUST-collect obligation is about HAVING a
	// bounded default, not about any particular marker dying.
	RetainMarkersForever = protocol.RetainMarkersForever
	// MarkerRetentionConfigPath / MarkerRetentionField are the v1.23 operator
	// knob: the retention_ms field of the system/config/chain-errors entity.
	MarkerRetentionConfigPath = protocol.MarkerRetentionConfigPath
	MarkerRetentionField      = protocol.MarkerRetentionField
	// MarkerRetentionKey is the config ENTITY path.
	//
	// Deprecated: use MarkerRetentionConfigPath + MarkerRetentionField. Kept so an
	// external referrer does not break; both name the same v1.23 key.
	MarkerRetentionKey = protocol.MarkerRetentionConfigPath
)

// CollectExpiredMarkers / retentionFromConfig re-export the core/protocol
// implementation so this package's callers and tests reach the one collector.
var (
	CollectExpiredMarkers = protocol.CollectExpiredMarkers
	retentionFromConfig   = protocol.RetentionFromConfig
)

// markerRoot is the §3.10 marker tree (both `lost` and `rejected` live under it).
const markerRoot = protocol.MarkerRoot

// collectThrottle bounds how often a bind pays for a sweep.
const collectThrottle = time.Minute

// maybeCollectMarkers runs a throttled sweep from the marker-bind path.
//
// Bind-time rather than a background ticker, deliberately. The tree has no timer
// in it and no ext handler owns a goroutine; adding a reaper loop would introduce
// a lifecycle (start, stop, leak-on-drop) to solve a problem that only exists
// while markers are being produced. Binding is precisely when the tree grows, so
// it is precisely when a bounded sweep is worth paying for, and a peer that has
// stopped failing has nothing to collect. The throttle keeps the amortized cost
// off the dispatch path.
//
// The consequence, stated plainly: the last batch of markers outlives the window
// until something binds again. That is conformant — §3.4 A.1 makes the window an
// ELIGIBILITY threshold ("GC-eligible after"), not a deadline — and it is bounded
// by one window's worth of markers on an idle peer.
func (h *Handler) maybeCollectMarkers(cs store.ContentStore, li store.LocationIndex) {
	// Throttle first — the tree lookup for the config knob and the sweep both
	// stay off the dispatch path except once per collectThrottle window.
	now := time.Now()
	h.mu.Lock()
	if !h.lastCollect.IsZero() && now.Sub(h.lastCollect) < collectThrottle {
		h.mu.Unlock()
		return
	}
	h.lastCollect = now
	h.mu.Unlock()
	h.maybeCollectMarkersAt(cs, li, uint64(now.UnixMilli()))
}

// maybeCollectMarkersAt resolves the effective retention window and sweeps at a
// caller-supplied now (ms). Split from the throttle so tests can drive the sweep
// at a fixed clock.
//
// v1.23 §3.4 A.1: the retention window is configured at
// system/config/chain-errors → retention_ms. The operator's tree config is the
// runtime knob and wins when present (including an explicit 0 =
// RetainMarkersForever, the operator turning collection off); the builder option
// (WithMarkerRetention, default 24h) is the deploy-time default it overrides.
func (h *Handler) maybeCollectMarkersAt(cs store.ContentStore, li store.LocationIndex, nowMs uint64) {
	retention := protocol.EffectiveRetention(cs, li, h.markerRetention())
	if retention == RetainMarkersForever {
		return
	}
	if n := protocol.CollectExpiredMarkers(cs, li, retention, nowMs); n > 0 {
		debugLog("collected %d expired chain-error marker(s) (retention %dms)", n, retention)
	}
}

func (h *Handler) markerRetention() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.markerRetentionMs
}
