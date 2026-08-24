package protocol

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Chain-error marker retention/collection (EXTENSION-CONTINUATION v1.23 §3.4 A.1).
//
// This lives in core/protocol, not ext/continuation, on purpose: chain-error
// markers are bound at THREE sites and two of them are here in the dispatcher,
// below ext in the DAG. `lost` markers are bound by the continuation handler
// (ext/continuation) on forward-dispatch failure; `rejected` markers are bound
// by THIS package's dispatcher (dispatch.go bindRejectedChainErrorMarker) on a
// chain-scoped cap rejection. The dispatcher cannot call an ext-level sweep — ext
// depends on core, not the reverse — so if the collector lived in ext, a peer
// that only ever DENIES chain dispatches (an attacker-driven 403 path) and never
// advances a continuation would bind `rejected` markers forever with nothing to
// reap them. Hosting the collector here lets both binders sweep. (Reported by
// entity-core-rust, 2026-08-15, who found the identical shape in their tree.)
//
// The window is configured at system/config/chain-errors → retention_ms (v1.23),
// read from the peer's own tree; the default is 24h. See EffectiveRetention.

const (
	// DefaultMarkerRetentionMs is the v1.23 §3.4 A.1 suggested default: 24 hours.
	DefaultMarkerRetentionMs uint64 = 24 * 60 * 60 * 1000

	// RetainMarkersForever (0) disables collection — the operator who wants the
	// full event log keeps it. The MUST-collect obligation is about HAVING a
	// bounded default so unbounded growth is not what you get by doing nothing,
	// not about any particular marker dying; an explicit opt-out is legitimate.
	RetainMarkersForever uint64 = 0

	// MarkerRetentionConfigPath / MarkerRetentionField locate the v1.23 operator
	// knob: the retention_ms field of the system/config/chain-errors entity.
	MarkerRetentionConfigPath = "system/config/chain-errors"
	MarkerRetentionField      = "retention_ms"

	// MarkerRoot is the §3.10 chain-error marker tree. Both kinds live under it —
	// `lost/` (sender-side) and `rejected/` (receiver-side, the dispatcher) — and
	// collection is indifferent to which: it reads the timestamp every marker
	// body carries.
	MarkerRoot = "system/runtime/chain-errors/"
)

// ChainErrorsConfig is the decode shape of the system/config/chain-errors entity
// (v1.23 §3.4 A.1). RetentionMs is a pointer so "field absent" (fall back to the
// default) is distinguishable from an explicit 0 (RetainMarkersForever — the
// operator turning collection off), which a bare uint64 zero-value could not
// carry. Unknown fields are MUST-ignore (V7 forward-compat).
type ChainErrorsConfig struct {
	RetentionMs *uint64 `cbor:"retention_ms"`
}

// RetentionFromConfig reads the v1.23 operator knob — the retention_ms field of
// the system/config/chain-errors entity — from a peer's own tree. Returns
// (value, true) when the entity resolves and carries retention_ms, else (0,
// false). Best-effort and read-only: an unresolved path, a missing entity, an
// undecodable body, or an absent field all mean "operator has set nothing here,"
// never an error — the config is advisory over a working default.
func RetentionFromConfig(cs store.ContentStore, li store.LocationIndex) (uint64, bool) {
	if cs == nil || li == nil {
		return 0, false
	}
	h, ok := li.Get(MarkerRetentionConfigPath)
	if !ok {
		return 0, false
	}
	ent, ok := cs.Get(h)
	if !ok {
		return 0, false
	}
	var cfg ChainErrorsConfig
	if err := ecf.Decode(ent.Data, &cfg); err != nil || cfg.RetentionMs == nil {
		return 0, false
	}
	return *cfg.RetentionMs, true
}

// EffectiveRetention resolves the retention window a sweep should use: the tree
// config (system/config/chain-errors → retention_ms) when present, else the
// supplied fallback. The tree config is the operator's runtime knob and wins,
// including an explicit 0 (RetainMarkersForever); the fallback is a deploy-time
// default (24h, or a handler's WithMarkerRetention).
func EffectiveRetention(cs store.ContentStore, li store.LocationIndex, fallback uint64) uint64 {
	if cfg, ok := RetentionFromConfig(cs, li); ok {
		return cfg
	}
	return fallback
}

// CollectExpiredMarkers removes every §3.10 chain-error marker under MarkerRoot
// whose origination timestamp is older than retentionMs before nowMs, returning
// how many it collected.
//
// SELF-collection: a peer reaping its own markers out of its own tree, under its
// own authority — it falls out of the own-tree/own-authority invariant (§3.10.7),
// not a policy choice. retentionMs == RetainMarkersForever disables it.
//
// Best-effort and non-reactive: an entity that is not positively a
// chain-error-lost marker, an undecodable body, or a marker with no timestamp is
// SKIPPED, never deleted — a reaper that removes what it cannot identify is a
// data-loss bug, and this tree is an event log. A failed removal is dropped.
func CollectExpiredMarkers(cs store.ContentStore, li store.LocationIndex, retentionMs, nowMs uint64) int {
	if retentionMs == RetainMarkersForever || cs == nil || li == nil {
		return 0
	}
	if nowMs <= retentionMs {
		return 0 // clock before the epoch+window; nothing can be expired yet
	}
	cutoff := nowMs - retentionMs

	collected := 0
	for _, entry := range li.List(MarkerRoot) {
		ent, ok := cs.Get(entry.Hash)
		if !ok {
			continue
		}
		if ent.Type != types.TypeChainErrorLost {
			// Not a marker — an intermediate binding, or something else's.
			continue
		}
		var d types.ChainErrorLostData
		if err := ecf.Decode(ent.Data, &d); err != nil {
			continue
		}
		// timestamp is captured at failure-ORIGINATION (§3.10.6), not at bind
		// time — a redelivered marker does not look younger than the failure it
		// records. A marker with no timestamp is not aged out: absent evidence
		// is not evidence of age.
		if d.Timestamp == 0 || d.Timestamp > cutoff {
			continue
		}
		if _, removed := li.Remove(entry.Path); removed {
			collected++
		}
	}
	return collected
}
