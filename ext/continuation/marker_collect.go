package continuation

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// MarkerRetentionKey is the named operator knob for the chain-error marker
// retention window, in milliseconds.
//
// The window had no name and no default anywhere in the spec: EXTENSION-
// CONTINUATION §3.4 A.1 says markers are "GC-eligible after the retention
// window (suggested default: 24 hours)" while defining no such window, no key
// and no actor. This names it, on the shape EXTENSION-DISCOVERY already uses
// for `candidate_history_retention`.
const MarkerRetentionKey = "system/runtime/chain-errors/retention-ms"

// DefaultMarkerRetentionMs is the §3.4 A.1 suggested default: 24 hours.
const DefaultMarkerRetentionMs uint64 = 24 * 60 * 60 * 1000

// RetainMarkersForever disables collection.
//
// Collection is a MUST, and this opting out of it is not a contradiction — the
// MUST exists to close an ASYMMETRY, not to force deletion. Binding a marker
// was elevated SHOULD → MUST, so a permanently-failing chain is *required* to
// produce ~1,440 marker nodes per day, indefinitely; leaving collection at MAY
// meant the spec mandated writing a record nothing was obliged to collect. The
// obligation is therefore on HAVING a reaper with a bounded default — which is
// what an impl can get wrong by omission — not on any particular marker dying.
//
// An operator who wants the full history is a legitimate case (the tree IS the
// event log) and sets this. What they cannot do is get unbounded growth by
// accident, which is the only thing the MUST was protecting against.
//
// Flagged to arch: if §5's MAY→MUST was meant as "markers MUST be deleted at
// 24h, no opt-out", this knob is non-conformant and the ruling should say so
// explicitly — an operator losing their own diagnostic history to a mandatory
// reaper with no override deserves to be a deliberate decision rather than a
// side effect of fixing a leak.
const RetainMarkersForever uint64 = 0

// markerRoot is the §3.10 marker tree. Both kinds live under it: `lost`
// (sender-side, this handler + the subscription engine) and `rejected`
// (receiver-side, the dispatcher). Collection is indifferent to which — it
// reads the timestamp every marker body carries.
const markerRoot = "system/runtime/chain-errors/"

// collectThrottle bounds how often a bind pays for a sweep.
const collectThrottle = time.Minute

// CollectExpiredMarkers removes every §3.10 chain-error marker whose
// origination timestamp is older than retentionMs before nowMs, returning how
// many it collected.
//
// SELF-collection: a peer reaping its own markers out of its own tree, under
// its own authority. That is not a policy choice here, it falls out of the
// own-tree-own-authority invariant — nobody else can, and nobody else should.
// There is no operator step, no external reaper, no substrate behaviour to
// depend on.
//
// retentionMs == RetainMarkersForever disables collection entirely.
//
// Best-effort and non-reactive, like every other operation on this tree: an
// unreadable or undecodable binding is skipped rather than deleted (it might
// not be ours), and a failed removal is dropped. Collection MUST NOT be able
// to affect a chain — it removes observations, never behaviour.
func CollectExpiredMarkers(cs store.ContentStore, li store.LocationIndex, retentionMs, nowMs uint64) int {
	if retentionMs == RetainMarkersForever || cs == nil || li == nil {
		return 0
	}
	if nowMs <= retentionMs {
		return 0 // clock before the epoch+window; nothing can be expired yet
	}
	cutoff := nowMs - retentionMs

	collected := 0
	for _, entry := range li.List(markerRoot) {
		ent, ok := cs.Get(entry.Hash)
		if !ok {
			continue
		}
		if ent.Type != types.TypeChainErrorLost {
			// Not a marker — an intermediate binding, or something else's.
			// Deleting an entity we did not identify is how a reaper becomes
			// a data-loss bug.
			continue
		}
		var d types.ChainErrorLostData
		if err := ecf.Decode(ent.Data, &d); err != nil {
			continue
		}
		// timestamp is captured at failure-ORIGINATION (§3.10.6), not at bind
		// time, which is exactly what makes it a sound age: a redelivered
		// marker does not look younger than the failure it records. A marker
		// with no timestamp is not aged out — absent evidence is not evidence
		// of age.
		if d.Timestamp == 0 || d.Timestamp > cutoff {
			continue
		}
		if _, removed := li.Remove(entry.Path); removed {
			collected++
		}
	}
	return collected
}

// maybeCollectMarkers runs a throttled sweep from the marker-bind path.
//
// Bind-time rather than a background ticker, deliberately. The tree has no
// timer in it and no ext handler owns a goroutine; adding a reaper loop would
// introduce a lifecycle (start, stop, leak-on-drop) to solve a problem that
// only exists while markers are being produced. Binding is precisely when the
// tree grows, so it is precisely when a bounded sweep is worth paying for, and
// a peer that has stopped failing has nothing to collect. The throttle keeps
// the amortized cost off the dispatch path.
//
// The consequence, stated plainly: the last batch of markers outlives the
// window until something binds again. That is conformant — §3.4 A.1 makes the
// window an ELIGIBILITY threshold ("GC-eligible after"), not a deadline — and
// it is bounded by one window's worth of markers on an idle peer.
func (h *Handler) maybeCollectMarkers(cs store.ContentStore, li store.LocationIndex) {
	retention := h.markerRetention()
	if retention == RetainMarkersForever {
		return
	}
	now := time.Now()
	h.mu.Lock()
	if !h.lastCollect.IsZero() && now.Sub(h.lastCollect) < collectThrottle {
		h.mu.Unlock()
		return
	}
	h.lastCollect = now
	h.mu.Unlock()

	if n := CollectExpiredMarkers(cs, li, retention, uint64(now.UnixMilli())); n > 0 {
		debugLog("collected %d expired chain-error marker(s) (retention %dms)", n, retention)
	}
}

func (h *Handler) markerRetention() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.markerRetentionMs
}
