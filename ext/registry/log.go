// Resolution log per EXTENSION-REGISTRY §11.2 (SHOULD). One entry per
// top-level meta_resolve invocation; cache hits MAY be elided per
// resolver-config.log_cache_hits (default false). The seq is per-peer
// monotonic, recovered on startup by walking the log prefix and taking
// max+1. Ring-buffer retention per resolver-config.resolution_log_capacity
// (default 1024) — eviction is logical via a tombstone sweep, NOT a
// seq reset.

package registry

import (
	"strconv"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// defaultLogCapacity per §11.2.
const defaultLogCapacity = 1024

// Logger writes resolution-log entries. Pass to Handler.SetLogger to
// activate. Seq counter is recovered from existing entries via the
// LocationIndex on first Append.
type Logger struct {
	mu       sync.Mutex
	seq      uint64
	loaded   bool
	capacity uint32
	clock    func() uint64
}

// NewLogger returns a Logger with seq=0 (unloaded). The capacity defaults
// to 1024 when zero. `clock` is optional; nil uses wall-clock-millis.
func NewLogger(capacity uint32, clock func() uint64) *Logger {
	if capacity == 0 {
		capacity = defaultLogCapacity
	}
	if clock == nil {
		clock = func() uint64 { return uint64(time.Now().UnixMilli()) }
	}
	return &Logger{capacity: capacity, clock: clock}
}

// Append writes one resolution-log entry, evicting the oldest if the
// ring buffer is at capacity. Per-peer monotonic seq is preserved across
// evictions (the seq counter never resets, only the bound entries are
// swept; see GC posture in §9).
//
// Cache-hit elision: caller checks resolver-config.log_cache_hits before
// invoking Append; this method writes unconditionally.
func (l *Logger) Append(hctx *handler.HandlerContext, name string, r types.ResolveResultData, reason string, isFallback bool) {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		l.seq = recoverMaxSeq(hctx.LocationIndex) + 1
		l.loaded = true
	} else {
		l.seq++
	}

	entry := types.ResolutionLogData{
		Seq:                 l.seq,
		Name:                name,
		Status:              r.Status,
		AttemptedAt:         l.clock(),
		IsFallbackReresolve: isFallback,
	}
	if r.Binding != nil {
		bh := *r.Binding
		entry.Binding = &bh
	}
	if r.BackendID != "" {
		bid := r.BackendID
		entry.BackendID = &bid
	}
	if reason != "" {
		rs := reason
		entry.Reason = &rs
	}

	ent, err := entry.ToEntity()
	if err != nil {
		return
	}
	if _, err := hctx.Store.Put(ent); err != nil {
		return
	}
	path := types.ResolutionLogPath(l.seq)
	if _, err := hctx.TreeSet(path, ent.ContentHash, "registry-log"); err != nil {
		return
	}
	l.evictIfOverCapacity(hctx)
}

// evictIfOverCapacity removes the oldest log entries when the bound count
// exceeds l.capacity. Eviction is by lowest-seq-first via prefix-list.
// Seq monotonicity is preserved (the counter does not reset).
func (l *Logger) evictIfOverCapacity(hctx *handler.HandlerContext) {
	prefix := types.ResolutionLogPrefix
	entries := hctx.LocationIndex.List(prefix)
	if uint32(len(entries)) <= l.capacity {
		return
	}
	// LocationIndex.List returns entries sorted ascending by path. The
	// path is `system/registry/resolution-log/{seq}` with decimal seq —
	// lexicographic ordering matches numeric ordering ONLY when seqs are
	// zero-padded. We do NOT pad (spec doesn't require it), so we re-sort
	// numerically by extracting the seq segment.
	type evictable struct {
		path string
		seq  uint64
	}
	es := make([]evictable, 0, len(entries))
	for _, e := range entries {
		seg := bareNameFromLogPath(e.Path)
		if seg == "" {
			continue
		}
		seqNum, err := strconv.ParseUint(seg, 10, 64)
		if err != nil {
			continue
		}
		es = append(es, evictable{path: e.Path, seq: seqNum})
	}
	// Insertion sort — small lists.
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j-1].seq > es[j].seq; j-- {
			es[j-1], es[j] = es[j], es[j-1]
		}
	}
	excess := len(es) - int(l.capacity)
	for i := 0; i < excess; i++ {
		// We pass the qualified path back through TreeRemove via the
		// handler-context wrapper that strips the peer-id prefix. The
		// HandlerContext API isn't quite that, so we use the absolute
		// remove on the raw LI.
		hctx.LocationIndex.Remove(es[i].path)
	}
}

// recoverMaxSeq walks the resolution-log prefix and returns the highest
// seq observed. Returns 0 for an empty log (next entry → seq=1 per
// the §11.2 monotonic-across-restarts rule, treating "0 entries" as
// "next seq = 1").
func recoverMaxSeq(li store.LocationIndex) uint64 {
	var max uint64
	for _, e := range li.List(types.ResolutionLogPrefix) {
		seg := bareNameFromLogPath(e.Path)
		if seg == "" {
			continue
		}
		n, err := strconv.ParseUint(seg, 10, 64)
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max
}

// bareNameFromLogPath extracts the trailing segment after
// `system/registry/resolution-log/` from a qualified or peer-relative
// path. Returns "" if the path doesn't match the prefix.
func bareNameFromLogPath(p string) string {
	const prefix = "system/registry/resolution-log/"
	idx := indexAt(p, prefix)
	if idx < 0 {
		return ""
	}
	return p[idx+len(prefix):]
}

func indexAt(s, needle string) int {
	// strings.Index without pulling the import — minimal hot path.
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
