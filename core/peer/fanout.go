package peer

import (
	"log"
	"sync"
	"sync/atomic"

	"go.entitychurch.org/entity-core-go/core/store"
)

// fanOut reads events from source and distributes them to N sinks, one
// goroutine per sink, with per-sink isolation. A slow or un-drained sink
// fills its OWN buffer and starts dropping events for that sink only;
// other sinks continue receiving uninterrupted. The fan-out reader
// goroutine never blocks waiting for any one sink.
//
// Per-sink drops are counted and exposed via FanOutStats (see SinkStats
// type) so operators can observe which sink is saturated and either
// resize its buffer or fix the consumer.
//
// Design principle (errors-at-saturation-boundaries, see the
// event-delivery-backpressure review):
// internal SDK fan-out is one layer of the event-delivery pipeline.
// At the head (NotifyingLocationIndex.emit), saturation surfaces as an
// error to the caller (Set returns ErrEventBufferFull). At intermediate
// internal stages like this one, saturation is an internal drop tracked
// via metrics — there's no external caller to error back to (the fan-out
// goroutine is internal SDK plumbing). The trade-off: in exchange for
// "one slow sink can't stall others" we accept "a saturated sink loses
// its own events." The dropped-count metric makes this observable.
//
// **Per-sink isolation, not global blocking.** Each sink has its own
// drainer goroutine and its own bounded buffer (already configured at
// the channel-creation point). When that buffer is full, fanOut's send
// to that sink uses non-blocking semantics and increments the per-sink
// drop counter.
//
// Closes all sinks on exit (source closed or done closed). After close,
// no further events are delivered.
func fanOut(source <-chan store.TreeChangeEvent, done <-chan struct{}, sinks ...chan<- store.TreeChangeEvent) *FanOutStats {
	stats := &FanOutStats{
		dropsPerSink: make([]atomic.Uint64, len(sinks)),
	}
	go func() {
		defer func() {
			for _, sink := range sinks {
				close(sink)
			}
		}()
		for {
			select {
			case <-done:
				return
			case evt, ok := <-source:
				if !ok {
					return
				}
				// Extract PeerID from the qualified path but keep Path unchanged.
				peerID, _ := store.SplitNamespace(evt.Path)
				evt.PeerID = peerID

				for i, sink := range sinks {
					// Per-sink isolation: non-blocking send. A slow sink fills
					// its own buffer and drops for ITSELF; other sinks
					// continue receiving. The dropped-count metric on this
					// sink is exposed via FanOutStats.SinkDrops(i) for ops.
					select {
					case <-done:
						return
					case sink <- evt:
					default:
						count := stats.dropsPerSink[i].Add(1)
						stats.logDrop(i, count, evt.Path)
					}
				}
			}
		}
	}()
	return stats
}

// FanOutStats reports per-sink drop counts so operators can detect a
// saturated sink without log-scraping. Drops are counted atomically per
// sink index (in registration order: cfg.treeEventSinks first, then the
// internal externalEvents channel last when present).
type FanOutStats struct {
	dropsPerSink []atomic.Uint64
	mu           sync.RWMutex
	logger       *log.Logger
	sinkNames    []string
}

// SinkDrops returns the running drop count for sink i (in registration order).
func (s *FanOutStats) SinkDrops(i int) uint64 {
	if i < 0 || i >= len(s.dropsPerSink) {
		return 0
	}
	return s.dropsPerSink[i].Load()
}

// AllDrops returns a snapshot of drop counts per sink.
func (s *FanOutStats) AllDrops() []uint64 {
	out := make([]uint64, len(s.dropsPerSink))
	for i := range s.dropsPerSink {
		out[i] = s.dropsPerSink[i].Load()
	}
	return out
}

// SetLogger enables per-drop logging (rate-limited internally — see logDrop).
func (s *FanOutStats) SetLogger(logger *log.Logger) {
	s.mu.Lock()
	s.logger = logger
	s.mu.Unlock()
}

// SetSinkNames associates a human-readable name with each sink index, used
// in drop logging. Optional; if unset, drops log as "sink[i]".
func (s *FanOutStats) SetSinkNames(names []string) {
	s.mu.Lock()
	s.sinkNames = names
	s.mu.Unlock()
}

func (s *FanOutStats) logDrop(i int, count uint64, path string) {
	s.mu.RLock()
	logger := s.logger
	names := s.sinkNames
	s.mu.RUnlock()
	if logger == nil {
		return
	}
	// Rate-limit: log first drop and every power-of-two thereafter
	// (1, 2, 4, 8, ...) so a saturated sink emits a few entries then
	// goes quiet, rather than spamming.
	if count&(count-1) != 0 {
		return
	}
	name := ""
	if i < len(names) {
		name = names[i]
	}
	if name == "" {
		logger.Printf("fanOut: sink[%d] full, dropped event (sink drops: %d): path=%s", i, count, path)
	} else {
		logger.Printf("fanOut: sink %q full, dropped event (sink drops: %d): path=%s", name, count, path)
	}
}
