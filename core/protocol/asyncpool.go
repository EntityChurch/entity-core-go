package protocol

import (
	"sync"
	"sync/atomic"
	"time"
)

// Bounded async-dispatch pool.
//
// "Async work" is the fire-and-forget continuation-advance / deliver-to
// dispatch spawned per request by EXTENSION-INBOX §3.3 / §4.3 semantics
// (inbox receive → continuation advance; EXECUTE with deliver_to → 202 +
// background delivery). Before this pool each such job was an unbounded
// `go func()`: a peer receiving 100k inbox messages spawned 100k goroutines,
// each doing network I/O — a latent OOM vector (the concurrency-backpressure
// review, inventory items F1/F3; SYSTEM-AUDIT ledger #4).
//
// The pool caps concurrency (workers) and pending depth (queue). Saturation
// is REFUSED, never blocked: Submit returns false immediately so the caller
// surfaces backpressure (429 at the wire/local async entry, durable-mailbox
// fallback at the inbox handler) instead of the peer growing without bound.
//
// Spec alignment: queue limits and the backpressure threshold are
// EXTENSION-INBOX §9.4 implementation-defined; refusing deliveries above an
// inbox depth threshold with 429 is §9.3 MAY. No protocol-visible contract
// changes — an accepted job still behaves exactly as the old `go func()`.
const (
	defaultAsyncWorkers   = 256
	defaultAsyncQueueSize = 4096
)

// asyncPool is a bounded worker pool for fire-and-forget dispatch jobs.
//
// Submit is non-blocking by design. Async jobs can themselves Submit
// sub-jobs (an inbox receive runs in a worker and submits the continuation
// advance), so a blocking Submit from inside a worker would deadlock the
// pool once every worker is busy and the queue is full. Non-blocking
// refusal makes the bound safe under reentrancy, trading shed load for
// liveness — which is the correct trade for a fire-and-forget path whose
// work is already durably recorded (write-ahead message / retry-capable
// delivery).
type asyncPool struct {
	jobs      chan func()
	stop      chan struct{}
	workers   int
	wg        sync.WaitGroup
	refused   atomic.Uint64
	stopped   atomic.Bool
	startOnce sync.Once
	stopOnce  sync.Once
}

// newAsyncPool prepares a pool with the given worker and queue sizes.
// Non-positive sizes fall back to the package defaults. Workers are not
// started until the first Submit (start()) so peers that never dispatch
// async work — the common case for short-lived tests — pay nothing.
func newAsyncPool(workers, queue int) *asyncPool {
	if workers <= 0 {
		workers = defaultAsyncWorkers
	}
	if queue <= 0 {
		queue = defaultAsyncQueueSize
	}
	return &asyncPool{
		jobs:    make(chan func(), queue),
		stop:    make(chan struct{}),
		workers: workers,
	}
}

// start launches the worker goroutines exactly once.
func (p *asyncPool) start() {
	p.startOnce.Do(func() {
		p.wg.Add(p.workers)
		for i := 0; i < p.workers; i++ {
			go p.worker()
		}
	})
}

func (p *asyncPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stop:
			return
		case job := <-p.jobs:
			if job != nil {
				job()
			}
		}
	}
}

// Submit enqueues fn for a pool worker. It returns false immediately —
// never blocking — if the pool is saturated (queue full) or stopped; the
// caller MUST handle refusal (429 / durable-mailbox fallback). Every
// refusal increments the counter surfaced via Peer.Stats().
func (p *asyncPool) Submit(fn func()) bool {
	if p.stopped.Load() {
		p.refused.Add(1)
		return false
	}
	p.start()
	select {
	case p.jobs <- fn:
		return true
	default:
		p.refused.Add(1)
		return false
	}
}

// Refused reports the cumulative count of jobs rejected because the pool
// was saturated or stopped. Surfaced as Peer.Stats().AsyncDispatchRefused.
func (p *asyncPool) Refused() uint64 {
	return p.refused.Load()
}

// stopJoinTimeout bounds how long Stop waits to join workers. A worker only
// exits after its current job returns; a job blocked on network I/O without
// a deadline could otherwise hang Stop (and Peer.Close) forever. After the
// timeout Stop returns; the goroutines still exit once their job unblocks.
const stopJoinTimeout = 5 * time.Second

// Stop signals workers to exit and waits (bounded) for in-flight jobs to
// finish. Idempotent. After Stop, Submit refuses (counted). Jobs still
// queued at stop time are abandoned — acceptable for a fire-and-forget path
// at teardown (the work is durably recorded and retry-capable).
func (p *asyncPool) Stop() {
	p.stopOnce.Do(func() {
		p.stopped.Store(true)
		close(p.stop)
	})
	done := make(chan struct{})
	go func() {
		p.wg.Wait() // no-op if workers were never started
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopJoinTimeout):
	}
}
