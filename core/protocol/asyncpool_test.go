package protocol

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAsyncPoolBoundsConcurrency verifies the pool never runs more than
// `workers` jobs at once — the core OOM-vector fix (CONCURRENCY-BACKPRESSURE
// -REVIEW §7.5 / SYSTEM-AUDIT ledger #4).
func TestAsyncPoolBoundsConcurrency(t *testing.T) {
	const workers = 4
	p := newAsyncPool(workers, 64)
	defer p.Stop()

	var inFlight, maxSeen atomic.Int64
	release := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		ok := p.Submit(func() {
			defer wg.Done()
			cur := inFlight.Add(1)
			for {
				prev := maxSeen.Load()
				if cur <= prev || maxSeen.CompareAndSwap(prev, cur) {
					break
				}
			}
			<-release // hold the worker so concurrency is observable
			inFlight.Add(-1)
		})
		if !ok {
			// Queue saturated before all 32 enqueued — expected under a
			// small queue; account for the un-run job.
			wg.Add(-1)
		}
	}

	// Give workers time to pick up jobs and saturate.
	time.Sleep(100 * time.Millisecond)
	if got := maxSeen.Load(); got > workers {
		close(release)
		t.Fatalf("pool ran %d jobs concurrently, exceeds bound of %d", got, workers)
	}
	close(release)
	wg.Wait()
}

// TestAsyncPoolRefusesWhenSaturated verifies Submit is non-blocking and
// increments the refusal counter when the queue is full, rather than
// blocking the caller (which would risk pool-reentrancy deadlock).
func TestAsyncPoolRefusesWhenSaturated(t *testing.T) {
	p := newAsyncPool(1, 2)
	defer p.Stop()

	block := make(chan struct{})
	// Occupy the single worker.
	if !p.Submit(func() { <-block }) {
		t.Fatal("first submit should be accepted")
	}
	time.Sleep(20 * time.Millisecond) // let the worker pick it up

	// Fill the queue (cap 2), then the next submit must be refused.
	accepted, refused := 0, 0
	for i := 0; i < 10; i++ {
		if p.Submit(func() {}) {
			accepted++
		} else {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("expected some submits to be refused when saturated")
	}
	if p.Refused() != uint64(refused) {
		t.Fatalf("Refused() = %d, want %d", p.Refused(), refused)
	}
	close(block)
}

// TestAsyncPoolStopNoLeak verifies workers exit after Stop (no goroutine
// leak) and that Submit refuses post-Stop.
func TestAsyncPoolStopNoLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	p := newAsyncPool(16, 32)

	var ran atomic.Int64
	for i := 0; i < 16; i++ {
		p.Submit(func() { ran.Add(1) })
	}
	time.Sleep(50 * time.Millisecond)

	p.Stop()

	if p.Submit(func() {}) {
		t.Fatal("Submit must refuse after Stop")
	}
	if p.Refused() == 0 {
		t.Fatal("post-Stop refusal must be counted")
	}

	// Allow the scheduler to reap exited workers, then confirm we are not
	// leaking goroutines relative to the pre-pool baseline.
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+4 { // small slack for test/runtime goroutines
		t.Fatalf("goroutine leak after Stop: before=%d after=%d", before, after)
	}

	p.Stop() // idempotent
}

// TestAsyncPoolStopIsBounded verifies Stop returns even if a job is wedged
// (no per-job deadline) — Stop must not hang Peer.Close forever.
func TestAsyncPoolStopIsBounded(t *testing.T) {
	p := newAsyncPool(2, 4)
	wedged := make(chan struct{})
	defer close(wedged)

	p.Submit(func() { <-wedged }) // never returns until the deferred close
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopJoinTimeout + 2*time.Second):
		t.Fatal("Stop did not return within the bounded join timeout")
	}
}
