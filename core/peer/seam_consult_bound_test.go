package peer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
)

// TestSeamConsultInterval pins the two observable properties NETWORK §10.3
// obligation 6 (v1.7) requires of the spacing schedule — non-decreasing and capped —
// leaving the exact numbers implementation-defined. Step 1 (the first consultation
// past the grace window) is the base interval; the cap is never exceeded.
func TestSeamConsultInterval(t *testing.T) {
	if got := seamConsultInterval(1); got != defaultSeamConsultBase {
		t.Fatalf("step 1 = %v, want the base interval %v", got, defaultSeamConsultBase)
	}
	if got := seamConsultInterval(0); got != defaultSeamConsultBase {
		t.Fatalf("step 0 clamps to step 1 (%v), got %v", defaultSeamConsultBase, got)
	}
	prev := seamConsultInterval(1)
	for step := 2; step <= 40; step++ {
		d := seamConsultInterval(step)
		if d < prev {
			t.Fatalf("interval decreased at step %d: %v < %v (must be non-decreasing)", step, d, prev)
		}
		if d > defaultSeamConsultCap {
			t.Fatalf("interval at step %d exceeded the cap: %v > %v", step, d, defaultSeamConsultCap)
		}
		prev = d
	}
	if seamConsultInterval(40) != defaultSeamConsultCap {
		t.Fatalf("interval did not reach the cap by step 40: %v", seamConsultInterval(40))
	}
}

// TestSeamConsultChargeAtStartAndSpacing is the obligation-6 gate in isolation, and
// it is deliberately framed to prove the "charge at START, not at return" MUST: the
// schedule is advanced purely by ALLOWING consultations — no seam is ever called and
// no outcome exists — and after the grace window the next consultation is refused.
// Any pooled connection (resetConsultLocked) re-opens the sequence.
func TestSeamConsultChargeAtStartAndSpacing(t *testing.T) {
	kp, _ := crypto.Generate()
	p, err := New(WithIdentity(kp))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	kp2, _ := crypto.Generate()
	target := crypto.PeerID(kp2.PeerID())

	// The grace window: the first defaultSeamConsultGrace consultations run unspaced.
	for i := 0; i < defaultSeamConsultGrace; i++ {
		if !p.chargeSeamConsult(target) {
			t.Fatalf("consultation %d within the grace window was refused", i+1)
		}
	}
	// Past the grace window, and within the base interval (defaultSeamConsultBase is
	// far larger than this synchronous test's runtime), the next consultation is
	// spaced out — refused — even though no seam was called and no outcome was seen.
	if p.chargeSeamConsult(target) {
		t.Fatal("consultation past the grace window was allowed within the cooldown — obligation 6 does not bound the sequence")
	}

	// A connection reaching the pool resets the sequence (v1.7): consultation is
	// allowed freely again.
	p.remote.mu.Lock()
	p.resetConsultLocked(target)
	p.remote.mu.Unlock()
	if !p.chargeSeamConsult(target) {
		t.Fatal("a pooled connection did not reset the consultation sequence")
	}

	// A different peer has its own independent schedule.
	kp3, _ := crypto.Generate()
	other := crypto.PeerID(kp3.PeerID())
	if !p.chargeSeamConsult(other) {
		t.Fatal("a second peer's first consultation was refused — the bound must be per-peer")
	}
}

// TestDispatchArmCapsSeamConsultationBurst is the enforcement point on the real wire
// path: driving the establishDispatch arm on repeated pool-misses for an unreachable
// peer, the live-establishment seam is consulted at most defaultSeamConsultGrace
// times across the whole burst, not once per pool-miss. This is the sequential face
// of "bounded third-party load per peer" — without the bound the seam would be
// consulted on every one of the iterations below.
func TestDispatchArmCapsSeamConsultationBurst(t *testing.T) {
	kp, _ := crypto.Generate()
	p, err := New(WithIdentity(kp))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	kp2, _ := crypto.Generate()
	target := crypto.PeerID(kp2.PeerID()) // no transport profile → plain dial fails, arm reached

	var seamCalls int32
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		return nil, errors.New("punch declined (test)") // declines → nothing pools, sequence not reset
	})

	ctx := context.Background()
	const burst = 20
	for i := 0; i < burst; i++ {
		// The dispatch arm; each call is one application-driven pool-miss.
		_, _ = p.establishRemote(ctx, target, establishDispatch)
	}
	if got := atomic.LoadInt32(&seamCalls); got != int32(defaultSeamConsultGrace) {
		t.Fatalf("live-establishment seam consulted %d times across %d dispatch pool-misses; obligation 6 caps the unspaced burst at the grace window (%d)",
			got, burst, defaultSeamConsultGrace)
	}

	// A pooled connection resets the sequence; the burst is allowed again.
	p.remote.mu.Lock()
	p.resetConsultLocked(target)
	p.remote.mu.Unlock()
	_, _ = p.establishRemote(ctx, target, establishDispatch)
	if got := atomic.LoadInt32(&seamCalls); got != int32(defaultSeamConsultGrace)+1 {
		t.Fatalf("after a pool reset the seam should be consulted once more (%d), got %d", defaultSeamConsultGrace+1, got)
	}
}
