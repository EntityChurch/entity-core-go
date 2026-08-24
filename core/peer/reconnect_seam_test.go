package peer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
)

// TestCallerOwnsRetryMarker is the round-trip of the caller-owned-retry ctx
// signal: absent by default (a §10 dispatch), present once marked (a §4.1
// reconnect, whose backoff owns retry). The marker carries the §10.3-obligation-4
// non-nesting boundary to the live-establishment seam.
func TestCallerOwnsRetryMarker(t *testing.T) {
	if CallerOwnsRetry(context.Background()) {
		t.Fatal("unmarked context must not own retry (full §7.2 budget)")
	}
	if !CallerOwnsRetry(WithCallerOwnedRetry(context.Background())) {
		t.Fatal("WithCallerOwnedRetry context must own retry")
	}
}

// TestEnsureConnectedSeamCallerOwnedRetryAndPreferRelayMemo covers rung 4's core:
// when the plain profile-dial fails, EnsureConnected consults the §10.3 seam with
// caller-owned retry (one attempt); a declined punch sets the session-local
// prefer-relay memo, which short-circuits the seam on the next reconnect; and
// clearing the memo (the "reachable again" transition) re-arms the seam.
func TestEnsureConnectedSeamCallerOwnedRetryAndPreferRelayMemo(t *testing.T) {
	kp, _ := crypto.Generate()
	p, err := New(WithIdentity(kp))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	kp2, _ := crypto.Generate()
	target := crypto.PeerID(kp2.PeerID()) // no transport profile → plain dial fails

	var seamCalls int32
	var sawCallerOwned atomic.Bool
	p.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		sawCallerOwned.Store(CallerOwnsRetry(ctx))
		return nil, errors.New("punch declined (test)")
	})

	ctx := context.Background()

	// 1. First reconnect: seam consulted with caller-owned retry; it declines.
	if err := p.EnsureConnected(ctx, target); err == nil {
		t.Fatal("expected an error when the seam declines and the peer is unreachable")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted %d times, want 1", got)
	}
	if !sawCallerOwned.Load() {
		t.Fatal("seam did not observe the caller-owned-retry marker (would nest §7.2 × §4.1 budgets)")
	}
	if !p.prefersRelay(target) {
		t.Fatal("prefer-relay memo not set after a failed punch under reconnect")
	}

	// 2. Next reconnect: the memo short-circuits the seam (no re-punch).
	if err := p.EnsureConnected(ctx, target); err == nil {
		t.Fatal("expected an error (still unreachable)")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 1 {
		t.Fatalf("seam consulted again despite prefer-relay memo: %d calls, want 1", got)
	}

	// 3. Reachable-again clears the memo; the seam re-arms for a future disconnect.
	p.clearPreferRelay(target)
	if p.prefersRelay(target) {
		t.Fatal("memo not cleared")
	}
	if err := p.EnsureConnected(ctx, target); err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&seamCalls); got != 2 {
		t.Fatalf("seam not re-consulted after the memo cleared: %d calls, want 2", got)
	}
}

// TestEnsureConnectedNoSeamPreservesPlainDialError confirms the additive nature of
// rung 4: with no live-establishment seam registered, EnsureConnected behaves
// exactly as before — the plain-dial error passes through and no memo is set.
func TestEnsureConnectedNoSeamPreservesPlainDialError(t *testing.T) {
	kp, _ := crypto.Generate()
	p, err := New(WithIdentity(kp))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	kp2, _ := crypto.Generate()
	target := crypto.PeerID(kp2.PeerID())

	if err := p.EnsureConnected(context.Background(), target); err == nil {
		t.Fatal("expected the plain-dial error with no seam registered")
	}
	if p.prefersRelay(target) {
		t.Fatal("no seam was attempted, so no prefer-relay memo should be set")
	}
}
