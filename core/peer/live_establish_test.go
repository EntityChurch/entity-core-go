package peer

// NETWORK §10.3 live-establishment seam (Amendment 14) — the substrate slot the
// SIGNALING §7 hole punch registers behind. These vectors exercise the seam
// WIRING with a stub policy (a plain dial standing in for a traversal): the
// ordering vs §10.2, the pool re-entry, and the byte-identical-when-unset floor.
// The real punch fills the seam; this proves the ladder consults it correctly.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// pingURI targets a peer's connect handler — every peer answers `ping` with a
// pong, so it is a transport-agnostic "did the dispatch land" probe.
func pingURI(target *Peer) string {
	return fmt.Sprintf("entity://%s/system/protocol/connect", target.PeerID())
}

func mustPing(t *testing.T) entity.Entity {
	t.Helper()
	ping, err := types.PingData{Timestamp: 1709740800000, Sequence: 7}.ToEntity()
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	return ping
}

// TestLiveEstablishUnsetIsUnreachable: with no seam registered and no durable
// profile, dispatch to a NAT'd-analog target fails exactly as the pre-seam
// ladder did — the additive, no-regression floor.
func TestLiveEstablishUnsetIsUnreachable(t *testing.T) {
	a := startPeer(t)
	b := startPeer(t) // reachable in principle, but A holds no profile for it

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No RegisterRemote, no SetLiveEstablish → getRemoteConnection fails and
	// there is no step-3b path.
	_, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil)
	if err == nil {
		t.Fatal("expected unreachable error with no profile and no live seam, got nil")
	}
}

// TestLiveEstablishProvidesAndPoolsConnection: the seam supplies a live
// connection to a peer A has NO durable profile for; the dispatch lands through
// it, and the connection is pooled so a second dispatch reuses it (the seam is
// consulted once — §10.3 "re-enters ordinary dispatch, pooled and reused").
func TestLiveEstablishProvidesAndPoolsConnection(t *testing.T) {
	a := startPeer(t)
	b := startPeer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var seamCalls int32
	a.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&seamCalls, 1)
		if peerID != b.PeerID() {
			return nil, fmt.Errorf("unexpected peer %s", peerID)
		}
		// Stand-in for the punch: obtain a live transport by other means.
		conn, err := a.Connect(ctx, b.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := conn.PerformConnect(ctx); err != nil {
			return nil, err
		}
		return conn, nil
	})

	// First dispatch: getRemoteConnection fails (no profile) → step-3b seam.
	resp, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil)
	if err != nil {
		t.Fatalf("dispatch via live seam: %v", err)
	}
	if resp.Status != 200 || resp.Result.Type != types.TypeNetworkPong {
		t.Fatalf("ping via punched-analog conn: status=%d type=%q", resp.Status, resp.Result.Type)
	}

	// Second dispatch: the pooled connection is reused — the seam is NOT
	// consulted again (§6.5.1b pool re-entry).
	if _, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil); err != nil {
		t.Fatalf("second dispatch (should reuse pooled conn): %v", err)
	}
	if n := atomic.LoadInt32(&seamCalls); n != 1 {
		t.Fatalf("seam consulted %d times, want exactly 1 (the connection must be pooled and reused)", n)
	}
}

// TestLiveEstablishBeforeDispatchFallback: the normative ordering MUST — when
// both seams are registered and the live seam succeeds, dispatch_fallback is
// NEVER consulted. Live first, store-and-forward last.
func TestLiveEstablishBeforeDispatchFallback(t *testing.T) {
	a := startPeer(t)
	b := startPeer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var fallbackCalls int32
	a.SetDispatchFallback(func(ctx context.Context, peerID crypto.PeerID, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (*handler.Response, bool, error) {
		atomic.AddInt32(&fallbackCalls, 1)
		return nil, false, nil
	})
	a.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		conn, err := a.Connect(ctx, b.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := conn.PerformConnect(ctx); err != nil {
			return nil, err
		}
		return conn, nil
	})

	if _, err := a.RemoteExecute(ctx, pingURI(b), "ping", mustPing(t), nil); err != nil {
		t.Fatalf("dispatch via live seam: %v", err)
	}
	if n := atomic.LoadInt32(&fallbackCalls); n != 0 {
		t.Fatalf("dispatch_fallback consulted %d times — §10.3 MUST is live-first: a successful establish_live must short-circuit before §10.2", n)
	}
}

// TestLiveEstablishNullFallsThroughToFallback: when the live seam declines
// (nil — symmetric NAT / not eligible), the ladder falls through to §10.2's
// dispatch_fallback, which then handles or declines. Proves the ordering does
// not swallow the fallback path.
func TestLiveEstablishNullFallsThroughToFallback(t *testing.T) {
	a := startPeer(t)
	bKP, _ := crypto.Generate()
	bID := crypto.PeerID(bKP.PeerID())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var liveCalls, fallbackCalls int32
	a.SetLiveEstablish(func(ctx context.Context, peerID crypto.PeerID) (*Connection, error) {
		atomic.AddInt32(&liveCalls, 1)
		return nil, nil // decline — no traversal path
	})
	a.SetDispatchFallback(func(ctx context.Context, peerID crypto.PeerID, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (*handler.Response, bool, error) {
		atomic.AddInt32(&fallbackCalls, 1)
		if peerID != bID {
			return nil, false, fmt.Errorf("unexpected peer %s", peerID)
		}
		// Handle it (a store-and-forward stand-in) so the caller gets a Response.
		return &handler.Response{Status: 202}, true, nil
	})

	resp, err := a.RemoteExecute(ctx, fmt.Sprintf("entity://%s/system/protocol/connect", bID), "ping", mustPing(t), nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 202 {
		t.Fatalf("expected the fallback's 202, got %d", resp.Status)
	}
	if atomic.LoadInt32(&liveCalls) != 1 {
		t.Fatalf("live seam consulted %d times, want 1", liveCalls)
	}
	if atomic.LoadInt32(&fallbackCalls) != 1 {
		t.Fatalf("dispatch_fallback consulted %d times, want 1 (live declined → fall through)", fallbackCalls)
	}
}
