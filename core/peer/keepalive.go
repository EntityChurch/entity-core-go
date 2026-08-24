package peer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// keepaliveState tracks the per-peer §5.4 keepalive loops and the activity
// timestamps that drive adaptive suppression. One loop per remote peer-id,
// started at outbound pool insert; the loop watches whatever connection is
// currently bound, so a redial does not spawn a second loop.
type keepaliveState struct {
	mu sync.Mutex
	// loops marks peer-ids with a running keepalive goroutine.
	loops map[crypto.PeerID]bool
	// lastActivity records the last successful outbound exchange per peer
	// (§5.4 adaptive suppression: keepalive only fires during idle periods).
	lastActivity map[crypto.PeerID]time.Time
}

// startKeepalive launches the §5 application-level keepalive loop for peerID
// unless one is already running. Called at every outbound pool insert
// (getRemoteConnection dial, AddRemoteConnection) — the seam where liveness
// tracking begins, per Amendment 12 rung 2 (keepalive is MUST, §12.1; it is
// NOT disabled when the transport carries its own pings, §5.1).
//
// Scope: outbound pooled connections only. The §6.11 inbound-reentry conns
// are the remote's outbound sockets — the remote's keepalive owns them; our
// serve loop observes their death directly as a read error.
func (p *Peer) startKeepalive(peerID crypto.PeerID) {
	if p.isClosed() || peerID == p.peerID {
		return
	}
	p.keepalive.mu.Lock()
	if p.keepalive.loops == nil {
		p.keepalive.loops = make(map[crypto.PeerID]bool)
	}
	if p.keepalive.loops[peerID] {
		p.keepalive.mu.Unlock()
		return
	}
	p.keepalive.loops[peerID] = true
	p.keepalive.mu.Unlock()
	go p.keepaliveLoop(peerID)
}

// markPeerActivity records a successful outbound exchange with peerID. The
// keepalive loop reads it for §5.4 adaptive suppression ("skip ping during
// active message exchange; any successful exchange resets the missed
// counter").
func (p *Peer) markPeerActivity(peerID crypto.PeerID) {
	p.keepalive.mu.Lock()
	if p.keepalive.lastActivity == nil {
		p.keepalive.lastActivity = make(map[crypto.PeerID]time.Time)
	}
	p.keepalive.lastActivity[peerID] = time.Now()
	p.keepalive.mu.Unlock()
}

// recentPeerActivity reports whether an exchange with peerID succeeded
// within the window.
func (p *Peer) recentPeerActivity(peerID crypto.PeerID, window time.Duration) bool {
	p.keepalive.mu.Lock()
	defer p.keepalive.mu.Unlock()
	t, ok := p.keepalive.lastActivity[peerID]
	return ok && time.Since(t) < window
}

// pooledEndpoint returns the outbound pool's current binding for peerID, or
// nil. The keepalive loop re-reads this every tick so it always probes the
// live binding, never a stale handle across a redial.
func (p *Peer) pooledEndpoint(peerID crypto.PeerID) remoteEndpoint {
	p.remote.mu.Lock()
	defer p.remote.mu.Unlock()
	return p.remote.conns[peerID]
}

// exitKeepaliveIfUnbound deregisters the loop and returns true iff the pool
// has no binding for peerID. The binding read happens under keepalive.mu —
// the same lock startKeepalive takes after a pool insert — so the loop can
// never deregister itself concurrently with an insert that saw it still
// registered (which would leave a bound connection unwatched).
func (p *Peer) exitKeepaliveIfUnbound(peerID crypto.PeerID) bool {
	p.keepalive.mu.Lock()
	defer p.keepalive.mu.Unlock()
	p.remote.mu.Lock()
	_, bound := p.remote.conns[peerID]
	p.remote.mu.Unlock()
	if bound {
		return false
	}
	delete(p.keepalive.loops, peerID)
	return true
}

// dropKeepaliveLoop deregisters the loop unconditionally (peer shutdown).
func (p *Peer) dropKeepaliveLoop(peerID crypto.PeerID) {
	p.keepalive.mu.Lock()
	delete(p.keepalive.loops, peerID)
	p.keepalive.mu.Unlock()
}

// keepaliveLoop is the §5.4 failure-detection loop for one remote peer: ping
// at interval_ms while idle, and on max_missed consecutive misses demote the
// peer to disconnected (reason keepalive-miss) and evict the dead connection
// — completing the Amendment 12 §A3 liveness floor's third write. Loop
// lifetime is bounded by serveCtx (Peer.Close) and by the pool binding: when
// the binding disappears and stays gone, the loop exits; the next pool
// insert restarts it.
func (p *Peer) keepaliveLoop(peerID crypto.PeerID) {
	interval := time.Duration(p.keepaliveCfg.EffectiveIntervalMs()) * time.Millisecond
	timeout := time.Duration(p.keepaliveCfg.EffectiveTimeoutMs()) * time.Millisecond
	maxMissed := p.keepaliveCfg.EffectiveMaxMissed()

	uri := fmt.Sprintf("entity://%s/system/protocol/connect", peerID)
	var sequence, missed uint64
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-p.serveCtx.Done():
			p.dropKeepaliveLoop(peerID)
			return
		case <-timer.C:
		}

		conn := p.pooledEndpoint(peerID)
		if conn == nil {
			if p.exitKeepaliveIfUnbound(peerID) {
				return
			}
			// Rebound concurrently — keep watching the new binding.
			missed = 0
			timer.Reset(interval)
			continue
		}

		// §5.4 adaptive suppression (SHOULD, §12.2): skip the ping during
		// active exchange; a successful exchange resets the missed counter.
		if p.recentPeerActivity(peerID, interval) {
			missed = 0
			timer.Reset(interval)
			continue
		}

		sequence++
		if err := p.sendKeepalivePing(conn, uri, sequence, timeout); err != nil {
			missed++
			p.debugf("keepalive: ping seq=%d to %s missed (%d/%d): %v", sequence, peerID, missed, maxMissed, err)
			if missed >= maxMissed {
				demoted := p.demotePeerOnKeepaliveMiss(peerID, conn,
					fmt.Errorf("keepalive: %d consecutive misses: %w", missed, err))
				if demoted && p.exitKeepaliveIfUnbound(peerID) {
					return
				}
				// Not demoted (a concurrent re-dial owns liveness now) or
				// already rebound — keep watching the current binding.
				missed = 0
			}
		} else {
			missed = 0
			// §A4 (rung-2 ruling 1): the status entity is TRANSITION-written
			// only — a keepalive success is NOT a tree write. Cadence
			// freshness is impl-internal bookkeeping: the pong is a
			// successful exchange, so record it exactly like dispatch
			// traffic. This one timestamp serves both §5.4 uses — adaptive
			// suppression, and the `last_seen` snapshot a later demotion
			// write carries as its evidence.
			p.markPeerActivity(peerID)
		}
		timer.Reset(interval)
	}
}

// sendKeepalivePing performs one §5.1 ping exchange: EXECUTE
// system/protocol/connect op "ping" with a system/network/ping params
// entity, bounded by timeout_ms. Only a transport failure or timeout is a
// miss: ANY decodable EXECUTE_RESPONSE — even an error status — proves
// protocol-level liveness (§5.1's target is "the handler loop is
// dispatching", the thing transport-level pings can't see), and stays
// tolerant of a peer that predates the ping op.
func (p *Peer) sendKeepalivePing(conn remoteEndpoint, uri string, sequence uint64, timeout time.Duration) error {
	ping, err := types.PingData{
		Timestamp: uint64(time.Now().UnixMilli()),
		Sequence:  sequence,
	}.ToEntity()
	if err != nil {
		return fmt.Errorf("encode ping: %w", err)
	}
	ctx, cancel := context.WithTimeout(p.serveCtx, timeout)
	defer cancel()
	_, err = conn.Execute(ctx, uri, "ping", ping, nil)
	return err
}

// lastPeerActivity returns the timestamp of the last successful exchange
// with peerID (dispatch traffic or keepalive pong), if any. Demotion writes
// read it to snapshot the §3.13 `last_seen` — per §A4 the field is a
// transition snapshot ("when I last heard from this peer as of this
// transition", the demotion's evidence), never cadence-refreshed to the
// tree. The rung-2 build originally implemented §5.4's update_last_seen as
// a tree write per the spec as then written; arch ruled that a spec defect
// (ARCH-RESPONSE-NETWORK-A12-RUNG2-GO ruling 1 — §6.6's own fan-out
// rationale applied to the status entity) and re-pinned cadence freshness
// as impl-internal.
func (p *Peer) lastPeerActivity(peerID crypto.PeerID) (time.Time, bool) {
	p.keepalive.mu.Lock()
	defer p.keepalive.mu.Unlock()
	t, ok := p.keepalive.lastActivity[peerID]
	return t, ok
}
