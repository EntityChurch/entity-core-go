package peer

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
)

// demotePeerOnTransportError is the EXTENSION-NETWORK Amendment 12 §A1 reactive
// demotion: a transport failure observed on a connection believed active MUST
// demote peer liveness by writing system/peer/status = suspect (reason
// transport-error), firing the same subscription the keepalive path fires. It
// also evicts the dead connection from the pool so the next dispatch redials.
//
// Seam discipline (normative MUST, mirrors Amendment 11): this is called at the
// dispatch caller that both observes the send() Err and holds peer_id — never
// buried inside a transport primitive that holds only a socket handle. The
// callers are the three direct-dispatch send sites in remote.go: remoteExecute
// (§10 step 1) and RemoteExecuteWithIncluded's TCP + HTTP branches (the §9
// intermediate-hop forward, itself a direct send to a connected next hop).
// Per the §A1 demotion-seam scope pin (Go rung-1 ask E), the two paths that
// MUST NOT demote — the §10.2 dispatch-fallback and the RELAY terminal-hop
// forward (SendRawFrameTo) — deliberately do NOT call this; they only evict.
func (p *Peer) demotePeerOnTransportError(peerID crypto.PeerID, failed remoteEndpoint, cause error) {
	p.demotePeer(peerID, failed, types.PeerStatusSuspect, types.PeerStatusReasonTransportError, cause)
}

// demotePeerOnKeepaliveMiss is the §5.4 escalation (Amendment 12 rung 2):
// max_missed consecutive keepalive failures demote the peer to disconnected
// (reason keepalive-miss) and evict the dead connection. Escalation is
// suspect → disconnected when a transport error already fired, but a dead
// IDLE connection that never went suspect goes straight to disconnected on
// the miss — both are §5.4 conformant. Returns true when the demotion fired
// (i.e. failed was still the bound connection); the keepalive loop uses the
// result to distinguish a real demotion from a stale-conn race where a
// concurrent re-dial owns liveness now.
func (p *Peer) demotePeerOnKeepaliveMiss(peerID crypto.PeerID, failed remoteEndpoint, cause error) bool {
	return p.demotePeer(peerID, failed, types.PeerStatusDisconnected, types.PeerStatusReasonKeepaliveMiss, cause)
}

// demotePeer is the shared §A1 demotion body under the no-clobber /
// idempotency guard (the Arc::ptr_eq precedent at remove_inbound): the
// eviction and the status write fire only if `failed` is still the connection
// currently bound for this peer — the pooled outbound conn, or the §6.11
// inbound-reentry conn for the no-published-profile path. If a concurrent
// re-dial already replaced it with a live connection (which wrote its own
// `connected`), or a concurrent identical failure already evicted it, we skip:
// never clobber the current binding's liveness, and stay idempotent under
// concurrent re-entry. Returns whether the demotion fired.
func (p *Peer) demotePeer(peerID crypto.PeerID, failed remoteEndpoint, status, reason string, cause error) bool {
	// Pooled outbound binding: evict under the lock iff `failed` is still it.
	p.remote.mu.Lock()
	bound, pooled := p.remote.conns[peerID]
	wasPooledBinding := pooled && bound == failed
	if wasPooledBinding {
		bound.Close()
		delete(p.remote.conns, peerID)
	}
	p.remote.mu.Unlock()

	// §6.11 reentry conns are not in the main pool; the inbound registration
	// is their binding. inboundForReentry/unregister take the lock themselves,
	// so this runs outside the critical section above.
	wasReentryBinding := false
	if tcp, ok := failed.(*Connection); ok {
		wasReentryBinding = p.inboundForReentry(peerID) == tcp
		p.unregisterInboundForReentry(peerID, tcp)
	}

	if !wasPooledBinding && !wasReentryBinding {
		// `failed` is no longer the bound path for this peer — a concurrent
		// re-establishment owns liveness now, or a concurrent failure already
		// demoted. Do not clobber.
		return false
	}

	p.writePeerDemotion(peerID, status, reason, cause)
	return true
}

// writePeerDemotion writes the §A1/§5.4 demoted status. Soft-fail: the
// liveness write is observability-only and must never mask the transport
// error the caller is about to return. A single transport error writes
// `suspect` (not `disconnected`) — one failure is not proof of a dead peer
// (it may be this pooled socket only); the §5.4 keepalive path is what
// escalates suspect → disconnected (reason keepalive-miss).
func (p *Peer) writePeerDemotion(peerID crypto.PeerID, status, reason string, cause error) {
	remoteHash, err := protocol.ResolveRemoteIdentityHash(peerID, nil)
	if err != nil {
		// SHA-256-form remote with no public_key threaded through — can't key
		// the path. Same graceful-skip contract as the session write.
		p.debugf("peer-status %s skipped for %s: %v", status, peerID, err)
		return
	}
	lastError := ""
	if cause != nil {
		lastError = cause.Error()
	}
	// §A4: `last_seen` is a transition snapshot — on a demotion write it is
	// the demotion's evidence ("when I last heard from this peer as of this
	// transition"), sourced from the impl-internal freshness bookkeeping.
	// Absent when no exchange was ever recorded.
	var lastSeen uint64
	if t, ok := p.lastPeerActivity(peerID); ok {
		lastSeen = uint64(t.UnixMilli())
	}
	// `failing_since` stamps the START of the failure episode, so it is
	// written once and carried forward: a suspect → disconnected escalation
	// (or a redial that trips the transport seam again mid-episode) must not
	// re-stamp it, or the derived §2.2 backoff curve restarts at min_ms every
	// time the peer fails a little harder. Only the `connected` write clears
	// it, by omission. This is the one field WritePeerStatus's callers must
	// preserve — the same seam that already owns the §A1 no-clobber guard,
	// for the same reason: only the caller knows the episode's history.
	failingSince := uint64(time.Now().UnixMilli())
	if prev, ok := protocol.ReadPeerStatus(p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash); ok &&
		prev.FailingSince != 0 {
		failingSince = prev.FailingSince
	}
	if _, werr := protocol.WritePeerStatus(
		p.Store(),
		p.LocationIndex(),
		string(p.PeerID()),
		remoteHash,
		types.PeerStatusData{
			PeerID:       string(peerID),
			Status:       status,
			Reason:       reason,
			LastError:    lastError,
			LastSeen:     lastSeen,
			FailingSince: failingSince,
		},
	); werr != nil {
		p.debugf("peer-status %s write for %s: %v", status, peerID, werr)
	}

	// §3.13 close/failure transition (ruling C): the demoted connection is
	// evicted, so its system/connection record flips to "closed". No-op when
	// establish never recorded one (reentry bindings — the remote dialed).
	if _, cerr := protocol.MarkConnectionClosed(
		p.Store(), p.LocationIndex(), string(p.PeerID()), remoteHash,
	); cerr != nil {
		p.debugf("connection-state closed write for %s: %v", peerID, cerr)
	}
}
