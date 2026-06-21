// Package peerwiring bridges the RELAY OutboundDispatcher seam to a live
// core/peer.Peer. The default Handler.dispatcher is a noop returning
// ErrDestinationUnreachable (conservative Mode-S-only posture); installing
// the PeerDispatcher activates §3.1.1 terminal-hop delivery and
// intermediate-hop forwarding over the peer's existing outbound connection
// pool.
package peerwiring

import (
	"context"
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// PeerDispatcher implements relay.OutboundDispatcher using a *peer.Peer's
// connection pool.
//
// §3.1.1 semantics:
//
//   - DeliverInner (terminal hop): the inner entity is a system/envelope-
//     typed entity whose .Data is the raw ECF-encoded {root, included} of
//     the source's signed envelope. We write those bytes verbatim onto the
//     destination's inbound frame via SendRawFrameTo. We do NOT decode,
//     re-encode, or re-sign — the destination verifies the source's
//     signature + cap chain exactly as on a direct connection (§3.1 +
//     §3.1.1 + §5.1). Fire-and-forget: any response from the destination
//     flows back via INBOX deliver_to (§3.1), not through the relay.
//
//   - ForwardToNextHop (intermediate hop): we re-encode the (TTL-decremented)
//     forward-request as a fresh entity and dispatch system/relay:forward
//     to next_hop, with the inner ENTITY included in the envelope's
//     included set so the next relay's lookupIncluded resolves it. The
//     inner entity's bytes are carried verbatim (we never decode .Data —
//     §9 / §10.4 opacity holds across every hop).
//
// When the destination has no live session AND no transport profile to
// dial, the raw-frame send fails — we translate that to
// relay.ErrDestinationUnreachable so the relay handler triggers §6.2.1
// fallback (queue at Mode-S).
type PeerDispatcher struct {
	peer *peer.Peer
}

// New returns a PeerDispatcher wrapping p.
func New(p *peer.Peer) *PeerDispatcher {
	return &PeerDispatcher{peer: p}
}

var _ relay.OutboundDispatcher = (*PeerDispatcher)(nil)

// DeliverInner implements §3.1.1 terminal-hop delivery — raw-frame.
//
// §3.1 pins the inner as a full materialized system/envelope {root, included}
// carrying its own signatures/caps. §9 + §10.4 forbid decoding or re-encoding
// the inner in any path including terminal delivery. So the only legal
// operation here is: copy inner.Data verbatim onto the destination's frame.
// The returned *handler.Response is always nil — any destination response
// flows back via INBOX deliver_to per §3.1, not through the relay.
func (d *PeerDispatcher) DeliverInner(ctx context.Context, destinationPeerID string, inner entity.Entity) (*handler.Response, error) {
	if inner.Type != types.TypeEnvelope {
		return nil, fmt.Errorf("relay terminal-hop: inner entity type %q, expected %q (raw-frame requires a system/envelope-typed inner per §3.1)",
			inner.Type, types.TypeEnvelope)
	}
	if len(inner.Data) == 0 {
		return nil, fmt.Errorf("relay terminal-hop: inner.Data empty — no raw envelope bytes to forward")
	}
	if err := d.peer.SendRawFrameTo(ctx, crypto.PeerID(destinationPeerID), []byte(inner.Data)); err != nil {
		if isUnreachable(err) {
			return nil, relay.ErrDestinationUnreachable
		}
		return nil, err
	}
	return nil, nil
}

// ForwardToNextHop implements §3.1.1 intermediate-hop forwarding.
func (d *PeerDispatcher) ForwardToNextHop(ctx context.Context, nextHopPeerID string, req types.ForwardRequestData, inner entity.Entity) (*handler.Response, error) {
	reqEnt, err := req.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("relay intermediate-hop: build forward-request entity: %w", err)
	}
	uri := "entity://" + nextHopPeerID + "/system/relay"
	extras := map[hash.Hash]entity.Entity{
		inner.ContentHash: inner,
	}
	resp, err := d.peer.RemoteExecuteWithIncluded(ctx, uri, "forward", reqEnt, nil, extras)
	if err != nil {
		if isUnreachable(err) {
			return nil, relay.ErrDestinationUnreachable
		}
		return nil, err
	}
	return resp, nil
}

// isUnreachable identifies the "no live session + can't dial" surface from
// core/peer so we can translate it to relay.ErrDestinationUnreachable. The
// peer layer surfaces these as wrapped errors with characteristic prefixes;
// we match on substring because there is no sentinel exported for the
// transport-profile-missing case.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	// Direct sentinel pass-through, if it ever bubbles up.
	if errors.Is(err, relay.ErrDestinationUnreachable) {
		return true
	}
	s := err.Error()
	for _, marker := range []string{
		"transport profile",
		"no transport",
		"connection refused",
		"i/o timeout",
		"remote connection",
		"dial",
	} {
		if containsFold(s, marker) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a := s[i+j]
			b := sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
