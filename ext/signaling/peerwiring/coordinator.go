// Package peerwiring bridges the ext/signaling §7 punch to a live core/peer.Peer,
// mirroring ext/relay/peerwiring. The punch algorithm (ext/signaling) is
// core-only and hands back a raw net.Conn; this package supplies the peer:
// Establish is the EXTENSION-NETWORK §10.3 LiveEstablishFunc a peer registers via
// SetLiveEstablish (the initiator half), and Respond is the responder half that a
// background loop drives on the peer's rendezvous keys. Producing the
// *peer.Connection (ConnectVia / ServeConn + PerformConnect + the §7.4 identity
// check) lives here so ext/signaling stays free of core/peer.
//
// What this package does NOT decide (injected by the cmd layer): candidate
// gathering (ext/network §6.7.3 + the srflx from a reflector), node selection
// from the pool + carrier construction, and the rendezvous-key mode. Injecting
// them keeps this package off ext/network and lets the caller own the policy.
package peerwiring

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// GatherFunc returns this peer's punch candidates (§6.7.3) and the shared local
// address the punch dials MUST bind — the SAME socket whose mapping produced the
// srflx (§7.3). Supplied via ext/network so this package need not import it.
type GatherFunc func(ctx context.Context) (local *net.TCPAddr, cands []types.NetworkCandidateData, err error)

// CarrierFunc returns a rendezvous carrier for a derived key: the cmd layer
// selects the pool member (§3.4) and builds a *signaling.Client, which satisfies
// signaling.Carrier.
type CarrierFunc func(ctx context.Context, key []byte) (signaling.Carrier, error)

// KeyFunc derives the rendezvous key that connects self to peer. The default
// (DefaultKeyFunc) is pair mode — signaling.PairKey, which is symmetric so both
// sides derive the same bucket.
type KeyFunc func(self, peer crypto.PeerID) ([]byte, error)

// DefaultKeyFunc derives the §3 pair-mode rendezvous key for the two peers.
func DefaultKeyFunc(self, peer crypto.PeerID) ([]byte, error) {
	return signaling.PairKey(self.String(), peer.String())
}

// Coordinator adapts the punch to a peer. Construct with New and register
// Establish via peer.SetLiveEstablish; run Respond (or a loop over it) to be
// reachable.
type Coordinator struct {
	peer    *peer.Peer
	gather  GatherFunc
	carrier CarrierFunc
	keyFor  KeyFunc

	trust signaling.VerificationPolicy

	poll            time.Duration
	crossingRetries int
	dialTimeout     time.Duration
	exchangeTimeout time.Duration
}

// Option tunes a Coordinator (all forwarded to the PunchParty; every one is §7.2
// implementation-defined — none touch the interoperable fire_at surface).
type Option func(*Coordinator)

// WithPoll sets the carrier poll cadence.
func WithPoll(d time.Duration) Option { return func(c *Coordinator) { c.poll = d } }

// WithCrossingRetries sets the §7.2.1 crossing-retry count — the number of
// simultaneous-open dials per crossing window (local; costs only the two peers).
// This is NOT the exchange budget; see EXTENSION-SIGNALING §7.2.1.
func WithCrossingRetries(n int) Option { return func(c *Coordinator) { c.crossingRetries = n } }

// WithDialTimeout bounds one establishment dial attempt.
func WithDialTimeout(d time.Duration) Option { return func(c *Coordinator) { c.dialTimeout = d } }

// WithExchangeTimeout bounds the whole carrier exchange before abandoning to the
// relay fallback (§10).
func WithExchangeTimeout(d time.Duration) Option {
	return func(c *Coordinator) { c.exchangeTimeout = d }
}

// WithTrust overrides the §6.3 collect posture for this coordinator's punches.
// See DefaultTrust for why the default is what it is and when it moves.
func WithTrust(p signaling.VerificationPolicy) Option {
	return func(c *Coordinator) { c.trust = p }
}

// DefaultTrust is the §6.3 posture of the native punch, named once here rather
// than defaulted inside the party — the Go counterpart of entity-core-rust's
// `PUNCH_TRUST` (core/peer/src/punch_establisher.rs).
//
// **THE §6.1 FLAG DAY IS CLOSED. This was the last line in it.** An unsealed
// coordination message is now refused, which is what §6.3's MUST asks for and
// what the tolerant window existed to reach without breaking anyone on the way.
//
// What licensed the flip, in order:
//
//   - Both implementations read AND seal. Go at `d56a690`, rust immediately
//     after; the migration window it existed for is over.
//   - rust raised their `PUNCH_TRUST` first, on a live cross-impl sealed punch
//     with both seats over the agreed CLI/JSON contract.
//   - Our own collector was then proven to ENFORCE, not merely to interoperate:
//     `signaling-punch --trust require` completes Go↔Go over a live node, and a
//     bare depositor built from our own pre-flip commit is refused BY NAME
//     rather than by timeout. A tolerant run could never have shown this — it
//     admits an unsealed counterpart, so it cannot distinguish a peer that
//     sealed from one that never did. Require is the assay.
//   - The refusal is observable. `core/peer`'s §10.3 seam used to discard the
//     reason entirely, which would have made this flip present as a NAT problem
//     the first time it fired. Fixed before flipping, not after.
//
// **`entity-core-py` is unaffected**: it implements the §4 signaling client but
// does not punch (`signaling/coordination.py` says so, and carries no
// signed-blob support), so it never enters the path this constant governs. When
// Python does build the punch it will need to seal from the start — there is no
// tolerant window left to arrive into, and that is deliberate.
//
// The bound this replaces is worth keeping in view rather than deleting, since
// it is why the window was survivable at all: THE KEY INTRODUCES, IT NEVER
// AUTHORIZES. A punched connection still runs the full §7.4 handshake and the
// capability flow, so even a forged coordination message only ever bought a
// wasted dial, never an authorized stranger. That made the migration safe; it
// was never a reason to leave it open.
const DefaultTrust = signaling.VerifyRequire

// New builds a Coordinator for p. A nil keyFor defaults to pair mode.
func New(p *peer.Peer, gather GatherFunc, carrier CarrierFunc, keyFor KeyFunc, opts ...Option) *Coordinator {
	if keyFor == nil {
		keyFor = DefaultKeyFunc
	}
	c := &Coordinator{peer: p, gather: gather, carrier: carrier, keyFor: keyFor, trust: DefaultTrust}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Establish is the EXTENSION-NETWORK §10.3 LiveEstablishFunc (register via
// peer.SetLiveEstablish). It runs the §7.1 initiator flow to peerID and, on a
// direct path, wraps it with PerformConnect and the §7.4 identity check. Per the
// seam contract, a returned error (or the identity check failing) is the
// "fall through to the relay fallback" signal — never a hard dispatch failure.
func (c *Coordinator) Establish(ctx context.Context, peerID crypto.PeerID) (*peer.Connection, error) {
	self := c.peer.PeerID()
	party, err := c.party(ctx, self, peerID)
	if err != nil {
		return nil, err
	}

	// §10.3 obligation 4 / SIGNALING §7.2 (budgets MUST NOT nest): Establish runs
	// exactly ONE carrier exchange — the offer/collect against the reflector and
	// signaling peers, the only work that touches third parties. It is never looped
	// here, so when driven by a §4.1 maintain-peer reconnection the punch spends one
	// exchange per backoff tick and §4.1 owns re-scheduling. (party.CrossingRetries is the
	// intra-crossing dial-retry against the TARGET's own socket — a local reliability
	// knob, not the third-party budget — so it is deliberately NOT reduced under
	// caller-owned retry; doing so only makes the crossing miss.) peer.CallerOwnsRetry
	// carries the boundary to this seam so that if a §7.2 multi-exchange budget is
	// ever added, the reconnect path stays single-exchange.
	raw, err := party.Initiate(ctx, peerID.String())
	if err != nil {
		return nil, fmt.Errorf("punch: initiate to %s: %w", peerID, err)
	}

	conn := c.peer.ConnectVia(raw)
	if err := conn.PerformConnect(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("punch: handshake over punched path to %s: %w", peerID, err)
	}
	// §7.4: the punched path MUST authenticate as the EXPECTED peer. A forged
	// candidate that reaches some other peer fails closed to the relay fallback.
	if got := conn.Session().RemotePeerID; got != peerID {
		conn.Close()
		return nil, fmt.Errorf("punch: path authenticated as %s, want %s (§7.4 identity binding)", got, peerID)
	}
	return conn, nil
}

// Respond runs the §7.1 responder flow once on key: it awaits and answers an
// incoming connect-request, punches back, and serves the resulting connection as
// a server (peer.ServeConn) so the initiator's handshake completes. Returns the
// initiator's peer-id. A background loop calls this repeatedly to stay reachable;
// an exchange timeout (no request arrived) is a normal, non-fatal outcome.
func (c *Coordinator) Respond(ctx context.Context, key []byte) (crypto.PeerID, error) {
	party, err := c.partyForKey(ctx, key)
	if err != nil {
		return "", err
	}
	raw, initiator, err := party.Respond(ctx)
	if err != nil {
		return "", err
	}
	c.peer.ServeConn(raw)
	return crypto.PeerID(initiator), nil
}

// RunResponder loops Respond on key until ctx is cancelled, staying reachable for
// incoming punches. Each answered punch serves a connection; exchange timeouts
// (nobody called) just re-arm the next poll. Returns ctx.Err() on cancellation.
func (c *Coordinator) RunResponder(ctx context.Context, key []byte) error {
	for ctx.Err() == nil {
		if _, err := c.Respond(ctx, key); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// party derives the rendezvous key for peerID and assembles a PunchParty.
func (c *Coordinator) party(ctx context.Context, self, peerID crypto.PeerID) (*signaling.PunchParty, error) {
	key, err := c.keyFor(self, peerID)
	if err != nil {
		return nil, fmt.Errorf("punch: derive rendezvous key for %s: %w", peerID, err)
	}
	return c.partyForKey(ctx, key)
}

// partyForKey assembles a PunchParty for an already-derived key: it gathers this
// peer's candidates + shared bind and builds the carrier.
func (c *Coordinator) partyForKey(ctx context.Context, key []byte) (*signaling.PunchParty, error) {
	local, cands, err := c.gather(ctx)
	if err != nil {
		return nil, fmt.Errorf("punch: gather candidates: %w", err)
	}
	carrier, err := c.carrier(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("punch: build carrier: %w", err)
	}
	return &signaling.PunchParty{
		Carrier: carrier,
		Key:     key,
		// The signing key and the identity are ONE source — the peer's own
		// keypair, which is also what `self` was derived from. The party derives
		// its id from it rather than being handed a string beside it, so a
		// coordinator cannot wire a peer that signs as one identity and addresses
		// itself as another.
		Identity:        c.peer.Keypair(),
		Trust:           c.trust,
		LocalCands:      cands,
		LocalAddr:       local,
		Poll:            c.poll,
		CrossingRetries: c.crossingRetries,
		DialTimeout:     c.dialTimeout,
		ExchangeTimeout: c.exchangeTimeout,
	}, nil
}
