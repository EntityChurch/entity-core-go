package signaling

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The §7 punch — the choreography registered behind NETWORK §10.3's
// establish_live seam. NETWORK owns the seam and the resulting transport's
// obligations (pooling, §5 keepalive); this owns steps 1–6 of §7.1: gather,
// exchange over the carrier, measure-and-schedule, simultaneous-open, and the
// §7.4 connectivity check. Producing the *peer.Connection from the punched
// net.Conn is core/peer's job (ConnectVia / ServeConn); this package stays
// core-only and hands back a raw net.Conn plus the observed remote peer-id, so
// the cmd-layer adapter (which may import both ext/network for gathering and
// core/peer for the seams) does the wrapping.
//
// Two roles, asymmetric trigger. The side that wants to reach a peer is the
// INITIATOR (Initiate — the body of a NETWORK §10.3 LiveEstablishFunc). The side
// that answers is the RESPONDER (Respond — driven by a background loop watching
// the peer's rendezvous keys). The punch itself is symmetric (both dial), but
// the handshake role is not: the initiator runs the client handshake
// (PerformConnect), the responder serves (ServeConn), so exactly one HELLO is
// sent.

// DialFunc dials remote over TCP from the bound local address. Production passes
// dialReusePort (SO_REUSEPORT, §7.3); tests inject a loopback dial. A nil DialFunc
// in PunchParty defaults to dialReusePort.
type DialFunc func(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error)

// Carrier is the punch's view of the rendezvous service (§4): deposit a
// coordination entity as an opaque blob, and read a bucket back classified. The
// live signaling *Client satisfies it directly (OfferMessage / CollectMessages),
// and an in-memory stub satisfies it for tests — the node is "an opaque blob
// store" (§4.4), so a minimal conforming store is a faithful stand-in.
type Carrier interface {
	OfferMessage(ctx context.Context, key []byte, e entity.Entity) (uint, error)
	CollectMessages(ctx context.Context, key []byte) (uint, []CollectedMessage, error)
}

// Punch tunables. All are §7.2 implementation-defined (local, MAY diverge) —
// they do not touch the interoperable surface (the fire_at clock domain and
// encoding, which live in PunchDelay / PunchSyncData).
const (
	// defaultPunchPoll is the carrier poll cadence while awaiting a counterpart's
	// blob. Matches the cohort's 200 ms (Python/Go signaling-meet).
	defaultPunchPoll = 200 * time.Millisecond
	// defaultCrossingRetries is the §7.2.1 CROSSING-retry count: how many
	// simultaneous-open dials to fire at the counterpart's already-known srflx
	// within one crossing window. Each dial costs ONLY the two peers (packets go
	// to the target's own socket), so this is purely local and tuned freely —
	// §7.2.1's "MUST NOT starve the crossing" forbids cutting it to satisfy the
	// exchange budget. The distinct EXCHANGE attempt (fresh nonce + fresh reflector
	// gathering + fresh carrier round trip — the layer that costs third parties) is
	// one Coordinator.Establish call; Go does not loop it here.
	defaultCrossingRetries = 3
	// defaultDialTimeout bounds one simultaneous-open dial attempt.
	defaultDialTimeout = 2 * time.Second
	// defaultExchangeTimeout bounds the whole carrier exchange (offer→collect)
	// before abandoning to the relay fallback.
	defaultExchangeTimeout = 15 * time.Second
)

// PunchParty is one side's inputs to a punch. LocalCands are this peer's gathered
// candidates (host/srflx/relay, §6.7.3) to advertise; LocalAddr is the shared
// local endpoint the punch dials MUST bind — the SAME socket whose mapping
// produced the srflx (§7.3), or the srflx candidate is a lie. Carrier, Key, and
// SelfID come from rendezvous (§3).
type PunchParty struct {
	Carrier    Carrier
	Key        []byte
	SelfID     string
	LocalCands []types.NetworkCandidateData
	LocalAddr  *net.TCPAddr
	Dial       DialFunc // nil → dialReusePort

	// CrossingRetries is the §7.2.1 crossing-retry count (local; costs only the
	// two peers). NOT the exchange budget — see defaultCrossingRetries.
	Poll            time.Duration // nil/0 → defaultPunchPoll
	CrossingRetries int           // 0 → defaultCrossingRetries
	DialTimeout     time.Duration // 0 → defaultDialTimeout
	ExchangeTimeout time.Duration // 0 → defaultExchangeTimeout
}

func (pp *PunchParty) dial() DialFunc {
	if pp.Dial != nil {
		return pp.Dial
	}
	return dialReusePort
}
func (pp *PunchParty) poll() time.Duration {
	if pp.Poll > 0 {
		return pp.Poll
	}
	return defaultPunchPoll
}
func (pp *PunchParty) crossingRetries() int {
	if pp.CrossingRetries > 0 {
		return pp.CrossingRetries
	}
	return defaultCrossingRetries
}
func (pp *PunchParty) dialTimeout() time.Duration {
	if pp.DialTimeout > 0 {
		return pp.DialTimeout
	}
	return defaultDialTimeout
}
func (pp *PunchParty) exchangeTimeout() time.Duration {
	if pp.ExchangeTimeout > 0 {
		return pp.ExchangeTimeout
	}
	return defaultExchangeTimeout
}

// Initiate runs the §7.1 initiator flow (steps 1–4) and returns the punched
// net.Conn. expectedID is the peer we intend to reach; the response MUST carry
// its peer-id (a shared-bucket answer from anyone else is skipped, §6.4). The
// caller wraps the conn with peer.ConnectVia + PerformConnect for the §7.4
// identity check. A nil conn with nil error never happens — a failed punch is an
// error, which the §10.3 seam maps to "fall through to relay."
func (pp *PunchParty) Initiate(ctx context.Context, expectedID string) (net.Conn, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("punch: nonce: %w", err)
	}

	// Step 2 (offer) — record send time for the rtt measurement (§7.2: the
	// initiator's offer to the collect that returns the response).
	reqEnt, err := types.ConnectRequestData{Candidates: pp.LocalCands, Initiator: pp.SelfID, Nonce: nonce}.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("punch: build connect-request: %w", err)
	}
	tSent := time.Now()
	if status, err := pp.Carrier.OfferMessage(ctx, pp.Key, reqEnt); err != nil || status != 200 {
		return nil, fmt.Errorf("punch: offer connect-request: status %d err %w", status, err)
	}

	// Step 2 (collect) — poll until expectedID's nonce-matched response lands.
	resp, err := pp.awaitResponse(ctx, nonce, expectedID)
	if err != nil {
		return nil, err
	}
	rttMs := uint64(time.Since(tSent).Milliseconds())

	// Step 3 (schedule) — d = max(rtt, floor); punch-sync carries d as a delay
	// from receipt (§7.2). The initiator fires at d after SENDING punch-sync.
	d := PunchDelay(rttMs)
	syncEnt, err := types.PunchSyncData{FireAt: d, Nonce: nonce}.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("punch: build punch-sync: %w", err)
	}
	if status, err := pp.Carrier.OfferMessage(ctx, pp.Key, syncEnt); err != nil || status != 200 {
		return nil, fmt.Errorf("punch: offer punch-sync: status %d err %w", status, err)
	}
	fireAt := time.Now().Add(time.Duration(d) * time.Millisecond)

	// Step 4 (punch) — simultaneous open toward the responder's srflx.
	target, ok := dialTarget(resp.Candidates)
	if !ok {
		return nil, fmt.Errorf("punch: responder advertised no dialable candidate")
	}
	return pp.fire(ctx, fireAt, target, expectedID)
}

// Respond runs the §7.1 responder flow: answer an incoming connect-request and
// punch back. It returns the punched net.Conn and the initiator's peer-id (the
// caller serves the conn with peer.ServeConn). The request is located by the
// bucket-read rules (§6.4): a request from anyone but self, oldest first.
func (pp *PunchParty) Respond(ctx context.Context) (net.Conn, string, error) {
	// Await a connect-request addressed at this rendezvous (not our own).
	req, err := pp.awaitRequest(ctx)
	if err != nil {
		return nil, "", err
	}

	respEnt, err := types.ConnectResponseData{Candidates: pp.LocalCands, Nonce: req.Nonce, Responder: pp.SelfID}.ToEntity()
	if err != nil {
		return nil, "", fmt.Errorf("punch: build connect-response: %w", err)
	}
	if status, err := pp.Carrier.OfferMessage(ctx, pp.Key, respEnt); err != nil || status != 200 {
		return nil, "", fmt.Errorf("punch: offer connect-response: status %d err %w", status, err)
	}

	// Await punch-sync for our nonce; the responder fires at d after RECEIVING it.
	sync, err := pp.awaitSync(ctx, req.Nonce)
	if err != nil {
		return nil, "", err
	}
	fireAt := time.Now().Add(time.Duration(sync.FireAt) * time.Millisecond)

	target, ok := dialTarget(req.Candidates)
	if !ok {
		return nil, "", fmt.Errorf("punch: initiator advertised no dialable candidate")
	}
	conn, err := pp.fire(ctx, fireAt, target, req.Initiator)
	if err != nil {
		return nil, "", err
	}
	return conn, req.Initiator, nil
}

// fire sleeps until the scheduled instant, then opens the direct path to target
// from the shared local socket (§7.1 step 4). Both peers dial — that is what
// opens both NAT holes — AND both listen on the same REUSEPORT port, so a peer's
// dial always lands rather than being refused between our own dial attempts
// (pure both-only-dial simultaneous-open connects only in the fragile instant
// both sockets are in SYN_SENT). Two connections can form (each side's dial
// lands on the other's listener); a deterministic tiebreak keeps exactly ONE on
// both sides: the connection the LOWER peer-id dialed survives. So the smaller
// id keeps its DIALED conn and the larger keeps its ACCEPTED conn — the two ends
// of the same TCP connection. peerID is the counterpart's id for that compare.
// Context cancel aborts throughout (the §10.3 cancellable-seam delta).
//
// The entity handshake role is independent of which end dialed: the caller
// applies its fixed role (initiator → PerformConnect, responder → serve) over
// whichever end it kept.
func (pp *PunchParty) fire(ctx context.Context, fireAt time.Time, target, peerID string) (net.Conn, error) {
	if err := sleepUntil(ctx, fireAt); err != nil {
		return nil, err
	}
	fireCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Deterministic role split so both sides converge on ONE connection without
	// depending on the fragile instant both SYNs cross in flight: the LOWER
	// peer-id dials the counterpart's srflx from the shared REUSEPORT socket; the
	// HIGHER listens on that same port and accepts. Either outcome binds each
	// side's advertised srflx port (§7.3) and is bidirectional, so the entity
	// handshake role (initiator→PerformConnect, responder→serve) applies over it
	// unchanged — the TCP dialer/acceptor split is independent of who sends HELLO.
	//
	// This is the loopback-reliable establishment. §7.5 cross-NAT gate: under real
	// NAT the LISTENING side must also emit an outbound packet toward the dialer's
	// srflx to open its OWN mapping before the dial arrives — the dual-hole
	// sequencing (and its TCP 4-tuple hazards) is hardened against real NAT there,
	// not on loopback where there is no mapping to open. See
	// docs/architecture/guides/PUNCH-SOCKET-REQUIREMENTS.md.
	if pp.SelfID < peerID {
		conn := pp.dialLoop(fireCtx, target)
		if conn == nil {
			return nil, fmt.Errorf("punch: dial to %s failed after %d crossing retries (%v)", target, pp.crossingRetries(), context.Cause(fireCtx))
		}
		return conn, nil
	}
	return pp.listenAccept(fireCtx, target)
}

// listenAccept binds the shared local port as a listener (SO_REUSEPORT — the
// same port the srflx was gathered on, §7.3) and returns the first accepted
// connection, bounded to the same window the dialer retries within so a peer
// that never appears does not hang the punch.
func (pp *PunchParty) listenAccept(ctx context.Context, target string) (net.Conn, error) {
	ln, err := listenReusePort(pp.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("punch: listen on shared local port: %w", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	accErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accErr <- err
			return
		}
		accepted <- c
	}()

	window := time.Duration(pp.crossingRetries()) * (pp.dialTimeout() + pp.poll())
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	select {
	case c := <-accepted:
		return c, nil
	case err := <-accErr:
		return nil, fmt.Errorf("punch: accept on shared local port: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-deadline.C:
		return nil, fmt.Errorf("punch: no inbound direct path within %s", window)
	}
}

// dialLoop retries dialReusePort (or the injected Dial) until it connects or the
// context is cancelled, returning nil on cancel/exhaustion. This is the §7.2.1
// CROSSING retry: the peer's listener may not be up at the first dial, and each
// dial goes only to the target's own socket — so it MUST NOT be starved to satisfy
// the exchange budget (§7.2.1).
func (pp *PunchParty) dialLoop(ctx context.Context, target string) net.Conn {
	dial := pp.dial()
	for i := 0; i < pp.crossingRetries(); i++ {
		dctx, cancel := context.WithTimeout(ctx, pp.dialTimeout())
		conn, err := dial(dctx, pp.LocalAddr, target)
		cancel()
		if err == nil {
			return conn
		}
		if ctx.Err() != nil {
			return nil
		}
		if err := sleepUntil(ctx, time.Now().Add(pp.poll())); err != nil {
			return nil
		}
	}
	return nil
}

// awaitResponse polls the carrier until expectedID's nonce-matched connect-
// response appears or the exchange deadline elapses.
func (pp *PunchParty) awaitResponse(ctx context.Context, nonce []byte, expectedID string) (*types.ConnectResponseData, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		_, msgs, err := pp.Carrier.CollectMessages(ctx, pp.Key)
		if err != nil {
			return nil, fmt.Errorf("punch: collect (response): %w", err)
		}
		if resp, ok := FindResponse(msgs, nonce, pp.SelfID); ok {
			if expectedID != "" && resp.Responder != expectedID {
				// A different peer answered our shared-bucket request; keep waiting
				// for the one we intend to reach (§6.4 correlate-by-identity).
			} else {
				return resp, nil
			}
		}
		if err := waitPoll(ctx, pp.poll(), deadline); err != nil {
			return nil, err
		}
	}
}

// awaitRequest polls until a connect-request from a peer other than self appears.
func (pp *PunchParty) awaitRequest(ctx context.Context) (*types.ConnectRequestData, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		_, msgs, err := pp.Carrier.CollectMessages(ctx, pp.Key)
		if err != nil {
			return nil, fmt.Errorf("punch: collect (request): %w", err)
		}
		if req, ok := FindRequest(msgs, pp.SelfID); ok {
			return req, nil
		}
		if err := waitPoll(ctx, pp.poll(), deadline); err != nil {
			return nil, err
		}
	}
}

// awaitSync polls until a punch-sync echoing nonce appears.
func (pp *PunchParty) awaitSync(ctx context.Context, nonce []byte) (*types.PunchSyncData, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		_, msgs, err := pp.Carrier.CollectMessages(ctx, pp.Key)
		if err != nil {
			return nil, fmt.Errorf("punch: collect (sync): %w", err)
		}
		for _, m := range msgs {
			if m.Kind == KindPunchSync && bytes.Equal(m.Sync.Nonce, nonce) {
				return m.Sync, nil
			}
		}
		if err := waitPoll(ctx, pp.poll(), deadline); err != nil {
			return nil, err
		}
	}
}

// dialTarget picks the address to punch toward from a remote candidate list: the
// srflx (the §7.1 hole-punch target) if present, else the first candidate in
// §6.7.3 try order (host → srflx → relay). Returns false for an empty list.
func dialTarget(cands []types.NetworkCandidateData) (string, bool) {
	ordered := OrderForDialing(cands)
	for _, c := range ordered {
		if c.Type == types.CandidateTypeSrflx {
			return c.Address, true
		}
	}
	if len(ordered) > 0 {
		return ordered[0].Address, true
	}
	return "", false
}

// sleepUntil blocks until t, or returns ctx.Err() if the context is cancelled
// first. A t already in the past returns immediately.
func sleepUntil(ctx context.Context, t time.Time) error {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// waitPoll sleeps one poll interval, returning an error if the context is
// cancelled or the exchange deadline has passed.
func waitPoll(ctx context.Context, interval time.Duration, deadline time.Time) error {
	if time.Now().After(deadline) {
		return fmt.Errorf("punch: carrier exchange timed out")
	}
	return sleepUntil(ctx, time.Now().Add(interval))
}
