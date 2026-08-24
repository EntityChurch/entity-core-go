package signaling

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
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

// ErrNoIdentity reports a party with no signing keypair. Every §6.1 deposit is
// sealed, so a punch without an identity cannot make its first move — and the
// failure is raised at preflight rather than at the deposit, where it would read
// as a carrier fault.
var ErrNoIdentity = errors.New("signaling: punch party has no Identity keypair — every §6.1 deposit is sealed (§6.3)")

// ErrUnverifiedCounterpart reports a message that WAS ours to act on and did not
// arrive sealed, under a party demanding §6.3.
//
// IT IS RAISED, NOT SKIPPED, AND THAT IS THE WHOLE POINT OF ITS EXISTENCE. §6.4
// skips a blob that fails a check, and for a stranger's blob in a shared bucket
// that is right — it cannot be allowed to end someone else's exchange. But a
// message that already passed the nonce echo and the expected-peer filter is not
// a stranger's: it is OUR answer, arriving in the framing we no longer accept.
// Skipping it leaves the initiator polling a bucket that already holds its reply
// and eventually reporting a timeout — which reads as "nobody replied", which
// reads as a NAT problem, and gets diagnosed a week later as a migration state
// nobody was looking at. The policy is therefore applied AFTER the filters, so
// only a message that was ours to act on can raise this. (entity-core-rust's
// `VerificationUnavailable`, b1eb4b5 — same rule, same reasoning.)
var ErrUnverifiedCounterpart = errors.New("signaling: counterpart deposited an unsealed §6.1 message and this party requires §6.3")

// DialFunc dials remote over TCP from the bound local address. Production passes
// dialReusePort (SO_REUSEPORT, §7.3); tests inject a loopback dial. A nil DialFunc
// in PunchParty defaults to dialReusePort.
type DialFunc func(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error)

// Carrier is the punch's view of the rendezvous service (§4): deposit an opaque
// blob, and read a bucket back classified AND verified. The live signaling
// *Client satisfies it directly (Offer / CollectMessagesVerified), and an
// in-memory stub satisfies it for tests — the node is "an opaque blob store"
// (§4.4), so a minimal conforming store is a faithful stand-in.
//
// IT DEPOSITS BYTES, NOT AN ENTITY, and that is the shape of the flag day. The
// punch now seals every deposit into a §6.3 container itself (see deposit), so
// handing the carrier an entity to frame would put the framing decision in the
// one place that does not hold the signing key. The carrier stayed an entity
// interface for exactly as long as the deposit was bare.
type Carrier interface {
	Offer(ctx context.Context, key, message []byte) (uint, error)
	CollectMessagesVerified(ctx context.Context, key []byte) (uint, []CollectedMessage, []error, error)
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
// produced the srflx (§7.3), or the srflx candidate is a lie. Carrier and Key
// come from rendezvous (§3).
type PunchParty struct {
	Carrier Carrier
	Key     []byte

	// Identity is this peer's keypair — BOTH who it says it is and what it signs
	// with, deliberately not two fields.
	//
	// entity-core-rust reached the same place from the other side: they take the
	// signing key from the carrier's own identity rather than a second injected
	// keypair, and added an `IdentitySkew` refusal for a party whose `self_id`
	// and signing key disagree. The failure that check exists to catch is vicious
	// precisely because it is invisible from either end alone — a peer signs its
	// offers as one identity while the node logs `caller=` another, the node sees
	// one id, the counterpart sees the other, and every individual step reports
	// success while the bucket is derived from one id and the signature proves a
	// different one. Silent never-meet, `included_count=0`, nothing in the error
	// path.
	//
	// Go had a `SelfID string` beside the key, which is exactly the two-source
	// shape that makes the check necessary. Removing it is strictly better than
	// checking it: the id is DERIVED here (selfID), so there is no second source
	// to disagree, and the skew is not refused at runtime — it is unrepresentable.
	// This is the same argument as OpenBlob's derived-not-decoded peer-id, applied
	// to our own end of the wire.
	Identity crypto.Keypair

	// Trust is the §6.3 posture for everything this party COLLECTS. Required —
	// the zero value is not a policy (ErrPolicyUnset). Deposits are not governed
	// by it: this party always seals (see deposit), because a flag day where the
	// depositor is configurable is a flag day that never ends.
	Trust VerificationPolicy

	LocalCands []types.NetworkCandidateData
	LocalAddr  *net.TCPAddr
	Dial       DialFunc // nil → dialReusePort

	// CrossingRetries is the §7.2.1 crossing-retry count (local; costs only the
	// two peers). NOT the exchange budget — see defaultCrossingRetries.
	Poll            time.Duration // nil/0 → defaultPunchPoll
	CrossingRetries int           // 0 → defaultCrossingRetries
	DialTimeout     time.Duration // 0 → defaultDialTimeout
	ExchangeTimeout time.Duration // 0 → defaultExchangeTimeout

	// OnSelect observes the §7.1-step-4 socket outcome: which of the two paths
	// produced a connection, and which end this side kept. Nil-default and purely
	// observational — it cannot change the selection.
	//
	// It exists because the distinct-4-tuple tie-break is otherwise UNOBSERVABLE
	// from outside: a punch that converges looks identical whether one socket
	// formed (the §7.3 case) or two formed and the tie-break resolved them. A
	// harness asserting "the tie-break executed" without this is asserting a
	// negative it cannot see.
	OnSelect func(dialedFormed, acceptedFormed, keptDialed bool)

	// OnSkip observes each blob the §6.4 read rules dropped, with its taxonomy
	// error. Nil-default and purely observational.
	//
	// The folded §6.3 says the skip is wire-silent but SHOULD be locally
	// observable, and this is that SHOULD. The reason it is worth a hook rather
	// than a dropped return value: the Ed448 hardcode in a sibling impl survived
	// precisely BECAUSE a failed check is skipped and never raised — it locked
	// out an identity that implementation itself minted, and stayed invisible
	// until a vector row crossed it. Silence in the implementation is how that
	// class of defect lives.
	OnSkip func(error)
}

// selfID is this peer's canonical id, derived from Identity rather than stored.
// See the Identity field: one source, so there is nothing to disagree with.
func (pp *PunchParty) selfID() string { return pp.Identity.PeerID().String() }

// preflight refuses a party that cannot run, before it deposits anything.
//
// Both checks catch omissions — a zero keypair and a zero policy are what a
// struct literal produces when a field is forgotten — so they are raised at the
// entry points where a human wrote the literal, not deep inside a poll where
// they would surface as "nobody replied."
func (pp *PunchParty) preflight() error {
	if pp.Identity.IsZero() {
		return ErrNoIdentity
	}
	if pp.Trust != VerifyTolerant && pp.Trust != VerifyRequire {
		return ErrPolicyUnset
	}
	return nil
}

// deposit seals one coordination entity into a bucket-bound §6.3 container and
// offers it — the §6.1 half of the flag day.
//
// EVERY §6.1 DEPOSIT IS SEALED, unconditionally. §6.1 needs this more than §6.5
// did, for a reason §6.5 does not have: connect-request and connect-response
// carry `initiator` / `responder` AS WIRE FIELDS, so an unverified deposit lets
// anyone assert either id — and the expected-peer filter in awaitResponse is
// then comparing against a string the attacker wrote. The §6.5 payloads carry no
// peer-id at all, so there was nothing there to forge.
func (pp *PunchParty) deposit(ctx context.Context, e entity.Entity) (uint, error) {
	sealed, err := SealBlob(e, pp.Identity, pp.Key)
	if err != nil {
		return 0, fmt.Errorf("punch: seal deposit: %w", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		return 0, fmt.Errorf("punch: frame sealed deposit: %w", err)
	}
	return pp.Carrier.Offer(ctx, pp.Key, blob)
}

// collect reads the bucket under this party's policy, reporting every skip to
// OnSkip.
func (pp *PunchParty) collect(ctx context.Context) ([]CollectedMessage, error) {
	_, msgs, skipped, err := pp.Carrier.CollectMessagesVerified(ctx, pp.Key)
	if err != nil {
		return nil, err
	}
	if pp.OnSkip != nil {
		for _, e := range skipped {
			pp.OnSkip(e)
		}
	}
	return msgs, nil
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
	if err := pp.preflight(); err != nil {
		return nil, fmt.Errorf("punch: %w", err)
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("punch: nonce: %w", err)
	}

	// Step 2 (offer) — record send time for the rtt measurement (§7.2: the
	// initiator's offer to the collect that returns the response).
	reqEnt, err := types.ConnectRequestData{Candidates: pp.LocalCands, Initiator: pp.selfID(), Nonce: nonce}.ToEntity()
	if err != nil {
		return nil, fmt.Errorf("punch: build connect-request: %w", err)
	}
	tSent := time.Now()
	if status, err := pp.deposit(ctx, reqEnt); err != nil || status != 200 {
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
	if status, err := pp.deposit(ctx, syncEnt); err != nil || status != 200 {
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
	if err := pp.preflight(); err != nil {
		return nil, "", fmt.Errorf("punch: %w", err)
	}
	// Await a connect-request addressed at this rendezvous (not our own).
	req, initiator, err := pp.awaitRequest(ctx)
	if err != nil {
		return nil, "", err
	}

	respEnt, err := types.ConnectResponseData{Candidates: pp.LocalCands, Nonce: req.Nonce, Responder: pp.selfID()}.ToEntity()
	if err != nil {
		return nil, "", fmt.Errorf("punch: build connect-response: %w", err)
	}
	if status, err := pp.deposit(ctx, respEnt); err != nil || status != 200 {
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
	// The initiator id handed onward is the one awaitRequest authenticated — the
	// §6.3 signer when the request arrived sealed, the claimed `initiator` field
	// only in the bare window. It is the id the caller runs the §7.4 identity
	// check against, so sourcing it from the signature rather than from a field
	// the depositor wrote is the difference between checking an identity and
	// checking a string somebody sent us.
	conn, err := pp.fire(ctx, fireAt, target, initiator)
	if err != nil {
		return nil, "", err
	}
	return conn, initiator, nil
}

// fire sleeps until the scheduled instant, then opens the direct path to target
// from the shared local socket (§7.1 step 4). It de-conflates three layers the
// pre-G1 code fused into one peer-id compare:
//
//   - Hole-opening (§7.1 step 4, MUST): BOTH sides always dial outbound. A NAT
//     opens a mapping only for a socket that has SENT a packet, so a listen-only
//     side never opens its hole and the counterpart's SYN hits a wall. This is
//     invisible on loopback (no NAT), which is exactly how the retracted
//     lower-dials/higher-listens shape passed both impls — so the correctness of
//     both-fire cannot be observed here, only asserted (the both-dialed test).
//   - Crossing reliability: BOTH sides also listen on the same REUSEPORT port, so
//     a dial lands on a listener rather than depending on the fragile instant both
//     sockets are in SYN_SENT together. Simultaneous-open can therefore yield TWO
//     sockets (each side's dial landing on the other's listener).
//   - Socket-selection: KEEP WHICHEVER connection formed. Under §7.3's shared
//     REUSEPORT socket the two directions share ONE 4-tuple, so exactly one
//     connection exists — reached via this side's connect() (simultaneous-open, or
//     a dial that landed on the peer's listener) OR via this side's accept() (the
//     peer's dial landing on our listener). A given side cannot predict which, so
//     it takes the one that formed, however it came. Both ends then hold the two
//     halves of that single connection — it converges without a tie-break. The
//     peer-id compare is retained ONLY for the distinct-4-tuple racing case (a
//     side holding BOTH a dialed and an accepted socket — not reachable on the
//     reuseport substrate, kept as defense): lower id keeps its dialed end, higher
//     keeps its accepted end, and the loser is closed. Nil on both paths → punch
//     failed, fall through to relay (§10.3).
//
// peerID is the counterpart's id for the tie-break. Context cancel aborts
// throughout (the §10.3 cancellable-seam delta). The entity handshake role
// (§7.4.1) is independent of all of this: the caller applies its fixed signaling
// role (initiator → PerformConnect, responder → serve) over whichever end it
// kept. "Responder serves" governs the HELLO on the already-open socket, not who
// dialed on the wire — on the wire both dial.
func (pp *PunchParty) fire(ctx context.Context, fireAt time.Time, target, peerID string) (net.Conn, error) {
	if err := sleepUntil(ctx, fireAt); err != nil {
		return nil, err
	}
	fireCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Both fire: dial (opens OUR hole, §7.1 step 4) AND listen (catches the peer's
	// dial). Each goroutine sends EXACTLY ONE value (a conn or nil) to its buffered
	// channel and exits, so both are always collectable without leaking a socket.
	dialedCh := make(chan net.Conn, 1)
	acceptedCh := make(chan net.Conn, 1)
	go func() { dialedCh <- pp.dialLoop(fireCtx, target) }() // nil on exhaustion/cancel
	go func() {
		c, err := pp.listenAccept(fireCtx, target)
		if err != nil {
			c = nil
		}
		acceptedCh <- c
	}()

	// Take the first connection from either path, then cancel to wind the other
	// path down and collect its result (a nil once cancelled, or a genuine racing
	// socket that had already landed). Either goroutine returns promptly on cancel,
	// so the second collect does not block. The crossing-retry budget (§7.2.1) is
	// fully available until the first success, since we only cancel after one lands.
	var dialed, accepted net.Conn
	select {
	case dialed = <-dialedCh:
		cancel()
		accepted = <-acceptedCh
	case accepted = <-acceptedCh:
		cancel()
		dialed = <-dialedCh
	case <-fireCtx.Done():
		cancel()
		dialed = <-dialedCh
		accepted = <-acceptedCh
	}

	kept, loser := selectSocket(dialed, accepted, pp.selfID() < peerID)
	if pp.OnSelect != nil {
		pp.OnSelect(dialed != nil, accepted != nil, kept != nil && kept == dialed)
	}
	if loser != nil {
		loser.Close()
	}
	if kept == nil {
		return nil, fmt.Errorf("punch: no direct path to %s (%d crossing retries, %v)",
			target, pp.crossingRetries(), context.Cause(fireCtx))
	}
	return kept, nil
}

// selectSocket picks the surviving connection from a punch's two paths. Normally
// only one formed (the §7.3 single-4-tuple case) and it is kept whichever way it
// came. If BOTH formed (distinct-4-tuple racing open), keepDialedOnRace — the
// peer-id tie-break — keeps one end deterministically and returns the other as
// the loser to close, so both peers converge on the same connection.
func selectSocket(dialed, accepted net.Conn, keepDialedOnRace bool) (kept, loser net.Conn) {
	switch {
	case dialed != nil && accepted != nil:
		if keepDialedOnRace {
			return dialed, accepted
		}
		return accepted, dialed
	case dialed != nil:
		return dialed, nil
	default:
		return accepted, nil // accepted or nil
	}
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
		// Never invoke dial on an already-cancelled context: a cancelled dial is a
		// no-op that issues no SYN, so calling it would let a dialed_outbound tap
		// (the §7.1 step-4 both-fire cross-impl signal) fire without a real outbound
		// connect ever leaving the shared endpoint. Checking here means the tap
		// records only genuine dial attempts under a live context.
		if ctx.Err() != nil {
			return nil
		}
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

// requireSealed applies this party's §6.3 posture to a message that has ALREADY
// passed every correlation filter — the last gate, never the first.
//
// The ordering is the rule, not an implementation detail: policy after the
// filters means an unsealed blob can only ever raise ErrUnverifiedCounterpart if
// it was ours to act on. A stranger's unsealed deposit in a shared lobby bucket
// never reaches here — it fails the nonce echo or the skip-own first and is
// skipped under §6.4, so it cannot end an exchange it was not part of. Getting
// this backwards would hand any passer-by a way to kill a punch by depositing a
// bare entity into a bucket it happened to know.
func (pp *PunchParty) requireSealed(signer VerifiedSigner, what string) error {
	if pp.Trust == VerifyRequire && signer.PeerID == "" {
		return fmt.Errorf("punch: %w (%s)", ErrUnverifiedCounterpart, what)
	}
	return nil
}

// awaitResponse polls the carrier until expectedID's nonce-matched connect-
// response appears or the exchange deadline elapses. Returns the response and
// its authenticated responder id.
func (pp *PunchParty) awaitResponse(ctx context.Context, nonce []byte, expectedID string) (*types.ConnectResponseData, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		msgs, err := pp.collect(ctx)
		if err != nil {
			return nil, fmt.Errorf("punch: collect (response): %w", err)
		}
		if resp, signer, ok := FindResponse(msgs, nonce, pp.selfID()); ok {
			// The expected-peer filter runs against the SIGNER when the response
			// arrived sealed. Comparing against `responder` — a field the
			// depositor wrote — is a filter an impostor passes by typing the
			// right name into it, which is the §6.1-specific exposure the
			// container closes.
			responder := signer.PeerID
			if responder == "" {
				responder = resp.Responder
			}
			if expectedID != "" && responder != expectedID {
				// A different peer answered our shared-bucket request; keep waiting
				// for the one we intend to reach (§6.4 correlate-by-identity).
			} else {
				if err := pp.requireSealed(signer, "connect-response"); err != nil {
					return nil, err
				}
				return resp, nil
			}
		}
		if err := waitPoll(ctx, pp.poll(), deadline); err != nil {
			return nil, err
		}
	}
}

// awaitRequest polls until a connect-request from a peer other than self
// appears. Returns the request and its authenticated initiator id.
func (pp *PunchParty) awaitRequest(ctx context.Context) (*types.ConnectRequestData, string, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		msgs, err := pp.collect(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("punch: collect (request): %w", err)
		}
		if req, signer, ok := FindRequest(msgs, pp.selfID()); ok {
			if err := pp.requireSealed(signer, "connect-request"); err != nil {
				return nil, "", err
			}
			initiator := signer.PeerID
			if initiator == "" {
				initiator = req.Initiator
			}
			return req, initiator, nil
		}
		if err := waitPoll(ctx, pp.poll(), deadline); err != nil {
			return nil, "", err
		}
	}
}

// awaitSync polls until a punch-sync echoing nonce appears.
//
// punch-sync names nobody, so the nonce echo is the whole of the correlation and
// §6.3 step 3 has nothing to compare — the position all three §6.5 payloads are
// in. It still decides WHEN THIS PEER FIRES, so an unsealed one is refused under
// VerifyRequire exactly like the other two: a forged fire_at desynchronizes the
// crossing just as effectively as a forged candidate misdirects it.
func (pp *PunchParty) awaitSync(ctx context.Context, nonce []byte) (*types.PunchSyncData, error) {
	deadline := time.Now().Add(pp.exchangeTimeout())
	for {
		msgs, err := pp.collect(ctx)
		if err != nil {
			return nil, fmt.Errorf("punch: collect (sync): %w", err)
		}
		for _, m := range msgs {
			if m.Kind == KindPunchSync && bytes.Equal(m.Sync.Nonce, nonce) {
				if err := pp.requireSealed(m.Signer, "punch-sync"); err != nil {
					return nil, err
				}
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
