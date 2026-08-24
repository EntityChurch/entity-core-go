// Command signaling-punch plays ONE role of ONE §7 hole punch as a process —
// Go's half of the cross-process go↔rust (or go↔py) punch. It is the live
// coordination + socket half of the §11.5 gate: two independent implementations,
// each a separate process on one host, coordinate through a lobby over a real
// node and complete a §7 punch to a working direct path over loopback. (Loopback
// has no NAT, so the true dual-hole traversal is the separate emulated-NAT rung;
// what this proves cross-impl is the coordination protocol + the socket
// choreography + a verified operation over the punched transport.)
//
// It speaks the same CLI + JSON contract shape as signaling-meet, extended for
// the punch — a driver in any language pairs the two:
//
//	go run ./cmd/signaling-punch \
//	    --node 127.0.0.1:4050 --role responder --mode lobby --input room-7 \
//	    --local-addr 127.0.0.1:52001 --timeout 20
//
//	{"ok":true,"role":"responder","peer_id":"...","remote_peer_id":"...",
//	 "dialed_outbound":true,"verified":true,"mode":"lobby","input":"room-7",
//	 "key":"00ea9b…"}
//
// Two fields do the load-bearing work beyond the meet:
//
//   - dialed_outbound — did THIS side fire an outbound dial at fire_at? The §7.1
//     step-4 both-fire MUST (G1) is invisible on loopback (a listen-only side
//     passes an ordinary punch), so each side reports whether its own dial fired.
//     A partner silently regressed to listen-only shows dialed_outbound:false —
//     the only signal short of a real cross-NAT run. It is a genuine tap of the
//     dial seam, not a hardcoded truth.
//
//   - verified — proof-of-punch is a completed handshake PLUS one operation over
//     the DIRECT path, not a socket merely forming (accepted §3.2). Per the §3.1
//     per-role pin agreed with Rust (2026-08-01), the two halves are deliberately
//     NOT symmetric:
//
//     INITIATOR (gating): PerformConnect + the §7.4.1 identity check, then one
//     EXECUTE (ping); verified means the pong came back over the punched, pooled
//     connection. A positive observation of the round trip.
//
//     RESPONDER (corroborating, never gating): it serves the punched conn and
//     reports establishment (IsConnected — the §6.11 reentry registration). This
//     half is structurally weaker because a responder never observes its own reply
//     landing, so what it reports is a fact about its own internals rather than
//     about the round trip. A ping to system/protocol/connect runs on the protocol
//     path and does NOT fire the dispatch hook, so establishment, not a dispatch
//     tap, is what this side can see. Rust's responder half reports a different
//     internal fact ("served, then clean EOF") — both are legal.
//
//     A harness MUST gate on the initiator and MUST NOT require the two to agree.
//
//   - reciprocal_grant_received / reciprocal_reach_status (responder only) — the
//     §6.5 (b) REACH leg. The responder is the acceptor, so if the dialer minted
//     it a reciprocal grant it originates one dispatch back over the connection
//     the dialer opened and reports the status. This is the difference between
//     proving the grant ARRIVED and proving it AUTHORIZES something: a cap that
//     verifies and reaches no handler is the failure the mechanism exists to
//     prevent, and it is invisible to any vector that stops at installation.
//     Pairs with Rust's initiator-side reciprocal_grant_sent — together the two
//     separate "their minter declined" from "our acceptor dropped it" without
//     either side reading the other's logs. Neither field gates ok: a counterpart
//     that has not adopted §6.5 (b) degrades to one-directional, which is not a
//     failed punch.
//
// The roles keep signaling-meet's asymmetric exit contract: each exits 0 only on
// its own verified. The proof of a punch is the INITIATOR's verified plus
// dialed_outbound on both sides (the §7.1-step-4 dual hole); the responder's
// verified corroborates it and does not gate.
//
// Identity: one keypair backs BOTH the node client (rendezvous identity) and the
// punch peer.Peer (direct-path identity), so the id a side advertises in the
// lobby is the id its punched path authenticates as — the §7.4.1 binding is
// between one identity, not two.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/punchwire"
	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// Punch tunables kept tight so loopback simultaneous-open lands within a few
// crossing windows (the same values the in-process punch tests use).
const (
	pollInterval    = 20 * time.Millisecond
	crossingRetries = 40
	dialTimeout     = 300 * time.Millisecond
	exchangeTimeout = 15 * time.Second
	verifyPoll      = 20 * time.Millisecond
	// lingerAfterVerify keeps the initiator's punched connection open briefly
	// after its pong so the RESPONDER (a separate process polling coarsely) can
	// observe the direct-path session establish. A real peer keeps a punched
	// transport pooled for reuse; a one-shot driver tearing it down the instant it
	// verifies is the artifact this compensates for — without it the responder's
	// establishment window is sub-millisecond on loopback and its poll misses it.
	lingerAfterVerify = 2 * time.Second
)

// deriveKey mirrors signaling-meet: the same four §3 rendezvous modes so a driver
// pairs a punch by the identical key derivation it uses for a meet.
func deriveKey(mode, value string) ([]byte, error) {
	switch mode {
	case "tag":
		return signaling.TagKey(value)
	case "secret":
		return signaling.SecretKey(value)
	case "lobby":
		return signaling.LobbyKey(value)
	case "pair":
		a, b, found := strings.Cut(value, ",")
		if !found || a == "" || b == "" {
			return nil, errors.New("--input for mode 'pair' must be 'peer-a,peer-b'")
		}
		return signaling.PairKey(a, b)
	}
	return nil, fmt.Errorf("unknown --mode %q", mode)
}

// expectedResponder is the peer-id the initiator's punch must reach, for the
// §7.4.1 pre-known identity check. In pair mode both ids are named, so it is the
// one that is not self; in the by-rendezvous modes (tag/secret/lobby) the peer is
// whoever answers the bucket, so it is "" (accept the answer and report the
// authenticated id — the lobby trust model).
func expectedResponder(mode, value, self string) string {
	if mode != "pair" {
		return ""
	}
	a, b, _ := strings.Cut(value, ",")
	if a == self {
		return b
	}
	return a
}

// recordingDial wraps the real reuseport dialer with a flag recording whether
// this side issued a genuine outbound connect on the shared local endpoint — the
// honest source of dialed_outbound (the §7.1 step-4 both-fire cross-impl signal).
// It records AFTER the dial and only when the socket actually bound and dialed: a
// reuseport-unsupported failure never leaves the endpoint, so it does not count
// (matching Rust's "over-counted before the bind" correction). A network error
// like connection-refused still means a SYN went out, so it counts. dialLoop
// guarantees this is never called on an already-cancelled context.
func recordingDial(dialed *atomic.Bool) signaling.DialFunc {
	return func(ctx context.Context, local *net.TCPAddr, remote string) (net.Conn, error) {
		conn, err := signaling.DialReusePort(ctx, local, remote)
		if !errors.Is(err, signaling.ErrReusePortUnsupported) {
			dialed.Store(true)
		}
		return conn, err
	}
}

// suppressedDial is the G3 negative control: it never issues an outbound connect,
// so this side's NAT mapping never opens (a listen-only regression, the pre-G1
// shape). Behind a NAT the counterpart's SYN is then dropped and the punch MUST
// fail — which is exactly what G3 asserts a one-dials build does. dialed_outbound
// stays false. (On loopback there is no NAT, so a suppressed side can still be
// caught by its listener; the control is only meaningful behind a real mapping.)
func suppressedDial() signaling.DialFunc {
	return func(_ context.Context, _ *net.TCPAddr, _ string) (net.Conn, error) {
		return nil, errors.New("dial suppressed (negative control: listen-only)")
	}
}

// socketsFormed names which of the two §7.1-step-4 paths produced a connection.
// "both" is the distinct-4-tuple race: the only case where the peer-id tie-break
// actually decides anything.
func socketsFormed(dialed, accepted bool) string {
	switch {
	case dialed && accepted:
		return "both"
	case dialed:
		return "dialed"
	case accepted:
		return "accepted"
	}
	return "none"
}

func pingURI(peerID string) string {
	return fmt.Sprintf("entity://%s/system/protocol/connect", peerID)
}

// runInitiator punches to the responder, runs PerformConnect + the §7.4.1
// identity check, pools the conn, and lands one ping/pong over the direct path.
func runInitiator(ctx context.Context, p *peer.Peer, party *signaling.PunchParty, expected string, dialed *atomic.Bool) map[string]any {
	raw, err := party.Initiate(ctx, expected)
	if err != nil {
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "error": "punch initiate: " + err.Error()}
	}
	conn := p.ConnectVia(raw)
	// §6.5 (b) §4.4: this seat drove the crossing off a §3 rendezvous key
	// (--mode/--input), so the establishment classifies symmetric. Set before
	// the handshake — the reciprocal mint fires at its tail. Locally derived;
	// nothing about it goes on the wire.
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		conn.Close()
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "error": "handshake over punched path: " + err.Error()}
	}
	authID := conn.Session().RemotePeerID
	// §7.4.1: if a specific peer was named (pair mode), the punched path MUST
	// authenticate as it — a candidate that reaches someone else fails closed.
	if expected != "" && authID.String() != expected {
		conn.Close()
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "remote_peer_id": authID.String(),
			"error": fmt.Sprintf("punched path authenticated as %s, want expected %s (§7.4.1)", authID, expected)}
	}
	if _, err := p.AddRemoteConnection(authID, conn); err != nil {
		conn.Close()
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "remote_peer_id": authID.String(), "error": "pool punched conn: " + err.Error()}
	}

	pingEnt, err := types.PingData{Timestamp: 1709740800000, Sequence: 7}.ToEntity()
	if err != nil {
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "remote_peer_id": authID.String(), "error": "build ping: " + err.Error()}
	}
	resp, err := p.RemoteExecute(ctx, pingURI(authID.String()), "ping", pingEnt, nil)
	if err != nil {
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "remote_peer_id": authID.String(), "error": "ping over punched conn: " + err.Error()}
	}
	verified := resp.Status == 200 && resp.Result.Type == types.TypeNetworkPong
	out := map[string]any{"ok": verified, "dialed_outbound": dialed.Load(), "verified": verified, "remote_peer_id": authID.String()}
	if !verified {
		out["error"] = fmt.Sprintf("ping response status=%d type=%q, want 200/%s", resp.Status, resp.Result.Type, types.TypeNetworkPong)
		return out
	}
	// Hold the pooled connection open so the responder process can observe the
	// direct-path session before we exit and tear it down.
	select {
	case <-ctx.Done():
	case <-time.After(lingerAfterVerify):
	}
	return out
}

// runResponder punches back, serves the punched conn, and waits (to the deadline)
// for the server handshake to reach establishment over the direct path — the
// responder's faithful half of §3.2. It cannot observe the initiator's ping the
// way the initiator does: a ping to system/protocol/connect is handled on the
// protocol/connect path, which does not fire the dispatch hook. But once the
// punched connection is established the peer registers it for §6.11 reentry, so
// IsConnected(initiator) becoming true proves a FULL handshake crossed the
// punched path — and the initiator's own verified proves the ping/pong round trip
// that this same session carried. Together the pair proves §3.2.
func runResponder(ctx context.Context, p *peer.Peer, party *signaling.PunchParty, dialed *atomic.Bool, deadline time.Time) map[string]any {
	raw, initiator, err := party.Respond(ctx)
	if err != nil {
		return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "error": "punch respond: " + err.Error()}
	}
	// §4.4 (rev 3): we camped on the key and answered whoever met us there —
	// symmetric by construction, classified without a wire field.
	served := p.ServeConn(raw)
	served.MarkEstablishedViaRendezvousKey() // server handshake, on a background goroutine

	// Wait for the direct-path session to establish (registered for §6.11 reentry),
	// or the deadline. Latch on first observation: the initiator holds the
	// connection open only briefly, so once seen established we keep verified even
	// if it later tears the pooled connection down.
	initiatorID := crypto.PeerID(initiator)

	// The §6.5 (b) reach leg starts NOW, concurrently — not after `verified`.
	// Its trigger is the grant landing (≈1 round trip after the handshake), which
	// is the moment we first hold originating authority and is comfortably inside
	// the window where the counterpart is still up. Sequencing it after the
	// establishment poll instead puts it behind the initiator's own ping/pong, and
	// an initiator that exits on its pong takes the connection with it — observed
	// as `connection closed`, and before the reach ran at all as
	// `no transport profile` once the §6.11 registration was torn down too.
	reachDone := make(chan map[string]any, 1)
	go func() {
		m := map[string]any{}
		reciprocalReachBack(ctx, p, served, initiatorID, m)
		reachDone <- m
	}()

	verified := false
	for !verified && time.Now().Before(deadline) {
		if p.IsConnected(initiatorID) {
			verified = true
			break
		}
		select {
		case <-ctx.Done():
			return map[string]any{"ok": false, "dialed_outbound": dialed.Load(), "remote_peer_id": initiator, "error": ctx.Err().Error()}
		case <-time.After(verifyPoll):
		}
	}
	// Hold the punched connection open after observing establishment, exactly as
	// the initiator does. Under the §3.1 per-role pin the INITIATOR's round trip
	// is what gates, and that round trip happens AFTER our handshake completes —
	// so returning the moment we see establishment closes the peer and tears the
	// path down under an initiator still waiting on its pong.
	//
	// This is not hypothetical: it is what produced the loopback row-4 failure in
	// the 2026-08-01 cross-impl report. Go registered the session for §6.11
	// reentry, returned, and p.Close() dropped the socket ~20 ms later while the
	// counterpart's ping was in flight — the counterpart saw an early EOF and
	// reported verified:false. Go↔Go only ever hid it on timing.
	out := map[string]any{"ok": verified, "dialed_outbound": dialed.Load(), "verified": verified, "remote_peer_id": initiator}

	// Collect the reach leg launched above. Bounded by the same floor it waits on
	// plus slack for the one dispatch, so a counterpart that never mints cannot
	// hold the driver open past its own contract.
	select {
	case m := <-reachDone:
		for k, v := range m {
			out[k] = v
		}
	case <-time.After(peer.ReciprocalGrantVectorFloor + 3*time.Second):
		out["reciprocal_reach_error"] = "reach leg did not complete"
	}

	if verified {
		select {
		case <-ctx.Done():
		case <-time.After(lingerAfterVerify):
		}
	}

	if !verified {
		out["error"] = "the punched path did not establish a session before the deadline"
	}
	return out
}

// reciprocalReachBack is the §6.5 (b) REACH leg: this seat is the acceptor, and
// if the dialer minted us a reciprocal grant we now originate back over the
// connection *they* opened and report what came of it.
//
// It exists because a crossing that only shows the grant arriving proves
// installation, not reach. V3 measured exactly that gap: both impls minted and
// both accepted, and nothing anywhere demonstrated a handler being reached under
// the cap cross-impl. The reach-back-serving MUST (§6.5 (b), single-impl-
// invisible) is about the half that silently fails — so the vector has to be the
// half that actually wields it.
//
// Two fields, never folded into `ok`:
//
//   - reciprocal_grant_received — did the counterpart mint to us at all? This is
//     the mirror of Rust's `reciprocal_grant_sent`, and the pair separates
//     "their minter declined" from "our acceptance dropped it" without either
//     side having to read the other's logs.
//   - reciprocal_reach_status — the status of one dispatch made under that
//     grant. 200 is reach; 401/403 is a grant that verified and authorizes
//     nothing, which is the failure the whole mechanism exists to prevent and is
//     invisible to every test that stops at installation.
//
// Deliberately NOT gating `ok`. The punch's own contract (§3.1 per-role pin) is
// about the punch, and a counterpart that has not adopted §6.5 (b) yet must
// degrade to one-directional rather than fail a punch that worked — the same
// fail-closed-not-fail-loud posture the bounded wait has.
func reciprocalReachBack(ctx context.Context, p *peer.Peer, served *peer.Connection, remote crypto.PeerID, out map[string]any) {
	// The floor's own scope: system/tree `get` over system/type/*. Every peer
	// seeds its type entities, so this reaches a real entity on any conformant
	// counterpart without assuming anything the §4.4 floor does not grant — and
	// it stays in scope even if the counterpart mints the bare floor rather than
	// an assembled set.
	const floorPath = "system/type/system/peer"

	if !served.AwaitOriginatingCapability(ctx, peer.ReciprocalGrantVectorFloor) {
		out["reciprocal_grant_received"] = false
		return
	}
	out["reciprocal_grant_received"] = true

	params, resource, err := tree.CreateGetRequest(floorPath, "hash")
	if err != nil {
		out["reciprocal_reach_error"] = "build get request: " + err.Error()
		return
	}
	resp, err := p.RemoteExecute(ctx, "entity://"+string(remote)+"/system/tree", "get", params, resource)
	if err != nil {
		// A transport failure here is not a verdict on the grant.
		out["reciprocal_reach_error"] = "originate under reciprocal grant: " + err.Error()
		return
	}
	out["reciprocal_reach_status"] = resp.Status
	out["reciprocal_reach"] = resp.Status == 200
}

// parseTrust maps the --trust string onto the §6.3 posture.
//
// There is no default here and an empty string is an error, even though the
// flag supplies one: signaling.VerificationPolicy's zero value is deliberately
// not a policy, and a silent fallback in this function would put back exactly
// the "acquired the weaker posture by forgetting" hole that invalid zero exists
// to close.
func parseTrust(s string) (signaling.VerificationPolicy, error) {
	switch s {
	case "tolerant":
		return signaling.VerifyTolerant, nil
	case "require":
		return signaling.VerifyRequire, nil
	default:
		return signaling.VerifyUnset, fmt.Errorf("--trust %q must be tolerant|require", s)
	}
}

// punchOpts is one signaling-punch invocation's inputs.
type punchOpts struct {
	node, role, mode, input string
	localAddr               string // the socket bind (private, behind a NAT)
	srflx                   string // the advertised srflx candidate, ASSERTED by the harness
	reflector               string // §6.7.1 reflector to DISCOVER the mapping from; wins over srflx
	dialFrom                string // NEGATIVE CONTROL: punch from an endpoint that is NOT the advertised one
	suppressDial            bool   // negative control: never dial (listen-only)
	trust                   string // §6.3 collect posture: tolerant|require
	debug                   bool   // peer debug log -> stderr; stdout stays the JSON line
	timeout                 float64
}

func punch(o punchOpts) (map[string]any, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	local, err := net.ResolveTCPAddr("tcp", o.localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve --local-addr %q: %w", o.localAddr, err)
	}
	// The candidate we ADVERTISE, and WHERE THAT CLAIM CAME FROM. Precedence
	// (identical to Rust's driver, so a cross-impl run is comparable):
	//
	//	--reflector  "reflector" — DISCOVERED: dial a §6.7.1 responder from the
	//	                           punch socket and use the source it observed.
	//	--srflx      "flag"      — ASSERTED: the harness says what the NAT will do.
	//	neither      "bind"      — the local bind (loopback, where that is true).
	//
	// The rung matters and is reported: a mapping-asserting run cannot detect a
	// §6.7.3 violation, because the assertion and the bind agree by construction
	// even when the NAT disagrees with both.
	srflxAddr, srflxSource := o.srflx, "flag"
	if srflxAddr == "" {
		srflxAddr, srflxSource = local.String(), "bind"
	}

	// The direct-path peer. One keypair for both this peer and the node client
	// below, so the id advertised in the lobby is the id the punched path
	// authenticates as (§7.4.1).
	peerOpts := []peer.Option{
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithStore(store.NewMemoryContentStore()),
		peer.WithLocationIndex(store.NewMemoryLocationIndex()),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	}
	if o.debug {
		// stderr ONLY — stdout is the JSON line a harness parses, and one stray
		// log line there breaks every driver that reads it.
		peerOpts = append(peerOpts, peer.WithDebugLog(log.New(os.Stderr, "[punch] ", log.Ltime|log.Lmicroseconds)))
	}
	p, err := peer.New(peerOpts...)
	if err != nil {
		return nil, fmt.Errorf("build punch peer: %w", err)
	}
	defer p.Close()

	// The node client (rendezvous carrier), same identity as the punch peer.
	client, err := validate.NewPeerClientWithKeypair(o.node, kp)
	if err != nil {
		return nil, fmt.Errorf("build node client: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration((o.timeout+15)*float64(time.Second)))
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect to node: %w", err)
	}
	client.PerformHandshake(ctx)
	if !client.Connected() {
		return nil, errors.New("node handshake did not complete")
	}
	peerID := p.PeerID().String()

	// DISCOVER the mapping, from the very socket the punch binds (§6.7.3). Done
	// after the node handshake because the node doubles as the reflector in the
	// harness, and deliberately fatal: there is no fall back to the bind address,
	// which behind SNAT is private and unreachable.
	if o.reflector != "" {
		observed, gerr := punchwire.ObserveSRFLXFrom(ctx, p, local, o.reflector)
		if gerr != nil {
			return nil, fmt.Errorf("srflx gather from %s: %w", o.reflector, gerr)
		}
		srflxAddr, srflxSource = observed, "reflector"
	}

	// `pair` needs both ids and ours is only known once identified — so a driver
	// passes "…,SELF" and we substitute, exactly as signaling-meet does.
	value := strings.ReplaceAll(o.input, "SELF", peerID)
	key, err := deriveKey(o.mode, value)
	if err != nil {
		return nil, err
	}

	var dialed atomic.Bool
	dial := recordingDial(&dialed)
	if o.suppressDial {
		dial = suppressedDial()
	}
	// §7.3/§6.7.3 NEGATIVE CONTROL. §7.3 requires punching from the very socket
	// whose mapping was advertised; this deliberately dials from a DIFFERENT
	// endpoint while the listener stays on the advertised one. Two uses, and both
	// need a violation that is real rather than described:
	//
	//   - behind a NAT it must FAIL — the counterpart dials a mapping with no
	//     conntrack entry behind it, so the hole never opens. That is the harness
	//     proving it can detect a §6.7.3 violation at all.
	//   - on loopback the two dials stop being reverses of one 4-tuple, so BOTH a
	//     dialed and an accepted socket form — the distinct-4-tuple race that the
	//     peer-id tie-break exists for and that no honest substrate can produce.
	if o.dialFrom != "" {
		from, ferr := net.ResolveTCPAddr("tcp", o.dialFrom)
		if ferr != nil {
			return nil, fmt.Errorf("resolve --dial-from %q: %w", o.dialFrom, ferr)
		}
		inner := dial
		dial = func(ctx context.Context, _ *net.TCPAddr, remote string) (net.Conn, error) {
			return inner(ctx, from, remote)
		}
	}

	// The §6.3 collect posture. This seat DEPOSITS sealed unconditionally; what
	// --trust selects is what it ACCEPTS, and only `require` proves anything
	// about this side: a tolerant collector admits an unsealed counterpart, so a
	// green tolerant run is equally consistent with the counterpart never having
	// sealed at all. Require is the assay — it refuses any blob without a §6.3
	// container, so a green run under it is positive proof the counterpart's
	// deposits are sealed AND that this collector enforces.
	//
	// It was hardcoded to tolerant, which entity-core-rust flagged: everything
	// their live cross-impl punch measured proved GO'S DEPOSITS seal, and
	// nothing proved Go's COLLECTOR enforces, because this seat could not be
	// asked to.
	trust, err := parseTrust(o.trust)
	if err != nil {
		return nil, err
	}

	// Socket outcome, so a harness can assert the tie-break EXECUTED rather than
	// infer it from a punch that merely converged.
	var sockDialed, sockAccepted, keptDialed atomic.Bool
	onSelect := func(d, a, kd bool) {
		sockDialed.Store(d)
		sockAccepted.Store(a)
		keptDialed.Store(kd)
	}
	party := &signaling.PunchParty{
		Carrier: signaling.NewClient(client),
		Key:     key,
		// One identity: the party derives its own peer-id from this keypair and
		// signs every §6.1 deposit with it, so the id in the bucket and the id in
		// the signature cannot drift apart. Tolerant on collect for the flag day.
		Identity:        kp,
		Trust:           trust,
		LocalCands:      []types.NetworkCandidateData{{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: srflxAddr}},
		LocalAddr:       local,
		Dial:            dial,
		Poll:            pollInterval,
		CrossingRetries: crossingRetries,
		DialTimeout:     dialTimeout,
		ExchangeTimeout: exchangeTimeout,
		OnSelect:        onSelect,
	}
	deadline := time.Now().Add(time.Duration(o.timeout * float64(time.Second)))

	var outcome map[string]any
	if o.role == "initiator" {
		outcome = runInitiator(ctx, p, party, expectedResponder(o.mode, value, peerID), &dialed)
	} else {
		outcome = runResponder(ctx, p, party, &dialed, deadline)
	}

	result := map[string]any{
		"role":         o.role,
		"peer_id":      peerID,
		"node_peer_id": client.RemotePeerID().String(),
		"mode":         o.mode,
		"input":        value,
		"local_addr":   local.String(),
		"srflx":        srflxAddr,
		"srflx_source": srflxSource,
		"sockets":      socketsFormed(sockDialed.Load(), sockAccepted.Load()),
		"kept":         map[bool]string{true: "dialed", false: "accepted"}[keptDialed.Load()],
		"key":          hex.EncodeToString(key),
		// Reported so a harness never has to infer the posture from the flags it
		// believes it passed — a run whose verdict is quoted without it is not
		// re-checkable.
		"trust": o.trust,
	}
	for k, v := range outcome {
		result[k] = v
	}
	return result, nil
}

// probeNATType runs the §6.7.1 multi-reflector NAT-type detection against one
// pinned local endpoint and reports the classification. It punches nothing and
// needs no node, no role and no rendezvous mode: this is the screening step that
// runs BEFORE a crossing is attempted (EXTENSION-SIGNALING §11.2 SHOULD, and the
// G4 precheck — a symmetric NAT on either side fails the punch late and looks
// exactly like a counterpart that never appeared).
//
// `ok` means a CONCLUSION WAS REACHABLE — two or more reflectors answered — not
// that the verdict was favourable. An endpoint-dependent verdict is a successful
// probe reporting a relay-only pair; one reachable reflector is a failed probe,
// because §6.7.1 forbids concluding a NAT type from a single observation.
func probeNATType(o punchOpts, reflectors []string) (map[string]any, error) {
	local, err := net.ResolveTCPAddr("tcp", o.localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve --local-addr %q: %w", o.localAddr, err)
	}
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	peerOpts := []peer.Option{
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithStore(store.NewMemoryContentStore()),
		peer.WithLocationIndex(store.NewMemoryLocationIndex()),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	}
	if o.debug {
		peerOpts = append(peerOpts, peer.WithDebugLog(log.New(os.Stderr, "[nat-type] ", log.Ltime|log.Lmicroseconds)))
	}
	p, err := peer.New(peerOpts...)
	if err != nil {
		return nil, fmt.Errorf("build probe peer: %w", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.timeout*float64(time.Second)))
	defer cancel()

	assessment, errs := punchwire.DetectMapping(ctx, p, local, reflectors)

	// Every failure is named. A probe that quietly consulted fewer reflectors than
	// it was given is how a wrong verdict gets published with a straight face.
	failures := make([]string, 0, len(errs))
	for _, e := range errs {
		failures = append(failures, e.Error())
	}
	observed := make([]map[string]string, 0, len(assessment.Observations))
	for _, ob := range assessment.Observations {
		observed = append(observed, map[string]string{"reflector": ob.Reflector, "observed": ob.Observed})
	}
	return map[string]any{
		"probe":         "nat-type",
		"ok":            len(assessment.Observations) >= 2,
		"peer_id":       p.PeerID().String(),
		"local_addr":    local.String(),
		"class":         string(assessment.Class),
		"punchable":     assessment.Class.Punchable(),
		"mapping":       assessment.Mapping,
		"reason":        assessment.Reason,
		"observations":  observed,
		"reflectors":    reflectors,
		"errors":        failures,
		"reflector_ok":  len(assessment.Observations),
		"reflector_all": len(reflectors),
	}, nil
}

func main() {
	node := flag.String("node", "", "host:port of the connection node (rendezvous carrier)")
	role := flag.String("role", "", "initiator|responder")
	mode := flag.String("mode", "", "tag|secret|lobby|pair")
	input := flag.String("input", "", "the mode's input; 'pair' takes 'peer-a,peer-b'; literal SELF -> this peer-id")
	localAddr := flag.String("local-addr", "", "host:port to bind the punch socket (the private bind behind a NAT)")
	srflx := flag.String("srflx", "", "host:port to advertise as this side's srflx candidate — the public NAT mapping the counterpart dials. Empty → --local-addr (loopback, no NAT).")
	suppressDial := flag.Bool("suppress-dial", false, "G3 negative control: never dial (listen-only). Behind a NAT this side's hole never opens and the punch MUST fail — the pre-G1 one-dials regression.")
	reflector := flag.String("reflector", "", "host:port of a §6.7.1 observe-address reflector to DISCOVER this side's srflx mapping from (dialed from --local-addr). Wins over --srflx; a failed gather is fatal, never a fallback.")
	dialFrom := flag.String("dial-from", "", "NEGATIVE CONTROL (§7.3/§6.7.3 violation): punch from this endpoint instead of --local-addr, while still listening on --local-addr. Behind a NAT the punch MUST fail; on loopback it produces the distinct-4-tuple race the peer-id tie-break exists for.")
	natType := flag.Bool("nat-type", false, "PROBE MODE (§6.7.1 / §11.2): consult --reflectors about --local-addr and classify the NAT mapping, then exit. Punches nothing; needs no --node/--role/--mode/--input. This is the G4 precheck — same mapping from every reflector => punchable, differing => symmetric => relay-only.")
	reflectors := flag.String("reflectors", "", "comma-separated §6.7.1 reflectors for --nat-type. TWO OR MORE: a single reflector is advisory and MUST NOT conclude a NAT type (§6.7.1, §9.3). All are dialed from --local-addr, since a mapping belongs to a socket (§6.7.3).")
	trust := flag.String("trust", "require", "§6.3 collect posture: tolerant|require. This seat always DEPOSITS sealed; --trust selects what it ACCEPTS. Defaults to `require`, matching the production posture (peerwiring.DefaultTrust) now that the §6.1 flag day is closed. `tolerant` remains for negative controls and for meeting a pre-flip build on purpose.")
	debug := flag.Bool("debug", false, "log the peer's activity to stderr; stdout stays the JSON line")
	timeout := flag.Float64("timeout", 20.0, "seconds to run")
	flag.Parse()

	fail := func(msg string) {
		out, _ := json.Marshal(map[string]any{"ok": false, "role": *role, "error": msg})
		fmt.Println(string(out))
		os.Exit(1)
	}

	if *natType {
		var list []string
		for _, r := range strings.Split(*reflectors, ",") {
			if r = strings.TrimSpace(r); r != "" {
				list = append(list, r)
			}
		}
		// ONE reflector is accepted and then REFUSED BY THE CLASSIFIER, not rejected
		// here. §6.7.1 says a single reflector is *advisory* — advisory means the
		// observation is usable (it is a valid srflx candidate) while the NAT-TYPE
		// conclusion is not. Rejecting at the arity check throws away a usable fact
		// and, found by running the two impls side by side, emits a refusal with no
		// `class` field at all — so a harness gating on class=="unknown" passed one
		// impl and failed the other. Both refusals were correct; the SHAPES diverged.
		// Go moved: probe, report the observation, and let the §6.7.1 rule refuse.
		switch {
		case *localAddr == "":
			fail("--local-addr is required (the socket whose mapping is being classified)")
		case len(list) == 0:
			fail("--reflectors is required for --nat-type (comma-separated host:port)")
		}
		result, err := probeNATType(punchOpts{localAddr: *localAddr, debug: *debug, timeout: *timeout}, list)
		if err != nil {
			fail(err.Error())
		}
		out, _ := json.Marshal(result)
		fmt.Println(string(out))
		if ok, _ := result["ok"].(bool); ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	switch {
	case *node == "":
		fail("--node is required")
	case *role != "initiator" && *role != "responder":
		fail("--role must be initiator|responder")
	case *mode != "tag" && *mode != "secret" && *mode != "lobby" && *mode != "pair":
		fail("--mode must be tag|secret|lobby|pair")
	case *input == "":
		fail("--input is required")
	case *localAddr == "":
		fail("--local-addr is required")
	case *trust != "tolerant" && *trust != "require":
		fail("--trust must be tolerant|require")
	}

	result, err := punch(punchOpts{
		node: *node, role: *role, mode: *mode, input: *input,
		localAddr: *localAddr, srflx: *srflx, reflector: *reflector, suppressDial: *suppressDial,
		dialFrom: *dialFrom, trust: *trust,
		debug: *debug, timeout: *timeout,
	})
	if err != nil {
		fail(err.Error())
	}
	out, _ := json.Marshal(result)
	fmt.Println(string(out))
	if ok, _ := result["ok"].(bool); ok {
		os.Exit(0)
	}
	os.Exit(1)
}
