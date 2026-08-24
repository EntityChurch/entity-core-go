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
	p.ServeConn(raw) // server handshake, on a background goroutine

	// Wait for the direct-path session to establish (registered for §6.11 reentry),
	// or the deadline. Latch on first observation: the initiator holds the
	// connection open only briefly, so once seen established we keep verified even
	// if it later tears the pooled connection down.
	initiatorID := crypto.PeerID(initiator)
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
	if verified {
		select {
		case <-ctx.Done():
		case <-time.After(lingerAfterVerify):
		}
	}

	out := map[string]any{"ok": verified, "dialed_outbound": dialed.Load(), "verified": verified, "remote_peer_id": initiator}
	if !verified {
		out["error"] = "the punched path did not establish a session before the deadline"
	}
	return out
}

// punchOpts is one signaling-punch invocation's inputs.
type punchOpts struct {
	node, role, mode, input string
	localAddr               string // the socket bind (private, behind a NAT)
	srflx                   string // the advertised srflx candidate, ASSERTED by the harness
	reflector               string // §6.7.1 reflector to DISCOVER the mapping from; wins over srflx
	suppressDial            bool   // negative control: never dial (listen-only)
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
	party := &signaling.PunchParty{
		Carrier:         signaling.NewClient(client),
		Key:             key,
		SelfID:          peerID,
		LocalCands:      []types.NetworkCandidateData{{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: srflxAddr}},
		LocalAddr:       local,
		Dial:            dial,
		Poll:            pollInterval,
		CrossingRetries: crossingRetries,
		DialTimeout:     dialTimeout,
		ExchangeTimeout: exchangeTimeout,
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
		"key":          hex.EncodeToString(key),
	}
	for k, v := range outcome {
		result[k] = v
	}
	return result, nil
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
	debug := flag.Bool("debug", false, "log the peer's activity to stderr; stdout stays the JSON line")
	timeout := flag.Float64("timeout", 20.0, "seconds to run")
	flag.Parse()

	fail := func(msg string) {
		out, _ := json.Marshal(map[string]any{"ok": false, "role": *role, "error": msg})
		fmt.Println(string(out))
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
	}

	result, err := punch(punchOpts{
		node: *node, role: *role, mode: *mode, input: *input,
		localAddr: *localAddr, srflx: *srflx, reflector: *reflector, suppressDial: *suppressDial,
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
