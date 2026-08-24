package validate

import (
	"context"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

const catSignaling = "signaling"

// runSignaling drives the signaling CLIENT (ext/signaling) against a LIVE
// rendezvous node — the brief §8 gate, go as oracle. Two Go peer identities
// derive a shared rendezvous_key, select the node from the pool by §3.1.1, and
// MEET through it: A offers a connect-request blob, B collects+classifies+finds
// it (skipping its own), answers with a connect-response echoing the nonce, and
// A collects and finds the answer (skipping its own request). One check per key
// mode — tag / secret / lobby / pair.
//
// This is the first real cross-impl evidence about the two things most likely to
// be wrong and invisible to a same-impl suite: the §2.2 key derivation and the
// §3.1.1 weight function. A wrong-but-self-consistent derivation passes every
// unit test exactly like a correct one; only two peers meeting (or failing to)
// validates it.
//
// Authority gate (like network.go's admin gate): the wrapped surface's admission
// is the ordinary dispatch-layer capability check, so the caller's connection
// grant must cover system/signaling:{offer,collect,advertise}. A public
// introducer seeds that on connect (the Rust live tests use a wildcard seed
// policy). If the node grants none — a 403 on advertise — every check SKIPs with
// guidance rather than failing: the node is misconfigured for the gate, not the
// client wrong.
//
// TWO-INSTANCE NOTE (§4.2): a real §3.1.1 gate needs a two-instance pool with
// DIFFERENT advertised endpoints — argmax over one member is trivial. This
// single-target category exercises the meet and the client end to end against
// one node's real storage/dedup/TTL; the two-instance selection itself is
// unit-tested (ext/signaling/pool_test.go). The multi-node live variant is a
// follow-up over the -peers convergence path.
func runSignaling(ctx context.Context, clientA *PeerClient, addr string) []CheckResult {
	r := NewCheckRunner(catSignaling)
	r.Declare("signaling_authority", "brief §5.1/§7 — advertise + caller grant covers system/signaling")
	r.Declare("signaling_meet_tag", "brief §4.1/§4.5 — two peers derive a `tag` key and meet")
	r.Declare("signaling_meet_secret", "brief §4.1/§4.5 — two peers derive a `secret` key and meet")
	r.Declare("signaling_meet_lobby", "brief §4.1/§4.5 — two peers derive a `lobby` key and meet")
	r.Declare("signaling_meet_pair", "brief §4.1/§4.5 — two peers derive a `pair` key and meet")

	// Peer B: a second, distinct identity connected to the same node. (A is the
	// harness's primary client, already connected.) A fresh keypair — NOT A's —
	// so pair mode has two real peer-ids and FindRequest/FindResponse's skip-own
	// rules are actually exercised.
	kpB, err := crypto.Generate()
	if err != nil {
		return skipAllSignaling(r, "generate peer-B keypair: "+err.Error())
	}
	clientB, err := NewPeerClientWithKeypair(addr, kpB)
	if err != nil {
		return skipAllSignaling(r, "build peer-B client: "+err.Error())
	}
	defer clientB.Close()
	clientB.SetVerbose(clientA.verbose)
	if err := clientB.Connect(ctx); err != nil {
		return skipAllSignaling(r, "peer-B connect: "+err.Error())
	}
	clientB.PerformHandshake(ctx)
	if !clientB.Connected() {
		return skipAllSignaling(r, "peer-B handshake did not complete")
	}

	sigA := signaling.NewClient(clientA)
	sigB := signaling.NewClient(clientB)
	idA := clientA.LocalPeerID().String()
	idB := clientB.LocalPeerID().String()

	// A fresh per-run token so the shared-bucket modes (tag/secret) use a clean
	// rendezvous each run instead of accumulating prior runs' requests within
	// the 60s TTL — py's stale-request finding (§4.5): a rerun that adopts a
	// stale request "succeeds" at every step yet A's current request goes
	// unanswered. Both local identities share the token; a future cross-process
	// gate hands one shared token to every impl the same way. pair is fresh via
	// the identities; lobby stays on the node's advertised constant (genuinely
	// shared across impls) and is made rerun-safe by signalingMeet answering
	// ALL pending requests.
	saltNonce, err := signaling.GenerateNonce()
	if err != nil {
		return skipAllSignaling(r, "generate run salt: "+err.Error())
	}
	runID := hex.EncodeToString(saltNonce)

	var pool []signaling.PoolMember
	lobbyConst := signaling.LobbyDefault

	r.Run("signaling_authority", func() CheckOutcome {
		status, adv, err := sigA.Advertise(ctx)
		if err != nil {
			return FailCheck("advertise EXECUTE: " + err.Error())
		}
		if status == 403 {
			return SkipCheck("node returned 403 (capability_denied) on advertise — the caller's connection grant does not cover system/signaling. A public introducer must seed it on connect; the standalone entity-signaling-node binary installs no seed policy (main.rs omits .with_seed_policy — only the Rust live tests' wildcard_seed grants it). Start the node with a seed policy covering system/signaling:{offer,collect,advertise} and re-run. See docs/validation/reports/2026-07-30-signaling-go-client-vs-rust-node.md.")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("advertise returned %d, want 200", status))
		}
		if adv.Endpoint == "" {
			return FailCheck("advertise returned an empty endpoint")
		}
		pool = []signaling.PoolMember{{Endpoint: adv.Endpoint, Priority: 0}}
		if adv.Lobby != nil {
			lobbyConst = *adv.Lobby
		}
		return PassCheck(fmt.Sprintf("node advertises endpoint %q (lobby %q); caller holds signaling authority", adv.Endpoint, lobbyConst))
	})

	meet := func(name, label string, deriveKey func() ([]byte, error)) {
		r.Run(name, func() CheckOutcome {
			if out, ok := r.Require("signaling_authority"); !ok {
				return out
			}
			key, err := deriveKey()
			if err != nil {
				return FailCheck("derive key: " + err.Error())
			}
			// §3.1.1 selection — both peers pick the same node. Trivial for a
			// one-member pool, but the call path is exercised.
			if _, ok := signaling.Select(key, pool); !ok {
				return FailCheck("pool selection returned no node")
			}
			return signalingMeet(ctx, sigA, sigB, idA, idB, key, label)
		})
	}

	meet("signaling_meet_tag", "tag", func() ([]byte, error) { return signaling.TagKey("conformance-" + runID) })
	meet("signaling_meet_secret", "secret", func() ([]byte, error) { return signaling.SecretKey("conformance-secret-" + runID) })
	meet("signaling_meet_lobby", "lobby", func() ([]byte, error) { return signaling.LobbyKey(lobbyConst) })
	meet("signaling_meet_pair", "pair(A,B)", func() ([]byte, error) { return signaling.PairKey(idA, idB) })

	return r.Results()
}

// signalingMeet runs the full §4 step-2 rendezvous between A and B at one node
// for a single derived key, and returns Pass only if A ends holding B's
// nonce-matched response.
func signalingMeet(ctx context.Context, sigA, sigB *signaling.Client, idA, idB string, key []byte, label string) CheckOutcome {
	cands := []types.NATCandidateData{
		{Type: signaling.CandidateHost, Substrate: signaling.SubstrateTCP, Address: "10.0.0.1:9000", Priority: 0},
	}
	nonce, err := signaling.GenerateNonce()
	if err != nil {
		return FailCheck("generate nonce: " + err.Error())
	}

	// A → connect-request.
	reqEnt, err := types.ConnectRequestData{Candidates: cands, Initiator: idA, Nonce: nonce}.ToEntity()
	if err != nil {
		return FailCheck("build connect-request: " + err.Error())
	}
	if status, err := sigA.OfferMessage(ctx, key, reqEnt); err != nil || status != 200 {
		return FailCheck(fmt.Sprintf("A offer connect-request: status %d err %v", status, err))
	}

	// B collects and answers EVERY non-own request it finds — not just the
	// first. On a rerun within the 60s TTL a shared-bucket mode (lobby) still
	// holds stale requests from a prior run, and answering only the oldest
	// (FindRequest's first match) would leave A's CURRENT request unanswered
	// while every step reports success (py's §4.5 stale-request finding).
	// Answering all is a legitimate gate policy — respond to everyone looking;
	// which one to answer is otherwise peer policy the library does not decide.
	// A then isolates its own answer by nonce echo below.
	_, bMsgs, err := sigB.CollectMessages(ctx, key)
	if err != nil {
		return FailCheck("B collect: " + err.Error())
	}
	answered := 0
	for _, m := range bMsgs {
		if m.Kind != signaling.KindConnectRequest || m.Request.Initiator == idB {
			continue
		}
		respEnt, err := types.ConnectResponseData{Candidates: cands, Nonce: m.Request.Nonce, Responder: idB}.ToEntity()
		if err != nil {
			return FailCheck("build connect-response: " + err.Error())
		}
		if status, err := sigB.OfferMessage(ctx, key, respEnt); err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("B offer connect-response: status %d err %v", status, err))
		}
		answered++
	}
	if answered == 0 {
		return FailCheck(fmt.Sprintf("B collected %d message(s) but found no connect-request to answer (%s)", len(bMsgs), label))
	}

	// A collects and isolates B's answer by nonce echo. collect is
	// non-destructive (§5.2), so A re-reads its OWN request — assert it's
	// present, which is exactly what makes the nonce-echo isolation load-bearing:
	// A must pick B's response out of a bucket that also holds A's own request
	// and, on a rerun within the TTL, stale requests/responses from prior runs.
	_, aMsgs, err := sigA.CollectMessages(ctx, key)
	if err != nil {
		return FailCheck("A collect: " + err.Error())
	}
	ownPresent := false
	for _, m := range aMsgs {
		if m.Kind == signaling.KindConnectRequest && m.Request.Initiator == idA && string(m.Request.Nonce) == string(nonce) {
			ownPresent = true
			break
		}
	}
	if !ownPresent {
		return FailCheck("A's own request absent from its own collect — collect should be non-destructive (§5.2)")
	}
	resp, found := signaling.FindResponse(aMsgs, nonce, idA)
	if !found {
		return FailCheck(fmt.Sprintf("A collected %d message(s) but found no nonce-matched response from B (%s)", len(aMsgs), label))
	}
	if resp.Responder != idB {
		return FailCheck(fmt.Sprintf("response responder %q, want B %q", resp.Responder, idB))
	}
	return PassCheck(fmt.Sprintf("A and B met via %s", label))
}

// skipAllSignaling SKIPs every declared check with one message. Only called on
// an early return (peer-B setup failure), before any check has run, so a plain
// Run per check is safe.
func skipAllSignaling(r *CheckRunner, msg string) []CheckResult {
	for _, name := range []string{"signaling_authority", "signaling_meet_tag", "signaling_meet_secret", "signaling_meet_lobby", "signaling_meet_pair"} {
		r.Run(name, func() CheckOutcome { return SkipCheck(msg) })
	}
	return r.Results()
}
