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
	// CITATIONS CORRECTED 2026-08-13. Five of these six cited "brief §N" —
	// a word that names no document, from when EXTENSION-SIGNALING was a
	// design brief rather than a landed spec. The checks ran and passed the
	// whole time; the conformance register simply could not attribute them
	// to anything, so the extension read as uncovered in the inventory while
	// being fully exercised. Naming the document is the entire fix.
	//
	// `signaling_authority` also moved SECTION, not just document: it cited
	// §5.1, and EXTENSION-SIGNALING §5 is Bucket Semantics with no
	// subsections. The capability-gated wrapped surface — what this check
	// actually asserts — is §8.1 Admission (and §2.2 names "the capability
	// model (§8)" for the wrapped surface). A citation that resolves to a
	// document but lands on the wrong section is the harder version of this
	// defect, because it looks resolved.
	r.Declare("signaling_authority", "EXTENSION-SIGNALING §8.1/§7 — the wrapped surface is capability-gated: advertise + caller grant covers system/signaling")
	r.Declare("signaling_limits_shape", "EXTENSION-SIGNALING §4.5 — advertise-result carries the committed limits shape (ttl_seconds/max_blob_bytes/max_bucket_blobs)")
	r.Declare("signaling_meet_tag", "EXTENSION-SIGNALING §4.1/§4.5 — two peers derive a `tag` key and meet")
	r.Declare("signaling_meet_secret", "EXTENSION-SIGNALING §4.1/§4.5 — two peers derive a `secret` key and meet")
	r.Declare("signaling_meet_lobby", "EXTENSION-SIGNALING §4.1/§4.5 — two peers derive a `lobby` key and meet")
	r.Declare("signaling_meet_pair", "EXTENSION-SIGNALING §4.1/§4.5 — two peers derive a `pair` key and meet")

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
	var advLimits types.SignalingLimitsData

	r.Run("signaling_authority", func() CheckOutcome {
		status, adv, err := sigA.Advertise(ctx)
		if err != nil {
			return FailCheck("advertise EXECUTE: " + err.Error())
		}
		if status == 403 {
			return SkipCheck("node returned 403 (capability_denied) on advertise — the caller's connection grant does not cover system/signaling. A public introducer must seed it on connect; the standalone entity-signaling-node binary installs no seed policy (main.rs omits .with_seed_policy — only the Rust live tests' wildcard_seed grants it). Start the node with a seed policy covering system/signaling:{offer,collect,advertise} and re-run. See docs/validation/reports/2026-07-30-signaling-go-client-vs-rust-node.md.")
		}
		// §2.1 / §11.3: "The server role is OPTIONAL for a conformant
		// implementation. The client role is the conformance surface." SIGNALING
		// deliberately departs from the RELAY precedent here — signaling is
		// deployed infrastructure with a non-entity hot path, and requiring three
		// server implementations is work with no consumer. So a peer that does
		// not serve the rendezvous node is NOT failing anything, and this whole
		// category (which needs the target itself to be the carrier) simply has
		// nothing to exercise.
		//
		// Skip rather than Pass, and Skip rather than Fail: Require() propagates
		// a skipped prerequisite as a skip, so the six dependent checks below
		// report "prerequisite skipped" instead of "blocked by a failure."
		//
		// Skip is NOT a pass here. This project implements everything, so an
		// unimplemented surface is an UNTESTED surface: the skip still counts
		// toward the run's FAIL gate (it is neither profile-keyed nor an
		// environment skip), and the way to close it is to build the node role —
		// not to allowlist it. The two severities carry different facts and both
		// are true at once: "not a spec violation" (§2.1) and "not exercised, so
		// this run does not prove the system works" (our bar).
		//
		// This check FAILed here until 2026-08-07, which put 7 spurious failures
		// on core-rust's and core-py's scorecards in the same sweep whose prose
		// correctly called the node role optional. A red that means less than it
		// looks like is the same disease as a green that does (ADR-0012).
		if status == 404 {
			return SkipCheck("target does not serve the §4/§5 rendezvous node (advertise → 404). Per §2.1 the SERVER ROLE IS OPTIONAL and the client role is the conformance surface, so this is NOT a conformance failure — the whole signaling category needs the target to BE the carrier and has nothing to exercise. Validate the peer's signaling CLIENT through a real crossing (cmd/signaling-punch against a node) instead.  THIS PROJECT IMPLEMENTS EVERYTHING: the node role unimplemented means §4/§5 and the whole punch-carrier surface go UNTESTED for this peer, so this counts toward the run's FAIL gate — do NOT wave it through with -allow-skip. §2.1 even names the cost of a single-server cohort: \"underspecification stays invisible — one implementation cannot disagree with itself.\"")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("advertise returned %d, want 200 (or 404 if this peer does not serve the §2.1 server role)", status))
		}
		if adv.Endpoint == "" {
			return FailCheck("advertise returned an empty endpoint")
		}
		pool = []signaling.PoolMember{{Endpoint: adv.Endpoint, Priority: 0}}
		advLimits = adv.Limits
		if len(adv.Limits.LobbyConstant) > 0 {
			lobbyConst = string(adv.Limits.LobbyConstant)
		}
		return PassCheck(fmt.Sprintf("node advertises endpoint %q (lobby %q); caller holds signaling authority", adv.Endpoint, lobbyConst))
	})

	// §4.5 limits shape — the F2 drift catcher. A node still emitting the
	// pre-v1.0 advertise shape (bucket_ttl_ms / max_message_bytes /
	// max_messages_per_key) decodes into the committed SignalingLimitsData as
	// ALL-ZERO, because the field names differ. So a zero-valued limits block is
	// the signature of a node that has not re-diffed to §4.5 — exactly the drift
	// that slipped past signaling_authority (which only checks the endpoint) and
	// that both Go and Rust flagged. WARN, not FAIL: the client is conformant and
	// the meet only needs the endpoint; this surfaces a NODE-side observation
	// without gating the meet. The ttl unit is load-bearing (§4.5 ttl_seconds vs
	// the drifted bucket_ttl_ms is a 1000x reap-race).
	r.Run("signaling_limits_shape", func() CheckOutcome {
		if out, ok := r.Require("signaling_authority"); !ok {
			return out
		}
		if advLimits.TTLSeconds == 0 || advLimits.MaxBlobBytes == 0 || advLimits.MaxBucketBlobs == 0 {
			return WarnCheck(fmt.Sprintf(
				"advertise-result limits decoded all/partly zero (ttl_seconds=%d max_blob_bytes=%d max_bucket_blobs=%d) — the node likely still emits the pre-§4.5 shape (bucket_ttl_ms/max_message_bytes/max_messages_per_key), which decodes to zero under the committed field names. Re-diff the node's advertise emission to §4.5. See docs/validation/reports/2026-07-31-signaling-redigest-and-punch-stage2-to-arch.md (F2).",
				advLimits.TTLSeconds, advLimits.MaxBlobBytes, advLimits.MaxBucketBlobs))
		}
		return PassCheck(fmt.Sprintf("advertise-result limits match §4.5 shape (ttl_seconds=%d max_blob_bytes=%d max_bucket_blobs=%d)",
			advLimits.TTLSeconds, advLimits.MaxBlobBytes, advLimits.MaxBucketBlobs))
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

	// The §7 punch on top of the same live carrier — coordination + socket
	// choreography end to end (everything but traversal, which needs real NAT).
	runSignalingPunch(ctx, r, sigA, sigB)

	return r.Results()
}

// signalingMeet runs the full §4 step-2 rendezvous between A and B at one node
// for a single derived key, and returns Pass only if A ends holding B's
// nonce-matched response.
func signalingMeet(ctx context.Context, sigA, sigB *signaling.Client, idA, idB string, key []byte, label string) CheckOutcome {
	cands := []types.NetworkCandidateData{
		{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "10.0.0.1:9000"},
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
	resp, _, found := signaling.FindResponse(aMsgs, nonce, idA)
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
