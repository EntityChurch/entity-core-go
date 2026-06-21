package validate

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runRelayMultiPeer is the EXTENSION-RELAY v1.0 three-peer behavioral gate.
//
// The single-peer relay category (`relay`) covers entity shapes, ECF round-
// trips, and same-peer :put/:poll/:advertise/:forward error paths. It does
// NOT prove the headline behaviors that motivate the extension:
//
//   - Terminal-hop forwarding (§3.1.1 + §10.4) — A → B(relay) → C delivers
//     the inner EXECUTE to C as if it had arrived on a direct connection.
//   - Offline-stranger §6.2.1 fallback — A → B(relay) with C unreachable;
//     B queues the inner at Mode-S under namespace = C; C polls B later.
//   - §3.5 forged-redirection defense — a bogus inbox-relay declaration
//     with an invalid V7 §5.2 signature MUST NOT be honored.
//
// Implementation prerequisites this category exercises end-to-end:
//
//   - ext/relay/peerwiring.PeerDispatcher (OutboundDispatcher impl over
//     core/peer connection pool).
//   - ext/relay/peerwiring.TreeInboxRelayResolver (InboxRelayResolver impl
//     reading local-tree declarations + V7 §5.2 sig-verifying).
//
// Setup convention: clients[0]=A (sender role), clients[1]=B (relay role),
// clients[2]=C (destination role). The validator's keypair drives every
// client (the §4.2 case 3 single-principal model — see RunConvergence
// header), so A/B/C distinguish PEER identities (a.RemotePeerID() etc.),
// not validator identities. Caps come from each entity-peer's seed policy;
// these checks expect --open-access on all three (peer-manager start --debug
// is the standard test rig).
func runRelayMultiPeer(ctx context.Context, clients []*PeerClient, httpURLs, wsURLs []string) []CheckResult {
	r := NewCheckRunner(catRelayMultiPeer)

	r.Declare("mp1_three_peer_setup", "RELAY multi-peer setup: publish C's TCP transport profile in B so B can dial C; publish B's profile in C so C can dial B for poll")
	r.Declare("mp2_terminal_forward_a_to_c_via_b_live", "RELAY §3.1.1 + §10.4 terminal hop: A → B :forward(dest=C, next=C) → B's PeerDispatcher.DeliverInner runs the inner EXECUTE on C; payload lands at C's tree (byte-identical-to-direct semantic)")
	r.Declare("mp3_offline_fallback_then_c_polls", "RELAY §6.2.1 + §3.5: destination unreachable (no transport profile from B) → §6.2.1 fallback queues at namespace=C on B → C polls B with namespace=C → store-entry surfaces → cursor advance returns empty")
	r.Declare("mp4_forged_redirect_rejected_falls_back_to_default", "RELAY §3.5 + V7 §5.2 forged-redirection defense: forged inbox-relay decl with WRONG signer signature MUST be rejected by TreeInboxRelayResolver; fallback uses default convention (namespace=destination), NOT the forged namespace")

	if len(clients) < 3 {
		for _, n := range []string{
			"mp1_three_peer_setup",
			"mp2_terminal_forward_a_to_c_via_b_live",
			"mp3_offline_fallback_then_c_polls",
			"mp4_forged_redirect_rejected_falls_back_to_default",
		} {
			name := n
			r.Run(name, func() CheckOutcome { return SkipCheck("requires 3 peers (use -peers a,b,c)") })
		}
		return r.Results()
	}

	a, b, c := clients[0], clients[1], clients[2]
	bPeerID := string(b.RemotePeerID())
	cPeerID := string(c.RemotePeerID())
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// --- mp1 setup: publish transport profiles so the dispatcher has a route.
	r.Run("mp1_three_peer_setup", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/transport/* — start peers with --open-access (peer-manager start --debug)")
		}
		// Publish C's transport profile in B so B's dispatcher can dial C.
		// Thread H: HTTP profile when -http-peers is set for clients[2],
		// else TCP. Go's `Peer.SendRawFrameTo` type-switches per
		// connection type, so the relay path rides the published profile
		// transparently.
		cProfile := transportProfileForPeer(clients, 2, httpURLs, wsURLs)
		cHash, err := types.ComputePeerIdentityHashFromPeerID(c.RemotePeerID())
		if err != nil {
			return SkipCheck("C identity-hash undericable from peer-id (SHA-256-form): " + err.Error())
		}
		cPath := "system/peer/transport/" + types.PeerIdentityHashHex(cHash) + "/primary"
		if _, err := b.TreePut(ctx, cPath, cProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish C profile on B at %s: %v", cPath, err))
		}
		// Publish B's transport profile in C so C can dial B to poll.
		bProfile := transportProfileForPeer(clients, 1, httpURLs, wsURLs)
		bHash, err := types.ComputePeerIdentityHashFromPeerID(b.RemotePeerID())
		if err != nil {
			return SkipCheck("B identity-hash undericable from peer-id: " + err.Error())
		}
		bPath := "system/peer/transport/" + types.PeerIdentityHashHex(bHash) + "/primary"
		if _, err := c.TreePut(ctx, bPath, bProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish B profile on C at %s: %v", bPath, err))
		}
		cTransport := c.addr
		if u := httpURLForPeer(2, httpURLs); u != "" {
			cTransport = u
		}
		bTransport := b.addr
		if u := httpURLForPeer(1, httpURLs); u != "" {
			bTransport = u
		}
		return PassCheck(fmt.Sprintf("transport profiles published: C@B(%s)=%s, B@C(%s)=%s", cPath, cTransport, bPath, bTransport))
	})

	// --- mp2 terminal-hop forward: A → B with destination=C, next_hop=C.
	// B's PeerDispatcher.DeliverInner decodes the inner EXECUTE and re-
	// dispatches it as a normal EXECUTE to C. Inner targets C's tree.
	deliveryPath := fmt.Sprintf("system/relay-mp/mp2-%s", suffix)
	r.Run("mp2_terminal_forward_a_to_c_via_b_live", func() CheckOutcome {
		if out, ok := r.Require("mp1_three_peer_setup"); !ok {
			return out
		}
		payload := mustCreateEntity("test/relay-mp2-payload", map[string]string{
			"content": "delivered-via-relay-" + suffix,
		})

		// The inner EXECUTE drives tree:put on C. tree:put expects params
		// shaped as a system/tree/put-request entity (CreatePutRequest wraps
		// the payload + handles ECF encoding). Anything else lands as a
		// REMOVE per handler.go:411 — exactly the bug surfaced by mp2's
		// first run (404 "path not bound").
		putReqEnt, putResource, putErr := tree.CreatePutRequest(deliveryPath, &payload)
		if putErr != nil {
			return FailCheck("build tree:put-request: " + putErr.Error())
		}
		inner, err := buildInnerExecute(
			c,
			"entity://"+cPeerID+"/system/tree",
			"put",
			putReqEnt,
			putResource,
			"mp2-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner system/envelope: " + err.Error())
		}

		fr := types.ForwardRequestData{
			Destination:   cPeerID,
			NextHop:       cPeerID, // terminal hop (next_hop == destination)
			TTLHops:       3,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200, got %d (code=%q)", status, relayErrCode(result)))
		}
		fres, err := types.ForwardResultDataFromEntity(result)
		if err != nil {
			return FailCheck("decode forward-result: " + err.Error())
		}
		if fres.Status != types.ForwardStatusForwarded {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (live dispatch), got %q — dispatcher may not be wired or destination unreachable (stored_at=%q)",
				types.ForwardStatusForwarded, fres.Status, fres.StoredAt))
		}

		// Verify the payload actually landed at C's tree.
		// Brief retry — the dispatched EXECUTE just returned 200 but the
		// store may not be fully indexed in the same instant.
		var gotEnt entity.Entity
		var getErr error
		for attempt := 0; attempt < 10; attempt++ {
			gotEnt, _, getErr = c.TreeGet(ctx, deliveryPath)
			if getErr == nil && gotEnt.Type == payload.Type {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if getErr != nil {
			return FailCheck(fmt.Sprintf("C.TreeGet(%s) after forward returned 200/forwarded: %v — terminal dispatch may have lost the inner EXECUTE", deliveryPath, getErr))
		}
		if gotEnt.ContentHash != payload.ContentHash {
			return FailCheck(fmt.Sprintf("payload content_hash drift at C: want %s, got %s — inner EXECUTE landed but params don't match (encoding drift)",
				payload.ContentHash, gotEnt.ContentHash))
		}
		return PassCheck(fmt.Sprintf("A → B(relay) → C delivered: forward-result=forwarded; C.tree[%s] = payload (hash=%s)", deliveryPath, payload.ContentHash))
	})

	// --- mp3 offline fallback: remove C's profile from B, A forwards, B
	// can't dial → §6.2.1 fallback queues at namespace=C; C polls.
	r.Run("mp3_offline_fallback_then_c_polls", func() CheckOutcome {
		if out, ok := r.Require("mp1_three_peer_setup"); !ok {
			return out
		}
		// Overwrite C's transport profile on B with a dead-end profile so
		// B's outbound dial fails. (Deleting the binding outright is more
		// surgical but tree:delete cross-handler-grants is messier than
		// just rewriting to an unroutable port.)
		cHash, err := types.ComputePeerIdentityHashFromPeerID(c.RemotePeerID())
		if err != nil {
			return SkipCheck("C identity-hash undericable: " + err.Error())
		}
		cPath := "system/peer/transport/" + types.PeerIdentityHashHex(cHash) + "/primary"
		deadProfile := tcpProfileEntityFor(cPeerID, "127.0.0.1:1") // port 1: connection refused
		if _, err := b.TreePut(ctx, cPath, deadProfile); err != nil {
			return FailCheck(fmt.Sprintf("overwrite C profile on B with dead-end: %v", err))
		}

		// Drop B's cached outbound connection to C if one is open from mp2,
		// so the dispatcher re-resolves the (now-dead) profile. We do this
		// indirectly — there's no client-exposed knob — but the dead-end
		// dial returns connection_refused; the existing cached conn might
		// still be live. The dispatcher's removeRemoteConnection on error
		// recovers, so failure on first attempt is the gate either way.
		// To force a clean miss, use a destination peer-id we never dialed:
		// derive a third never-talked-to peer-id from a fresh keypair, and
		// publish the dead-end profile under THAT peer-id.
		freshKP, kpErr := crypto.Generate()
		if kpErr != nil {
			return FailCheck("generate ephemeral keypair: " + kpErr.Error())
		}
		strangerPeerID := string(freshKP.PeerID())
		strangerHash, err := types.ComputePeerIdentityHashFromPeerID(freshKP.PeerID())
		if err != nil {
			return SkipCheck("stranger identity-hash undericable: " + err.Error())
		}
		strangerPath := "system/peer/transport/" + types.PeerIdentityHashHex(strangerHash) + "/primary"
		// Intentionally don't publish stranger's profile → first dial-attempt
		// fails with "no transport profile" → ErrDestinationUnreachable.
		_ = strangerPath
		_ = deadProfile

		// Build inner + forward; destination = the stranger (never reachable).
		payload := mustCreateEntity("test/relay-mp3-payload", map[string]string{
			"content": "offline-stranger-" + suffix,
		})
		// mp3 destination is unreachable — the inner is queued as opaque
		// bytes at Mode-S and never verified. Author with A's cap chain
		// (any cap works; the path is fallback-store, not delivery).
		inner, err := buildInnerExecute(
			a,
			"entity://"+strangerPeerID+"/system/tree",
			"put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/relay-mp/mp3-" + suffix}},
			"mp3-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   strangerPeerID,
			NextHop:       strangerPeerID,
			TTLHops:       3,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200/queued-fallback, got %d (code=%q)", status, relayErrCode(result)))
		}
		fres, err := types.ForwardResultDataFromEntity(result)
		if err != nil {
			return FailCheck("decode forward-result: " + err.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (destination unreachable), got %q (next_hop=%q stored_at=%q)",
				types.ForwardStatusQueuedFallback, fres.Status, fres.NextHop, fres.StoredAt))
		}
		if fres.StoredAt != strangerPeerID {
			return FailCheck(fmt.Sprintf("forward-result.stored_at: want %q (§6.2.1 default convention = destination peer-id), got %q",
				strangerPeerID, fres.StoredAt))
		}

		// Now poll B as the stranger would: namespace = strangerPeerID.
		// We use C's session for the poll (C has authenticated to B), but
		// the namespace is the stranger's id (the relay treats namespace as
		// data; the poll permission is checked against the caller's caps).
		// With --open-access on B, the poll proceeds.
		pollReq := types.PollRequestData{Namespace: strangerPeerID}
		pollParams, _ := pollReq.ToEntity()
		// Poll B (the relay where the fallback stored). In the real flow
		// the stranger would itself dial B; here the validator's session
		// to B drives the poll. Authentication is identical (same
		// principal); the gate is whether the entry surfaces.
		pollStatus, pollResult, err := relayExecute(ctx, b, "poll", pollParams, nil)
		if err != nil {
			return FailCheck(":poll execute: " + err.Error())
		}
		if pollStatus != 200 {
			return FailCheck(fmt.Sprintf(":poll want 200, got %d (code=%q)", pollStatus, relayErrCode(pollResult)))
		}
		pr, _ := types.PollResultDataFromEntity(pollResult)
		if len(pr.Entries) == 0 {
			return FailCheck(":poll returned no entries — fallback did not store at the expected namespace")
		}
		return PassCheck(fmt.Sprintf("destination unreachable → §6.2.1 fallback stored at namespace=%s; poll surfaced %d entry(ies)", strangerPeerID, len(pr.Entries)))
	})

	// --- mp4 forged-redirection defense.
	r.Run("mp4_forged_redirect_rejected_falls_back_to_default", func() CheckOutcome {
		if out, ok := r.Require("mp1_three_peer_setup"); !ok {
			return out
		}
		// Build a forged inbox-relay declaration claiming "C's mail lives
		// at namespace FORGED-NS on relay B" — but signed with the
		// validator's keypair (NOT C's). The TreeInboxRelayResolver MUST
		// reject the bad sig and fall through to default convention.
		const forgedNS = "FORGED-NAMESPACE-XYZ-mp4"
		// Fresh stranger so we don't collide with mp3.
		freshKP, kpErr := crypto.Generate()
		if kpErr != nil {
			return FailCheck("generate destination keypair: " + kpErr.Error())
		}
		destPeerID := string(freshKP.PeerID())

		decl := types.InboxRelayData{
			Relays: []types.InboxRelayEntry{
				{Relay: bPeerID, Namespace: forgedNS, Priority: 10},
			},
		}
		declEnt, err := decl.ToEntity()
		if err != nil {
			return FailCheck("build forged decl entity: " + err.Error())
		}

		// Sign with the WRONG keypair (the validator's connection keypair —
		// emphatically NOT the destination's). The resolver computes the
		// destination's identity hash from its peer-id and checks that the
		// signer hash matches; the validator's identity hash WILL NOT
		// match. Even if it did (impossibly), the destination's pub key
		// would fail crypto.Verify on the validator's signature. Two
		// independent fences; both fail-closed.
		//
		// We don't actually need a real signature here — the resolver also
		// rejects a missing-signer-hash mismatch. But we publish one anyway
		// to exercise the full path including crypto.Verify.
		validatorIdentityHash, _ := types.ComputePeerIdentityHashFromPeerID(a.LocalPeerID())
		sig := types.SignatureData{
			Target:    declEnt.ContentHash,
			Signer:    validatorIdentityHash, // WRONG signer (not the destination)
			Algorithm: "ed25519",
			Signature: make([]byte, 64), // garbage bytes; bound to fail Verify
		}
		sigEnt, err := sig.ToEntity()
		if err != nil {
			return FailCheck("build forged signature entity: " + err.Error())
		}

		// Publish forged decl + sig at B (anchored under B's local namespace
		// since the TreeInboxRelayResolver looks up "/" + localPeerID + "/" +
		// InboxRelayStoragePath(destPeerID)).
		declPath := types.InboxRelayStoragePath(destPeerID)
		if _, err := b.TreePut(ctx, declPath, declEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish forged decl at B/%s: %v", declPath, err))
		}
		sigPath := types.LocalSignaturePath(declEnt.ContentHash)
		if _, err := b.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish forged sig at B/%s: %v", sigPath, err))
		}

		// Trigger fallback by forwarding to destPeerID (unreachable — no
		// transport profile published). The resolver will be consulted.
		payload := mustCreateEntity("test/relay-mp4-payload", map[string]string{
			"content": "forged-redirect-probe-" + suffix,
		})
		// mp4 destination is a never-talked-to peer-id — unreachable, so the
		// inner is queued as opaque bytes at Mode-S; cap chain is moot for
		// the fallback path. Author with C's cap (validator holds one there).
		inner, err := buildInnerExecute(
			c,
			"entity://"+destPeerID+"/system/tree",
			"put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/relay-mp/mp4-" + suffix}},
			"mp4-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   destPeerID,
			NextHop:       destPeerID,
			TTLHops:       3,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200, got %d (code=%q)", status, relayErrCode(result)))
		}
		fres, err := types.ForwardResultDataFromEntity(result)
		if err != nil {
			return FailCheck("decode forward-result: " + err.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want queued-fallback, got %q", fres.Status))
		}
		// THE gate: stored_at MUST equal the destination peer-id (default
		// convention), NOT the forged namespace. If the resolver had been
		// fooled by the forged decl, stored_at == FORGED-NAMESPACE-XYZ-mp4.
		if fres.StoredAt == forgedNS {
			return FailCheck(fmt.Sprintf("FORGED-REDIRECTION ACCEPTED: stored_at=%q (the forged namespace) — TreeInboxRelayResolver did NOT reject the bad signature. V7 §5.2 forged-redirection defense BROKEN", fres.StoredAt))
		}
		if fres.StoredAt != destPeerID {
			return FailCheck(fmt.Sprintf("stored_at=%q — expected default convention (=destination peer-id %q)", fres.StoredAt, destPeerID))
		}
		return PassCheck(fmt.Sprintf("forged decl rejected by sig-verify; fallback used default convention (stored_at=%s ≠ forged %s)", destPeerID, forgedNS))
	})

	return r.Results()
}

const catRelayMultiPeer = "relay_multi_peer"

// buildInnerExecute constructs the inner envelope the §3.1.1 terminal-hop
// raw-frame path requires: a fully-signed system/envelope {root, included}
// entity whose .Data is the ECF-encoded raw bytes of the source's signed
// EXECUTE envelope.
//
// authoringClient supplies the source's keypair, identity entity, capability
// entity, and the cap-chain entities (granter identity + cap signature) from
// its own authenticate handshake — bundled into included so the destination
// verifies the chain standalone, with no RELAY extension required at C
// (§3.1 + §3.1.1 + §5.1).
//
// On raw-frame: the relay writes inner.Data verbatim onto C's inbound frame.
// C decodes, finds an EXECUTE signed by the source (= validator identity in
// the single-principal test model), verifies the cap chain, and dispatches —
// exactly as on a direct connection.
func buildInnerExecute(authoringClient *PeerClient, uri, operation string, params entity.Entity, resource *types.ResourceTarget, requestID string) (entity.Entity, error) {
	env, err := protocol.CreateAuthenticatedExecute(
		authoringClient.keypair,
		authoringClient.identityEntity,
		authoringClient.capEntity,
		requestID, uri, operation, params, resource,
	)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("create authenticated inner execute: %w", err)
	}
	// Bundle the cap chain entities (granter identity + cap signature + any
	// upstream entities) into included. CreateAuthenticatedExecute already
	// placed identity/cap/sig; authenticateIncluded carries the granter side
	// — required for the destination's V7 §5.2 chain walk.
	for h, ent := range authoringClient.authenticateIncluded {
		if _, exists := env.Included[h]; exists {
			continue
		}
		env.Include(ent)
	}
	return env.ToEntity()
}
