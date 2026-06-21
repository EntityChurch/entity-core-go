package validate

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runRelaySourceRoute is the EXTENSION-RELAY source-routed multi-hop
// behavioral gate — PROPOSAL-RELAY-SOURCE-ROUTED-MULTIHOP §2 (arch DRAFT,
// build-test pass against Go before fold).
//
// The pre-proposal v1 relay can only single-hop: a `forward-request` carries
// one `next_hop` peer-id and no path, so a chain cannot advance past the
// first named hop. This category proves the source-routed path works
// end-to-end across two relay hops (A → B → C → D), where A is the
// validator (sender role), B and C are intermediate relays, and D is the
// destination. The 4-distinct-peer wire path falls out of using validator
// keypair as A plus 3 connected clients.
//
// Setup convention:
//   - clients[0]=B (first relay; A dispatches `:forward` here)
//   - clients[1]=C (intermediate relay)
//   - clients[2]=D (destination, runs the inner EXECUTE)
//
// Caps come from each peer's seed policy; checks expect --open-access on B
// and C so they grant `relay-forward` to A and B respectively (peer-manager
// start --debug is the standard test rig).
//
// Checks (proposal §4):
//   - srcr1_four_peer_setup — publish C's profile on B + D's profile on C
//     so the per-hop dispatcher can dial.
//   - srcr2_3hop_a_to_d (= SRCROUTE-3HOP-1) — A→B→C→D with route=[C, D];
//     payload binds at D's tree.
//   - srcr3_terminal_equiv (= SRCROUTE-TERMINAL-EQUIV-1) — route=[D] alone
//     (NextHop empty) at B is equivalent to v1.0 next_hop=D terminal hop.
//   - srcr4_ttl_exhaust (= SRCROUTE-TTL-EXHAUST-1) — receive-side ttl=0
//     with route=[D] rejects ttl_exhausted/400, never silently delivers.
//   - srcr5_intermediate_unreachable_fallback (= SRCROUTE-UNREACHABLE-
//     FALLBACK-1) — route=[stranger, D] where stranger unreachable from B
//     triggers §6.2.1 Mode-S fallback (not silent drop).
//   - srcr6_no_route_no_next (= RESOLVER-DEFAULT-1) — empty route + empty
//     next_hop → no_route/502 (v1 default resolver = direct-or-no_route;
//     Phase 2 ROUTE wires the table-backed resolver).
//
// Deferred (documented in cohort handoff, not implemented here):
//   - SRCROUTE-4HOP-1 (validates two genuine intermediate hops) — would
//     need a 4th client. Covered in-process by unit tests in
//     ext/relay/relay_test.go.
//   - SRCROUTE-CAP-PERHOP-1 (per-hop cap enforcement under source-route) —
//     needs a relay without `relay-forward` granted to its predecessor;
//     incompatible with the --open-access rig.  The per-hop cap path is
//     not source-route-specific (existing capability category exercises
//     it), so the source-route extension does not re-prove it.
func runRelaySourceRoute(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catRelaySourceRoute)

	r.Declare("srcr1_four_peer_setup", "publish C's TCP transport profile on B and D's profile on C so B can dial C and C can dial D for a 3-hop A→B→C→D source-routed path")
	r.Declare("srcr2_3hop_a_to_d", "PROPOSAL §4 SRCROUTE-3HOP-1: A → B(route=[C,D]) → C(route=[D]) → D; payload lands at D's tree via genuine intermediate hop at C")
	r.Declare("srcr3_terminal_equiv", "PROPOSAL §4 SRCROUTE-TERMINAL-EQUIV-1: route=[D] (single-element) at B behaves identically to next_hop=D (the degenerate single-hop source route)")
	r.Declare("srcr4_ttl_exhaust", "PROPOSAL §4 SRCROUTE-TTL-EXHAUST-1: a receiver getting forward-request with ttl_hops=0 MUST reject ttl_exhausted/400; no partial or silent delivery (§4.3 fail-closed)")
	r.Declare("srcr5_intermediate_unreachable_fallback", "PROPOSAL §4 SRCROUTE-UNREACHABLE-FALLBACK-1: route=[unreachable-peer, D]; first-hop relay cannot reach the routed intermediate → §6.2.1 Mode-S fallback queues at namespace=D, not a silent drop")
	r.Declare("srcr6_no_route_no_next", "PROPOSAL §4 RESOLVER-DEFAULT-1: forward-request with neither route nor next_hop and no resolver wired → no_route/502 (v1 default resolver)")

	if len(clients) < 3 {
		for _, n := range []string{
			"srcr1_four_peer_setup",
			"srcr2_3hop_a_to_d",
			"srcr3_terminal_equiv",
			"srcr4_ttl_exhaust",
			"srcr5_intermediate_unreachable_fallback",
			"srcr6_no_route_no_next",
		} {
			name := n
			r.Run(name, func() CheckOutcome { return SkipCheck("requires 3 peers (use -peers b,c,d)") })
		}
		return r.Results()
	}

	b, c, d := clients[0], clients[1], clients[2]
	cPeerID := string(c.RemotePeerID())
	dPeerID := string(d.RemotePeerID())
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// --- srcr1 setup: profiles so the relay chain can dial each next hop.
	r.Run("srcr1_four_peer_setup", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/transport/*") || !c.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B or C connection grants do not allow writes under system/peer/transport/* — start peers with --open-access (peer-manager start --debug)")
		}
		// Publish C's TCP profile in B so B's dispatcher can dial C.
		cProfile := tcpProfileEntityFor(cPeerID, c.addr)
		cHash, err := types.ComputePeerIdentityHashFromPeerID(c.RemotePeerID())
		if err != nil {
			return SkipCheck("C identity-hash underivable from peer-id (SHA-256-form): " + err.Error())
		}
		cPath := "system/peer/transport/" + types.PeerIdentityHashHex(cHash) + "/primary"
		if _, err := b.TreePut(ctx, cPath, cProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish C profile on B at %s: %v", cPath, err))
		}
		// Publish D's TCP profile in C so C's dispatcher can dial D.
		dProfile := tcpProfileEntityFor(dPeerID, d.addr)
		dHash, err := types.ComputePeerIdentityHashFromPeerID(d.RemotePeerID())
		if err != nil {
			return SkipCheck("D identity-hash underivable from peer-id: " + err.Error())
		}
		dPath := "system/peer/transport/" + types.PeerIdentityHashHex(dHash) + "/primary"
		if _, err := c.TreePut(ctx, dPath, dProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish D profile on C at %s: %v", dPath, err))
		}
		return PassCheck(fmt.Sprintf("transport profiles published: C@B(%s)=%s, D@C(%s)=%s", cPath, c.addr, dPath, d.addr))
	})

	// --- srcr2: full 3-hop source-routed A → B → C → D.
	deliveryPathSRCR2 := fmt.Sprintf("system/relay-srcr/srcr2-%s", suffix)
	r.Run("srcr2_3hop_a_to_d", func() CheckOutcome {
		if out, ok := r.Require("srcr1_four_peer_setup"); !ok {
			return out
		}
		payload := mustCreateEntity("test/relay-srcr2-payload", map[string]string{
			"content": "delivered-via-2-relay-hops-" + suffix,
		})
		putReqEnt, putResource, putErr := tree.CreatePutRequest(deliveryPathSRCR2, &payload)
		if putErr != nil {
			return FailCheck("build tree:put-request: " + putErr.Error())
		}
		// Inner EXECUTE targets D's tree:put — authored against the cap that
		// D will accept (the validator's connection to D).
		inner, err := buildInnerExecute(
			d,
			"entity://"+dPeerID+"/system/tree",
			"put",
			putReqEnt,
			putResource,
			"srcr2-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner system/envelope: " + err.Error())
		}
		// Source-routed forward: route=[C, D], NextHop=C (must equal Route[0]
		// per proposal §2.1), Destination=D. B pops C, forwards Route=[D]
		// NextHop=D to C with ttl-1; C sees Route[0]=D=Destination → terminal,
		// delivers inner to D.
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
			Route:         []string{cPeerID, dPeerID},
			NextHop:       cPeerID,
			TTLHops:       8,
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
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (B dispatched to C), got %q (stored_at=%q) — B's dispatcher may have failed to dial C, route popping may be broken, or B is not pop-aware",
				types.ForwardStatusForwarded, fres.Status, fres.StoredAt))
		}
		if fres.NextHop != cPeerID {
			return FailCheck(fmt.Sprintf("forward-result.next_hop: want %q (Route[0] B popped), got %q — pop algorithm may be reading NextHop instead of Route[0]", cPeerID, fres.NextHop))
		}

		// Brief retry — the inner EXECUTE travels A→B→C→D over two real
		// network hops + a final dispatch; D's tree-bind may lag.
		var gotEnt entity.Entity
		var getErr error
		for attempt := 0; attempt < 30; attempt++ {
			gotEnt, _, getErr = d.TreeGet(ctx, deliveryPathSRCR2)
			if getErr == nil && gotEnt.Type == payload.Type {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if getErr != nil {
			return FailCheck(fmt.Sprintf("D.TreeGet(%s) after 3-hop forward: %v — terminal dispatch at C may have lost the inner, or C is not pop-aware (route=[D] case)", deliveryPathSRCR2, getErr))
		}
		if gotEnt.ContentHash != payload.ContentHash {
			return FailCheck(fmt.Sprintf("payload content_hash drift at D: want %s, got %s — §9 envelope opacity broken across a relay hop (inner was re-encoded)",
				payload.ContentHash, gotEnt.ContentHash))
		}
		return PassCheck(fmt.Sprintf("A → B → C → D delivered: forward-result=forwarded next_hop=%s; D.tree[%s] = payload (hash=%s)",
			cPeerID, deliveryPathSRCR2, payload.ContentHash))
	})

	// --- srcr3: route=[D] alone → terminal at B, equivalent to next_hop=D.
	deliveryPathSRCR3 := fmt.Sprintf("system/relay-srcr/srcr3-%s", suffix)
	r.Run("srcr3_terminal_equiv", func() CheckOutcome {
		if out, ok := r.Require("srcr1_four_peer_setup"); !ok {
			return out
		}
		// B needs D's profile to deliver directly. Publish it now (srcr1
		// only published C@B, D@C — for srcr3 the terminal-hop is at B
		// itself reaching D).
		dProfile := tcpProfileEntityFor(dPeerID, d.addr)
		dHash, err := types.ComputePeerIdentityHashFromPeerID(d.RemotePeerID())
		if err != nil {
			return SkipCheck("D identity-hash underivable from peer-id: " + err.Error())
		}
		dPathOnB := "system/peer/transport/" + types.PeerIdentityHashHex(dHash) + "/primary"
		if _, err := b.TreePut(ctx, dPathOnB, dProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish D profile on B at %s: %v", dPathOnB, err))
		}
		payload := mustCreateEntity("test/relay-srcr3-payload", map[string]string{
			"content": "terminal-equiv-route-of-one-" + suffix,
		})
		putReqEnt, putResource, putErr := tree.CreatePutRequest(deliveryPathSRCR3, &payload)
		if putErr != nil {
			return FailCheck("build tree:put-request: " + putErr.Error())
		}
		inner, err := buildInnerExecute(d,
			"entity://"+dPeerID+"/system/tree", "put",
			putReqEnt, putResource, "srcr3-"+suffix)
		if err != nil {
			return FailCheck("build inner system/envelope: " + err.Error())
		}
		// route=[D] alone, NextHop intentionally empty — Route is sufficient.
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
			Route:         []string{dPeerID},
			TTLHops:       2,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200, got %d (code=%q) — route=[D] alone must be sufficient (proposal §2.1)", status, relayErrCode(result)))
		}
		fres, _ := types.ForwardResultDataFromEntity(result)
		if fres.Status != types.ForwardStatusForwarded {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (terminal at B), got %q stored_at=%q",
				types.ForwardStatusForwarded, fres.Status, fres.StoredAt))
		}

		var gotEnt entity.Entity
		var getErr error
		for attempt := 0; attempt < 30; attempt++ {
			gotEnt, _, getErr = d.TreeGet(ctx, deliveryPathSRCR3)
			if getErr == nil && gotEnt.Type == payload.Type {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if getErr != nil || gotEnt.ContentHash != payload.ContentHash {
			return FailCheck(fmt.Sprintf("D.TreeGet(%s) after route=[D] terminal at B: err=%v got_hash=%s want=%s",
				deliveryPathSRCR3, getErr, gotEnt.ContentHash, payload.ContentHash))
		}
		return PassCheck(fmt.Sprintf("route=[%s] alone delivered to D — terminal-equivalence to next_hop holds", dPeerID))
	})

	// --- srcr4: ttl_hops=0 on receipt → ttl_exhausted/400. The receiver
	// is C; we send :forward to C directly (validator → C), so the 400
	// surfaces synchronously without traversing B's fire-and-forget hop.
	r.Run("srcr4_ttl_exhaust", func() CheckOutcome {
		if out, ok := r.Require("srcr1_four_peer_setup"); !ok {
			return out
		}
		payload := mustCreateEntity("test/relay-srcr4-payload", map[string]string{
			"content": "ttl-exhaust-should-not-deliver-" + suffix,
		})
		inner, err := buildInnerExecute(d,
			"entity://"+dPeerID+"/system/tree", "put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/relay-srcr/srcr4-" + suffix}},
			"srcr4-"+suffix)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
			Route:         []string{dPeerID},
			TTLHops:       0, // already exhausted on arrival per §3.1 / §4.3
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, c, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf(":forward want 400 (ttl_exhausted), got %d (code=%q) — ttl=0 receive-side gate did not fire fail-closed",
				status, relayErrCode(result)))
		}
		if code := relayErrCode(result); code != types.RelayErrTTLExhausted {
			return FailCheck(fmt.Sprintf("error code: want %q, got %q", types.RelayErrTTLExhausted, code))
		}
		return PassCheck("ttl_hops=0 on receipt rejected ttl_exhausted/400 fail-closed; no silent delivery")
	})

	// --- srcr5: route=[stranger, D] where stranger is unreachable from B.
	// B pops stranger as next, ForwardToNextHop fails ErrDestinationUnreachable,
	// §6.2.1 fallback queues at namespace=D on B (default convention).
	r.Run("srcr5_intermediate_unreachable_fallback", func() CheckOutcome {
		if out, ok := r.Require("srcr1_four_peer_setup"); !ok {
			return out
		}
		// Stranger peer-id: a fresh keypair B has no transport profile for.
		strangerKP, kpErr := crypto.Generate()
		if kpErr != nil {
			return FailCheck("generate stranger keypair: " + kpErr.Error())
		}
		strangerPeerID := string(strangerKP.PeerID())

		payload := mustCreateEntity("test/relay-srcr5-payload", map[string]string{
			"content": "route-via-stranger-unreachable-" + suffix,
		})
		inner, err := buildInnerExecute(d,
			"entity://"+dPeerID+"/system/tree", "put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/relay-srcr/srcr5-" + suffix}},
			"srcr5-"+suffix)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
			Route:         []string{strangerPeerID, dPeerID},
			NextHop:       strangerPeerID,
			TTLHops:       8,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200 (queued-fallback is success), got %d (code=%q)",
				status, relayErrCode(result)))
		}
		fres, _ := types.ForwardResultDataFromEntity(result)
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (stranger unreachable → §6.2.1), got %q",
				types.ForwardStatusQueuedFallback, fres.Status))
		}
		// stored_at = bare namespace = destination peer-id (default convention,
		// since D has no published inbox-relay declaration here).
		if fres.StoredAt != dPeerID {
			return FailCheck(fmt.Sprintf("stored_at: want %q (default convention = destination peer-id), got %q",
				dPeerID, fres.StoredAt))
		}
		return PassCheck(fmt.Sprintf("source-routed intermediate unreachable → §6.2.1 fallback at namespace=%s (default convention); never a silent drop", dPeerID))
	})

	// --- srcr6: empty route AND empty next_hop → no_route/502 (v1 floor).
	r.Run("srcr6_no_route_no_next", func() CheckOutcome {
		if out, ok := r.Require("srcr1_four_peer_setup"); !ok {
			return out
		}
		payload := mustCreateEntity("test/relay-srcr6-payload", map[string]string{
			"content": "no-route-no-next-" + suffix,
		})
		inner, err := buildInnerExecute(d,
			"entity://"+dPeerID+"/system/tree", "put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/relay-srcr/srcr6-" + suffix}},
			"srcr6-"+suffix)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
			// Route + NextHop both intentionally empty.
			TTLHops:       4,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 502 {
			return FailCheck(fmt.Sprintf(":forward want 502 (no_route), got %d (code=%q) — v1 default resolver is direct-or-no_route; a table-driven resolver may have been wired (Phase 2 ROUTE)",
				status, relayErrCode(result)))
		}
		if code := relayErrCode(result); code != types.RelayErrNoRoute {
			return FailCheck(fmt.Sprintf("error code: want %q, got %q", types.RelayErrNoRoute, code))
		}
		return PassCheck("no route + no next_hop → no_route/502 (v1 default resolver)")
	})

	return r.Results()
}

const catRelaySourceRoute = "relay_source_route"
