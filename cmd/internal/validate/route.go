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

// runRoute is the EXTENSION-ROUTE v1 storage-plane behavioral gate per
// PROPOSAL-EXTENSION-ROUTE.md (arch DRAFT — storage plane
// only; producers are out of scope, the v1 floor is the `system/route`
// entity + the documented match relay applies + the `route-configure`
// cap).
//
// The category proves the RESOLVER seam introduced by
// PROPOSAL-RELAY-SOURCE-ROUTED-MULTIHOP §3 reads the local route
// table (EXTENSION-ROUTE §3 match) when a `forward-request` carries
// neither a source route nor an explicit `next_hop`:
//
//   - source route > table read > direct/no_route default (precedence)
//   - exact destination > `*` default (longest-match-wins, degenerate
//     over a non-hierarchical peer-id space)
//   - lowest metric wins on ties
//   - expired routes are skipped
//   - no match → no_route/502 (fail-closed)
//
// The category hand-populates the table from the validator. Per the
// proposal §4 deferral: route *production* (config/DHT/gossip-learned)
// is out of ROUTE's scope by design — peer/DISCOVERY/GOSSIP would fill
// the table in deployment; tests configure it directly.
//
// Setup: clients[0]=B (the relay under test; routes published here),
// clients[1]=C (a reachable next-hop for `forward` actions), clients[2]
// =D (the destination for the `deliver` action end-to-end check).
//
// Wire witness: B's forward-result.next_hop reports the hop B's
// resolver picked. The category does not require the next-hop relay to
// successfully complete delivery — only the *resolver decision* on B is
// under test for the forward-action vectors (table-driven hop selection
// is the gate). The deliver-action vector exercises B's terminal-hop
// dispatch end-to-end because that path is observable at D.
//
// Vectors mapped to PROPOSAL-EXTENSION-ROUTE §7:
//   - route1_setup — fixture (no spec gate)
//   - route2_absent_table_no_route (= ROUTE-ABSENT-TABLE-1 + ROUTE-NOROUTE-1)
//   - route3_exact_forward (= ROUTE-EXACT-1)
//   - route4_metric_tiebreak (= ROUTE-METRIC-TIEBREAK-1)
//   - route5_expired_skipped (= ROUTE-EXPIRED-SKIP-1)
//   - route6_default_route (= ROUTE-DEFAULT-1)
//   - route7_exact_beats_default (proposal §3 longest-match-wins)
//   - route8_deliver_action (= ROUTE-DELIVER-1)
//
// Deferred:
//   - ROUTE-PERHOP-CAP-1 — needs a relay that does NOT grant the
//     forwarder `relay-forward`; incompatible with the --open-access
//     rig. Per-hop cap is not ROUTE-specific (it's RELAY §5.2); the
//     existing capability category exercises it.
func runRoute(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catRoute)

	r.Declare("route1_setup", "publish D's TCP profile on B so the deliver-action check has a reachable terminal hop")
	r.Declare("route2_absent_table_no_route", "EXTENSION-ROUTE §7 ROUTE-ABSENT-TABLE-1 + ROUTE-NOROUTE-1: with no system/route entries (and no source route + no next_hop), :forward MUST 502 no_route (v1 default resolver is direct-or-no_route)")
	r.Declare("route3_exact_forward", "ROUTE-EXACT-1: a system/route with exact Match + action=forward + Via picks Via as next-hop; forward-result.next_hop = the Via")
	r.Declare("route4_metric_tiebreak", "ROUTE-METRIC-TIEBREAK-1: two exact routes for the same dest with different metrics; the lower-Metric route wins")
	r.Declare("route5_expired_skipped", "ROUTE-EXPIRED-SKIP-1: a route whose ExpiresAt is past at match-time MUST be skipped; with no other matching route → no_route/502")
	r.Declare("route6_default_route", "ROUTE-DEFAULT-1: `*` default-route Match resolves when no exact-match route exists")
	r.Declare("route7_exact_beats_default", "PROPOSAL §3 longest-match-wins: an exact Match outranks `*` even when `*` has a competing route in the table")
	r.Declare("route8_deliver_action", "ROUTE-DELIVER-1: action=deliver → terminal hop at this relay (next == destination); B's dispatcher delivers inner to D end-to-end")

	if len(clients) < 3 {
		for _, n := range []string{
			"route1_setup",
			"route2_absent_table_no_route",
			"route3_exact_forward",
			"route4_metric_tiebreak",
			"route5_expired_skipped",
			"route6_default_route",
			"route7_exact_beats_default",
			"route8_deliver_action",
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

	// freshPeerID returns a fresh Base58-shaped stranger peer-id, used to
	// give each check an independent "destination" so routes published in
	// one check don't shadow another. Generated by a real keypair so the
	// peer-id form is conformant.
	freshPeerID := func() (string, error) {
		kp, err := crypto.Generate()
		if err != nil {
			return "", err
		}
		return string(kp.PeerID()), nil
	}

	// publishRoute publishes a system/route entity on B's tree under the
	// canonical RoutePath. Returns the route's content hash so callers
	// can identify which routes they put if needed.
	publishRoute := func(rd types.RouteData) (hash.Hash, error) {
		ent, err := rd.ToEntity()
		if err != nil {
			return hash.Hash{}, err
		}
		path := types.RoutePath(ent.ContentHash)
		return b.TreePut(ctx, path, ent)
	}

	// probeForward sends a :forward to B with no Route, no NextHop, ttl=4,
	// for the given destination. Returns the forward-result + http status.
	probeForward := func(destination string, label string) (uint, types.ForwardResultData, entity.Entity, error) {
		payload := mustCreateEntity("test/route-"+label, map[string]string{
			"content": "probe-" + label + "-" + suffix,
		})
		inner, err := buildInnerExecute(
			d,
			"entity://"+destination+"/system/tree",
			"put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/route-probe/" + label + "-" + suffix}},
			"route-"+label+"-"+suffix,
		)
		if err != nil {
			return 0, types.ForwardResultData{}, entity.Entity{}, fmt.Errorf("build inner: %w", err)
		}
		fr := types.ForwardRequestData{
			Destination:   destination,
			TTLHops:       4,
			EnvelopeInner: inner.ContentHash,
		}
		params, _ := fr.ToEntity()
		included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
		status, result, err := relayExecute(ctx, b, "forward", params, included)
		if err != nil {
			return 0, types.ForwardResultData{}, entity.Entity{}, err
		}
		var fres types.ForwardResultData
		if status == 200 {
			fres, _ = types.ForwardResultDataFromEntity(result)
		}
		return status, fres, result, nil
	}

	// --- route1 setup: publish D's TCP profile on B so route8's terminal
	//     deliver-action has a reachable next-hop.
	r.Run("route1_setup", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/transport/* — start peers with --open-access")
		}
		dProfile := tcpProfileEntityFor(dPeerID, d.addr)
		dHash, err := types.ComputePeerIdentityHashFromPeerID(d.RemotePeerID())
		if err != nil {
			return SkipCheck("D identity-hash underivable from peer-id: " + err.Error())
		}
		dPathOnB := "system/peer/transport/" + types.PeerIdentityHashHex(dHash) + "/primary"
		if _, err := b.TreePut(ctx, dPathOnB, dProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish D profile on B at %s: %v", dPathOnB, err))
		}
		return PassCheck(fmt.Sprintf("D profile published on B at %s", dPathOnB))
	})

	// --- route2: absent table → no_route/502. Run BEFORE any `*` route is
	//     published so the leaked default doesn't shadow the stranger dest.
	r.Run("route2_absent_table_no_route", func() CheckOutcome {
		strangerDest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		status, _, result, err := probeForward(strangerDest, "absent-table")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 502 {
			return FailCheck(fmt.Sprintf("status: want 502, got %d (code=%q) — empty table MUST surface no_route", status, relayErrCode(result)))
		}
		if code := relayErrCode(result); code != types.RelayErrNoRoute {
			return FailCheck(fmt.Sprintf("error code: want %q, got %q", types.RelayErrNoRoute, code))
		}
		return PassCheck("empty table → no_route/502")
	})

	// --- route3: exact match → forward action picks Via.
	r.Run("route3_exact_forward", func() CheckOutcome {
		dest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		if _, err := publishRoute(types.RouteData{
			Match: dest, Action: types.RouteActionForward, Via: cPeerID,
		}); err != nil {
			return FailCheck("publishRoute: " + err.Error())
		}
		status, fres, result, err := probeForward(dest, "exact-forward")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("status: want 200 (table resolved → forward), got %d (code=%q)", status, relayErrCode(result)))
		}
		if fres.NextHop != cPeerID {
			return FailCheck(fmt.Sprintf("forward-result.next_hop: want %q (table Via), got %q — resolver did NOT pick the exact route's Via",
				cPeerID, fres.NextHop))
		}
		return PassCheck(fmt.Sprintf("exact-Match route → next_hop=%s (Via)", cPeerID))
	})

	// --- route4: lowest metric wins on tie.
	r.Run("route4_metric_tiebreak", func() CheckOutcome {
		dest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		// Higher metric first.
		if _, err := publishRoute(types.RouteData{
			Match: dest, Action: types.RouteActionForward, Via: dPeerID, Metric: 20,
		}); err != nil {
			return FailCheck("publishRoute(high-metric): " + err.Error())
		}
		// Lower metric second — should win.
		if _, err := publishRoute(types.RouteData{
			Match: dest, Action: types.RouteActionForward, Via: cPeerID, Metric: 5,
		}); err != nil {
			return FailCheck("publishRoute(low-metric): " + err.Error())
		}
		status, fres, result, err := probeForward(dest, "metric-tiebreak")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("status: %d (code=%q)", status, relayErrCode(result)))
		}
		if fres.NextHop != cPeerID {
			return FailCheck(fmt.Sprintf("forward-result.next_hop: want %q (Metric=5 lower than 20), got %q", cPeerID, fres.NextHop))
		}
		return PassCheck("lower-Metric route wins tie-break")
	})

	// --- route5: expired route skipped → with no fresh route, 502.
	//     Run BEFORE `*` is published (else `*` would mask the expiry).
	r.Run("route5_expired_skipped", func() CheckOutcome {
		dest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		// ExpiresAt = 1 ms — definitely past at any plausible test time.
		if _, err := publishRoute(types.RouteData{
			Match: dest, Action: types.RouteActionForward, Via: cPeerID,
			ExpiresAt: 1,
		}); err != nil {
			return FailCheck("publishRoute(expired): " + err.Error())
		}
		status, _, result, err := probeForward(dest, "expired-skipped")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 502 {
			return FailCheck(fmt.Sprintf("status: want 502 (expired route filtered → no usable match), got %d (code=%q) — resolver may be honoring expired routes",
				status, relayErrCode(result)))
		}
		if code := relayErrCode(result); code != types.RelayErrNoRoute {
			return FailCheck(fmt.Sprintf("error code: want %q, got %q", types.RelayErrNoRoute, code))
		}
		return PassCheck("expired route silently filtered; falls through to no_route/502")
	})

	// --- route6: `*` default-route Match resolves when no exact match.
	//     IMPORTANT: after this check, the `*` route stays bound on B
	//     and serves as the default for every subsequent destination
	//     that has no exact-match route. Subsequent route checks MUST
	//     publish exact routes that supersede it.
	r.Run("route6_default_route", func() CheckOutcome {
		dest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		if _, err := publishRoute(types.RouteData{
			Match: types.RouteMatchDefault, Action: types.RouteActionForward, Via: cPeerID,
		}); err != nil {
			return FailCheck("publishRoute(*-default): " + err.Error())
		}
		status, fres, result, err := probeForward(dest, "default-route")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("status: %d (code=%q) — `*` default route did not match a destination with no exact entry",
				status, relayErrCode(result)))
		}
		if fres.NextHop != cPeerID {
			return FailCheck(fmt.Sprintf("forward-result.next_hop: want %q (Via from `*`), got %q", cPeerID, fres.NextHop))
		}
		return PassCheck(fmt.Sprintf("`*` default route → next_hop=%s", cPeerID))
	})

	// --- route7: exact > default on tiebreak (proposal §3 longest-match-wins).
	//     The `*` route from route6 is still bound; we publish an exact route
	//     for a fresh dest with Via=dPeerID. Resolver must prefer the exact
	//     route's Via=dPeerID over the leaked `*` route's Via=cPeerID.
	r.Run("route7_exact_beats_default", func() CheckOutcome {
		if out, ok := r.Require("route6_default_route"); !ok {
			return out
		}
		dest, err := freshPeerID()
		if err != nil {
			return FailCheck("freshPeerID: " + err.Error())
		}
		if _, err := publishRoute(types.RouteData{
			Match: dest, Action: types.RouteActionForward, Via: dPeerID,
		}); err != nil {
			return FailCheck("publishRoute(exact): " + err.Error())
		}
		status, fres, result, err := probeForward(dest, "exact-beats-default")
		if err != nil {
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("status: %d (code=%q)", status, relayErrCode(result)))
		}
		if fres.NextHop != dPeerID {
			return FailCheck(fmt.Sprintf("forward-result.next_hop: want %q (exact Via=D, not `*` Via=C), got %q — resolver ignored longest-match-wins (proposal §3)",
				dPeerID, fres.NextHop))
		}
		return PassCheck(fmt.Sprintf("exact Match outranked `*` default: next_hop=%s (not %s)", dPeerID, cPeerID))
	})

	// --- route8: action=deliver → terminal hop at B (next == destination).
	//     B's dispatcher delivers inner directly to D; D's tree gets the
	//     payload. Uses D (real reachable peer) as the destination so
	//     the terminal hop has a transport profile.
	r.Run("route8_deliver_action", func() CheckOutcome {
		if out, ok := r.Require("route1_setup"); !ok {
			return out
		}
		// Publish: route {Match=D, Action=deliver}.
		if _, err := publishRoute(types.RouteData{
			Match:  dPeerID,
			Action: types.RouteActionDeliver,
		}); err != nil {
			return FailCheck("publishRoute(deliver): " + err.Error())
		}
		deliveryPath := fmt.Sprintf("system/route-probe/route8-%s", suffix)
		payload := mustCreateEntity("test/route-route8-payload", map[string]string{
			"content": "deliver-action-end-to-end-" + suffix,
		})
		putReqEnt, putResource, putErr := tree.CreatePutRequest(deliveryPath, &payload)
		if putErr != nil {
			return FailCheck("build tree:put-request: " + putErr.Error())
		}
		inner, err := buildInnerExecute(
			d,
			"entity://"+dPeerID+"/system/tree",
			"put",
			putReqEnt,
			putResource,
			"route8-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner: " + err.Error())
		}
		fr := types.ForwardRequestData{
			Destination:   dPeerID,
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
		fres, _ := types.ForwardResultDataFromEntity(result)
		if fres.Status != types.ForwardStatusForwarded {
			return FailCheck(fmt.Sprintf("forward-result.status: want forwarded (table resolved deliver → terminal-at-B → DeliverInner), got %q (stored_at=%q) — B's dispatcher may not have a route to D, or the deliver action was misinterpreted",
				fres.Status, fres.StoredAt))
		}
		// End-to-end: verify D's tree received the payload.
		var gotEnt entity.Entity
		var getErr error
		for attempt := 0; attempt < 30; attempt++ {
			gotEnt, _, getErr = d.TreeGet(ctx, deliveryPath)
			if getErr == nil && gotEnt.Type == payload.Type {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if getErr != nil || gotEnt.ContentHash != payload.ContentHash {
			return FailCheck(fmt.Sprintf("D.TreeGet(%s) after deliver-action terminal: err=%v got_hash=%s want=%s",
				deliveryPath, getErr, gotEnt.ContentHash, payload.ContentHash))
		}
		return PassCheck(fmt.Sprintf("action=deliver resolved at B → terminal; D.tree[%s] = payload (hash=%s)", deliveryPath, payload.ContentHash))
	})

	return r.Results()
}

const catRoute = "route"
