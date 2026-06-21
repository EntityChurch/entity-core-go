package validate

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// catTransportFamily exercises the §7.3 mechanical track of PROPOSAL-
// TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE on a single
// target peer (no second peer required):
//
//   - G1 mixed-transport coexistence — TCP and HTTP profile entries
//     for the same synthetic peer must occupy two distinct slots in
//     the target's tree under system/peer/transport/{peer_id}/{id}.
//     Pre-G1, an HTTP profile collided with TCP at "primary" and
//     silently overwrote it.
//
//   - R3a granter idempotency over reconnect — opening a fresh
//     connection with the same identity must reproduce the same
//     capability-token entity hash. Pre-R3a, the granter minted a
//     CreatedAt: now() entity per handshake, churning the token hash.
//
// Cross-peer subscription over HTTP (R1) lives in the convergence
// flow (catConvergence) when -http-peers is provided — it requires
// two peer endpoints + their HTTP URLs.
const catTransportFamily = "transport_family"

// transportFamilyRunner carries the pre-handshaken primary client and
// a factory that opens a second client against the same target with
// the same identity (for the R3a reconnect check).
type transportFamilyRunner struct {
	primary   *PeerClient
	reconnect func() (*PeerClient, error)
}

func runTransportFamily(ctx context.Context, run transportFamilyRunner) []CheckResult {
	r := NewCheckRunner(catTransportFamily)

	r.Declare("g1_mixed_transport_coexist", "EXTENSION-NETWORK §6.5 (Amendment 8; ex-proposal G1)")
	r.Declare("r3a_cap_hash_stable_across_reconnect", "EXTENSION-NETWORK §6.6 (Amendment 8 R3a idempotency)")
	r.Declare("q1_priority_field_round_trips", "EXTENSION-NETWORK §6.5 (Amendment 8 Q1 priority)")
	r.Declare("q5_priority_selection_ordering", "EXTENSION-NETWORK §10 (Amendment 8 Q5 selection ordering)")
	r.Declare("r3_profile_enum_membership", "EXTENSION-NETWORK §6.5.1 (ratified freshness/cap_flow enums; RULING-CYCLE-CLOSEOUT-0.3 R3)")

	// Synthetic peer-id (never dialed). Profile entries are tree-only
	// fixtures; URLs can be unreachable placeholders.
	// V7.64: path segment is hex of synthetic peer's identity hash.
	fakeKP, _ := crypto.Generate()
	fakePeerID := fakeKP.PeerID()
	fakeHash, _ := types.ComputePeerIdentityHashFromPeerID(fakePeerID)
	fakeHashHex := types.PeerIdentityHashHex(fakeHash)
	transportPrefix := "system/peer/transport/" + fakeHashHex + "/"

	// G1: Mixed-transport coexistence. Publish TCP + HTTP profiles
	// for the synthetic peer in the target's tree. List the prefix
	// and assert BOTH bindings present — pre-G1 the HTTP write would
	// overwrite TCP at "primary".
	r.Run("g1_mixed_transport_coexist", func() CheckOutcome {
		if !run.primary.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}

		tcpEnt := tcpProfileEntityFor(string(fakePeerID), "127.0.0.1:65535")
		tcpPath := transportPrefix + "primary"
		if _, err := run.primary.TreePut(ctx, tcpPath, tcpEnt); err != nil {
			return FailCheck("publish TCP profile at " + tcpPath + ": " + err.Error())
		}

		httpEnt := httpProfileEntityFor(string(fakePeerID), "http://127.0.0.1:65534/entity")
		httpPath := transportPrefix + "primary-http"
		if _, err := run.primary.TreePut(ctx, httpPath, httpEnt); err != nil {
			return FailCheck("publish HTTP profile at " + httpPath + ": " + err.Error())
		}

		listing, _, err := run.primary.TreeListing(ctx, transportPrefix)
		if err != nil {
			return FailCheck("list " + transportPrefix + ": " + err.Error())
		}

		gotTCP, gotHTTP := false, false
		for k := range listing {
			if k == "primary" || strings.HasSuffix(k, "/primary") {
				gotTCP = true
			}
			if k == "primary-http" || strings.HasSuffix(k, "/primary-http") {
				gotHTTP = true
			}
		}

		if !gotTCP || !gotHTTP {
			keys := make([]string, 0, len(listing))
			for k := range listing {
				keys = append(keys, k)
			}
			return FailCheck(fmt.Sprintf(
				"G1: expected BOTH primary (tcp) and primary-http (http) under %s — got tcp=%v http=%v (listing keys=%v); HTTP write likely collided with TCP at \"primary\"",
				transportPrefix, gotTCP, gotHTTP, keys))
		}
		return PassCheck(fmt.Sprintf("G1: tcp at primary + http at primary-http coexist under %s (2 distinct slots)", transportPrefix))
	})

	// Q1 round-trip: publish two HTTP profiles for the synthetic peer
	// with DISTINCT explicit Priority values, list them back, fetch
	// each entity, and assert the target peer's decoder surfaces the
	// priority field intact. This is the cross-impl wire-shape gate
	// for the Q1 ratification — pre-Q1 the field didn't exist; an
	// impl that silently drops or mis-types it (Gap A: silent wire-
	// type divergence) would fail here against an impl that doesn't.
	//
	// The test does NOT exercise the selection rule's runtime path
	// (that would require dispatch to a real peer and is covered by
	// cross_peer_http_subscription). It validates the surface: an
	// emitted priority value survives a round-trip through the target
	// peer's tree handler decode/re-encode cycle.
	r.Run("q1_priority_field_round_trips", func() CheckOutcome {
		if !run.primary.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}
		// Use a SECOND synthetic peer to avoid colliding with the
		// G1 coexist check above (which already wrote to
		// transportPrefix). This keeps the priority test
		// independently meaningful even when both run.
		fakeKP2, _ := crypto.Generate()
		fakePeer2 := string(fakeKP2.PeerID())
		// V7.64: path segment is hex of synthetic peer's identity hash.
		fakeHash2, _ := types.ComputePeerIdentityHashFromPeerID(fakeKP2.PeerID())
		prefix2 := "system/peer/transport/" + types.PeerIdentityHashHex(fakeHash2) + "/"

		highPrio := uint64(10)
		lowPrio := uint64(50)

		entHigh := httpProfileEntityWithPriority(fakePeer2, "http://127.0.0.1:65500/entity", &highPrio)
		entLow := httpProfileEntityWithPriority(fakePeer2, "http://127.0.0.1:65501/entity", &lowPrio)

		if _, err := run.primary.TreePut(ctx, prefix2+"primary", entHigh); err != nil {
			return FailCheck("publish high-priority profile at primary: " + err.Error())
		}
		if _, err := run.primary.TreePut(ctx, prefix2+"secondary", entLow); err != nil {
			return FailCheck("publish low-priority profile at secondary: " + err.Error())
		}

		gotHigh, _, err := run.primary.TreeGet(ctx, prefix2+"primary")
		if err != nil {
			return FailCheck("read back primary: " + err.Error())
		}
		gotLow, _, err := run.primary.TreeGet(ctx, prefix2+"secondary")
		if err != nil {
			return FailCheck("read back secondary: " + err.Error())
		}

		dataHigh, err := types.HTTPProfileDataFromEntity(gotHigh)
		if err != nil {
			return FailCheck("decode primary profile: " + err.Error())
		}
		dataLow, err := types.HTTPProfileDataFromEntity(gotLow)
		if err != nil {
			return FailCheck("decode secondary profile: " + err.Error())
		}

		if dataHigh.Priority == nil {
			return FailCheck("Q1 wire round-trip failed: primary profile decoded with Priority == nil (target peer dropped the field)")
		}
		if *dataHigh.Priority != highPrio {
			return FailCheck(fmt.Sprintf("Q1 wire round-trip failed: primary priority got %d, want %d", *dataHigh.Priority, highPrio))
		}
		if dataLow.Priority == nil {
			return FailCheck("Q1 wire round-trip failed: secondary profile decoded with Priority == nil")
		}
		if *dataLow.Priority != lowPrio {
			return FailCheck(fmt.Sprintf("Q1 wire round-trip failed: secondary priority got %d, want %d", *dataLow.Priority, lowPrio))
		}
		return PassCheck(fmt.Sprintf("Q1: priority field round-trips through target peer (primary=%d, secondary=%d both intact)", highPrio, lowPrio))
	})

	// Q5 (§8.10 residual; AMENDMENT-8 landing gate): the dispatcher MUST
	// select transport profiles by (priority asc, profile-id lex) at
	// RUNTIME — not just round-trip the priority field. Q1 ratified the
	// field shape; Q5 pins that selection actually USES it. When this
	// gate is 3-way green, the staged R5 §10 + R6 amendment lands.
	//
	// Wire-observable test: publish 3 TCP profiles for a synthetic peer
	// at 3 ephemeral listeners, with priorities {alpha-a=100, bravo-b=10,
	// charlie-c=50} so neither lex order, publish order, nor numeric
	// order coincides with priority order. Then trigger a cross-peer
	// EXECUTE (validator → target → synthetic) which forces the target's
	// dispatcher to resolve a transport profile for the synthetic peer
	// and dial. We watch which listener gets the FIRST TCP connection:
	// MUST be bravo-b (priority 10).
	//
	// The dial cannot complete (the synthetic peer is just bare TCP
	// sockets recording the connect attempt), so the validator's EXECUTE
	// will fail downstream — but the TCP-level dial observation is the
	// load-bearing signal and happens BEFORE any cap or handshake
	// validation against the synthetic peer.
	r.Run("q5_priority_selection_ordering", func() CheckOutcome {
		if !run.primary.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}

		// Synthetic target peer — no real peer behind this identity.
		synthKP, err := crypto.Generate()
		if err != nil {
			return FailCheck("generate synthetic keypair: " + err.Error())
		}
		synthPeerID := string(synthKP.PeerID())

		// Three ephemeral listeners. Each goroutine atomically records the
		// FIRST connect time; subsequent connections are ignored. We compare
		// the three timestamps at the end and pick the earliest — robust
		// against dispatchers that fan out or retry on failure.
		type listenerObs struct {
			profileID string
			priority  uint64
			port      int
			ln        net.Listener
			firstNs   atomic.Int64
		}
		// Design: lex order is alpha-a < bravo-b < charlie-c. Assign
		// priority 100 to alpha (lex first; should LOSE if dispatcher
		// reads priority), 10 to bravo (must WIN), 50 to charlie.
		obs := []*listenerObs{
			{profileID: "alpha-a", priority: 100},
			{profileID: "bravo-b", priority: 10},
			{profileID: "charlie-c", priority: 50},
		}
		const winnerIdx = 1
		for i, o := range obs {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				for _, prev := range obs[:i] {
					prev.ln.Close()
				}
				return FailCheck("open ephemeral TCP listener: " + err.Error())
			}
			o.ln = ln
			o.port = ln.Addr().(*net.TCPAddr).Port
			go func(o *listenerObs) {
				for {
					conn, err := o.ln.Accept()
					if err != nil {
						return
					}
					o.firstNs.CompareAndSwap(0, time.Now().UnixNano())
					conn.Close()
				}
			}(o)
		}
		defer func() {
			for _, o := range obs {
				o.ln.Close()
			}
		}()

		// Publish 3 transport profiles in NON-monotonic publish order
		// (charlie, alpha, bravo) so neither publish order nor lex order
		// nor priority order is accidentally the same as the iteration.
		publishOrder := []int{2, 0, 1}
		// V7.64: path segment is hex of synthetic peer's identity hash.
		synthHash, _ := types.ComputePeerIdentityHashFromPeerID(crypto.PeerID(synthPeerID))
		transportPrefix := "system/peer/transport/" + types.PeerIdentityHashHex(synthHash) + "/"
		for _, i := range publishOrder {
			o := obs[i]
			addr := "127.0.0.1:" + fmt.Sprintf("%d", o.port)
			prio := o.priority
			ent := tcpProfileEntityWithPriority(synthPeerID, addr, &prio)
			path := transportPrefix + o.profileID
			if _, err := run.primary.TreePut(ctx, path, ent); err != nil {
				return FailCheck(fmt.Sprintf("publish profile %s (priority=%d): %v", o.profileID, o.priority, err))
			}
		}

		// Trigger via the subscription-delivery path — the only wire-
		// accessible mechanism that fires DispatchLocalEnvelope (the
		// path where the dispatcher cross-peer-routes via RemoteExecute).
		// A direct SendExecute(entity://synth/...) is wire-received and
		// goes through DispatchEnvelope, which does NOT cross-peer-route
		// (matches local handler patterns). Subscriptions are the path
		// cross_peer_tcp_subscription uses; we mimic that without
		// needing a real receiver — the dispatcher dials before any
		// receiver-side validation.
		suffix := fmt.Sprintf("q5-%d", time.Now().UnixNano())
		deliverURI := "entity://" + synthPeerID + "/system/inbox/" + suffix
		pattern := "system/validate/" + suffix + "/*"
		events := []string{"created"}

		tokenEntity, tokenSigEntity, err := run.primary.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck("create delivery token: " + err.Error())
		}

		subID, _, _, err := run.primary.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, events, nil)
		if err != nil {
			return FailCheck("subscribe (deliver=" + deliverURI + ") rejected: " + err.Error())
		}
		defer func() { _, _, _ = run.primary.Unsubscribe(ctx, subID) }()

		// Trigger: write under the subscription pattern. Subscription
		// engine fires → queues delivery → delivery worker calls
		// DispatchLocalEnvelope with the EXECUTE → cross-peer route to
		// synthPeerID → resolveTransportTarget → DIAL. The dispatcher
		// dials our priority-10 listener first if (priority asc, lex)
		// is honored.
		probeEnt := mustCreateEntity("test/q5-priority-probe", map[string]string{"value": "x"})
		probePath := "system/validate/" + suffix + "/probe"
		if _, err := run.primary.TreePut(ctx, probePath, probeEnt); err != nil {
			return FailCheck("trigger put: " + err.Error())
		}

		// Collect observations: wait up to 3s past the trigger for any
		// connections to land, then pick the earliest. If no listener got
		// a connection, the dispatcher never tried to dial.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			anyHit := false
			for _, o := range obs {
				if o.firstNs.Load() != 0 {
					anyHit = true
					break
				}
			}
			if anyHit {
				time.Sleep(200 * time.Millisecond)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		earliestIdx := -1
		var earliestNs int64
		for i, o := range obs {
			ns := o.firstNs.Load()
			if ns == 0 {
				continue
			}
			if earliestIdx == -1 || ns < earliestNs {
				earliestIdx = i
				earliestNs = ns
			}
		}
		if earliestIdx == -1 {
			return FailCheck(fmt.Sprintf(
				"no dial attempt observed at any of the 3 published profiles within 3s — target dispatcher did not route the cross-peer EXECUTE to the synthetic peer (profiles published at %s{alpha-a,bravo-b,charlie-c})",
				transportPrefix,
			))
		}
		hit := obs[earliestIdx]
		if earliestIdx == winnerIdx {
			return PassCheck(fmt.Sprintf(
				"dispatcher dialed %s (priority=%d) first across {alpha-a=100, bravo-b=10, charlie-c=50} — (priority asc, lex) ordering verified end-to-end",
				hit.profileID, hit.priority,
			))
		}
		return FailCheck(fmt.Sprintf(
			"dispatcher dialed %s (priority=%d) first; expected %s (priority=10). Published {alpha-a=100, bravo-b=10, charlie-c=50}; dispatcher is selecting by something other than priority asc (likely lex order, which would pick alpha-a=100, or publish order)",
			hit.profileID, hit.priority, obs[winnerIdx].profileID,
		))
	})

	// R3a: Reconnect against the same target with the same identity
	// MUST yield the same capability-token entity content hash. Pre-
	// R3a behavior stamped CreatedAt: now() every handshake, so each
	// reconnect produced a fresh token.
	r.Run("r3a_cap_hash_stable_across_reconnect", func() CheckOutcome {
		if run.reconnect == nil {
			return SkipCheck("transport_family runner missing reconnect factory")
		}
		firstHash := run.primary.CapEntity().ContentHash
		if firstHash.IsZero() {
			return FailCheck("primary client has no cap entity after handshake")
		}

		second, err := run.reconnect()
		if err != nil {
			return FailCheck("reconnect: " + err.Error())
		}
		defer second.Close()

		secondHash := second.CapEntity().ContentHash
		if secondHash.IsZero() {
			return FailCheck("reconnect client has no cap entity after handshake")
		}

		if firstHash != secondHash {
			return FailCheck(fmt.Sprintf(
				"R3a violated: reconnect minted a fresh token — first=%s second=%s (pre-R3a behavior: CreatedAt: now() per handshake)",
				firstHash, secondHash))
		}
		return PassCheck(fmt.Sprintf("R3a: cap token entity hash stable across reconnect (%s)", firstHash))
	})

	// R3 (RULING-CYCLE-CLOSEOUT-0.3): EXTENSION-NETWORK §6.5.1 ratifies the
	// freshness / cap_flow enums; the validator MAY assert membership since
	// they are normative. Read the TARGET's OWN self-published transport
	// profiles (system/peer/transport/{ownID}/) and assert every advertised
	// freshness ∈ {live, async, static-immutable+signed-pointer} and
	// cap_flow ∈ {egress, ingress, both}. This is the gate that catches the
	// pre-ruling Python `cap_flow: none` (outside the enum → egress). Peers
	// that self-publish no profile (the common default — self-publication is a
	// serving-mode behaviour) WARN cleanly: nothing advertised, nothing to
	// assert. Decode is partial (just the two enum fields), so it is agnostic
	// to which profile type (tcp / http / http-poll) carries them.
	r.Run("r3_profile_enum_membership", func() CheckOutcome {
		freshnessOK := map[string]bool{"live": true, "async": true, "static-immutable+signed-pointer": true}
		capFlowOK := map[string]bool{"egress": true, "ingress": true, "both": true}

		// V7.64: path segment is hex of target's identity hash.
		ownHash, hashErr := types.ComputePeerIdentityHashFromPeerID(run.primary.RemotePeerID())
		if hashErr != nil {
			return SkipCheck("target identity hash undericable (SHA-256-form): " + hashErr.Error())
		}
		ownPrefix := "system/peer/transport/" + types.PeerIdentityHashHex(ownHash) + "/"
		listing, _, err := run.primary.TreeListing(ctx, ownPrefix)
		if err != nil || len(listing) == 0 {
			return WarnCheck(fmt.Sprintf("target self-publishes no transport profile under %s — nothing to assert (self-publication is a serving-mode behaviour; enum gate is inert here, not a failure)", ownPrefix))
		}

		var violations []string
		checked := 0
		for key := range listing {
			ent, _, gerr := run.primary.TreeGet(ctx, ownPrefix+key)
			if gerr != nil {
				continue
			}
			var pf struct {
				TransportType string `cbor:"transport_type"`
				Freshness     string `cbor:"freshness"`
				CapFlow       string `cbor:"cap_flow"`
			}
			if ecf.Decode(ent.Data, &pf) != nil {
				continue
			}
			checked++
			if pf.Freshness != "" && !freshnessOK[pf.Freshness] {
				violations = append(violations, fmt.Sprintf("%s.freshness=%q (not in {live,async,static-immutable+signed-pointer})", key, pf.Freshness))
			}
			if pf.CapFlow != "" && !capFlowOK[pf.CapFlow] {
				violations = append(violations, fmt.Sprintf("%s.cap_flow=%q (not in {egress,ingress,both} — §6.5.1; e.g. \"none\" → \"egress\")", key, pf.CapFlow))
			}
		}
		if len(violations) > 0 {
			return FailCheck(fmt.Sprintf("§6.5.1 enum violation on self-published profile(s): %v", violations))
		}
		if checked == 0 {
			return WarnCheck(fmt.Sprintf("profiles listed under %s but none decoded with freshness/cap_flow — nothing asserted", ownPrefix))
		}
		return PassCheck(fmt.Sprintf("all %d self-published profile(s) have freshness/cap_flow within the ratified §6.5.1 enums", checked))
	})

	return r.Results()
}

// httpProfileEntityFor builds an HTTPProfileData entity at the §6.5
// wire shape. Mirrors tcpProfileEntityFor in convergence.go.
func httpProfileEntityFor(peerID, url string) entity.Entity {
	return httpProfileEntityWithPriority(peerID, url, nil)
}

// wsProfileEntityFor builds a WebSocketProfileData entity at the
// §6.5.2b wire shape — Thread F substrate gate. Mirrors the http/tcp
// builders above.
func wsProfileEntityFor(peerID, url string) entity.Entity {
	data := types.WebSocketProfileData{
		PeerID:        peerID,
		TransportType: "websocket",
		Endpoint:      types.TransportEndpointURL{URL: url},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportWebSocket, cbor.RawMessage(raw))
	return ent
}

// tcpProfileEntityWithPriority builds a TCPProfileData entity at the
// §4.1 wire shape with an optional explicit Priority field (Q1 / arch
// §8.9). priority == nil ⇒ wire omitempty; consumers apply the default
// rule (primary → 0, others → 100).
func tcpProfileEntityWithPriority(peerID, addr string, priority *uint64) entity.Entity {
	data := types.TCPProfileData{
		PeerID:        peerID,
		TransportType: "tcp",
		Endpoint:      types.TransportEndpointURL{URL: "tcp://" + addr},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
		Priority:      priority,
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(raw))
	return ent
}

// httpProfileEntityWithPriority constructs an HTTP transport profile
// entity with an optional explicit Priority field (Q1 / arch §8.9).
// priority == nil means the wire emits omitempty; consumers apply the
// default rule (primary → 0, others → 100).
func httpProfileEntityWithPriority(peerID, url string, priority *uint64) entity.Entity {
	data := types.HTTPProfileData{
		PeerID:        peerID,
		TransportType: "http",
		Endpoint:      types.TransportEndpointURL{URL: url},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
		Priority:      priority,
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportHTTP, cbor.RawMessage(raw))
	return ent
}
