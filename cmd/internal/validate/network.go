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
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/inbox"
)

const catNetwork = "network"

// runNetwork drives the rung-3 system/network handler (EXTENSION-NETWORK §4,
// Amendment 12) against a LIVE target, reconciling the maintain-peer reconnect
// lifecycle cross-peer instead of by build-shape comparison. Five probes,
// in dependency order:
//
//	network_maintain_installs_graph — maintain-peer → §2.4 result + the three
//	    §4.1 lifecycle continuations resident in the target's tree, each riding
//	    the handler grant.
//	network_status_reports_peer     — status → the peer present + connected,
//	    pending_count bare zero (no §8 outbox, Amendment 11).
//	network_release_tears_down      — release-peer → §2.6 result lists the
//	    continuation paths, they are gone, terminal disconnected write lands.
//	network_retry_survives_outage   — the loop keeps retrying against a peer
//	    that stays dead, counted from outside by dials. The anchor below cannot
//	    ask this: it restarts the peer, so one retry satisfies it.
//	network_reconnect_anchor        — the §4.1 failure path, LIVE: maintain →
//	    kill → target flips off connected and stamps the failure episode
//	    (§3.13 failing_since) → restart → status returns connected on its own,
//	    episode cleared. This was the marker-proposal §4 vector (a lost marker
//	    with reason connection_failed); that requirement is retired — the
//	    on-disconnect continuation now carries on_error, so a failed reconnect
//	    routes to the backoff seam instead of binding a marker per attempt.
//
// Like the §A3 liveness floor (liveness.go, whose killable-counterpart
// mechanism this reuses), the handler's reactive half is only observable by
// KILLING the peer at the other end of a live connection — so the harness runs
// its own throwaway Go counterpart on an ephemeral 127.0.0.1 port (reachable
// from podman siblings — they run --network host), asks the TARGET to
// maintain-peer TOWARD it, and reads the graph the target installs. Probe 4
// additionally RESTARTS the counterpart on the same addr+identity, which the
// floor never needed; that is what networkCounterpart adds over
// livenessCounterpart.
//
// Admin posture (§3.2): maintain-peer is admin-only. The validator authors it
// as the connected peer with its connection grant; a 403 is the §3.2 contract,
// not a bug — the probe SKIPs with guidance to run -identity framework-admin,
// mirroring the liveness category's grant gate.
func runNetwork(ctx context.Context, client *PeerClient, keepaliveEnvelopeMs int) []CheckResult {
	r := NewCheckRunner(catNetwork)

	r.Declare("network_maintain_installs_graph", "EXTENSION-NETWORK §4.1 maintain-peer + §2.4 result + the §4.1 reconnect continuation graph")
	r.Declare("network_status_reports_peer", "EXTENSION-NETWORK §4.3 status / §2.7 (pending_count bare zero — Amendment 11)")
	r.Declare("network_release_tears_down", "EXTENSION-NETWORK §4.2 release-peer / §2.6 + terminal §3.13 disconnected write")
	r.Declare("network_retry_survives_outage", "EXTENSION-NETWORK §4.1/§2.2: the reconnect retry loop survives a lasting outage (retry-forever is normative)")
	r.Declare("network_reconnect_anchor", "EXTENSION-NETWORK §4.1 reconnect: autonomous re-establish + the §3.13 failure episode (failing_since stamped, then cleared)")

	if client.Profile() == ProfileCore {
		for _, name := range []string{
			"network_maintain_installs_graph",
			"network_status_reports_peer",
			"network_release_tears_down",
			"network_retry_survives_outage",
			"network_reconnect_anchor",
		} {
			r.Run(name, func() CheckOutcome {
				return SkipCheck("outside --profile core (NETWORK-extension handler, V7 §9.0)")
			})
		}
		return r.Results()
	}

	// Counterpart A serves probes 1–3 (one maintain session, released by
	// probe 3). Probe 4 runs its own restartable counterpart so its
	// kill/restart never entangles the teardown assertions.
	var cpA *networkCounterpart
	defer func() {
		if cpA != nil {
			cpA.kill()
		}
	}()

	r.Run("network_maintain_installs_graph", func() CheckOutcome {
		if client.RemotePeerIdentityHash().IsZero() {
			return FailCheck("no remote identity hash from handshake — cannot derive status/continuation paths")
		}
		cp, err := startNetworkCounterpart()
		if err != nil {
			return FailCheck("start in-process counterpart peer: " + err.Error())
		}
		cpA = cp

		// EXECUTE maintain-peer toward the counterpart. Address is passed so
		// the target's EnsureConnected can resolve the dial without a
		// pre-published transport profile.
		result, out := networkMaintain(ctx, client, cp)
		if !out.pass {
			return out.outcome
		}

		// §2.4 result shape.
		if result.SessionID == "" {
			return FailCheck("maintain-result carries no session_id (§2.4)")
		}
		if len(result.Subscriptions) != 2 {
			return FailCheck(fmt.Sprintf("maintain-result lists %d subscriptions, want exactly 2 (the on-disconnect + on-reconnect lifecycle subs, §4.1)", len(result.Subscriptions)))
		}
		// §3.11: a chain_id MUST be a single path segment, because it IS a
		// segment of the §3.10.6 marker path. The value itself is opaque (§3.11
		// gives it no format), so this asserts the SHAPE and nothing more — the
		// old assertion demanded a literal "network/maintain/" prefix, which is
		// precisely the multi-segment value the rule now forbids.
		if result.ChainID == "" {
			return FailCheck("maintain-result carries no chain_id (§2.4 / §4.1 graph chain)")
		}
		if strings.Contains(result.ChainID, "/") {
			return FailCheck(fmt.Sprintf("maintain-result chain_id %q is not a single path segment (§3.11) — it would fork the §3.10.6 marker tree into extra levels", result.ChainID))
		}

		// The §4.1 graph: three continuations must be resident in the target's
		// tree, each dispatching under the network handler's own grant.
		grantHash, gerr := networkGrantHash(ctx, client)
		if gerr != nil {
			return FailCheck("resolve target's network handler grant: " + gerr.Error())
		}
		for _, cont := range []struct {
			label, b58, hexp string
		}{
			{"on-disconnect", cp.inboxPath("on-disconnect"), cp.inboxPathHex("on-disconnect")},
			{"on-reconnect", cp.inboxPath("on-reconnect"), cp.inboxPathHex("on-reconnect")},
			{"on-reconnect-backoff", cp.managedPath("on-reconnect-backoff"), cp.managedPathHex("on-reconnect-backoff")},
		} {
			data, path, ok := getContinuation(ctx, client, cont.b58, cont.hexp)
			if !ok {
				return FailCheck(fmt.Sprintf("no %s continuation in the target's tree at %s (nor the hex-peer-id form) — the §4.1 graph did not install", cont.label, cont.b58))
			}
			if data.DispatchCapability != grantHash {
				return FailCheck(fmt.Sprintf("%s continuation at %s has dispatch_capability %s, want the network handler grant %s (§11 — the graph advances under the handler's own authority)", cont.label, path, data.DispatchCapability, grantHash))
			}
		}
		return PassCheck(fmt.Sprintf("maintain-peer installed the §4.1 graph: session_id=%s, 2 lifecycle subs, chain_id=%s, three continuations resident under the handler grant", result.SessionID, result.ChainID))
	})

	r.Run("network_status_reports_peer", func() CheckOutcome {
		if out, ok := r.Require("network_maintain_installs_graph"); !ok {
			return out
		}
		st, out := networkStatus(ctx, client)
		if !out.pass {
			return out.outcome
		}
		if st.PendingCount != 0 {
			return FailCheck(fmt.Sprintf("top-level status pending_count = %d, want 0 — Go ships no §8 outbox (Amendment 11); a nonzero here is a real divergence, not tolerated", st.PendingCount))
		}
		var found *types.NetworkPeerSummaryData
		for i := range st.MaintainedPeers {
			if st.MaintainedPeers[i].PeerID == cpA.peerID {
				found = &st.MaintainedPeers[i]
				break
			}
		}
		if found == nil {
			return FailCheck(fmt.Sprintf("counterpart %s absent from status maintained_peers (%d peers reported) — status is not surfacing the maintain session", cpA.peerID[:12], len(st.MaintainedPeers)))
		}
		if found.Status != types.PeerStatusConnected {
			return FailCheck(fmt.Sprintf("counterpart reported status=%q, want connected (the session established in probe 1)", found.Status))
		}
		if found.PendingCount != 0 {
			return FailCheck(fmt.Sprintf("per-peer pending_count = %d, want 0 (Amendment 11 — no §8 outbox)", found.PendingCount))
		}
		return PassCheck(fmt.Sprintf("status reports the counterpart connected, pending_count 0 per-peer and top-level (%d maintained peer(s))", len(st.MaintainedPeers)))
	})

	r.Run("network_release_tears_down", func() CheckOutcome {
		if out, ok := r.Require("network_maintain_installs_graph"); !ok {
			return out
		}
		rel, out := networkRelease(ctx, client, cpA.peerID)
		if !out.pass {
			return out.outcome
		}

		// §2.6 cleaned_up lists the three lifecycle paths. Match by suffix so
		// the Base58-vs-hex peer-id segment form is tolerated cross-impl.
		wantSuffixes := []string{"/on-disconnect", "/on-reconnect", "/on-reconnect-backoff"}
		for _, suf := range wantSuffixes {
			if !anyHasSuffix(rel.CleanedUp, suf) {
				return FailCheck(fmt.Sprintf("release-result cleaned_up %v does not list a %s path (§2.6 — teardown must report every removed continuation)", rel.CleanedUp, suf))
			}
		}

		// The continuations must be GONE from the tree.
		for _, cont := range []struct{ label, b58, hexp string }{
			{"on-disconnect", cpA.inboxPath("on-disconnect"), cpA.inboxPathHex("on-disconnect")},
			{"on-reconnect", cpA.inboxPath("on-reconnect"), cpA.inboxPathHex("on-reconnect")},
			{"on-reconnect-backoff", cpA.managedPath("on-reconnect-backoff"), cpA.managedPathHex("on-reconnect-backoff")},
		} {
			if _, _, ok := getContinuation(ctx, client, cont.b58, cont.hexp); ok {
				return FailCheck(fmt.Sprintf("%s continuation still resident after release-peer (%s) — §4.2 teardown left the graph standing", cont.label, cont.b58))
			}
		}

		// Terminal §3.13 write: release-peer (default reason shutdown) evicts
		// the connection and records disconnected.
		if _, lastState, found := pollPeerStatus(ctx, client, cpA.hexID, 10*time.Second, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusDisconnected
		}); !found {
			return FailCheck(fmt.Sprintf("target's status for the released peer never reached disconnected (%s) — §4.2 shutdown must write the terminal §3.13 transition", lastState))
		}
		return PassCheck("release-peer tore down the graph: 3 paths reported in cleaned_up, all gone from the tree, terminal disconnected write landed")
	})

	// The retry loop must SURVIVE the outage, not merely start one.
	//
	// network_reconnect_anchor cannot ask this and never could: it restarts the
	// counterpart promptly, so recovering needs exactly ONE retry to land. A
	// loop that fires twice and dies passes it. That is not a hypothetical —
	// Go's loop did exactly that (bisected to before 2026-07-16, found only by
	// leaving a peer dead and counting), because §4.1's one-shot backoff
	// continuation is re-installed by the very maintain-peer it dispatches, and
	// the advance then consumes the remaining_executions it read before that
	// re-install existed. The path ends up empty and the next advance reports
	// {advanced:false} with status 200 — no error, no marker, no log. Routed
	// to arch 2026-07-16 as the §4.1 one-shot backoff clobber.
	//
	// Any impl following §4.1's one-shot literally is a candidate, so this asks
	// the question of the wire rather than of the pseudocode.
	//
	// Measured from OUTSIDE by dial count: the counterpart is killed and its
	// address taken over by a socket that counts connects. Nothing about the
	// target's internals is assumed — every impl's retry ends in a dial.
	r.Run("network_retry_survives_outage", func() CheckOutcome {
		// Harness fail-closed (arch ruling 2026-07-17 §4): VERIFY the envelope
		// against the target's observed pings — never take the flag's word and
		// then blame the peer for a window it was never configured to meet.
		if keepaliveEnvelopeMs <= 0 {
			return SkipCheck("harness: pass -keepalive-envelope-ms matching the target's §2.3 envelope so the disconnect is observable in seconds — start the target with --keepalive 2000,1000,2")
		}
		cp, err := startNetworkCounterpart()
		if err != nil {
			return FailCheck("start retry-survival counterpart: " + err.Error())
		}
		defer cp.kill()

		// Short backoff so several retries fit in a probe window:
		// delays 500ms, 1s, 1s, … ⇒ the 4th retry is due ~3.5s after the
		// failure. Under the §2.2 defaults it would be ~15s.
		minMs, maxMs := uint64(500), uint64(1000)
		if _, out := networkMaintainWithBackoff(ctx, client, cp,
			&types.BackoffConfigData{MinMs: &minMs, MaxMs: &maxMs}); !out.pass {
			return out.outcome
		}

		// Harness fail-closed (arch ruling 2026-07-17 §4). MUST sit here, after
		// maintain: the target pings peers it MAINTAINS, so before the
		// relationship exists there is nothing to measure. Everything below
		// asserts the target notices a dead counterpart inside the envelope —
		// a claim that is only the PEER's to answer if the target was actually
		// started with that envelope. Verify it; never infer it from the flag.
		if out := RequireKeepaliveEnvelope(cp, keepaliveEnvelopeMs); out != nil {
			return *out
		}
		if _, lastState, found := pollPeerStatus(ctx, client, cp.hexID, 15*time.Second, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("retry-survival counterpart never reached connected (%s) — cannot arm the outage vector", lastState))
		}

		// Kill it and take the port, so every later dial is counted.
		cp.kill()
		dc, derr := startDialCounter(cp.addr)
		if derr != nil {
			return FailCheck(derr.Error())
		}
		defer dc.stop()

		demoteDeadline := time.Duration(keepaliveEnvelopeMs)*time.Millisecond*3/2 + 10*time.Second
		if _, lastState, found := pollPeerStatus(ctx, client, cp.hexID, demoteDeadline, func(d types.PeerStatusData) bool {
			return d.Status != types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("target's status never left connected within %v (%s) — the disconnect was not detected, so no retry loop to survive", demoteDeadline, lastState))
		}

		// Poll to the threshold rather than sleeping a fixed window: a healthy
		// loop reaches 4 dials ~3.5s after the failure and the probe ends there.
		// Only a stalled one pays the full deadline.
		const wantDials = 4
		deadline := time.Now().Add(25 * time.Second)
		for dc.count() < wantDials && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return FailCheck("context canceled while counting reconnect dials")
			case <-time.After(200 * time.Millisecond):
			}
		}
		if n := dc.count(); n < wantDials {
			return FailCheck(fmt.Sprintf("only %d reconnect dial(s) in %v against a peer that stayed dead, want >=%d at min_ms=500/max_ms=1000 — the retry loop stopped instead of retrying forever, so this peer would never recover a neighbour that came back later. A loop that dies after ~2 attempts is the §4.1 one-shot backoff clobber — the continuation is re-installed by the very maintain-peer it dispatches, and the advance then consumes the remaining_executions it read before that re-install existed; the reconnect anchor cannot see it because re-establishing needs only one retry",
				n, time.Since(deadline.Add(-25*time.Second)).Round(time.Millisecond), wantDials))
		}
		return PassCheck(fmt.Sprintf("retry loop survived the outage: %d reconnect dials against a peer that stayed dead (>=%d at min_ms=500/max_ms=1000) — retry-forever holds", dc.count(), wantDials))
	})

	r.Run("network_reconnect_anchor", func() CheckOutcome {
		if out, ok := r.Require("network_maintain_installs_graph"); !ok {
			return out
		}
		// Harness fail-closed (arch ruling 2026-07-17 §4) — see above.
		if keepaliveEnvelopeMs <= 0 {
			return SkipCheck("harness: pass -keepalive-envelope-ms matching the target's §2.3 envelope so the disconnect is observable in seconds — start the target with --keepalive 2000,1000,2")
		}
		cp, err := startNetworkCounterpart()
		if err != nil {
			return FailCheck("start reconnect-anchor counterpart: " + err.Error())
		}
		defer cp.kill()

		// 1. Maintain toward the fresh counterpart, then confirm connected.
		if _, out := networkMaintain(ctx, client, cp); !out.pass {
			return out.outcome
		}

		// Harness fail-closed (arch ruling 2026-07-17 §4) — verified after
		// maintain, for the reason given at the retry probe.
		if out := RequireKeepaliveEnvelope(cp, keepaliveEnvelopeMs); out != nil {
			return *out
		}
		if _, lastState, found := pollPeerStatus(ctx, client, cp.hexID, 15*time.Second, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("reconnect-anchor counterpart never reached connected in the target's tree (%s) — cannot arm the kill vector", lastState))
		}

		// 2. Kill it. The target's keepalive loop (short envelope) demotes off
		// connected; the on-disconnect lifecycle sub then fires the reconnect
		// continuation, whose EnsureConnected fails against the dead addr and
		// — carrying no on_error — binds the §3.10 lost marker.
		cp.kill()

		demoteDeadline := time.Duration(keepaliveEnvelopeMs)*time.Millisecond*3/2 + 10*time.Second
		if _, lastState, found := pollPeerStatus(ctx, client, cp.hexID, demoteDeadline, func(d types.PeerStatusData) bool {
			return d.Status != types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("target's status for the killed counterpart never left connected within %v (%s) — the disconnect was not detected, so the reconnect lifecycle never fired", demoteDeadline, lastState))
		}

		// The failure record. This used to REQUIRE a lost-error marker with
		// reason connection_failed, and that requirement is now retired: the
		// on-disconnect continuation carries `on_error` routing to the
		// managed-namespace backoff seam, so a failed reconnect ROUTES rather
		// than binding a §3.10 no-on_error marker. A reconnect failing against
		// an offline peer is the expected path through the §4.1 graph, and the
		// marker recorded the lifecycle working as though it were breaking —
		// one marker per retry, forever, for a peer that is merely away.
		//
		// PROPOSAL-CONTINUATION-LOST-ERROR-MARKER §4 named this path its
		// "natural test subject", so retiring it here is deliberate and worth
		// stating: the proposal's §4 "Key convergence" requirement (same
		// scenario ⇒ same (chain_id, step_index, reason) on all three impls)
		// loses its canonical vector. It needs a new one — a chain that fails
		// with no on_error BY DESIGN, rather than one whose no-on_error was the
		// defect. Routed, not silently dropped.
		//
		// What replaces it is the durable record the §2 ruling made canonical:
		// the §3.13 status entity's `failing_since`, transition-written ONCE per
		// failure episode. That is strictly better as an anchor — it is one
		// record instead of one-per-attempt, and it is the field the §2.2 retry
		// pacing is actually derived from, so asserting it tests the mechanism
		// rather than a by-product of it.
		//
		// FAIL when absent — TIGHTENED 2026-08-13, on the condition this comment
		// itself set.
		//
		// It read: "Go leads here and the sibling catch-up is drafted but unsent,
		// so Rust/Python have no `failing_since` yet … it tightens to FAIL once
		// the seats land §2." Both seats have landed it, and the claim was stale
		// rather than merely cautious — it survived because a WARN is invisible
		// in a green run, so nothing ever forced a re-measure.
		//
		// Measured 3-of-3 on the wire, not read from a report:
		//   go      validate-complete.sh, both home formats
		//   rust    1152d35 — network_reconnect_anchor PASS, 5/5 0 skips
		//   python  ad0ef98 — network_reconnect_anchor PASS, 5/5 0 skips
		// (`-keepalive-envelope-ms 2000` against a peer started
		//  `--keepalive 1000,500,2`; source: rust core/peer/src/peer_status.rs:135,
		//  py packages/entity-core/.../peer/remote.go:489 stamping the episode.)
		//
		// The sibling measurement was itself unavailable until today: the
		// envelope precondition rejected a correctly-configured harness at the
		// boundary, so this check skipped against every peer from a direct
		// `validate-peer` run and the staleness could not be seen. See
		// RequireKeepaliveEnvelope.
		failing, _, fok := pollPeerStatus(ctx, client, cp.hexID, demoteDeadline, func(d types.PeerStatusData) bool {
			return d.FailingSince != 0
		})
		episodeRecorded := fok && failing.FailingSince != 0
		if !episodeRecorded {
			return FailCheck(fmt.Sprintf("target's §3.13 status for the killed peer carries no failing_since within %v — "+
				"the failure episode has no durable record, so §2.2 retry pacing cannot be derived and cannot survive a restart. "+
				"All three impls stamp it as of 2026-08-13 (go, rust 1152d35, python ad0ef98, each measured on the wire), "+
				"so this is a regression rather than a not-yet-landed surface", demoteDeadline))
		}

		// 3. Restart the counterpart on the same addr+identity; the paced
		// backoff retry's EnsureConnected now succeeds — status returns to
		// connected with no further operator action.
		if err := cp.start(); err != nil {
			return FailCheck("restart counterpart on same addr: " + err.Error())
		}
		reconnectDeadline := time.Duration(keepaliveEnvelopeMs)*time.Millisecond + 60*time.Second
		recovered, lastState, found := pollPeerStatus(ctx, client, cp.hexID, reconnectDeadline, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		})
		if !found {
			return FailCheck(fmt.Sprintf("target never re-established connected after the counterpart restarted on %s within %v (%s) — the §4.1 backoff reconnect did not recover the relationship autonomously", cp.addr, reconnectDeadline, lastState))
		}
		// Recovery ENDS the episode. A failing_since surviving a re-establish
		// would have the next failure resume a stale curve — deriving a large
		// attempt count and a max-length wait for a peer that just came back —
		// so the clear is as load-bearing as the stamp.
		if episodeRecorded && recovered.FailingSince != 0 {
			return FailCheck(fmt.Sprintf("target re-established connected but its §3.13 status still carries failing_since=%d — the failure episode was never closed, so the next failure will resume a stale §2.2 backoff curve instead of starting a fresh one", recovered.FailingSince))
		}

		// The retired requirement, kept as its negative. Every reconnect that
		// failed during the outage has now happened, so one pass is enough: if
		// the failures were still being recorded as lost chain dispatches
		// instead of routed to the backoff seam, a marker would be sitting here.
		// Asserting the absence is what keeps on_error from silently rotting
		// off the on-disconnect continuation — nothing else would notice.
		if m, mp, found := findLostMarker(ctx, client, "connection_failed"); found {
			return FailCheck(fmt.Sprintf("a lost-error marker with reason connection_failed is bound at %s (coordinate %s/%s) — the failed reconnect was recorded as a lost chain dispatch instead of routing through the on-disconnect continuation's on_error to the backoff seam, which binds one marker per retry for a peer that is merely away", mp, m.ChainID, m.StepIndex))
		}

		return PassCheck(fmt.Sprintf("reconnect anchor: kill → demoted off connected (failure episode recorded, failing_since=%d) → restart → autonomous re-establish to connected, episode cleared; failed reconnect routed via on_error, no lost marker bound", failing.FailingSince))
	})

	return r.Results()
}

// networkOutcome carries a probe helper's terminal outcome plus a pass flag so
// callers can early-return the exact CheckOutcome (skip vs fail) the helper
// decided.
type networkOutcome struct {
	pass    bool
	outcome CheckOutcome
}

func netOK() networkOutcome                { return networkOutcome{pass: true} }
func netBad(o CheckOutcome) networkOutcome { return networkOutcome{outcome: o} }

// networkMaintain EXECUTEs maintain-peer toward the counterpart and decodes the
// §2.4 result. A 403 is the §3.2 admin-only contract → SkipCheck.
func networkMaintain(ctx context.Context, client *PeerClient, cp *networkCounterpart) (types.MaintainResultData, networkOutcome) {
	return networkMaintainWithBackoff(ctx, client, cp, nil)
}

// networkMaintainWithBackoff is networkMaintain with an explicit §2.2 backoff.
// The defaults (min 1s, max 60s) are right for real deployments and useless for
// a probe that has to observe several retries: the fourth would land ~15s in
// and the seventh past two minutes. A probe passing a short backoff is not
// weakening the vector — the schedule's shape is what is under test, not its
// wall-clock constants.
func networkMaintainWithBackoff(ctx context.Context, client *PeerClient, cp *networkCounterpart, backoff *types.BackoffConfigData) (types.MaintainResultData, networkOutcome) {
	req := types.MaintainRequestData{PeerID: cp.peerID, Address: cp.addr, Backoff: backoff}
	params, err := req.ToEntity()
	if err != nil {
		return types.MaintainResultData{}, netBad(FailCheck("build maintain-request: " + err.Error()))
	}
	resp, _, _, err := client.SendExecuteRaw(ctx, networkURI(client), "maintain-peer", params,
		&types.ResourceTarget{Targets: []string{"system/network"}})
	if err != nil {
		return types.MaintainResultData{}, netBad(FailCheck("maintain-peer EXECUTE: " + err.Error()))
	}
	if resp.Status == 403 {
		return types.MaintainResultData{}, netBad(SkipCheck("target refused maintain-peer with 403 — the network handler is admin-only (§3.2). Run -identity framework-admin (the same grant the liveness category uses)."))
	}
	if resp.Status != 200 {
		code, _ := decodeResultErrorCode(resp)
		return types.MaintainResultData{}, netBad(FailCheck(fmt.Sprintf("maintain-peer returned %d (code %s), want 200", resp.Status, code)))
	}
	var data types.MaintainResultData
	inner, err := decodeResultData(resp, &data)
	if err != nil {
		return types.MaintainResultData{}, netBad(FailCheck("decode maintain-peer result: " + err.Error()))
	}
	if inner.Type != types.TypeNetworkMaintainResult {
		return types.MaintainResultData{}, netBad(FailCheck(fmt.Sprintf("maintain-peer result type %q, want %s (§2.4)", inner.Type, types.TypeNetworkMaintainResult)))
	}
	return data, netOK()
}

// networkStatus EXECUTEs the status operation (nil params) and decodes §2.7.
func networkStatus(ctx context.Context, client *PeerClient) (types.NetworkStatusData, networkOutcome) {
	resp, _, _, err := client.SendExecuteRaw(ctx, networkURI(client), "status",
		mustCreateEntity("primitive/any", map[string]any{}), nil)
	if err != nil {
		return types.NetworkStatusData{}, netBad(FailCheck("status EXECUTE: " + err.Error()))
	}
	if resp.Status != 200 {
		code, _ := decodeResultErrorCode(resp)
		return types.NetworkStatusData{}, netBad(FailCheck(fmt.Sprintf("status returned %d (code %s), want 200", resp.Status, code)))
	}
	var data types.NetworkStatusData
	if _, err := decodeResultData(resp, &data); err != nil {
		return types.NetworkStatusData{}, netBad(FailCheck("decode status result: " + err.Error()))
	}
	return data, netOK()
}

// networkRelease EXECUTEs release-peer (default reason shutdown) and decodes §2.6.
func networkRelease(ctx context.Context, client *PeerClient, peerID string) (types.ReleaseResultData, networkOutcome) {
	req := types.ReleaseRequestData{PeerID: peerID}
	params, err := req.ToEntity()
	if err != nil {
		return types.ReleaseResultData{}, netBad(FailCheck("build release-request: " + err.Error()))
	}
	resp, _, _, err := client.SendExecuteRaw(ctx, networkURI(client), "release-peer", params,
		&types.ResourceTarget{Targets: []string{"system/network"}})
	if err != nil {
		return types.ReleaseResultData{}, netBad(FailCheck("release-peer EXECUTE: " + err.Error()))
	}
	if resp.Status != 200 {
		code, _ := decodeResultErrorCode(resp)
		return types.ReleaseResultData{}, netBad(FailCheck(fmt.Sprintf("release-peer returned %d (code %s), want 200", resp.Status, code)))
	}
	var data types.ReleaseResultData
	inner, err := decodeResultData(resp, &data)
	if err != nil {
		return types.ReleaseResultData{}, netBad(FailCheck("decode release-peer result: " + err.Error()))
	}
	if inner.Type != types.TypeNetworkReleaseResult {
		return types.ReleaseResultData{}, netBad(FailCheck(fmt.Sprintf("release-peer result type %q, want %s (§2.6)", inner.Type, types.TypeNetworkReleaseResult)))
	}
	return data, netOK()
}

// networkURI is the target's system/network handler address.
func networkURI(client *PeerClient) string {
	return "entity://" + string(client.RemotePeerID()) + "/system/network"
}

// networkGrantHash resolves the content hash of the target's network handler
// grant (bound at system/capability/grants/system/network) — the value every
// §4.1 continuation's dispatch_capability must equal.
func networkGrantHash(ctx context.Context, client *PeerClient) (hash.Hash, error) {
	ent, _, err := client.TreeGet(ctx, "system/capability/grants/system/network")
	if err != nil {
		return hash.Hash{}, err
	}
	if ent.ContentHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("grant entity carried no content_hash")
	}
	return ent.ContentHash, nil
}

// getContinuation fetches a system/continuation binding, trying the Base58
// peer-id path first and the hex-identity-hash path second — Go writes the
// graph under the Base58 peer id, siblings may use the hex form; the SHAPE and
// entity type are asserted, not literal peer-string equality. Returns the
// decoded data, the path that resolved, and ok.
func getContinuation(ctx context.Context, client *PeerClient, b58Path, hexPath string) (types.ContinuationData, string, bool) {
	for _, path := range []string{b58Path, hexPath} {
		ent, _, err := client.TreeGet(ctx, path)
		if err != nil || ent.Type != types.TypeContinuation {
			continue
		}
		data, derr := types.ContinuationDataFromEntity(ent)
		if derr != nil {
			continue
		}
		return data, path, true
	}
	return types.ContinuationData{}, "", false
}

// findLostMarker walks system/runtime/chain-errors/lost/ for a marker whose
// reason equals want, in a single pass.
//
// Single-pass, where this used to poll to a deadline: its caller now asserts
// ABSENCE, and polling for something that must not exist just burns the whole
// timeout on every clean run. The call site is ordered so one pass is sound —
// it looks only AFTER the outage has ended, by which point every reconnect
// attempt that could have bound a marker has already been made and observed.
func findLostMarker(ctx context.Context, client *PeerClient, want string) (types.ChainErrorLostData, string, bool) {
	var paths []string
	walkTreePaths(ctx, client, "system/runtime/chain-errors/lost/", 0, &paths)
	for _, p := range paths {
		ent, _, err := client.TreeGet(ctx, p)
		if err != nil || ent.Type != types.TypeChainErrorLost {
			continue
		}
		var d types.ChainErrorLostData
		if derr := ecf.Decode(ent.Data, &d); derr != nil {
			continue
		}
		if d.Reason == want {
			return d, p, true
		}
	}
	return types.ChainErrorLostData{}, "", false
}

// walkTreePaths collects every descendant path under prefix (which must end in
// "/") into out, bounded to a depth that accommodates every cohort marker
// layout. The nominal shape is .../lost/{chain_id}/{step_index}/{reason}/
// {marker_hash} — four levels — but {chain_id} need not be a single segment on
// every seat yet: Python (c4631c1) uses a path-shaped chain id
// ("unknown/cont-forward-system/network/peers/{peer}/on-disconnect"), putting
// its marker entity at depth 7. A cap of 6 silently truncated the walk one
// level ABOVE Python's markers, so the category reported "no marker" for
// markers that were present and conformant.
//
// The bound stays generous DELIBERATELY, and the reason has inverted. §3.11 now
// requires chain_id to be a single path segment, so the nominal four levels are
// true for Go and the cap could in principle come down — but the walk's only
// caller now asserts a NEGATIVE ("no connection_failed marker was bound"), and
// for a negative a too-shallow walk does not FAIL, it silently PASSES. It would
// conclude "no marker" by failing to look far enough, which is precisely the
// false signal that cost this cycle a bogus Python bug report. Restoring the
// tight cap is safe only once every seat emits single-segment chain ids AND
// nothing depends on the walk for an absence claim; until then, generous. The
// lost tree is small in a test run.
func walkTreePaths(ctx context.Context, client *PeerClient, prefix string, depth int, out *[]string) {
	if depth > 12 {
		return
	}
	entries, _, err := client.TreeListing(ctx, prefix)
	if err != nil {
		return
	}
	for name := range entries {
		full := prefix + name
		*out = append(*out, full)
		walkTreePaths(ctx, client, full+"/", depth+1, out)
	}
}

// anyHasSuffix reports whether any string in ss ends with suffix.
func anyHasSuffix(ss []string, suffix string) bool {
	for _, s := range ss {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// networkCounterpart is the harness's restartable killable peer: a minimal
// in-process Go peer on a FIXED 127.0.0.1 port with a stable identity, so it
// can be torn down and brought back on the SAME addr+identity — the extra
// capability the reconnect anchor needs over the liveness floor's
// single-shot livenessCounterpart. Go listeners set SO_REUSEADDR, so the port
// rebinds even while the killed connection's sockets sit in TIME_WAIT.
type networkCounterpart struct {
	kp     crypto.Keypair
	peer   *peer.Peer
	cancel context.CancelFunc
	addr   string // fixed listen addr, reused across restarts
	peerID string // Base58
	hexID  string // lowercase hex identity hash (66-char, format byte included)
	// pings counts the target's inbound §5.4 keepalive pings, fed by the
	// dispatch hook in start(). Survives restarts (the hook re-registers
	// against this same struct).
	pings pingObservation
}

func startNetworkCounterpart() (*networkCounterpart, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate counterpart keypair: %w", err)
	}
	cp := &networkCounterpart{kp: kp, addr: "127.0.0.1:0"}
	if err := cp.start(); err != nil {
		return nil, err
	}
	h, err := types.ComputePeerIdentityHashFromPeerID(cp.peer.PeerID())
	if err != nil {
		cp.kill()
		return nil, fmt.Errorf("derive counterpart identity hash: %w", err)
	}
	cp.peerID = string(cp.peer.PeerID())
	cp.hexID = types.PeerIdentityHashHex(h)
	return cp, nil
}

// start (re-)constructs and listens the counterpart. The first call binds an
// ephemeral port then pins cp.addr to it; every later call reuses that concrete
// addr so the target's cached dial address still resolves.
func (cp *networkCounterpart) start() error {
	p, err := peer.New(
		peer.WithIdentity(cp.kp),
		peer.WithListenAddr(cp.addr),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		// Count the TARGET's inbound §5.4 keepalive pings. The counterpart —
		// not the validator's client — is the peer the target MAINTAINS, so
		// this is the only place the target's real keepalive cadence is
		// observable. It is what lets the probe VERIFY -keepalive-envelope-ms
		// instead of trusting it (arch ruling 2026-07-17 §4).
		//
		// A WIRE hook, not a dispatch hook: `ping` rides the connect fast path
		// (core/protocol/execute.go's connectPath branch → dispatchToHandler),
		// which never reaches the fireDispatchHooks in handleExecute. So the
		// whole system/protocol/connect surface is invisible to dispatch hooks
		// — see the note routed with this change. The wire hook sees the frame
		// regardless of which dispatch path claims it.
		peer.WithWireHook("keepalive-precondition", func(evt peer.WireEvent) {
			if evt.Direction != peer.WireInbound || evt.RootType != types.TypeExecute {
				return
			}
			var env entity.Envelope
			if ecf.Decode(evt.FrameBytes, &env) != nil {
				return
			}
			var ed types.ExecuteData
			if ecf.Decode(env.Root.Data, &ed) != nil {
				return
			}
			if ed.Operation == "ping" {
				cp.pings.note()
			}
		}),
		// A real inbox so the target's §6.2 establish / any delivery lands 200.
		peer.WithHandler("system/inbox", inbox.NewHandler()),
	)
	if err != nil {
		return fmt.Errorf("construct counterpart peer: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go p.ListenReady(ctx, ready)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		p.Close()
		return fmt.Errorf("counterpart listener never became ready")
	}
	cp.peer = p
	cp.cancel = cancel
	cp.addr = p.Addr().String()
	return nil
}

// kill tears the counterpart down abruptly: listener and every live connection
// close. Idempotent-ish (safe to call after start replaced the peer).
func (cp *networkCounterpart) kill() {
	if cp.cancel != nil {
		cp.cancel()
	}
	if cp.peer != nil {
		cp.peer.Close()
	}
}

// Path helpers — mirror ext/network/session.go's scheme. Base58 peer-id form
// (what Go writes) plus the hex-identity form (siblings may use it).
func (cp *networkCounterpart) inboxPath(leaf string) string {
	return "system/inbox/network/" + cp.peerID + "/" + leaf
}
func (cp *networkCounterpart) inboxPathHex(leaf string) string {
	return "system/inbox/network/" + cp.hexID + "/" + leaf
}
func (cp *networkCounterpart) managedPath(leaf string) string {
	return "system/network/peers/" + cp.peerID + "/" + leaf
}
func (cp *networkCounterpart) managedPathHex(leaf string) string {
	return "system/network/peers/" + cp.hexID + "/" + leaf
}

// dialCounter takes over an address and counts inbound TCP connections,
// closing each immediately.
//
// It exists to count a target's reconnect attempts FROM OUTSIDE, without
// reading its internals or trusting what it records. Every impl's retry, by
// whatever internal mechanism, ends in a dial to this address — so accepts are
// the one signal that means the same thing on all three seats. (Counting the
// target's own chain-error markers would work today, but only for the impls
// that still bind one per retry — it measures the record, not the retry.)
//
// Accept-and-close, deliberately: the target completes a TCP connect, then its
// handshake gets EOF, so EnsureConnected fails exactly as it would against a
// dead peer. The connection refused it would otherwise get is the same failure
// one layer down — and cannot be counted.
type dialCounter struct {
	ln net.Listener
	n  atomic.Int64
}

func startDialCounter(addr string) (*dialCounter, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("take over counterpart addr %s to count reconnect dials: %w", addr, err)
	}
	d := &dialCounter{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.n.Add(1)
			c.Close()
		}
	}()
	return d, nil
}

func (d *dialCounter) count() int64 { return d.n.Load() }
func (d *dialCounter) stop()        { d.ln.Close() }
