package validate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/inbox"
)

const catNetwork = "network"

// runNetwork drives the rung-3 system/network handler (EXTENSION-NETWORK §4,
// Amendment 12) against a LIVE target, reconciling the maintain-peer reconnect
// lifecycle cross-peer instead of by build-shape comparison. Four probes,
// in dependency order:
//
//	network_maintain_installs_graph — maintain-peer → §2.4 result + the three
//	    §4.1 lifecycle continuations resident in the target's tree, each riding
//	    the handler grant.
//	network_status_reports_peer     — status → the peer present + connected,
//	    pending_count bare zero (no §8 outbox, Amendment 11).
//	network_release_tears_down      — release-peer → §2.6 result lists the
//	    continuation paths, they are gone, terminal disconnected write lands.
//	network_reconnect_anchor        — the marker-proposal §4 vector, LIVE:
//	    maintain → kill → target flips off connected + a lost marker
//	    (reason connection_failed) lands → restart → status returns connected.
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
	r.Declare("network_reconnect_anchor", "EXTENSION-NETWORK §4.1 reconnect + PROPOSAL-CONTINUATION-LOST-ERROR-MARKER §4 (reason connection_failed)")

	if client.Profile() == ProfileCore {
		for _, name := range []string{
			"network_maintain_installs_graph",
			"network_status_reports_peer",
			"network_release_tears_down",
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
		if !strings.HasPrefix(result.ChainID, "network/maintain/") {
			return FailCheck(fmt.Sprintf("maintain-result chain_id %q lacks the network/maintain/ prefix (§4.1 graph chain)", result.ChainID))
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

	r.Run("network_reconnect_anchor", func() CheckOutcome {
		if out, ok := r.Require("network_maintain_installs_graph"); !ok {
			return out
		}
		if keepaliveEnvelopeMs <= 0 {
			return SkipCheck("pass -keepalive-envelope-ms matching the target's §2.3 envelope (interval_ms × max_missed + timeout_ms) so the disconnect is observable in seconds — the reconnect anchor is opt-in like the §5.4 floor probe. Go target: start entity-peer with a short --keepalive (peer-manager --keepalive 2000,1000,2). Siblings need the keepalive-CLI cohort item before this runs fast against them.")
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

		// The lost marker: reason connection_failed. Assert reason + coordinate
		// STRUCTURE, NOT the literal chain_id/step_index — that is the §4
		// convergence finding (Go/Rust key on delivery request ids, Python on
		// the F1 fallback; the literal key is implementation-defined).
		marker, mpath, mok := pollLostMarker(ctx, client, "connection_failed", demoteDeadline)
		if !mok {
			return FailCheck(fmt.Sprintf("no lost-error marker with reason connection_failed appeared under system/runtime/chain-errors/lost/ within %v — the §3.10 no-on_error observability record for the failed reconnect is missing (PROPOSAL-CONTINUATION-LOST-ERROR-MARKER §4)", demoteDeadline))
		}
		if marker.ChainID == "" || marker.StepIndex == "" {
			return FailCheck(fmt.Sprintf("lost marker at %s carries reason connection_failed but an empty coordinate (chain_id=%q step_index=%q) — the §3.10.6 denormalized coordinate fields are required", mpath, marker.ChainID, marker.StepIndex))
		}

		// 3. Restart the counterpart on the same addr+identity; the paced
		// backoff retry's EnsureConnected now succeeds — status returns to
		// connected with no further operator action.
		if err := cp.start(); err != nil {
			return FailCheck("restart counterpart on same addr: " + err.Error())
		}
		reconnectDeadline := time.Duration(keepaliveEnvelopeMs)*time.Millisecond + 60*time.Second
		if _, lastState, found := pollPeerStatus(ctx, client, cp.hexID, reconnectDeadline, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("target never re-established connected after the counterpart restarted on %s within %v (%s) — the §4.1 backoff reconnect did not recover the relationship autonomously", cp.addr, reconnectDeadline, lastState))
		}
		return PassCheck(fmt.Sprintf("reconnect anchor: kill → demoted off connected + lost marker (reason connection_failed, coordinate %s/%s) → restart → autonomous re-establish to connected", marker.ChainID, marker.StepIndex))
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

func netOK() networkOutcome              { return networkOutcome{pass: true} }
func netBad(o CheckOutcome) networkOutcome { return networkOutcome{outcome: o} }

// networkMaintain EXECUTEs maintain-peer toward the counterpart and decodes the
// §2.4 result. A 403 is the §3.2 admin-only contract → SkipCheck.
func networkMaintain(ctx context.Context, client *PeerClient, cp *networkCounterpart) (types.MaintainResultData, networkOutcome) {
	req := types.MaintainRequestData{PeerID: cp.peerID, Address: cp.addr}
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

// pollLostMarker walks system/runtime/chain-errors/lost/ for a marker whose
// reason equals want, retrying until the deadline (the marker lands only after
// the reconnect dispatch fails, which trails the status demotion).
func pollLostMarker(ctx context.Context, client *PeerClient, want string, within time.Duration) (types.ChainErrorLostData, string, bool) {
	deadline := time.Now().Add(within)
	for {
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
		if time.Now().After(deadline) {
			return types.ChainErrorLostData{}, "", false
		}
		select {
		case <-ctx.Done():
			return types.ChainErrorLostData{}, "", false
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// walkTreePaths collects every descendant path under prefix (which must end in
// "/") into out, bounded to a shallow depth — the lost-marker tree
// (.../lost/{chain_id}/{step_index}/{reason}/{marker_hash}) is four levels
// deep and small in a test run.
func walkTreePaths(ctx context.Context, client *PeerClient, prefix string, depth int, out *[]string) {
	if depth > 6 {
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
