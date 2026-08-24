package validate

import (
	"context"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/inbox"
)

const catLiveness = "liveness"

// runLiveness is the DIRECTIONAL TWO-PEER DEMOTION HARNESS — the wire-level
// probe for the Amendment 12 §A3 liveness floor (rungs 1+2, as ruled in
// ARCH-RESPONSE-NETWORK-A12-RUNG{1,2}-GO). It verifies the three
// system/peer/status transition writes AS OBSERVED IN THE TARGET'S TREE:
//
//	connected     — on §6.2 establish (rung 1)
//	suspect       — reason transport-error, at the direct-dispatch seam (§A1)
//	disconnected  — reason keepalive-miss, from the §5.4 loop (rung 2)
//
// Why an in-process counterpart: demotion is only observable by KILLING the
// peer at the other end of a live connection, and the validator cannot kill
// the target or (in -peers mode) either real peer. So the harness runs its
// own throwaway Go counterpart on an ephemeral 127.0.0.1 port (reachable
// from podman siblings — they run --network host), publishes its transport
// profile in the target's tree, and forces the target to DIAL OUT via the
// subscription-delivery path (the same DispatchLocalEnvelope route the Q5
// transport-family probe uses). Then it kills the counterpart and watches
// the target's status entity flip. Directionality: the flips under test are
// always the TARGET's writes about the counterpart (run the category against
// each impl to cover each direction); the counterpart's own responder-side
// `connected` write is additionally asserted as the reverse-direction
// establish evidence — that half is Go-reference behavior, not the target's.
//
// The §5.4 escalation probe needs the target's §2.3 keepalive envelope
// (interval_ms × max_missed + timeout_ms — impl-defined per §12.4, spec
// defaults ≈100 s). It only runs when -keepalive-envelope-ms is passed, so
// a default full-suite run never stalls for minutes: start the target with
// a short envelope (Go: entity-peer --keepalive-interval-ms/-timeout-ms/
// -max-missed) and pass the matching envelope here.
//
// Field strictness follows the rulings: STATUS values are normative (a
// transport error writes suspect, NOT disconnected — rung-1 ruling, §A1);
// `reason`/`last_error`/`last_seen` are OPTIONAL §A2/§3.13 fields, so an
// absent field WARNs (convergence signal, not a gate) while a PRESENT field
// with the wrong value FAILs.
func runLiveness(ctx context.Context, client *PeerClient, keepaliveEnvelopeMs int) []CheckResult {
	r := NewCheckRunner(catLiveness)

	r.Declare("liveness_dialback_establish", "EXTENSION-NETWORK §6.2 + §10 dial-out (harness setup; reverse-direction connected write)")
	r.Declare("liveness_connected_on_establish", "Amendment 12 §A3 rung 1 / ENTITY-CORE-PROTOCOL §3.13")
	r.Declare("liveness_suspect_on_transport_error", "Amendment 12 §A1 — direct-dispatch demotion seam")
	r.Declare("liveness_disconnected_on_keepalive_miss", "EXTENSION-NETWORK §5.4 / Amendment 12 rung 2 + §A4 last_seen snapshot")

	if client.Profile() == ProfileCore {
		for _, name := range []string{
			"liveness_dialback_establish",
			"liveness_connected_on_establish",
			"liveness_suspect_on_transport_error",
			"liveness_disconnected_on_keepalive_miss",
		} {
			r.Run(name, func() CheckOutcome {
				return SkipCheck("outside --profile core (NETWORK-extension liveness, V7 §9.0)")
			})
		}
		return r.Results()
	}

	targetHash := client.RemotePeerIdentityHash()
	var counterpart *livenessCounterpart
	var trigger func(label string) error
	defer func() {
		if counterpart != nil {
			counterpart.kill()
		}
	}()

	r.Run("liveness_dialback_establish", func() CheckOutcome {
		if !client.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}
		if targetHash.IsZero() {
			return FailCheck("no remote identity hash from handshake — cannot derive status/transport paths")
		}
		lc, err := startLivenessCounterpart()
		if err != nil {
			return FailCheck("start in-process counterpart peer: " + err.Error())
		}
		counterpart = lc

		tag := fmt.Sprintf("liveness-%d", time.Now().UnixNano())
		trig, err := armDialback(ctx, client, lc, tag)
		if err != nil {
			return FailCheck(err.Error())
		}
		trigger = trig
		if err := trigger("establish"); err != nil {
			return FailCheck("trigger put (establish): " + err.Error())
		}

		// The counterpart observes the target's inbound §6.2 handshake and
		// (being a Go reference peer) writes its responder-side `connected`
		// about the target — the reverse-direction half of the establish
		// vector, read straight from the counterpart's store.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if d, ok := lc.statusFor(targetHash); ok && d.Status == types.PeerStatusConnected {
				return PassCheck(fmt.Sprintf("target dialed the counterpart and completed §6.2 establish (counterpart responder-side status for target: connected; counterpart %s at %s)", lc.peerID[:8], lc.addr))
			}
			time.Sleep(100 * time.Millisecond)
		}
		return FailCheck("target never dialed the counterpart (no inbound establish observed within 15s) — subscription-delivery dial-out did not happen; check the target's outbound TCP dispatch")
	})

	r.Run("liveness_connected_on_establish", func() CheckOutcome {
		if out, ok := r.Require("liveness_dialback_establish"); !ok {
			return out
		}
		d, lastState, found := pollPeerStatus(ctx, client, counterpart.hexID, 10*time.Second, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		})
		if !found {
			return FailCheck(fmt.Sprintf("target's system/peer/status/%s never showed connected after establish (%s) — the rung-1 §A3 establish write is missing on the dialer side", counterpart.hexID, lastState))
		}
		if d.PeerID != counterpart.peerID {
			return FailCheck(fmt.Sprintf("connected status peer_id = %q, want the counterpart's Base58 peer-id %q (§3.13 data-field identity)", d.PeerID, counterpart.peerID))
		}
		if d.Reason != "" {
			return FailCheck(fmt.Sprintf("connected establish write carries reason %q — reasons belong to demotion transitions (§A2)", d.Reason))
		}
		return PassCheck("target wrote connected at system/peer/status/{counterpart} on establish (peer_id correct, no demotion reason)")
	})

	r.Run("liveness_suspect_on_transport_error", func() CheckOutcome {
		if out, ok := r.Require("liveness_connected_on_establish"); !ok {
			return out
		}
		// Kill the counterpart: the target's pooled connection is now dead,
		// but only a dispatch can observe that (§A1 is reactive, not
		// polled). The next trigger rides the dead conn and MUST demote.
		counterpart.kill()
		if err := trigger("transport-error"); err != nil {
			return FailCheck("trigger put (transport-error): " + err.Error())
		}
		d, lastState, found := pollPeerStatus(ctx, client, counterpart.hexID, 20*time.Second, func(d types.PeerStatusData) bool {
			return d.Status != types.PeerStatusConnected
		})
		if !found {
			return FailCheck(fmt.Sprintf("target's status for the dead counterpart never left connected after a failed dispatch (%s) — the §A1 transport-error demotion is missing", lastState))
		}
		if d.Status != types.PeerStatusSuspect {
			return FailCheck(fmt.Sprintf("status flipped to %q (reason %q) — a single transport error writes suspect, NOT %q (rung-1 ruling: one failure is not proof of a dead peer; §5.4 escalates)", d.Status, d.Reason, d.Status))
		}
		if d.Reason != "" && d.Reason != types.PeerStatusReasonTransportError {
			return FailCheck(fmt.Sprintf("suspect write carries reason %q, want %q (§A2 enum)", d.Reason, types.PeerStatusReasonTransportError))
		}
		if d.Reason == "" {
			return WarnCheck("suspect write landed but carries no reason — §A2 reason is OPTIONAL so this passes, flagged as a convergence divergence (Go writes transport-error)")
		}
		if d.LastError == "" {
			return WarnCheck("suspect/transport-error landed; last_error absent (OPTIONAL §A2 field — flagged, not gated)")
		}
		return PassCheck(fmt.Sprintf("target demoted connected → suspect (reason transport-error) on the failed dispatch; last_error=%q", d.LastError))
	})

	r.Run("liveness_disconnected_on_keepalive_miss", func() CheckOutcome {
		if out, ok := r.Require("liveness_dialback_establish"); !ok {
			return out
		}
		if keepaliveEnvelopeMs <= 0 {
			return SkipCheck("pass -keepalive-envelope-ms matching the target's §2.3 envelope (interval_ms × max_missed + timeout_ms; spec defaults ≈100000) — the §5.4 escalation probe is opt-in so default runs don't stall for minutes. Go targets: start entity-peer with --keepalive-interval-ms/--keepalive-timeout-ms/--keepalive-max-missed for a short envelope.")
		}

		// Fresh counterpart: the suspect probe's eviction already tore down
		// the first one's binding. This one establishes, then goes silent —
		// no dispatch ever touches the dead conn, so only the target's §5.4
		// keepalive loop can notice (that is what distinguishes this write
		// from the §A1 path).
		lc2, err := startLivenessCounterpart()
		if err != nil {
			return FailCheck("start second counterpart peer: " + err.Error())
		}
		defer lc2.kill()
		tag := fmt.Sprintf("liveness-ka-%d", time.Now().UnixNano())
		trig2, err := armDialback(ctx, client, lc2, tag)
		if err != nil {
			return FailCheck(err.Error())
		}
		if err := trig2("ka-establish"); err != nil {
			return FailCheck("trigger put (ka-establish): " + err.Error())
		}
		if _, lastState, found := pollPeerStatus(ctx, client, lc2.hexID, 15*time.Second, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusConnected
		}); !found {
			return FailCheck(fmt.Sprintf("second counterpart never reached connected in the target's tree (%s) — cannot arm the keepalive-miss vector", lastState))
		}

		lc2.kill()

		// Idle-dead from here: poll for the §5.4 escalation within the
		// declared envelope (+50%+10s margin for loop phase + write lag).
		// An intermediate suspect is fine; disconnected/keepalive-miss is
		// the vector's terminal state.
		deadline := time.Duration(keepaliveEnvelopeMs)*time.Millisecond*3/2 + 10*time.Second
		d, lastState, found := pollPeerStatus(ctx, client, lc2.hexID, deadline, func(d types.PeerStatusData) bool {
			return d.Status == types.PeerStatusDisconnected
		})
		if !found {
			return FailCheck(fmt.Sprintf("target's status for the idle-dead counterpart never escalated to disconnected within %v (%s) — the §5.4 keepalive-miss demotion (rung 2, the floor's third write) is missing", deadline, lastState))
		}
		if d.Reason != "" && d.Reason != types.PeerStatusReasonKeepaliveMiss {
			return FailCheck(fmt.Sprintf("disconnected write carries reason %q, want %q (§A2 enum)", d.Reason, types.PeerStatusReasonKeepaliveMiss))
		}
		if d.Reason == "" {
			return WarnCheck("disconnected landed but carries no reason — §A2 reason is OPTIONAL so this passes, flagged as a convergence divergence (Go writes keepalive-miss)")
		}
		if d.LastSeen == 0 {
			return WarnCheck("disconnected/keepalive-miss landed; last_seen snapshot absent — §A4 makes it the demotion's evidence when an exchange was recorded (one was: the establish dispatch). OPTIONAL §3.13 field, so flagged, not gated")
		}
		return PassCheck(fmt.Sprintf("target escalated to disconnected (reason keepalive-miss) with no dispatch traffic, within the declared envelope; last_seen snapshot %d", d.LastSeen))
	})

	return r.Results()
}

// livenessCounterpart is the harness's killable peer: a minimal in-process
// Go peer on an ephemeral 127.0.0.1 port. It exists to be dialed by the
// target and then abruptly closed — listener and all accepted connections —
// so the target's pooled outbound connection to it dies.
type livenessCounterpart struct {
	peer   *peer.Peer
	cancel context.CancelFunc
	addr   string
	peerID string // Base58
	hexID  string // lowercase hex identity hash (66-char, format byte included)
}

func startLivenessCounterpart() (*livenessCounterpart, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate counterpart keypair: %w", err)
	}
	p, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		// A real inbox so the target's subscription deliveries land 200 —
		// the establish/dispatch path stays indistinguishable from a
		// production peer's.
		peer.WithHandler("system/inbox", inbox.NewHandler()),
	)
	if err != nil {
		return nil, fmt.Errorf("construct counterpart peer: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go p.ListenReady(ctx, ready)
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		p.Close()
		return nil, fmt.Errorf("counterpart listener never became ready")
	}
	h, err := types.ComputePeerIdentityHashFromPeerID(p.PeerID())
	if err != nil {
		cancel()
		p.Close()
		return nil, fmt.Errorf("derive counterpart identity hash: %w", err)
	}
	return &livenessCounterpart{
		peer:   p,
		cancel: cancel,
		addr:   p.Addr().String(),
		peerID: string(p.PeerID()),
		hexID:  types.PeerIdentityHashHex(h),
	}, nil
}

// kill tears the counterpart down abruptly: listener and every live
// connection close. Idempotent.
func (lc *livenessCounterpart) kill() {
	lc.cancel()
	lc.peer.Close()
}

// statusFor reads the counterpart's OWN system/peer/status entity for the
// given remote identity hash (in-process store read — the counterpart is
// harness-owned, not probed over the wire).
func (lc *livenessCounterpart) statusFor(remote hash.Hash) (types.PeerStatusData, bool) {
	h, ok := lc.peer.LocationIndex().Get(types.PeerStatusPath(lc.peerID, remote))
	if !ok {
		return types.PeerStatusData{}, false
	}
	ent, ok := lc.peer.Store().Get(h)
	if !ok {
		return types.PeerStatusData{}, false
	}
	d, err := types.PeerStatusDataFromEntity(ent)
	if err != nil {
		return types.PeerStatusData{}, false
	}
	return d, true
}

// armDialback makes the target able and motivated to dial the counterpart:
// publishes the counterpart's TCP transport profile in the target's tree and
// installs a subscription whose deliveries route to the counterpart's inbox.
// The returned trigger fires one delivery (a put under the subscription
// pattern) — the only wire-accessible mechanism that drives the target's
// cross-peer dispatcher (see the Q5 probe in transport_family.go).
func armDialback(ctx context.Context, client *PeerClient, lc *livenessCounterpart, tag string) (func(label string) error, error) {
	if _, err := client.TreePut(ctx, transportProfilePath(lc.hexID), tcpProfileEntityFor(lc.peerID, lc.addr)); err != nil {
		return nil, fmt.Errorf("publish counterpart transport profile: %w", err)
	}
	deliverURI := "entity://" + lc.peerID + "/system/inbox/" + tag
	token, tokenSig, err := client.CreateDeliveryToken(deliverURI, "receive")
	if err != nil {
		return nil, fmt.Errorf("create delivery token: %w", err)
	}
	pattern := "system/validate/" + tag + "/*"
	if _, _, _, err := client.Subscribe(ctx, pattern, deliverURI, "receive",
		token, tokenSig, []string{"created"}, nil); err != nil {
		return nil, fmt.Errorf("subscribe (deliver=%s): %w", deliverURI, err)
	}
	return func(label string) error {
		ent := mustCreateEntity("test/liveness-probe", map[string]string{"phase": label})
		_, err := client.TreePut(ctx, "system/validate/"+tag+"/"+label, ent)
		return err
	}, nil
}

// pollPeerStatus polls the TARGET's system/peer/status/{remoteHex} over the
// wire until accept() returns true or the deadline lapses. Returns the
// accepted data, a description of the last observed state (for failure
// messages), and whether accept was satisfied. An unbound path ("tree get
// status 404") counts as "no status entity yet", not an error — rung-1
// establishes it.
func pollPeerStatus(ctx context.Context, client *PeerClient, remoteHex string, within time.Duration, accept func(types.PeerStatusData) bool) (types.PeerStatusData, string, bool) {
	path := types.TypePeerStatus + "/" + remoteHex
	lastState := "no status entity ever appeared"
	deadline := time.Now().Add(within)
	for {
		ent, _, err := client.TreeGet(ctx, path)
		if err == nil {
			d, derr := types.PeerStatusDataFromEntity(ent)
			if derr != nil {
				lastState = "status entity present but undecodable: " + derr.Error()
			} else {
				if accept(d) {
					return d, "", true
				}
				lastState = fmt.Sprintf("last observed status=%q reason=%q", d.Status, d.Reason)
			}
		} else {
			lastState = "last read: " + err.Error()
		}
		if time.Now().After(deadline) {
			return types.PeerStatusData{}, lastState, false
		}
		select {
		case <-ctx.Done():
			return types.PeerStatusData{}, lastState + " (context canceled)", false
		case <-time.After(250 * time.Millisecond):
		}
	}
}
