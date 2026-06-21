package validate

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.entitychurch.org/entity-core-go/core/types"
)

// runCrossPeerTCPSubscription is the TCP-only sibling of
// runCrossPeerHTTPSubscription. Both peers reachable over TCP, peer B
// subscribes to events on B, deliverURI = entity://A/system/inbox/...,
// a write on B fires the subscription, B dispatches the notification
// to A's inbox over TCP.
//
// Why we have this in addition to convergence.go's xsub_* checks:
// xsub_* is one of many tests in the convergence flow. When B's TCP
// dispatcher is broken (e.g. Rust — TCP dialer didn't strip
// the tcp:// URL scheme), xsub_notification_delivered fails but it
// looks like one of 30+ cascading convergence failures rather than a
// focused dialer bug. This category is one focused check that fails
// CLEAN when a peer's outbound TCP dispatch is broken, so the cohort
// triage doesn't have to dig.
//
// The R1 motivation for this gate is the SAME shape as R1 for HTTP:
// we want a small, dedicated, named gate per transport that proves
// the end-to-end dispatch path. R1's gate proved HTTP works; this
// gate proves TCP works for the same flow.
func runCrossPeerTCPSubscription(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catCrossPeerTCPSub)

	r.Declare("xsubtcp_setup_tcp_only_transport", "EXTENSION-NETWORK §6.5 / SUBSCRIPTION §5 over TCP")
	r.Declare("xsubtcp_subscribe", "SUBSCRIPTION §3 (over TCP-only transport)")
	r.Declare("xsubtcp_trigger_put", "SUBSCRIPTION §5")
	r.Declare("xsubtcp_notification_delivered", "EXTENSION-NETWORK §6.5 / SUBSCRIPTION §5 — outbound TCP dispatch from peer B")
	r.Declare("xsubtcp_unsubscribe", "SUBSCRIPTION §3")

	if len(clients) < 2 {
		fail := FailCheck(fmt.Sprintf("TCP gate requires at least 2 peers (got %d)", len(clients)))
		for _, name := range []string{
			"xsubtcp_setup_tcp_only_transport",
			"xsubtcp_subscribe",
			"xsubtcp_trigger_put",
			"xsubtcp_notification_delivered",
			"xsubtcp_unsubscribe",
		} {
			r.Run(name, func() CheckOutcome { return fail })
		}
		return r.Results()
	}

	a, b := clients[0], clients[1]
	suffix := fmt.Sprintf("%d", rand.Intn(100000))
	prefix := "system/validate/xsubtcp-" + suffix + "/"

	// Step 1: Make TCP the ONLY transport for A in B's view. Overwrite
	// the "primary" slot AND the "primary-http" slot (if it exists) with
	// A's TCP profile so the dispatcher has no HTTP path to fall back
	// to. The address comes from a.addr — the validator's existing TCP
	// connection target.
	r.Run("xsubtcp_setup_tcp_only_transport", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}
		peerAID := string(a.RemotePeerID())
		ent := tcpProfileEntityFor(peerAID, a.addr)
		// V7.64: path segment is hex of A's identity hash, not Base58 PeerID.
		aHash, hashErr := types.ComputePeerIdentityHashFromPeerID(a.RemotePeerID())
		if hashErr != nil {
			return SkipCheck("A's identity hash undericable (SHA-256-form peer; v7.64 requires public_key): " + hashErr.Error())
		}
		prefix := "system/peer/transport/" + types.PeerIdentityHashHex(aHash) + "/"
		primaryPath := prefix + "primary"
		if _, err := b.TreePut(ctx, primaryPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("overwrite primary slot with TCP profile at %s: %v", primaryPath, err))
		}
		// Also overwrite primary-http to kill any prior HTTP profile —
		// we want TCP to be the ONLY usable transport for the dispatch.
		httpPath := prefix + "primary-http"
		if _, err := b.TreePut(ctx, httpPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("overwrite primary-http slot with TCP profile at %s: %v", httpPath, err))
		}
		return PassCheck(fmt.Sprintf("TCP-only transport for A on B (addr=%s): wrote primary + primary-http both = TCP", a.addr))
	})

	r.Run("xsubtcp_subscribe", func() CheckOutcome {
		if out, ok := r.Require("xsubtcp_setup_tcp_only_transport"); !ok {
			return out
		}
		peerAID := string(a.RemotePeerID())
		inboxPath := "system/inbox/validate-xsubtcp-" + suffix
		deliverURI := "entity://" + peerAID + "/" + inboxPath
		pattern := prefix + "*"
		events := []string{"created", "updated", "deleted"}

		tokenEntity, tokenSigEntity, err := b.CreateDeliveryToken(deliverURI, "receive")
		if err != nil {
			return FailCheck(fmt.Sprintf("create delivery token: %v", err))
		}

		subID, _, _, err := b.Subscribe(ctx, pattern, deliverURI, "receive",
			tokenEntity, tokenSigEntity, events, nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("subscribe failed: %v", err))
		}
		if subID == "" {
			return FailCheck("subscribe returned empty subscription_id")
		}

		r.Store("subID", subID)
		r.Store("inboxPath", inboxPath)
		return PassCheck(fmt.Sprintf("subscribed on B: id=%s pattern=%s deliver=%s", subID, pattern, deliverURI))
	})

	r.Run("xsubtcp_trigger_put", func() CheckOutcome {
		if out, ok := r.Require("xsubtcp_subscribe"); !ok {
			return out
		}
		ent := mustCreateEntity("test/cross-peer-tcp-notification", map[string]string{
			"content": "xsubtcp-test-" + suffix,
		})
		testPath := prefix + "item-1"
		h, err := b.TreePut(ctx, testPath, ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B failed: %v", err))
		}
		return PassCheck(fmt.Sprintf("put %s on B (hash=%s)", testPath, h))
	})

	// This is the diagnostic check. When a peer's outbound TCP dialer
	// is broken (e.g. doesn't strip "tcp://" scheme — see
	// RUST-TCP-URL-DIALER-BUG), the notification never
	// arrives at A's inbox and this fails with a focused message.
	r.Run("xsubtcp_notification_delivered", func() CheckOutcome {
		if out, ok := r.Require("xsubtcp_trigger_put"); !ok {
			return out
		}
		inboxPath := r.Load("inboxPath").(string)
		notifPrefix := inboxPath + "/"
		start := time.Now()

		var entries map[string]interface{}
		for attempt := 0; attempt < 25; attempt++ {
			time.Sleep(200 * time.Millisecond)
			es, _, err := a.TreeListing(ctx, notifPrefix)
			if err == nil && len(es) > 0 {
				entries = es
				break
			}
		}

		if len(entries) > 0 {
			return PassCheck(fmt.Sprintf("notification delivered to A's inbox over TCP in %dms (%d entries at %s)",
				time.Since(start).Milliseconds(), len(entries), notifPrefix))
		}

		localEntries, _, _ := b.TreeListing(ctx, notifPrefix)
		if len(localEntries) > 0 {
			return FailCheck("notification delivered to B's LOCAL inbox instead of A — outbound dispatch not routing")
		}
		return FailCheck(fmt.Sprintf("no notification at A's inbox after 5s (path: %s) — TCP profile published but dispatch did not deliver. Check peer B's outbound TCP dialer (does it strip scheme? does it bind to the resolved profile URL?)", notifPrefix))
	})

	r.Run("xsubtcp_unsubscribe", func() CheckOutcome {
		if out, ok := r.Require("xsubtcp_subscribe"); !ok {
			return out
		}
		subID := r.Load("subID").(string)
		if _, _, err := b.Unsubscribe(ctx, subID); err != nil {
			return WarnCheck(fmt.Sprintf("unsubscribe failed: %v", err))
		}
		return PassCheck("unsubscribed successfully")
	})

	return r.Results()
}

const catCrossPeerTCPSub = "cross_peer_tcp_subscription"
