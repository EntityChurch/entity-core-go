package validate

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// (advertised_at population: see tcpProfileEntityFor comment in
// convergence.go for the cross-impl rationale; xsubHTTPProfileEntity
// applies the same fix to the HTTP path.)

// runCrossPeerHTTPSubscription executes PROPOSAL-TRANSPORT-FAMILY-
// LIVE-REACHABILITY §7.3 R1 — the cross-peer-subscription-over-HTTP
// gate. Mirrors the existing TCP-based xsub_* checks in convergence.go
// but publishes ONLY an HTTP profile in B's view of A, so the
// notification dispatch from B→A must traverse the HTTP path (pre-R1
// dispatcher walked only TCP profiles and would fail here).
//
// Requires:
//   - At least two TCP-connected clients (the convergence harness).
//   - httpURLs[i] paired by index with clients[i]; each URL is a fully-
//     qualified HTTP-live POST target (e.g. http://host:port/entity).
//
// When httpURLs is empty (no -http-peers flag), the category SKIPs
// with a clear hint — the single-peer-local 34/34 subscription pass
// does NOT pin R1; this gate is the test that does.
func runCrossPeerHTTPSubscription(ctx context.Context, clients []*PeerClient, httpURLs []string) []CheckResult {
	r := NewCheckRunner(catCrossPeerHTTPSub)

	r.Declare("xsubhttp_setup_http_only_transport", "EXTENSION-NETWORK §6.5 (Amendment 8)")
	r.Declare("xsubhttp_subscribe", "SUBSCRIPTION §3 (over HTTP-only transport)")
	r.Declare("xsubhttp_trigger_put", "SUBSCRIPTION §5")
	r.Declare("xsubhttp_notification_delivered", "EXTENSION-NETWORK §6.5 / EXTENSION-SUBSCRIPTION §5")
	r.Declare("xsubhttp_unsubscribe", "SUBSCRIPTION §3")

	if len(httpURLs) == 0 {
		skip := SkipCheck("no -http-peers provided — start peers with --http-addr and pass URLs: -http-peers http://h1:p/entity,http://h2:p/entity")
		for _, name := range []string{
			"xsubhttp_setup_http_only_transport",
			"xsubhttp_subscribe",
			"xsubhttp_trigger_put",
			"xsubhttp_notification_delivered",
			"xsubhttp_unsubscribe",
		} {
			r.Run(name, func() CheckOutcome { return skip })
		}
		return r.Results()
	}

	if len(clients) < 2 || len(httpURLs) < 2 {
		fail := FailCheck(fmt.Sprintf("R1 gate requires at least 2 peers + 2 HTTP URLs (got %d peers, %d URLs)", len(clients), len(httpURLs)))
		for _, name := range []string{
			"xsubhttp_setup_http_only_transport",
			"xsubhttp_subscribe",
			"xsubhttp_trigger_put",
			"xsubhttp_notification_delivered",
			"xsubhttp_unsubscribe",
		} {
			r.Run(name, func() CheckOutcome { return fail })
		}
		return r.Results()
	}

	a, b := clients[0], clients[1]
	aHTTP := httpURLs[0]
	suffix := fmt.Sprintf("%d", rand.Intn(100000))
	prefix := "system/validate/xsubhttp-" + suffix + "/"

	// Step 1: Make HTTP the ONLY transport for A in B's view. We
	// overwrite the `primary` slot with A's HTTP profile — this slot
	// is the one the convergence flow's xsub_setup_transport just
	// wrote a TCP profile to, so this overwrite ensures the dispatcher
	// has no TCP path to fall back to. We also write the HTTP profile
	// at the conventional `primary-http` slot (G1 coexist convention)
	// so the published-view matches what an operator using
	// RegisterRemoteHTTP would produce. Either entry is sufficient for
	// the R1 dispatch test; both being present matches real-world G1
	// usage.
	//
	// "HTTP-only" is critical for R1 specifically because pre-R1 the
	// dispatcher only walked TCP profiles; testing R1 with a TCP slot
	// also present lets the dispatcher silently regress to TCP and
	// still pass. Hence: kill the TCP slot.
	r.Run("xsubhttp_setup_http_only_transport", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/transport/* — run with -identity framework-admin")
		}
		peerAID := string(a.RemotePeerID())
		ent := xsubHTTPProfileEntity(peerAID, aHTTP)
		// V7.64: path segment is hex of A's identity hash, not Base58 PeerID.
		aHash, hashErr := types.ComputePeerIdentityHashFromPeerID(a.RemotePeerID())
		if hashErr != nil {
			return SkipCheck("A's identity hash undericable (SHA-256-form peer; v7.64 requires public_key): " + hashErr.Error())
		}
		prefix := "system/peer/transport/" + types.PeerIdentityHashHex(aHash) + "/"
		primaryPath := prefix + "primary"
		if _, err := b.TreePut(ctx, primaryPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("overwrite primary slot with HTTP profile at %s: %v", primaryPath, err))
		}
		httpPath := prefix + "primary-http"
		if _, err := b.TreePut(ctx, httpPath, ent); err != nil {
			return FailCheck(fmt.Sprintf("publish A's HTTP profile in B at %s: %v", httpPath, err))
		}
		return PassCheck(fmt.Sprintf("HTTP-only transport for A on B (url=%s): wrote primary + primary-http both = HTTP", aHTTP))
	})

	// Step 2: B subscribes to its own tree under our test prefix, with
	// deliver target = A's inbox. When B's tree changes under the
	// pattern, B dispatches the notification to A's inbox; since A's
	// only transport in B's tree is HTTP (or HTTP is selected), the
	// dispatch must traverse HTTP.
	r.Run("xsubhttp_subscribe", func() CheckOutcome {
		if out, ok := r.Require("xsubhttp_setup_http_only_transport"); !ok {
			return out
		}
		peerAID := string(a.RemotePeerID())
		inboxPath := "system/inbox/validate-xsubhttp-" + suffix
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

	// Step 3: trigger a write on B under the subscription pattern.
	r.Run("xsubhttp_trigger_put", func() CheckOutcome {
		if out, ok := r.Require("xsubhttp_subscribe"); !ok {
			return out
		}
		ent := mustCreateEntity("test/cross-peer-http-notification", map[string]string{
			"content": "xsubhttp-test-" + suffix,
		})
		testPath := prefix + "item-1"
		h, err := b.TreePut(ctx, testPath, ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("put on B failed: %v", err))
		}
		return PassCheck(fmt.Sprintf("put %s on B (hash=%s)", testPath, h))
	})

	// Step 4: poll A's inbox; the notification must arrive (over HTTP).
	r.Run("xsubhttp_notification_delivered", func() CheckOutcome {
		if out, ok := r.Require("xsubhttp_trigger_put"); !ok {
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
			return PassCheck(fmt.Sprintf("notification delivered to A's inbox over HTTP in %dms (%d entries at %s)",
				time.Since(start).Milliseconds(), len(entries), notifPrefix))
		}

		// Did it land on B's local inbox instead?
		localEntries, _, _ := b.TreeListing(ctx, notifPrefix)
		if len(localEntries) > 0 {
			return FailCheck("notification delivered to B's LOCAL inbox instead of A — cross-peer dispatch not firing (HTTP profile published, but dispatcher did not route)")
		}
		return FailCheck(fmt.Sprintf("no notification at A's inbox after 5s (path: %s) — HTTP profile published but dispatch did not deliver", notifPrefix))
	})

	r.Run("xsubhttp_unsubscribe", func() CheckOutcome {
		if out, ok := r.Require("xsubhttp_subscribe"); !ok {
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

const catCrossPeerHTTPSub = "cross_peer_http_subscription"

// xsubHTTPProfileEntity builds an HTTPProfileData entity for the §6.5
// wire shape — a sibling of tcpProfileEntityFor in convergence.go.
// Kept here so cross_peer_http.go stays self-contained.
func xsubHTTPProfileEntity(peerID, url string) entity.Entity {
	data := types.HTTPProfileData{
		PeerID:        peerID,
		TransportType: "http",
		Endpoint:      types.TransportEndpointURL{URL: url},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportHTTP, cbor.RawMessage(raw))
	return ent
}
