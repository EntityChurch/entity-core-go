package validate

import "go.entitychurch.org/entity-core-go/core/entity"

// Thread H — HTTP transport for the relay-categories cohort gate.
//
// Background: `relay_multi_peer`, `relay_offline_delivery`, and
// `relay_offline_delivery_registry` historically ran TCP-only — every
// transport profile they published in B↔C↔registry was a TCP profile.
// Go's `Peer.SendRawFrameTo` type-switches TCP / HTTPConnection
// (unit-proven at `core/peer/http_raw_frame_test.go`), so the relay
// path can ride HTTP just as well as TCP. The Thread H gate proves
// that end-to-end across the cohort.
//
// Activation: validate-peer accepts `-http-peers urlA,urlB,urlC`
// already (added for the cross-peer HTTP subscription gate). When that
// flag is present, the suite passes the URLs through to these three
// relay categories, and the profile-publish sites pick HTTP over TCP
// per peer-index. Cohort-readiness pre-check:
// Rust READY (HttpConnection::dispatch_raw); Python MISSING (HTTP raw-frame
// gap). Go self-PASS validates the harness independently of cohort.

// transportProfileForPeer returns a transport-profile entity for the
// peer at clients[i]. Selection precedence (Thread F + Thread H):
//
//  1. wsURLs[i] non-empty  → WebSocketProfileData (§6.5.2b)
//  2. httpURLs[i] non-empty → HTTPProfileData (§5)
//  3. fallback              → TCPProfileData (§4.1)
//
// Lex-sort under §6.5 D-1 lands "primary" (TCP) before "primary-http"
// before "primary-ws"; for the per-relay-test profile we publish at
// the chosen substrate, so when the test installs a WS profile the
// relay path resolves WS first. This is the single seam Thread F
// added to Thread H — the three callers below pass the (httpURLs,
// wsURLs) pair straight through.
func transportProfileForPeer(clients []*PeerClient, i int, httpURLs, wsURLs []string) entity.Entity {
	peerID := string(clients[i].RemotePeerID())
	if i < len(wsURLs) && wsURLs[i] != "" {
		return wsProfileEntityFor(peerID, wsURLs[i])
	}
	if i < len(httpURLs) && httpURLs[i] != "" {
		return httpProfileEntityFor(peerID, httpURLs[i])
	}
	return tcpProfileEntityFor(peerID, clients[i].addr)
}

// httpURLForPeer returns the HTTP-live URL for clients[i] when set, "" otherwise.
// Used by call sites that need to log or check the active transport URL.
func httpURLForPeer(i int, httpURLs []string) string {
	if i < len(httpURLs) {
		return httpURLs[i]
	}
	return ""
}

// wsURLForPeer returns the WebSocket-live URL for clients[i] when set, "" otherwise.
func wsURLForPeer(i int, wsURLs []string) string {
	if i < len(wsURLs) {
		return wsURLs[i]
	}
	return ""
}
