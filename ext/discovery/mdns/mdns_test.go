package mdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/discovery"

	"github.com/fxamacker/cbor/v2"
	"github.com/grandcat/zeroconf"
)

// -----------------------------------------------------------------------
// §3.2 wire pin — the cross-impl-convergence anchor
// -----------------------------------------------------------------------

func TestWirePinConstants(t *testing.T) {
	// These constants are LOAD-BEARING for cross-impl convergence. Rust + Py
	// MUST use the same strings, or LAN-discovery silently fails (the spec
	// flagged this as the worst splinter mode — no error to catch).
	if ServiceType != "_entity-core._udp.local." {
		t.Fatalf("§3.2 PIN: ServiceType drifted to %q — Rust+Py would silently not discover Go peers", ServiceType)
	}
	if ServiceTypeLabel != "_entity-core._udp" {
		t.Fatalf("ServiceTypeLabel drifted to %q (must be ServiceType minus the trailing `.local.` domain)", ServiceTypeLabel)
	}
	if ServiceDomain != "local." {
		t.Fatalf("ServiceDomain drifted to %q", ServiceDomain)
	}
	if TXTKeyVersion != "version" {
		t.Fatalf("§3.2 PIN: TXTKeyVersion drifted to %q", TXTKeyVersion)
	}
	if TXTKeyPeerIDHint != "peer_id_hint" {
		t.Fatalf("§3.2 PIN: TXTKeyPeerIDHint drifted to %q", TXTKeyPeerIDHint)
	}
	if TXTKeyProfileRef != "profile_ref" {
		t.Fatalf("§3.2 PIN: TXTKeyProfileRef drifted to %q", TXTKeyProfileRef)
	}
	if CurrentVersion != "1" {
		t.Fatalf("§3.2 PIN: CurrentVersion drifted to %q (only bump on breaking wire change)", CurrentVersion)
	}
	if BackendKind != "mdns" {
		t.Fatalf("§3.2 PIN: BackendKind drifted to %q (must match types.DiscoveryBackendMDNS)", BackendKind)
	}
	if BackendKind != types.DiscoveryBackendMDNS {
		t.Fatalf("BackendKind %q != types.DiscoveryBackendMDNS %q", BackendKind, types.DiscoveryBackendMDNS)
	}
}

// -----------------------------------------------------------------------
// Backend interface conformance (compile-time + Kind check)
// -----------------------------------------------------------------------

func TestBackendSatisfiesInterface(t *testing.T) {
	var _ discovery.Backend = (*Backend)(nil) // compile-time check
	b := New("2Kpeer", nil)
	if b.Kind() != BackendKind {
		t.Fatalf("Kind(): want %q got %q", BackendKind, b.Kind())
	}
}

// -----------------------------------------------------------------------
// Announce — resolver wiring + idempotence
// -----------------------------------------------------------------------

func TestAnnounceRequiresResolver(t *testing.T) {
	b := New("2Kpeer", nil) // nil resolver
	err := b.Announce(context.Background(), "profile-http-poll")
	if err == nil {
		t.Fatal("Announce with nil resolver must error")
	}
	if !strings.Contains(err.Error(), "ProfileResolver not wired") {
		t.Fatalf("error must surface missing resolver, got: %v", err)
	}
}

func TestAnnounceUnknownProfileError(t *testing.T) {
	resolver := StaticResolver(map[string]struct {
		Port   int
		Protos []string
	}{
		"known-profile": {Port: 9002, Protos: []string{"tcp"}},
	})
	b := New("2Kpeer", resolver)
	err := b.Announce(context.Background(), "unknown-profile")
	if err == nil {
		t.Fatal("Announce with unknown profile must error")
	}
	if !strings.Contains(err.Error(), "unknown profile_ref") {
		t.Fatalf("error must surface unknown profile, got: %v", err)
	}
}

// -----------------------------------------------------------------------
// AnnounceStop — idempotent on never-announced
// -----------------------------------------------------------------------

func TestAnnounceStopIdempotent(t *testing.T) {
	b := New("2Kpeer", nil)
	if err := b.AnnounceStop(context.Background(), "profile-never-announced"); err != nil {
		t.Fatalf("AnnounceStop on never-announced must be idempotent (no error), got: %v", err)
	}
}

// -----------------------------------------------------------------------
// candidateFromServiceEntry / endpoint_hint round-trip
// -----------------------------------------------------------------------

func TestCandidateFromServiceEntryShape(t *testing.T) {
	entry := &zeroconf.ServiceEntry{
		HostName: "peer-host.local.",
		Port:     9002,
		Text: []string{
			"version=1",
			"peer_id_hint=2KSomeBase58PeerID",
			"profile_ref=profile-http-poll",
			"proto=tcp,http-poll",
			"unknown_key=should_be_dropped",
		},
	}
	cd := candidateFromServiceEntry(entry)

	if cd.Backend != BackendKind {
		t.Fatalf("Backend: want %q got %q", BackendKind, cd.Backend)
	}
	if cd.PeerID != "" {
		// §2.1 — peer_id is null pre-IDENTIFY. The TXT key peer_id_hint
		// is *advertised* but NOT trusted until IDENTIFY completes (§5.3).
		t.Fatalf("§2.1: PeerID must remain null pre-IDENTIFY, got %q", cd.PeerID)
	}
	if cd.IdentityHint != nil {
		// §2.2.1: mDNS backend doesn't surface a non-nil identity_hint in
		// v1; admission falls back to TOFU + the §2 grant decision.
		t.Fatalf("§2.2.1: mDNS candidate identity_hint must be nil (TOFU), got %+v", cd.IdentityHint)
	}
	if len(cd.EndpointHint) == 0 {
		t.Fatal("EndpointHint must carry the opaque per-§2.1 backend blob")
	}

	host, port, txt, err := DecodeEndpointHint(cd.EndpointHint)
	if err != nil {
		t.Fatalf("DecodeEndpointHint: %v", err)
	}
	if host != "peer-host.local." {
		t.Fatalf("host: want %q got %q", "peer-host.local.", host)
	}
	if port != 9002 {
		t.Fatalf("port: want 9002 got %d", port)
	}
	if txt[TXTKeyVersion] != "1" {
		t.Fatalf("version TXT: want %q got %q", "1", txt[TXTKeyVersion])
	}
	if txt[TXTKeyPeerIDHint] != "2KSomeBase58PeerID" {
		t.Fatalf("peer_id_hint TXT drift: %q", txt[TXTKeyPeerIDHint])
	}
	if txt[TXTKeyProfileRef] != "profile-http-poll" {
		t.Fatalf("profile_ref TXT drift: %q", txt[TXTKeyProfileRef])
	}
	if txt[TXTKeyProto] != "tcp,http-poll" {
		t.Fatalf("proto TXT drift: %q", txt[TXTKeyProto])
	}
	if _, ok := txt["unknown_key"]; ok {
		t.Fatal("§3.2: unknown TXT keys MUST be ignored, but it survived")
	}
}

func TestParseTXTKeysDropsUnknown(t *testing.T) {
	got := parseTXTKeys([]string{
		"version=1",
		"peer_id_hint=2Kfoo",
		"future_extension=opaque",
		"malformed_no_equals",
		"display_name=Cool Peer",
	})
	if got[TXTKeyVersion] != "1" {
		t.Fatalf("version drift: %v", got)
	}
	if got[TXTKeyDisplayName] != "Cool Peer" {
		t.Fatalf("display_name drift: %v", got)
	}
	if _, ok := got["future_extension"]; ok {
		t.Fatal("future-key MUST be dropped per §3.2 forward-compat")
	}
	if _, ok := got["malformed_no_equals"]; ok {
		t.Fatal("malformed TXT entry must not surface as a key")
	}
}

// -----------------------------------------------------------------------
// Scan timeout — bounded, returns nil + nil-error on no-network
// -----------------------------------------------------------------------

func TestScanReturnsWithinScanTimeout(t *testing.T) {
	// Short timeout. Real multicast may or may not be available; the
	// behavior we pin is "doesn't hang past timeout, doesn't error on
	// no-announcements." Empty + nil-error is the correct quiet-network
	// behavior.
	b := New("2Kpeer", nil, WithScanTimeout(200*time.Millisecond))
	start := time.Now()
	got, err := b.Scan(context.Background(), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Scan exceeded reasonable timeout bound: %v", elapsed)
	}
	// `got` may be nil (no peers) or non-empty (CI peer; rare). Both fine.
	_ = got
}

// -----------------------------------------------------------------------
// EndpointHint encoding stability — ECF determinism guard
// -----------------------------------------------------------------------

func TestEndpointHintRoundTrip(t *testing.T) {
	entry := &zeroconf.ServiceEntry{
		HostName: "h.local.",
		Port:     9003,
		Text:     []string{"version=1", "peer_id_hint=p", "profile_ref=r"},
	}
	cd := candidateFromServiceEntry(entry)
	// Same input → same encoded bytes (encoding is fxamacker/cbor.Marshal,
	// not ECF, since EndpointHint is opaque per §2.1; we still pin
	// stability so candidate content_hash is reproducible across the
	// same Backend wire path).
	cd2 := candidateFromServiceEntry(entry)
	if string(cd.EndpointHint) != string(cd2.EndpointHint) {
		t.Fatalf("endpoint_hint encoding not stable across equal inputs")
	}
}

// Silence the unused-import for cbor.RawMessage (only used in fixtures
// above through the candidate path).
var _ cbor.RawMessage
