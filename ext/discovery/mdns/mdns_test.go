package mdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
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

// EXTENSION-DISCOVERY §3.3 (corrected 2026-08-11) is a two-case rule, so this
// test covers both halves. It used to wire a nil resolver and assert that
// stopping ANY profile was a silent success — which is the defect: idempotency
// answers "recognized but not running", and it was being applied to a profile
// the backend had never heard of.
func TestAnnounceStopTwoCaseRule(t *testing.T) {
	resolver := StaticResolver(map[string]struct {
		Port   int
		Protos []string
	}{
		"tcp": {Port: 9000, Protos: []string{"entity-core/1"}},
	})
	b := New("2Kpeer", resolver)

	// Case 1 — recognized, not currently announcing: idempotent success.
	if err := b.AnnounceStop(context.Background(), "tcp"); err != nil {
		t.Fatalf("AnnounceStop on a recognized, not-running profile must be idempotent, got: %v", err)
	}

	// Case 2 — unrecognized by the backend: a caller error the handler maps
	// to 400, NOT a silent 200.
	err := b.AnnounceStop(context.Background(), "profile-never-announced")
	if err == nil {
		t.Fatal("AnnounceStop on a backend-unrecognized profile_ref returned nil — " +
			"idempotency covers the recognized case only (§3.3); a silent success here " +
			"means the backend never asked whether it recognizes the ref")
	}
	if !errors.Is(err, discovery.ErrUnknownProfileRef) {
		t.Fatalf("AnnounceStop unknown profile_ref: want ErrUnknownProfileRef sentinel "+
			"(the handler keys its 400 off it), got: %v", err)
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

// -----------------------------------------------------------------------
// Persistent watcher (§3.0) — lifecycle. These are unit-level (no
// multicast traffic), matching the package's altitude: they prove the
// watcher STARTS on observe-wiring, STOPS cleanly on Close (no goroutine
// leak — Close waits on the done channel), and is idempotent on
// re-registration and double-Close. End-to-end arrival streaming rides
// the same Browse plumbing Scan already exercises.
// -----------------------------------------------------------------------

func watcherState(b *Backend) (started bool, done chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.watcherStarted, b.watcherDone
}

func TestSetObserveCallbackStartsWatcher(t *testing.T) {
	b := New("peer-local", nil)
	if started, _ := watcherState(b); started {
		t.Fatal("watcher started before SetObserveCallback")
	}
	b.SetObserveCallback(func(types.CandidateData) {}, func(h hash.Hash) {})
	started, done := watcherState(b)
	if !started || done == nil {
		t.Fatalf("watcher did not start on non-nil observe wiring (started=%v done=%v)", started, done != nil)
	}
	b.Close()
}

func TestNilObserveDoesNotStartWatcher(t *testing.T) {
	b := New("peer-local", nil)
	b.SetObserveCallback(nil, nil)
	if started, _ := watcherState(b); started {
		t.Fatal("watcher started on a nil observe hook — nil means no streaming sink")
	}
}

func TestCloseStopsWatcherNoLeak(t *testing.T) {
	b := New("peer-local", nil)
	b.SetObserveCallback(func(types.CandidateData) {}, func(h hash.Hash) {})
	_, done := watcherState(b)
	if done == nil {
		t.Fatal("no watcher to stop")
	}
	b.Close() // blocks until the goroutine exits
	select {
	case <-done:
		// closed => goroutine returned
	default:
		t.Fatal("Close returned but watcher done channel is still open — goroutine leak")
	}
	if started, _ := watcherState(b); started {
		t.Fatal("watcherStarted not reset after Close")
	}
	b.Close() // idempotent — must not panic or block
}

func TestReRegistrationDoesNotStartSecondWatcher(t *testing.T) {
	b := New("peer-local", nil)
	b.SetObserveCallback(func(types.CandidateData) {}, func(h hash.Hash) {})
	_, done1 := watcherState(b)
	b.SetObserveCallback(func(types.CandidateData) {}, func(h hash.Hash) {})
	_, done2 := watcherState(b)
	if done1 != done2 {
		t.Fatal("re-registration started a second watcher (done channel changed)")
	}
	b.Close()
}

func TestWithWatchIntervalHonored(t *testing.T) {
	b := New("peer-local", nil, WithWatchInterval(250*time.Millisecond))
	if b.watchInterval != 250*time.Millisecond {
		t.Fatalf("watchInterval = %v, want 250ms", b.watchInterval)
	}
	// Non-positive is ignored (keeps the default).
	b2 := New("peer-local", nil, WithWatchInterval(0))
	if b2.watchInterval != 30*time.Second {
		t.Fatalf("watchInterval = %v, want default 30s (non-positive ignored)", b2.watchInterval)
	}
}

// TestWatcherReBrowsesAndClosesCleanly exercises the periodic re-browse loop
// (ticker → browseCycle → cancel) over several ticks with short timeouts,
// then asserts Close joins the goroutine with no leak. No mDNS responders are
// needed: each cycle is a bounded empty browse (same as TestScan…), the point
// is the cadence + shutdown mechanics, not observation.
func TestWatcherReBrowsesAndClosesCleanly(t *testing.T) {
	b := New("peer-local", nil,
		WithScanTimeout(15*time.Millisecond),
		WithWatchInterval(20*time.Millisecond))
	b.SetObserveCallback(func(types.CandidateData) {}, func(h hash.Hash) {})
	_, done := watcherState(b)
	if done == nil {
		t.Fatal("watcher did not start")
	}
	time.Sleep(120 * time.Millisecond) // ~5 cycles
	select {
	case <-done:
		t.Fatal("watcher exited on its own before Close")
	default:
	}
	b.Close()
	select {
	case <-done:
	default:
		t.Fatal("Close returned but watcher goroutine still running — leak")
	}
}
