package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// defaultFixture mirrors the -fixture flag default: entity-browser-rust's
// committed federation corpus, a SIBLING repo that may be absent on a fresh
// checkout. When absent the test SKIPs LOUDLY (never a silent pass) — this is a
// cross-impl driver and the sibling legitimately may not be cloned, but the
// AGENTS.md skip-guard rule requires the absence be visible and the path live.
const defaultFixture = "../../../entity-browser-rust/tests/fixtures/registry-federation"

// TestConsumeFederation is B5 — go's peerissued.Backend resolving names a rust
// publisher bound, over an in-process HTTP hop against browser-rust's committed
// bytes. Every leg must be green: four names resolve to their MAPPING peer-ids,
// an unbound name is not_found, transports are the D8 bare-hash shape, and one
// page dereferences the resolved domain's signed root by hash.
func TestConsumeFederation(t *testing.T) {
	fixture := os.Getenv("FEDERATION_FIXTURE")
	if fixture == "" {
		fixture = defaultFixture
	}
	if _, err := os.Stat(filepath.Join(fixture, "MAPPING.txt")); err != nil {
		t.Skipf("SKIP (fixture absent, cross-impl driver): %s not found (%v) — "+
			"clone entity-browser-rust (54f31a7) or set FEDERATION_FIXTURE", fixture, err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(fixture)))
	defer srv.Close()

	results, allOK := run(srv.URL)
	for _, r := range results {
		if !r.OK {
			t.Errorf("leg %q %q FAILED: %s", r.Leg, r.Name, r.Detail)
		}
	}
	if !allOK {
		t.Fatalf("B5 federation consume: not all legs green (%d legs)", len(results))
	}
	// Anti-vacuity: a driver that ran zero legs must not read as a pass.
	if len(results) < 6 {
		t.Fatalf("B5: expected >=6 legs (4 resolves + neg-control + transport + page), got %d", len(results))
	}
}
