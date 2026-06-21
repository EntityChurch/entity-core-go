package continuation

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestV120_PerOccurrencePathMultiplicity pins the v1.20 §3.10.1 property:
// each distinct chain-error observation lands at its own {marker_hash}
// terminal path segment because each occurrence's body differs (the
// timestamp varies). A flapping target produces multiple markers at
// distinct paths — the tree IS the event log.
//
// This is the property §3.10.6 timestamp-capture discipline ENABLES:
// when timestamps are captured at failure-origination time (not bind-
// site), distinct wall-clock failures produce distinct body bytes
// → distinct content hashes → distinct paths.
func TestV120_PerOccurrencePathMultiplicity(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-flap"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-flap"}

	// Drive three sequential failures with the same handler code. Sleep
	// >1ms between to ensure distinct origination timestamps (which the
	// caller captures, per §3.10.6 discipline).
	counter := 0
	hctx.Execute = func(ctx context.Context, uri, op string, params entity.Entity, opts ...handler.ExecuteOption) (*handler.Response, error) {
		counter++
		ed, _ := types.ErrorData{Code: "internal"}.ToEntity()
		return &handler.Response{Status: 500, Result: ed}, nil
	}

	capHash := testCapHash(t, hctx.Store)

	// Three independent advance calls — each fires a fresh dispatch and
	// observes its own non-2xx → its own marker bind.
	for i := 0; i < 3; i++ {
		remaining := uint64(1)
		path := "system/inbox/flap-" + string(rune('a'+i))
		storeContinuation(t, hctx, path, types.ContinuationData{
			Target:              "system/tree",
			Operation:           "put",
			RemainingExecutions: &remaining,
			DispatchCapability:  capHash,
		})
		resp, err := h.Handle(context.Background(), makeAdvanceRequest(t, hctx, path, 200, "payload"))
		if err != nil {
			t.Fatalf("advance %d: %v", i, err)
		}
		if resp.Status != 200 {
			t.Fatalf("advance %d: status=%d, want 200 (best-effort)", i, resp.Status)
		}
		// Stretch the wall clock just enough that the next iteration's
		// origination timestamp differs at ms granularity. The test
		// runs in <100ms total so this doesn't slow CI.
		sleepMs(2)
	}

	// All three markers MUST coexist under the same {reason} prefix at
	// distinct {marker_hash} terminal segments per v1.20 §3.10.1.
	prefix := "system/runtime/chain-errors/lost/chain-flap/req-flap/internal/"
	entries := hctx.LocationIndex.List(prefix)
	if len(entries) != 3 {
		t.Fatalf("expected 3 distinct markers under %s (one per occurrence), got %d", prefix, len(entries))
	}
	// Verify each entry's path terminal segment matches its content_hash
	// per V7 §3.5 invariant-pointer hex form.
	seen := map[string]bool{}
	for _, e := range entries {
		segs := strings.Split(e.Path, "/")
		terminal := segs[len(segs)-1]
		expected := hex.EncodeToString(e.Hash.Bytes())
		if terminal != expected {
			t.Fatalf("entry %s: terminal segment %q != marker_hash %q", e.Path, terminal, expected)
		}
		if seen[terminal] {
			t.Fatalf("duplicate {marker_hash} %s — distinct occurrences should produce distinct hashes", terminal)
		}
		seen[terminal] = true
	}
}

// TestV120_SameContentReboundIsNoop pins v1.20 §3.10.1's content-
// addressed-idempotency property: re-binding bytes-identical body at
// the same path is a genuine tree:put no-op (Class A spec, same-hash
// same-path put fires no event). This covers subscription redelivery
// under the §3.10.6 timestamp-capture discipline — same origination
// timestamp → same body bytes → same content_hash → same path.
//
// We exercise this directly at the bindLostErrorMarker layer because
// the natural test (multiple advance() calls with frozen time) requires
// mocking the time source. The layer-level test pins the idempotency
// claim explicitly.
func TestV120_SameContentReboundIsNoop(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-redeliver"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-redeliver"}

	// Same origination timestamp + same reason + same body fields →
	// same content_hash → same path on every call.
	const frozenTS uint64 = 1_700_000_000_000
	ed, _ := ecf.Encode(types.ErrorData{Code: "unavailable", Message: "redelivered"})

	for i := 0; i < 5; i++ {
		h.bindLostErrorMarker(hctx, "entity://test/peer/sys", 503, ed, "unavailable", frozenTS, hashZero())
	}

	prefix := "system/runtime/chain-errors/lost/chain-redeliver/req-redeliver/unavailable/"
	entries := hctx.LocationIndex.List(prefix)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 marker after 5 same-content rebinds (redelivery dedup), got %d", len(entries))
	}
}

// TestV120_DistinctCodesCoexistAsSiblings pins v1.19 §3.10.5 + v1.20
// §3.10.1: distinct response codes at the same (chain_id, step_index)
// land at sibling {reason} subtrees, each with its own {marker_hash}
// terminal segment. Restores the v1.16 sibling-paths property under
// the unified-design vocabulary.
func TestV120_DistinctCodesCoexistAsSiblings(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-sibs"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-sibs"}

	// Three different codes from the same step. Each produces its own
	// {reason} subtree.
	codes := []string{"internal", "unavailable", "not_found"}
	for _, code := range codes {
		ed, _ := ecf.Encode(types.ErrorData{Code: code})
		h.bindLostErrorMarker(hctx, "entity://test/peer/sys", 500, ed, code, 1_700_000_000_000, hashZero())
	}

	for _, code := range codes {
		prefix := "system/runtime/chain-errors/lost/chain-sibs/req-sibs/" + code + "/"
		entries := hctx.LocationIndex.List(prefix)
		if len(entries) != 1 {
			t.Fatalf("code %q: expected 1 sibling marker under %s, got %d", code, prefix, len(entries))
		}
	}
}

// TestV120_PathTerminalIsV7Section35HexForm pins the §3.10.1 encoding
// rule: the {marker_hash} terminal path segment uses the V7 §3.5
// invariant-pointer hex form — hex.EncodeToString(content_hash.Bytes())
// — lowercase, format-code-included, 66 chars. Same encoding
// core/capability/storage_path.go uses for multi-sig-root capability
// paths.
//
// If a future refactor regresses to Hash.String() (the V7 §1.2 UI-only
// display form "ecf-sha256:<hex>"), this test fails by detecting the
// colon character forbidden in the terminal segment.
func TestV120_PathTerminalIsV7Section35HexForm(t *testing.T) {
	h := NewHandler()
	hctx := newTestContext()
	hctx.RequestID = "req-enc"
	hctx.Bounds = &types.BoundsData{ChainID: "chain-enc"}

	ed, _ := ecf.Encode(types.ErrorData{Code: "internal"})
	h.bindLostErrorMarker(hctx, "entity://test/peer/sys", 500, ed, "internal", 1_700_000_000_000, hashZero())

	prefix := "system/runtime/chain-errors/lost/chain-enc/req-enc/internal/"
	entries := hctx.LocationIndex.List(prefix)
	if len(entries) != 1 {
		t.Fatalf("expected 1 marker, got %d", len(entries))
	}
	terminal := strings.TrimPrefix(entries[0].Path, "/")
	segs := strings.Split(terminal, "/")
	hashSeg := segs[len(segs)-1]

	// V7 §3.5 hex form is 66 lowercase hex chars (format byte + 32-byte digest).
	if len(hashSeg) != 66 {
		t.Fatalf("terminal segment length: got %d, want 66 (V7 §3.5 invariant-pointer hex form)", len(hashSeg))
	}
	if strings.Contains(hashSeg, ":") {
		t.Fatalf("terminal segment contains ':' — that's V7 §1.2 Hash.String() display form which is UI-only, NEVER on wire/paths per V7 §3.5")
	}
	// Verify byte-equality with the entry's hash via the V7 §3.5 encoder.
	expected := hex.EncodeToString(entries[0].Hash.Bytes())
	if hashSeg != expected {
		t.Fatalf("terminal segment %q != hex.EncodeToString(hash.Bytes()) %q", hashSeg, expected)
	}
}

// sleepMs sleeps for ms milliseconds — helper for the per-occurrence
// multiplicity test to ensure distinct origination timestamps at ms
// granularity.
func sleepMs(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// hashZero returns the zero hash for tests that pass an empty mirror-
// pointer argument to bindLostErrorMarker.
func hashZero() hash.Hash {
	return hash.Hash{}
}
