package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

func TestNotifyingCreatedEvent(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x01

	n.Set("system/tree/foo", h)

	select {
	case evt := <-events:
		if evt.ChangeType != ChangeCreated {
			t.Fatalf("expected ChangeCreated, got %d", evt.ChangeType)
		}
		if evt.Path != "system/tree/foo" {
			t.Fatalf("wrong path: %s", evt.Path)
		}
		if evt.Hash != h {
			t.Fatal("wrong hash")
		}
		if !evt.PreviousHash.IsZero() {
			t.Fatal("previous hash should be zero for create")
		}
	default:
		t.Fatal("expected event")
	}
}

func TestNotifyingModifiedEvent(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	h1 := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h1.Digest[0] = 0x01
	h2 := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h2.Digest[0] = 0x02

	n.Set("system/tree/foo", h1)
	<-events // drain create event

	n.Set("system/tree/foo", h2)

	select {
	case evt := <-events:
		if evt.ChangeType != ChangeModified {
			t.Fatalf("expected ChangeModified, got %d", evt.ChangeType)
		}
		if evt.Hash != h2 {
			t.Fatal("wrong new hash")
		}
		if evt.PreviousHash != h1 {
			t.Fatal("wrong previous hash")
		}
	default:
		t.Fatal("expected event")
	}
}

// TestNotifyingIdempotentSet pins the no-op suppression in setInternal:
// when a path is already bound to the same hash, Set must NOT emit an event
// or run sync hooks. This invariant is what makes seed-on-restart safe with
// persistent storage (DESIGN-SQLITE-PERSISTENCE.md §4.2).
func TestNotifyingIdempotentSet(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x42

	n.Set("system/tree/seed", h)
	<-events // drain create

	hookFired := 0
	n.AddNamedSyncHook("test/idempotent", func(evt TreeChangeEvent) *ConsumerResult {
		hookFired++
		return &ConsumerResult{Status: 200}
	})

	// Re-set same path to same hash — must be a no-op.
	n.Set("system/tree/seed", h)

	select {
	case evt := <-events:
		t.Fatalf("expected no event for idempotent set, got %+v", evt)
	default:
	}
	if hookFired != 0 {
		t.Fatalf("sync hook fired %d times on idempotent set; want 0", hookFired)
	}

	// Sanity: a real change still emits.
	h2 := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h2.Digest[0] = 0x43
	n.Set("system/tree/seed", h2)
	select {
	case <-events:
	default:
		t.Fatal("real change after idempotent no-op did not emit")
	}
	if hookFired != 1 {
		t.Fatalf("sync hook fired %d times on real change; want 1", hookFired)
	}
}

func TestNotifyingDeletedEvent(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x01

	n.Set("system/tree/foo", h)
	<-events // drain create

	removed, ok := n.Remove("system/tree/foo")
	if !ok {
		t.Fatal("expected remove to succeed")
	}
	if removed != h {
		t.Fatal("wrong removed hash")
	}

	select {
	case evt := <-events:
		if evt.ChangeType != ChangeDeleted {
			t.Fatalf("expected ChangeDeleted, got %d", evt.ChangeType)
		}
		if evt.PreviousHash != h {
			t.Fatal("wrong previous hash")
		}
		if !evt.Hash.IsZero() {
			t.Fatal("hash should be zero for delete")
		}
	default:
		t.Fatal("expected event")
	}
}

func TestNotifyingRemoveNonExistent(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	_, ok := n.Remove("nonexistent")
	if ok {
		t.Fatal("expected remove to return false")
	}

	select {
	case <-events:
		t.Fatal("should not emit event for non-existent remove")
	default:
	}
}

func TestNotifyingPassthrough(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x01

	n.Set("a/b", h)
	n.Set("a/c", h)

	if !n.Has("a/b") {
		t.Fatal("Has should return true")
	}
	if n.Has("nonexistent") {
		t.Fatal("Has should return false")
	}

	got, ok := n.Get("a/b")
	if !ok || got != h {
		t.Fatal("Get passthrough failed")
	}

	entries := n.List("a/")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

// TestNotifyingNonBlockingOnFullBuffer was removed when emit's drop-on-full
// behavior was replaced with blocking backpressure. The previous behavior
// it asserted (Set returns immediately, events silently dropped) is now
// considered a correctness bug — see TestNotifyingEmitBackpressure for the
// regression test guarding the new design, and the workbench-team
// SQLite busy bulk-ingest report
// for the production incident that motivated the change.

func TestNotifyingDoneStopsSending(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	close(done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x01
	n.Set("a", h)

	select {
	case <-events:
		t.Fatal("should not emit after done is closed")
	default:
	}

	// Inner should still work.
	if !inner.Has("a") {
		t.Fatal("inner should have the path")
	}
}

func TestNotifyingConcurrentAccess(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 1024)
	done := make(chan struct{})
	n := NewNotifyingLocationIndex(inner, events, done)

	var wg sync.WaitGroup
	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hi := h
			hi.Digest[0] = byte(i)
			path := "test/" + string(rune('a'+i%26))
			n.Set(path, hi)
			n.Has(path)
			n.Get(path)
			n.List("test/")
		}(i)
	}
	wg.Wait()
}

// TestNotifyingEmitErrorOnSaturation verifies the design after
// the event-delivery-backpressure review: emit returns
// ErrEventBufferFull when the channel is saturated, the binding still
// commits (per V7 §2870), and the error propagates to the caller of Set.
//
// This replaces the older TestNotifyingEmitBackpressure that asserted
// blocking semantics. Blocking-on-saturation was found to convert silent
// data loss into deadlock — the same defect manifesting differently. The
// correct shape per §2688 is errors-at-saturation-boundaries, propagated
// to the caller.
func TestNotifyingEmitErrorOnSaturation(t *testing.T) {
	const bufferSize = 4 // intentionally tiny — easy to saturate

	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, bufferSize)
	done := make(chan struct{})
	defer close(done)

	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}

	// Phase 1: fill the buffer. Each Set succeeds while there's room.
	for i := 0; i < bufferSize; i++ {
		hi := h
		hi.Digest[0] = byte(i)
		if err := n.Set(fmt.Sprintf("/p/i/%d", i), hi); err != nil {
			t.Fatalf("Set(%d) with buffer not yet full: unexpected err: %v", i, err)
		}
	}

	// Phase 2: writes past the buffer cap saturate. emit returns
	// ErrEventBufferFull; Set propagates it. The binding STILL commits
	// (per V7 §2870 atomicity-at-binding-level).
	hi := h
	hi.Digest[0] = 99
	err := n.Set("/p/saturated", hi)
	if !errors.Is(err, ErrEventBufferFull) {
		t.Fatalf("Set after buffer full: got err=%v, want ErrEventBufferFull", err)
	}

	// The binding committed — the index reflects the write even though the
	// event was lost. Caller can decide whether to retry, abort, or accept
	// the loss based on operational context.
	if !inner.Has("/p/saturated") {
		t.Fatal("binding should have committed despite emit error (V7 §2870)")
	}
	if got, _ := inner.Get("/p/saturated"); got != hi {
		t.Fatal("inner index should reflect the new hash")
	}

	// Saturation counter increments — operators observe this via Peer.Stats().
	if got := n.DroppedEvents(); got == 0 {
		t.Fatal("DroppedEvents should be > 0 after saturation")
	}

	// Phase 3: drain a slot. Subsequent Set succeeds — the saturation is
	// transient, the caller's retry pattern works once the consumer catches up.
	<-events // drain one
	hi.Digest[0] = 100
	if err := n.Set("/p/after-drain", hi); err != nil {
		t.Fatalf("Set after draining: unexpected err: %v", err)
	}
}

// TestNotifyingEmitShutdownNotError verifies that emit returns
// ErrShuttingDown (NOT ErrEventBufferFull) when done is closed mid-write.
// Callers may use errors.Is(err, store.ErrShuttingDown) to distinguish
// "lost event" from "shutting down."
func TestNotifyingEmitShutdownNotError(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 4)
	done := make(chan struct{})

	n := NewNotifyingLocationIndex(inner, events, done)

	close(done) // shut down BEFORE writing

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	h.Digest[0] = 0x01
	err := n.Set("/p/during-shutdown", h)
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("Set during shutdown: got err=%v, want ErrShuttingDown", err)
	}

	// The binding committed in the inner index (the inner Set ran before emit).
	if !inner.Has("/p/during-shutdown") {
		t.Fatal("binding should have committed before emit was attempted")
	}
}

// TestNotifyingEmitDrainAndRetry exercises the caller's "retry after
// saturation" pattern. When emit fails with ErrEventBufferFull, the caller
// can wait briefly and retry; once the consumer catches up, subsequent
// writes succeed.
//
// Note: retrying the SAME Set(path, hash) is a no-op (the binding already
// committed; subsequent identical writes are suppressed via no-op detection
// at line 117 of notifying.go). The retry pattern applies to writes for
// DIFFERENT (path, hash) tuples — under sustained saturation, the caller
// can rate-limit themselves until DroppedEvents stops growing.
func TestNotifyingEmitDrainAndRetry(t *testing.T) {
	const bufferSize = 2

	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, bufferSize)
	done := make(chan struct{})
	defer close(done)

	n := NewNotifyingLocationIndex(inner, events, done)

	h := hash.Hash{Algorithm: hash.AlgorithmSHA256}

	// Fill buffer.
	for i := 0; i < bufferSize; i++ {
		hi := h
		hi.Digest[0] = byte(i)
		if err := n.Set(fmt.Sprintf("/p/fill/%d", i), hi); err != nil {
			t.Fatalf("Set during fill: %v", err)
		}
	}

	// Next write saturates.
	hi := h
	hi.Digest[0] = byte(bufferSize)
	if err := n.Set("/p/sat", hi); !errors.Is(err, ErrEventBufferFull) {
		t.Fatalf("expected saturation: got %v", err)
	}

	// Drain ALL pending events.
	for len(events) > 0 {
		<-events
	}

	// Retry: a new write succeeds because buffer has room.
	hi.Digest[0] = byte(bufferSize + 1)
	if err := n.Set("/p/retry", hi); err != nil {
		t.Fatalf("Set after drain: %v", err)
	}
}

// TestPathMatchesPattern pins the pattern grammar — exact, prefix-wildcard,
// universal, plus the three coordinate-space cases (peer-relative, absolute-
// specific-peer, absolute-any-peer).
//
// The peer-relative form is namespace-agnostic by design: a pattern like
// "system/attestation/*" matches events under ANY peer's namespace in the
// local tree (local + remote-via-sync/revision). Scope to a specific peer
// with "/PID/system/attestation/*"; observers wanting explicit
// namespace-agnostic semantics can also write "/*/system/attestation/*".
func TestPathMatchesPattern(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// "" and "*" match all.
		{"", "any/path", true},
		{"", "", true},
		{"*", "any/path", true},
		{"*", "/PIDA/data/x", true},

		// ---- Peer-relative patterns: any peer namespace + suffix match ----
		// Absolute event paths under different peers all match the same
		// peer-relative pattern.
		{"system/attestation/*", "/PIDA/system/attestation/x", true},
		{"system/attestation/*", "/PIDB/system/attestation/y", true},
		{"system/attestation/*", "/PIDC/system/attestation/nested/z", true},
		{"system/attestation/*", "/PIDA/system/clock/now", false}, // wrong suffix
		{"system/attestation/*", "/PIDA/system/attestation", true}, // bare prefix
		{"system/attestation",   "/PIDA/system/attestation", true}, // exact peer-rel
		{"system/attestation",   "/PIDA/system/attestation/x", false},

		// ---- Absolute specific-peer patterns: that peer only ----
		{"/PIDA/system/attestation/*", "/PIDA/system/attestation/x", true},
		{"/PIDA/system/attestation/*", "/PIDB/system/attestation/x", false}, // other peer
		{"/PIDA/system/exact/path",    "/PIDA/system/exact/path", true},
		{"/PIDA/system/exact/path",    "/PIDB/system/exact/path", false},

		// ---- Absolute any-peer patterns: /*/ wildcard segment ----
		{"/*/system/attestation/*", "/PIDA/system/attestation/x", true},
		{"/*/system/attestation/*", "/PIDB/system/attestation/y", true},
		{"/*/system/attestation/*", "/PIDA/system/clock/now", false},
		{"/*/system/exact",         "/PIDA/system/exact", true},
		{"/*/system/exact",         "/PIDB/system/exact/x", false},

		// ---- Backward-compatible cases on naked (non-namespaced) paths ----
		{"system/foo",            "system/foo", true},
		{"system/foo",            "system/foo/bar", false},
		{"system/attestation/*",  "system/attestation/x", true},
		{"system/attestation/*",  "system/attest", false},
		{"system/attestation/*",  "system/attestationextra", false},
	}
	for _, tc := range cases {
		got := pathMatchesPattern(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("pathMatchesPattern(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// TestNamedSyncHookPatternFiltering verifies that pattern-filtered hooks only
// fire for matching events and are silently skipped (not "Skipped" in the
// CascadeResult) for non-matching events.
func TestNamedSyncHookPatternFiltering(t *testing.T) {
	inner := NewMemoryLocationIndex()
	events := make(chan TreeChangeEvent, 16)
	done := make(chan struct{})
	defer close(done)
	n := NewNotifyingLocationIndex(inner, events, done)

	var attCount, allCount, exactCount int
	n.AddNamedSyncHookWithPattern("att-only", "system/attestation/*", func(evt TreeChangeEvent) *ConsumerResult {
		attCount++
		return nil
	})
	n.AddNamedSyncHook("legacy-all", func(evt TreeChangeEvent) *ConsumerResult {
		allCount++
		return nil
	})
	n.AddNamedSyncHookWithPattern("exact", "system/clock/now", func(evt TreeChangeEvent) *ConsumerResult {
		exactCount++
		return nil
	})

	for _, p := range []string{
		"system/attestation/a1",
		"system/attestation/a2",
		"system/clock/now",
		"unrelated/path",
	} {
		h := hash.Hash{Algorithm: hash.AlgorithmSHA256}
		h.Digest[0] = byte(len(p))
		if err := n.Set(p, h); err != nil {
			t.Fatalf("Set %s: %v", p, err)
		}
		<-events // drain
	}

	if attCount != 2 {
		t.Errorf("att-only fired %d times, want 2", attCount)
	}
	if allCount != 4 {
		t.Errorf("legacy-all fired %d times, want 4", allCount)
	}
	if exactCount != 1 {
		t.Errorf("exact fired %d times, want 1", exactCount)
	}
}
