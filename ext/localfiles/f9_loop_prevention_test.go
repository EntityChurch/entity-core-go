package localfiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
)

// TestF9_HandleWrite_MarksWrittenBeforeDiskWrite pins the F9 fix
// (workbench Round 6 handoff): dispatch-driven writes through
// local/files:write MUST go through the same reverseTracker loop-
// prevention circuit breaker as tree-event-driven writes through the
// reverseWrite path. Without this symmetry, a same-path subscription
// loop runs unbounded (workbench's repro: 2169 entities/5s from one
// user write).
//
// Asymmetry being pinned:
//   - reverse.go:185 — calls tracker.markWritten(treePath) before disk write
//   - operations.go (post-fix) — same call before its disk write
//
// Without this test, a future refactor could silently re-introduce the
// asymmetry. The repro itself lives in workbench-go's
// TestStage3_F9_SelfLoop_SinglePeer.
func TestF9_HandleWrite_MarksWrittenBeforeDiskWrite(t *testing.T) {
	h, hctx, tmpDir := newTestHandler(t)

	// Inject a tracker so handleWrite's lookup finds one. In production
	// this is established by StartReverseWrite; the test reaches in
	// directly to avoid needing the full reverse-write loop wired.
	tracker := newReverseTracker()
	h.mu.Lock()
	h.reverseTracker = tracker
	h.mu.Unlock()

	const treePath = "local/files/test/loop-probe.md"
	body := []byte("F9 loop-probe body")

	req := &handler.Request{
		Operation: "write",
		Params:    makeWriteParams(body, true),
		Context:   withResource(hctx, treePath),
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("handleWrite returned status %d (expected 200)", resp.Status)
	}

	// Disk side effect actually happened (sanity).
	fsPath := filepath.Join(tmpDir, "loop-probe.md")
	if _, err := os.Stat(fsPath); err != nil {
		t.Fatalf("expected disk write at %s: %v", fsPath, err)
	}

	// F9 invariant: tracker MUST be marked. If a future change drops
	// the markWritten call from handleWrite, the loop reappears under
	// any dual-watch / self-subscription topology.
	if !tracker.isRecentlyWritten(treePath) {
		t.Fatalf("F9 regression: handleWrite did not mark %q via reverseTracker before disk write — same-path subscription loop is no longer guarded", treePath)
	}
}

// TestF9_HandleWrite_NoTracker_StillWorks confirms the F9 fix degrades
// gracefully when no watcher (and thus no reverseTracker) has been
// configured — handler-only deployments without StartReverseWrite
// continue to work. The tracker == nil branch must skip the mark.
func TestF9_HandleWrite_NoTracker_StillWorks(t *testing.T) {
	h, hctx, _ := newTestHandler(t)
	// Deliberately do NOT inject a tracker — reverseTracker stays nil.

	const treePath = "local/files/test/no-tracker.md"
	body := []byte("F9 no-tracker probe")

	req := &handler.Request{
		Operation: "write",
		Params:    makeWriteParams(body, true),
		Context:   withResource(hctx, treePath),
	}
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("handleWrite returned status %d with nil tracker (expected 200)", resp.Status)
	}
}
