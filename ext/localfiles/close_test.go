package localfiles

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestHandlerClose_StopsAllWatchers pins the WB-24 fix (workbench-go Stage 4
// watcher-close feedback): Handler.Close MUST stop
// every active fsnotify watcher so their inotify instances are released. The
// per-user fs.inotify.max_user_instances cap (default 128 on Linux) bites
// multi-peer-per-process test harnesses if watchers leak.
func TestHandlerClose_StopsAllWatchers(t *testing.T) {
	h, hctx, _ := newTestHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wire one watcher so Close has something to stop. peerIdentityHash can
	// be the zero hash for the teardown-only path under test.
	if err := h.StartWatching(ctx, "test", hctx.Store, hctx.LocationIndex, hash.Hash{}); err != nil {
		t.Fatalf("StartWatching: %v", err)
	}

	h.mu.Lock()
	if len(h.watchers) != 1 {
		h.mu.Unlock()
		t.Fatalf("expected 1 watcher after StartWatching, got %d", len(h.watchers))
	}
	h.mu.Unlock()

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	h.mu.Lock()
	if len(h.watchers) != 0 {
		h.mu.Unlock()
		t.Fatalf("watchers map non-empty after Close: %d entries", len(h.watchers))
	}
	h.mu.Unlock()

	// Idempotent — a second Close finds an empty map and is a no-op.
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// Allow any background flush in the (already-stopped) watcher to settle
	// — Stop closes the fsnotify watcher synchronously but the event loop
	// goroutine may take a scheduler tick to exit.
	time.Sleep(10 * time.Millisecond)
}

// TestHandlerClose_NoWatchers exercises the no-watcher path — Close must be
// safe to call on a Handler that never started any watcher (handler-only
// deployments without StartWatching).
func TestHandlerClose_NoWatchers(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	h := NewHandler(nil)
	cfg := RootConfigData{Prefix: "local/files/test/", FilesystemRoot: t.TempDir()}
	if err := h.AddRoot("test", cfg, cs, li); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close with no watchers: %v", err)
	}
}
