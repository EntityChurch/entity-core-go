package localfiles

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestStartWatchingPersistsWatcherState is the teeth for workbench-go row 3:
// watcher liveness must be a TREE FACT any renderer can read, not a Go-API
// affordance only in-process consumers can reach. handleWatch already persisted
// it for the explicit `watch` op; the auto/restart path (StartWatching from
// Load/AddRoot) did not, so a mount whose watcher died read identically to a
// healthy one. StartWatching now persists the state.
//
// Mutation witness: remove the persistWatcherState call in StartWatching and
// the "active" tree fact is absent.
func TestStartWatchingPersistsWatcherState(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), "2KHyyndBo6LW3FigmdHPQdkvscNpngeNS3FAGoRfoMoYwN")
	tmpDir := t.TempDir()

	h := NewHandler(nil)
	if err := h.AddRoot("downloads", RootConfigData{Prefix: "local/files/downloads/", FilesystemRoot: tmpDir}, cs, li); err != nil {
		t.Fatalf("AddRoot: %v", err)
	}
	if err := h.StartWatching(context.Background(), "downloads", cs, li, hash.Hash{}); err != nil {
		t.Fatalf("StartWatching: %v", err)
	}

	wc := readWatcherState(t, cs, li, "downloads")
	if wc.Status != "active" {
		t.Fatalf("watcher state Status = %q, want \"active\" (row 3 — liveness not a tree fact)", wc.Status)
	}
	if wc.RootName != "downloads" {
		t.Fatalf("watcher state RootName = %q, want \"downloads\"", wc.RootName)
	}
}

func readWatcherState(t *testing.T, cs store.ContentStore, li store.LocationIndex, rootName string) WatcherConfigData {
	t.Helper()
	h, ok := li.Get("system/config/local/files/watch/" + rootName)
	if !ok {
		t.Fatalf("no watcher-state binding at watch/%s — watcher liveness is not a tree fact (row 3)", rootName)
	}
	ent, ok := cs.Get(h)
	if !ok {
		t.Fatalf("watcher-state entity %s not in store", h)
	}
	var wc WatcherConfigData
	if err := ecf.Decode(ent.Data, &wc); err != nil {
		t.Fatalf("decode watcher state: %v", err)
	}
	return wc
}
