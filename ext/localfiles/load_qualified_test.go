package localfiles

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
)

// TestLoadRehydratesFromPeerQualifiedPath is the teeth for workbench-go row 10:
// the location index returns PEER-QUALIFIED paths, and Load's old TrimPrefix
// (against the bare configPathPrefix) never matched, so the remainder kept its
// slashes and EVERY root was skipped on restart — mount lists healthy, every
// write 404s, the watcher never restarts. Load now uses relativeUnder, correct
// for both the bare and peer-qualified forms.
//
// Mutation witness: replace the relativeUnder call with the old
// `strings.TrimPrefix(entry.Path, configPathPrefix)` and this test reds (the
// root is not restored).
func TestLoadRehydratesFromPeerQualifiedPath(t *testing.T) {
	cs := store.NewMemoryContentStore()
	// The REAL restart scenario: the handler's index is a NamespacedIndex
	// (as a peer wires it), so a bare Set is stored — and List'd — in the
	// peer-qualified form. This is exactly the shape the old TrimPrefix missed.
	const peer = "2KHyyndBo6LW3FigmdHPQdkvscNpngeNS3FAGoRfoMoYwN"
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), peer)
	tmpDir := t.TempDir()

	cfg := RootConfigData{Prefix: "local/files/downloads/", FilesystemRoot: tmpDir}

	// First lifetime: AddRoot persists the config (at a qualified path via the
	// namespaced index).
	h1 := NewHandler(nil)
	if err := h1.AddRoot("downloads", cfg, cs, li); err != nil {
		t.Fatalf("AddRoot: %v", err)
	}

	// Restart: a fresh handler rehydrates from the same store + index.
	h2 := NewHandler(nil)
	if err := h2.Load(context.Background(), cs, li, hash.Hash{}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	h2.mu.Lock()
	root := h2.findRootMapping("local/files/downloads/probe.txt")
	h2.mu.Unlock()
	if root == nil {
		t.Fatal("Load did not restore the root from a peer-qualified config path (row 10 — every mount dies after restart)")
	}
}

// TestRelativeUnder pins the helper on both path forms.
func TestRelativeUnder(t *testing.T) {
	const prefix = "system/config/local/files/"
	cases := []struct {
		path    string
		wantRel string
		wantOK  bool
	}{
		{"system/config/local/files/downloads", "downloads", true},           // bare
		{"/2KHyy.../system/config/local/files/downloads", "downloads", true}, // peer-qualified
		{"system/config/local/files/watch/x", "watch/x", true},               // under, but nested (caller rejects on "/")
		{"system/other/thing", "", false},                                    // not under
		{"/2KHyy.../system/other/thing", "", false},                          // qualified, not under
	}
	for _, c := range cases {
		rel, ok := relativeUnder(c.path, prefix)
		if ok != c.wantOK || rel != c.wantRel {
			t.Errorf("relativeUnder(%q) = (%q, %v), want (%q, %v)", c.path, rel, ok, c.wantRel, c.wantOK)
		}
	}
}
