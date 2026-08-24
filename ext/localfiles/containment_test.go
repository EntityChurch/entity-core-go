package localfiles

import (
	"os"
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/store"
)

// TestEnforceContainmentRejectsSymlinkedParentDirectory is the regression test
// for the watcher's half-applied §8.3 defense.
//
// The watcher's debounce-flush ingest — one of the six callsites
// DOMAIN-LOCAL-FILES §8.3 binds BY NAME — used to Lstat the leaf and nothing
// else. That refuses a symlinked FILE and passes a symlinked PARENT DIRECTORY
// straight through: a file sitting under a planted directory symlink Lstats as
// an ordinary file, so the watcher would ingest content from outside the root
// into the content store and the tree and propagate it cross-peer.
//
// This case is deliberately NOT reachable from the wire probes in
// cmd/internal/validate (V4/V4a-c drive read/write/list/delete). The watcher
// ingest has no request to send at it, which is exactly why the gap survived:
// the shared probe is read-only and structurally cannot see it.
func TestEnforceContainmentRejectsSymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// A real file outside the root, reached through a directory symlink
	// planted INSIDE it. The leaf itself is an ordinary file — that is the
	// whole point.
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "escape-dir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}

	escaping := filepath.Join(linkDir, "secret.txt")
	if info, err := os.Lstat(escaping); err != nil {
		t.Fatalf("fixture: %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixture is wrong: the LEAF must be an ordinary file, or this test would pass under a leaf-only defense and prove nothing")
	}

	if err := enforceContainment(rm, escaping, "escape-dir/secret.txt"); err == nil {
		t.Fatal("enforceContainment accepted a path under a symlinked parent directory — content outside the root would be ingested and propagated cross-peer (§8.3 requires BOTH defenses at every callsite)")
	}
}

// TestEnforceContainmentRejectsLeafSymlink pins the other half at the same
// entry point, so both defenses are covered where they now live.
func TestEnforceContainmentRejectsLeafSymlink(t *testing.T) {
	root := t.TempDir()
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}
	if err := enforceContainment(rm, link, "escape.txt"); err == nil {
		t.Fatal("enforceContainment accepted a leaf symlink escaping the root")
	}
}

// TestEnforceContainmentAcceptsOrdinaryPaths guards the other direction: a
// containment check that refuses everything is not a containment check, and
// would take the whole local-files surface down with it.
func TestEnforceContainmentAcceptsOrdinaryPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "sub", "present.txt")
	if err := os.WriteFile(existing, []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}

	for _, tc := range []struct{ name, path string }{
		{"existing file", existing},
		// Writes legitimately target a file that does not exist yet.
		{"not-yet-existing file", filepath.Join(root, "sub", "future.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := enforceContainment(rm, tc.path, tc.name); err != nil {
				t.Fatalf("enforceContainment refused an ordinary in-root path: %v", err)
			}
		})
	}
}

// TestWatcherFlushRefusesSymlinkedParentDirectory drives the actual watcher
// ingest, not just the helper it calls.
//
// The previous test proves enforceContainment implements both defenses; this
// one proves the WATCHER applies it, which is the part that was broken. flush()
// is driven directly with a pending event rather than through fsnotify — the
// defect is in what flush does with a path, not in how the path arrived, and a
// real event would make the test depend on inotify timing.
func TestWatcherFlushRefusesSymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape-dir")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	w, err := newWatcher(rm, 1, cs, li, nil, nil)
	if err != nil {
		t.Skipf("cannot create watcher on this platform: %v", err)
	}
	defer w.Stop()

	// Queue the escaping path exactly as a create event would, then flush.
	relPath := filepath.Join("escape-dir", "secret.txt")
	w.mu.Lock()
	w.pending[relPath] = fsCreated
	w.mu.Unlock()
	w.flush()

	treePath := rm.Prefix + filepath.ToSlash(relPath)
	if _, ok := li.Get(treePath); ok {
		t.Fatalf("watcher ingested %q through a symlinked parent directory — content from outside the root is now bound in the tree and will propagate cross-peer", treePath)
	}
}

// TestEnforceContainmentRejectsPrefixSharingSibling pins the containment
// comparison to PATH COMPONENTS rather than to the raw string.
//
// Conformance vector: LF-CONTAIN-BOUNDARY-1 (DOMAIN-LOCAL-FILES §8.3, added
// 2026-08-11). Arch accepted the routing and took the defect: §8.3's own
// pseudocode read "if not canonical starts with canonicalize(root)" — a raw
// string prefix test — so strings.HasPrefix was that spec implemented
// faithfully. §8.3 is now invariant-first, its defenses explicitly NOT a
// closed list, and "V4a green is not containment audited" is normative.
//
// The check was `strings.HasPrefix(resolvedPath, canonical)`, which matches
// mid-component: root "/srv/peerroot" string-contains "/srv/peerroot-backup".
// This vector satisfies BOTH existing defenses on purpose — every component
// resolves cleanly and the leaf is an ordinary file — so neither the
// symlinked-parent test nor the leaf-symlink test can see it. Sibling
// directories that extend a root's name are ordinary in deployments
// (`-backup`, `.old`, `2`), which is what makes it reachable rather than
// theoretical.
func TestEnforceContainmentRejectsPrefixSharingSibling(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "peerroot")
	sibling := filepath.Join(base, "peerroot-backup")
	for _, d := range []string{root, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(sibling, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}

	escaping := filepath.Join(link, "secret.txt")
	if info, err := os.Lstat(escaping); err != nil {
		t.Fatalf("fixture: %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixture is wrong: the LEAF must be an ordinary file, or a leaf-only defense would pass this and prove nothing")
	}

	if err := enforceContainment(rm, escaping, "link/secret.txt"); err == nil {
		t.Fatal("enforceContainment accepted a path resolving into a prefix-sharing sibling of the root — the string prefix matched mid-component")
	}
}

// TestEnforceContainmentRejectsPrefixSharingTraversal is the same boundary
// without a symlink: a bare `..` join into the prefix-sharing sibling.
// enforceContainment is the defense-in-depth layer and must reject it on its
// own, regardless of what upstream path validation also rejects.
func TestEnforceContainmentRejectsPrefixSharingTraversal(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "peerroot")
	sibling := filepath.Join(base, "peerroot-backup")
	for _, d := range []string{root, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}

	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}
	fsPath := filepath.Join(root, "../peerroot-backup/secret.txt")
	if err := enforceContainment(rm, fsPath, "../peerroot-backup/secret.txt"); err == nil {
		t.Fatalf("enforceContainment accepted %q, which resolves outside root %q", fsPath, root)
	}
}

// TestEnforceContainmentAcceptsRootItself guards the boundary fix from
// over-correcting: the root directory itself is contained, and a separator
// requirement that refuses it would break `list` on the root.
func TestEnforceContainmentAcceptsRootItself(t *testing.T) {
	root := t.TempDir()
	rm := &RootMapping{Name: "test", Prefix: "local/files/test/", FSRoot: root}
	if err := enforceContainment(rm, root, ""); err != nil {
		t.Fatalf("enforceContainment refused the root itself: %v", err)
	}
}
