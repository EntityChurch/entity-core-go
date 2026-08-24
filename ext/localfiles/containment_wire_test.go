package localfiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.entitychurch.org/entity-core-go/core/handler"
)

// The §8.3 containment audit AT THE HANDLER, not at the helper.
//
// WHY THIS FILE EXISTS SEPARATELY FROM containment_test.go. Those tests call
// `enforceContainment` directly and prove the helper is correct. **That is not
// the same claim as "the operation is safe"**, and the difference is exactly
// where the defect lived in Python: their ELOOP→403 branch existed and was
// correct, and was *unreachable*, because `os.path.exists()` follows symlinks
// and 404'd first. A unit test of their containment helper would have passed
// while `list` returned 200 with an outside directory's contents.
//
// So the question a helper test cannot answer is **ordering**: does the
// operation reach the containment check before anything else short-circuits?
// These drive the handler.
//
// STANDING ITEM. `meta/AGENTS.md` carries this as the ecosystem's one open
// security item — *"a symlinked directory escaping the peer root returned 200
// with the outside directory's contents on `list`. Fixed in py; go and rust
// unaudited — the V4 probe is read-only and structurally cannot see it."*
// Python re-reported it 2026-08-13 after fixing their own, and noted the read
// direction is the milder half: they also found the escaping-directory `list`
// returning outside contents. This is Go's audit. It passes — but it passes
// *now*, and an untested pass is what the Python case was before it broke.
//
// The wire probes cannot cover this: planting a symlink needs filesystem
// access to the peer's root, which a conformance client does not have. That is
// structural, not an oversight, and it is why the guard has to live here.

func TestListRefusesEscapingSymlinkedDirectory(t *testing.T) {
	h, hctx, root := newTestHandler(t)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape-dir")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	// TEETH. A refusal test passes for free if the attack was never possible —
	// a mistyped path or a symlink that silently failed to resolve gives a
	// green run that proves nothing. Assert the filesystem WOULD have served
	// the outside directory through this link, so the only thing standing
	// between the request and `secret.txt` is the containment check under test.
	if entries, rerr := os.ReadDir(link); rerr != nil {
		t.Fatalf("fixture is inert: the escape link does not resolve (%v) — this test would pass without testing anything", rerr)
	} else {
		var found bool
		for _, e := range entries {
			if e.Name() == "secret.txt" {
				found = true
			}
		}
		if !found {
			t.Fatal("fixture is inert: the escape link resolves but does not expose secret.txt — nothing to leak, so a refusal proves nothing")
		}
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "list",
		Context:   withResource(hctx, "local/files/test/escape-dir/"),
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The failure this guards is NOT "wrong status code" — it is the peer
	// serving a directory listing from outside its own root. Assert the
	// contents are absent regardless of how the refusal is spelled, so a
	// future status-code change cannot silently turn this green.
	if resp.Status == 200 {
		if dir, derr := DirectoryDataFromEntity(resp.Result); derr == nil {
			for _, c := range dir.Children {
				if c.Name == "secret.txt" {
					t.Fatalf("SECURITY: list through an escaping symlinked directory returned 200 and leaked %q from outside the root — this is the meta open item, live in Go", c.Name)
				}
			}
		}
		t.Fatalf("list through an escaping symlinked directory returned 200 (want a refusal); §8.3 requires containment at every path-resolving callsite")
	}
	if resp.Status != 403 {
		t.Errorf("escaping symlinked directory refused with %d; §8.3's containment refusal is 403 path_traversal_rejected (a 404 would conflate 'escapes the root' with 'does not exist' — the ordering bug Python hit)", resp.Status)
	}
}

// The deeper form: listing THROUGH the symlinked directory into a subdirectory
// under it. Distinct from the case above because the escaping component is now
// a PARENT rather than the leaf, so a leaf-only defense passes it.
func TestListRefusesPathThroughEscapingSymlinkedDirectory(t *testing.T) {
	h, hctx, root := newTestHandler(t)

	outside := t.TempDir()
	sub := filepath.Join(outside, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape-dir")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "list",
		Context:   withResource(hctx, "local/files/test/escape-dir/sub/"),
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.Status == 200 {
		if dir, derr := DirectoryDataFromEntity(resp.Result); derr == nil {
			for _, c := range dir.Children {
				if c.Name == "secret.txt" {
					t.Fatalf("SECURITY: list THROUGH an escaping symlinked parent returned 200 and leaked %q — a leaf-only defense passes this case", c.Name)
				}
			}
		}
		t.Fatal("list through an escaping symlinked parent returned 200 (want a refusal)")
	}
}

// The read direction, for completeness — the milder half of the same defect,
// and the one the wire probe DOES reach.
func TestReadRefusesEscapingSymlinkedDirectory(t *testing.T) {
	h, hctx, root := newTestHandler(t)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE THE SANDBOX"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape-dir")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	resp, err := h.Handle(context.Background(), &handler.Request{
		Operation: "read",
		Context:   withResource(hctx, "local/files/test/escape-dir/secret.txt"),
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.Status >= 200 && resp.Status < 300 {
		t.Fatalf("SECURITY: read through an escaping symlinked directory returned %d — content outside the root is being served", resp.Status)
	}
}
