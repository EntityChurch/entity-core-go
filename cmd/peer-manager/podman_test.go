package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// planImageBuild is the source-provenance decision at the heart of the
// stale-image fix: the whole point is that a plain cached `make build` can hand
// back a stale image, so peer-manager must decide from git provenance whether to
// skip, build normally, or force a cache-busting rebuild.
func TestPlanImageBuild(t *testing.T) {
	tests := []struct {
		name         string
		sha          string
		dirty        bool
		forceEnv     bool
		srcTagExists bool
		latestExists bool
		want         buildPlan
	}{
		{
			// The silent-stale case this fix exists for: an image is present but
			// was built from a different commit, so its layer cache is suspect.
			name: "image predates HEAD -> force no-cache",
			sha:  "abc123", latestExists: true,
			want: buildPlan{noCache: true, reason: "existing image predates abc123"},
		},
		{
			name: "exact source already built -> skip",
			sha:  "abc123", srcTagExists: true, latestExists: true,
			want: buildPlan{skip: true, reason: "already built from abc123"},
		},
		{
			name: "no image at all -> plain build (cold cache cannot be stale)",
			sha:  "abc123",
			want: buildPlan{reason: "first build at abc123"},
		},
		{
			// Uncommitted changes (e.g. the 2026-07-30 Rust seed-policy fix before
			// it was committed) cannot be represented by a commit tag, so never
			// trust the cache.
			name: "dirty tree -> force no-cache",
			sha:  "abc123", dirty: true, srcTagExists: false, latestExists: true,
			want: buildPlan{noCache: true, reason: "working tree dirty at abc123"},
		},
		{
			name: "explicit override -> force no-cache even when a src tag exists",
			sha:  "abc123", forceEnv: true, srcTagExists: true, latestExists: true,
			want: buildPlan{noCache: true, reason: "ENTITY_PM_NO_CACHE set"},
		},
		{
			name: "no git provenance -> old build-and-trust behavior",
			sha:  "", latestExists: true,
			want: buildPlan{reason: "no git provenance"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := planImageBuild(tc.sha, tc.dirty, tc.forceEnv, tc.srcTagExists, tc.latestExists)
			if got != tc.want {
				t.Fatalf("planImageBuild = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A source change with an image already present MUST NOT skip and MUST bust the
// cache — the exact regression that let a 36 h-old image serve fixed code.
func TestPlanImageBuild_SourceChangeNeverSkipsOrTrustsCache(t *testing.T) {
	got := planImageBuild("newcommit", false, false, false /*no src tag for HEAD*/, true /*old image present*/)
	if got.skip {
		t.Fatal("planned to skip the build despite the source having moved past the built image")
	}
	if !got.noCache {
		t.Fatal("planned a cache-trusting build despite a source change — this is the silent-stale bug")
	}
}

// gitStamp is the trigger for the dirty->force-no-cache branch (the
// uncommitted-fix scenario). Exercise it against a throwaway repo so the dirty
// detection is proven without touching any real sibling tree.
func TestGitStamp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// Not a repo yet -> no provenance.
	if sha, dirty := gitStamp(dir); sha != "" || dirty {
		t.Fatalf("non-repo: got (%q,%v), want (\"\",false)", sha, dirty)
	}

	run("init")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f")
	run("commit", "-m", "one")

	// Clean, committed tree -> a sha and NOT dirty.
	sha, dirty := gitStamp(dir)
	if sha == "" || dirty {
		t.Fatalf("clean tree: got (%q,%v), want (non-empty,false)", sha, dirty)
	}

	// An untracked file makes it dirty (the seed-policy-uncommitted case).
	if err := os.WriteFile(filepath.Join(dir, "g"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sha2, dirty2 := gitStamp(dir); sha2 != sha || !dirty2 {
		t.Fatalf("dirty tree: got (%q,%v), want (%q,true)", sha2, dirty2, sha)
	}
}
