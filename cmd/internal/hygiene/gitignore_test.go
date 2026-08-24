// Package hygiene holds tree-hygiene invariants that are cheap to state and
// have already cost the repo something when left to discipline.
package hygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestGitignoreCoversEveryCommand asserts that every main package under cmd/
// has a matching root-anchored .gitignore entry.
//
// `go build ./cmd/...` without -o writes each main package's binary to the
// working directory, so a missing entry shows up as a multi-MB untracked binary
// at the repo root — and, if someone runs `git add -A`, as a multi-MB binary in
// the history. That is not hypothetical: `webrtc-vectors`, 4.5 MB of compiled
// ELF, was committed at f4c908d and lived in the tree until 2026-08-09.
//
// The .gitignore comment already said "ADD A LINE WHEN YOU ADD A cmd/ — this
// list drifted behind cmd/ twice." It had drifted a third time when this test
// was written, by four entries, one of which was added the same day by the
// person who then went looking for why the list drifts. A hand-maintained list
// that must be updated in lockstep with a directory is not a discipline
// problem; it is a missing check. This is the check.
func TestGitignoreCoversEveryCommand(t *testing.T) {
	root := repoRoot(t)

	ignored := rootAnchoredEntries(t, filepath.Join(root, ".gitignore"))
	var missing []string
	for _, name := range commandBinaryNames(t, filepath.Join(root, "cmd")) {
		if !ignored[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("main packages under cmd/ with no .gitignore entry: %s\n"+
			"`go build ./cmd/...` drops each of these at the repo root. Add one line per name:\n  /%s",
			strings.Join(missing, ", "), strings.Join(missing, "\n  /"))
	}
}

// TestGitignoreHasNoStaleCommandEntries is the other direction. A stale entry
// is harmless at runtime but it is how the list stops being readable as an
// inventory — and an unreadable list is what let four real entries go missing
// behind two dead ones.
func TestGitignoreHasNoStaleCommandEntries(t *testing.T) {
	root := repoRoot(t)

	built := map[string]bool{}
	for _, name := range commandBinaryNames(t, filepath.Join(root, "cmd")) {
		built[name] = true
	}
	// Names ignored for reasons other than "cmd/ builds it here". Keep this
	// list short and justified; it is an escape hatch, not a parking lot.
	allowed := map[string]bool{}

	var stale []string
	for name := range rootAnchoredEntries(t, filepath.Join(root, ".gitignore")) {
		if !built[name] && !allowed[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("root-anchored .gitignore entries with no matching main package under cmd/: %s\n"+
			"Either the command was removed and the line should go, or it belongs in the allowed set with a reason.",
			strings.Join(stale, ", "))
	}
}

// commandBinaryNames returns the binary name `go build` would emit for every
// main package under cmd/, at any depth — cmd/internal/* mains build to the
// root too, which is how three of the four missing entries got missed.
func commandBinaryNames(t *testing.T, cmdDir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(cmdDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !regexp.MustCompile(`(?m)^package main\b`).Match(src) {
			return nil
		}
		// go build names the binary after the package DIRECTORY, not the file.
		names = append(names, filepath.Base(filepath.Dir(path)))
		return nil
	})
	if err != nil {
		t.Fatalf("walk cmd/: %v", err)
	}
	sort.Strings(names)
	return dedup(names)
}

var rootAnchored = regexp.MustCompile(`(?m)^/([A-Za-z0-9._-]+)\s*$`)

func rootAnchoredEntries(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	out := map[string]bool{}
	for _, m := range rootAnchored.FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("no root-anchored entries parsed from .gitignore — the test's own parser is broken, " +
			"which would make it pass vacuously")
	}
	return out
}

// repoRoot walks up from the test's working directory to the go.work that
// defines this multi-module layout.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repo root (no go.work found walking up)")
	return ""
}

func dedup(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
