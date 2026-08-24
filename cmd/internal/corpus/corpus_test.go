package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures, not the real corpora. The registry entries are checked against the
// live spec repo by `corpus-check` in the gate; these tests assert that the
// CONTRACT detects each way a corpus can be wrong, which is a different
// question and must not go red when arch edits a vector.

const fixtureDiag = "[1, 2, 3, \"vector\"]"

func writeCorpus(t *testing.T, dir, name, diag string) Copy {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dp := filepath.Join(dir, name+".diag")
	cp := filepath.Join(dir, name+".cbor")
	if err := os.WriteFile(dp, []byte(diag), 0o644); err != nil {
		t.Fatal(err)
	}
	encoded, _, err := encode(dp)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if err := os.WriteFile(cp, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return Copy{Label: name, Diag: dp, Cbor: cp}
}

func fixtureCorpus(t *testing.T, copies ...Copy) Corpus {
	t.Helper()
	b, err := os.ReadFile(copies[0].Cbor)
	if err != nil {
		t.Fatal(err)
	}
	return Corpus{Name: "fixture", Subject: "test", ExpectedSHA: shaHex(b), Copies: copies}
}

func TestCleanCorpusPasses(t *testing.T) {
	dir := t.TempDir()
	c := fixtureCorpus(t, writeCorpus(t, dir, "a", fixtureDiag))
	res, err := c.Check()
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("clean corpus reported failures: %v", res.Failures)
	}
	if res.Vectors != 4 {
		t.Errorf("vectors = %d, want 4", res.Vectors)
	}
}

// TestDriftIsCaught is the whole reason the package exists: the artifact stops
// being what the source produces. This is the assertion the ecf-conformance
// corpus did not have, and the one whose absence hid the F16 divergence for two
// months on the other corpus.
func TestDriftIsCaught(t *testing.T) {
	dir := t.TempDir()
	cp := writeCorpus(t, dir, "a", fixtureDiag)
	c := fixtureCorpus(t, cp)

	// The SOURCE moves and the artifact does not — the real-world direction:
	// someone edits a vector and forgets to rebuild.
	if err := os.WriteFile(cp.Diag, []byte("[1, 2, 3, \"vector\", 99]"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := c.Check()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("source moved away from the artifact and Check() passed — this is exactly the defect the package exists to catch")
	}
	joined := strings.Join(res.Failures, " ")
	if !strings.Contains(joined, "DRIFT") {
		t.Errorf("failure does not name the drift: %v", res.Failures)
	}
	// The message must carry BOTH digests, or a reader cannot tell which side
	// moved — which is the decision the June regeneration skipped.
	if !strings.Contains(joined, res.OnDisk["a"]) || !strings.Contains(joined, res.Encoded["a"]) {
		t.Errorf("failure does not name both the committed and the re-encoded sha: %v", res.Failures)
	}
}

// TestArtifactChangeIsCaught covers the other direction — the artifact is
// replaced (or corrupted) while the source is untouched. Source-produces-
// artifact alone would not see a change that the source happens to reproduce,
// so the pinned sha is not redundant with it.
func TestArtifactChangeIsCaught(t *testing.T) {
	dir := t.TempDir()
	cp := writeCorpus(t, dir, "a", fixtureDiag)
	c := fixtureCorpus(t, cp)
	c.ExpectedSHA = strings.Repeat("0", 64) // a pin nothing matches

	res, err := c.Check()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("committed artifact did not match the pinned sha and Check() passed")
	}
	if !strings.Contains(strings.Join(res.Failures, " "), "pinned") {
		t.Errorf("failure does not name the pin: %v", res.Failures)
	}
}

// TestCopyDivergenceIsCaught is the arch 3042bd8 invariant: where a corpus has
// two committed copies they must encode identically. It is asserted on the
// ENCODED bytes, so a de-versioning edit to an encoded field (id, description)
// is caught even when both artifacts still match their own sources.
func TestCopyDivergenceIsCaught(t *testing.T) {
	dir := t.TempDir()
	a := writeCorpus(t, filepath.Join(dir, "a"), "x", fixtureDiag)
	b := writeCorpus(t, filepath.Join(dir, "b"), "x", "[1, 2, 3, \"DIFFERENT\"]")
	c := fixtureCorpus(t, a, b)

	res, err := c.Check()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("two copies encoding to different bytes passed the byte-identity invariant")
	}
	if !strings.Contains(strings.Join(res.Failures, " "), "diverged in ENCODED content") {
		t.Errorf("failure does not explain the divergence: %v", res.Failures)
	}
}

// TestAbsentSpecRepoIsDistinctFromFailure: an uncloned sibling must not read as
// a corpus defect, and must not read as a pass either.
func TestAbsentSpecRepoIsDistinct(t *testing.T) {
	c := Corpus{Name: "gone", Copies: []Copy{{"a", "/nonexistent/x.diag", "/nonexistent/x.cbor"}}}
	if _, err := c.Check(); err == nil {
		t.Fatal("absent corpus returned no error")
	} else if !strings.Contains(err.Error(), ErrAbsent.Error()) {
		t.Errorf("absent corpus did not report ErrAbsent: %v", err)
	}
}

// TestCheckWritesNothing — a gate that can rewrite what it checks turns a drift
// into a pass. Assert it by mtime and content, not by reading the code.
func TestCheckWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cp := writeCorpus(t, dir, "a", fixtureDiag)
	c := fixtureCorpus(t, cp)
	if err := os.WriteFile(cp.Diag, []byte("[1, 2, 3, \"vector\", 99]"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cp.Cbor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cp.Cbor)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Check() rewrote the artifact it was checking")
	}
}

// TestRegistryIsWellFormed guards the registry itself: every corpus needs a
// name, a pin, and at least one copy, and the pin has to be a sha256. A
// registry entry with an empty ExpectedSHA would silently skip the
// artifact-is-expected half.
func TestRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if c.Name == "" || c.Subject == "" {
			t.Errorf("corpus %+v is missing a name or subject", c)
		}
		if seen[c.Name] {
			t.Errorf("duplicate corpus name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Copies) == 0 {
			t.Errorf("%s has no copies", c.Name)
		}
		if len(c.ExpectedSHA) != 64 {
			t.Errorf("%s: ExpectedSHA is not a sha256 (%q) — the artifact-is-expected half would not run", c.Name, c.ExpectedSHA)
		}
		for _, cp := range c.Copies {
			if !strings.HasSuffix(cp.Diag, ".diag") || !strings.HasSuffix(cp.Cbor, ".cbor") {
				t.Errorf("%s/%s: source must be .diag and artifact .cbor", c.Name, cp.Label)
			}
		}
	}
	if len(All()) < 2 {
		t.Error("the registry has fewer than two corpora — ecf-conformance was added precisely because a one-corpus registry is a process, not a contract")
	}
}
