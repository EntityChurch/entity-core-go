package hygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The versioning invariants for this repo, made checkable.
//
// WHY THIS EXISTS. On 2026-08-23 a release-coordination pass wrote
// `## [0.8.2]` into this repo's CHANGELOG. 0.8.2 is `entity-core-protocol`'s
// version — the SPEC repo's own release number — and it is not ours. The edit
// was reverted, but nothing in the tree would have caught it, and nothing in
// the tree said what our number IS. That absence is why the question had to be
// asked from outside the repo. These two tests are the answer, enforced.
//
// THE SCHEME, in one paragraph ([ADR-0002], accepted ecosystem-wide
// 2026-06-16). This repo versions on **3-field SemVer**, its own, forward-only
// from the published `v0.8.0`. The spec / conformance level it targets is
// carried **out-of-band** — never as a 4th digit, never by adopting a sibling's
// number. ADR-0002's stated reason is exactly the mistake above: a version that
// encodes the spec level "conflates two genuinely different things: which spec
// level an implementation targets vs the implementation's own release." Our
// out-of-band anchor is already in the tree and has been since v0.8.0: the
// protocol level is spelled `V7` / `v7.NN` at every claim site (README §Overview,
// the `--profile core` note, the flag help, the conformance headline in
// docs/STATUS.md), and the conformance number is published as
// `N · 0F · 0S · 0W @ <commit>` per [ADR-0012]. Three distinct numbers, three
// distinct jobs: **0.y.z** is go's release, **v7.NN** is the spec revision we
// implement, **N·0F** is what we measured.
//
// GO MAKES THIS BINDING, NOT ADVISORY. These are Go modules published under a
// vanity domain. The module resolver parses `vMAJOR.MINOR.PATCH` out of the tag
// and nothing else: a 4th field is not a valid module version, so encoding the
// spec level in the version is not merely inadvisable here — the toolchain
// rejects it. And a consumer resolving `.../cmd@vX` reads that module's own
// `require` lines while IGNORING its `replace` directives, so an intra-repo
// require left at the previous release publishes a `cmd` that builds against a
// stale `core`. The requires are therefore part of the cut, not a follow-up.

// semVer3 is the only version shape this project may cut. Three fields, no
// pre-release/build suffix — we have never needed one and admitting the syntax
// admits the 4th-digit shape ADR-0002 rejects.
var semVer3 = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// changelogHeading matches a released `## [X.Y.Z] — date` heading. `[Unreleased]`
// deliberately does not match: it is not a cut.
var changelogHeading = regexp.MustCompile(`(?m)^##\s+\[([^\]]+)\]`)

// TestChangelogVersionsAreThreeFieldSemVer pins the SHAPE of every release
// number this repo has cut.
//
// The failure it exists for is a 4th digit — `0.8.2.1`, `0.8.0-v7.77` — which is
// how a spec/conformance level gets smuggled into a version. ADR-0002 rejected
// that explicitly and the Go module resolver rejects it mechanically; this test
// is the third and earliest of the three refusals.
func TestChangelogVersionsAreThreeFieldSemVer(t *testing.T) {
	root := repoRoot(t)
	versions, sawUnreleased := changelogVersions(t, filepath.Join(root, "CHANGELOG.md"))

	if !sawUnreleased {
		t.Error("CHANGELOG.md has no `## [Unreleased]` heading — the Keep a Changelog " +
			"format the file declares requires one, and its absence is how in-flight " +
			"work gets written under a release heading that was never cut")
	}
	if len(versions) == 0 {
		t.Fatal("no released `## [X.Y.Z]` headings parsed from CHANGELOG.md — the test's " +
			"own parser is broken, which would make every assertion below vacuous")
	}
	for _, v := range versions {
		if !semVer3.MatchString(v) {
			t.Errorf("CHANGELOG.md release heading `## [%s]` is not 3-field SemVer.\n"+
				"[ADR-0002] cuts this project on 3-field SemVer and carries the spec/conformance "+
				"level OUT-OF-BAND — never as a 4th digit, never by adopting the protocol repo's "+
				"number. Go agrees mechanically: `v%s` is not a resolvable module version.", v, v)
		}
	}
}

// TestModuleRequiresMatchTheLatestRelease is the lockstep gate.
//
// Every in-tree declaration of this project's own module version must equal the
// newest CHANGELOG release heading. Two failures live here and they are not the
// same:
//
//   - A CUT that did not bump the modules. `ext` and `cmd` still `require core
//     v<previous>`. Locally invisible — the sibling-path `replace` short-circuits
//     resolution — and broken for every external consumer, who gets the requires
//     without the replaces and so builds the new `cmd` against the old `core`.
//   - A FOREIGN number written into the CHANGELOG. This is the 2026-08-23 case:
//     `## [0.8.2]` is well-formed SemVer, so the shape test above passes it. It
//     fails HERE, because the modules say 0.8.0 and nothing in this repo ever
//     decided to move to 0.8.2. A number this repo did not choose cannot arrive
//     silently.
//
// Both are one edit. The message names every file.
func TestModuleRequiresMatchTheLatestRelease(t *testing.T) {
	root := repoRoot(t)

	versions, _ := changelogVersions(t, filepath.Join(root, "CHANGELOG.md"))
	if len(versions) == 0 {
		t.Fatal("no released `## [X.Y.Z]` headings parsed from CHANGELOG.md — parser broken")
	}
	// Keep a Changelog is newest-first, so the first heading is the current release.
	want := versions[0]

	sites := ownModuleVersionSites(t, root)
	if len(sites) == 0 {
		t.Fatal("no `go.entitychurch.org/entity-core-go/... vX.Y.Z` declarations found — " +
			"the test's own scanner is broken, which would make this pass vacuously")
	}

	var wrong []string
	for _, s := range sites {
		if s.version != want {
			wrong = append(wrong, s.String())
		}
	}
	if len(wrong) > 0 {
		sort.Strings(wrong)
		t.Errorf("CHANGELOG.md's newest release is %s, but these declare a different version:\n  %s\n\n"+
			"Cutting a release is ONE edit across every site — the CHANGELOG heading, the intra-repo\n"+
			"`require`/`replace` lines in ext/go.mod and cmd/go.mod, and the README module example.\n"+
			"A `replace` hides a stale `require` from us and from nobody else: an external consumer\n"+
			"resolves `.../cmd@v%s` and gets its requires WITHOUT its replaces, so a `cmd` cut at %s\n"+
			"that still requires an older `core` publishes a build nobody outside this workspace can\n"+
			"reproduce.\n\n"+
			"If you got here because a version arrived from outside this repo: it does not belong here\n"+
			"unless this repo chose it. Per [ADR-0002] our version is our OWN 3-field SemVer, forward-only\n"+
			"from the published v0.8.0; the protocol level we target rides out-of-band as `v7.NN`, and\n"+
			"`entity-core-protocol`'s release number is that repo's, not ours.",
			want, strings.Join(wrong, "\n  "), want, want)
	}
}

type moduleVersionSite struct {
	file    string
	line    int
	module  string
	version string
}

func (s moduleVersionSite) String() string {
	return s.file + ":" + strconv.Itoa(s.line) + " — " + s.module + " v" + s.version
}

// ownModuleVersionFiles is the closed set of files that may declare this
// project's own module version. It is short on purpose: a version declaration
// that is not in this list is a version nobody will remember to bump.
var ownModuleVersionFiles = []string{
	"README.md",
	"ext/go.mod",
	"cmd/go.mod",
}

var ownModuleRef = regexp.MustCompile(`go\.entitychurch\.org/entity-core-go/(core|ext|cmd)\s+v(\d+\.\d+\.\d+)`)

func ownModuleVersionSites(t *testing.T, root string) []moduleVersionSite {
	t.Helper()
	var out []moduleVersionSite
	for _, rel := range ownModuleVersionFiles {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			for _, m := range ownModuleRef.FindAllStringSubmatch(line, -1) {
				out = append(out, moduleVersionSite{
					file: rel, line: i + 1, module: m[1], version: m[2],
				})
			}
		}
	}
	return out
}

// changelogVersions returns the released version strings in file order (newest
// first, per Keep a Changelog) and whether an `[Unreleased]` heading is present.
func changelogVersions(t *testing.T, path string) (versions []string, sawUnreleased bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	for _, m := range changelogHeading.FindAllStringSubmatch(string(raw), -1) {
		label := strings.TrimSpace(m[1])
		if strings.EqualFold(label, "Unreleased") {
			sawUnreleased = true
			continue
		}
		versions = append(versions, strings.TrimPrefix(label, "v"))
	}
	return versions, sawUnreleased
}
