package main

// Tests are hermetic: a fixture check-package and a fixture document tree, so
// they assert the tool's behaviour rather than the current state of the specs.
// A test pinned to the live trees would go red the next time arch renumbers a
// section, which trains the next reader to ignore it.
//
// Every resolution class is asserted in BOTH directions — the citation that
// resolves and the one that must not. A resolver that cannot be made to report
// a gap has not been shown to detect one (doctrine 3).

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixturePkg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := `package validate

const catFoo = "foo"
const catBar = "bar"

var coreProfileCategories = map[string]bool{
	catFoo: true,
}

func AllCategories() []string {
	return []string{catFoo, catBar, "ghost"}
}

func runFoo(r *CheckRunner) []CheckResult {
	r := NewCheckRunner(catFoo)
	r.Declare("resolves", "V7 §1.1 — a real section")
	r.DeclareSelf("offline_kat", "V7 §1.1 — never contacts the peer")
	r.Declare("stale_section", "V7 §44.44 — a section that is not there")
	r.Declare("guide_only", "GUIDE-CONFORMANCE §2.4a")
	r.Declare("no_citation", "harness")
	r.Declare(computedName, "V7 §1.1")
	r.Declare("computed_ref", someVar)
	return nil
}

func runBar() []CheckResult {
	r := NewCheckRunner(catBar)
	r.Declare("amendment_ok", "NETWORK Amendment 4 — http-poll")
	r.Declare("amendment_missing", "NETWORK Amendment 99 — not in the document")
	r.Declare("unknown_doc", "COHERENT-CAP §1")
	r.Declare("bare_section", "§2.2 with no document named")
	r.Declare("partial", "V7 §1.1 plus V7 §44.44")
	return nil
}

func helperDeclares(r *CheckRunner) {
	r.Declare("orphan", "V7 §1.1")
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// A test file in the same directory must be ignored: its declarations are
	// not conformance checks.
	if err := os.WriteFile(filepath.Join(dir, "fixture_test.go"), []byte("package validate\n\nfunc x(r *CheckRunner) { r.Declare(\"not_a_check\", \"V7 §1.1\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFixtureDocs(t *testing.T) (proto, arch string) {
	t.Helper()
	root := t.TempDir()
	proto = filepath.Join(root, "proto")
	arch = filepath.Join(root, "arch")

	write := func(path, body string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(proto, "specs", "ENTITY-CORE-PROTOCOL.md"), `# Entity Core Protocol

## 1. Foundations

### 1.1 Entity

Text that cross-references §7.3 without heading it.

### 1.2a Content format
`)
	write(filepath.Join(arch, "specs", "extensions", "EXTENSION-NETWORK.md"), `# Network Extension

## 6. Transport

### 6.5 Substrates

#### 6.5.2c.1 HTTP-substrate conventions (Amendment 4)

## 2. Types

### 2.2 Backoff
`)
	write(filepath.Join(arch, "guides", "GUIDE-CONFORMANCE.md"), `# GUIDE-CONFORMANCE

## §2 Vector authoring

### §2.4a Every check asserts the negative half
`)
	write(filepath.Join(arch, "docs", "proposals", "PROPOSAL-EXAMPLE.md"), "# Proposal\n\n## 1. Scope\n")
	return proto, arch
}

func loadFixture(t *testing.T) (*Extraction, *DocSet) {
	t.Helper()
	pkg := writeFixturePkg(t)
	proto, arch := writeFixtureDocs(t)
	ext, err := Extract(pkg)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	docs, err := LoadDocs(proto, arch)
	if err != nil {
		t.Fatalf("LoadDocs: %v", err)
	}
	for i := range ext.Rows {
		Resolve(&ext.Rows[i], docs)
	}
	return ext, docs
}

func rowByKey(t *testing.T, ext *Extraction, key string) Row {
	t.Helper()
	for _, r := range ext.Rows {
		if r.Key() == key {
			return r
		}
	}
	t.Fatalf("no row %q; have %d rows", key, len(ext.Rows))
	return Row{}
}

func TestExtractReconciles(t *testing.T) {
	ext, _ := loadFixture(t)
	if err := ext.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// 7 in runFoo + 5 in runBar + 1 in the helper. The two in the _test.go
	// file must NOT appear.
	if got, want := len(ext.Rows), 13; got != want {
		t.Errorf("rows = %d, want %d", got, want)
	}
	if ext.DeclareSites != len(ext.Rows) {
		t.Errorf("declare sites %d != rows %d", ext.DeclareSites, len(ext.Rows))
	}
	for _, r := range ext.Rows {
		if r.Check == "not_a_check" {
			t.Error("a declaration in a _test.go file was extracted as a conformance check")
		}
	}
}

// TestReconcileCatchesADrop is the mutation for the reconciliation itself: if
// the extractor ever starts skipping declarations it cannot read, this is what
// notices.
func TestReconcileCatchesADrop(t *testing.T) {
	ext := &Extraction{Rows: []Row{{Category: "a", Check: "b"}}, DeclareSites: 2}
	if err := ext.Reconcile(); err == nil {
		t.Fatal("Reconcile accepted 1 row for 2 declare sites — a dropped declaration would be invisible")
	}
}

func TestSelfCheckAndProfileAreRead(t *testing.T) {
	ext, _ := loadFixture(t)
	self := rowByKey(t, ext, "foo.offline_kat")
	if !self.SelfCheck {
		t.Error("DeclareSelf did not mark the row as a self-check — a run against another peer would count it as peer-attributable")
	}
	if !self.CoreProfile {
		t.Error("coreProfileCategories was not read from source")
	}
	if peer := rowByKey(t, ext, "bar.amendment_ok"); peer.SelfCheck {
		t.Error("Declare marked a row as a self-check")
	} else if peer.CoreProfile {
		t.Error("bar is not in the fixture's core profile")
	}
}

func TestUnattributedDeclarationIsReportedNotGuessed(t *testing.T) {
	ext, _ := loadFixture(t)
	row := rowByKey(t, ext, "?.orphan")
	if row.Category != "" {
		t.Errorf("category = %q; a declaration in a helper must not be attributed by guesswork", row.Category)
	}
	if row.Note == "" {
		t.Error("unattributed row carries no note explaining why")
	}
}

func TestDynamicDeclarationsAreReported(t *testing.T) {
	ext, _ := loadFixture(t)
	var dynamic int
	for _, r := range ext.Rows {
		if r.Verdict == VerdictDynamic {
			dynamic++
			if r.Note == "" {
				t.Errorf("%s is DYNAMIC with no note", r.Key())
			}
		}
	}
	if dynamic != 2 {
		t.Errorf("dynamic rows = %d, want 2 (one computed name, one computed ref)", dynamic)
	}
}

func TestVerdicts(t *testing.T) {
	ext, _ := loadFixture(t)
	for _, tc := range []struct {
		key  string
		want Verdict
	}{
		{"foo.resolves", VerdictResolved},
		{"foo.offline_kat", VerdictResolved},
		{"foo.stale_section", VerdictUnresolved},
		{"foo.guide_only", VerdictNonNormative},
		{"foo.no_citation", VerdictNoCitation},
		{"bar.amendment_ok", VerdictResolved},
		{"bar.amendment_missing", VerdictUnresolved},
		{"bar.unknown_doc", VerdictUnresolved},
		{"bar.bare_section", VerdictUnresolved},
		{"bar.partial", VerdictPartial},
	} {
		if got := rowByKey(t, ext, tc.key).Verdict; got != tc.want {
			t.Errorf("%s: verdict = %s, want %s", tc.key, got, tc.want)
		}
	}
}

func TestSectionHitTiers(t *testing.T) {
	_, docs := loadFixture(t)
	proto, ok := docs.Lookup("V7")
	if !ok {
		t.Fatal("V7 did not resolve to ENTITY-CORE-PROTOCOL")
	}
	for _, tc := range []struct {
		sec  string
		want SectionHit
	}{
		{"1.1", HitHeading},
		{"1.2a", HitHeading},
		{"1.1.4", HitHeadingParent}, // deeper than any heading, parent §1.1 exists
		{"7.3", HitBody},            // cross-referenced in the text, never headed
		{"44.44", HitMissing},
		// THE ESCAPE. §1 is a heading in this document, as §1/§2/§3 are in
		// nearly every document — so a one-component parent must NOT rescue a
		// bogus child. Found by mutating a live citation to `§3.6999` and
		// watching `-check` pass anyway.
		{"1.6999", HitMissing},
	} {
		if got := proto.HasSection(tc.sec); got != tc.want {
			t.Errorf("§%s: hit = %s, want %s", tc.sec, got, tc.want)
		}
	}
}

func TestAliasPrecedenceSpecBeatsGuide(t *testing.T) {
	_, docs := loadFixture(t)
	d, ok := docs.Lookup("NETWORK")
	if !ok {
		t.Fatal("EXTENSION-NETWORK is not reachable as NETWORK")
	}
	if !d.Normative {
		t.Error("a specs/ document must be normative")
	}
	g, ok := docs.Lookup("GUIDE-CONFORMANCE")
	if !ok {
		t.Fatal("GUIDE-CONFORMANCE did not resolve")
	}
	if g.Normative {
		t.Error("a guide must not be classified normative — that is the whole point of the NON_NORMATIVE verdict")
	}
}

// TestAdjacencyKeepsProseOutOfTheFindings pins the rule that a doc-shaped token
// only claims a section directly beside it. Without it, every hyphenated vector
// ID in a message (`TV-RV-2`, `A4-AUTHZ`, `SHA-384`) is reported as a missing
// document and the real gaps drown.
func TestAdjacencyKeepsProseOutOfTheFindings(t *testing.T) {
	_, docs := loadFixture(t)

	punctuated := parseCitations("V7 §1 (AUTHZ-SCOPE-EXCEEDS-1): §1.1 dispatch-level", docs)
	for _, c := range punctuated {
		if c.Status == statusUnknown {
			t.Errorf("a parenthesized vector ID was reported as an unknown document: %+v", c)
		}
		if !c.Resolved() {
			t.Errorf("citation %s did not resolve to V7: %+v", c.Raw, c)
		}
	}

	// ... but a doc-shaped token directly before a section IS a claim, and an
	// unknown one must still be reported.
	adjacent := parseCitations("COHERENT-CAP §1", docs)
	if len(adjacent) != 1 || adjacent[0].Status != statusUnknown {
		t.Errorf("an unknown document cited directly before a section was not reported: %+v", adjacent)
	}
}

func TestMultipleDocumentsInOneRef(t *testing.T) {
	_, docs := loadFixture(t)
	cits := parseCitations("NETWORK §6.5 + V7 §1.1", docs)
	if len(cits) != 2 {
		t.Fatalf("citations = %d, want 2: %+v", len(cits), cits)
	}
	if cits[0].Doc != "NETWORK" || cits[1].Doc != "V7" {
		t.Errorf("sections bound to the wrong documents: %+v", cits)
	}
	for _, c := range cits {
		if !c.Resolved() {
			t.Errorf("%s %s did not resolve", c.Doc, c.Raw)
		}
	}
}

// TestVersionTokenDoesNotStealTheDocument covers the shape `REVISION v1.6 §3.2`
// — a version between the document and its section must not break the binding.
func TestVersionTokenDoesNotStealTheDocument(t *testing.T) {
	_, docs := loadFixture(t)
	cits := parseCitations("NETWORK v1.6 §6.5 keepalive", docs)
	if len(cits) != 1 || !cits[0].Resolved() || cits[0].Doc != "NETWORK" {
		t.Errorf("version token broke the document binding: %+v", cits)
	}
}

func TestCandidatesAreReportedNotApplied(t *testing.T) {
	_, docs := loadFixture(t)
	cits := parseCitations("§6.5 with no document", docs)
	if len(cits) != 1 {
		t.Fatalf("citations = %d, want 1", len(cits))
	}
	c := cits[0]
	if c.Resolved() {
		t.Fatal("an unnamed document resolved anyway — the tool must not pick a candidate for the author")
	}
	if len(c.Candidates) != 1 || c.Candidates[0] != "EXTENSION-NETWORK" {
		t.Errorf("candidates = %v, want [EXTENSION-NETWORK]", c.Candidates)
	}
}

func TestOrphanCategoryIsSurfaced(t *testing.T) {
	pkg := writeFixturePkg(t)
	all, err := AllCategoriesFrom(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !all["ghost"] {
		t.Fatal("AllCategories() was not read")
	}
	ext, err := Extract(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if ext.CategoriesSeen["ghost"] {
		t.Error("a category that declares nothing was recorded as seen")
	}
}

// TestMissingSpecTreeIsAHardError: resolving against an absent spec repo would
// report every citation as unresolved, which reads as 1,100 new findings rather
// than as a missing checkout.
func TestMissingSpecTreeIsAHardError(t *testing.T) {
	proto, arch := writeFixtureDocs(t)
	if _, err := LoadDocs(filepath.Join(proto, "nope"), arch); err == nil {
		t.Fatal("LoadDocs accepted a missing spec root")
	}
}

// --- the adoption boundary ---------------------------------------------------

func TestTierClassification(t *testing.T) {
	_, docs := loadFixture(t)
	for _, tc := range []struct {
		alias string
		want  Tier
	}{
		{"V7", TierCore},                     // entity-core-protocol/specs
		{"EXTENSION-NETWORK", TierExtension}, // arch specs/extensions
		{"GUIDE-CONFORMANCE", TierGuide},
		{"PROPOSAL-EXAMPLE", TierProposal},
	} {
		d, ok := docs.Lookup(tc.alias)
		if !ok {
			t.Errorf("%s did not resolve", tc.alias)
			continue
		}
		if d.Tier != tc.want {
			t.Errorf("%s: tier = %s, want %s", tc.alias, d.Tier, tc.want)
		}
	}
}

// TestOnlyTheCoreFloorIsNonAdoptable pins the distinction the whole tier model
// exists for: a peer may decline every tier except the core floor. If this ever
// flips, an absent extension starts reading as a conformance failure.
func TestOnlyTheCoreFloorIsNonAdoptable(t *testing.T) {
	if TierCore.Adoptable() {
		t.Error("the core floor must not be adoptable — it binds every conforming peer")
	}
	for _, tr := range []Tier{TierExtension, TierDomain, TierSDK, TierSystem, TierApp, TierGuide, TierProposal} {
		if !tr.Adoptable() {
			t.Errorf("%s must be adoptable — a peer that has not adopted it owes nothing to its spec", tr)
		}
	}
}

func TestCrossingIsOnlyReportedForCoreProfile(t *testing.T) {
	_, docs := loadFixture(t)
	ext := Row{CoreProfile: false, SpecRef: "NETWORK §6.5"}
	Resolve(&ext, docs)
	if crossesAdoptionBoundary(ext) {
		t.Error("a non-core-profile check citing an extension is not a boundary crossing — that is just an extension check")
	}
	core := Row{CoreProfile: true, SpecRef: "NETWORK §6.5"}
	Resolve(&core, docs)
	if !crossesAdoptionBoundary(core) {
		t.Error("a core-profile check citing an extension IS a crossing and must be visible")
	}
	floor := Row{CoreProfile: true, SpecRef: "V7 §1.1"}
	Resolve(&floor, docs)
	if crossesAdoptionBoundary(floor) {
		t.Error("a core-profile check citing the core floor is not a crossing")
	}
}

// TestSharedKeysAreNotCollapsed: the extractor cannot name a check whose name is
// built at runtime, so several rows legitimately share one key. The first
// baseline stored a single verdict per key and lost 22 rows — a shared key going
// from {RESOLVED, UNRESOLVED} to {UNRESOLVED, UNRESOLVED} was invisible.
func TestSharedKeysAreNotCollapsed(t *testing.T) {
	reg := &Register{Rows: []Row{
		{Category: "a", Check: "shared", Verdict: VerdictResolved},
		{Category: "a", Check: "shared", Verdict: VerdictUnresolved},
		{Category: "a", Check: "solo", Verdict: VerdictNoCitation},
	}}
	before := reg.findings()
	if before["a.shared"] != "RESOLVED,UNRESOLVED" {
		t.Fatalf("shared key = %q, want the full multiset", before["a.shared"])
	}
	if reg.findingRows() != 2 {
		t.Errorf("findingRows = %d, want 2 — the count must describe declarations, not keys", reg.findingRows())
	}

	// The regression: the resolved twin degrades. Key count is unchanged, so a
	// single-verdict baseline would report no difference at all.
	reg.Rows[0].Verdict = VerdictUnresolved
	after := reg.findings()
	if len(after) != len(before) {
		t.Fatal("key count changed; this test is meant to cover the case where it does not")
	}
	if after["a.shared"] == before["a.shared"] {
		t.Error("a row degrading inside a shared key produced an identical baseline entry — the gate would not see it")
	}
}
