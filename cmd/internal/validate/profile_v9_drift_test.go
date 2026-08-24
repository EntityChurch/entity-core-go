package validate

// Drift gate for §10.3 of PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY:
// re-derive the core-profile category set from V7 §9.0 (the spec's
// authoritative prose enumeration) and fail if the hand-maintained
// `coreProfileCategories` map in profile.go drifts. Kills F26's
// retroactive-drift risk surfaced in v7.72 cohort review.
//
// Until keystone ships a structured spec-data snapshot (called out in
// the proposal as the long-term machine-readable source), the test
// parses the §9.0 prose: it reads the core-protocol spec, finds the
// "Runs the core-profile category set:" sentence in §9.0, extracts the
// back-ticked category names, and diffs the set against
// `coreProfileCategories`.
//
// The spec is in a sibling repo (../entity-core-protocol — the V8 split
// moved the core protocol floor there; the old ../entity-core-architecture
// path pointed at the STALE pre-split repo and this test silently SKIPped
// against it for as long as it did). If it isn't checked out — Go-only
// consumer of this module, vendored release tarball, CI without the sibling
// — the test SKIPs with a pointer rather than failing. The hand-maintained
// map stays the source of truth at runtime; this test is a guard against
// silent drift, not a runtime dependency.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// v7SpecPathRel is the relative path from this package to the core-protocol
// spec in the sibling entity-core-protocol repo (§9.0 lives here post-V8-split).
// Override via ENTITY_CORE_V7_SPEC.
const v7SpecPathRel = "../../../../entity-core-protocol/specs/ENTITY-CORE-PROTOCOL.md"

// TestCoreProfileCategoriesMatchSpec extracts the core-profile category
// set from V7 §9.0 prose and asserts it equals `coreProfileCategories`.
// Drift on either side fails the test; the V7 §9.0 enumeration wins.
func TestCoreProfileCategoriesMatchSpec(t *testing.T) {
	path := os.Getenv("ENTITY_CORE_V7_SPEC")
	if path == "" {
		path = v7SpecPathRel
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Skipf("resolve V7 spec path %q: %v (set ENTITY_CORE_V7_SPEC to override)", path, err)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("V7 spec not found at %s (set ENTITY_CORE_V7_SPEC to override): %v", abs, err)
	}

	specSet, err := parseCoreCategoriesFromV9(string(body))
	if err != nil {
		t.Fatalf("parse §9.0 from spec at %s: %v", abs, err)
	}
	if len(specSet) == 0 {
		t.Fatalf("parsed zero categories from §9.0 at %s — parser broke or §9.0 was restructured", abs)
	}

	mapSet := make(map[string]bool, len(coreProfileCategories))
	for k := range coreProfileCategories {
		mapSet[k] = true
	}

	var missingFromMap, extraInMap []string
	for k := range specSet {
		if !mapSet[k] {
			missingFromMap = append(missingFromMap, k)
		}
	}
	for k := range mapSet {
		if !specSet[k] {
			extraInMap = append(extraInMap, k)
		}
	}
	sort.Strings(missingFromMap)
	sort.Strings(extraInMap)
	if len(missingFromMap) > 0 || len(extraInMap) > 0 {
		t.Fatalf("coreProfileCategories drifted from V7 §9.0:\n  in spec but missing from map: %v\n  in map but not in spec:     %v",
			missingFromMap, extraInMap)
	}
}

// parseCoreCategoriesFromV9 extracts the back-ticked category names from
// the "Runs the core-profile category set:" sentence in V7 §9.0. The
// sentence appears once, immediately after the "Oracle-side contract."
// heading. Parser is intentionally conservative — fails loudly if the
// surrounding prose is restructured, so the drift gate can't silently
// pass against a spec section that moved.
func parseCoreCategoriesFromV9(spec string) (map[string]bool, error) {
	// Bound the search to §9.0 to avoid picking up unrelated back-ticked
	// names elsewhere in the spec.
	start := strings.Index(spec, "### 9.0 Conformance Profiles")
	if start < 0 {
		return nil, &parseErr{"§9.0 heading not found"}
	}
	end := strings.Index(spec[start:], "### 9.1")
	if end < 0 {
		return nil, &parseErr{"§9.1 heading not found (could not bound §9.0)"}
	}
	section := spec[start : start+end]

	// Locate the sentence. It's the prose-level enumeration, distinct
	// from any other back-ticked references in the section.
	sentenceStart := strings.Index(section, "Runs the core-profile category set")
	if sentenceStart < 0 {
		return nil, &parseErr{`"Runs the core-profile category set" sentence not found in §9.0`}
	}
	// Take until the parenthetical close that ends the sentence.
	sentenceEnd := strings.Index(section[sentenceStart:], ")")
	if sentenceEnd < 0 {
		return nil, &parseErr{"could not find end of §9.0 category-set sentence"}
	}
	sentence := section[sentenceStart : sentenceStart+sentenceEnd]

	re := regexp.MustCompile("`([a-z_][a-z0-9_]*)`")
	matches := re.FindAllStringSubmatch(sentence, -1)
	out := make(map[string]bool, len(matches))
	for _, m := range matches {
		out[m[1]] = true
	}
	return out, nil
}

// TestCoreTypeFloorMatchesSpec re-derives the 53-type Core Type Floor from
// V7 §9.5's fenced type blocks and asserts it equals `coreTypeFloor` in
// profile.go. Same guard as the category drift test, one axis over: the
// type floor was hand-maintained with no spec check (S5 guardrail gap), so
// a spec edit to §9.5 or a hand-edit to the map could silently diverge.
func TestCoreTypeFloorMatchesSpec(t *testing.T) {
	path := os.Getenv("ENTITY_CORE_V7_SPEC")
	if path == "" {
		path = v7SpecPathRel
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Skipf("resolve V7 spec path %q: %v (set ENTITY_CORE_V7_SPEC to override)", path, err)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("V7 spec not found at %s (set ENTITY_CORE_V7_SPEC to override): %v", abs, err)
	}

	specSet, err := parseCoreTypeFloorFromV95(string(body))
	if err != nil {
		t.Fatalf("parse §9.5 from spec at %s: %v", abs, err)
	}
	// §9.5 states "Total: 53 types"; the map is the same floor. A count
	// mismatch is drift before the diff even runs.
	if len(specSet) != 53 {
		t.Fatalf("parsed %d types from §9.5 at %s, want 53 — parser broke or §9.5 was restructured", len(specSet), abs)
	}

	var missingFromMap, extraInMap []string
	for k := range specSet {
		if !coreTypeFloor[k] {
			missingFromMap = append(missingFromMap, k)
		}
	}
	for k := range coreTypeFloor {
		if !specSet[k] {
			extraInMap = append(extraInMap, k)
		}
	}
	sort.Strings(missingFromMap)
	sort.Strings(extraInMap)
	if len(missingFromMap) > 0 || len(extraInMap) > 0 {
		t.Fatalf("coreTypeFloor drifted from V7 §9.5:\n  in spec but missing from map: %v\n  in map but not in spec:     %v",
			missingFromMap, extraInMap)
	}
}

// parseCoreTypeFloorFromV95 extracts the type names from the fenced code
// blocks in V7 §9.5 (bounded by the §9.5 and §9.5a headings). The blocks
// contain only whitespace-separated canonical type names; prose back-ticks
// (single) are ignored — only triple-fenced blocks are read.
func parseCoreTypeFloorFromV95(spec string) (map[string]bool, error) {
	start := strings.Index(spec, "### 9.5 Core Type Floor Manifest")
	if start < 0 {
		return nil, &parseErr{"§9.5 heading not found"}
	}
	end := strings.Index(spec[start:], "### 9.5a")
	if end < 0 {
		return nil, &parseErr{"§9.5a heading not found (could not bound §9.5)"}
	}
	section := spec[start : start+end]

	const fence = "```"
	tok := regexp.MustCompile(`^[a-z][a-z0-9/_-]*$`)
	out := make(map[string]bool)
	rest := section
	for {
		i := strings.Index(rest, fence)
		if i < 0 {
			break
		}
		rest = rest[i+len(fence):]
		j := strings.Index(rest, fence)
		if j < 0 {
			return nil, &parseErr{"unterminated code fence in §9.5"}
		}
		block := rest[:j]
		rest = rest[j+len(fence):]
		for _, f := range strings.Fields(block) {
			if tok.MatchString(f) {
				out[f] = true
			}
		}
	}
	return out, nil
}

type parseErr struct{ msg string }

func (e *parseErr) Error() string { return e.msg }
