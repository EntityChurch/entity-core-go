package validate

// Drift gate for §10.3 of PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY:
// re-derive the core-profile category set from V7 §9.0 (the spec's
// authoritative prose enumeration) and fail if the hand-maintained
// `coreProfileCategories` map in profile.go drifts. Kills F26's
// retroactive-drift risk surfaced in v7.72 cohort review.
//
// Until keystone ships a structured spec-data snapshot (called out in
// the proposal as the long-term machine-readable source), the test
// parses the §9.0 prose: it reads the sibling architecture repo's
// V7 spec, finds the "Runs the core-profile category set:" sentence
// in §9.0, extracts the back-ticked category names, and diffs the set
// against `coreProfileCategories`.
//
// The spec is in a sibling repo (../entity-core-architecture). If it
// isn't checked out — Go-only consumer of this module, vendored
// release tarball, CI without the sibling — the test SKIPs with a
// pointer rather than failing. The hand-maintained map stays the
// source of truth at runtime; this test is a guard against silent
// drift, not a runtime dependency.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// v7SpecPath is the relative path from this package to the V7 spec in
// the sibling architecture repo. Override via ENTITY_CORE_V7_SPEC.
const v7SpecPathRel = "../../../../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/ENTITY-CORE-PROTOCOL-V7.md"

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

type parseErr struct{ msg string }

func (e *parseErr) Error() string { return e.msg }
