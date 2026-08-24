package main

// The anti-vacuity guards — gates, not decoration.
//
// GUIDE-CONFORMANCE §7c.4(2): "The anti-vacuity guards travel WITH the corpus —
// as gates, not decoration. Port the five verbatim... A corpus that cannot meet
// them is vacuous — the ECF-F30 / F-D3 'green-can-be-empty' lesson. Add one
// guard the intra-Go harness didn't need: every cross-impl vector MUST exercise
// the alternate engine on each side, never a fallback to the reference — else
// the cross-impl agreement is circular too."
//
// The failure mode these exist for is not a wrong answer. It is a GREEN run
// that proves nothing: a sweep that agreed about 300 error cases, or two
// engines that agreed because one of them silently was the other. Three
// instances of that already exist in this track's history (F-D3 compared two
// dead grids; ECF F30's tag_reject vectors rejected for the wrong reason).
//
// So the guards run as a gate on the emission, and a failing guard is a FAILED
// run — not a warning printed under a passing summary.

import (
	"fmt"
	"sort"
	"strings"
)

// guardResult is one guard's verdict.
type guardResult struct {
	name   string
	passed bool
	detail string
}

// guardReport is the full gate outcome.
type guardReport struct {
	results []guardResult
}

func (r *guardReport) add(name string, passed bool, format string, args ...interface{}) {
	r.results = append(r.results, guardResult{
		name:   name,
		passed: passed,
		detail: fmt.Sprintf(format, args...),
	})
}

// Failed reports whether any guard failed.
func (r *guardReport) Failed() bool {
	for _, g := range r.results {
		if !g.passed {
			return true
		}
	}
	return false
}

func (r *guardReport) String() string {
	var sb strings.Builder
	for _, g := range r.results {
		mark := "PASS"
		if !g.passed {
			mark = "FAIL"
		}
		fmt.Fprintf(&sb, "  [%s] %-28s %s\n", mark, g.name, g.detail)
	}
	return sb.String()
}

// requireAlternate selects whether guard 6 is enforced. It is off for a
// fixture-building run (core-go's Stage-1 emission, which is legitimately the
// reference) and on for an AE-1 admission run.
func runGuards(c *Corpus, em *Emission, requireAlternate bool) *guardReport {
	r := &guardReport{}

	total := len(c.Vectors)
	var valueOutcomes, errorOutcomes int
	codes := map[string]int{}
	byID := make(map[string]Outcome, len(em.Results))
	for id, o := range em.Results {
		byID[id] = o
		if o.Kind == OutcomeError {
			errorOutcomes++
			codes[o.Code]++
		} else {
			valueOutcomes++
		}
	}

	// Guard 0 — coverage. Not one of the five, but the five are all ratios and
	// a ratio over a partial run is a lie. §3.1(2): a skip counts as a failure.
	missing := total - len(em.Results)
	r.add("coverage", missing == 0 && len(em.Skipped) == 0,
		"%d/%d vectors answered, %d skipped", len(em.Results), total, len(em.Skipped))

	// Guard 1 — at least 25% non-error outcomes. Below that, the corpus is
	// mostly agreeing about error strings and the generator is producing
	// garbage rather than programs.
	minValues := total / 4
	r.add("value-outcomes>=25%", valueOutcomes >= minValues,
		"%d non-error / %d error of %d (floor %d)", valueOutcomes, errorOutcomes, total, minValues)

	// Guard 2 — at least one error outcome. Error-as-value propagation is part
	// of the contract, not a failure of the corpus to be well-formed.
	r.add("error-outcomes>=1", errorOutcomes >= 1,
		"%d error outcomes", errorOutcomes)

	// Guard 3 — at least one closure actually built.
	//
	// The workbench original reads this off engine instrumentation
	// (Stats().Closures). There is no equivalent counter on Stage-1, and adding
	// one would mean instrumenting ext/compute for the benefit of a test
	// harness. So the guard is restated as a property of the ARTIFACT plus the
	// emission: at least one vector tagged `closure` must have produced a
	// NON-ERROR outcome.
	//
	// This is deliberately the weaker form and worth naming as such: it proves a
	// map/filter/fold vector ran to completion, which cannot happen without the
	// closure being constructed and invoked, but it does not count closures. It
	// is also the stronger form in one respect — it is checkable by every impl
	// from the artifact alone, with no engine instrumentation to port. The tag
	// requirement is what makes it non-vacuous: a vector that errors before
	// reaching the lambda does not satisfy it.
	closureRan := 0
	for _, v := range c.Vectors {
		if !hasTag(v.Requires, "closure") {
			continue
		}
		if o, ok := byID[v.ID]; ok && o.Kind != OutcomeError {
			closureRan++
		}
	}
	r.add("closures-exercised>=1", closureRan >= 1,
		"%d closure-tagged vectors completed without error", closureRan)

	// Guard 4 — zero fallbacks. A fallback compares an engine to itself.
	r.add("fallbacks==0", em.Fallbacks == 0,
		"%d fallbacks reported by %s/%s", em.Fallbacks, em.Impl, em.Engine)

	// Guard 5 — at least three distinct error codes. One code repeated 140
	// times means the error surface is covered on paper only.
	r.add("distinct-error-codes>=3", len(codes) >= 3,
		"%d distinct: %s", len(codes), formatCodes(codes))

	// Guard 6 (§7c.4(2), the cross-impl addition) — the emitting engine must be
	// the alternate one, never a fallback to the reference.
	//
	// core-go's own emission legitimately fails this and is meant to: Stage-1 IS
	// the reference, and the honest way to say so is a recorded role rather than
	// a claim in prose. The guard is enforced only for an AE-1 admission run,
	// which is where circular agreement would actually mislead.
	if requireAlternate {
		r.add("engine-role==alternate", em.EngineRole == RoleAlternate,
			"engine %q declared role %q", em.Engine, em.EngineRole)
	} else {
		r.add("engine-role (advisory)", true,
			"engine %q role %q — alternate-engine gate not requested", em.Engine, em.EngineRole)
	}

	return r
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func formatCodes(codes map[string]int) string {
	if len(codes) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, codes[k]))
	}
	return strings.Join(parts, " ")
}
