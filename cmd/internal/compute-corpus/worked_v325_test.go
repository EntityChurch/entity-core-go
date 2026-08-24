package main

import (
	"bytes"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"
)

// TestV325CornerOutcomes runs go's emit over the SEEDED corner vectors (all 16 CV
// arms — CV-4a/CV-5 joined once COMPUTE v3.26 ruled the containment boundary
// (spec-issue 2026-08-20-f); the three CV-7 collection-operand short-circuits
// joined after core-rust/core-py caught go's resolveCollection type_mismatch; the
// four CV-8 CLOSURE-RESULT arms joined on arch's C-8 ruling §6 — map CONTAINS a
// closure error both minted (CV-8a) and value-form (CV-8b, the provenance pair),
// filter SHORT-CIRCUITS its predicate result (CV-8c), fold CONTAINS/RECOVERS its
// accumulator (CV-8d — a closure that ignores its accumulator recovers)) and asserts
// go produces the outcomes GUIDE-CONFORMANCE §7c.6 rules. This is the go-emit half;
// the three-way cross-bless of the 359 set is a fresh obligation on rust/py
// (spec-issue 2026-08-21-b).
func TestV325CornerOutcomes(t *testing.T) {
	vs, err := buildWorked(profileInproc)
	if err != nil {
		t.Fatalf("buildWorked: %v", err)
	}
	byID := map[string]Vector{}
	for _, v := range vs {
		if strings.HasPrefix(v.ID, "worked/v325-corner/") {
			byID[v.ID] = v
		}
	}
	if len(byID) != 16 {
		t.Fatalf("expected 16 seeded v325-corner vectors, got %d", len(byID))
	}

	// error-outcome arms: the exact code is the boundary (§7c.3 code-only).
	wantErr := map[string]string{
		"worked/v325-corner/cv2-assoc-oob-negative":                        "index_out_of_range",
		"worked/v325-corner/cv2-assoc-oob-overflow":                        "index_out_of_range",
		"worked/v325-corner/cv3-range-negative":                            "count_out_of_range",
		"worked/v325-corner/cv4b-assoc-index-error-shortcircuit":           "seeded_error",
		"worked/v325-corner/cv6-group-by-error-key":                        "seeded_error",
		"worked/v325-corner/cv7a-assoc-collection-error-shortcircuit":      "seeded_error",
		"worked/v325-corner/cv7b-group-by-collection-error-shortcircuit":   "seeded_error",
		"worked/v325-corner/cv7c-concat-sub-collection-error-shortcircuit": "seeded_error",
		// CV-8c: filter's predicate result is CONSUMED (read for truthiness) → the
		// error short-circuits and IS the boundary.
		"worked/v325-corner/cv8c-filter-predicate-error-shortcircuit": "seeded_error",
	}
	// value/entity-outcome arms: a materialized boundary, no error. CV-4a and
	// CV-5 are the v3.26 CONTAINED half — the error is present IN the output
	// array (code-only) and the boundary is the materialized construct, not an error.
	// CV-8a/CV-8b are the map closure-result CONTAINED pair: the output array carries
	// the closure errors code-only (minted and value-form must agree), so the boundary
	// is a materialized value, not an error. CV-8d is fold RECOVERING — the closure
	// ignores its error accumulator and returns the last element, a value boundary.
	wantValue := []string{
		"worked/v325-corner/cv1-group-by-shape",
		"worked/v325-corner/cv3-range-zero",
		"worked/v325-corner/cv4a-assoc-value-error-contained",
		"worked/v325-corner/cv5-concat-error-transparent",
		"worked/v325-corner/cv8a-map-contains-minted-error",
		"worked/v325-corner/cv8b-map-contains-valueform-error",
		"worked/v325-corner/cv8d-fold-ignores-accumulator-recovers",
	}

	for id, code := range wantErr {
		o, err := evalVector(byID[id])
		if err != nil {
			t.Errorf("%s: evalVector error: %v", id, err)
			continue
		}
		if o.Kind != OutcomeError || o.Code != code {
			t.Errorf("%s: got kind=%q code=%q, want error/%s", id, o.Kind, o.Code, code)
		}
	}
	for _, id := range wantValue {
		o, err := evalVector(byID[id])
		if err != nil {
			t.Errorf("%s: evalVector error: %v", id, err)
			continue
		}
		if o.Kind == OutcomeError {
			t.Errorf("%s: reduced to error{%s}, want a value/entity boundary", id, o.Code)
		}
	}
}

// TestV325MapProvenancePairIsByteIdentical is the teeth for arch §6's "the pair is
// the point": a map whose closure yields a MINTED error and one whose closure yields a
// VALUE-FORM error WITH THE SAME CODE must produce BYTE-IDENTICAL boundaries. That is
// the §2.4 provenance-independence [MUST] the map asymmetry violated — a
// provenance-dependent impl fails exactly one arm. Both closures produce
// division_by_zero: the minted arm is div(1,0); the value-form arm is a stored
// compute/error{code: division_by_zero} returned via SA-1. (The corpus CV-8a/CV-8b
// carry DIFFERENT codes — div vs seeded_error — because each independently asserts
// containment; this test matches the codes so the only remaining variable is
// provenance.) A mutation that reintroduces the minted-form short-circuit
// (containOrPropagate → propagate) turns the minted arm into an error boundary while
// the value arm stays a contained value, diverging the two and turning this RED.
func TestV325MapProvenancePairIsByteIdentical(t *testing.T) {
	eval := func(valueForm bool) Outcome {
		b := newIRBuilder(nil)
		coll := b.lit([]interface{}{int64(1), int64(2)})
		var body hash.Hash
		if valueForm {
			ent, err := (types.ComputeErrorData{Code: "division_by_zero"}).ToEntity()
			if err != nil {
				t.Fatalf("build value-form division_by_zero: %v", err)
			}
			body = b.addRaw(ent)
		} else {
			body = b.arith("div", b.lit(int64(1)), b.lit(int64(0)))
		}
		root := probe(b, b.mapB(coll, b.lambda([]string{"x"}, body)))
		v, err := b.freeze("teeth/map-provenance", 0, root, map[string]interface{}{}, stdBudget)
		if err != nil {
			t.Fatalf("freeze: %v", err)
		}
		o, err := evalVector(v)
		if err != nil {
			t.Fatalf("evalVector: %v", err)
		}
		return o
	}
	minted := eval(false)
	valueForm := eval(true)
	if minted.Kind == OutcomeError {
		t.Fatalf("minted arm reduced to error{%s} — map must CONTAIN, not short-circuit", minted.Code)
	}
	if minted.Kind != valueForm.Kind || !bytes.Equal(minted.Boundary, valueForm.Boundary) {
		t.Errorf("map provenance pair diverges (§2.4 provenance-dependence — the map asymmetry):\n"+
			"  minted (div 1/0):        kind=%q boundary=%x\n"+
			"  value-form (stored E):   kind=%q boundary=%x\n"+
			"a compute/error must behave identically however it was produced",
			minted.Kind, minted.Boundary, valueForm.Kind, valueForm.Boundary)
	}
}

// TestV325ContainedErrorBoundaryIsCodeOnly is the positive teeth that replaced
// the old "…IsBlocked" pin: it proves the v3.26 carve-out materializes a
// CONTAINED compute/error CODE-ONLY. The load-bearing property is that the
// boundary bytes do NOT depend on the error's message/at — otherwise two
// conformant peers whose diagnostics differ would fork the containing array's
// content hash (§3.5). So it emits an assoc(value=E) probe twice with E carrying
// two DIFFERENT messages and asserts the boundary is byte-identical AND not an
// error outcome. A mutation that re-embedded message (dropping ToMaterializedEntity)
// makes the two boundaries diverge, turning this RED.
func TestV325ContainedErrorBoundaryIsCodeOnly(t *testing.T) {
	build := func(message string) Outcome {
		b := newIRBuilder(nil)
		ent, err := (types.ComputeErrorData{Code: "seeded_error", Message: message}).ToEntity()
		if err != nil {
			t.Fatalf("build seed E: %v", err)
		}
		errHash := b.addRaw(ent)
		coll := b.lit([]interface{}{int64(1), int64(2), int64(3)})
		root := probe(b, b.builtin(compute.BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": b.lit(int64(1)), "value": errHash,
		}))
		v, err := b.freeze("teeth/cv4a-codeonly", 0, root, map[string]interface{}{}, stdBudget)
		if err != nil {
			t.Fatalf("freeze: %v", err)
		}
		o, err := evalVector(v)
		if err != nil {
			t.Fatalf("evalVector: %v", err)
		}
		return o
	}

	a := build("diagnostic message A")
	b := build("an entirely different diagnostic message B")

	if a.Kind == OutcomeError {
		t.Fatalf("contained error emitted an error boundary, want value/entity: %s", a.Code)
	}
	if a.Kind != b.Kind || !bytes.Equal(a.Boundary, b.Boundary) {
		t.Errorf("contained-error boundary depends on message (NOT code-only):\n"+
			"  message A: kind=%q boundary=%x\n"+
			"  message B: kind=%q boundary=%x\n"+
			"code-only materialization (ToMaterializedEntity) must exclude message/at (§3.5, §2.4)",
			a.Kind, a.Boundary, b.Kind, b.Boundary)
	}
}
