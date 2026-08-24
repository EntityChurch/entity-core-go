package main

import (
	"strings"
	"testing"
)

// TestV325CornerOutcomes runs go's emit over the SEEDED corner vectors (7 of the
// 9 CV arms — CV-4a and CV-5 are held in v325BlockedOnMaterialization, see below)
// and asserts go produces the outcomes GUIDE-CONFORMANCE §7c.6 rules. This is the
// go-emit half of C-5; the three-way cross-bless is gated on rust/py landing v3.25.
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
	if len(byID) != 7 {
		t.Fatalf("expected 7 seeded v325-corner vectors, got %d", len(byID))
	}

	// error-outcome arms: the exact code is the boundary (§7c.3 code-only).
	wantErr := map[string]string{
		"worked/v325-corner/cv2-assoc-oob-negative":              "index_out_of_range",
		"worked/v325-corner/cv2-assoc-oob-overflow":              "index_out_of_range",
		"worked/v325-corner/cv3-range-negative":                  "count_out_of_range",
		"worked/v325-corner/cv4b-assoc-index-error-shortcircuit": "seeded_error",
		"worked/v325-corner/cv6-group-by-error-key":              "seeded_error",
	}
	// value/entity-outcome arms: a materialized boundary, no error.
	wantValue := []string{
		"worked/v325-corner/cv1-group-by-shape",
		"worked/v325-corner/cv3-range-zero",
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

// TestV325ContainedErrorBoundaryIsBlocked pins the CV-4a/CV-5 finding: go cannot
// yet emit a boundary for a value that CONTAINS a compute/error (v3.25 C-4's
// data-position containment), because materialize()'s v3.23 ruling-B guard
// rejects any compute/error reaching it. This test asserts the current, blocked
// behavior — it is the teeth for spec-issue 2026-08-20-f: when the containment
// boundary is ruled and go's materialize() is fixed, THIS test flips (the
// vectors emit a value boundary) and the pair moves into v325CornerVectors.
func TestV325ContainedErrorBoundaryIsBlocked(t *testing.T) {
	for _, wv := range v325BlockedOnMaterialization {
		b := newIRBuilder(nil)
		root := wv.build(b)
		v, err := b.freeze(wv.id, 0, root, map[string]interface{}{}, stdBudget)
		if err != nil {
			t.Fatalf("%s: freeze: %v", wv.id, err)
		}
		_, err = evalVector(v)
		if err == nil {
			t.Errorf("%s: now emits cleanly — spec-issue 2026-08-20-f may be resolved; "+
				"move this vector into v325CornerVectors, re-freeze, re-pin the SHA", wv.id)
			continue
		}
		if !strings.Contains(err.Error(), "compute/error reached materialize()") {
			t.Errorf("%s: blocked for an unexpected reason: %v", wv.id, err)
		}
	}
}
