package types

import "testing"

// EXTENSION-TYPE v1.1 §3.3/§4 — a constraint declared on a built-in's field MUST
// survive into the descriptor the peer publishes.
//
// OverrideField REPLACES the whole FieldSpec, so a second override of an
// already-constrained field silently drops its constraints. That is exactly what
// happened to converge-request.type_paths and reconcile-request.type_paths: both
// were registered with min_count(2), then re-overridden later in
// RegisterCoreTypes with the same element type and no constraints, so Go
// advertised a descriptor without the constraint it had declared.
//
// It stayed invisible for two compounding reasons, both now closed: the
// type-descriptor differ in validate-peer compared shape only, so a
// constraint-only divergence surfaced as a hash mismatch with "no structural
// differences — likely a CBOR encoding edge"; and a Go-only run cannot see it at
// all, because Go's writer and reader share the same descriptor. It took
// entity-core-py publishing the constraint Go did not.
//
// This test asserts the published descriptor, not the registration call, so it
// fails for a re-clobber regardless of which override does the clobbering.
func TestDeclaredFieldConstraintsSurviveIntoPublishedDescriptors(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	cases := []struct {
		typeName   string
		field      string
		constraint string
		why        string
	}{
		{TypeTypeConvergeRequest, "type_paths", TypeConstraintMinCount, "§4 — converging fewer than 2 types is meaningless"},
		{TypeTypeReconcileRequest, "type_paths", TypeConstraintMinCount, "§4 — reconciling fewer than 2 types is meaningless"},
		{TypeTypeReconcileRequest, "strategy", TypeConstraintOneOf, "§7.6 — strategy is a closed set"},
		{TypeTypeViolation, "kind", TypeConstraintOneOf, "§8 — violation kind is a closed set"},
		{TypeTypeCompatibleRequest, "direction", TypeConstraintOneOf, "§7.5 — direction is a closed set"},
		{TypeTypeCompatibilityReport, "level", TypeConstraintOneOf, "§7.5 — compatibility level is a closed set"},
	}

	for _, tc := range cases {
		def, ok := r.Get(tc.typeName)
		if !ok {
			t.Errorf("%s: not registered", tc.typeName)
			continue
		}
		spec, ok := def.Fields[tc.field]
		if !ok {
			t.Errorf("%s: field %q absent from the published descriptor", tc.typeName, tc.field)
			continue
		}
		found := false
		for _, c := range spec.Constraints {
			if c.Type == tc.constraint {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s.%s: declared constraint %s is MISSING from the published descriptor (%s). A later OverrideField almost certainly replaced the FieldSpec and dropped it — carry the constraints, or drop the redundant override.",
				tc.typeName, tc.field, tc.constraint, tc.why)
		}
	}
}
