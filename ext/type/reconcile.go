package typeext

import (
	"context"
	"fmt"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// handleReconcile implements §7.6 — merge diverged type definitions into a
// single definition by an explicit strategy. Three strategies:
//
//   - intersect: minimal common structure (drop fields unique to any input)
//   - union:     all fields; uniques become optional; incompatibles excluded
//   - prefer:    first path is the preferred definition; others supply
//                additional fields as optional; incompatibles take the
//                preferred's version
//
// The handler returns a ReconcileResult that wraps the merged entity in
// reconciled_type alongside metadata about what changed. Caller decides
// whether to tree-put the entity.
func (h *Handler) handleReconcile(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.ReconcileRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode reconcile-request: "+err.Error())
	}
	if len(dispatch.TypePaths) < 2 {
		return handler.NewErrorResponse(400, "invalid_request",
			"reconcile requires at least 2 type_paths")
	}
	switch dispatch.Strategy {
	case types.ReconcileIntersect, types.ReconcileUnion, types.ReconcilePrefer:
		// supported
	default:
		return handler.NewErrorResponse(400, "invalid_strategy",
			fmt.Sprintf("strategy must be one of intersect/union/prefer; got %q", dispatch.Strategy))
	}

	defs, paths, errResp := resolveAll(req.Context, dispatch.TypePaths)
	if errResp != nil {
		return errResp, nil
	}

	var result types.ReconcileResultData
	switch dispatch.Strategy {
	case types.ReconcileIntersect:
		result = reconcileIntersect(defs, paths)
	case types.ReconcileUnion:
		result = reconcileUnion(defs, paths)
	case types.ReconcilePrefer:
		result = reconcilePrefer(defs, paths)
	}
	result.StrategyUsed = dispatch.Strategy
	result.Sources = append([]string(nil), paths...)

	ent, err := result.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_error",
			"failed to encode reconcile-result: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// reconcileIntersect keeps only fields present in ALL definitions with
// compatible types. Constraints become the most-restrictive (union of
// constraint bundles per intersection-of-allowed-values).
func reconcileIntersect(defs []types.TypeDefinition, paths []string) types.ReconcileResultData {
	merged := types.TypeDefinition{
		Name:   reconcileName("intersect", paths),
		Fields: map[string]types.FieldSpec{},
	}
	var dropped []string

	// Collect every field name that appears in any def, sorted for
	// determinism.
	allNames := collectFieldNames(defs)
	for _, name := range allNames {
		specs := fieldSpecsAcross(defs, name)
		if len(specs) != len(defs) {
			dropped = append(dropped, name)
			continue
		}
		// All inputs have it — check shape compatibility.
		if !allShapesMatch(specs) {
			dropped = append(dropped, name)
			continue
		}
		merged.Fields[name] = types.FieldSpec{
			TypeRef:     specs[0].TypeRef,
			ArrayOf:     specs[0].ArrayOf,
			MapOf:       specs[0].MapOf,
			UnionOf:     specs[0].UnionOf,
			Optional:    allOptional(specs), // most restrictive
			Constraints: mergeConstraintsIntersect(specs),
		}
	}

	rawMerged, _ := ecf.Encode(merged)
	return types.ReconcileResultData{
		ReconciledType: rawMerged,
		FieldsDropped:  nonNilStrings(dropped),
	}
}

// reconcileUnion keeps ALL fields. Fields not present in every def become
// optional. Incompatible shapes (same name, different types) are excluded
// and reported. Constraints use the least-restrictive of inputs — exact
// intersection of allowed values is the union of constraint exclusions,
// which inverts to keeping no constraint at all on the disagreeing axis;
// the conservative pin: drop constraints where impls differ; preserve
// constraints where impls agree.
func reconcileUnion(defs []types.TypeDefinition, paths []string) types.ReconcileResultData {
	merged := types.TypeDefinition{
		Name:   reconcileName("union", paths),
		Fields: map[string]types.FieldSpec{},
	}
	var madeOptional []string
	var incompat []types.FieldIncompatibilityData

	allNames := collectFieldNames(defs)
	for _, name := range allNames {
		specs := fieldSpecsAcross(defs, name)
		if !allShapesMatch(specs) {
			a, b := firstTwoDistinctShapes(specs)
			incompat = append(incompat, types.FieldIncompatibilityData{
				FieldName: name,
				AType:     a,
				BType:     b,
				Reason:    "field shape differs across reconcile inputs",
			})
			continue
		}
		// Pick a representative spec (first non-empty).
		rep := specs[0]
		// Optional iff not present in all inputs OR any input marked it optional.
		isOptional := len(specs) < len(defs) || anyOptional(specs)
		if isOptional && !rep.Optional {
			madeOptional = append(madeOptional, name)
		}
		merged.Fields[name] = types.FieldSpec{
			TypeRef:     rep.TypeRef,
			ArrayOf:     rep.ArrayOf,
			MapOf:       rep.MapOf,
			UnionOf:     rep.UnionOf,
			Optional:    isOptional,
			Constraints: mergeConstraintsUnionLeast(specs),
		}
	}

	rawMerged, _ := ecf.Encode(merged)
	return types.ReconcileResultData{
		ReconciledType:     rawMerged,
		FieldsMadeOptional: nonNilStrings(madeOptional),
		Incompatibilities:  incompat,
	}
}

// reconcilePrefer takes the first input's definition as canonical. Other
// inputs supply additional fields (made optional). Incompatibilities are
// resolved by taking the preferred input's version (and reported).
func reconcilePrefer(defs []types.TypeDefinition, paths []string) types.ReconcileResultData {
	if len(defs) == 0 {
		return types.ReconcileResultData{}
	}
	pref := defs[0]
	merged := types.TypeDefinition{
		Name:   reconcileName("prefer", paths),
		Fields: copyFields(pref.Fields),
	}
	var madeOptional []string
	var incompat []types.FieldIncompatibilityData

	allNames := collectFieldNames(defs)
	sort.Strings(allNames)
	for _, name := range allNames {
		prefSpec, inPref := pref.Fields[name]
		othersHaveIt := false
		for _, other := range defs[1:] {
			if otherSpec, ok := other.Fields[name]; ok {
				othersHaveIt = true
				if inPref && !fieldShapeMatches(prefSpec, otherSpec) {
					incompat = append(incompat, types.FieldIncompatibilityData{
						FieldName: name,
						AType:     fieldShapeName(prefSpec),
						BType:     fieldShapeName(otherSpec),
						Reason:    "preferred input retained; non-preferred has incompatible shape",
					})
				}
			}
		}
		if !inPref && othersHaveIt {
			// New field from a non-preferred input — add as optional.
			// Use the shape from the first def that carries it.
			for _, other := range defs[1:] {
				if otherSpec, ok := other.Fields[name]; ok {
					added := otherSpec
					added.Optional = true
					merged.Fields[name] = added
					madeOptional = append(madeOptional, name)
					break
				}
			}
		}
	}

	rawMerged, _ := ecf.Encode(merged)
	return types.ReconcileResultData{
		ReconciledType:     rawMerged,
		FieldsMadeOptional: nonNilStrings(madeOptional),
		Incompatibilities:  incompat,
	}
}

// reconcileName produces a deterministic non-conflicting name for the
// merged type. Callers can override before tree-put.
func reconcileName(strategy string, paths []string) string {
	return fmt.Sprintf("reconciled/%s/%d-types", strategy, len(paths))
}

// collectFieldNames returns the sorted union of field names across defs.
func collectFieldNames(defs []types.TypeDefinition) []string {
	seen := map[string]struct{}{}
	for _, d := range defs {
		for n := range d.Fields {
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// fieldSpecsAcross returns the field specs for `name` across all defs
// that have it (skipping defs that don't). Caller checks
// len(returned) == len(defs) to detect "present in all".
func fieldSpecsAcross(defs []types.TypeDefinition, name string) []types.FieldSpec {
	out := []types.FieldSpec{}
	for _, d := range defs {
		if fs, ok := d.Fields[name]; ok {
			out = append(out, fs)
		}
	}
	return out
}

// allShapesMatch returns true iff every spec in specs has the same shape
// as specs[0].
func allShapesMatch(specs []types.FieldSpec) bool {
	if len(specs) <= 1 {
		return true
	}
	for _, s := range specs[1:] {
		if !fieldShapeMatches(specs[0], s) {
			return false
		}
	}
	return true
}

// firstTwoDistinctShapes returns a printable rendering of two distinct
// field shapes from specs, used to populate field-incompatibility
// reports.
func firstTwoDistinctShapes(specs []types.FieldSpec) (string, string) {
	if len(specs) == 0 {
		return "<empty>", "<empty>"
	}
	a := specs[0]
	for _, b := range specs[1:] {
		if !fieldShapeMatches(a, b) {
			return fieldShapeName(a), fieldShapeName(b)
		}
	}
	return fieldShapeName(a), fieldShapeName(a)
}

func allOptional(specs []types.FieldSpec) bool {
	for _, s := range specs {
		if !s.Optional {
			return false
		}
	}
	return true
}

func anyOptional(specs []types.FieldSpec) bool {
	for _, s := range specs {
		if s.Optional {
			return true
		}
	}
	return false
}

// mergeConstraintsUnionLeast preserves the constraints that EVERY input
// agrees on; constraints unique to a subset of inputs are dropped. This
// implements the union strategy's "least restrictive" posture (§7.6
// constraint reconciliation): a value valid under any one input's
// constraints should not be rejected by the union — so we only keep the
// intersection of the constraint sets.
func mergeConstraintsUnionLeast(specs []types.FieldSpec) []entity.Entity {
	if len(specs) == 0 {
		return nil
	}
	// Canonical-key index per spec.
	keysPerSpec := make([]map[string]entity.Entity, len(specs))
	for i, s := range specs {
		keysPerSpec[i] = make(map[string]entity.Entity, len(s.Constraints))
		for _, c := range s.Constraints {
			canon, err := canonicalizeRaw(c.Data)
			if err != nil {
				continue
			}
			keysPerSpec[i][c.Type+"|"+string(canon)] = c
		}
	}
	// Keep keys present in EVERY spec.
	common := []entity.Entity{}
	for k, c := range keysPerSpec[0] {
		shared := true
		for _, m := range keysPerSpec[1:] {
			if _, ok := m[k]; !ok {
				shared = false
				break
			}
		}
		if shared {
			common = append(common, c)
		}
	}
	// Deterministic order.
	sort.Slice(common, func(i, j int) bool {
		if common[i].Type != common[j].Type {
			return common[i].Type < common[j].Type
		}
		return string(common[i].Data) < string(common[j].Data)
	})
	return common
}

// Compile-time anchor — keeps cbor in the import set in case the
// generated boilerplate above stops referencing it directly.
var _ cbor.RawMessage
