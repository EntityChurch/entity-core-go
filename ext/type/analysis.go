package typeext

import (
	"context"
	"sort"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleCompare implements §7.2 — structural diff of two type defs.
func (h *Handler) handleCompare(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.CompareRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode compare-request: "+err.Error())
	}

	a, okA := resolveTypeDefinition(req.Context, stripTypePathPrefix(dispatch.TypeA))
	b, okB := resolveTypeDefinition(req.Context, stripTypePathPrefix(dispatch.TypeB))
	if !okA {
		return handler.NewErrorResponse(404, "type_not_found",
			"could not resolve type_a: "+dispatch.TypeA)
	}
	if !okB {
		return handler.NewErrorResponse(404, "type_not_found",
			"could not resolve type_b: "+dispatch.TypeB)
	}

	result := compareTypes(dispatch.TypeA, dispatch.TypeB, a, b)
	return handler.NewResponse(200, types.TypeTypeCompareResult, result)
}

// handleCompatible implements §7.3 — directional compatibility check.
func (h *Handler) handleCompatible(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.CompatibleRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode compatible-request: "+err.Error())
	}

	a, okA := resolveTypeDefinition(req.Context, stripTypePathPrefix(dispatch.TypeA))
	b, okB := resolveTypeDefinition(req.Context, stripTypePathPrefix(dispatch.TypeB))
	if !okA {
		return handler.NewErrorResponse(404, "type_not_found",
			"could not resolve type_a: "+dispatch.TypeA)
	}
	if !okB {
		return handler.NewErrorResponse(404, "type_not_found",
			"could not resolve type_b: "+dispatch.TypeB)
	}

	report := compatibleTypes(dispatch.TypeA, dispatch.TypeB, dispatch.Direction, a, b)
	return handler.NewResponse(200, types.TypeTypeCompatibilityReport, report)
}

// compareTypes implements the structural diff algorithm.
func compareTypes(pathA, pathB string, a, b types.TypeDefinition) types.CompareResultData {
	shared := map[string]types.FieldComparisonData{}
	var onlyA, onlyB []string
	var incompat []types.FieldIncompatibilityData

	for _, name := range sortedFieldNames(a.Fields) {
		fa := a.Fields[name]
		fb, present := b.Fields[name]
		if !present {
			onlyA = append(onlyA, name)
			continue
		}
		typeMatch := fieldShapeMatches(fa, fb)
		if !typeMatch {
			incompat = append(incompat, types.FieldIncompatibilityData{
				FieldName: name,
				AType:     fieldShapeName(fa),
				BType:     fieldShapeName(fb),
				Reason:    "field shape differs",
			})
		}
		shared[name] = types.FieldComparisonData{
			TypeMatch:       typeMatch,
			ConstraintMatch: constraintSetsEqual(fa.Constraints, fb.Constraints),
			AOptional:       fa.Optional,
			BOptional:       fb.Optional,
		}
	}
	for _, name := range sortedFieldNames(b.Fields) {
		if _, present := a.Fields[name]; !present {
			onlyB = append(onlyB, name)
		}
	}

	return types.CompareResultData{
		TypeAPath:    pathA,
		TypeBPath:    pathB,
		Shared:       shared,
		OnlyA:        nonNilStrings(onlyA),
		OnlyB:        nonNilStrings(onlyB),
		Incompatible: incompat,
	}
}

// compatibleTypes implements the directional compatibility level.
func compatibleTypes(pathA, pathB, direction string, a, b types.TypeDefinition) types.CompatibilityReportData {
	cmp := compareTypes(pathA, pathB, a, b)

	report := types.CompatibilityReportData{
		TypeAPath:          pathA,
		TypeBPath:          pathB,
		Direction:          direction,
		SharedFields:       []string{},
		IncompatibleFields: cmp.Incompatible,
	}
	for name := range cmp.Shared {
		report.SharedFields = append(report.SharedFields, name)
	}
	sort.Strings(report.SharedFields)

	// "Missing required" means: a required field on the other side is
	// absent here. In forward direction (A → B), entities of type A must
	// satisfy B; any required B field that doesn't exist on A is a gap.
	for _, name := range cmp.OnlyB {
		if !b.Fields[name].Optional {
			report.MissingRequiredA = append(report.MissingRequiredA, name)
		}
	}
	for _, name := range cmp.OnlyA {
		if !a.Fields[name].Optional {
			report.MissingRequiredB = append(report.MissingRequiredB, name)
		}
	}

	report.Level = computeLevel(cmp, report, direction)
	return report
}

func computeLevel(cmp types.CompareResultData, report types.CompatibilityReportData, direction string) string {
	if len(cmp.Incompatible) > 0 {
		// Any incompatible shared field blocks at least one direction.
		switch direction {
		case types.DirectionForward, types.DirectionBackward:
			return types.CompatibilityIncompatible
		default:
			return types.CompatibilityIncompatible
		}
	}

	missingA := len(report.MissingRequiredA) > 0
	missingB := len(report.MissingRequiredB) > 0
	switch direction {
	case types.DirectionForward:
		if missingA {
			return types.CompatibilityIncompatible
		}
		if missingB {
			// A is a superset of B's required fields — A entities satisfy B.
			return types.CompatibilityForwardOnly
		}
		return types.CompatibilityFullyCompatible
	case types.DirectionBackward:
		if missingB {
			return types.CompatibilityIncompatible
		}
		if missingA {
			return types.CompatibilityBackwardOnly
		}
		return types.CompatibilityFullyCompatible
	default: // bidirectional or unknown
		switch {
		case !missingA && !missingB:
			return types.CompatibilityFullyCompatible
		case !missingA && missingB:
			return types.CompatibilityForwardOnly
		case missingA && !missingB:
			return types.CompatibilityBackwardOnly
		default:
			return types.CompatibilityPartiallyCompatible
		}
	}
}

// fieldShapeMatches returns true iff two field specs have the same
// shape (same type_ref / array_of / map_of / union_of). Constraints are
// compared separately (§7.2 algorithm note).
func fieldShapeMatches(a, b types.FieldSpec) bool {
	if a.TypeRef != b.TypeRef {
		return false
	}
	if (a.ArrayOf == nil) != (b.ArrayOf == nil) {
		return false
	}
	if a.ArrayOf != nil && !fieldShapeMatches(*a.ArrayOf, *b.ArrayOf) {
		return false
	}
	if (a.MapOf == nil) != (b.MapOf == nil) {
		return false
	}
	if a.MapOf != nil && !fieldShapeMatches(*a.MapOf, *b.MapOf) {
		return false
	}
	if len(a.UnionOf) != len(b.UnionOf) {
		return false
	}
	for i := range a.UnionOf {
		if !fieldShapeMatches(a.UnionOf[i], b.UnionOf[i]) {
			return false
		}
	}
	return true
}

// fieldShapeName returns a compact human-readable shape descriptor for
// the field-incompatibility report.
func fieldShapeName(fs types.FieldSpec) string {
	switch {
	case fs.ArrayOf != nil:
		return "array_of(" + fieldShapeName(*fs.ArrayOf) + ")"
	case fs.MapOf != nil:
		return "map_of(" + fieldShapeName(*fs.MapOf) + ")"
	case len(fs.UnionOf) > 0:
		out := "union_of["
		for i, u := range fs.UnionOf {
			if i > 0 {
				out += ","
			}
			out += fieldShapeName(u)
		}
		return out + "]"
	default:
		if fs.TypeRef == "" {
			return "<unknown>"
		}
		return fs.TypeRef
	}
}

// constraintSetsEqual reports whether two constraint arrays carry the same
// set of constraint types with the same ECF-canonical data payloads. Order
// of constraints within an array is not significant for the equality.
func constraintSetsEqual(a, b []entity.Entity) bool {
	if len(a) != len(b) {
		return false
	}
	canon := func(cs []entity.Entity) (map[string]struct{}, bool) {
		m := map[string]struct{}{}
		for _, c := range cs {
			cdat, err := canonicalizeRaw(c.Data)
			if err != nil {
				return nil, false
			}
			key := c.Type + "|" + string(cdat)
			m[key] = struct{}{}
		}
		return m, true
	}
	ma, okA := canon(a)
	if !okA {
		return false
	}
	mb, okB := canon(b)
	if !okB {
		return false
	}
	if len(ma) != len(mb) {
		return false
	}
	for k := range ma {
		if _, ok := mb[k]; !ok {
			return false
		}
	}
	return true
}

// stripTypePathPrefix strips a leading "system/type/" or absolute
// "/peerid/system/type/" so the remaining bare type name can be passed to
// resolveTypeDefinition. Compare/compatible requests carry tree paths
// (system/tree/path); resolution wants the bare name.
func stripTypePathPrefix(path string) string {
	const prefix = "system/type/"
	// Try peer-relative first.
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		return path[len(prefix):]
	}
	// Absolute path: /{peer_id}/system/type/{name}
	for i := 1; i < len(path); i++ {
		if path[i] == '/' && i+len(prefix) < len(path) && path[i+1:i+1+len(prefix)] == prefix {
			return path[i+1+len(prefix):]
		}
	}
	return path
}

func sortedFieldNames(m map[string]types.FieldSpec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
