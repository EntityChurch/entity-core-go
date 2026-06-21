package typeext

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleConverge implements §7.4 — compute the intersection type across
// multiple definitions. Result is a system/type entity carrying only the
// fields present in ALL inputs with compatible shapes. Constraints
// reconcile as the most-restrictive across all inputs (same posture as
// reconcile strategy=intersect).
//
// The handler returns the entity inline; the caller decides whether to
// tree-put it (§7.4 result paragraph).
func (h *Handler) handleConverge(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.ConvergeRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode converge-request: "+err.Error())
	}
	if len(dispatch.TypePaths) < 2 {
		return handler.NewErrorResponse(400, "invalid_request",
			"converge requires at least 2 type_paths")
	}

	defs, paths, errResp := resolveAll(req.Context, dispatch.TypePaths)
	if errResp != nil {
		return errResp, nil
	}

	merged := convergeDefinitions(defs, paths)
	ent, err := merged.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_error",
			"failed to encode converged type: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// resolveAll resolves the listed type paths to TypeDefinitions. Returns
// the resolved defs in input order alongside the original paths. On the
// first failure it returns an error response and (nil, nil, errResp).
func resolveAll(hctx *handler.HandlerContext, paths []string) ([]types.TypeDefinition, []string, *handler.Response) {
	defs := make([]types.TypeDefinition, 0, len(paths))
	for _, p := range paths {
		def, ok := resolveTypeDefinition(hctx, stripTypePathPrefix(p))
		if !ok {
			resp, _ := handler.NewErrorResponse(404, "type_not_found",
				"could not resolve type at path: "+p)
			return nil, nil, resp
		}
		defs = append(defs, def)
	}
	return defs, paths, nil
}

// convergeDefinitions returns the intersection of defs — fields present
// in EVERY def with matching shapes. Constraints become the most
// restrictive across the inputs (per §7.6's intersect strategy applied to
// converge's intersection-of-shapes posture).
func convergeDefinitions(defs []types.TypeDefinition, paths []string) types.TypeDefinition {
	if len(defs) == 0 {
		return types.TypeDefinition{}
	}

	out := types.TypeDefinition{
		Name:   convergedName(paths),
		Fields: map[string]types.FieldSpec{},
	}

	// Start from the first def's fields; keep only those that all other
	// defs also carry with matching shapes.
	for fname, fa := range defs[0].Fields {
		shared := true
		all := []types.FieldSpec{fa}
		for _, other := range defs[1:] {
			fb, present := other.Fields[fname]
			if !present {
				shared = false
				break
			}
			if !fieldShapeMatches(fa, fb) {
				shared = false
				break
			}
			all = append(all, fb)
		}
		if !shared {
			continue
		}

		merged := fa
		// Optional iff ALL inputs marked it optional (intersect — most
		// restrictive on optionality means required-if-any-required).
		merged.Optional = true
		for _, f := range all {
			if !f.Optional {
				merged.Optional = false
				break
			}
		}
		// Constraints: most-restrictive intersection. Implemented as the
		// union of all constraint entities across the inputs — every
		// input's constraint applies to the merged type, which is exactly
		// the "most restrictive" semantic since constraints are
		// conjunctive (§3.2).
		merged.Constraints = mergeConstraintsIntersect(all)
		out.Fields[fname] = merged
	}
	return out
}

// convergedName produces a deterministic name for the merged type that
// identifies the inputs but is not itself bound at any path. Callers can
// override before tree-put.
func convergedName(paths []string) string {
	return fmt.Sprintf("converged/%d-types", len(paths))
}

// mergeConstraintsIntersect unions the constraint entities across inputs,
// deduping by ECF-canonical (type, data) key. This gives the
// most-restrictive bundle: every constraint that any input declared
// applies to the merged type, since constraints are conjunctive (§3.2).
func mergeConstraintsIntersect(specs []types.FieldSpec) []entity.Entity {
	all := []entity.Entity{}
	for _, s := range specs {
		all = append(all, s.Constraints...)
	}
	return dedupConstraintsByCanonical(all)
}

// dedupConstraintsByCanonical preserves order, dropping duplicate
// constraints by ECF-canonical (type, data) key. ECF is the cross-impl
// equality boundary for constraints (§5.5 is the analogous pin for
// values); two constraints that canonicalize identically are the same
// constraint, regardless of incoming byte form.
func dedupConstraintsByCanonical(cs []entity.Entity) []entity.Entity {
	if len(cs) == 0 {
		return nil
	}
	out := make([]entity.Entity, 0, len(cs))
	seen := map[string]struct{}{}
	for _, c := range cs {
		canon, err := canonicalizeRaw(c.Data)
		if err != nil {
			// Couldn't canonicalize — keep as-is; pessimistic about
			// dedup, optimistic about preservation.
			out = append(out, c)
			continue
		}
		key := c.Type + "|" + string(canon)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}
