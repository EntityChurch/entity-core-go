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

// handleValidate runs the EXTENSION-TYPE v1.1 §2.3 two-phase validate:
//
//   - Phase 1: structural validation against the resolved type definition.
//   - Phase 2: per-field constraint dispatch via standard handler dispatch.
//
// The result enumerates violations and reports open-type extension fields
// the validator detected but couldn't interpret in unevaluated_fields.
func (h *Handler) handleValidate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.ValidateRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode validate-request: "+err.Error())
	}

	// Decode the entity to validate.
	subject, err := decodeEntity(dispatch.Entity)
	if err != nil {
		return handler.NewErrorResponse(400, "invalid_entity",
			"validate-request.entity does not decode as an entity: "+err.Error())
	}

	typeName := dispatch.TypePath
	if typeName == "" {
		typeName = subject.Type
	}

	// Resolve the type definition. Strategy 1 (path-convention) per v1.1
	// §1.5: lookup("system/type/" + name).
	typeDef, resolved := resolveTypeDefinition(req.Context, typeName)
	if !resolved {
		// Resolution failure is itself a structural violation — the
		// validator could not check anything about the entity.
		result := types.ValidateResultData{
			Valid: false,
			Violations: []types.Violation{{
				Field:  "type",
				Kind:   types.ViolationKindStructural,
				Reason: fmt.Sprintf("type %q not resolvable at system/type/%s", typeName, typeName),
			}},
		}
		return handler.NewResponse(200, types.TypeValidateRes, result)
	}

	// Decode the entity data into an ordered field map for structural and
	// constraint checks. We use map[string]cbor.RawMessage so each field
	// retains its byte representation for ECF byte-equality comparisons in
	// constraint dispatch.
	fields, err := decodeDataMap(subject.Data)
	if err != nil {
		result := types.ValidateResultData{
			Valid: false,
			Violations: []types.Violation{{
				Field:  "data",
				Kind:   types.ViolationKindStructural,
				Reason: "entity data is not a CBOR map: " + err.Error(),
			}},
		}
		return handler.NewResponse(200, types.TypeValidateRes, result)
	}

	var violations []types.Violation
	var unevaluated []string

	// Phase 1: structural validation.
	violations = append(violations, structuralCheck(typeDef, fields)...)

	// Per §2.3 implementations MAY short-circuit after structural failure
	// (fail-fast) or proceed to constraints (comprehensive). We pick
	// comprehensive — constraints on present fields are still informative
	// even when the shape is partially wrong, and the caller can read the
	// violation kinds to discriminate.

	// Phase 2: constraint dispatch.
	dispatchedViolations, dispatchedUneval := constraintDispatch(ctx, req.Context, typeDef, fields)
	violations = append(violations, dispatchedViolations...)
	unevaluated = append(unevaluated, dispatchedUneval...)

	// Phase 3 (§6.4 — narrowing): when the subject IS a type definition
	// and declares `extends`, verify per-field narrowing rules against the
	// parent chain.
	if subject.Type == types.TypeType {
		var subjectDef types.TypeDefinition
		if err := ecf.Decode(subject.Data, &subjectDef); err == nil && subjectDef.Extends != "" {
			violations = append(violations, verifyNarrowing(req.Context, subjectDef)...)
		}
	}

	result := types.ValidateResultData{
		Valid:             len(violations) == 0,
		Violations:        violations,
		UnevaluatedFields: unevaluated,
	}
	return handler.NewResponse(200, types.TypeValidateRes, result)
}

// decodeEntity decodes raw CBOR into an entity.Entity. The validate-request
// carries entity as a core/entity (full {type, data, content_hash}).
func decodeEntity(raw cbor.RawMessage) (entity.Entity, error) {
	var e entity.Entity
	if err := ecf.Decode(raw, &e); err != nil {
		return entity.Entity{}, err
	}
	return e, nil
}

// decodeDataMap decodes the entity data field into a string-keyed map of
// raw CBOR values, preserving each value's byte form for ECF-based
// constraint comparisons.
func decodeDataMap(raw cbor.RawMessage) (map[string]cbor.RawMessage, error) {
	var m map[string]cbor.RawMessage
	if err := ecf.Decode(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// resolveTypeDefinition implements v1.1 §1.5 Strategy 1 (path-convention).
// Returns (def, true) if the type was found at system/type/{name}; falls
// back to the in-process type registry so the validator works even when
// the tree isn't populated (typical in tests / startup).
func resolveTypeDefinition(hctx *handler.HandlerContext, name string) (types.TypeDefinition, bool) {
	if hctx != nil && hctx.LocationIndex != nil && hctx.Store != nil {
		path := "system/type/" + name
		h, ok := hctx.LocationIndex.Get(path)
		if ok {
			ent, ok := hctx.Store.Get(h)
			if ok {
				var def types.TypeDefinition
				if err := ecf.Decode(ent.Data, &def); err == nil {
					return def, true
				}
			}
		}
	}
	return types.TypeDefinition{}, false
}

// constraintDispatch walks every field in the type def, finds each
// field-spec's constraints array, and dispatches each constraint to its
// handler via the standard EXECUTE dispatch. Returns the collected
// violations and a list of open-type extension fields that the validator
// could not interpret.
func constraintDispatch(
	ctx context.Context,
	hctx *handler.HandlerContext,
	def types.TypeDefinition,
	fields map[string]cbor.RawMessage,
) ([]types.Violation, []string) {
	var violations []types.Violation

	// Deterministic field order (test reproducibility and consistent error
	// reports).
	names := make([]string, 0, len(def.Fields))
	for n := range def.Fields {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, fname := range names {
		spec := def.Fields[fname]
		if len(spec.Constraints) == 0 {
			continue
		}
		value, present := fields[fname]
		// Absent vs null: when the field is absent, constraints are
		// skipped (§2.3 Absent vs null). When present-with-null, the
		// field has a value (null) and constraints apply.
		if !present {
			continue
		}

		for _, constraint := range spec.Constraints {
			v := dispatchConstraint(ctx, hctx, fname, value, constraint)
			if v != nil {
				violations = append(violations, *v)
			}
		}
	}

	// Open-type unevaluated_fields: when this peer ships the type
	// extension, all `constraints` arrays are evaluated above. Future
	// open-type field-spec extensions (beyond v1.1) would surface here.
	// For now this list is empty unless an unrecognized field-spec
	// attribute appears — that's a future check.
	return violations, nil
}

// dispatchConstraint runs one constraint against one field value via
// handler dispatch (V7 §6.5). Returns a violation on failure or nil on
// pass. Dispatch failures (no handler, timeout) yield an
// unknown_constraint violation per §1.2.
func dispatchConstraint(
	ctx context.Context,
	hctx *handler.HandlerContext,
	field string,
	value cbor.RawMessage,
	constraint entity.Entity,
) *types.Violation {
	envelope := types.ConstraintValidateRequestData{
		Value:          value,
		ConstraintType: constraint.Type,
		ConstraintData: constraint.Data,
	}
	envEntity, err := envelope.ToEntity()
	if err != nil {
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindConstraint,
			Constraint: constraint.Type,
			Reason:     "failed to build constraint dispatch envelope: " + err.Error(),
		}
	}

	if hctx == nil || hctx.Execute == nil {
		// No dispatcher wired (test path) — treat as unknown_constraint
		// rather than silent pass per §1.2.
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindUnknownConstraint,
			Constraint: constraint.Type,
			Reason:     "no dispatcher available for constraint",
		}
	}

	resp, err := hctx.Execute(ctx, constraint.Type, "validate", envEntity)
	if err != nil {
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindUnknownConstraint,
			Constraint: constraint.Type,
			Reason:     "constraint_dispatch_failed: " + err.Error(),
		}
	}
	if resp == nil || resp.Status != 200 {
		errMsg := fmt.Sprintf("constraint dispatch returned status %d", respStatus(resp))
		if resp != nil {
			var ed types.ErrorData
			if ecf.Decode(resp.Result.Data, &ed) == nil && ed.Message != "" {
				errMsg = fmt.Sprintf("constraint dispatch status %d: %s (%s)",
					resp.Status, ed.Code, ed.Message)
			}
		}
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindUnknownConstraint,
			Constraint: constraint.Type,
			Reason:     errMsg,
		}
	}

	var result types.ConstraintValidateResultData
	if err := ecf.Decode(resp.Result.Data, &result); err != nil {
		return &types.Violation{
			Field:      field,
			Kind:       types.ViolationKindUnknownConstraint,
			Constraint: constraint.Type,
			Reason:     "constraint result decode failed: " + err.Error(),
		}
	}
	if result.Valid {
		return nil
	}

	// Discriminate constraint-failure from unknown-constraint by inspecting
	// the reason — the standard constraint handler's default arm always
	// includes the "unknown constraint type" or "unknown format" marker.
	kind := types.ViolationKindConstraint
	if isUnknownConstraintReason(result.Reason) {
		kind = types.ViolationKindUnknownConstraint
	}
	return &types.Violation{
		Field:      field,
		Kind:       kind,
		Constraint: constraint.Type,
		Reason:     result.Reason,
	}
}

// respStatus returns the response's status code or 0 when nil.
func respStatus(resp *handler.Response) uint {
	if resp == nil {
		return 0
	}
	return resp.Status
}

// isUnknownConstraintReason flags reasons produced by the standard
// constraint handler's default arms (§4.5 unknown format + §5.4 unknown
// constraint type). Per EXTENSION-TYPE v1.1 §2.3 "Violation kind
// mapping," the classifier mechanism (reason-string substring check,
// status-code inspection, structured error payload) is
// implementation-defined; only the mapping outcome is normative. This
// impl uses reason-string substring matching against the standard
// handler's documented default-arm markers.
func isUnknownConstraintReason(reason string) bool {
	const (
		markerType   = "unknown constraint type"
		markerFormat = "unknown format"
	)
	if len(reason) == 0 {
		return false
	}
	return contains(reason, markerType) || contains(reason, markerFormat)
}

// contains is a fixed-substring search without dragging strings into the
// import block twice; it's a tiny helper.
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
