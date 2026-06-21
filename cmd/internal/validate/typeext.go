package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catType = "type"

// runType validates an EXTENSION-TYPE v1.1 implementation. Covers the
// §12.1 MUST surface plus the §5.5 normative ECF byte-equality gate and
// the §4.5 fail-closed format vocabulary.
//
// The category is structurally permissive: type analysis ops (compare,
// compatible) are SHOULD per §12.2 — they yield WarnCheck on absence.
// Validate is MUST and yields FailCheck.
func runType(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catType)

	// --- Declare checks ---

	r.Declare("handler_manifest", "TYPE §7.1")
	r.Declare("handler_op_validate", "TYPE §8.3 / §12.1 MUST")
	r.Declare("constraint_handler_manifest", "TYPE §5.1 / §12.1 MUST")
	r.Declare("constraint_handler_op_validate", "TYPE §5.1")

	for _, kind := range standardConstraintKinds() {
		r.Declare("type_constraint_"+kind, "TYPE §4 / §11.1")
	}
	r.Declare("type_validate_request", "TYPE §8.3")
	r.Declare("type_validate_result", "TYPE §8.4")
	r.Declare("type_violation", "TYPE §8.5")

	r.Declare("validate_clean", "TYPE §2.3 — structural-sound entity passes")
	r.Declare("validate_missing_required", "TYPE §2.3 — required field absent reports structural violation")
	r.Declare("validate_constraint_fail", "TYPE §2.3 — value failing constraint reports kind=constraint")
	r.Declare("validate_unknown_constraint", "TYPE §1.2 — unknown constraint MUST fail closed with kind=unknown_constraint")
	r.Declare("validate_unknown_format", "TYPE §4.5 — unknown format MUST fail closed")
	r.Declare("validate_pcre_pattern_rejected", "TYPE §4.3 / §12.1 — PCRE backref MUST NOT silent-pass")
	r.Declare("validate_one_of_ecf_byte_equality", "TYPE §5.5 — one_of normative byte equality gate")

	// SHOULD ops (§12.2) and MAY ops (§12.3) — best-effort wire checks.
	// Absence on a peer is conformant; presence must round-trip cleanly.
	r.Declare("op_compare_roundtrip", "TYPE §7.2 SHOULD — compare round-trips")
	r.Declare("op_compatible_roundtrip", "TYPE §7.3 SHOULD — compatible round-trips")
	r.Declare("op_converge_roundtrip", "TYPE §7.4 MAY — converge round-trips")
	r.Declare("op_adopt_roundtrip", "TYPE §7.5 MAY — adopt round-trips")
	r.Declare("op_reconcile_roundtrip", "TYPE §7.6 MAY — reconcile round-trips")

	// --- Step 1: Handler manifests ---

	r.Run("handler_manifest", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/type")
		if err != nil {
			if isHandlerAbsent(err) {
				return SkipCheck("system/type handler not present — EXTENSION-TYPE is optional; absence is conformant (S1)")
			}
			return FailCheck("system/type handler manifest not present: " + err.Error())
		}
		r.Store("type_handler_manifest", ent)
		return PassCheck(fmt.Sprintf("system/type handler manifest at system/handler/system/type (type: %s)", ent.Type))
	})

	r.Run("handler_op_validate", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest"); !ok {
			return out
		}
		ent := r.Load("type_handler_manifest").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode type handler manifest: " + err.Error())
		}
		if _, ok := iface.Operations["validate"]; !ok {
			return FailCheck("system/type handler missing op validate (§12.1 MUST)")
		}
		return PassCheck("system/type:validate advertised")
	})

	r.Run("constraint_handler_manifest", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/type/constraint")
		if err != nil {
			if isHandlerAbsent(err) {
				return SkipCheck("system/type/constraint handler not present — optional; absence is conformant (S1)")
			}
			return FailCheck("system/type/constraint handler manifest not present: " + err.Error())
		}
		r.Store("constraint_handler_manifest", ent)
		return PassCheck("standard constraint handler manifest at system/handler/system/type/constraint")
	})

	r.Run("constraint_handler_op_validate", func() CheckOutcome {
		if out, ok := r.Require("constraint_handler_manifest"); !ok {
			return out
		}
		ent := r.Load("constraint_handler_manifest").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode constraint handler manifest: " + err.Error())
		}
		if _, ok := iface.Operations["validate"]; !ok {
			return FailCheck("system/type/constraint handler missing op validate")
		}
		return PassCheck("system/type/constraint:validate advertised")
	})

	// --- Step 2: Standard constraint types registered ---

	for _, kind := range standardConstraintKinds() {
		kind := kind
		r.Run("type_constraint_"+kind, func() CheckOutcome {
			path := "system/type/system/type/constraint/" + kind
			_, _, err := client.TreeGet(ctx, path)
			if err != nil {
				return FailCheck("standard constraint type not registered: " + path)
			}
			return PassCheck("standard constraint type registered: " + kind)
		})
	}

	r.Run("type_validate_request", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/type/validate-request")
		if err != nil {
			return FailCheck("system/type/validate-request type not registered: " + err.Error())
		}
		return PassCheck("system/type/validate-request registered")
	})
	r.Run("type_validate_result", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/type/validate-result")
		if err != nil {
			return FailCheck("system/type/validate-result type not registered: " + err.Error())
		}
		return PassCheck("system/type/validate-result registered")
	})
	r.Run("type_violation", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/type/violation")
		if err != nil {
			return FailCheck("system/type/violation type not registered: " + err.Error())
		}
		return PassCheck("system/type/violation registered")
	})

	// --- Step 3: End-to-end validate flow ---
	//
	// Install a type definition into the peer's tree, then dispatch
	// system/type:validate with various subject entities. The peer must
	// resolve the type via Strategy 1 (system/type/{name}).

	// Each install uses a distinct path to avoid cross-test bleed.
	installType := func(name string, def types.TypeDefinition) (string, error) {
		ent, err := def.ToEntity()
		if err != nil {
			return "", fmt.Errorf("encode def: %w", err)
		}
		path := "system/type/" + name
		if _, err := client.TreePut(ctx, path, ent); err != nil {
			return "", fmt.Errorf("put type def at %s: %w", path, err)
		}
		return path, nil
	}

	doValidate := func(typeName string, subject entity.Entity) (types.ValidateResultData, error) {
		dispatch := types.ValidateRequestData{TypePath: typeName}
		raw, err := ecf.Encode(subject)
		if err != nil {
			return types.ValidateResultData{}, fmt.Errorf("encode subject: %w", err)
		}
		dispatch.Entity = cbor.RawMessage(raw)
		paramEnt, err := dispatch.ToEntity()
		if err != nil {
			return types.ValidateResultData{}, fmt.Errorf("encode dispatch: %w", err)
		}
		uri := fmt.Sprintf("entity://%s/system/type", client.RemotePeerID())
		env, _, err := client.SendExecute(ctx, uri, "validate", paramEnt, nil)
		if err != nil {
			return types.ValidateResultData{}, fmt.Errorf("SendExecute: %w", err)
		}
		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return types.ValidateResultData{}, fmt.Errorf("decode response: %w", err)
		}
		if respData.Status != 200 {
			return types.ValidateResultData{}, fmt.Errorf("validate status %d", respData.Status)
		}
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return types.ValidateResultData{}, fmt.Errorf("decode result entity: %w", err)
		}
		if resultEntity.Type != types.TypeValidateRes {
			return types.ValidateResultData{}, fmt.Errorf("unexpected result type %q", resultEntity.Type)
		}
		var result types.ValidateResultData
		if err := ecf.Decode(resultEntity.Data, &result); err != nil {
			return types.ValidateResultData{}, fmt.Errorf("decode result: %w", err)
		}
		return result, nil
	}

	r.Run("validate_clean", func() CheckOutcome {
		_, err := installType("validate/clean", types.TypeDefinition{
			Name: "validate/clean",
			Fields: map[string]types.FieldSpec{
				"name": {TypeRef: "primitive/string"},
				"age":  {TypeRef: "primitive/uint", Optional: true},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/clean", map[string]interface{}{"name": "alice", "age": uint64(30)})
		result, err := doValidate("validate/clean", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if !result.Valid {
			return FailCheck(fmt.Sprintf("clean entity reported invalid: violations=%+v", result.Violations))
		}
		return PassCheck("clean entity validates as valid:true")
	})

	r.Run("validate_missing_required", func() CheckOutcome {
		_, err := installType("validate/req-name", types.TypeDefinition{
			Name: "validate/req-name",
			Fields: map[string]types.FieldSpec{
				"name": {TypeRef: "primitive/string"},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/req-name", map[string]interface{}{})
		result, err := doValidate("validate/req-name", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result.Valid {
			return FailCheck("missing required field MUST yield valid:false")
		}
		found := false
		for _, v := range result.Violations {
			if v.Kind == types.ViolationKindStructural && v.Field == "name" {
				found = true
				break
			}
		}
		if !found {
			return FailCheck(fmt.Sprintf("missing structural violation on field 'name': %+v", result.Violations))
		}
		return PassCheck("missing required field reported as kind=structural")
	})

	r.Run("validate_constraint_fail", func() CheckOutcome {
		minLen, err := types.ConstraintMinLengthData{MinLength: 1}.ToEntity()
		if err != nil {
			return SkipCheck("encode constraint: " + err.Error())
		}
		_, err = installType("validate/min-len", types.TypeDefinition{
			Name: "validate/min-len",
			Fields: map[string]types.FieldSpec{
				"name": {
					TypeRef:     "primitive/string",
					Constraints: []entity.Entity{minLen},
				},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/min-len", map[string]interface{}{"name": ""})
		result, err := doValidate("validate/min-len", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result.Valid {
			return FailCheck("empty string MUST fail min_length:1")
		}
		for _, v := range result.Violations {
			if v.Kind == types.ViolationKindConstraint && v.Constraint == types.TypeConstraintMinLength {
				return PassCheck("constraint failure reported as kind=constraint")
			}
		}
		return FailCheck(fmt.Sprintf("no constraint violation on min_length: %+v", result.Violations))
	})

	r.Run("validate_unknown_constraint", func() CheckOutcome {
		rogue, err := entity.NewEntity("system/type/constraint/rogue", cbor.RawMessage([]byte{0xa0}))
		if err != nil {
			return SkipCheck(err.Error())
		}
		_, err = installType("validate/unknown-c", types.TypeDefinition{
			Name: "validate/unknown-c",
			Fields: map[string]types.FieldSpec{
				"x": {
					TypeRef:     "primitive/string",
					Constraints: []entity.Entity{rogue},
				},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/unknown-c", map[string]interface{}{"x": "anything"})
		result, err := doValidate("validate/unknown-c", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result.Valid {
			return FailCheck("unknown constraint MUST NOT silent-pass (§1.2)")
		}
		for _, v := range result.Violations {
			if v.Kind == types.ViolationKindUnknownConstraint {
				return PassCheck("unknown constraint reported as kind=unknown_constraint")
			}
		}
		return FailCheck(fmt.Sprintf("no unknown_constraint violation: %+v", result.Violations))
	})

	r.Run("validate_unknown_format", func() CheckOutcome {
		fmtC, err := types.ConstraintFormatData{Format: "email"}.ToEntity()
		if err != nil {
			return SkipCheck(err.Error())
		}
		_, err = installType("validate/unknown-fmt", types.TypeDefinition{
			Name: "validate/unknown-fmt",
			Fields: map[string]types.FieldSpec{
				"v": {
					TypeRef:     "primitive/string",
					Constraints: []entity.Entity{fmtC},
				},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/unknown-fmt", map[string]interface{}{"v": "a@b.c"})
		result, err := doValidate("validate/unknown-fmt", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result.Valid {
			return FailCheck("unknown format MUST fail closed (§4.5)")
		}
		for _, v := range result.Violations {
			if v.Kind == types.ViolationKindUnknownConstraint {
				return PassCheck("unknown format reported as kind=unknown_constraint")
			}
		}
		return FailCheck(fmt.Sprintf("unknown format did not surface as unknown_constraint: %+v", result.Violations))
	})

	r.Run("validate_pcre_pattern_rejected", func() CheckOutcome {
		patC, err := types.ConstraintPatternData{Pattern: `(a)\1`}.ToEntity()
		if err != nil {
			return SkipCheck(err.Error())
		}
		_, err = installType("validate/pcre", types.TypeDefinition{
			Name: "validate/pcre",
			Fields: map[string]types.FieldSpec{
				"v": {
					TypeRef:     "primitive/string",
					Constraints: []entity.Entity{patC},
				},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		subj := mustEntity("validate/pcre", map[string]interface{}{"v": "aa"})
		result, err := doValidate("validate/pcre", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result.Valid {
			return FailCheck("PCRE backref pattern MUST be rejected — silent pass implies a backtracking engine (§12.1 violation)")
		}
		return PassCheck("PCRE-only pattern rejected (RE2 compliance §12.1)")
	})

	r.Run("validate_one_of_ecf_byte_equality", func() CheckOutcome {
		// Allowed list: ["alice", "bob", 42]. The dispatch envelope's
		// `values` field uses ECF-canonical encoding. The peer MUST
		// reproduce the same canonicalization on the input value to
		// determine membership — this is the §5.5 normative gate.
		mustRaw := func(v interface{}) cbor.RawMessage {
			raw, _ := ecf.Encode(v)
			return cbor.RawMessage(raw)
		}
		oneOf, err := types.ConstraintOneOfData{
			Values: []cbor.RawMessage{mustRaw("alice"), mustRaw("bob"), mustRaw(uint64(42))},
		}.ToEntity()
		if err != nil {
			return SkipCheck(err.Error())
		}
		_, err = installType("validate/one-of", types.TypeDefinition{
			Name: "validate/one-of",
			Fields: map[string]types.FieldSpec{
				"v": {
					TypeRef:     "primitive/string",
					Constraints: []entity.Entity{oneOf},
				},
			},
		})
		if err != nil {
			return SkipCheck("could not install test type: " + err.Error())
		}
		// Subject matching one of the values.
		subj := mustEntity("validate/one-of", map[string]interface{}{"v": "alice"})
		result, err := doValidate("validate/one-of", subj)
		if err != nil {
			return FailCheck(err.Error())
		}
		if !result.Valid {
			return FailCheck(fmt.Sprintf("ECF byte equality failed: 'alice' should match one_of[alice,bob,42]: %+v", result.Violations))
		}
		// And subject NOT in the list.
		subj2 := mustEntity("validate/one-of", map[string]interface{}{"v": "carol"})
		result2, err := doValidate("validate/one-of", subj2)
		if err != nil {
			return FailCheck(err.Error())
		}
		if result2.Valid {
			return FailCheck("'carol' should not match one_of[alice,bob,42]")
		}
		return PassCheck("one_of ECF byte equality gate green")
	})

	// --- Step 4: Optional analysis ops (compare, compatible, converge,
	// adopt, reconcile). These are best-effort. Implementations that
	// don't ship the op emit unknown_operation; that's conformant per
	// §12.2 / §12.3 — we Warn rather than Fail in that case.

	typeExecute := func(op string, params entity.Entity) (types.ExecuteResponseData, error) {
		uri := fmt.Sprintf("entity://%s/system/type", client.RemotePeerID())
		env, _, err := client.SendExecute(ctx, uri, op, params, nil)
		if err != nil {
			return types.ExecuteResponseData{}, err
		}
		return types.ExecuteResponseDataFromEntity(env.Root)
	}
	checkOptionalOp := func(opName, resultType string, params entity.Entity) CheckOutcome {
		respData, err := typeExecute(opName, params)
		if err != nil {
			return FailCheck("execute " + opName + ": " + err.Error())
		}
		if respData.Status == 400 {
			// May be "unknown_operation" — peer doesn't ship the op.
			return WarnCheck(opName + " not implemented (400 — acceptable for §12.2/§12.3 ops)")
		}
		if respData.Status != 200 {
			return FailCheck(fmt.Sprintf("%s returned status %d", opName, respData.Status))
		}
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return FailCheck("decode " + opName + " result: " + err.Error())
		}
		if resultType != "" && resultEntity.Type != resultType {
			return FailCheck(fmt.Sprintf("%s result type %q (want %q)", opName, resultEntity.Type, resultType))
		}
		return PassCheck(opName + " round-trips (status 200, result type " + resultEntity.Type + ")")
	}

	// Install three small types for analysis-op probing.
	mustInstallOpType := func(name string) bool {
		_, err := installType(name, types.TypeDefinition{
			Name: name,
			Fields: map[string]types.FieldSpec{
				"id":   {TypeRef: "primitive/string"},
				"note": {TypeRef: "primitive/string", Optional: true},
			},
		})
		return err == nil
	}

	r.Run("op_compare_roundtrip", func() CheckOutcome {
		if !mustInstallOpType("optest/a") || !mustInstallOpType("optest/b") {
			return SkipCheck("could not install probe types")
		}
		params, err := types.CompareRequestData{
			TypeA: "system/type/optest/a",
			TypeB: "system/type/optest/b",
		}.ToEntity()
		if err != nil {
			return SkipCheck("encode: " + err.Error())
		}
		return checkOptionalOp("compare", types.TypeTypeCompareResult, params)
	})

	r.Run("op_compatible_roundtrip", func() CheckOutcome {
		if !mustInstallOpType("optest/a") || !mustInstallOpType("optest/b") {
			return SkipCheck("could not install probe types")
		}
		params, err := types.CompatibleRequestData{
			TypeA:     "system/type/optest/a",
			TypeB:     "system/type/optest/b",
			Direction: types.DirectionBidirectional,
		}.ToEntity()
		if err != nil {
			return SkipCheck("encode: " + err.Error())
		}
		return checkOptionalOp("compatible", types.TypeTypeCompatibilityReport, params)
	})

	r.Run("op_converge_roundtrip", func() CheckOutcome {
		if !mustInstallOpType("optest/a") || !mustInstallOpType("optest/b") {
			return SkipCheck("could not install probe types")
		}
		params, err := types.ConvergeRequestData{
			TypePaths: []string{"system/type/optest/a", "system/type/optest/b"},
		}.ToEntity()
		if err != nil {
			return SkipCheck("encode: " + err.Error())
		}
		// converge returns system/type (the merged definition).
		return checkOptionalOp("converge", types.TypeType, params)
	})

	r.Run("op_adopt_roundtrip", func() CheckOutcome {
		if !mustInstallOpType("optest/a") {
			return SkipCheck("could not install probe type")
		}
		params, err := types.AdoptRequestData{
			SourcePath: "system/type/optest/a",
			LocalName:  "optest/adopted",
		}.ToEntity()
		if err != nil {
			return SkipCheck("encode: " + err.Error())
		}
		return checkOptionalOp("adopt", types.TypeType, params)
	})

	r.Run("op_reconcile_roundtrip", func() CheckOutcome {
		if !mustInstallOpType("optest/a") || !mustInstallOpType("optest/b") {
			return SkipCheck("could not install probe types")
		}
		params, err := types.ReconcileRequestData{
			TypePaths: []string{"system/type/optest/a", "system/type/optest/b"},
			Strategy:  types.ReconcileUnion,
		}.ToEntity()
		if err != nil {
			return SkipCheck("encode: " + err.Error())
		}
		return checkOptionalOp("reconcile", types.TypeTypeReconcileResult, params)
	})

	return r.Results()
}

// standardConstraintKinds enumerates the 11 §11.1 constraint kinds.
func standardConstraintKinds() []string {
	return []string{
		"min", "max",
		"min-length", "max-length",
		"min-count", "max-count",
		"pattern",
		"one-of", "not-one-of",
		"format",
		"type-pattern",
	}
}

// mustEntity is a tiny helper for fixture entities.
func mustEntity(typ string, data interface{}) entity.Entity {
	raw, err := ecf.Encode(data)
	if err != nil {
		panic(err)
	}
	e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		panic(err)
	}
	return e
}
