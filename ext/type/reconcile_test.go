package typeext

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

func (e *testEnv) reconcileViaHandler(t *testing.T, paths []string, strategy string) types.ReconcileResultData {
	t.Helper()
	dispatch, err := types.ReconcileRequestData{TypePaths: paths, Strategy: strategy}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "reconcile",
		Params:    dispatch,
		Context:   e.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("reconcile status %d (%s)", resp.Status, resp.Result.Type)
	}
	if resp.Result.Type != types.TypeTypeReconcileResult {
		t.Fatalf("reconcile result type %q (want %s)", resp.Result.Type, types.TypeTypeReconcileResult)
	}
	var out types.ReconcileResultData
	if err := ecf.Decode(resp.Result.Data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeMergedDef(t *testing.T, r types.ReconcileResultData) types.TypeDefinition {
	t.Helper()
	var d types.TypeDefinition
	if err := ecf.Decode(r.ReconciledType, &d); err != nil {
		t.Fatalf("decode reconciled_type: %v", err)
	}
	return d
}

func TestReconcileIntersect(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"shared": {TypeRef: "primitive/string"},
			"only_a": {TypeRef: "primitive/uint"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"shared": {TypeRef: "primitive/string"},
			"only_b": {TypeRef: "primitive/uint"},
		},
	})
	r := env.reconcileViaHandler(t, []string{"system/type/app/a", "system/type/app/b"}, types.ReconcileIntersect)
	merged := decodeMergedDef(t, r)
	if _, ok := merged.Fields["shared"]; !ok {
		t.Error("intersect should keep shared")
	}
	if _, ok := merged.Fields["only_a"]; ok {
		t.Error("intersect should drop only_a")
	}
	if _, ok := merged.Fields["only_b"]; ok {
		t.Error("intersect should drop only_b")
	}
	if len(r.FieldsDropped) != 2 {
		t.Errorf("FieldsDropped: %v", r.FieldsDropped)
	}
}

func TestReconcileUnionMakesUniqueFieldsOptional(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"shared": {TypeRef: "primitive/string"},
			"phone":  {TypeRef: "primitive/string"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"shared":  {TypeRef: "primitive/string"},
			"address": {TypeRef: "primitive/string"},
		},
	})
	r := env.reconcileViaHandler(t, []string{"system/type/app/a", "system/type/app/b"}, types.ReconcileUnion)
	merged := decodeMergedDef(t, r)
	if !merged.Fields["phone"].Optional {
		t.Error("union should make 'phone' optional (only in a)")
	}
	if !merged.Fields["address"].Optional {
		t.Error("union should make 'address' optional (only in b)")
	}
	if merged.Fields["shared"].Optional {
		t.Error("union should leave 'shared' required (in all inputs)")
	}
	if len(r.FieldsMadeOptional) != 2 {
		t.Errorf("FieldsMadeOptional = %v", r.FieldsMadeOptional)
	}
}

func TestReconcileUnionReportsIncompatibleShapes(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name:   "app/a",
		Fields: map[string]types.FieldSpec{"id": {TypeRef: "primitive/string"}},
	})
	env.install(t, types.TypeDefinition{
		Name:   "app/b",
		Fields: map[string]types.FieldSpec{"id": {TypeRef: "primitive/uint"}},
	})
	r := env.reconcileViaHandler(t, []string{"system/type/app/a", "system/type/app/b"}, types.ReconcileUnion)
	if len(r.Incompatibilities) != 1 || r.Incompatibilities[0].FieldName != "id" {
		t.Errorf("expected one incompatibility on 'id', got %+v", r.Incompatibilities)
	}
	merged := decodeMergedDef(t, r)
	if _, ok := merged.Fields["id"]; ok {
		t.Error("union should exclude incompatible 'id' from merged fields")
	}
}

func TestReconcilePreferKeepsFirstInputShape(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/pref",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/string"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/other",
		Fields: map[string]types.FieldSpec{
			"id":    {TypeRef: "primitive/uint"}, // incompatible
			"extra": {TypeRef: "primitive/string"},
		},
	})
	r := env.reconcileViaHandler(t, []string{"system/type/app/pref", "system/type/app/other"}, types.ReconcilePrefer)
	merged := decodeMergedDef(t, r)
	idSpec := merged.Fields["id"]
	if idSpec.TypeRef != "primitive/string" {
		t.Errorf("prefer should keep pref's id shape, got %+v", idSpec)
	}
	if !merged.Fields["extra"].Optional {
		t.Error("prefer should add other's 'extra' as optional")
	}
	if len(r.Incompatibilities) != 1 {
		t.Errorf("expected one incompatibility on 'id', got %+v", r.Incompatibilities)
	}
}

func TestReconcileRejectsBadStrategy(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{Name: "app/x"})
	env.install(t, types.TypeDefinition{Name: "app/y"})
	dispatch, err := types.ReconcileRequestData{
		TypePaths: []string{"system/type/app/x", "system/type/app/y"},
		Strategy:  "nonsense",
	}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "reconcile", Params: dispatch, Context: env.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Errorf("bad strategy: status %d (want 400)", resp.Status)
	}
	// EXTENSION-TYPE Appendix A (v1.3) reserves the type-analysis 400 slot for
	// `invalid_request` — a bad strategy is a structural defect of the request,
	// and the table defines no `invalid_strategy` for these ops (that code is
	// EXTENSION-REVISION merge-config's, a different operation). Converged to
	// join the cohort (core-py already emits invalid_request here). SA-PY-40.
	ed, err := types.ErrorDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode error entity: %v", err)
	}
	if ed.Code != "invalid_request" {
		t.Errorf("bad strategy: code %q (want invalid_request per Appendix A)", ed.Code)
	}
}

// TestReconcileDecodeFailureIsInvalidRequest pins the Appendix A row-1 converge:
// undecodable params answer 400 invalid_request, not the pre-fold decode_error.
func TestReconcileDecodeFailureIsInvalidRequest(t *testing.T) {
	env := newTestEnv(t)
	// Valid CBOR at the entity level (a bare integer) so the entity constructs,
	// but undecodable as a reconcile-request struct — exercises the decode arm.
	badData, err := ecf.Encode(42)
	if err != nil {
		t.Fatal(err)
	}
	garbage, err := entity.NewEntity("system/type/reconcile-request", badData)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "reconcile", Params: garbage, Context: env.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Fatalf("undecodable reconcile: status %d (want 400)", resp.Status)
	}
	ed, err := types.ErrorDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode error entity: %v", err)
	}
	if ed.Code != "invalid_request" {
		t.Errorf("undecodable reconcile: code %q (want invalid_request per Appendix A row 1)", ed.Code)
	}
}

func TestReconcileUnionLeastRestrictiveConstraints(t *testing.T) {
	env := newTestEnv(t)
	commonMin, _ := types.ConstraintMinData{Min: 0}.ToEntity()
	aOnlyMax, _ := types.ConstraintMaxData{Max: 100}.ToEntity()
	bOnlyMax, _ := types.ConstraintMaxData{Max: 50}.ToEntity()
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{commonMin, aOnlyMax}},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{commonMin, bOnlyMax}},
		},
	})
	r := env.reconcileViaHandler(t, []string{"system/type/app/a", "system/type/app/b"}, types.ReconcileUnion)
	merged := decodeMergedDef(t, r)
	// Union strategy = least restrictive: keep ONLY constraints both
	// inputs agreed on. commonMin is shared; the differing max
	// constraints (100 vs 50) get dropped.
	if len(merged.Fields["v"].Constraints) != 1 {
		t.Errorf("union should keep only the 1 shared constraint, got %d: %+v",
			len(merged.Fields["v"].Constraints), merged.Fields["v"].Constraints)
	}
	if merged.Fields["v"].Constraints[0].Type != types.TypeConstraintMin {
		t.Errorf("kept constraint type = %s, want %s",
			merged.Fields["v"].Constraints[0].Type, types.TypeConstraintMin)
	}
}
