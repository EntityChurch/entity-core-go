package typeext

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// compareViaHandler runs compare via the full handler path so the dispatch
// envelope wiring is exercised end-to-end.
func (e *testEnv) compareViaHandler(t *testing.T, pathA, pathB string) types.CompareResultData {
	t.Helper()
	dispatch, err := types.CompareRequestData{TypeA: pathA, TypeB: pathB}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "compare",
		Params:    dispatch,
		Context:   e.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("compare status %d (%s)", resp.Status, resp.Result.Type)
	}
	var out types.CompareResultData
	if err := ecf.Decode(resp.Result.Data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *testEnv) compatibleViaHandler(t *testing.T, pathA, pathB, dir string) types.CompatibilityReportData {
	t.Helper()
	dispatch, err := types.CompatibleRequestData{TypeA: pathA, TypeB: pathB, Direction: dir}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "compatible",
		Params:    dispatch,
		Context:   e.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("compatible status %d (%s)", resp.Status, resp.Result.Type)
	}
	var out types.CompatibilityReportData
	if err := ecf.Decode(resp.Result.Data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCompareIdenticalTypes(t *testing.T) {
	env := newTestEnv(t)
	def := types.TypeDefinition{
		Name: "app/user",
		Fields: map[string]types.FieldSpec{
			"name": {TypeRef: "primitive/string"},
			"age":  {TypeRef: "primitive/uint", Optional: true},
		},
	}
	env.install(t, def)
	r := env.compareViaHandler(t, "system/type/app/user", "system/type/app/user")
	if len(r.OnlyA) != 0 || len(r.OnlyB) != 0 {
		t.Errorf("identical types should have no only_a / only_b: %+v", r)
	}
	if len(r.Incompatible) != 0 {
		t.Errorf("identical types should not have incompatibilities: %+v", r.Incompatible)
	}
	for name, fc := range r.Shared {
		if !fc.TypeMatch {
			t.Errorf("%s: type_match should be true", name)
		}
	}
}

func TestCompareDifferentFieldSets(t *testing.T) {
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
	r := env.compareViaHandler(t, "system/type/app/a", "system/type/app/b")
	if len(r.OnlyA) != 1 || r.OnlyA[0] != "only_a" {
		t.Errorf("OnlyA = %v, want [only_a]", r.OnlyA)
	}
	if len(r.OnlyB) != 1 || r.OnlyB[0] != "only_b" {
		t.Errorf("OnlyB = %v, want [only_b]", r.OnlyB)
	}
	if _, ok := r.Shared["shared"]; !ok {
		t.Errorf("shared field missing from comparison: %+v", r.Shared)
	}
}

func TestCompareFlagsIncompatibleShape(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/string"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/uint"},
		},
	})
	r := env.compareViaHandler(t, "system/type/app/a", "system/type/app/b")
	if len(r.Incompatible) != 1 || r.Incompatible[0].FieldName != "id" {
		t.Errorf("want one incompatibility on 'id', got %+v", r.Incompatible)
	}
	if r.Shared["id"].TypeMatch {
		t.Errorf("Shared[id].TypeMatch should be false")
	}
}

func TestCompatibleFullyCompatible(t *testing.T) {
	env := newTestEnv(t)
	def := types.TypeDefinition{
		Name:   "app/x",
		Fields: map[string]types.FieldSpec{"id": {TypeRef: "primitive/string"}},
	}
	env.install(t, def)
	r := env.compatibleViaHandler(t, "system/type/app/x", "system/type/app/x", types.DirectionBidirectional)
	if r.Level != types.CompatibilityFullyCompatible {
		t.Errorf("level = %s, want fully_compatible", r.Level)
	}
}

func TestCompatibleForwardOnly(t *testing.T) {
	// A has every required field of B + an extra. A → B works (forward).
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/big",
		Fields: map[string]types.FieldSpec{
			"id":    {TypeRef: "primitive/string"},
			"extra": {TypeRef: "primitive/string"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/small",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/string"},
		},
	})
	r := env.compatibleViaHandler(t, "system/type/app/big", "system/type/app/small", types.DirectionForward)
	if r.Level != types.CompatibilityForwardOnly && r.Level != types.CompatibilityFullyCompatible {
		t.Errorf("level = %s, want forward_only or fully_compatible", r.Level)
	}
}

func TestCompatibleIncompatible(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/string"},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"id": {TypeRef: "primitive/uint"}, // shape mismatch
		},
	})
	r := env.compatibleViaHandler(t, "system/type/app/a", "system/type/app/b", types.DirectionBidirectional)
	if r.Level != types.CompatibilityIncompatible {
		t.Errorf("level = %s, want incompatible", r.Level)
	}
}

func TestConstraintSetsEqual(t *testing.T) {
	a, _ := types.ConstraintMinData{Min: 1}.ToEntity()
	b, _ := types.ConstraintMinData{Min: 1}.ToEntity()
	c, _ := types.ConstraintMinData{Min: 2}.ToEntity()
	d, _ := types.ConstraintMaxData{Max: 10}.ToEntity()

	if !constraintSetsEqual([]entity.Entity{a, d}, []entity.Entity{d, b}) {
		t.Error("order-insensitive set equality should match {a,d} vs {d,b}")
	}
	if constraintSetsEqual([]entity.Entity{a}, []entity.Entity{c}) {
		t.Error("differing constraint data must not be equal")
	}
}
