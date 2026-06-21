package typeext

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

func (e *testEnv) convergeViaHandler(t *testing.T, paths []string) types.TypeDefinition {
	t.Helper()
	dispatch, err := types.ConvergeRequestData{TypePaths: paths}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "converge",
		Params:    dispatch,
		Context:   e.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("converge status %d (%s)", resp.Status, resp.Result.Type)
	}
	if resp.Result.Type != types.TypeType {
		t.Fatalf("converge result type %q (want system/type)", resp.Result.Type)
	}
	var def types.TypeDefinition
	if err := ecf.Decode(resp.Result.Data, &def); err != nil {
		t.Fatal(err)
	}
	return def
}

func TestConvergeIntersectsShape(t *testing.T) {
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
	out := env.convergeViaHandler(t, []string{
		"system/type/app/a", "system/type/app/b",
	})
	if _, ok := out.Fields["shared"]; !ok {
		t.Errorf("converge should keep 'shared': %+v", out.Fields)
	}
	if _, ok := out.Fields["only_a"]; ok {
		t.Error("converge should drop fields unique to one input")
	}
	if _, ok := out.Fields["only_b"]; ok {
		t.Error("converge should drop fields unique to one input")
	}
}

func TestConvergeDropsIncompatibleShape(t *testing.T) {
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
	out := env.convergeViaHandler(t, []string{
		"system/type/app/a", "system/type/app/b",
	})
	if _, ok := out.Fields["id"]; ok {
		t.Error("converge should drop fields with incompatible shapes")
	}
}

func TestConvergeMergesConstraintsRestrictively(t *testing.T) {
	env := newTestEnv(t)
	minA, _ := types.ConstraintMinData{Min: 0}.ToEntity()
	maxA, _ := types.ConstraintMaxData{Max: 100}.ToEntity()
	maxB, _ := types.ConstraintMaxData{Max: 50}.ToEntity()
	env.install(t, types.TypeDefinition{
		Name: "app/a",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{minA, maxA}},
		},
	})
	env.install(t, types.TypeDefinition{
		Name: "app/b",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{maxB}},
		},
	})
	out := env.convergeViaHandler(t, []string{
		"system/type/app/a", "system/type/app/b",
	})
	v, ok := out.Fields["v"]
	if !ok {
		t.Fatal("converge should keep 'v'")
	}
	// Converge keeps every constraint across all inputs (intersection of
	// allowed-value sets = union of constraint exclusions). So we expect
	// min (from A), max=100 (from A), max=50 (from B) — all three present,
	// deduped only when ECF-canonical-equal.
	if len(v.Constraints) != 3 {
		t.Errorf("expected 3 constraints (min0, max100, max50), got %d: %+v",
			len(v.Constraints), v.Constraints)
	}
}

func TestConvergeRejectsTooFewInputs(t *testing.T) {
	env := newTestEnv(t)
	dispatch, err := types.ConvergeRequestData{TypePaths: []string{"system/type/x"}}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "converge",
		Params:    dispatch,
		Context:   env.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 400 {
		t.Errorf("converge with 1 path: status %d (want 400)", resp.Status)
	}
}
