package typeext

import (
	"context"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

func (e *testEnv) adoptViaHandler(t *testing.T, sourcePath, localName string) types.TypeDefinition {
	t.Helper()
	dispatch, err := types.AdoptRequestData{SourcePath: sourcePath, LocalName: localName}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "adopt",
		Params:    dispatch,
		Context:   e.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("adopt status %d", resp.Status)
	}
	if resp.Result.Type != types.TypeType {
		t.Fatalf("adopt result type %q (want system/type)", resp.Result.Type)
	}
	var def types.TypeDefinition
	if err := ecf.Decode(resp.Result.Data, &def); err != nil {
		t.Fatal(err)
	}
	return def
}

func TestAdoptRewritesName(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "sensor/temperature",
		Fields: map[string]types.FieldSpec{
			"value": {TypeRef: "primitive/float"},
		},
	})
	got := env.adoptViaHandler(t, "system/type/sensor/temperature", "sensor/temp-local")
	if got.Name != "sensor/temp-local" {
		t.Errorf("adopt name = %q, want sensor/temp-local", got.Name)
	}
	if _, ok := got.Fields["value"]; !ok {
		t.Error("adopt should preserve fields")
	}
}

func TestAdoptDerivesNameWhenOmitted(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "sensor/humidity",
		Fields: map[string]types.FieldSpec{
			"value": {TypeRef: "primitive/float"},
		},
	})
	// Omit local_name — should derive from source_path.
	got := env.adoptViaHandler(t, "system/type/sensor/humidity", "")
	if got.Name != "sensor/humidity" {
		t.Errorf("adopt name = %q, want sensor/humidity (derived)", got.Name)
	}
}

func TestAdoptNormalizesAbsoluteExtends(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "sensor/base",
	})
	env.install(t, types.TypeDefinition{
		Name:    "sensor/specialized",
		Extends: "/REMOTEPEERID/system/type/sensor/base",
	})
	got := env.adoptViaHandler(t, "system/type/sensor/specialized", "sensor/local")
	// After adopt the extends reference should be the bare name so the
	// local resolver can find it at system/type/sensor/base.
	if got.Extends != "sensor/base" {
		t.Errorf("adopt extends = %q, want bare name 'sensor/base'", got.Extends)
	}
}

func TestAdoptPreservesPeerRelativeExtends(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "sensor/base",
	})
	env.install(t, types.TypeDefinition{
		Name:    "sensor/specialized",
		Extends: "sensor/base", // already peer-relative
	})
	got := env.adoptViaHandler(t, "system/type/sensor/specialized", "sensor/specialized-local")
	if got.Extends != "sensor/base" {
		t.Errorf("adopt extends = %q, want sensor/base (preserved)", got.Extends)
	}
}

func TestAdoptMissingSource(t *testing.T) {
	env := newTestEnv(t)
	dispatch, err := types.AdoptRequestData{SourcePath: "system/type/does/not/exist"}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := env.typeHandler.Handle(context.Background(), &handler.Request{
		Operation: "adopt",
		Params:    dispatch,
		Context:   env.hctx(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Errorf("adopt missing source: status %d (want 404)", resp.Status)
	}
}
