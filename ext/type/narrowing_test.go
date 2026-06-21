package typeext

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// validateTypeDef stores the type def and then runs the narrowing check
// directly via verifyNarrowing. The full validate flow's Phase 1 wants the
// meta-type system/type to exist in the tree, which isn't relevant to the
// narrowing rules — we test those in isolation.
//
// The returned ValidateResultData is shaped like the full result so each
// test can inspect Violations the same way it would over the wire.
func (e *testEnv) validateTypeDef(t *testing.T, def types.TypeDefinition) types.ValidateResultData {
	t.Helper()
	e.install(t, def)
	hctx := e.hctx()
	vs := verifyNarrowing(hctx, def)
	return types.ValidateResultData{Valid: len(vs) == 0, Violations: vs}
}

func mustConstraint(t *testing.T, fn func() (entity.Entity, error)) entity.Entity {
	t.Helper()
	e, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestNarrowingMinNarrower(t *testing.T) {
	env := newTestEnv(t)
	parentMin := mustConstraint(t, types.ConstraintMinData{Min: 0}.ToEntity)
	childMin := mustConstraint(t, types.ConstraintMinData{Min: 1}.ToEntity)

	env.install(t, types.TypeDefinition{
		Name: "app/age-parent",
		Fields: map[string]types.FieldSpec{
			"age": {TypeRef: "primitive/uint", Constraints: []entity.Entity{parentMin}},
		},
	})

	r := env.validateTypeDef(t, types.TypeDefinition{
		Name:    "app/age-child",
		Extends: "app/age-parent",
		Fields: map[string]types.FieldSpec{
			"age": {TypeRef: "primitive/uint", Constraints: []entity.Entity{childMin}},
		},
	})

	if !r.Valid {
		t.Fatalf("child.min >= parent.min should narrow: %+v", r.Violations)
	}
}

func TestNarrowingMinWiderRejected(t *testing.T) {
	env := newTestEnv(t)
	parentMin := mustConstraint(t, types.ConstraintMinData{Min: 1}.ToEntity)
	childMin := mustConstraint(t, types.ConstraintMinData{Min: 0}.ToEntity)

	env.install(t, types.TypeDefinition{
		Name: "app/age-parent",
		Fields: map[string]types.FieldSpec{
			"age": {TypeRef: "primitive/uint", Constraints: []entity.Entity{parentMin}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name:    "app/age-child",
		Extends: "app/age-parent",
		Fields: map[string]types.FieldSpec{
			"age": {TypeRef: "primitive/uint", Constraints: []entity.Entity{childMin}},
		},
	})
	if r.Valid {
		t.Fatal("child.min < parent.min must be rejected")
	}
}

func TestNarrowingMaxNarrower(t *testing.T) {
	env := newTestEnv(t)
	parentMax := mustConstraint(t, types.ConstraintMaxData{Max: 100}.ToEntity)
	childMax := mustConstraint(t, types.ConstraintMaxData{Max: 50}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{parentMax}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{childMax}},
		},
	})
	if !r.Valid {
		t.Fatalf("narrower max should pass: %+v", r.Violations)
	}
}

func TestNarrowingChildRemovesParentConstraintRejected(t *testing.T) {
	env := newTestEnv(t)
	parentMin := mustConstraint(t, types.ConstraintMinData{Min: 1}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{parentMin}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint"}, // no constraints — removed!
		},
	})
	if r.Valid {
		t.Fatal("child removing parent constraint must be rejected")
	}
}

func TestNarrowingChildOmitsFieldInheritsConstraints(t *testing.T) {
	// §6.3: parent field absent on child = child inherits parent
	// unchanged; narrowing is satisfied trivially.
	env := newTestEnv(t)
	parentMin := mustConstraint(t, types.ConstraintMinData{Min: 1}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/uint", Constraints: []entity.Entity{parentMin}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		// No fields declared at all — inheriting from parent.
	})
	if !r.Valid {
		t.Fatalf("child omitting field inherits parent constraints unchanged: %+v", r.Violations)
	}
}

func TestNarrowingPatternEqualOnly(t *testing.T) {
	env := newTestEnv(t)
	parentPat := mustConstraint(t, types.ConstraintPatternData{Pattern: "^[a-z]+$"}.ToEntity)
	childPat := mustConstraint(t, types.ConstraintPatternData{Pattern: "^[a-z]+$"}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parentPat}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{childPat}},
		},
	})
	if !r.Valid {
		t.Fatalf("equal patterns must narrow: %+v", r.Violations)
	}

	// Now a different-but-arguably-narrower regex — v1.1 §6.2 rejects it
	// as incomparable.
	childPatDifferent := mustConstraint(t, types.ConstraintPatternData{Pattern: "^[a-c]+$"}.ToEntity)
	env2 := newTestEnv(t)
	env2.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parentPat}},
		},
	})
	r = env2.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{childPatDifferent}},
		},
	})
	if r.Valid {
		t.Fatal("non-equal patterns MUST be incomparable per v1.1 §6.2 — speculative subset is forbidden")
	}
}

func TestNarrowingFormatEqualOnly(t *testing.T) {
	env := newTestEnv(t)
	parentFmt := mustConstraint(t, types.ConstraintFormatData{Format: types.FormatURI}.ToEntity)
	childFmtEqual := mustConstraint(t, types.ConstraintFormatData{Format: types.FormatURI}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parentFmt}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{childFmtEqual}},
		},
	})
	if !r.Valid {
		t.Fatalf("equal format names must narrow: %+v", r.Violations)
	}

	// Different format name → incomparable, even if a deployment thinks
	// of it as "narrower".
	env2 := newTestEnv(t)
	childFmtDiff := mustConstraint(t, types.ConstraintFormatData{Format: types.FormatDate}.ToEntity)
	env2.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parentFmt}},
		},
	})
	r = env2.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{childFmtDiff}},
		},
	})
	if r.Valid {
		t.Fatal("non-equal format names MUST be incomparable per v1.1 §6.2")
	}
}

func TestNarrowingOneOfSubset(t *testing.T) {
	mustRaw := func(v interface{}) cbor.RawMessage {
		t.Helper()
		raw, err := ecf.Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		return cbor.RawMessage(raw)
	}
	env := newTestEnv(t)
	parent := mustConstraint(t, types.ConstraintOneOfData{
		Values: []cbor.RawMessage{mustRaw("a"), mustRaw("b"), mustRaw("c")},
	}.ToEntity)
	child := mustConstraint(t, types.ConstraintOneOfData{
		Values: []cbor.RawMessage{mustRaw("a"), mustRaw("b")},
	}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parent}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{child}},
		},
	})
	if !r.Valid {
		t.Fatalf("one_of subset should narrow: %+v", r.Violations)
	}

	// Child adds a value the parent didn't allow → not a subset → reject.
	env2 := newTestEnv(t)
	childExtra := mustConstraint(t, types.ConstraintOneOfData{
		Values: []cbor.RawMessage{mustRaw("a"), mustRaw("z")},
	}.ToEntity)
	env2.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parent}},
		},
	})
	r = env2.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{childExtra}},
		},
	})
	if r.Valid {
		t.Fatal("one_of widening must be rejected")
	}
}

func TestNarrowingNotOneOfSuperset(t *testing.T) {
	mustRaw := func(v interface{}) cbor.RawMessage {
		raw, _ := ecf.Encode(v)
		return cbor.RawMessage(raw)
	}
	env := newTestEnv(t)
	parent := mustConstraint(t, types.ConstraintNotOneOfData{
		Values: []cbor.RawMessage{mustRaw("a")},
	}.ToEntity)
	child := mustConstraint(t, types.ConstraintNotOneOfData{
		Values: []cbor.RawMessage{mustRaw("a"), mustRaw("b")},
	}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{parent}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "primitive/string", Constraints: []entity.Entity{child}},
		},
	})
	if !r.Valid {
		t.Fatalf("not_one_of superset should narrow: %+v", r.Violations)
	}
}

func TestNarrowingTypePatternMoreSpecific(t *testing.T) {
	env := newTestEnv(t)
	parent := mustConstraint(t, types.ConstraintTypePatternData{Pattern: "system/capability/*"}.ToEntity)
	child := mustConstraint(t, types.ConstraintTypePatternData{Pattern: "system/capability/grant"}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "system/hash", Constraints: []entity.Entity{parent}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "system/hash", Constraints: []entity.Entity{child}},
		},
	})
	if !r.Valid {
		t.Fatalf("more-specific type_pattern should narrow: %+v", r.Violations)
	}
}

func TestNarrowingTypePatternWiderRejected(t *testing.T) {
	env := newTestEnv(t)
	parent := mustConstraint(t, types.ConstraintTypePatternData{Pattern: "system/capability/grant"}.ToEntity)
	child := mustConstraint(t, types.ConstraintTypePatternData{Pattern: "system/capability/*"}.ToEntity)
	env.install(t, types.TypeDefinition{
		Name: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "system/hash", Constraints: []entity.Entity{parent}},
		},
	})
	r := env.validateTypeDef(t, types.TypeDefinition{
		Name: "c", Extends: "p",
		Fields: map[string]types.FieldSpec{
			"v": {TypeRef: "system/hash", Constraints: []entity.Entity{child}},
		},
	})
	if r.Valid {
		t.Fatal("widening type_pattern must be rejected")
	}
}
