package compute

import (
	"bytes"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// testCtx creates a minimal EvalContext backed by a memory content store.
func testCtx() (*EvalContext, store.ContentStore) {
	cs := store.NewMemoryContentStore()
	return &EvalContext{
		ContentStore: cs,
		Included:     make(map[hash.Hash]entity.Entity),
	}, cs
}

// mustPut stores an entity and returns its content hash.
func mustPut(t *testing.T, cs store.ContentStore, ent entity.Entity) hash.Hash {
	t.Helper()
	h, err := cs.Put(ent)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	return h
}

// mustE unwraps a (entity.Entity, error) pair.
func mustE(ent entity.Entity, err error) entity.Entity {
	if err != nil {
		panic("ToEntity failed: " + err.Error())
	}
	return ent
}

func TestEvalLiteral(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLiteralData{Value: int64(42)}.ToEntity())

	result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CBOR roundtrip: positive int64 decodes as uint64.
	rv, ok := toFloat64(result)
	if !ok || rv != 42 {
		t.Fatalf("expected 42, got %v (%T)", result, result)
	}
}

func TestEvalLiteralString(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLiteralData{Value: "hello"}.ToEntity())

	result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Fatalf("expected 'hello', got %v", result)
	}
}

func TestEvalLookupScope(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	scope := NewScope()
	scope.Set("x", int64(99))

	result, err := Evaluate(ent, scope, DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != int64(99) {
		t.Fatalf("expected 99, got %v", result)
	}
}

func TestEvalLookupScopeMissing(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLookupScopeData{Name: "missing"}.ToEntity())

	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected error for missing scope binding")
	}
	ce, ok := err.(*ComputeError)
	if !ok {
		t.Fatalf("expected ComputeError, got %T", err)
	}
	if ce.Code != ErrNotFound {
		t.Fatalf("expected not_found, got %s", ce.Code)
	}
}

func TestEvalArithmetic(t *testing.T) {
	tests := []struct {
		op     string
		left   interface{}
		right  interface{}
		expect interface{}
	}{
		// Per v3.16 rule 10: integer results encode signed → Go's int64.
		{"add", int64(3), int64(4), int64(7)},
		{"sub", int64(10), int64(3), int64(7)},
		{"mul", int64(5), int64(6), int64(30)},
		{"div", int64(10), int64(2), int64(5)},
		{"mod", int64(10), int64(3), int64(1)},
		{"add", float64(1.5), float64(2.5), float64(4.0)},
		{"div", int64(7), int64(2), float64(3.5)},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			ctx, cs := testCtx()
			leftEnt := mustE(types.ComputeLiteralData{Value: tt.left}.ToEntity())
			rightEnt := mustE(types.ComputeLiteralData{Value: tt.right}.ToEntity())
			leftHash := mustPut(t, cs, leftEnt)
			rightHash := mustPut(t, cs, rightEnt)

			arithEnt := mustE(types.ComputeArithmeticData{
				Op: tt.op, Left: leftHash, Right: rightHash,
			}.ToEntity())

			result, err := Evaluate(arithEnt, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expect {
				t.Fatalf("expected %v (%T), got %v (%T)", tt.expect, tt.expect, result, result)
			}
		})
	}
}

func TestEvalDivisionByZero(t *testing.T) {
	ctx, cs := testCtx()
	leftEnt := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	rightEnt := mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity())
	leftHash := mustPut(t, cs, leftEnt)
	rightHash := mustPut(t, cs, rightEnt)

	arithEnt := mustE(types.ComputeArithmeticData{
		Op: "div", Left: leftHash, Right: rightHash,
	}.ToEntity())

	_, err := Evaluate(arithEnt, NewScope(), DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected division by zero error")
	}
	ce := err.(*ComputeError)
	if ce.Code != ErrDivisionByZero {
		t.Fatalf("expected division_by_zero, got %s", ce.Code)
	}
}

func TestEvalCompare(t *testing.T) {
	tests := []struct {
		op     string
		left   interface{}
		right  interface{}
		expect bool
	}{
		{"eq", int64(5), int64(5), true},
		{"eq", int64(5), int64(6), false},
		{"neq", int64(5), int64(6), true},
		{"lt", int64(3), int64(5), true},
		{"gt", int64(5), int64(3), true},
		{"lte", int64(5), int64(5), true},
		{"gte", int64(5), int64(5), true},
		{"eq", "abc", "abc", true},
		{"lt", "a", "b", true},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			ctx, cs := testCtx()
			leftEnt := mustE(types.ComputeLiteralData{Value: tt.left}.ToEntity())
			rightEnt := mustE(types.ComputeLiteralData{Value: tt.right}.ToEntity())
			leftHash := mustPut(t, cs, leftEnt)
			rightHash := mustPut(t, cs, rightEnt)

			cmpEnt := mustE(types.ComputeCompareData{
				Op: tt.op, Left: leftHash, Right: rightHash,
			}.ToEntity())

			result, err := Evaluate(cmpEnt, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expect {
				t.Fatalf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestEvalLogic(t *testing.T) {
	ctx, cs := testCtx()
	trueEnt := mustE(types.ComputeLiteralData{Value: true}.ToEntity())
	falseEnt := mustE(types.ComputeLiteralData{Value: false}.ToEntity())
	trueHash := mustPut(t, cs, trueEnt)
	falseHash := mustPut(t, cs, falseEnt)

	t.Run("and_true", func(t *testing.T) {
		ent := mustE(types.ComputeLogicData{Op: "and", Left: trueHash, Right: &trueHash}.ToEntity())
		result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != true {
			t.Fatalf("expected true, got %v", result)
		}
	})

	t.Run("and_false", func(t *testing.T) {
		ent := mustE(types.ComputeLogicData{Op: "and", Left: trueHash, Right: &falseHash}.ToEntity())
		result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != false {
			t.Fatalf("expected false, got %v", result)
		}
	})

	t.Run("or", func(t *testing.T) {
		ent := mustE(types.ComputeLogicData{Op: "or", Left: falseHash, Right: &trueHash}.ToEntity())
		result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != true {
			t.Fatalf("expected true, got %v", result)
		}
	})

	t.Run("not", func(t *testing.T) {
		ent := mustE(types.ComputeLogicData{Op: "not", Left: trueHash}.ToEntity())
		result, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != false {
			t.Fatalf("expected false, got %v", result)
		}
	})
}

func TestEvalIf(t *testing.T) {
	ctx, cs := testCtx()
	trueEnt := mustE(types.ComputeLiteralData{Value: true}.ToEntity())
	thenEnt := mustE(types.ComputeLiteralData{Value: "yes"}.ToEntity())
	elseEnt := mustE(types.ComputeLiteralData{Value: "no"}.ToEntity())
	trueHash := mustPut(t, cs, trueEnt)
	thenHash := mustPut(t, cs, thenEnt)
	elseHash := mustPut(t, cs, elseEnt)

	ifEnt := mustE(types.ComputeIfData{
		Condition: trueHash, Then: thenHash, Else: &elseHash,
	}.ToEntity())

	result, err := Evaluate(ifEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "yes" {
		t.Fatalf("expected 'yes', got %v", result)
	}
}

func TestEvalIfFalse(t *testing.T) {
	ctx, cs := testCtx()
	falseEnt := mustE(types.ComputeLiteralData{Value: false}.ToEntity())
	thenEnt := mustE(types.ComputeLiteralData{Value: "yes"}.ToEntity())
	elseEnt := mustE(types.ComputeLiteralData{Value: "no"}.ToEntity())
	falseHash := mustPut(t, cs, falseEnt)
	thenHash := mustPut(t, cs, thenEnt)
	elseHash := mustPut(t, cs, elseEnt)

	ifEnt := mustE(types.ComputeIfData{
		Condition: falseHash, Then: thenHash, Else: &elseHash,
	}.ToEntity())

	result, err := Evaluate(ifEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "no" {
		t.Fatalf("expected 'no', got %v", result)
	}
}

func TestEvalLet(t *testing.T) {
	ctx, cs := testCtx()

	// let x = 5, y = x + 1 in y
	lit5 := mustE(types.ComputeLiteralData{Value: int64(5)}.ToEntity())
	lit1 := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	lookupX := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	lookupY := mustE(types.ComputeLookupScopeData{Name: "y"}.ToEntity())

	lit5Hash := mustPut(t, cs, lit5)
	lit1Hash := mustPut(t, cs, lit1)
	lookupXHash := mustPut(t, cs, lookupX)
	lookupYHash := mustPut(t, cs, lookupY)

	// x + 1
	addEnt := mustE(types.ComputeArithmeticData{
		Op: "add", Left: lookupXHash, Right: lit1Hash,
	}.ToEntity())
	addHash := mustPut(t, cs, addEnt)

	letEnt := mustE(types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{
			{Name: "x", Value: lit5Hash},
			{Name: "y", Value: addHash},
		},
		Body: lookupYHash,
	}.ToEntity())

	result, err := Evaluate(letEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != int64(6) {
		t.Fatalf("expected 6, got %v (%T)", result, result)
	}
}

func TestEvalLambdaAndApply(t *testing.T) {
	ctx, cs := testCtx()

	// lambda(a): a + 1, then apply with a=10
	lookupA := mustE(types.ComputeLookupScopeData{Name: "a"}.ToEntity())
	lit1 := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	lookupAHash := mustPut(t, cs, lookupA)
	lit1Hash := mustPut(t, cs, lit1)

	bodyEnt := mustE(types.ComputeArithmeticData{
		Op: "add", Left: lookupAHash, Right: lit1Hash,
	}.ToEntity())
	bodyHash := mustPut(t, cs, bodyEnt)

	lambdaEnt := mustE(types.ComputeLambdaData{
		Params: []string{"a"},
		Body:   bodyHash,
	}.ToEntity())

	// Evaluate lambda to get closure.
	closureVal, err := Evaluate(lambdaEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("lambda eval failed: %v", err)
	}
	closureEntity, ok := closureVal.(entity.Entity)
	if !ok {
		t.Fatalf("expected entity.Entity, got %T", closureVal)
	}
	if closureEntity.Type != types.TypeComputeClosure {
		t.Fatalf("expected compute/closure, got %s", closureEntity.Type)
	}

	// Store closure and apply it.
	closureHash := mustPut(t, cs, closureEntity)
	argEnt := mustE(types.ComputeLiteralData{Value: int64(10)}.ToEntity())
	argHash := mustPut(t, cs, argEnt)

	applyEnt := mustE(types.ComputeApplyData{
		Fn:   closureHash,
		Args: map[string]hash.Hash{"a": argHash},
	}.ToEntity())

	result, err := Evaluate(applyEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result != int64(11) {
		t.Fatalf("expected 11, got %v (%T)", result, result)
	}
}

func TestEvalBudgetExhausted(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())

	budget := NewBudget(2, 100)
	_, err := Evaluate(ent, NewScope(), budget, ctx)
	if err != nil {
		t.Fatalf("should succeed with budget=2: %v", err)
	}

	budget = NewBudget(1, 100)
	_, err = Evaluate(ent, NewScope(), budget, ctx)
	if err == nil {
		t.Fatal("expected budget_exhausted error")
	}
	ce := err.(*ComputeError)
	if ce.Code != ErrBudgetExhausted {
		t.Fatalf("expected budget_exhausted, got %s", ce.Code)
	}
}

func TestEvalDepthExceeded(t *testing.T) {
	ctx, _ := testCtx()
	ent := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())

	budget := NewBudget(100, 0)
	_, err := Evaluate(ent, NewScope(), budget, ctx)
	if err == nil {
		t.Fatal("expected depth_exceeded error")
	}
	ce := err.(*ComputeError)
	if ce.Code != ErrDepthExceeded {
		t.Fatalf("expected depth_exceeded, got %s", ce.Code)
	}
}

func TestEvalTruthiness(t *testing.T) {
	tests := []struct {
		name   string
		value  interface{}
		expect bool
	}{
		{"nil", nil, false},
		{"false", false, false},
		{"true", true, true},
		{"zero_int", int64(0), false},
		{"nonzero_int", int64(1), true},
		{"zero_uint", uint64(0), false},
		{"nonzero_uint", uint64(1), true},
		{"zero_float", float64(0), false},
		{"nonzero_float", float64(0.1), true},
		{"empty_string", "", false},
		{"nonempty_string", "x", true},
		{"empty_slice", []interface{}{}, false},
		{"nonempty_slice", []interface{}{1}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if truthy(tt.value) != tt.expect {
				t.Fatalf("truthy(%v) = %v, want %v", tt.value, !tt.expect, tt.expect)
			}
		})
	}
}

func TestEvalConstruct(t *testing.T) {
	ctx, cs := testCtx()

	nameEnt := mustE(types.ComputeLiteralData{Value: "test-name"}.ToEntity())
	nameHash := mustPut(t, cs, nameEnt)

	constructEnt := mustE(types.ComputeConstructData{
		EntityType: "app/thing",
		Fields:     map[string]hash.Hash{"name": nameHash},
	}.ToEntity())

	result, err := Evaluate(constructEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// v3.19c Part A R3 (M3): Evaluate returns the in-flight *constructedValue;
	// materialize() at a boundary converts it to a bare entity.Entity.
	cv, ok := result.(*constructedValue)
	if !ok {
		t.Fatalf("expected *constructedValue, got %T", result)
	}
	if cv.entityType != "app/thing" {
		t.Fatalf("expected entityType app/thing, got %s", cv.entityType)
	}
	mat, err := materialize(cv, cs)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	resultEnt, ok := mat.(entity.Entity)
	if !ok {
		t.Fatalf("expected materialized entity.Entity, got %T", mat)
	}
	if resultEnt.Type != "app/thing" {
		t.Fatalf("expected type app/thing, got %s", resultEnt.Type)
	}
}

// TestEvalFieldReadbackReturnsBareHash is the Go-side regression detector for
// arch's N3 read-back-nav ruling (entity-core-architecture 6e73d3d). When the
// target of compute/field is a *materialized* entity (stored / hand-built /
// read back — not an in-flight *constructedValue from this eval), an
// entity-valued field MUST return the bare system/hash bytes from .data. The
// caller follows the ref via an explicit compute/lookup/hash.
//
// Auto-resolving via a "33-byte ⇒ entity ref" heuristic is forbidden: it
// shape-sniffs (N3), and the length itself is a non-invariant (V7 §1.2 hashes
// are variable-length with an extensible varint format-code; 33 bytes is just
// today's ecfv1-sha256). This test mirrors Rust's
// test_v319c_readback_navigation_returns_hash and the validator vector
// v319c_readback_navigation_returns_hash.
func TestEvalFieldReadbackReturnsBareHash(t *testing.T) {
	ctx, cs := testCtx()
	// Non-compute targets are resolvable via content-store access (compute
	// /lookup/hash brings the bare wrapper into eval as the field target).
	ctx.HasContentStoreAccess = true

	// Hand-build inner = app/user{name:"alice"}; put in content store.
	innerData, err := ecf.Encode(map[string]interface{}{"name": "alice"})
	if err != nil {
		t.Fatalf("encode inner: %v", err)
	}
	innerEnt, err := entity.NewEntity("app/user", cbor.RawMessage(innerData))
	if err != nil {
		t.Fatalf("inner NewEntity: %v", err)
	}
	mustPut(t, cs, innerEnt)

	// Hand-build wrapper = app/wrapper{inner:<bare innerHash>}. This is the
	// V7 §1.4 bare form — exactly what the materialized output of
	// compute/construct produces, but built directly without going through
	// compute, so no in-flight typing exists for the wrapper. The read-back
	// path is what arch's N3 ruling governs.
	wrapperData, err := ecf.Encode(map[string]interface{}{"inner": innerEnt.ContentHash})
	if err != nil {
		t.Fatalf("encode wrapper: %v", err)
	}
	wrapperEnt, err := entity.NewEntity("app/wrapper", cbor.RawMessage(wrapperData))
	if err != nil {
		t.Fatalf("wrapper NewEntity: %v", err)
	}
	mustPut(t, cs, wrapperEnt)

	// Bring the wrapper into eval via compute/lookup/hash — its evaluated
	// value is the stored wrapper entity.
	lookupEnt := mustE(types.ComputeLookupHashData{Hash: wrapperEnt.ContentHash}.ToEntity())
	lookupHash := mustPut(t, cs, lookupEnt)

	// field(lookup_hash(wrapper), "inner") — N3 read-back: result MUST be
	// the bare bytes of innerEnt.ContentHash, not an unwrapped app/user.
	fieldEnt := mustE(types.ComputeFieldData{
		Name:   "inner",
		Entity: lookupHash,
	}.ToEntity())

	result, err := Evaluate(fieldEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("evaluate field: %v", err)
	}

	// N3 ruling: result MUST be the bare hash bytes. Returning an
	// entity.Entity (or *constructedValue) means an auto-resolve heuristic
	// fired — a regression.
	if ent, ok := result.(entity.Entity); ok {
		t.Fatalf("read-back field auto-resolved to entity type=%s — N3 violation. The 33-byte hash must be returned as bare bytes; caller follows via explicit compute/lookup/hash.", ent.Type)
	}
	if _, ok := result.(*constructedValue); ok {
		t.Fatalf("read-back field returned *constructedValue — N3 violation; bare wrapper has no in-flight typing")
	}

	bs, ok := result.([]byte)
	if !ok {
		t.Fatalf("expected []byte (bare system/hash ref), got %T", result)
	}

	// The returned bytes should be byte-equal to the inner entity's content
	// hash on the wire (algorithm byte || digest). Compare against the
	// structural form rather than asserting a fixed length (V7 §1.2: hashes
	// are variable-length + LEB128-extensible; 33 is today's ecfv1-sha256
	// accident).
	expected := innerEnt.ContentHash.Bytes()
	if !bytes.Equal(bs, expected) {
		t.Fatalf("read-back field bytes don't match inner content_hash: got %x, expected %x", bs, expected)
	}
}

func TestCanonicalSorted(t *testing.T) {
	m := map[string]hash.Hash{
		"bb":  {},
		"a":   {},
		"ccc": {},
		"aa":  {},
	}
	sorted := canonicalSorted(m)
	expected := []string{"a", "aa", "bb", "ccc"}
	for i, e := range sorted {
		if e.Key != expected[i] {
			t.Fatalf("position %d: expected %s, got %s", i, expected[i], e.Key)
		}
	}
}

func TestIsComputeExpression(t *testing.T) {
	exprTypes := []string{
		types.TypeComputeLiteral, types.TypeComputeLookupScope, types.TypeComputeLookupTree,
		types.TypeComputeApply, types.TypeComputeIf, types.TypeComputeLet, types.TypeComputeLambda,
		types.TypeComputeArithmetic, types.TypeComputeCompare, types.TypeComputeLogic,
		types.TypeComputeField, types.TypeComputeConstruct,
	}
	for _, typ := range exprTypes {
		ent := entity.Entity{Type: typ}
		if !IsComputeExpression(ent) {
			t.Fatalf("expected %s to be compute expression", typ)
		}
	}

	nonExprTypes := []string{
		types.TypeComputeClosure, types.TypeComputeScope,
		types.TypeComputeResult, types.TypeComputeError,
		"system/peer",
	}
	for _, typ := range nonExprTypes {
		ent := entity.Entity{Type: typ}
		if IsComputeExpression(ent) {
			t.Fatalf("expected %s to NOT be compute expression", typ)
		}
	}
}

func TestEvalLookupTree(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	valueEnt := mustE(types.ComputeLiteralData{Value: int64(42)}.ToEntity())
	valueHash := mustPut(t, cs, valueEnt)
	li.Set("/peer1/app/data", valueHash)

	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		Included:      make(map[hash.Hash]entity.Entity),
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{Path: "/peer1/app/data"}.ToEntity())

	// Tree entity is a compute expression, so it should be evaluated.
	result, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CBOR roundtrip decodes positive integers as uint64.
	rv, ok := toFloat64(result)
	if !ok || rv != 42 {
		t.Fatalf("expected 42, got %v (%T)", result, result)
	}
}

func TestTailCallOptimization(t *testing.T) {
	ctx, cs := testCtx()

	// Build a chain of 1500 if-true-then-next expressions.
	// Each if branch is a tail position. Without TCO this would need 1500 depth;
	// with TCO the trampoline reuses the frame, using O(1) depth and O(n) budget.
	trueEnt := mustE(types.ComputeLiteralData{Value: true}.ToEntity())
	trueHash := mustPut(t, cs, trueEnt)
	finalEnt := mustE(types.ComputeLiteralData{Value: int64(42)}.ToEntity())
	current := mustPut(t, cs, finalEnt)

	for i := 0; i < 1500; i++ {
		ifEnt := mustE(types.ComputeIfData{
			Condition: trueHash, Then: current,
		}.ToEntity())
		current = mustPut(t, cs, ifEnt)
	}

	chainEnt, _ := cs.Get(current)
	budget := NewBudget(200000, DefaultMaxDepth)
	result, err := Evaluate(chainEnt, NewScope(), budget, ctx)
	if err != nil {
		t.Fatalf("TCO should handle 1500 chained tail calls: %v", err)
	}
	rv, ok := toFloat64(result)
	if !ok || rv != 42 {
		t.Fatalf("expected 42, got %v", result)
	}
}

func TestTailCallOptimizationLet(t *testing.T) {
	ctx, cs := testCtx()

	// Chain 1500 let expressions: let _=1 in (let _=1 in ... in 42).
	// The let body is a tail position. Without TCO this needs 1500 depth.
	litEnt := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	litHash := mustPut(t, cs, litEnt)
	finalEnt := mustE(types.ComputeLiteralData{Value: int64(99)}.ToEntity())
	current := mustPut(t, cs, finalEnt)

	for i := 0; i < 1500; i++ {
		letEnt := mustE(types.ComputeLetData{
			Bindings: []types.ComputeLetBinding{{Name: "_", Value: litHash}},
			Body:     current,
		}.ToEntity())
		current = mustPut(t, cs, letEnt)
	}

	chainEnt, _ := cs.Get(current)
	budget := NewBudget(200000, DefaultMaxDepth)
	result, err := Evaluate(chainEnt, NewScope(), budget, ctx)
	if err != nil {
		t.Fatalf("TCO should handle 1500 chained let tail calls: %v", err)
	}
	rv, ok := toFloat64(result)
	if !ok || rv != 99 {
		t.Fatalf("expected 99, got %v", result)
	}
}

func TestTailCallDepthExceededWithoutTCO(t *testing.T) {
	// Verify that non-tail recursion still respects depth limits.
	// Build: add(literal, add(literal, add(literal, ...))) — depth 5, budget 1000.
	ctx, cs := testCtx()

	lit1 := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	lit1Hash := mustPut(t, cs, lit1)

	// Chain 6 nested adds: add(1, add(1, add(1, add(1, add(1, 1)))))
	// Each add evaluates both operands (non-tail), so depth grows.
	current := lit1Hash
	for i := 0; i < 5; i++ {
		addEnt := mustE(types.ComputeArithmeticData{
			Op: "add", Left: lit1Hash, Right: current,
		}.ToEntity())
		current = mustPut(t, cs, addEnt)
	}
	addEnt, _ := cs.Get(current)

	// Depth 3 should be insufficient for 5 nested levels.
	budget := NewBudget(1000, 3)
	_, err := Evaluate(addEnt, NewScope(), budget, ctx)
	if err == nil {
		t.Fatal("expected depth_exceeded for non-tail deep nesting")
	}
	ce := err.(*ComputeError)
	if ce.Code != ErrDepthExceeded {
		t.Fatalf("expected depth_exceeded, got %s", ce.Code)
	}
}

func TestEvalLookupTreeRelativePath(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	valueEnt := mustE(types.ComputeLiteralData{Value: int64(99)}.ToEntity())
	valueHash := mustPut(t, cs, valueEnt)
	li.Set("/peer1/app/job/data/input", valueHash)

	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		Included:      make(map[hash.Hash]entity.Entity),
		SubgraphRoot:  "/peer1/app/job",
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{
		Path: "data/input", Relative: true,
	}.ToEntity())

	result, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rv, ok := toFloat64(result)
	if !ok || rv != 99 {
		t.Fatalf("expected 99, got %v (%T)", result, result)
	}
}

func TestEvalLookupTreeRelativePathDependencyRegistration(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	valueEnt := mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())
	valueHash := mustPut(t, cs, valueEnt)
	li.Set("/peer1/root/data/x", valueHash)

	var registeredDep string
	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		Included:      make(map[hash.Hash]entity.Entity),
		SubgraphRoot:  "/peer1/root",
		RegisterDep: func(path string) {
			registeredDep = path
		},
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{
		Path: "data/x", Relative: true,
	}.ToEntity())

	_, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if registeredDep != "/peer1/root/data/x" {
		t.Fatalf("expected absolute dep registration, got %q", registeredDep)
	}
}

// EXTENSION-COMPUTE v3.20 / S8: a bare (peer-relative) path with relative
// absent/false is local-peer-qualified at eval time AND for dep registration,
// matching the canonical absolute form the tree layer notifies on.
func TestEvalLookupTreeBarePathCanonicalized(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	valueEnt := mustE(types.ComputeLiteralData{Value: int64(42)}.ToEntity())
	valueHash := mustPut(t, cs, valueEnt)
	li.Set("/peer1/app/x", valueHash)

	var registeredDep string
	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		LocalPeerID:   "peer1",
		Included:      make(map[hash.Hash]entity.Entity),
		RegisterDep: func(path string) {
			registeredDep = path
		},
	}

	// Bare path, Relative absent/false — should resolve and dep-track as
	// /peer1/app/x, not the verbatim "app/x".
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: "app/x"}.ToEntity())

	result, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if registeredDep != "/peer1/app/x" {
		t.Fatalf("expected dep registered at canonical /peer1/app/x, got %q", registeredDep)
	}
	rv, ok := toFloat64(result)
	if !ok || rv != 42 {
		t.Fatalf("expected resolved value 42, got %v (%T)", result, result)
	}
}

// makeCapEntity builds a capability entity granting `op` on resource patterns
// against handler patterns. Used by proposal-coverage tests.
func makeCapEntity(t *testing.T, ops, handlers, resources []string) entity.Entity {
	t.Helper()
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Operations: types.CapabilityScope{Include: ops},
			Handlers:   types.CapabilityScope{Include: handlers},
			Resources:  types.CapabilityScope{Include: resources},
		}},
		CreatedAt: 1000,
	}
	ent, err := capData.ToEntity()
	if err != nil {
		t.Fatalf("build capability: %v", err)
	}
	return ent
}

// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.2: lookup/tree must check ctx.Capability.
func TestEvalLookupTreeCapabilityDeniesOutOfScope(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	valueEnt := mustE(types.ComputeLiteralData{Value: int64(42)}.ToEntity())
	li.Set("/peer1/system/secret", mustPut(t, cs, valueEnt))

	cap := makeCapEntity(t, []string{"get"}, []string{"system/tree"}, []string{"/peer1/app/*"})
	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		LocalPeerID:   "peer1",
		Capability:    cap,
		Included:      make(map[hash.Hash]entity.Entity),
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{Path: "/peer1/system/secret"}.ToEntity())
	_, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected permission_denied for out-of-scope tree read")
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrPermissionDenied {
		t.Fatalf("expected permission_denied, got %v", err)
	}
}

func TestEvalLookupTreeCapabilityAllowsInScope(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	valueEnt := mustE(types.ComputeLiteralData{Value: int64(7)}.ToEntity())
	li.Set("/peer1/app/data", mustPut(t, cs, valueEnt))

	cap := makeCapEntity(t, []string{"get"}, []string{"system/tree"}, []string{"/peer1/app/*"})
	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		LocalPeerID:   "peer1",
		Capability:    cap,
		Included:      make(map[hash.Hash]entity.Entity),
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{Path: "/peer1/app/data"}.ToEntity())
	result, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	rv, ok := toFloat64(result)
	if !ok || rv != 7 {
		t.Fatalf("expected 7, got %v", result)
	}
}

// PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §3.2: dual-check enforces handler-grant
// ceiling on compute/apply with explicit capability override.
func TestEvalApplyDualCheckHandlerGrantBlocksEscape(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Handler grant: only system/tree (narrow scope).
	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})
	// Provided capability: admin (broad scope) — would otherwise authorize system/admin.
	adminCap := makeCapEntity(t, []string{"*"}, []string{"*"}, []string{"*"})
	adminCapHash := mustPut(t, cs, adminCap)

	// Capability field of compute/apply needs an expression that resolves to the cap.
	// Bind it via scope as "admin_cap" and use lookup/scope to retrieve.
	lookupCapEnt := mustE(types.ComputeLookupScopeData{Name: "admin_cap"}.ToEntity())
	lookupCapHash := mustPut(t, cs, lookupCapEnt)

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer1/anything"}},
	}.ToEntity())
	resourceLitHash := mustPut(t, cs, resourceLit)

	applyEnt := mustE(types.ComputeApplyData{
		Path:       "system/admin", // outside handler grant
		Operation:  "delete",
		Resource:   resourceLitHash,
		Capability: lookupCapHash,
	}.ToEntity())

	dispatched := false
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     map[hash.Hash]entity.Entity{adminCapHash: adminCap},
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			dispatched = true
			return &handler.Response{Status: 200}, nil
		},
	}
	scope := NewScope()
	scope.Set("admin_cap", adminCap)

	_, err := Evaluate(applyEnt, scope, DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected permission_denied for handler-scope escape")
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrPermissionDenied {
		t.Fatalf("expected permission_denied, got %v", err)
	}
	if dispatched {
		t.Fatal("dispatch must NOT happen when handler grant denies the target")
	}
}

func TestEvalApplyDualCheckProvidedCapBlocks(t *testing.T) {
	cs := store.NewMemoryContentStore()

	// Handler grant covers system/tree.
	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})
	// Caller's cap doesn't cover system/tree (only system/clock).
	callerCap := makeCapEntity(t, []string{"*"}, []string{"system/clock"}, []string{"*"})
	callerCapHash := mustPut(t, cs, callerCap)

	lookupCapEnt := mustE(types.ComputeLookupScopeData{Name: "caller_cap"}.ToEntity())
	lookupCapHash := mustPut(t, cs, lookupCapEnt)

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer1/x"}},
	}.ToEntity())
	resourceLitHash := mustPut(t, cs, resourceLit)

	applyEnt := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "get",
		Resource:   resourceLitHash,
		Capability: lookupCapHash,
	}.ToEntity())

	dispatched := false
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     map[hash.Hash]entity.Entity{callerCapHash: callerCap},
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			dispatched = true
			return &handler.Response{Status: 200}, nil
		},
	}
	scope := NewScope()
	scope.Set("caller_cap", callerCap)

	_, err := Evaluate(applyEnt, scope, DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected permission_denied when provided cap doesn't cover target")
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrPermissionDenied {
		t.Fatalf("expected permission_denied, got %v", err)
	}
	if dispatched {
		t.Fatal("dispatch must NOT happen when provided cap denies the target")
	}
}

func TestEvalApplyDualCheckBothPassDispatchesWithOverride(t *testing.T) {
	cs := store.NewMemoryContentStore()

	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})
	callerCap := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"/peer1/app/public/*"})
	callerCapHash := mustPut(t, cs, callerCap)

	lookupCapEnt := mustE(types.ComputeLookupScopeData{Name: "caller_cap"}.ToEntity())
	lookupCapHash := mustPut(t, cs, lookupCapEnt)

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer1/app/public/y"}},
	}.ToEntity())
	resourceLitHash := mustPut(t, cs, resourceLit)

	applyEnt := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "get",
		Resource:   resourceLitHash,
		Capability: lookupCapHash,
	}.ToEntity())

	var seenOverride *entity.Entity
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     map[hash.Hash]entity.Entity{callerCapHash: callerCap},
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			seenOverride = override
			return &handler.Response{Status: 200}, nil
		},
	}
	scope := NewScope()
	scope.Set("caller_cap", callerCap)

	_, err := Evaluate(applyEnt, scope, DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("expected dispatch to succeed, got %v", err)
	}
	if seenOverride == nil {
		t.Fatal("dispatch must receive non-nil override when capability field is present")
	}
	if seenOverride.ContentHash != callerCap.ContentHash {
		t.Fatalf("override capability mismatch: got %s, want %s",
			seenOverride.ContentHash, callerCap.ContentHash)
	}
}

func TestEvalApplyNoCapabilityFieldUsesCtxCapability(t *testing.T) {
	cs := store.NewMemoryContentStore()
	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})

	// No Capability field on the apply entity.
	applyEnt := mustE(types.ComputeApplyData{
		Path:      "system/tree",
		Operation: "get",
	}.ToEntity())

	var seenOverride *entity.Entity
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     make(map[hash.Hash]entity.Entity),
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			seenOverride = override
			return &handler.Response{Status: 200}, nil
		},
	}

	_, err := Evaluate(applyEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if seenOverride != nil {
		t.Fatal("override must be nil when capability field is absent")
	}
}

// PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING test vector row 3 (the security test).
// Handler grant covers tree:get on /peer1/app/*; caller cap covers tree:get on
// /peer1/system/secret/*. Without resource-aware dual-check, the handler grant
// "ceiling" passes at handler+op only and the dispatch goes through with the
// caller's cap, reading the secret. With F2, the ceiling check sees resource
// "/peer1/system/secret/x" and rejects.
func TestEvalApplyDualCheckResourceCeiling(t *testing.T) {
	cs := store.NewMemoryContentStore()

	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"/peer1/app/*"})
	callerCap := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"/peer1/system/secret/*"})
	callerCapHash := mustPut(t, cs, callerCap)

	lookupCapEnt := mustE(types.ComputeLookupScopeData{Name: "caller_cap"}.ToEntity())
	lookupCapHash := mustPut(t, cs, lookupCapEnt)

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer1/system/secret/x"}},
	}.ToEntity())
	resourceLitHash := mustPut(t, cs, resourceLit)

	applyEnt := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "get",
		Resource:   resourceLitHash,
		Capability: lookupCapHash,
	}.ToEntity())

	dispatched := false
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     map[hash.Hash]entity.Entity{callerCapHash: callerCap},
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			dispatched = true
			return &handler.Response{Status: 200}, nil
		},
	}
	scope := NewScope()
	scope.Set("caller_cap", callerCap)

	_, err := Evaluate(applyEnt, scope, DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected permission_denied — handler grant must not cover secret resource")
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrPermissionDenied {
		t.Fatalf("expected permission_denied, got %v", err)
	}
	if dispatched {
		t.Fatal("dispatch must NOT happen when handler grant doesn't cover the resource")
	}
}

// F5 runtime: capability override without resource is invalid_expression.
func TestEvalApplyF5RuntimeRejectsCapabilityWithoutResource(t *testing.T) {
	cs := store.NewMemoryContentStore()

	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})
	callerCap := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})
	callerCapHash := mustPut(t, cs, callerCap)

	lookupCapEnt := mustE(types.ComputeLookupScopeData{Name: "caller_cap"}.ToEntity())
	lookupCapHash := mustPut(t, cs, lookupCapEnt)

	applyEnt := mustE(types.ComputeApplyData{
		Path:       "system/tree",
		Operation:  "get",
		Capability: lookupCapHash, // no Resource — F5 violation.
	}.ToEntity())

	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     map[hash.Hash]entity.Entity{callerCapHash: callerCap},
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			t.Fatal("dispatch must NOT be called for F5-rejected expression")
			return nil, nil
		},
	}
	scope := NewScope()
	scope.Set("caller_cap", callerCap)

	_, err := Evaluate(applyEnt, scope, DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected invalid_expression for capability without resource")
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrInvalidExpression {
		t.Fatalf("expected invalid_expression, got %v", err)
	}
}

// F4: dispatched EXECUTE carries the resolved resource through to the handler.
func TestEvalApplyDispatchedExecuteCarriesResource(t *testing.T) {
	cs := store.NewMemoryContentStore()

	handlerGrant := makeCapEntity(t, []string{"*"}, []string{"system/tree"}, []string{"*"})

	resourceLit := mustE(types.ComputeLiteralData{
		Value: types.ResourceTarget{Targets: []string{"/peer1/app/x"}},
	}.ToEntity())
	resourceLitHash := mustPut(t, cs, resourceLit)

	applyEnt := mustE(types.ComputeApplyData{
		Path:      "system/tree",
		Operation: "get",
		Resource:  resourceLitHash,
	}.ToEntity())

	var seenResource *types.ResourceTarget
	ctx := &EvalContext{
		ContentStore: cs,
		LocalPeerID:  "peer1",
		Capability:   handlerGrant,
		Included:     make(map[hash.Hash]entity.Entity),
		DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
			seenResource = resource
			return &handler.Response{Status: 200}, nil
		},
	}

	_, err := Evaluate(applyEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if seenResource == nil {
		t.Fatal("dispatched EXECUTE must carry the resolved resource")
	}
	if len(seenResource.Targets) != 1 || seenResource.Targets[0] != "/peer1/app/x" {
		t.Fatalf("dispatched resource targets = %v, want [/peer1/app/x]", seenResource.Targets)
	}
}

func TestEvalLookupTreeNonExpression(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	// Store a non-compute entity at a path.
	identEnt, err := entity.NewEntity("system/peer", []byte{0xa0}) // empty CBOR map
	if err != nil {
		t.Fatal(err)
	}
	identHash := mustPut(t, cs, identEnt)
	li.Set("/peer1/system/peer", identHash)

	ctx := &EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		Included:      make(map[hash.Hash]entity.Entity),
	}

	lookupEnt := mustE(types.ComputeLookupTreeData{Path: "/peer1/system/peer"}.ToEntity())

	result, err := Evaluate(lookupEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resultEnt, ok := result.(entity.Entity)
	if !ok {
		t.Fatalf("expected entity.Entity for non-expression, got %T", result)
	}
	if resultEnt.Type != "system/peer" {
		t.Fatalf("expected system/peer, got %s", resultEnt.Type)
	}
}

// --- N.1 + N.4 tests: compute/index, compute/length, compute/numeric-cast,
//                      and arithmetic same-type / mixed-type rules. ---

// litHash stores a compute/literal with the given value and returns its hash.
func litHash(t *testing.T, cs store.ContentStore, v interface{}) hash.Hash {
	t.Helper()
	return mustPut(t, cs, mustE(types.ComputeLiteralData{Value: v}.ToEntity()))
}

func TestEvalIndex(t *testing.T) {
	ctx, cs := testCtx()
	arr := litHash(t, cs, []interface{}{"a", "b", "c"})

	t.Run("middle", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(1))}.ToEntity())
		v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil || v != "b" {
			t.Fatalf("expected \"b\", got %v err=%v", v, err)
		}
	})
	t.Run("first", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(0))}.ToEntity())
		v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil || v != "a" {
			t.Fatalf("expected \"a\", got %v err=%v", v, err)
		}
	})
	t.Run("last", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(2))}.ToEntity())
		v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err != nil || v != "c" {
			t.Fatalf("expected \"c\", got %v err=%v", v, err)
		}
	})
}

func TestEvalIndexOutOfRange(t *testing.T) {
	ctx, cs := testCtx()
	arr := litHash(t, cs, []interface{}{int64(1), int64(2)})

	t.Run("past_end", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(5))}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err == nil {
			t.Fatal("expected index_out_of_range")
		}
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrIndexOutOfRange {
			t.Fatalf("expected index_out_of_range, got %v", err)
		}
	})
	t.Run("negative", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(-1))}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if err == nil {
			t.Fatal("expected index_out_of_range")
		}
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrIndexOutOfRange {
			t.Fatalf("expected index_out_of_range, got %v", err)
		}
	})
	t.Run("empty_zero", func(t *testing.T) {
		empty := litHash(t, cs, []interface{}{})
		ent := mustE(types.ComputeIndexData{Array: empty, Index: litHash(t, cs, int64(0))}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrIndexOutOfRange {
			t.Fatalf("expected index_out_of_range on empty array, got %v", err)
		}
	})
}

func TestEvalIndexTypeMismatch(t *testing.T) {
	ctx, cs := testCtx()
	t.Run("non_array", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: litHash(t, cs, "hello"), Index: litHash(t, cs, int64(0))}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch on non-array, got %v", err)
		}
	})
	t.Run("null", func(t *testing.T) {
		ent := mustE(types.ComputeIndexData{Array: litHash(t, cs, nil), Index: litHash(t, cs, int64(0))}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch on null, got %v", err)
		}
	})
	t.Run("non_int_index", func(t *testing.T) {
		arr := litHash(t, cs, []interface{}{int64(1)})
		ent := mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, "x")}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch on non-int index, got %v", err)
		}
	})
}

func TestEvalLength(t *testing.T) {
	ctx, cs := testCtx()
	tests := []struct {
		name string
		arr  []interface{}
		want int64
	}{
		{"empty", []interface{}{}, 0},
		{"one", []interface{}{int64(1)}, 1},
		{"many", []interface{}{int64(1), int64(2), int64(3), int64(4)}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := mustE(types.ComputeLengthData{Array: litHash(t, cs, tt.arr)}.ToEntity())
			v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if v != tt.want {
				t.Fatalf("expected %d, got %v (%T)", tt.want, v, v)
			}
		})
	}
}

func TestEvalLengthTypeMismatch(t *testing.T) {
	ctx, cs := testCtx()
	t.Run("string", func(t *testing.T) {
		ent := mustE(types.ComputeLengthData{Array: litHash(t, cs, "hello")}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch, got %v", err)
		}
	})
	t.Run("null", func(t *testing.T) {
		ent := mustE(types.ComputeLengthData{Array: litHash(t, cs, nil)}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch, got %v", err)
		}
	})
}

// --- v3.16 arithmetic semantics (rules 8-11) ---

// Rule 8: sign-agnostic add of two positive operands — no longer "preserves
// uint" type; per rule 10 the result encodes signed → int64.
func TestArithmeticSignAgnosticAdd(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, uint64(7))
	right := litHash(t, cs, uint64(3))
	ent := mustE(types.ComputeArithmeticData{Op: "add", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != 10 {
		t.Fatalf("expected int64(10), got %v (%T)", v, v)
	}
}

// Rule 8: sign-agnostic — mixed-sign operands no longer trigger type_mismatch
// (that was v3.14 rule 9, removed in v3.16). add(-1, 2) = 1 via two's-comp.
func TestArithmeticMixedSignAdd(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, int64(-1))
	right := litHash(t, cs, int64(2))
	ent := mustE(types.ComputeArithmeticData{Op: "add", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("expected success for sign-agnostic add, got: %v", err)
	}
	if r, ok := v.(int64); !ok || r != 1 {
		t.Fatalf("expected int64(1), got %v (%T)", v, v)
	}
}

// Rule 8: add at the uint64 width wraps to 0. Per rule 10 the wrap result
// encodes signed (bit-63 clear → major type 0, value 0).
func TestArithmeticWraparoundAtUint64Width(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, uint64(1<<64-1))
	right := litHash(t, cs, uint64(1))
	ent := mustE(types.ComputeArithmeticData{Op: "add", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != 0 {
		t.Fatalf("expected int64(0) on wrap, got %v (%T)", v, v)
	}
}

// Rule 8: add at the int64 boundary wraps via two's-complement. MinInt64 + -1
// → MaxInt64 (bit pattern, signed interpretation).
func TestArithmeticWraparoundAtInt64Boundary(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, int64(-1<<63))
	right := litHash(t, cs, int64(-1))
	ent := mustE(types.ComputeArithmeticData{Op: "add", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != (1<<63)-1 {
		t.Fatalf("expected int64(MaxInt64) on wrap, got %v (%T)", v, v)
	}
}

// Rule 10 canonical wire encoding: sub(3, 5) → bit pattern 0xFFF...FE.
// Encoded as int64(-2) → CBOR major type 1. Verify Go returns int64 so the
// CBOR encoder picks the signed wire form.
func TestArithmeticSignedCanonicalEncoding(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, uint64(3))
	right := litHash(t, cs, uint64(5))
	ent := mustE(types.ComputeArithmeticData{Op: "sub", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	r, ok := v.(int64)
	if !ok {
		t.Fatalf("expected int64 result for canonical signed encoding, got %T", v)
	}
	if r != -2 {
		t.Fatalf("expected int64(-2), got %v", r)
	}
}

func TestArithmeticIntWraparound(t *testing.T) {
	// (-2^63) + (-1) → 2^63-1 by two's-complement wrap.
	ctx, cs := testCtx()
	left := litHash(t, cs, int64(-1<<63))
	right := litHash(t, cs, int64(-1))
	ent := mustE(types.ComputeArithmeticData{Op: "add", Left: left, Right: right}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != (1<<63)-1 {
		t.Fatalf("expected int64(MaxInt64) on wrap, got %v (%T)", v, v)
	}
}

// --- N.4: compute/numeric-cast edge cases. ---

func TestNumericCastIntToUint(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, int64(-1)),
		ToType: "primitive/uint",
	}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(uint64); !ok || r != ^uint64(0) {
		t.Fatalf("expected uint64(MaxUint64), got %v (%T)", v, v)
	}
}

func TestNumericCastUintToInt(t *testing.T) {
	// uint64(1<<63) reinterpreted as int64 → MinInt64.
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, uint64(1<<63)),
		ToType: "primitive/int",
	}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != -1<<63 {
		t.Fatalf("expected int64(MinInt64), got %v (%T)", v, v)
	}
}

func TestNumericCastIntToFloatLossy(t *testing.T) {
	// (2^53)+1 is not exactly representable in float64 — lossy but not an error.
	ctx, cs := testCtx()
	val := int64(1<<53) + 1
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, uint64(val)),
		ToType: "primitive/float",
	}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", v)
	}
	// Lossy: low bit drops, so 2^53+1 ≡ 2^53 in float64.
	if f != float64(int64(1<<53)) {
		t.Fatalf("expected lossy %v, got %v", float64(int64(1<<53)), f)
	}
}

func TestNumericCastFloatToIntTruncate(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, float64(3.7)),
		ToType: "primitive/int",
	}.ToEntity())
	v, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r, ok := v.(int64); !ok || r != 3 {
		t.Fatalf("expected int64(3) truncated, got %v (%T)", v, v)
	}
}

func TestNumericCastFloatNaNToInt(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, math.NaN()),
		ToType: "primitive/int",
	}.ToEntity())
	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrCastOutOfRange {
		t.Fatalf("expected cast_out_of_range for NaN, got %v", err)
	}
}

func TestNumericCastFloatInfToInt(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, math.Inf(1)),
		ToType: "primitive/int",
	}.ToEntity())
	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrCastOutOfRange {
		t.Fatalf("expected cast_out_of_range for +Inf, got %v", err)
	}
}

func TestNumericCastFloatNegToUint(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, float64(-1.5)),
		ToType: "primitive/uint",
	}.ToEntity())
	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrCastOutOfRange {
		t.Fatalf("expected cast_out_of_range for negative float→uint, got %v", err)
	}
}

func TestNumericCastFloatHugeToInt(t *testing.T) {
	// 2^70 well beyond int64.
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, math.Pow(2, 70)),
		ToType: "primitive/int",
	}.ToEntity())
	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrCastOutOfRange {
		t.Fatalf("expected cast_out_of_range for 2^70 → int, got %v", err)
	}
}

func TestNumericCastInvalidToType(t *testing.T) {
	ctx, cs := testCtx()
	ent := mustE(types.ComputeNumericCastData{
		Value:  litHash(t, cs, int64(1)),
		ToType: "primitive/bool",
	}.ToEntity())
	_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
		t.Fatalf("expected type_mismatch for primitive/bool target, got %v", err)
	}
}

func TestNumericCastNonNumeric(t *testing.T) {
	ctx, cs := testCtx()
	t.Run("string", func(t *testing.T) {
		ent := mustE(types.ComputeNumericCastData{
			Value:  litHash(t, cs, "hello"),
			ToType: "primitive/int",
		}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch for string, got %v", err)
		}
	})
	t.Run("null", func(t *testing.T) {
		ent := mustE(types.ComputeNumericCastData{
			Value:  litHash(t, cs, nil),
			ToType: "primitive/int",
		}.ToEntity())
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrTypeMismatch {
			t.Fatalf("expected type_mismatch for null, got %v", err)
		}
	})
}

// --- N.2 builtin tests: map / filter / fold / inline-equivalent aliases. ---
// store is exercised in the engine_test wiring where a real dispatch loop
// runs system/tree:put; here we only cover the no-dispatch error path so
// the unit test stays self-contained.

// buildClosure constructs a compute/closure entity for a unary lambda whose
// body is the given expression entity referring to `param`.
func buildClosure(t *testing.T, cs store.ContentStore, ctx *EvalContext, param string, body entity.Entity) entity.Entity {
	t.Helper()
	bodyHash := mustPut(t, cs, body)
	lambda := mustE(types.ComputeLambdaData{Params: []string{param}, Body: bodyHash}.ToEntity())
	v, err := Evaluate(lambda, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("lambda eval failed: %v", err)
	}
	ent, ok := v.(entity.Entity)
	if !ok || ent.Type != types.TypeComputeClosure {
		t.Fatalf("expected closure, got %T", v)
	}
	return ent
}

func TestBuiltinMap(t *testing.T) {
	ctx, cs := testCtx()
	// fn = lambda(x): x + 1
	lookupX := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	lookupXHash := mustPut(t, cs, lookupX)
	oneHash := litHash(t, cs, uint64(1))
	addBody := mustE(types.ComputeArithmeticData{Op: "add", Left: lookupXHash, Right: oneHash}.ToEntity())
	fn := buildClosure(t, cs, ctx, "x", addBody)
	fnHash := mustPut(t, cs, fn)

	coll := litHash(t, cs, []interface{}{uint64(10), uint64(20), uint64(30)})

	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinMap,
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": coll, "fn": fnHash},
	}.ToEntity())

	v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) != 3 {
		t.Fatalf("expected length-3 array, got %v (%T)", v, v)
	}
	want := []int64{11, 21, 31}
	for i, w := range want {
		got, ok := arr[i].(int64)
		if !ok || got != w {
			t.Fatalf("arr[%d]: expected int64(%d), got %v (%T)", i, w, arr[i], arr[i])
		}
	}
}

func TestBuiltinFilter(t *testing.T) {
	ctx, cs := testCtx()
	// predicate = lambda(x): x > 5 → compute/compare gt
	lookupX := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	lookupXHash := mustPut(t, cs, lookupX)
	fiveHash := litHash(t, cs, uint64(5))
	predBody := mustE(types.ComputeCompareData{Op: "gt", Left: lookupXHash, Right: fiveHash}.ToEntity())
	pred := buildClosure(t, cs, ctx, "x", predBody)
	predHash := mustPut(t, cs, pred)

	coll := litHash(t, cs, []interface{}{uint64(1), uint64(7), uint64(3), uint64(9), uint64(2)})

	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinFilter,
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": coll, "fn": predHash},
	}.ToEntity())

	v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("filter failed: %v", err)
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("expected length-2 array, got %v (%T)", v, v)
	}
	want := []uint64{7, 9}
	for i, w := range want {
		got, ok := arr[i].(uint64)
		if !ok || got != w {
			t.Fatalf("arr[%d]: expected %d, got %v (%T)", i, w, arr[i], arr[i])
		}
	}
}

func TestBuiltinFold(t *testing.T) {
	ctx, cs := testCtx()
	// fn = lambda(acc, x): acc + x — two-param closure.
	lookupAcc := mustE(types.ComputeLookupScopeData{Name: "acc"}.ToEntity())
	lookupX := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	accH := mustPut(t, cs, lookupAcc)
	xH := mustPut(t, cs, lookupX)
	addBody := mustE(types.ComputeArithmeticData{Op: "add", Left: accH, Right: xH}.ToEntity())
	bodyHash := mustPut(t, cs, addBody)
	lambda := mustE(types.ComputeLambdaData{Params: []string{"acc", "x"}, Body: bodyHash}.ToEntity())
	v, err := Evaluate(lambda, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("lambda eval failed: %v", err)
	}
	fnEnt := v.(entity.Entity)
	fnHash := mustPut(t, cs, fnEnt)

	coll := litHash(t, cs, []interface{}{uint64(1), uint64(2), uint64(3), uint64(4)})
	initial := litHash(t, cs, uint64(0))

	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinFold,
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": coll, "fn": fnHash, "initial": initial},
	}.ToEntity())

	got, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("fold failed: %v", err)
	}
	if r, ok := got.(int64); !ok || r != 10 {
		t.Fatalf("expected int64(10), got %v (%T)", got, got)
	}
}

func TestBuiltinFoldEmpty(t *testing.T) {
	ctx, cs := testCtx()
	// initial returned as-is for empty collection.
	lookupX := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	xH := mustPut(t, cs, lookupX)
	body := mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity())
	bodyH := mustPut(t, cs, body)
	_ = xH
	lambda := mustE(types.ComputeLambdaData{Params: []string{"acc", "x"}, Body: bodyH}.ToEntity())
	cv, _ := Evaluate(lambda, NewScope(), DefaultBudget(), ctx)
	fnEnt := cv.(entity.Entity)
	fnHash := mustPut(t, cs, fnEnt)

	coll := litHash(t, cs, []interface{}{})
	initial := litHash(t, cs, "seed")
	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinFold,
		Operation: "eval",
		Args:      map[string]hash.Hash{"collection": coll, "fn": fnHash, "initial": initial},
	}.ToEntity())

	got, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil || got != "seed" {
		t.Fatalf("expected \"seed\", got %v err=%v", got, err)
	}
}

// Inline-equivalent builtin alias produces the same result as the inline form.
func TestBuiltinArithmeticAlias(t *testing.T) {
	ctx, cs := testCtx()
	left := litHash(t, cs, uint64(3))
	right := litHash(t, cs, uint64(4))
	op := litHash(t, cs, "add")

	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinArithmetic,
		Operation: "eval",
		Args:      map[string]hash.Hash{"op": op, "left": left, "right": right},
	}.ToEntity())

	got, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("builtin arithmetic alias failed: %v", err)
	}
	if r, ok := got.(int64); !ok || r != 7 {
		t.Fatalf("expected int64(7), got %v (%T)", got, got)
	}
}

func TestBuiltinStoreWithoutDispatch(t *testing.T) {
	ctx, cs := testCtx()
	// ctx.DispatchExecute is nil in testCtx — store should reject cleanly.
	apply := mustE(types.ComputeApplyData{
		Path:      BuiltinStore,
		Operation: "eval",
		Args: map[string]hash.Hash{
			"path":  litHash(t, cs, "/p/test"),
			"value": litHash(t, cs, uint64(1)),
		},
	}.ToEntity())
	_, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err == nil {
		t.Fatal("expected error without DispatchExecute")
	}
	if ce, ok := err.(*ComputeError); !ok || ce.Code != ErrInvalidExpression {
		t.Fatalf("expected invalid_expression, got %v", err)
	}
}

// --- v3.16 rule 11: eager numeric-cast at point of use ---

// Rule 11 positive: cast directly at the operand triggers unsigned div.
// MaxUint64 / 2 unsigned = 0x7FFF_FFFF_FFFF_FFFF; signed (MaxUint64 as -1) / 2 = 0.
func TestEagerCastDivUnsigned(t *testing.T) {
	ctx, cs := testCtx()
	xLit, _ := types.ComputeLiteralData{Value: uint64(1<<64 - 2)}.ToEntity()
	xHash := mustPut(t, cs, xLit)
	leftCast, _ := types.ComputeNumericCastData{Value: xHash, ToType: "primitive/uint"}.ToEntity()
	leftCastHash := mustPut(t, cs, leftCast)
	twoHash := litHash(t, cs, uint64(2))

	divEnt := mustE(types.ComputeArithmeticData{Op: "div", Left: leftCastHash, Right: twoHash}.ToEntity())
	v, err := Evaluate(divEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("div failed: %v", err)
	}
	r, ok := v.(uint64)
	if !ok {
		t.Fatalf("expected uint64 result (unsigned div), got %T", v)
	}
	if r != (1<<63)-1 {
		t.Fatalf("expected (2^63)-1, got %v", r)
	}
}

// Rule 11 negative: cast through a let-binding is NOT preserved — the cast is
// consumed by the binding, and div uses signed-default.
func TestEagerCastDoesNotFlowThroughLet(t *testing.T) {
	ctx, cs := testCtx()
	xLit, _ := types.ComputeLiteralData{Value: uint64(1<<64 - 2)}.ToEntity()
	xHash := mustPut(t, cs, xLit)
	castExpr, _ := types.ComputeNumericCastData{Value: xHash, ToType: "primitive/uint"}.ToEntity()
	castHash := mustPut(t, cs, castExpr)

	lookupY, _ := types.ComputeLookupScopeData{Name: "y"}.ToEntity()
	lookupYHash := mustPut(t, cs, lookupY)
	twoHash := litHash(t, cs, uint64(2))

	divEnt, _ := types.ComputeArithmeticData{Op: "div", Left: lookupYHash, Right: twoHash}.ToEntity()
	divHash := mustPut(t, cs, divEnt)

	letEnt := mustE(types.ComputeLetData{
		Bindings: []types.ComputeLetBinding{{Name: "y", Value: castHash}},
		Body:     divHash,
	}.ToEntity())

	v, err := Evaluate(letEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("let div failed: %v", err)
	}
	// Signed: int64(MaxUint64 - 1) = -2; -2 / 2 = -1 (exact).
	r, ok := v.(int64)
	if !ok {
		t.Fatalf("expected int64 result (signed-default — cast consumed by let), got %v (%T)", v, v)
	}
	if r != -1 {
		t.Fatalf("expected -1 (signed div of -2 by 2), got %v", r)
	}
}

// Rule 11: cast not consumed by a sign-sensitive op has no effect beyond
// §2.2 value reinterpretation. add(cast(MaxUint, uint), 1) wraps the bit
// pattern to 0 sign-agnostically.
func TestEagerCastNotConsumedByAddIsNoOp(t *testing.T) {
	ctx, cs := testCtx()
	xLit, _ := types.ComputeLiteralData{Value: uint64(1<<64 - 1)}.ToEntity()
	xHash := mustPut(t, cs, xLit)
	cast, _ := types.ComputeNumericCastData{Value: xHash, ToType: "primitive/uint"}.ToEntity()
	castHash := mustPut(t, cs, cast)
	oneHash := litHash(t, cs, uint64(1))

	addEnt := mustE(types.ComputeArithmeticData{Op: "add", Left: castHash, Right: oneHash}.ToEntity())
	v, err := Evaluate(addEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}
	// Bit pattern of MaxUint + 1 = 0; rule 10 → int64.
	if r, ok := v.(int64); !ok || r != 0 {
		t.Fatalf("expected int64(0) after sign-agnostic wrap, got %v (%T)", v, v)
	}
}

// Rule 11: compare with cast triggers unsigned ordering. uint(MaxUint64) > 1
// is true unsigned, false signed (signed MaxUint64 = -1).
func TestEagerCastCompareUnsigned(t *testing.T) {
	ctx, cs := testCtx()
	xLit, _ := types.ComputeLiteralData{Value: uint64(1<<64 - 1)}.ToEntity()
	xHash := mustPut(t, cs, xLit)
	cast, _ := types.ComputeNumericCastData{Value: xHash, ToType: "primitive/uint"}.ToEntity()
	castHash := mustPut(t, cs, cast)
	oneHash := litHash(t, cs, uint64(1))

	cmpEnt := mustE(types.ComputeCompareData{Op: "gt", Left: castHash, Right: oneHash}.ToEntity())
	v, err := Evaluate(cmpEnt, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("gt failed: %v", err)
	}
	if v != true {
		t.Fatalf("expected true (unsigned MaxUint64 > 1), got %v", v)
	}

	// Without the cast, signed-default: MaxUint64 → -1, -1 > 1 = false.
	cmpSigned := mustE(types.ComputeCompareData{Op: "gt", Left: xHash, Right: oneHash}.ToEntity())
	v2, err := Evaluate(cmpSigned, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("gt signed failed: %v", err)
	}
	if v2 != false {
		t.Fatalf("expected false (signed -1 > 1), got %v", v2)
	}
}
