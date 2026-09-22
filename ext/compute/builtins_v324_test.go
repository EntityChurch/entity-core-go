package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-COMPUTE v3.24 §3.5 — the four collection primitives. These produce
// boundary bytes (MUST-given-COMPUTE §10.1), so the observable semantics are
// pinned; the tests assert the pinned edges directly.

func evalBuiltinApply(t *testing.T, ctx *EvalContext, path string, args map[string]hash.Hash) (interface{}, error) {
	t.Helper()
	apply := mustE(types.ComputeApplyData{Path: path, Operation: "eval", Args: args}.ToEntity())
	return Evaluate(apply, NewScope(), DefaultBudget(), ctx)
}

func mustComputeErr(t *testing.T, err error, wantCode, ctxMsg string) {
	t.Helper()
	ce, ok := err.(*ComputeError)
	if !ok {
		t.Fatalf("%s: expected *ComputeError, got %v (%T)", ctxMsg, err, err)
	}
	if ce.Code != wantCode {
		t.Fatalf("%s: expected code %q, got %q (%s)", ctxMsg, wantCode, ce.Code, ce.Message)
	}
}

func TestBuiltinRange(t *testing.T) {
	ctx, cs := testCtx()

	t.Run("zero-is-empty", func(t *testing.T) {
		v, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": litHash(t, cs, int64(0))})
		if err != nil {
			t.Fatalf("range(0): %v", err)
		}
		if arr, ok := v.([]interface{}); !ok || len(arr) != 0 {
			t.Fatalf("range(0) must be empty array, got %v (%T)", v, v)
		}
	})

	t.Run("counts-up", func(t *testing.T) {
		v, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": litHash(t, cs, int64(4))})
		if err != nil {
			t.Fatalf("range(4): %v", err)
		}
		arr := v.([]interface{})
		want := []int64{0, 1, 2, 3}
		if len(arr) != len(want) {
			t.Fatalf("range(4) len=%d, want 4", len(arr))
		}
		for i, w := range want {
			if got, ok := arr[i].(int64); !ok || got != w {
				t.Fatalf("range(4)[%d]=%v (%T), want int64(%d)", i, arr[i], arr[i], w)
			}
		}
	})

	t.Run("negative-is-count-out-of-range", func(t *testing.T) {
		// v3.25 (C-3, ruled): negative n → count_out_of_range, NOT type_mismatch
		// (an out-of-domain magnitude is not a type error, §2.2) and NOT clamped.
		_, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": litHash(t, cs, int64(-1))})
		mustComputeErr(t, err, ErrCountOutOfRange, "range(-1)")
	})

	t.Run("non-integer-is-type-mismatch", func(t *testing.T) {
		_, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": litHash(t, cs, "nope")})
		mustComputeErr(t, err, ErrTypeMismatch, "range(\"nope\")")
	})

	t.Run("huge-n-exhausts-budget-not-memory", func(t *testing.T) {
		apply := mustE(types.ComputeApplyData{Path: BuiltinRange, Operation: "eval",
			Args: map[string]hash.Hash{"n": litHash(t, cs, int64(1)<<40)}}.ToEntity())
		_, err := Evaluate(apply, NewScope(), NewBudget(1000, 64), ctx)
		mustComputeErr(t, err, ErrBudgetExhausted, "range(2^40)")
	})
}

// TestBuiltinRangeErrorNShortCircuits — n is a CONTROL operand, so an error in
// it short-circuits in BOTH compute/error representations (the repeat-biter
// rule: a test that exercises one form has not touched the other).
func TestBuiltinRangeErrorNShortCircuits(t *testing.T) {
	ctx, cs := testCtx()

	t.Run("value-form", func(t *testing.T) {
		errHash := storedErrorOperand(t, cs, "n_error")
		_, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": errHash})
		mustComputeErr(t, err, "n_error", "range(value-form-error)")
	})

	t.Run("minted-form", func(t *testing.T) {
		// A minted *ComputeError: index out of range on an inner compute/index.
		arr := litHash(t, cs, []interface{}{int64(7)})
		badIndex := mustPut(t, cs, mustE(types.ComputeIndexData{Array: arr, Index: litHash(t, cs, int64(9))}.ToEntity()))
		_, err := evalBuiltinApply(t, ctx, BuiltinRange, map[string]hash.Hash{"n": badIndex})
		mustComputeErr(t, err, ErrIndexOutOfRange, "range(minted-error)")
	})
}

func TestBuiltinGroupBy(t *testing.T) {
	ctx, cs := testCtx()
	// fn = lambda(x): x mod 2  — key is parity.
	lookupX := mustPut(t, cs, mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity()))
	twoHash := litHash(t, cs, int64(2))
	modBody := mustE(types.ComputeArithmeticData{Op: "mod", Left: lookupX, Right: twoHash}.ToEntity())
	fn := buildClosure(t, cs, ctx, "x", modBody)
	fnHash := mustPut(t, cs, fn)

	coll := litHash(t, cs, []interface{}{int64(1), int64(2), int64(3), int64(4), int64(5), int64(6)})
	v, err := evalBuiltinApply(t, ctx, BuiltinGroupBy, map[string]hash.Hash{"collection": coll, "fn": fnHash})
	if err != nil {
		t.Fatalf("group-by: %v", err)
	}
	groups, ok := v.([]interface{})
	if !ok || len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %v (%T)", v, v)
	}
	// v3.25 (C-1): each group is a system/compute/group{key, members}; the KEY
	// is carried. Groups ordered by FIRST APPEARANCE of key: elt 1 → key 1 (odd)
	// first, then elt 2 → key 0 (even). Within each, input order preserved.
	assertGroup(t, groups[0], 1, []int64{1, 3, 5}, "odds (first-appearance)")
	assertGroup(t, groups[1], 0, []int64{2, 4, 6}, "evens")
}

// assertGroup checks a group-by result element is a system/compute/group entity
// carrying the expected key and members (in input order).
func assertGroup(t *testing.T, g interface{}, wantKey int64, wantMembers []int64, label string) {
	t.Helper()
	cv, ok := g.(*constructedValue)
	if !ok || cv.entityType != types.TypeComputeGroup {
		t.Fatalf("%s: expected *constructedValue of %s, got %v (%T)", label, types.TypeComputeGroup, g, g)
	}
	k, isInt, inInt64 := asIndex(cv.fields["key"])
	if !isInt || !inInt64 || k != wantKey {
		t.Fatalf("%s: key=%v (%T), want %d", label, cv.fields["key"], cv.fields["key"], wantKey)
	}
	members, ok := cv.fields["members"].([]interface{})
	if !ok {
		t.Fatalf("%s: members is %T, want array", label, cv.fields["members"])
	}
	assertInt64Group(t, members, wantMembers, label+".members")
}

// assertInt64Group compares integer array elements by magnitude, accepting
// either int64 (freshly minted, e.g. by range) or uint64 (a non-negative int
// literal after its ECF major-type-0 round-trip) — int/uint are annotations,
// not distinct value types (§2.2), so both are valid integer forms.
func assertInt64Group(t *testing.T, g interface{}, want []int64, label string) {
	t.Helper()
	arr, ok := g.([]interface{})
	if !ok || len(arr) != len(want) {
		t.Fatalf("%s: expected group of %d, got %v (%T)", label, len(want), g, g)
	}
	for i, w := range want {
		got, isInt, inInt64 := asIndex(arr[i])
		if !isInt || !inInt64 || got != w {
			t.Fatalf("%s[%d]=%v (%T), want integer %d", label, i, arr[i], arr[i], w)
		}
	}
}

// TestBuiltinGroupByKeyErrorShortCircuits — a derived key is a control value; an
// error deriving it cannot be grouped and short-circuits.
func TestBuiltinGroupByKeyErrorShortCircuits(t *testing.T) {
	ctx, cs := testCtx()
	// fn = lambda(x): <stored compute/error>  — the closure body IS an error value.
	errHash := storedErrorOperand(t, cs, "key_error")
	// A lambda whose body looks up the stored error via compute/lookup/hash.
	lookupErr := mustPut(t, cs, mustE(types.ComputeLookupHashData{Hash: errHash}.ToEntity()))
	lambda := mustE(types.ComputeLambdaData{Params: []string{"x"}, Body: lookupErr}.ToEntity())
	cv, _ := Evaluate(lambda, NewScope(), DefaultBudget(), ctx)
	fnHash := mustPut(t, cs, cv.(entity.Entity))

	coll := litHash(t, cs, []interface{}{int64(1), int64(2)})
	_, err := evalBuiltinApply(t, ctx, BuiltinGroupBy, map[string]hash.Hash{"collection": coll, "fn": fnHash})
	mustComputeErr(t, err, "key_error", "group-by(error-key)")
}

func TestBuiltinConcat(t *testing.T) {
	ctx, cs := testCtx()

	t.Run("joins-order-preserving", func(t *testing.T) {
		colls := litHash(t, cs, []interface{}{
			[]interface{}{int64(1), int64(2)},
			[]interface{}{int64(3)},
			[]interface{}{},
			[]interface{}{int64(4), int64(5)},
		})
		v, err := evalBuiltinApply(t, ctx, BuiltinConcat, map[string]hash.Hash{"collections": colls})
		if err != nil {
			t.Fatalf("concat: %v", err)
		}
		assertInt64Group(t, v, []int64{1, 2, 3, 4, 5}, "concat")
	})

	t.Run("empty-is-empty", func(t *testing.T) {
		colls := litHash(t, cs, []interface{}{})
		v, err := evalBuiltinApply(t, ctx, BuiltinConcat, map[string]hash.Hash{"collections": colls})
		if err != nil {
			t.Fatalf("concat(): %v", err)
		}
		if arr, ok := v.([]interface{}); !ok || len(arr) != 0 {
			t.Fatalf("concat() must be empty array, got %v", v)
		}
	})

	t.Run("element-type-mismatch", func(t *testing.T) {
		colls := litHash(t, cs, []interface{}{
			[]interface{}{int64(1)},
			[]interface{}{"x"},
		})
		_, err := evalBuiltinApply(t, ctx, BuiltinConcat, map[string]hash.Hash{"collections": colls})
		mustComputeErr(t, err, ErrTypeMismatch, "concat(int,string)")
	})

	t.Run("compute-error-element-is-type-transparent", func(t *testing.T) {
		// v3.25 (C-4): a compute/error element neither matches nor mismatches the
		// element-type check — it flows through untouched (the NaN analogy). An
		// error among integers must NOT raise type_mismatch.
		//
		// The error is delivered the way it actually arises — a LIVE entity in an
		// array (as a map result would produce), here via a scope binding, which
		// preserves the value live exactly as a `let` does. (A literal round-trip
		// would degrade it to a generic map and never reach this path.)
		errEnt := mustE((&ComputeError{Code: "poisoned", Message: "loud prose"}).ToEntity())
		scope := NewScope()
		scope.Set("coll", []interface{}{[]interface{}{int64(1), errEnt, int64(2)}})
		collHash := mustPut(t, cs, mustE(types.ComputeLookupScopeData{Name: "coll"}.ToEntity()))
		apply := mustE(types.ComputeApplyData{Path: BuiltinConcat, Operation: "eval",
			Args: map[string]hash.Hash{"collections": collHash}}.ToEntity())

		v, err := Evaluate(apply, scope, DefaultBudget(), ctx)
		if err != nil {
			t.Fatalf("concat with error element must not fault: %v", err)
		}
		arr, ok := v.([]interface{})
		if !ok || len(arr) != 3 {
			t.Fatalf("concat should join 3 elements incl. the error, got %v", v)
		}
		if _, isErr := computeErrorFromValue(arr[1]); !isErr {
			t.Fatalf("the error element must flow through at position 1, got %v (%T)", arr[1], arr[1])
		}
	})

	t.Run("one-level-no-recursive-flatten", func(t *testing.T) {
		colls := litHash(t, cs, []interface{}{
			[]interface{}{[]interface{}{int64(1)}},
			[]interface{}{[]interface{}{int64(2)}},
		})
		v, err := evalBuiltinApply(t, ctx, BuiltinConcat, map[string]hash.Hash{"collections": colls})
		if err != nil {
			t.Fatalf("concat nested: %v", err)
		}
		arr := v.([]interface{})
		if len(arr) != 2 {
			t.Fatalf("one-level concat must keep 2 array elements, got %d: %v", len(arr), arr)
		}
		if _, ok := arr[0].([]interface{}); !ok {
			t.Fatalf("elements must stay arrays (no recursive flatten), got %T", arr[0])
		}
	})
}

func TestBuiltinAssoc(t *testing.T) {
	ctx, cs := testCtx()
	coll := litHash(t, cs, []interface{}{int64(10), int64(20), int64(30)})

	t.Run("replaces-at-index", func(t *testing.T) {
		v, err := evalBuiltinApply(t, ctx, BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": litHash(t, cs, int64(1)), "value": litHash(t, cs, int64(99)),
		})
		if err != nil {
			t.Fatalf("assoc: %v", err)
		}
		assertInt64Group(t, v, []int64{10, 99, 30}, "assoc")
	})

	t.Run("out-of-range-is-index-out-of-range", func(t *testing.T) {
		// v3.25 (C-2, ruled): same code and condition as compute/index (§2.2) —
		// go's v3.24 type_mismatch re-litigated a landed ruling and is corrected.
		_, err := evalBuiltinApply(t, ctx, BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": litHash(t, cs, int64(5)), "value": litHash(t, cs, int64(0)),
		})
		mustComputeErr(t, err, ErrIndexOutOfRange, "assoc(oob)")
	})

	t.Run("negative-index-is-index-out-of-range", func(t *testing.T) {
		_, err := evalBuiltinApply(t, ctx, BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": litHash(t, cs, int64(-1)), "value": litHash(t, cs, int64(0)),
		})
		mustComputeErr(t, err, ErrIndexOutOfRange, "assoc(-1)")
	})

	t.Run("error-value-flows-in-not-short-circuit", func(t *testing.T) {
		// value is a DATA position: an error-as-value is PLACED into the array,
		// matching map's element results. The whole assoc must NOT short-circuit.
		errHash := storedErrorOperand(t, cs, "placed_error")
		v, err := evalBuiltinApply(t, ctx, BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": litHash(t, cs, int64(0)), "value": errHash,
		})
		if err != nil {
			t.Fatalf("assoc(error value) must not short-circuit, got err=%v", err)
		}
		arr := v.([]interface{})
		got, ok := arr[0].(entity.Entity)
		if !ok || got.Type != types.TypeComputeError {
			t.Fatalf("assoc must place the error VALUE at index 0, got %v (%T)", arr[0], arr[0])
		}
	})

	t.Run("index-error-short-circuits", func(t *testing.T) {
		// index is a CONTROL position — an error-as-value there short-circuits.
		errHash := storedErrorOperand(t, cs, "idx_error")
		_, err := evalBuiltinApply(t, ctx, BuiltinAssoc, map[string]hash.Hash{
			"collection": coll, "index": errHash, "value": litHash(t, cs, int64(0)),
		})
		mustComputeErr(t, err, "idx_error", "assoc(error index)")
	})
}
