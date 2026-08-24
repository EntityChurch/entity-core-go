package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Corner 1 of the §3.5 open corners arch ruled in the C-8 packet (172589e):
// the CLOSURE RESULT of map/filter/fold has a per-primitive disposition,
// because handing a value to a closure is a BINDING, not a consumption, and
// what each primitive then DOES with the result is what decides contain vs
// short-circuit. go exhibited the §2.4-forbidden provenance asymmetry — the
// minted *ComputeError form and the value-form compute/error took different
// paths at the same position.
//
//   - filter: predicate result is CONSUMED (read for truthiness) → short-circuit.
//   - map:    output element is CONTAINED (placed, never read) → contain.
//   - fold:   final accumulator is CONTAINED — fold binds it into the next closure
//             invocation and never reads it, so a closure that ignores its
//             accumulator RECOVERS (arch C-8, CV-8d). fold NEVER short-circuits on
//             an error accumulator. This corrected an earlier reading that took
//             arch's word "propagates" (= threads onward into the next call) to
//             mean short-circuit; arch flagged fold as the one with the widest
//             blast radius because the wrong reading produces a different VALUE.
//
// Both representations are asserted at each contained/consumed position: a minted
// error (closure body div(1,0)) and a value-form error (closure body is a stored
// compute/error, returned via SA-1 with a nil Go-error) — the §2.4 provenance
// independence the map asymmetry violated.

// oneElemArray is a non-empty collection so the closure is invoked at least once.
func oneElemArray(t *testing.T, cs store.ContentStore) hash.Hash {
	t.Helper()
	return mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1)}}.ToEntity()))
}

func TestFilterPredicateResultErrorShortCircuits(t *testing.T) {
	ctx, cs := testCtx()
	coll := oneElemArray(t, cs)

	// value form: predicate body IS a stored compute/error → SA-1 value result.
	valueErrBody := storedErrorOperand(t, cs, "operand_error")
	valuePred := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: valueErrBody}.ToEntity()))

	// minted form: predicate body div(1,0) → Evaluate mints a *ComputeError.
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedBody := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))
	mintedPred := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: mintedBody}.ToEntity()))

	for _, tc := range []struct {
		rep, wantCode string
		fn            hash.Hash
	}{
		{"value-form", "operand_error", valuePred},
		{"minted", "division_by_zero", mintedPred},
	} {
		t.Run(tc.rep, func(t *testing.T) {
			apply := mustE(types.ComputeApplyData{Path: BuiltinFilter, Operation: "eval",
				Args: map[string]hash.Hash{"collection": coll, "fn": tc.fn}}.ToEntity())
			_, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			ce, ok := err.(*ComputeError)
			if !ok {
				// The value-form failure mode is especially quiet: truthy(errorEntity)
				// hits the default `return true`, so the element is silently KEPT.
				t.Fatalf("filter(%s predicate error): did NOT short-circuit — got err=%v (want *ComputeError %s)", tc.rep, err, tc.wantCode)
			}
			if ce.Code != tc.wantCode {
				t.Errorf("filter(%s predicate error): short-circuited to %q, want %q", tc.rep, ce.Code, tc.wantCode)
			}
		})
	}
}

// TestFoldAccumulatorErrorRecovers enforces arch's C-8 ruling (CV-8d) that fold's
// accumulator is CONTAINED, not short-circuited: a closure that ignores its
// accumulator RECOVERS from an error acc, and the wrong reading (short-circuit)
// produces a different VALUE — which is why arch flagged fold as the widest blast
// radius. A closure λacc x. x ignores the accumulator and returns the element, so
// an error threaded in as the initial accumulator is dropped and the fold returns
// the last element. Asserted for BOTH representations of the error initial
// (value-form and minted): fold must not short-circuit on either.
func TestFoldAccumulatorErrorRecovers(t *testing.T) {
	ctx, cs := testCtx()
	// two elements so the accumulator is carried across an iteration — the closure
	// ignoring an error acc on step 2 is the per-iteration recovery a single element
	// cannot exercise (the mutation that survives a set-initial-only test).
	twoElem := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2)}}.ToEntity()))
	// λacc x. x — ignores the accumulator, returns the element.
	ignoreAccBody := mustPut(t, cs, mustE(types.ComputeLookupScopeData{Name: "x"}.ToEntity()))
	ignoreAccFn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"acc", "x"}, Body: ignoreAccBody}.ToEntity()))

	// value-form error initial: a stored compute/error resolved via SA-1.
	valueErrInitial := storedErrorOperand(t, cs, "operand_error")
	// minted error initial: div(1,0) evaluates to a *ComputeError.
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedErrInitial := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))

	for _, tc := range []struct {
		rep     string
		initial hash.Hash
	}{
		{"value-form", valueErrInitial},
		{"minted", mintedErrInitial},
	} {
		t.Run(tc.rep, func(t *testing.T) {
			apply := mustE(types.ComputeApplyData{Path: BuiltinFold, Operation: "eval",
				Args: map[string]hash.Hash{"collection": twoElem, "fn": ignoreAccFn, "initial": tc.initial}}.ToEntity())
			v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("fold(%s error initial, λacc x.x): did NOT recover — short-circuited err=%v (want value 2)", tc.rep, err)
			}
			// The element round-trips through the collection literal's CBOR, so a
			// positive int decodes as uint64 (eval_test.go: "positive int64 decodes
			// as uint64"). The point is that fold RECOVERED to the element value —
			// err==nil above — rather than short-circuiting to the error.
			if got, ok := v.(uint64); !ok || got != 2 {
				t.Fatalf("fold(%s error initial, λacc x.x): recovered to %#v, want uint64(2)", tc.rep, v)
			}
		})
	}
}

// TestFoldFinalAccumulatorErrorContained enforces the other half of CV-8d: when
// the closure PRODUCES an error every step, the final accumulator is a CONTAINED
// compute/error VALUE (err==nil), not a short-circuit. With two elements the
// per-iteration containment branch runs on step 2 with an error accumulator from
// step 1 — the proof fold keeps folding rather than aborting. Both representations.
func TestFoldFinalAccumulatorErrorContained(t *testing.T) {
	ctx, cs := testCtx()
	twoElem := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2)}}.ToEntity()))
	validInitial := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))

	// value form: fn body IS a stored compute/error → acc becomes a value-form error.
	valueErrBody := storedErrorOperand(t, cs, "operand_error")
	valueFn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"acc", "x"}, Body: valueErrBody}.ToEntity()))

	// minted form: fn body div(1,0).
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedBody := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))
	mintedFn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"acc", "x"}, Body: mintedBody}.ToEntity()))

	for _, tc := range []struct {
		rep, wantCode string
		fn            hash.Hash
	}{
		{"value-form", "operand_error", valueFn},
		{"minted", "division_by_zero", mintedFn},
	} {
		t.Run(tc.rep, func(t *testing.T) {
			apply := mustE(types.ComputeApplyData{Path: BuiltinFold, Operation: "eval",
				Args: map[string]hash.Hash{"collection": twoElem, "fn": tc.fn, "initial": validInitial}}.ToEntity())
			v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("fold(%s fn error): CONTAINS final acc, got short-circuit err=%v", tc.rep, err)
			}
			ce, isErr := computeErrorFromValue(v)
			if !isErr {
				t.Fatalf("fold(%s fn error): final accumulator is not a contained compute/error, got %#v", tc.rep, v)
			}
			if ce.Code != tc.wantCode {
				t.Errorf("fold(%s fn error): contained final acc code %q, want %q", tc.rep, ce.Code, tc.wantCode)
			}
		})
	}
}

// TestMapClosureResultContains enforces arch's C-8 ruling that map's output
// element CONTAINS a closure error result — for BOTH representations, killing
// the §2.4 provenance asymmetry (a value-form error already flowed in as the
// element; a minted error used to abort the whole map). A produced error becomes
// a contained output element, index-for-index — mapping a fallible fn returns an
// array with error markers (NaN-style, §1.5), never a short-circuit.
func TestMapClosureResultContains(t *testing.T) {
	ctx, cs := testCtx()
	// two-element collection so "contained" (2 error elements) is unambiguously
	// distinguished from "short-circuit" (a single error, no array).
	twoElem := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2)}}.ToEntity()))

	// value-form closure result: body IS a stored compute/error → SA-1 value.
	valueErrBody := storedErrorOperand(t, cs, "operand_error")
	valueFn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: valueErrBody}.ToEntity()))

	// minted closure result: body div(1,0) → Evaluate mints a *ComputeError.
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedBody := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))
	mintedFn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: mintedBody}.ToEntity()))

	for _, tc := range []struct {
		rep, wantCode string
		fn            hash.Hash
	}{
		{"value-form", "operand_error", valueFn},
		{"minted", "division_by_zero", mintedFn},
	} {
		t.Run(tc.rep, func(t *testing.T) {
			apply := mustE(types.ComputeApplyData{Path: BuiltinMap, Operation: "eval",
				Args: map[string]hash.Hash{"collection": twoElem, "fn": tc.fn}}.ToEntity())
			v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			if err != nil {
				t.Fatalf("map(%s closure error): CONTAINS, got short-circuit err=%v", tc.rep, err)
			}
			arr, ok := v.([]interface{})
			if !ok || len(arr) != 2 {
				t.Fatalf("map(%s closure error): want a 2-element array (errors contained), got %T %v", tc.rep, v, v)
			}
			for i, e := range arr {
				ce, isErr := computeErrorFromValue(e)
				if !isErr {
					t.Fatalf("map(%s closure error): element %d is not a contained compute/error, got %#v", tc.rep, i, e)
				}
				if ce.Code != tc.wantCode {
					t.Errorf("map(%s closure error): element %d code %q, want %q", tc.rep, i, ce.Code, tc.wantCode)
				}
			}
		})
	}
}

// TestShortCircuitLimitCodeClassification locks arch §8 (EXTENSION-COMPUTE 3.27
// D5): the SHORT-CIRCUIT eval-limit set is EXACTLY {budget_exhausted, cascade_limit}
// — the codes whose counter is NOT restored on unwind (§5.1), so a contained
// result would fork cross-impl. depth_exceeded is NOT in it: its `depth` is restored
// on unwind, so it is element-local and CONTAINS like any other error (§8.3). This
// reverses go's prior 1-of-3 outlier reading (which short-circuited all three);
// rust and py were right and the spec arbitrates against go (ruling h §2).
func TestShortCircuitLimitCodeClassification(t *testing.T) {
	for _, c := range []string{ErrBudgetExhausted, ErrCascadeLimit} {
		if !isShortCircuitLimitCode(c) {
			t.Errorf("isShortCircuitLimitCode(%q) = false, want true (counter not restored on unwind → short-circuits)", c)
		}
	}
	// depth_exceeded is the row that flipped: it CONTAINS now.
	for _, c := range []string{ErrDepthExceeded, ErrDivisionByZero, ErrTypeMismatch, ErrIndexOutOfRange, ErrPermissionDenied, ErrScopeUnreachable, "operand_error"} {
		if isShortCircuitLimitCode(c) {
			t.Errorf("isShortCircuitLimitCode(%q) = true, want false (contained: element-local or a produced value-error)", c)
		}
	}

	// End-to-end: a budget so small the loop exhausts → map returns the
	// short-circuited budget_exhausted, NOT a contained array. Whether it exhausts
	// in setup or mid-loop, a short-circuit limit code never yields a contained
	// array — it aborts (§8.1, CV-9b).
	ctx, cs := testCtx()
	coll := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2), int64(3), int64(4), int64(5), int64(6), int64(7), int64(8)}}.ToEntity()))
	body := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	fn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: body}.ToEntity()))
	apply := mustE(types.ComputeApplyData{Path: BuiltinMap, Operation: "eval",
		Args: map[string]hash.Hash{"collection": coll, "fn": fn}}.ToEntity())
	v, err := Evaluate(apply, NewScope(), &Budget{Operations: 4, Depth: 64}, ctx)
	if _, isArr := v.([]interface{}); isArr {
		t.Fatalf("map with an exhausting budget returned a CONTAINED array %v — budget_exhausted must abort, not be contained", v)
	}
	ce, ok := err.(*ComputeError)
	if !ok || ce.Code != ErrBudgetExhausted {
		t.Fatalf("map with an exhausting budget: want short-circuited budget_exhausted, got v=%v err=%v", v, err)
	}
}

// TestMapValueFormShortCircuitLimitCodeShortCircuits is the CV-9c defect fix
// (arch §8.4 / D6 / SA-PY-25): a VALUE-FORM budget_exhausted / cascade_limit
// flowing out of a closure into map's contained output position MUST short-circuit
// exactly as a minted one does — keyed on the CODE, never the variant. go's
// minted-only carve-out used to CONTAIN a value-form budget_exhausted while
// short-circuiting a minted one — the exact §2.4 provenance asymmetry Corner 1 was
// opened to kill, reinstated inside the carve-out Corner 1 created. Mutation: with
// the value-form arm removed this returns a contained array and fails.
func TestMapValueFormShortCircuitLimitCodeShortCircuits(t *testing.T) {
	ctx, cs := testCtx()
	twoElem := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2)}}.ToEntity()))
	for _, code := range []string{ErrBudgetExhausted, ErrCascadeLimit} {
		t.Run(code, func(t *testing.T) {
			// closure body IS a stored compute/error{code} → SA-1 value-form result.
			errBody := storedErrorOperand(t, cs, code)
			fn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: errBody}.ToEntity()))
			apply := mustE(types.ComputeApplyData{Path: BuiltinMap, Operation: "eval",
				Args: map[string]hash.Hash{"collection": twoElem, "fn": fn}}.ToEntity())
			v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			if _, isArr := v.([]interface{}); isArr {
				t.Fatalf("map(value-form %s): CONTAINED %v — a value-form short-circuit code must abort, keyed on the code (§8.4/D6)", code, v)
			}
			ce, ok := err.(*ComputeError)
			if !ok || ce.Code != code {
				t.Fatalf("map(value-form %s): want short-circuit to %q, got v=%v err=%v", code, code, v, err)
			}
		})
	}
}

// TestMapDepthExceededContains locks §8.3: depth_exceeded CONTAINS in map's output
// position, for BOTH representations. `depth` is restored on unwind, so element i
// begins at the same depth every time — map(f,xs) exceeding depth on one element
// yields [.., E, ..], the §1.5 NaN model, evaluated identically by every peer. This
// is the CV-9a shape and the row that flipped from go's prior reading.
func TestMapDepthExceededContains(t *testing.T) {
	ctx, cs := testCtx()
	twoElem := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(1), int64(2)}}.ToEntity()))
	// value-form depth_exceeded flowing out of the closure body.
	errBody := storedErrorOperand(t, cs, ErrDepthExceeded)
	fn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: errBody}.ToEntity()))
	apply := mustE(types.ComputeApplyData{Path: BuiltinMap, Operation: "eval",
		Args: map[string]hash.Hash{"collection": twoElem, "fn": fn}}.ToEntity())
	v, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	if err != nil {
		t.Fatalf("map(value-form depth_exceeded): CONTAINS, got short-circuit err=%v", err)
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("map(value-form depth_exceeded): want a 2-element array (contained), got %T %v", v, v)
	}
	for i, e := range arr {
		ce, isErr := computeErrorFromValue(e)
		if !isErr || ce.Code != ErrDepthExceeded {
			t.Fatalf("map(value-form depth_exceeded): element %d = %#v, want contained depth_exceeded", i, e)
		}
	}
}
