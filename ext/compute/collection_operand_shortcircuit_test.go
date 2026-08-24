package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestCollectionOperandErrorShortCircuits enforces §7.2: the `collection`
// operand of map/filter/fold/assoc/group-by is a CONSUMED position, so a
// compute/error there MUST short-circuit — NOT be reported as type_mismatch.
// resolveCollection used bare Evaluate, which masks a value-form error (an
// SA-1 literal / a lookup onto a stored error is not a Go-error, so it fell to
// the "not an array" branch). is_error is kind-based, so BOTH representations
// are asserted: the value form AND a minted form (a div-by-zero collection).
//
// This is the gap core-rust and core-py both traced back to go and the reason
// the 352-vector corpus LOCKED with the bug live — no vector placed an error in
// the collection operand. Fixed: resolveCollection uses evalOperand.
func TestCollectionOperandErrorShortCircuits(t *testing.T) {
	ctx, cs := testCtx()

	// value form: an SA-1 stored compute/error, referenced as the collection.
	valueErr := storedErrorOperand(t, cs, "operand_error")

	// minted form: a div(1,0) expression whose evaluation mints a *ComputeError.
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedErr := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))

	// a valid closure arg, so nothing but the collection short-circuit is exercised.
	body := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	fn := mustPut(t, cs, mustE(types.ComputeClosureData{Params: []string{"x"}, Body: body}.ToEntity()))

	ops := []struct {
		name string
		path string
		args func(collection hash.Hash) map[string]hash.Hash
	}{
		{"map", BuiltinMap, func(c hash.Hash) map[string]hash.Hash { return map[string]hash.Hash{"collection": c, "fn": fn} }},
		{"filter", BuiltinFilter, func(c hash.Hash) map[string]hash.Hash { return map[string]hash.Hash{"collection": c, "fn": fn} }},
		{"fold", BuiltinFold, func(c hash.Hash) map[string]hash.Hash {
			return map[string]hash.Hash{"collection": c, "fn": fn, "initial": body}
		}},
		{"group-by", BuiltinGroupBy, func(c hash.Hash) map[string]hash.Hash { return map[string]hash.Hash{"collection": c, "fn": fn} }},
		{"assoc", BuiltinAssoc, func(c hash.Hash) map[string]hash.Hash {
			return map[string]hash.Hash{"collection": c, "index": body, "value": body}
		}},
	}

	reps := []struct {
		rep      string
		hash     hash.Hash
		wantCode string
	}{
		{"value-form", valueErr, "operand_error"},
		{"minted", mintedErr, "division_by_zero"},
	}

	for _, op := range ops {
		for _, r := range reps {
			t.Run(op.name+"/"+r.rep, func(t *testing.T) {
				apply := mustE(types.ComputeApplyData{Path: op.path, Operation: "eval", Args: op.args(r.hash)}.ToEntity())
				_, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
				ce, ok := err.(*ComputeError)
				if !ok {
					t.Fatalf("%s(%s collection): did NOT short-circuit (§7.2) — got err=%v (want *ComputeError %s)", op.name, r.rep, err, r.wantCode)
				}
				if ce.Code != r.wantCode {
					t.Errorf("%s(%s collection): short-circuited to %q, want %q — a consumed error operand must propagate its own code, not be masked as type_mismatch", op.name, r.rep, ce.Code, r.wantCode)
				}
			})
		}
	}
}

// TestConcatSubCollectionErrorShortCircuits enforces the concat half of the same
// §7.2 rule: EACH `collection` (sub-array) is consumed, so an error SUB-collection
// short-circuits — distinct from an error ELEMENT of a valid sub-collection, which
// is contained (CV-5). go typed each sub-collection via c.([]interface{}), which
// reported type_mismatch for an error sub-collection instead of propagating it.
func TestConcatSubCollectionErrorShortCircuits(t *testing.T) {
	ctx, cs := testCtx()
	valueErr := storedErrorOperand(t, cs, "operand_error")

	// collections = assoc([0], 0, E) → [E]: a single error sub-collection, live
	// (a frozen literal would degrade E to a bare map). concat consumes it.
	seed := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: []interface{}{int64(0)}}.ToEntity()))
	idx0 := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	collections := mustPut(t, cs, mustE(types.ComputeApplyData{
		Path: BuiltinAssoc, Operation: "eval",
		Args: map[string]hash.Hash{"collection": seed, "index": idx0, "value": valueErr},
	}.ToEntity()))

	apply := mustE(types.ComputeApplyData{
		Path: BuiltinConcat, Operation: "eval",
		Args: map[string]hash.Hash{"collections": collections},
	}.ToEntity())

	_, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
	ce, ok := err.(*ComputeError)
	if !ok {
		t.Fatalf("concat(error sub-collection): did NOT short-circuit (§7.2) — got err=%v", err)
	}
	if ce.Code != "operand_error" {
		t.Errorf("concat(error sub-collection): short-circuited to %q, want operand_error (a consumed sub-collection error, not a contained element)", ce.Code)
	}
}

// TestStorePathOperandErrorShortCircuits enforces the SAME §7.2 consumed-operand
// rule on store's `path`: the path STEERS where the write goes (like assoc's
// index), so a compute/error path SHORT-CIRCUITS — it is not type_mismatch. §200
// states the store model directly ("an error-valued store field would
// short-circuit to that error"). Only store's `value` is the write/contain
// position. store resolved `path` with bare Evaluate + .(string), the
// resolveCollection slip on store's own operand — found by the 2026-08-21
// consumed-operand sweep. Both representations asserted.
func TestStorePathOperandErrorShortCircuits(t *testing.T) {
	cs := store.NewMemoryContentStore()
	valueErr := storedErrorOperand(t, cs, "operand_error")
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	zero := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity()))
	mintedErr := mustPut(t, cs, mustE(types.ComputeArithmeticData{Op: "div", Left: one, Right: zero}.ToEntity()))
	val := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(7)}.ToEntity()))

	var dispatched bool
	ctx := &EvalContext{
		ContentStore:          cs,
		LocationIndex:         store.NewMemoryLocationIndex(),
		HasContentStoreAccess: true,
		DispatchExecute: func(string, string, *types.ResourceTarget, entity.Entity, *entity.Entity) (*handler.Response, error) {
			dispatched = true
			return &handler.Response{Status: 200}, nil
		},
	}

	for _, tc := range []struct {
		rep      string
		path     hash.Hash
		wantCode string
	}{
		{"value-form", valueErr, "operand_error"},
		{"minted", mintedErr, "division_by_zero"},
	} {
		t.Run(tc.rep, func(t *testing.T) {
			dispatched = false
			apply := mustE(types.ComputeApplyData{
				Path: BuiltinStore, Operation: "eval",
				Args: map[string]hash.Hash{"path": tc.path, "value": val},
			}.ToEntity())
			_, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx)
			ce, ok := err.(*ComputeError)
			if !ok {
				t.Fatalf("store(%s path): did NOT short-circuit (§7.2) — got err=%v", tc.rep, err)
			}
			if ce.Code != tc.wantCode {
				t.Errorf("store(%s path): short-circuited to %q, want %q (a consumed error operand must propagate, not mask as type_mismatch)", tc.rep, ce.Code, tc.wantCode)
			}
			if dispatched {
				t.Errorf("store(%s path): dispatched a write on an error path — the short-circuit must precede the write", tc.rep)
			}
		})
	}
}
