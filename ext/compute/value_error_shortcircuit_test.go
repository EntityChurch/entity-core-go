package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// storedErrorOperand puts a compute/error VALUE entity and returns its hash, so
// it can be referenced as an operand. On evaluate, SA-1 returns it as a value
// (nil Go-error) — the entity-VALUE error form, distinct from a minted
// *ComputeError. This is the form py's ~300 tests never covered (they all mint
// their error via an unresolvable hash), and the form Go's error-propagation
// also under-covers.
func storedErrorOperand(t *testing.T, cs store.ContentStore, code string) hash.Hash {
	t.Helper()
	ent := mustE((&ComputeError{Code: code, Message: "LOUD diagnostic prose that must not drive the outcome"}).ToEntity())
	return mustPut(t, cs, ent)
}

// TestValueFormErrorShortCircuits measures / enforces §2131 (v3.23): the
// consuming ops MUST short-circuit an is_error operand — kind-based, so an
// entity-VALUE compute/error counts, not only a minted *ComputeError. Go
// auto-propagates the minted form via its Go-error return; the value form is a
// value with nil error and must be caught by an explicit is_error check at each
// consumer. This is the representation split py hit at its crossing, in Go's
// internal consumers.
func TestValueFormErrorShortCircuits(t *testing.T) {
	ctx, cs := testCtx()
	errHash := storedErrorOperand(t, cs, "operand_error")
	one := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity()))
	tru := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: true}.ToEntity()))

	check := func(name string, ent entity.Entity) {
		t.Helper()
		_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
		ce, ok := err.(*ComputeError)
		if !ok {
			t.Errorf("%s: an is_error operand did NOT short-circuit (§2131) — got err=%v (want *ComputeError propagating operand_error)", name, err)
			return
		}
		if ce.Code != "operand_error" {
			t.Errorf("%s: short-circuited to %q, want the operand's own code operand_error (the op masked the error)", name, ce.Code)
		}
	}

	check("arithmetic", mustE(types.ComputeArithmeticData{Op: "add", Left: errHash, Right: one}.ToEntity()))
	check("compare", mustE(types.ComputeCompareData{Op: "eq", Left: errHash, Right: one}.ToEntity()))
	check("if-condition", mustE(types.ComputeIfData{Condition: errHash, Then: tru, Else: &tru}.ToEntity()))
	check("field", mustE(types.ComputeFieldData{Entity: errHash, Name: "code"}.ToEntity()))
}

// TestStoreErrorCrossingIsCodeOnly is the SA-9 store half of the §2.4
// write-site materialization gate — the imperative sibling of
// TestReactiveErrorCrossingIsCodeOnly (which covers the §7.2 result_path
// crossing). SA-9 store is a WRITE site (N1 §2.3 / §2.4 / §2148): a compute/error
// reaching store's value materializes code-only and is written to the path,
// message/at stripped so the content-addressed result converges cross-impl.
//
// This closes a two-representation gap: the §2131 fix (877edf5) covered the
// result_path crossing but NOT this store crossing — both are value-form-error
// materialization surfaces, so testing one was 0% coverage of the other (the
// exact AP-14 / two-representation shape). BOTH error representations are
// asserted at this one crossing:
//   - minted:     store(path, div(1,0)) — Evaluate returns a *ComputeError;
//   - value-form: store(path, lookup→stored error) — SA-1 value, nil Go-error.
//
// Before the fix the value form hit materialize() (which rejects a compute/error
// post-v3.23) and returned an internal error, writing nothing.
func TestStoreErrorCrossingIsCodeOnly(t *testing.T) {
	// minted: store(path, div(1,0)) — Evaluate returns a *ComputeError Go-error.
	div0 := func(t *testing.T, cs store.ContentStore, _ store.LocationIndex) hash.Hash {
		t.Helper()
		return mustPut(t, cs, mustE(types.ComputeArithmeticData{
			Op:    "div",
			Left:  mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(1)}.ToEntity())),
			Right: mustPut(t, cs, mustE(types.ComputeLiteralData{Value: int64(0)}.ToEntity())),
		}.ToEntity()))
	}
	// value-form: store(path, lookup/tree→stored error) — SA-1 returns it as a value.
	valueForm := func(t *testing.T, cs store.ContentStore, li store.LocationIndex) hash.Hash {
		t.Helper()
		errPath := "/peer1/app/err"
		errEnt := mustE((&ComputeError{Code: "stored_err", Message: "LOUD prose that must not reach the store hash"}).ToEntity())
		errHash, _ := cs.Put(errEnt)
		li.Set(errPath, errHash)
		return mustPut(t, cs, mustE(types.ComputeLookupTreeData{Path: errPath}.ToEntity()))
	}

	cases := []struct {
		name     string
		build    func(t *testing.T, cs store.ContentStore, li store.LocationIndex) hash.Hash
		wantCode string
	}{
		{"minted", div0, "division_by_zero"},
		{"value-form", valueForm, "stored_err"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := store.NewMemoryContentStore()
			li := store.NewMemoryLocationIndex()
			valueHash := tc.build(t, cs, li)
			pathHash := mustPut(t, cs, mustE(types.ComputeLiteralData{Value: "/peer1/app/dest"}.ToEntity()))

			var wrote *entity.Entity
			ctx := &EvalContext{
				ContentStore:  cs,
				LocationIndex: li,
				LocalPeerID:   "peer1",
				DispatchExecute: func(path, op string, resource *types.ResourceTarget, p entity.Entity, override *entity.Entity) (*handler.Response, error) {
					var pr types.PutRequestData
					if err := ecf.Decode(p.Data, &pr); err == nil {
						var ent entity.Entity
						if err := ecf.Decode(pr.Entity, &ent); err == nil {
							wrote = &ent
						}
					}
					return &handler.Response{Status: 200}, nil
				},
			}

			apply := mustE(types.ComputeApplyData{
				Path:      BuiltinStore,
				Operation: "eval",
				Args:      map[string]hash.Hash{"path": pathHash, "value": valueHash},
			}.ToEntity())

			if _, err := Evaluate(apply, NewScope(), DefaultBudget(), ctx); err != nil {
				t.Fatalf("store(%s error) returned err=%v — a write-site error must materialize, not fault", tc.name, err)
			}
			if wrote == nil {
				t.Fatalf("store(%s error) wrote nothing — the error was not materialized at the SA-9 write site", tc.name)
			}
			if wrote.Type != types.TypeComputeError {
				t.Fatalf("store(%s error) wrote %s, want compute/error", tc.name, wrote.Type)
			}
			fields := decodeErrorFields(t, *wrote)
			if len(fields) != 1 || fields["code"] != tc.wantCode {
				t.Errorf("store(%s error) is not code-only (§2.4): %v — want {code:%s}; message leaked into the content-addressed write", tc.name, fields, tc.wantCode)
			}
		})
	}
}
