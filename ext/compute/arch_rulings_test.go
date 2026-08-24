package compute

// Conformance tests for the two arch rulings absorbed from the compute corpus's
// first cross-impl run (ARCH-RESPONSE-COMPUTE-CORPUS-FIRST-RUN, 2026-07-23).
//
//   F-2 (R3): an out-of-range INTEGER index is index_out_of_range, not
//             type_mismatch — int/uint are annotations, not distinct value
//             types (§9.1 + §2.2). Rust was ruled correct; Go answered
//             type_mismatch for a uint64 above int64 range.
//   Q1:       a MATERIALIZED compute/error is content-hashed over `code` alone.
//             message/at/expression are diagnostic and MUST NOT enter the bytes
//             V7 content-addresses, or two impls raising the same code with
//             different prose diverge on the tree hash — breaking dedup,
//             cross-peer sync, and AE-1 error-boundary equivalence.

import (
	"math"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestReactiveErrorCrossingIsCodeOnly is the engine-side of (B) v3.23 and the Go
// analog of the representation split py hit at its crossing (2026-08-16). A
// reactive subgraph whose root resolves to an entity-VALUE compute/error (here a
// lookup/tree onto a stored error) evaluates to that error as a value — SA-1, nil
// Go-error — so the *ComputeError branch never fires. The result_path write is a
// materialized crossing (§2.4 code-only), so it MUST be recognized as the error
// path and stripped to code. Before the fix it fell through to wrapResult and was
// written verbatim (message intact) — a cross-impl result-hash divergence.
func TestReactiveErrorCrossingIsCodeOnly(t *testing.T) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	engine := NewEngine(cs, li, nil)
	engine.localPeerID = "testpeer"
	grantHash := makeTestGrant(t, cs)

	// The lookup target holds a compute/error VALUE carrying a loud message.
	errPath := "/testpeer/app/err"
	stored := mustE((&ComputeError{Code: "reactive_error", Message: "LOUD prose that must not reach the result hash"}).ToEntity())
	storedHash, _ := cs.Put(stored)
	li.Set(errPath, storedHash)

	// Root expression: lookup/tree(errPath) → the stored error, returned as a value.
	lookupEnt := mustE(types.ComputeLookupTreeData{Path: errPath}.ToEntity())
	lookupHash, _ := cs.Put(lookupEnt)
	exprPath := store.QualifyPath("testpeer", "app/expr")
	li.Set(exprPath, lookupHash)

	resultPath := store.QualifyPath("testpeer", "app/expr/result")
	subgraphPath := subgraphPrefix + deterministicID(exprPath)
	sgData := types.ComputeSubgraphData{
		RootExpressionPath: exprPath,
		RootExpression:     lookupHash,
		InstallationGrant:  grantHash,
		ResultPath:         resultPath,
		Status:             "active",
	}
	sgEnt, _ := sgData.ToEntity()
	sgHash, _ := cs.Put(sgEnt)
	li.Set(store.QualifyPath("testpeer", subgraphPath), sgHash)
	engine.registerSubgraphDependencies(subgraphPath, exprPath, lookupEnt)

	// Re-eval on a message-only change to the stored error.
	updated := mustE((&ComputeError{Code: "reactive_error", Message: "an ENTIRELY different message, of a different length"}).ToEntity())
	updatedHash, _ := cs.Put(updated)
	li.Set(errPath, updatedHash)
	engine.OnTreeChange(store.TreeChangeEvent{Path: errPath, Hash: updatedHash, ChangeType: store.ChangeModified})

	resultHash, ok := li.Get(resultPath)
	if !ok {
		t.Fatal("expected a result written at result_path")
	}
	resultEnt, ok := cs.Get(resultHash)
	if !ok {
		t.Fatal("expected result entity in store")
	}
	if resultEnt.Type != types.TypeComputeError {
		t.Fatalf("reactive error crossing wrote %s, want compute/error — the value-form error was not recognized at the crossing", resultEnt.Type)
	}
	fields := decodeErrorFields(t, resultEnt)
	if len(fields) != 1 || fields["code"] != "reactive_error" {
		t.Errorf("result_path error is not code-only (§2.4): %v — message leaked into the content-addressed result", fields)
	}
}

// --- F-2: index error classification ---

func TestIndexErrorClassification(t *testing.T) {
	ctx, cs := testCtx()
	arr := litHash(t, cs, []interface{}{"a", "b", "c"}) // length 3

	cases := []struct {
		name  string
		index interface{}
		want  string
	}{
		// The F-2 case proper: a uint64 above int64 range. It is a well-formed
		// integer index (a valid ARGUMENT) whose magnitude is out of bounds — no
		// array approaches 2⁶³ elements — so index_out_of_range, not type error.
		{"uint64-above-int64-range", uint64(math.MaxInt64) + 1, ErrIndexOutOfRange},
		{"uint64-max", uint64(math.MaxUint64), ErrIndexOutOfRange},
		// The reading that motivates the ruling: the corpus hit this as
		// index(arr, cast(-4, uint)) = 2⁶⁴−4.
		{"cast-negative-to-uint-magnitude", uint64(math.MaxUint64) - 3, ErrIndexOutOfRange},
		// In-int64-range out-of-bounds: unchanged, already index_out_of_range.
		{"large-in-range", int64(99), ErrIndexOutOfRange},
		{"negative", int64(-1), ErrIndexOutOfRange},
		// Genuine non-integers stay type_mismatch — the ruling reclassifies
		// out-of-range integers only, it does not make everything an index error.
		{"string", "x", ErrTypeMismatch},
		{"float", float64(1.5), ErrTypeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ent := mustE(types.ComputeIndexData{
				Array: arr, Index: litHash(t, cs, tc.index),
			}.ToEntity())
			_, err := Evaluate(ent, NewScope(), DefaultBudget(), ctx)
			ce, ok := err.(*ComputeError)
			if !ok {
				t.Fatalf("expected a ComputeError, got %v", err)
			}
			if ce.Code != tc.want {
				t.Errorf("index %v (%T): expected %q, got %q (%s)",
					tc.index, tc.index, tc.want, ce.Code, ce.Message)
			}
		})
	}
}

// --- Q1: materialized compute/error is code-only ---

// decodeErrorFields reports which fields a materialized compute/error entity's
// data actually carries, by decoding into an open map. This is the honest check:
// asserting on the typed struct would hide a `message: ""` that is present in
// the bytes, and it is exactly the bytes V7 hashes that matter.
func decodeErrorFields(t *testing.T, ent entity.Entity) map[string]interface{} {
	t.Helper()
	if ent.Type != types.TypeComputeError {
		t.Fatalf("not a compute/error entity: %s", ent.Type)
	}
	var m map[string]interface{}
	if err := ecf.Decode(ent.Data, &m); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	return m
}

func TestMaterializedErrorIsCodeOnly(t *testing.T) {
	ce := &ComputeError{
		Code:    ErrDivisionByZero,
		Message: "Division by zero",
		At:      "some/expr/path",
	}
	ent, err := ce.ToMaterializedEntity()
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeErrorFields(t, ent)
	if len(fields) != 1 {
		t.Fatalf("materialized error must carry code alone, got fields %v", fields)
	}
	if fields["code"] != ErrDivisionByZero {
		t.Errorf("code = %v, want %q", fields["code"], ErrDivisionByZero)
	}
}

// The core determinism claim: two errors with the same code and DIFFERENT prose
// must materialize to the same content hash. This is what keeps dedup and
// cross-peer sync from diverging over the error input-space.
func TestMaterializedErrorHashIgnoresProse(t *testing.T) {
	a := &ComputeError{Code: ErrIndexOutOfRange, Message: "index 99 out of range for array of length 4"}
	b := &ComputeError{Code: ErrIndexOutOfRange, Message: "index 99 >= length 4", At: "b/path"}

	entA, err := a.ToMaterializedEntity()
	if err != nil {
		t.Fatal(err)
	}
	entB, err := b.ToMaterializedEntity()
	if err != nil {
		t.Fatal(err)
	}
	if entA.ContentHash != entB.ContentHash {
		t.Errorf("same code, different prose → different materialized hash:\n  %s\n  %s\n"+
			"this is the Go↔Rust message divergence (135 vectors) leaking into the content hash",
			entA.ContentHash, entB.ContentHash)
	}
}

// A materialized error and a code-different error must NOT collide — the strip
// keeps code, it does not blank everything.
func TestMaterializedErrorDistinguishesCode(t *testing.T) {
	a := &ComputeError{Code: ErrIndexOutOfRange, Message: "x"}
	b := &ComputeError{Code: ErrDivisionByZero, Message: "x"}
	entA, _ := a.ToMaterializedEntity()
	entB, _ := b.ToMaterializedEntity()
	if entA.ContentHash == entB.ContentHash {
		t.Error("different codes materialized to the same hash — code was dropped")
	}
}

// The in-flight form is the dispatch-boundary representation and MAY keep
// diagnostics (§3.7 / F10). The ruling preserves it; only materialization
// strips. Guard that ToEntity still carries the message so the wire status-200
// error-as-value return remains diagnostic.
func TestInFlightErrorKeepsDiagnostics(t *testing.T) {
	ce := &ComputeError{Code: ErrNotFound, Message: "No scope binding: n", At: "expr/0"}
	ent, err := ce.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeErrorFields(t, ent)
	if fields["message"] != "No scope binding: n" {
		t.Errorf("in-flight error dropped its message: %v", fields)
	}
	if fields["at"] != "expr/0" {
		t.Errorf("in-flight error dropped its at: %v", fields)
	}
}

// (B) v3.23 reversed this. materialize() USED to code-only-strip a compute/error
// threaded into a construct field (behaviour A); the ruling makes an error at any
// consumption site short-circuit BEFORE materialize (§4.1 is_error [MUST]), so an
// error must never reach materialize() at all. This is the negative form of the
// removed convention (per AGENTS.md — a removed-convention assert becomes an
// invariant test, not a deleted one): if an error ever reaches materialize(), a
// short-circuit was missed upstream and it fails loudly rather than silently
// re-embedding (regressing to A).
func TestMaterializeRejectsErrorEntity(t *testing.T) {
	_, cs := testCtx()
	inflight := mustE((&ComputeError{
		Code: ErrTypeMismatch, Message: "operand types differ", At: "p",
	}).ToEntity())

	if _, err := materialize(inflight, cs); err == nil {
		t.Fatal("materialize() accepted a compute/error — it must reject one (v3.23: errors propagate from consumption sites, never materialize there)")
	}

	// The code-only stripping did not disappear — it MOVED to the write site
	// (§7.2 result_path / SA-9 store), which goes through ToMaterializedEntity.
	matEnt := mustE((&ComputeError{
		Code: ErrTypeMismatch, Message: "operand types differ", At: "p",
	}).ToMaterializedEntity())
	fields := decodeErrorFields(t, matEnt)
	if len(fields) != 1 || fields["code"] != ErrTypeMismatch {
		t.Errorf("ToMaterializedEntity did not strip the error to code-only: %v", fields)
	}

	// A non-error entity still passes through materialize untouched.
	lit := mustE(types.ComputeLiteralData{Value: int64(5)}.ToEntity())
	passed, err := materialize(lit, cs)
	if err != nil {
		t.Fatal(err)
	}
	if pe, ok := passed.(entity.Entity); !ok || pe.ContentHash != lit.ContentHash {
		t.Errorf("materialize altered a non-error entity: %v", passed)
	}
}
