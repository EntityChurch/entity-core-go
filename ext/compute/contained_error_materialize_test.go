package compute

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestMaterializeContainedErrorIsCodeOnly is the mechanism teeth for the v3.26
// carve-out (COMPUTE §3.5, spec-issue 2026-08-20-f): a compute/error CONTAINED as
// a direct array element — the three §3.5 data positions (assoc's value, concat's
// elements, group-by's members) and map's output-element precedent — materializes
// CODE-ONLY and is referenced by a bare system/hash, exactly like any other
// entity-valued element. It asserts three things at the materialize() boundary:
//  1. the element becomes a bare hash (not the inlined error entity);
//  2. the stored entity behind that hash is code-only (message/at stripped, §2.4);
//  3. the bare hash does NOT depend on the error's message — two errors with the
//     same code and different messages produce the SAME element hash, so the
//     containing array's content hash cannot fork cross-impl on unpinned prose.
func TestMaterializeContainedErrorIsCodeOnly(t *testing.T) {
	cs := store.NewMemoryContentStore()

	errEnt := func(code, message string) entity.Entity {
		return mustE((&ComputeError{Code: code, Message: message}).ToEntity())
	}

	mv, err := materialize([]interface{}{int64(1), errEnt("boom", "message A"), int64(3)}, cs)
	if err != nil {
		t.Fatalf("materialize contained error: %v — the v3.26 array-element carve-out must not reject", err)
	}
	arr, ok := mv.([]interface{})
	if !ok || len(arr) != 3 {
		t.Fatalf("materialized array shape wrong: %T %v", mv, mv)
	}

	// (1) element became a bare hash, not the inlined error entity.
	elemHash, ok := arr[1].(hash.Hash)
	if !ok {
		t.Fatalf("contained error element is %T, want a bare system/hash reference", arr[1])
	}
	// the sibling primitives pass through unchanged.
	if arr[0] != int64(1) || arr[2] != int64(3) {
		t.Errorf("carve-out disturbed sibling elements: got [%v _ %v], want [1 _ 3]", arr[0], arr[2])
	}

	// (2) the stored entity is code-only.
	stored, ok := cs.Get(elemHash)
	if !ok {
		t.Fatalf("code-only error %s not resident in the content store — a bare hash element must resolve", elemHash)
	}
	if stored.Type != types.TypeComputeError {
		t.Fatalf("contained element resolves to %s, want compute/error", stored.Type)
	}
	fields := decodeErrorFields(t, stored)
	if len(fields) != 1 || fields["code"] != "boom" {
		t.Errorf("contained error is not code-only (§2.4): %v — want {code:boom}; message/at leaked into the content-addressed element", fields)
	}

	// (3) message-independence: same code, different message → same element hash.
	mv2, err := materialize([]interface{}{int64(1), errEnt("boom", "an entirely different message B"), int64(3)}, cs)
	if err != nil {
		t.Fatalf("materialize contained error (variant): %v", err)
	}
	elemHash2 := mv2.([]interface{})[1].(hash.Hash)
	if elemHash.String() != elemHash2.String() {
		t.Errorf("contained-error element hash depends on message (NOT code-only):\n  A: %s\n  B: %s", elemHash, elemHash2)
	}
}

// TestMaterializeScalarErrorStillRejects is the other half of the scoped ruling:
// the v3.26 carve-out is EXACTLY the contained-array-element position. A
// compute/error reaching materialize() as a SCALAR — a top-level result, a
// construct-field scalar, a scope-binding scalar — is still the §4.1 defect (a
// missed short-circuit) and must fail loudly, not materialize quietly. The tell
// that the carve-out was over-broadened would be either of these passing.
func TestMaterializeScalarErrorStillRejects(t *testing.T) {
	cs := store.NewMemoryContentStore()
	scalarErr := mustE((&ComputeError{Code: "boom", Message: "x"}).ToEntity())

	// top-level scalar
	if _, err := materialize(scalarErr, cs); err == nil {
		t.Errorf("a top-level scalar compute/error materialized quietly — the §4.1 guard must still fire")
	}

	// construct-field scalar (recurses into the field value, which is a scalar error)
	cv := &constructedValue{entityType: "app/x", fields: map[string]interface{}{"e": scalarErr}}
	if _, err := materialize(cv, cs); err == nil {
		t.Errorf("a construct-field scalar compute/error materialized quietly — the §4.1 guard must still fire")
	}
}
