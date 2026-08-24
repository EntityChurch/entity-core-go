package main

// The evaluate + materialize + hash stage — the one thing the wire-conformance
// pipeline did not already have.
//
// GUIDE-CONFORMANCE §7c.2: the wire pipeline's "scaffolding and discipline are
// directly reusable; it needs one new stage — evaluate + materialize + hash
// (today it only does static encode/decode; a compute vector's 'expected'
// requires running an evaluator)." This file is that stage.
//
// THE BOUNDARY REDUCTION
//
// Both the result and the comparison are routed through compute.CaptureScope —
// Stage-1's OWN materialization path — rather than reimplemented here. That is
// the same choice the workbench harness made, for the same reason: using the
// reference's code for the final reduction means the boundary hash is
// authoritative instead of something this file re-derives and could get wrong
// in the same direction as the evaluator it is measuring.
//
// WHAT IS DROPPED FROM THE WORKBENCH FORM, AND WHY
//
// The workbench harness renders a value-kind boundary as "value:%T:<hex>" —
// the Go type name, then the canonical bytes. The type name cannot cross a
// language boundary, and it is redundant: it was standing in for the
// signed/unsigned distinction, which the canonical CBOR bytes already carry as
// a major-type difference (int64(5) is 0x05, uint64(5) is 0x05 — identical, but
// int64(-3) is 0x22 and no unsigned value encodes that way; the cases where the
// Go type differs but the bytes agree are exactly the cases where the VALUES
// agree). Emitting the Go type would make every non-Go impl fail on a field
// that pins nothing — defect S3, the privileged-encoder anti-pattern, in a new
// place. So the emission carries kind + bytes only.

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"
)

// evalVector runs one vector to its boundary outcome.
func evalVector(v Vector) (Outcome, error) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()

	byHash := make(map[string]entity.Entity, len(v.Entities))
	for i, ve := range v.Entities {
		ent, err := entity.NewEntity(ve.Type, ve.Data)
		if err != nil {
			return Outcome{}, fmt.Errorf("entity %d (%s): %w", i, ve.Type, err)
		}
		if _, err := cs.Put(ent); err != nil {
			return Outcome{}, fmt.Errorf("store entity %d: %w", i, err)
		}
		byHash[string(ent.ContentHash.Bytes())] = ent
	}
	for path, h := range v.Tree {
		if err := li.Set(path, h); err != nil {
			return Outcome{}, fmt.Errorf("tree %q: %w", path, err)
		}
	}

	root, ok := byHash[string(v.Root.Bytes())]
	if !ok {
		return Outcome{}, fmt.Errorf("root %s not in closure", v.Root)
	}

	var bindings map[string]interface{}
	if err := ecf.Decode(v.Bindings, &bindings); err != nil {
		return Outcome{}, fmt.Errorf("decode bindings: %w", err)
	}
	scope := compute.NewScope()
	for k, val := range bindings {
		scope.Set(k, val)
	}

	ctx := &compute.EvalContext{
		ContentStore:  cs,
		LocationIndex: li,
		// The corpus evaluates a closed expression graph against a supplied
		// scope and tree — there is no peer, no capability chain, and no
		// dispatcher. HasContentStoreAccess is set so lookup/hash can reach the
		// vector's own non-compute entities; withholding it would make the
		// materialized-hash-readback vector fail for an authorization reason
		// that has nothing to do with the semantics being pinned.
		HasContentStoreAccess: true,
	}

	budget := compute.NewBudget(v.Budget.Operations, v.Budget.Depth)
	result, err := compute.Evaluate(root, scope, budget, ctx)
	if err != nil {
		if ce, ok := err.(*compute.ComputeError); ok {
			return Outcome{Kind: OutcomeError, Code: ce.Code, Message: ce.Message}, nil
		}
		// A non-ComputeError escaping the evaluator is a harness-visible defect,
		// not a vector outcome: it has no spec-defined code, so recording it as
		// an error outcome would invent one and let a crash cross-bless green.
		return Outcome{}, fmt.Errorf("evaluate returned a non-compute error: %w", err)
	}

	return boundaryOf(result, cs)
}

// boundaryOf reduces an evaluation result to its materialized-boundary form by
// binding it into a scope and capturing that scope — Stage-1's own
// materialization path, reached through exported API.
func boundaryOf(v interface{}, cs store.ContentStore) (Outcome, error) {
	s := compute.NewScope()
	s.Set("r", v)
	ent, err := compute.CaptureScope(s, cs)
	if err != nil {
		return Outcome{}, fmt.Errorf("capture scope: %w", err)
	}
	var d types.ComputeScopeData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return Outcome{}, fmt.Errorf("decode captured scope: %w", err)
	}
	b, ok := d.Bindings["r"]
	if !ok {
		return Outcome{}, fmt.Errorf("captured scope is missing binding r")
	}

	switch b.Kind {
	case types.ScopeBindingKindEntity:
		if b.EntityHash == nil {
			return Outcome{}, fmt.Errorf("entity binding carries no hash")
		}
		// Bytes(), not EffectiveDigest(): the algorithm byte travels with the
		// hash, and a digest-only form would compare equal across two different
		// hash algorithms.
		return Outcome{Kind: OutcomeEntity, Boundary: b.EntityHash.Bytes()}, nil
	case types.ScopeBindingKindValue:
		raw, err := ecf.Encode(b.Value)
		if err != nil {
			return Outcome{}, fmt.Errorf("encode value binding: %w", err)
		}
		return Outcome{Kind: OutcomeValue, Boundary: raw}, nil
	default:
		return Outcome{}, fmt.Errorf("unknown scope binding kind %q", b.Kind)
	}
}
