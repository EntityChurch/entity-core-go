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
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/compute"
)

// corpusTreePut is the minimal system/tree:put dispatcher the SA-9 store
// crossing needs, and nothing more. The corpus is otherwise dispatcher-free by
// design (see the ctx note below), but §2.4's code-only materialization has TWO
// write sites — the reactive result_path and SA-9 store — and store hard-requires
// a dispatcher (`builtinStore` returns invalid_expression without one). A
// store-then-read-back vector reduces "the written error is content-hashed over
// code alone" to an ordinary entity-kind boundary, so wiring exactly this one
// operation makes item 2 of the §2131 family expressible in the existing shape.
//
// It is deliberately un-authorized: the corpus is a closed, trusted expression
// graph (no capability chain), so this stores the put-request's entity and sets
// the target path with no permission check — the same posture as the rest of the
// harness. Any dispatch that is NOT system/tree:put is a vector reaching for a
// surface the corpus does not model; it fails loudly rather than passing blind.
// Each porting impl wires the equivalent tree:put for its own store crossing.
func corpusTreePut(cs store.ContentStore, li store.LocationIndex) func(string, string, *types.ResourceTarget, entity.Entity, *entity.Entity) (*handler.Response, error) {
	return func(path, op string, resource *types.ResourceTarget, params entity.Entity, _ *entity.Entity) (*handler.Response, error) {
		if path != "system/tree" || op != "put" {
			return nil, fmt.Errorf("corpus dispatcher models only system/tree:put, got %s:%s", path, op)
		}
		if resource == nil || len(resource.Targets) != 1 {
			return nil, fmt.Errorf("system/tree:put needs exactly one target path")
		}
		var pr types.PutRequestData
		if err := ecf.Decode(params.Data, &pr); err != nil {
			return nil, fmt.Errorf("decode put-request: %w", err)
		}
		var ent entity.Entity
		if err := ecf.Decode(pr.Entity, &ent); err != nil {
			return nil, fmt.Errorf("decode put-request entity: %w", err)
		}
		if _, err := cs.Put(ent); err != nil {
			return nil, fmt.Errorf("store put entity: %w", err)
		}
		if err := li.Set(resource.Targets[0], ent.ContentHash); err != nil {
			return nil, fmt.Errorf("set %q: %w", resource.Targets[0], err)
		}
		return &handler.Response{Status: 200, Result: ent}, nil
	}
}

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
		// scope and tree — there is no peer and no capability chain.
		// HasContentStoreAccess is set so lookup/hash can reach the vector's own
		// non-compute entities; withholding it would make the
		// materialized-hash-readback vector fail for an authorization reason
		// that has nothing to do with the semantics being pinned. The one
		// dispatcher wired is system/tree:put (corpusTreePut), for the SA-9 store
		// crossing only — see its doc; every other dispatch fails loudly.
		HasContentStoreAccess: true,
		DispatchExecute:       corpusTreePut(cs, li),
	}

	budget := compute.NewBudget(v.Budget.Operations, v.Budget.Depth)
	result, err := compute.Evaluate(root, scope, budget, ctx)

	// BoundaryPath: the boundary is the entity WRITTEN to that path (read out of
	// band), not the eval result — the only way to observe §2.4 code-only. If
	// nothing was written (an impl that propagated instead of materializing), fall
	// through to the normal result reduction, which still diverges from a writer.
	if v.BoundaryPath != "" {
		if o, ok, berr := boundaryFromWrittenPath(v.BoundaryPath, li, cs); berr != nil {
			return Outcome{}, berr
		} else if ok {
			return o, nil
		}
	}

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

// boundaryFromWrittenPath reads the entity at a tree path after evaluation and
// returns its content hash as an entity-kind boundary — the SA-9 store vectors'
// window onto the bytes §2.4 governs. `ok` is false (fall back to the result
// reduction) when nothing was written there.
func boundaryFromWrittenPath(path string, li store.LocationIndex, cs store.ContentStore) (Outcome, bool, error) {
	h, ok := li.Get(path)
	if !ok {
		return Outcome{}, false, nil
	}
	ent, ok := cs.Get(h)
	if !ok {
		return Outcome{}, false, fmt.Errorf("boundary path %q → %s not in store", path, h)
	}
	ch, err := hash.Compute(ent.Type, ent.Data)
	if err != nil {
		return Outcome{}, false, fmt.Errorf("hash boundary entity at %q: %w", path, err)
	}
	return Outcome{Kind: OutcomeEntity, Boundary: ch.Bytes()}, true, nil
}

// boundaryOf reduces an evaluation result to its materialized-boundary form by
// binding it into a scope and capturing that scope — Stage-1's own
// materialization path, reached through exported API.
func boundaryOf(v interface{}, cs store.ContentStore) (Outcome, error) {
	// A value-form compute/error result reduces to error-kind, NOT entity-kind.
	// is_error is kind-based (§4.1), so a compute/error is an error outcome however
	// it arrived — minted (evalVector's err!=nil path) or as a value (SA-1, here) —
	// and reducing the value form to an entity boundary while the minted form
	// reduces to error-kind is the two-representation split (AP-14) in the harness,
	// which disagreed with the wire (F10) on exactly the store vectors. Match the
	// wire. (The store vectors observe the WRITTEN entity via Vector.BoundaryPath —
	// evalVector reads it out of band — precisely because this result reduction is
	// blind to the stored bytes §2.4 governs.)
	if ent, ok := v.(entity.Entity); ok && ent.Type == types.TypeComputeError {
		var d types.ComputeErrorData
		if err := ecf.Decode(ent.Data, &d); err != nil {
			return Outcome{}, fmt.Errorf("decode compute/error result: %w", err)
		}
		return Outcome{Kind: OutcomeError, Code: d.Code, Message: d.Message}, nil
	}
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
