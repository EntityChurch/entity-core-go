package compute

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Scope holds name-to-value bindings during evaluation.
type Scope struct {
	bindings map[string]interface{}
}

// NewScope creates an empty scope.
func NewScope() *Scope {
	return &Scope{bindings: make(map[string]interface{})}
}

func (s *Scope) Has(name string) bool {
	_, ok := s.bindings[name]
	return ok
}

func (s *Scope) Get(name string) interface{} {
	return s.bindings[name]
}

func (s *Scope) Set(name string, value interface{}) {
	s.bindings[name] = value
}

// Copy returns a shallow copy of the scope.
func (s *Scope) Copy() *Scope {
	cp := &Scope{bindings: make(map[string]interface{}, len(s.bindings))}
	for k, v := range s.bindings {
		cp.bindings[k] = v
	}
	return cp
}

// IsEmpty returns true if the scope has no bindings.
func (s *Scope) IsEmpty() bool {
	return len(s.bindings) == 0
}

// CaptureScope creates a compute/scope entity from the current scope and stores
// it in the content store.
//
// v3.19b N1/N3/N4 (§2.3): bindings are kind-tagged. An entity-valued binding
// (an entity.Entity Go value, regardless of its compute/* or app/* type) is
// emitted as {kind:"entity", entity_hash:<hash>} and the entity itself is
// ensured-resident in the content store so load_scope can resolve it. Other
// values are emitted as {kind:"value", value:<bare>}. This makes the captured
// scope content-addressed and navigable-by-kind (no shape heuristics).
func CaptureScope(scope *Scope, cs store.ContentStore) (entity.Entity, error) {
	if scope.IsEmpty() {
		return entity.Entity{}, nil
	}

	bindings := make(map[string]types.ComputeScopeBinding, len(scope.bindings))
	for name, v := range scope.bindings {
		b, err := buildScopeBinding(v, cs)
		if err != nil {
			return entity.Entity{}, err
		}
		bindings[name] = b
	}

	d := types.ComputeScopeData{Bindings: bindings}
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	ent, err := entity.NewEntity(types.TypeComputeScope, cbor.RawMessage(raw))
	if err != nil {
		return entity.Entity{}, err
	}
	if _, err := cs.Put(ent); err != nil {
		return entity.Entity{}, err
	}
	return ent, nil
}

// buildScopeBinding classifies a Go scope value into a kind-tagged binding.
// Entity-typed values are made store-resident and emitted as kind="entity";
// everything else is emitted inline as kind="value".
//
// v3.19c Part A R3: a *constructedValue (in-flight compute/construct result)
// is materialized to a bare entity.Entity BEFORE being emitted as a kind=
// entity binding, so the referenced entity in the content store follows the
// V7 §1.4 / M1 convention (scope-binding kind tags are compute-internal; the
// entities they reference are V7-bare).
func buildScopeBinding(v interface{}, cs store.ContentStore) (types.ComputeScopeBinding, error) {
	// Materialize first so a *constructedValue becomes an entity.Entity that
	// the entity-case below handles uniformly.
	if _, isConstructed := v.(*constructedValue); isConstructed {
		mv, err := materialize(v, cs)
		if err != nil {
			return types.ComputeScopeBinding{}, err
		}
		v = mv
	}
	switch ev := v.(type) {
	case entity.Entity:
		// Capture-side residency (v3.19b N1): ensure the binding entity is in
		// the content store so a subsequent load_scope can resolve it via N4.
		// content_store.Put is idempotent by content addressing.
		if _, err := cs.Put(ev); err != nil {
			return types.ComputeScopeBinding{}, err
		}
		h := ev.ContentHash
		return types.ComputeScopeBinding{
			Kind:       types.ScopeBindingKindEntity,
			EntityHash: &h,
		}, nil
	case *entity.Entity:
		if ev == nil {
			return types.ComputeScopeBinding{
				Kind:  types.ScopeBindingKindValue,
				Value: nil,
			}, nil
		}
		if _, err := cs.Put(*ev); err != nil {
			return types.ComputeScopeBinding{}, err
		}
		h := ev.ContentHash
		return types.ComputeScopeBinding{
			Kind:       types.ScopeBindingKindEntity,
			EntityHash: &h,
		}, nil
	default:
		return types.ComputeScopeBinding{
			Kind:  types.ScopeBindingKindValue,
			Value: v,
		}, nil
	}
}

// LoadScope reconstructs a Scope from a captured compute/scope entity hash.
//
// v3.19b N4/N8 (§2.3): kind="entity" bindings resolve via direct content-store
// access (the binding rides the closure's already-granted authorization; we do
// NOT run validate_compute_resolvable — the binding entity need not be
// is_compute_type or sealed-set). On miss, returns a *ComputeError with code
// "scope_unreachable" so the caller surfaces it as a compute/error VALUE at
// status 200 per F10, not a transport failure.
func LoadScope(envHash hash.Hash, ctx *EvalContext) (*Scope, error) {
	if envHash.IsZero() {
		return NewScope(), nil
	}
	ent, ok := ctx.ContentStore.Get(envHash)
	if !ok {
		// The scope entity itself was unreachable — this is the same failure
		// class as a binding entity being unreachable; surface as N8.
		return nil, newComputeError(ErrScopeUnreachable,
			"scope entity not found: "+envHash.String())
	}
	var d types.ComputeScopeData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}
	s := &Scope{bindings: make(map[string]interface{}, len(d.Bindings))}
	for name, b := range d.Bindings {
		v, err := resolveScopeBinding(name, b, ctx)
		if err != nil {
			return nil, err
		}
		s.bindings[name] = v
	}
	return s, nil
}

// resolveScopeBinding turns a kind-tagged binding back into a Go scope value.
// Entity bindings go through direct content-store access (N4); a miss yields
// scope_unreachable (N8).
func resolveScopeBinding(name string, b types.ComputeScopeBinding, ctx *EvalContext) (interface{}, error) {
	switch b.Kind {
	case types.ScopeBindingKindEntity:
		if b.EntityHash == nil {
			return nil, newComputeError(ErrInvalidExpression,
				"scope binding "+name+": kind=entity missing entity_hash")
		}
		// N4: direct content_store access — the closure was already
		// authorized; bindings inherit. NOT through validate_compute_resolvable.
		ent, ok := ctx.ContentStore.Get(*b.EntityHash)
		if !ok {
			return nil, newComputeError(ErrScopeUnreachable,
				"scope binding "+name+": entity "+b.EntityHash.String()+" not resolvable")
		}
		return ent, nil
	case types.ScopeBindingKindValue:
		return b.Value, nil
	default:
		return nil, newComputeError(ErrInvalidExpression,
			"scope binding "+name+": unknown kind "+b.Kind)
	}
}
