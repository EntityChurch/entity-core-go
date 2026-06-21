package compute

import (
	"fmt"
	"math"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

func evalField(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeFieldData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	targetRef, err := resolveOrError(d.Entity, ctx, "field target")
	if err != nil {
		return nil, err
	}
	target, err := Evaluate(targetRef, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	// v3.19c Part A R3 (M3): compute/field dispatches on the target's Go type.
	//   *constructedValue: in-flight typed; return the named field directly —
	//                      kind is the value's Go type, no shape sniffing.
	//   entity.Entity:     materialized or hand-built; navigate V7-bare per
	//                      §1.4 (the field value is whatever's in .data, which
	//                      for entity-typed fields is a bare system/hash ref).
	//   bare record/map:   N.5 record navigation (flat).
	switch t := target.(type) {
	case *constructedValue:
		val, exists := t.fields[d.Name]
		if !exists {
			return nil, newComputeError(ErrNotFound, "Field not found: "+d.Name)
		}
		return val, nil
	case entity.Entity:
		var dataMap map[string]interface{}
		if err := ecf.Decode(t.Data, &dataMap); err != nil {
			return nil, newComputeError(ErrTypeMismatch, "Field access requires an entity with map data")
		}
		val, exists := dataMap[d.Name]
		if !exists {
			return nil, newComputeError(ErrNotFound, "Field not found: "+d.Name)
		}
		return val, nil
	default:
		dataMap := toStringMap(t)
		if dataMap == nil {
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("Field access requires an entity or record value, got: %T", target))
		}
		val, exists := dataMap[d.Name]
		if !exists {
			return nil, newComputeError(ErrNotFound, "Field not found: "+d.Name)
		}
		return val, nil
	}
}

// constructedValue is the v3.19c Part A in-flight, compute-internal form of
// a compute/construct result (M3 — typed in-flight, not a sniffable wire
// shape). Each field's value is held as a TYPED Go value: entity.Entity for
// entity-kind fields, anything else for value-kind. Navigation (field /
// index / length) reads field values directly off this typed structure — no
// kind tag in any wire data, no shape sniffing.
//
// At every compute→non-compute boundary (M3: eval-return, store→tree,
// apply-arg, cross-peer, plus scope-binding capture), this in-flight form
// is materialize()'d into a normal bare entity.Entity per V7 §1.4 — entity-
// kind fields become bare system/hash refs, value-kind fields inline. The
// materialized form is byte-identical to entity.NewEntity-built entities.
type constructedValue struct {
	entityType string
	fields     map[string]interface{}
}

// materialize converts an in-flight compute value into its bare wire form
// (v3.19c M1 + M3): a *constructedValue becomes a normal entity.Entity whose
// data follows V7 §1.4 — entity-kind fields are bare 33-byte system/hash
// content refs, value-kind fields inline as their raw value. Materialization
// is recursive: a constructed entity nested as a field value is materialized
// first (and stored), then referenced by hash in its parent.
//
// Inputs that aren't *constructedValue pass through unchanged (entity.Entity
// is already materialized; primitives, arrays, maps are bare).
//
// Note: this does NOT recurse into Go maps. compute/construct fields are held
// on *constructedValue directly (recursed above) and no current op produces a
// naked map[string]interface{} carrying constructed values across a boundary.
// If a future op (compute/record, compute/merge) does, materialize() must be
// extended to recurse into map values the same way it does for array elements.
func materialize(v interface{}, cs store.ContentStore) (interface{}, error) {
	switch t := v.(type) {
	case *constructedValue:
		dataMap := make(map[string]interface{}, len(t.fields))
		for k, fv := range t.fields {
			// Recursively materialize nested constructed values.
			mv, err := materialize(fv, cs)
			if err != nil {
				return nil, err
			}
			// Per M1: entity-typed materialized field → bare system/hash ref
			// (V7 §1.4). hash.Hash's MarshalCBOR emits the 33-byte bytestring.
			if ent, ok := mv.(entity.Entity); ok {
				dataMap[k] = ent.ContentHash
			} else {
				dataMap[k] = mv
			}
		}
		raw, err := ecf.Encode(dataMap)
		if err != nil {
			return nil, err
		}
		ent, err := entity.NewEntity(t.entityType, raw)
		if err != nil {
			return nil, err
		}
		if cs != nil {
			if _, err := cs.Put(ent); err != nil {
				return nil, err
			}
		}
		return ent, nil
	case []interface{}:
		// Array: each element may itself be a constructed value; materialize
		// element-wise so a constructed array-element becomes its bare hash.
		out := make([]interface{}, len(t))
		for i, e := range t {
			me, err := materialize(e, cs)
			if err != nil {
				return nil, err
			}
			if ent, ok := me.(entity.Entity); ok {
				out[i] = ent.ContentHash
			} else {
				out[i] = me
			}
		}
		return out, nil
	default:
		// Already bare: entity.Entity (materialized or hand-built), primitive,
		// bare map, etc. Pass through.
		return v, nil
	}
}

func evalConstruct(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeConstructData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	// v3.19c Part A R3 (PROPOSAL-COMPUTE-V3.19C-CAPTURED-STATE-CLOSEOUT.md):
	// produce an in-flight typed value (constructedValue) — kind lives in the
	// evaluator's runtime Go types, NOT in any wire/byte form (M3). The
	// materialized bare form is emitted by materialize() at compute→non-compute
	// boundaries; per M1 / V7 §1.4, that form is identical to entity.NewEntity
	// for the same logical entity.
	fields := make(map[string]interface{}, len(d.Fields))
	for _, entry := range canonicalSorted(d.Fields) {
		valueTarget, err := resolveOrError(entry.Hash, ctx, "construct field "+entry.Key)
		if err != nil {
			return nil, err
		}
		value, err := Evaluate(valueTarget, scope, budget, ctx)
		if err != nil {
			return nil, err
		}
		fields[entry.Key] = value
	}
	return &constructedValue{entityType: d.EntityType, fields: fields}, nil
}

// evalIndex implements compute/index per §2.2:
// - resolves the array and index expressions
// - returns the element at index
// - negative index or index >= length → index_out_of_range
// - array is null or non-array → type_mismatch
func evalIndex(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeIndexData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	arrTarget, err := resolveOrError(d.Array, ctx, "index array")
	if err != nil {
		return nil, err
	}
	arrVal, err := Evaluate(arrTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	arr, ok := arrVal.([]interface{})
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("compute/index requires an array, got %T", arrVal))
	}

	idxTarget, err := resolveOrError(d.Index, ctx, "index value")
	if err != nil {
		return nil, err
	}
	idxVal, err := Evaluate(idxTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	idx, ok := asInt64Index(idxVal)
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("compute/index requires an integer index, got %T", idxVal))
	}
	if idx < 0 || idx >= int64(len(arr)) {
		return nil, newComputeError(ErrIndexOutOfRange,
			fmt.Sprintf("index %d out of range for array of length %d", idx, len(arr)))
	}
	// v3.19c Part A R3: no kind-tagged data in wire form. Array elements are
	// returned bare (whatever Go type they decoded as — could be a primitive,
	// a bare hash bytestring for entity-valued elements in a materialized
	// array, etc.). Caller navigates V7-style if further composition needed.
	return arr[idx], nil
}

// evalLength implements compute/length per §2.2:
// - resolves the array expression
// - returns the element count (0 for empty)
// - array is null or non-array → type_mismatch
func evalLength(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLengthData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	arrTarget, err := resolveOrError(d.Array, ctx, "length array")
	if err != nil {
		return nil, err
	}
	arrVal, err := Evaluate(arrTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}
	arr, ok := arrVal.([]interface{})
	if !ok {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("compute/length requires an array, got %T", arrVal))
	}
	return int64(len(arr)), nil
}

// asInt64Index coerces a numeric value used as an array index to int64. Accepts
// int64 and uint64 (rejecting uint64 values above MaxInt64 — too large to be a
// valid array index in any case). Floats are rejected.
func asInt64Index(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}
