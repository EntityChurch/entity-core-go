package compute

import (
	"fmt"
	"math"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

func evalArithmetic(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeArithmeticData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	leftTarget, err := resolveOrError(d.Left, ctx, "arithmetic left")
	if err != nil {
		return nil, err
	}
	left, err := Evaluate(leftTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	rightTarget, err := resolveOrError(d.Right, ctx, "arithmetic right")
	if err != nil {
		return nil, err
	}
	right, err := Evaluate(rightTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	// Rule 11: eager-cast detection. Only a numeric-cast(uint) literally at
	// the operand position triggers unsigned interpretation. div/mod use the
	// hint (rule 9); add/sub/mul ignore it (rule 8).
	unsignedHint := castIntent(leftTarget) || castIntent(rightTarget)
	return applyArithmeticWithIntent(d.Op, left, right, unsignedHint)
}

func evalCompare(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeCompareData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	leftTarget, err := resolveOrError(d.Left, ctx, "compare left")
	if err != nil {
		return nil, err
	}
	left, err := Evaluate(leftTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	rightTarget, err := resolveOrError(d.Right, ctx, "compare right")
	if err != nil {
		return nil, err
	}
	right, err := Evaluate(rightTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	// Rule 11: eager-cast detection for unsigned compare on values in
	// [2^63, 2^64). When neither operand is a numeric-cast(uint), the
	// comparator uses signed interpretation per rule 9.
	unsignedHint := castIntent(leftTarget) || castIntent(rightTarget)
	return applyCompareWithIntent(d.Op, left, right, unsignedHint)
}

func evalLogic(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeLogicData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	leftTarget, err := resolveOrError(d.Left, ctx, "logic left")
	if err != nil {
		return nil, err
	}
	left, err := Evaluate(leftTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	if d.Op == "not" {
		return !truthy(left), nil
	}

	if d.Right == nil {
		return nil, newComputeError(ErrInvalidExpression, "logic op "+d.Op+" requires right operand")
	}
	rightTarget, err := resolveOrError(*d.Right, ctx, "logic right")
	if err != nil {
		return nil, err
	}
	right, err := Evaluate(rightTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	switch d.Op {
	case "and":
		return truthy(left) && truthy(right), nil
	case "or":
		return truthy(left) || truthy(right), nil
	default:
		return nil, newComputeError(ErrInvalidExpression, "Unknown logic op: "+d.Op)
	}
}

// evalNumericCast implements compute/numeric-cast per §2.2:
// intra-numeric conversion among primitive/int, primitive/uint, primitive/float.
// int↔uint reinterpret bits at 64-bit width; int/uint→float native conversion
// (defined-lossy above 2^53); float→int/uint truncate toward zero, with
// NaN/±Inf/out-of-range → cast_out_of_range. Other targets/values → type_mismatch.
func evalNumericCast(ent entity.Entity, scope *Scope, budget *Budget, ctx *EvalContext) (interface{}, error) {
	var d types.ComputeNumericCastData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return nil, err
	}

	valTarget, err := resolveOrError(d.Value, ctx, "numeric-cast value")
	if err != nil {
		return nil, err
	}
	val, err := Evaluate(valTarget, scope, budget, ctx)
	if err != nil {
		return nil, err
	}

	switch d.ToType {
	case "primitive/int":
		switch v := val.(type) {
		case int64:
			return v, nil
		case uint64:
			return int64(v), nil
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, newComputeError(ErrCastOutOfRange,
					"cannot cast NaN or ±Inf to primitive/int")
			}
			t := math.Trunc(v)
			if t < math.MinInt64 || t >= float64(math.MaxInt64)+1 {
				return nil, newComputeError(ErrCastOutOfRange,
					fmt.Sprintf("float %v out of range for primitive/int", v))
			}
			return int64(t), nil
		default:
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("compute/numeric-cast value must be numeric, got %T", val))
		}
	case "primitive/uint":
		switch v := val.(type) {
		case int64:
			return uint64(v), nil
		case uint64:
			return v, nil
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, newComputeError(ErrCastOutOfRange,
					"cannot cast NaN or ±Inf to primitive/uint")
			}
			t := math.Trunc(v)
			if t < 0 || t >= float64(math.MaxUint64)+1 {
				return nil, newComputeError(ErrCastOutOfRange,
					fmt.Sprintf("float %v out of range for primitive/uint", v))
			}
			return uint64(t), nil
		default:
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("compute/numeric-cast value must be numeric, got %T", val))
		}
	case "primitive/float":
		switch v := val.(type) {
		case int64:
			return float64(v), nil
		case uint64:
			return float64(v), nil
		case float64:
			return v, nil
		default:
			return nil, newComputeError(ErrTypeMismatch,
				fmt.Sprintf("compute/numeric-cast value must be numeric, got %T", val))
		}
	default:
		return nil, newComputeError(ErrTypeMismatch,
			"compute/numeric-cast to_type must be primitive/int, primitive/uint, or primitive/float; got "+d.ToType)
	}
}

// --- Arithmetic (§2.2) ---
//
// Rules per EXTENSION-COMPUTE v3.14 §2.2:
//  1. Float promotion: either operand float → both promoted to float64.
//  2-3. Integer arithmetic; div with two integers → integer if exact else float.
//  4. Truncated mod (Go's % matches the sign-of-dividend rule).
//  5. Integer div/mod by zero → division_by_zero; float div/0 → IEEE 754.
//  6. Non-numeric → type_mismatch.
//  8. Integer overflow → wraparound at operand type's width. In Go, int64
//     and uint64 arithmetic both wrap natively, so this is free; we just
//     stop coercing uint64 → int64 (which previously could promote
//     uint64(2^63) into a negative int64 with the wrong result).
//  9. Mixed int/uint → type_mismatch. Same-type integer ops preserve the
//     operand type (uint+uint→uint, int+int→int).
//
// Concretely in Go: int64⊕int64 → int64; uint64⊕uint64 → uint64; one of each
// → type_mismatch. Float promotion applies when either operand is float64.

// --- Arithmetic (§2.2 rules 1-11, v3.16) ---
//
// Integer model: WASM/LLVM/JVM-style — integer types are widths (64-bit),
// signedness is a property of operations, not values.
//
//   Rule 1: float promotion — either operand float ⇒ both promoted; result float.
//   Rule 4: mod is integer-only; float operand → type_mismatch.
//   Rule 5: integer div/mod by 0 → division_by_zero; float div by 0 → IEEE 754.
//   Rule 6: non-numeric operand → type_mismatch.
//   Rule 8: add/sub/mul are sign-agnostic 64-bit two's-complement (one wrap
//           at 2^64). No int/uint decision, no mixed case.
//   Rule 9: div/mod/compare use signed interpretation by default. Unsigned
//           is requested via compute/numeric-cast → primitive/uint on the
//           operand immediately before the op (eager, point-of-use — rule 11).
//   Rule 10: integer results encode by their signed two's-complement
//           interpretation. Go: return int64 from arithmetic; CBOR encoder
//           writes bit-63-set int64 as major type 1.
//   Rule 11: numeric-cast is eager — its effect is consumed by the
//           immediately-following op and does NOT flow through compute/let.
//           Detected by inspecting the operand entity's type, not the value.

func applyArithmetic(op string, left, right interface{}) (interface{}, error) {
	return applyArithmeticWithIntent(op, left, right, false)
}

// applyArithmeticWithIntent is the dispatch evaluator's entry point — it knows
// whether the operand expressions carried an eager numeric-cast to uint
// (rule 11). add/sub/mul ignore the hint (rule 8: sign-agnostic); div/mod use
// it to flip from signed-default (rule 9) into unsigned.
func applyArithmeticWithIntent(op string, left, right interface{}, unsignedHint bool) (interface{}, error) {
	_, lFloat := left.(float64)
	_, rFloat := right.(float64)
	lBits, lInt := bits64(left)
	rBits, rInt := bits64(right)

	if !lFloat && !lInt {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("Arithmetic requires numeric operands, got %T", left))
	}
	if !rFloat && !rInt {
		return nil, newComputeError(ErrTypeMismatch,
			fmt.Sprintf("Arithmetic requires numeric operands, got %T", right))
	}

	// Rule 1 + Rule 4: float promotion applies to add/sub/mul/div, NOT mod.
	if lFloat || rFloat {
		if op == "mod" {
			return nil, newComputeError(ErrTypeMismatch,
				"Modulo requires integer operands")
		}
		lf, _ := toFloat64(left)
		rf, _ := toFloat64(right)
		switch op {
		case "add":
			return lf + rf, nil
		case "sub":
			return lf - rf, nil
		case "mul":
			return lf * rf, nil
		case "div":
			return lf / rf, nil // IEEE 754 special values per rule 5
		default:
			return nil, newComputeError(ErrInvalidExpression, "Unknown arithmetic op: "+op)
		}
	}

	// Rule 8: 64-bit two's-complement, sign-agnostic for add/sub/mul.
	switch op {
	case "add":
		return signedResult(lBits + rBits), nil
	case "sub":
		return signedResult(lBits - rBits), nil
	case "mul":
		return signedResult(lBits * rBits), nil

	// Rule 9: div/mod signed-default; cast-hint flips to unsigned.
	case "div":
		if rBits == 0 {
			return nil, newComputeError(ErrDivisionByZero, "Division by zero")
		}
		if unsignedHint {
			if lBits%rBits == 0 {
				return unsignedResult(lBits / rBits), nil
			}
			return float64(lBits) / float64(rBits), nil
		}
		l, r := int64(lBits), int64(rBits)
		if l%r == 0 {
			return signedResult(uint64(l / r)), nil
		}
		return float64(l) / float64(r), nil
	case "mod":
		if rBits == 0 {
			return nil, newComputeError(ErrDivisionByZero, "Division by zero")
		}
		if unsignedHint {
			return unsignedResult(lBits % rBits), nil
		}
		l, r := int64(lBits), int64(rBits)
		return signedResult(uint64(l % r)), nil
	default:
		return nil, newComputeError(ErrInvalidExpression, "Unknown arithmetic op: "+op)
	}
}

// castIntent reports whether a resolved operand entity is literally a
// compute/numeric-cast(to_type=primitive/uint). When true, the operand
// triggers unsigned interpretation for the immediately-following sign-
// sensitive op (rule 11). A cast indirected behind a let or a lookup is NOT
// recognized — that's exactly the spec's "doesn't flow through let" semantic.
func castIntent(ent entity.Entity) bool {
	if ent.Type != types.TypeComputeNumericCast {
		return false
	}
	var d types.ComputeNumericCastData
	if err := ecf.Decode(ent.Data, &d); err != nil {
		return false
	}
	return d.ToType == "primitive/uint"
}

// bits64 extracts the 64-bit pattern from an integer value. int64 and uint64
// share the same memory layout, so reinterpretation is bit-identical.
func bits64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case int64:
		return uint64(n), true
	case uint64:
		return n, true
	}
	return 0, false
}

// signedResult returns int64. Per rule 10, arithmetic results encode by their
// signed two's-complement interpretation — Go's CBOR encoder writes bit-63-set
// int64 as CBOR major type 1, giving cross-impl wire-form agreement.
func signedResult(bits uint64) int64 { return int64(bits) }

// unsignedResult returns uint64 — used only when the op was unsigned
// (cast-intent detected on operand). Per A.5: a result intended as unsigned
// in [2^63, 2^64) encodes as CBOR major type 0.
func unsignedResult(bits uint64) uint64 { return bits }

// --- Comparison (§2.2) ---

func applyCompare(op string, left, right interface{}) (interface{}, error) {
	switch op {
	case "eq":
		return compareEqual(left, right), nil
	case "neq":
		return !compareEqual(left, right), nil
	case "lt", "gt", "lte", "gte":
		return compareOrdered(op, left, right, false)
	default:
		return nil, newComputeError(ErrInvalidExpression, "Unknown compare op: "+op)
	}
}

// applyCompareWithIntent is the cast-aware variant called by evalCompare.
// Equality is sign-independent (bit-pattern compare via promotion); ordering
// honors the unsigned hint per rule 9.
func applyCompareWithIntent(op string, left, right interface{}, unsignedHint bool) (interface{}, error) {
	switch op {
	case "eq":
		return compareEqual(left, right), nil
	case "neq":
		return !compareEqual(left, right), nil
	case "lt", "gt", "lte", "gte":
		return compareOrdered(op, left, right, unsignedHint)
	default:
		return nil, newComputeError(ErrInvalidExpression, "Unknown compare op: "+op)
	}
}

func compareEqual(a, b interface{}) bool {
	if !sameTypeClass(a, b) {
		return false
	}
	// Entities: compare by content hash.
	if ae, ok := a.(entity.Entity); ok {
		if be, ok := b.(entity.Entity); ok {
			return ae.ContentHash == be.ContentHash
		}
		return false
	}
	// Numeric: promote to float for cross-type comparison.
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		return af == bf
	}
	// Same primitive type: direct comparison.
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// sameTypeClass checks if two values are in the same type class for equality
// comparison (v3.6 A2). Numeric values are comparable across int/float.
func sameTypeClass(a, b interface{}) bool {
	_, aNum := toFloat64(a)
	_, bNum := toFloat64(b)
	if aNum && bNum {
		return true
	}
	// Same concrete type.
	switch a.(type) {
	case string:
		_, ok := b.(string)
		return ok
	case bool:
		_, ok := b.(bool)
		return ok
	case entity.Entity:
		_, ok := b.(entity.Entity)
		return ok
	}
	return false
}

func compareOrdered(op string, left, right interface{}, unsignedHint bool) (bool, error) {
	// Integer-integer compare: signed-default per rule 9; unsigned via eager
	// cast (rule 11). When either operand is float, fall through to float
	// promotion below.
	lb, lIntBits := bits64(left)
	rb, rIntBits := bits64(right)
	_, lFloat := left.(float64)
	_, rFloat := right.(float64)
	if lIntBits && rIntBits && !lFloat && !rFloat {
		if unsignedHint {
			switch op {
			case "lt":
				return lb < rb, nil
			case "gt":
				return lb > rb, nil
			case "lte":
				return lb <= rb, nil
			case "gte":
				return lb >= rb, nil
			}
		} else {
			l, r := int64(lb), int64(rb)
			switch op {
			case "lt":
				return l < r, nil
			case "gt":
				return l > r, nil
			case "lte":
				return l <= r, nil
			case "gte":
				return l >= r, nil
			}
		}
	}

	lf, lok := toFloat64(left)
	rf, rok := toFloat64(right)
	if lok && rok {
		switch op {
		case "lt":
			return lf < rf, nil
		case "gt":
			return lf > rf, nil
		case "lte":
			return lf <= rf, nil
		case "gte":
			return lf >= rf, nil
		}
	}
	// String comparison.
	ls, lsOk := left.(string)
	rs, rsOk := right.(string)
	if lsOk && rsOk {
		switch op {
		case "lt":
			return ls < rs, nil
		case "gt":
			return ls > rs, nil
		case "lte":
			return ls <= rs, nil
		case "gte":
			return ls >= rs, nil
		}
	}
	return false, newComputeError(ErrTypeMismatch,
		fmt.Sprintf("Cannot compare %T and %T with %s", left, right, op))
}

// --- Numeric helpers ---

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}
