package compute

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// Error codes per EXTENSION-COMPUTE §9.1.
const (
	ErrBudgetExhausted          = "budget_exhausted"
	ErrDepthExceeded            = "depth_exceeded"
	ErrTypeMismatch             = "type_mismatch"
	ErrDivisionByZero           = "division_by_zero"
	ErrNotFound                 = "not_found"
	ErrUnknownType              = "unknown_type"
	ErrMissingArgument          = "missing_argument"
	ErrInvalidExpression        = "invalid_expression"
	ErrCascadeLimit             = "cascade_limit"
	ErrPermissionDenied         = "permission_denied"
	ErrInstallationGrantInvalid = "installation_grant_invalid"
	ErrIndexOutOfRange          = "index_out_of_range"
	ErrCastOutOfRange           = "cast_out_of_range"
	// v3.25 §9.1: range(n) with a negative n, or an n exceeding the maximum
	// representable array length, is count_out_of_range — following
	// cast_out_of_range's precedent rather than overloading type_mismatch
	// (an out-of-domain magnitude is not a type error, §2.2) or index_out_of_range.
	ErrCountOutOfRange = "count_out_of_range"
	// v3.19b N8 (§9.1): a kind:"entity" scope binding's hash resolves in
	// neither the local content store nor the envelope `included`. Returned
	// as an error VALUE at status 200 per F10, not a transport failure.
	ErrScopeUnreachable = "scope_unreachable"
)

// ComputeError is the error type returned during evaluation.
type ComputeError struct {
	Code       string
	Message    string
	At         string
	Expression hash.Hash
}

func (e *ComputeError) Error() string {
	if e.At != "" {
		return e.Code + ": " + e.Message + " at " + e.At
	}
	return e.Code + ": " + e.Message
}

func newComputeError(code, message string) *ComputeError {
	return &ComputeError{Code: code, Message: message}
}

func newComputeErrorAt(code, message, at string) *ComputeError {
	return &ComputeError{Code: code, Message: message, At: at}
}

// ToEntity converts a ComputeError to its IN-FLIGHT / dispatch-boundary
// compute/error entity — the §3.7 / F10 status-200 error-as-value form, which
// MAY carry the diagnostic fields (Q1). This is NOT the form to write when the
// error crosses to materialized state (result_path, construct field, wire
// subtree); use ToMaterializedEntity there.
func (e *ComputeError) ToEntity() (entity.Entity, error) {
	d := e.data()
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(types.TypeComputeError, cbor.RawMessage(raw))
}

// ToMaterializedEntity converts a ComputeError to its code-only materialized
// compute/error entity (Q1). Used wherever the error is written to a tree path
// or otherwise content-addressed: two impls raising the same code with
// different prose MUST converge on one content hash.
func (e *ComputeError) ToMaterializedEntity() (entity.Entity, error) {
	return e.data().ToMaterializedEntity()
}

func (e *ComputeError) data() types.ComputeErrorData {
	d := types.ComputeErrorData{
		Code:    e.Code,
		Message: e.Message,
		At:      e.At,
	}
	if !e.Expression.IsZero() {
		d.Expression = &e.Expression
	}
	return d
}

// IsComputeError checks if an error is a ComputeError.
func IsComputeError(err error) bool {
	_, ok := err.(*ComputeError)
	return ok
}

// computeErrorFromValue is the §4.1 `is_error(v)` predicate for a consumed
// sub-evaluation result — kind-based, per COMPUTE v3.23: it is true iff the
// value's kind is `compute/error`, regardless of whether evaluation
// "succeeded" (an SA-1 literal or a lookup resolving to a stored error
// evaluates fine and is STILL an error for every consumer). When true it
// returns the `*ComputeError` to propagate: the §4.1 / §7.2 `[MUST]`
// short-circuit returns the error unchanged rather than embedding it.
//
// This is the code face of arch's ruling (B): a `compute/error` reaching a
// `compute/construct` field, a `compute/apply` arg, or a scope binding
// PROPAGATES — it is never materialized there. An error materializes only
// where it is WRITTEN (§7.2 `result_path` / SA-9 `store`, via
// ToMaterializedEntity), never where it is consumed. N1 listed those three
// consumption sites as embed-and-reference and was wrong at all three
// (corrected v3.23).
func computeErrorFromValue(v interface{}) (*ComputeError, bool) {
	ent, ok := v.(entity.Entity)
	if !ok || ent.Type != types.TypeComputeError {
		return nil, false
	}
	d, err := types.ComputeErrorDataFromEntity(ent)
	if err != nil {
		// A malformed compute/error still short-circuits — surfaced loudly as a
		// decode failure rather than embedded as a broken value.
		return newComputeError(ErrInvalidExpression, "malformed compute/error value: "+err.Error()), true
	}
	ce := &ComputeError{Code: d.Code, Message: d.Message, At: d.At}
	if d.Expression != nil {
		ce.Expression = *d.Expression
	}
	return ce, true
}
