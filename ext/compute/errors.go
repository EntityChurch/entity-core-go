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
