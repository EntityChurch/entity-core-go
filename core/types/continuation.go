package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Continuation type constants.
const (
	TypeContinuation               = "system/continuation"
	TypeContinuationTransform      = "system/continuation/transform"
	TypeContinuationTransformOp    = "system/continuation/transform-op"
	TypeContinuationJoin           = "system/continuation/join"
	TypeContinuationSuspended      = "system/continuation/suspended"
	TypeContinuationResumeRequest  = "system/continuation/resume-request"
	TypeContinuationAbandonRequest = "system/continuation/abandon-request"
	TypeContinuationAdvanceRequest = "system/continuation/advance-request"
	// Install takes no wrapper request type — caller passes a system/continuation
	// or system/continuation/join entity directly as params, with the install path
	// in EXECUTE.resource per V7 §3.2 path-as-resource convention.
	TypeContinuationInstallResult = "system/continuation/install-result"
)

// ContinuationTransformOpData is one bounded field operation within a
// transform's transform_ops (EXTENSION-CONTINUATION §2.2, type
// system/continuation/transform-op). Ops are closed, total, pure, and
// bounded — field plumbing, not a computation surface. Op-specific fields
// are optional; which apply depends on Op (see the §2.2 op table).
type ContinuationTransformOpData struct {
	Op      string   `cbor:"op"`
	Field   string   `cbor:"field,omitempty"`
	Into    string   `cbor:"into,omitempty"`
	Fields  []string `cbor:"fields,omitempty"`
	Prefix  string   `cbor:"prefix,omitempty"`
	Literal string   `cbor:"literal,omitempty"`
	From    string   `cbor:"from,omitempty"`
	To      string   `cbor:"to,omitempty"`
	Sep     string   `cbor:"sep,omitempty"`
	Range   string   `cbor:"range,omitempty"`
}

// ToEntity creates a system/continuation/transform-op entity.
func (d ContinuationTransformOpData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationTransformOp, cbor.RawMessage(raw))
}

// TypeChainErrorLost is the lost-error marker entity bound under
// system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason} when
// a forward dispatch's downstream verdict is otherwise unobservable
// (EXTENSION-CONTINUATION §3.4, v1.16 per-reason subsegment).
// Purely informational — an observation sink, never a control path. It is
// deliberately NOT registered in the type registry: it is a runtime
// observational marker, not a protocol message type (same treatment as
// system/continuation/advancement-result).
const TypeChainErrorLost = "system/runtime/chain-error-lost"

// ChainErrorLostData captures a chain-dispatch failure that would
// otherwise be silently lost. Both `lost` and `rejected` kinds share this
// body shape; the kind distinction lives in the path per EXTENSION-
// CONTINUATION v1.20 §3.10.1. The `Reason` field carries the canonical
// error code per §3.10.5's unified rule — `{reason}` IS `result.data.code`
// verbatim for response-derived failures, OR a code from
// EXTENSION-CONTINUATION Appendix A for engine-internal failures, OR a
// code from V7 §6.12 for per-request transport failures.
//
// Consumers MAY aggregate the marker; it MUST NOT trigger advancement,
// retry, or any reactive behavior.
//
// v1.20 path scheme:
//
//	system/runtime/chain-errors/{kind}/{chain_id}/{step_index}/{reason}/{marker_hash}
//
// where {marker_hash} is the V7 §3.5 invariant-pointer hex form of this
// marker's content_hash — hex.EncodeToString(content_hash.Bytes()) —
// 66 lowercase chars (format byte + 32-byte digest). Each distinct
// observation lands at its own path; same-content redelivery dedupes
// (genuine tree:put no-op) IFF Timestamp is captured at failure-
// origination time per §3.10.6, NOT regenerated at bind site.
type ChainErrorLostData struct {
	OriginalCode      string `cbor:"original_code,omitempty"`
	OriginalStatus    uint   `cbor:"original_status"`
	FailedDeliveryURI string `cbor:"failed_delivery_uri"`
	OriginalRequestID string `cbor:"original_request_id,omitempty"`
	Timestamp         uint64 `cbor:"timestamp"`
	Reason            string `cbor:"reason,omitempty"`
	// ChainID and StepIndex are denormalized into the body for in-body
	// inspection without path parsing per §3.10.6 reserved body fields.
	ChainID   string `cbor:"chain_id,omitempty"`
	StepIndex string `cbor:"step_index,omitempty"`

	// RequestingPeerID and AttemptedURI are reserved on the `rejected`
	// kind per §3.10.6 (receiver-side capture for cap-rejected chain
	// dispatches).
	RequestingPeerID string `cbor:"requesting_peer_id,omitempty"`
	AttemptedURI     string `cbor:"attempted_uri,omitempty"`

	// TargetPeerID is reserved on the `lost` kind per §3.10.6 (sender-side
	// capture: the peer the dispatch was aimed at).
	TargetPeerID string `cbor:"target_peer_id,omitempty"`

	// RejectedMarkerHash is reserved on the `lost` kind when the marker
	// mirrors a peer's rejected marker (§3.10.4 mirror-pointer pattern).
	// Body-side companion to wire-side ErrorData.RejectedMarker so the
	// cross-peer audit walker can follow the reference without inspecting
	// wire metadata.
	RejectedMarkerHash hash.Hash `cbor:"rejected_marker_hash,omitzero"`
}

// EXTENSION-CONTINUATION v1.20 Appendix A — continuation engine codes.
// Canonical home for codes the continuation engine emits on internal
// failures (no wire response). Used as the {reason} path segment per
// §3.10.5 when the failure originates inside the engine.
const (
	// ChainErrorReasonOnErrorDispatchFailed: the on_error dispatch itself
	// failed (transport error or handler-level non-2xx). v1.9 §3.4 (A.1)
	// reason; canonical home moved to Appendix A as of v1.19.
	ChainErrorReasonOnErrorDispatchFailed = "on_error_dispatch_failed"

	// ChainErrorReasonMergeValueNotMap: result_merge: true met a non-map
	// post-transform value at the param-assembly step. Per
	// PROPOSAL-CONTINUATION-MERGE-ASSEMBLY; canonical home moved to
	// Appendix A as of v1.19.
	ChainErrorReasonMergeValueNotMap = "merge_value_not_map"

	// ChainErrorReasonTransformFailed: continuation-transform vocabulary
	// evaluation produced an error (per §2.2 transform contract).
	// NEW v1.19.
	ChainErrorReasonTransformFailed = "transform_failed"

	// ChainErrorReasonChainConstructionInvalid: malformed continuation
	// entity at install time (per §3.2 install). NEW v1.19.
	ChainErrorReasonChainConstructionInvalid = "chain_construction_invalid"
)

// V7 §6.12 — per-request transport error codes. Used as the {reason}
// path segment per §3.10.5 when the failure originates in the per-
// request transport layer (no response received).
const (
	// ChainErrorReasonRecvTimeout: per-request deadline (V7 §6.11(c))
	// fired before any response received. Status 503.
	ChainErrorReasonRecvTimeout = "recv_timeout"

	// ChainErrorReasonConnectionBroken: transport closed before response
	// (peer-close, local-close, reader-task exit). Status 503.
	ChainErrorReasonConnectionBroken = "connection_broken"

	// ChainErrorReasonProtocolError: response received but malformed
	// (decode failure, missing required envelope fields, OR error
	// response with status >= 400 missing required `code` field).
	// Status 502.
	ChainErrorReasonProtocolError = "protocol_error"
)

// ChainErrorRejectedCapDenied is the canonical 403 cap-rejection code
// per V7 §3.3 line 736; used as the {reason} segment of receiver-side
// rejected markers and the sender-side mirror lost markers. NOT a new
// vocabulary — same string the V7 dispatcher already emits in
// ErrorData.code for cap-rejection responses.
const ChainErrorRejectedCapDenied = "capability_denied"

// Deprecated: Use ChainErrorReasonOnErrorDispatchFailed. Same string;
// canonical home moved to Appendix A in v1.19.
const ChainErrorLostReasonOnErrorDispatchFailed = ChainErrorReasonOnErrorDispatchFailed

// Deprecated: v1.19 §3.10.5 collapses the reason vocabulary — for
// response-derived markers, use the response's `result.data.code`
// verbatim as the {reason}. The `forward_dispatch_non2xx` catch-all is
// no longer the marker reason; the actual handler code (e.g.,
// `capability_denied`, `tree_not_found`, `internal`) becomes the path
// segment so distinct codes coexist as sibling paths.
const ChainErrorLostReasonForwardDispatchNon2xx = "forward_dispatch_non2xx"

// Deprecated: Use ChainErrorReasonMergeValueNotMap. Same string;
// canonical home moved to Appendix A in v1.19.
const ChainErrorLostReasonMergeValueNotMap = ChainErrorReasonMergeValueNotMap

// ToEntity creates a system/runtime/chain-error-lost entity.
func (d ChainErrorLostData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeChainErrorLost, cbor.RawMessage(raw))
}

// ContinuationTransformData is the data payload for system/continuation/transform.
type ContinuationTransformData struct {
	Extract          string                        `cbor:"extract,omitempty"`
	Select           map[string]string             `cbor:"select,omitempty"`
	TransformOps     []ContinuationTransformOpData `cbor:"transform_ops,omitempty"`
	ResourceExtract  string                        `cbor:"resource_extract,omitempty"`
	TargetExtract    string                        `cbor:"target_extract,omitempty"`
	OperationExtract string                        `cbor:"operation_extract,omitempty"`
}

// ToEntity creates a system/continuation/transform entity.
func (d ContinuationTransformData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationTransform, cbor.RawMessage(raw))
}

// ContinuationTransformDataFromEntity decodes a continuation transform entity's data.
func ContinuationTransformDataFromEntity(e entity.Entity) (ContinuationTransformData, error) {
	var d ContinuationTransformData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationTransformData{}, err
	}
	return d, nil
}

// ContinuationData is the data payload for system/continuation.
type ContinuationData struct {
	Target              string                     `cbor:"target"`
	Operation           string                     `cbor:"operation"`
	Resource            *ResourceTarget            `cbor:"resource,omitempty"`
	Params              cbor.RawMessage            `cbor:"params,omitempty"`
	ResultTransform     *ContinuationTransformData `cbor:"result_transform,omitempty"`
	ResultField         string                     `cbor:"result_field,omitempty"`
	// ResultMerge: when true, the post-transform value (which must be a
	// map — typically a `select` output) is shallow-merged into the
	// static `params` at top level rather than nested under a single
	// `result_field` key. Mutually exclusive with `result_field`
	// (rejected at install). Per PROPOSAL-CONTINUATION-MERGE-ASSEMBLY.
	ResultMerge         bool                       `cbor:"result_merge,omitempty"`
	OnError             *DeliverySpec              `cbor:"on_error,omitempty"`
	DeliverTo           *DeliverySpec              `cbor:"deliver_to,omitempty"`
	RemainingExecutions *uint64                    `cbor:"remaining_executions,omitempty"`
	DispatchCapability  hash.Hash                  `cbor:"dispatch_capability,omitzero"`
}

// ToEntity creates a system/continuation entity.
func (d ContinuationData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuation, cbor.RawMessage(raw))
}

// ContinuationDataFromEntity decodes a continuation entity's data.
func ContinuationDataFromEntity(e entity.Entity) (ContinuationData, error) {
	var d ContinuationData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationData{}, err
	}
	return d, nil
}

// ContinuationJoinData is the data payload for system/continuation/join.
type ContinuationJoinData struct {
	Expected            []string                   `cbor:"expected"`
	Received            map[string]cbor.RawMessage `cbor:"received,omitempty"`
	Target              string                     `cbor:"target"`
	Operation           string                     `cbor:"operation"`
	Resource            *ResourceTarget            `cbor:"resource,omitempty"`
	Params              cbor.RawMessage            `cbor:"params,omitempty"`
	ResultField         string                     `cbor:"result_field,omitempty"`
	OnError             *DeliverySpec              `cbor:"on_error,omitempty"`
	DeliverTo           *DeliverySpec              `cbor:"deliver_to,omitempty"`
	RemainingExecutions *uint64                    `cbor:"remaining_executions,omitempty"`
	DispatchCapability  hash.Hash                  `cbor:"dispatch_capability,omitzero"`
}

// ToEntity creates a system/continuation/join entity.
func (d ContinuationJoinData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationJoin, cbor.RawMessage(raw))
}

// ContinuationJoinDataFromEntity decodes a continuation join entity's data.
func ContinuationJoinDataFromEntity(e entity.Entity) (ContinuationJoinData, error) {
	var d ContinuationJoinData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationJoinData{}, err
	}
	return d, nil
}

// ContinuationSuspendedData is the data payload for system/continuation/suspended.
type ContinuationSuspendedData struct {
	Target         string          `cbor:"target"`
	Operation      string          `cbor:"operation"`
	Resource       *ResourceTarget `cbor:"resource,omitempty"`
	Params         cbor.RawMessage `cbor:"params,omitempty"`
	Reason         string          `cbor:"reason"`
	ChainID        string          `cbor:"chain_id"`
	OriginalAuthor hash.Hash       `cbor:"original_author"`
	SuspendedAt    uint64          `cbor:"suspended_at"`
}

// ToEntity creates a system/continuation/suspended entity.
func (d ContinuationSuspendedData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationSuspended, cbor.RawMessage(raw))
}

// ContinuationSuspendedDataFromEntity decodes a suspended continuation entity's data.
func ContinuationSuspendedDataFromEntity(e entity.Entity) (ContinuationSuspendedData, error) {
	var d ContinuationSuspendedData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationSuspendedData{}, err
	}
	return d, nil
}

// ContinuationResumeRequestData is the data payload for system/continuation/resume-request.
type ContinuationResumeRequestData struct {
	Bounds     *BoundsData     `cbor:"bounds,omitempty"`
	Resolution cbor.RawMessage `cbor:"resolution,omitempty"`
	DeliverTo  *DeliverySpec   `cbor:"deliver_to,omitempty"`
}

// ToEntity creates a system/continuation/resume-request entity.
func (d ContinuationResumeRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationResumeRequest, cbor.RawMessage(raw))
}

// ContinuationResumeRequestDataFromEntity decodes a resume request entity's data.
func ContinuationResumeRequestDataFromEntity(e entity.Entity) (ContinuationResumeRequestData, error) {
	var d ContinuationResumeRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationResumeRequestData{}, err
	}
	return d, nil
}

// ContinuationAbandonRequestData is the data payload for system/continuation/abandon-request.
type ContinuationAbandonRequestData struct{}

// ToEntity creates a system/continuation/abandon-request entity.
func (d ContinuationAbandonRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationAbandonRequest, cbor.RawMessage(raw))
}

// ContinuationAbandonRequestDataFromEntity decodes an abandon request entity's data.
func ContinuationAbandonRequestDataFromEntity(e entity.Entity) (ContinuationAbandonRequestData, error) {
	var d ContinuationAbandonRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationAbandonRequestData{}, err
	}
	return d, nil
}

// ContinuationInstallResultData is the data payload for system/continuation/install-result.
type ContinuationInstallResultData struct {
	Path string `cbor:"path"`
}

// ToEntity creates a system/continuation/install-result entity.
func (d ContinuationInstallResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationInstallResult, cbor.RawMessage(raw))
}

// ContinuationInstallResultDataFromEntity decodes an install result entity's data.
func ContinuationInstallResultDataFromEntity(e entity.Entity) (ContinuationInstallResultData, error) {
	var d ContinuationInstallResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationInstallResultData{}, err
	}
	return d, nil
}

// ContinuationAdvanceRequestData is the data payload for system/continuation/advance-request.
type ContinuationAdvanceRequestData struct {
	Result cbor.RawMessage `cbor:"result,omitempty"`
	Status *uint           `cbor:"status,omitempty"`
}

// ToEntity creates a system/continuation/advance-request entity.
func (d ContinuationAdvanceRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeContinuationAdvanceRequest, cbor.RawMessage(raw))
}

// ContinuationAdvanceRequestDataFromEntity decodes an advance request entity's data.
func ContinuationAdvanceRequestDataFromEntity(e entity.Entity) (ContinuationAdvanceRequestData, error) {
	var d ContinuationAdvanceRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ContinuationAdvanceRequestData{}, err
	}
	return d, nil
}
