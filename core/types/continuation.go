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

// Sentinels for a marker coordinate whose wire-supplied value fails
// path-safety. A coordinate segment collapses to one fixed sentinel and the
// original is preserved in the marker body (arch rulings 2026-07-17 §1/§3).
// One sentinel per coordinate, so a quarantined marker still says WHICH
// coordinate was hostile without the value being on the path.
const (
	// ReasonUnspecified is landed spec — EXTENSION-CONTINUATION §3.10.5
	// prescribes it by name for a non-path-safe `code`.
	ReasonUnspecified = "unspecified_error"
	// ChainIDUnspecified / StepIndexUnspecified are Go's proposed spellings.
	// Arch left the exact strings to the cohort to converge and pinned only
	// the shape ("one fixed sentinel in the same spirit"); these follow
	// §3.10.5's landed `unspecified_error` pattern. Reported for pinning.
	ChainIDUnspecified   = "unspecified_chain_id"
	StepIndexUnspecified = "unspecified_step_index"
)

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
	// Code is the RAW `result.data.code`, preserved verbatim even when the
	// path's {reason} collapsed to ReasonUnspecified (§3.10.5). Equals Reason
	// whenever the code is path-safe, which is the ordinary case.
	Code string `cbor:"code,omitempty"`
	// Status is the downstream status code (§3.10.6, reserved on `lost`).
	Status uint `cbor:"status,omitempty"`
	// TargetURI is the URI the dispatch was aimed at (§3.10.6, `lost`).
	TargetURI string `cbor:"target_uri,omitempty"`
	Timestamp uint64 `cbor:"timestamp"`
	// Reason mirrors this marker's {reason} path segment — the SANITIZED
	// value (§3.10.6: "matching this marker's path segment"). The raw code
	// lives in Code.
	Reason string `cbor:"reason,omitempty"`
	// ChainID and StepIndex carry the ORIGINAL wire-supplied values, NOT the
	// sanitized path segments (arch ruling 2026-07-17 §2: "plain names, each
	// meaning the original value; the body is the record, the path is an
	// index"). They agree with the path whenever the value was path-safe,
	// which is every conformant dispatch; they diverge exactly when a
	// coordinate collapsed to a sentinel, which is the case the body exists to
	// keep recoverable.
	//
	// This is deliberately narrower than §3.10.6's "for in-body inspection
	// without path parsing" gloss, which reads as a path mirror. The registry
	// predates coordinate sanitization; a mirror would make the sentinel a
	// one-way loss. See the spec-issue routed 2026-07-17.
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

	// JoinPath and JoinSlots are reserved for the two join-completion
	// reasons (ChainErrorReasonJoinIncomplete / ...JoinErrorSlot).
	//
	// PROPOSAL-CONTINUATION-STANDING-MODEL §4 requires the abandon path to
	// emit "a lost marker naming the missing slots", but the §3.10.6 marker
	// registry has nowhere to put them: every existing field describes a
	// DISPATCH that failed, and an abandoned round never dispatched at all.
	// Without these the marker records that a round failed and loses which
	// slots — which is the entire diagnostic content of the observation.
	//
	// Go's proposed spelling, routed for cohort pinning with the round clock
	// (docs/validation/spec-issues/2026-07-22-join-completion-round-clock.md).
	// Both are omitempty, so no non-join marker's bytes change.
	JoinPath  string   `cbor:"join_path,omitempty"`
	JoinSlots []string `cbor:"join_slots,omitempty"`

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

	// ChainErrorReasonJoinIncomplete: a join round hit its
	// completion_deadline_ms with slots still missing and on_incomplete
	// "abandon" failed the round (PROPOSAL-CONTINUATION-STANDING-MODEL §4
	// mechanism 2). The marker names the missing slots; the round then
	// resets so the next one can fire clean.
	//
	// Go's proposed spelling — §4 requires "a lost marker naming the missing
	// slots" and pins no code. Routed for cohort pinning alongside the
	// round-clock field.
	ChainErrorReasonJoinIncomplete = "join_incomplete"

	// ChainErrorReasonJoinErrorSlot: a join round completed the barrier but
	// one or more slots arrived carrying a non-2xx result (§4 mechanism 1).
	// The round is observably failed rather than silently folded into a
	// boundary entity computed from an error payload.
	ChainErrorReasonJoinErrorSlot = "join_error_slot"

	// ChainErrorReasonJoinLate: a slot advance targeted a round that is no
	// longer current — a straggler from an abandoned (or already-fired) round
	// arriving after the join advanced to the next generation (§4.1 "drop
	// stale, loudly"). The slot is NOT admitted; the marker names the stale
	// slot and the round it targeted so lateness is observable, not merely
	// survived — a silently mixed generation is worse than a dropped round.
	//
	// Go's proposed spelling — §4.1 requires "a lost/late marker naming the
	// stale slot" and pins no code. Routed for cohort pinning alongside the
	// round_id field.
	ChainErrorReasonJoinLate = "join_late"
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
	Target          string                     `cbor:"target"`
	Operation       string                     `cbor:"operation"`
	Resource        *ResourceTarget            `cbor:"resource,omitempty"`
	Params          cbor.RawMessage            `cbor:"params,omitempty"`
	ResultTransform *ContinuationTransformData `cbor:"result_transform,omitempty"`
	ResultField     string                     `cbor:"result_field,omitempty"`
	// ResultMerge: when true, the post-transform value (which must be a
	// map — typically a `select` output) is shallow-merged into the
	// static `params` at top level rather than nested under a single
	// `result_field` key. Mutually exclusive with `result_field`
	// (rejected at install). Per PROPOSAL-CONTINUATION-MERGE-ASSEMBLY.
	ResultMerge         bool          `cbor:"result_merge,omitempty"`
	OnError             *DeliverySpec `cbor:"on_error,omitempty"`
	DeliverTo           *DeliverySpec `cbor:"deliver_to,omitempty"`
	RemainingExecutions *uint64       `cbor:"remaining_executions,omitempty"`
	DispatchCapability  hash.Hash     `cbor:"dispatch_capability,omitzero"`
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

// Join completion policy (PROPOSAL-CONTINUATION-STANDING-MODEL §4 Facet B).
//
// The barrier fires only on allSlotsReceived (§3.5) and a standing join resets
// `received` only after firing, so §2.3/§3.5 never define what happens when a
// slot NEVER arrives: a dropped trigger, a pool refusal (429), or an error
// returning before delivery wedges that round and every subsequent one. These
// are the two policies a join may carry for that case.
const (
	// JoinOnIncompleteAbandon fails the round: bind a lost marker naming the
	// missing slots, reset `received`, ready for the next round. A standing
	// per-tick join thus self-heals rather than wedging. This is the default.
	JoinOnIncompleteAbandon = "abandon"

	// JoinOnIncompleteFirePartial fires the target with the partial `received`
	// plus an explicit incomplete marker listing the missing slots. Never the
	// default — a stitch that assumes k fragments must opt in.
	JoinOnIncompleteFirePartial = "fire-partial"
)

// JoinIncompleteField is the key under which a fire-partial dispatch carries
// its explicit incomplete marker into the assembled params, alongside the
// partial `received`. Its presence IS the signal to the target that this round
// is short; a target that ignores it has opted into partial input by choosing
// fire-partial at install.
//
// Only ever present on a fire-partial round. A complete round assembles exactly
// the bytes it assembled before this proposal — the success path is untouched,
// which is what keeps the boundary-equivalence licence honest.
const JoinIncompleteField = "incomplete"

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

	// CompletionDeadlineMs is the per-round wall budget (STANDING-MODEL §4).
	// ABSENT = wait forever, which is the pre-proposal behavior — no silent
	// change; the policy is opt-in per join set by the substrate that installs
	// it. Reset with `received` each round.
	CompletionDeadlineMs *uint64 `cbor:"completion_deadline_ms,omitempty"`

	// OnIncomplete is JoinOnIncompleteAbandon (default, also the meaning of
	// absent) or JoinOnIncompleteFirePartial. Only consulted when
	// CompletionDeadlineMs is set — without a deadline no round can be
	// incomplete, because it never ends.
	OnIncomplete string `cbor:"on_incomplete,omitempty"`

	// RoundStartedMs stamps when the current round began accumulating, so the
	// deadline has a reference point that survives a peer restart and is
	// observable in the tree. Armed when the round's FIRST slot lands, cleared
	// with `received` on reset.
	//
	// NOT in the proposal's §4 field list, which names only the two policy
	// fields — but a deadline is unenforceable without a start, so some
	// impl-side state is forced. Keeping it on the entity rather than in
	// handler memory is the choice that follows this codebase's grain (the
	// tree IS the event log; nothing here owns a timer goroutine) and makes a
	// wedged round diagnosable by reading the tree. It is a wire-visible field
	// on a spec'd type, so it is a cross-impl surface and is routed to arch for
	// pinning rather than assumed — see
	// docs/validation/spec-issues/2026-07-22-join-completion-round-clock.md.
	RoundStartedMs *uint64 `cbor:"round_started_ms,omitempty"`

	// ReceivedStatus records the advance status of any slot that arrived
	// carrying a NON-2xx result (STANDING-MODEL §4 mechanism 1: "the join's
	// `received` map MUST preserve each slot's status"). A delivered error
	// FILLS its slot — the barrier still completes — so without this the round
	// looks clean and the failure disappears into the stitch.
	//
	// Sparse by construction: an all-good round carries no `received_status`
	// key at all, so its entity bytes and its assembled params are identical to
	// what they were before this proposal. Failure-path only.
	ReceivedStatus map[string]uint `cbor:"received_status,omitempty"`

	// RoundID is the join's current round generation (STANDING-MODEL §4.1 — the
	// abandon straggler guard, a MUST). Incremented on every round turnover
	// (abandon-reset, fire-reset, fire-partial-reset). A slot advance carries
	// the round_id it targets (ContinuationAdvanceRequestData.RoundID); a slot
	// whose round_id ≠ this MUST NOT be admitted — otherwise a straggler from an
	// abandoned round N lands in round N+1's slot and the round is stitched from
	// two generations, a boundary hash that is wrong, deterministic-looking, and
	// reproducible (the silent seam-collapse the compute POC exists to prevent).
	//
	// Scoped to deadline-carrying joins (the joins §4.1's abandon path applies
	// to): a pre-§4 wait-forever join never turns a round over via abandon and
	// carries no round_id, so `omitempty` keeps its bytes identical to today. The
	// guard engages only when BOTH the join is deadline-carrying and the advance
	// opts in by tagging its round_id — additive, no silent change.
	//
	// Wire-visible on a spec'd type, so cross-impl-observable: §6 R3(a) pins
	// `round_id: uint` on the join echoed on each slot advance. The exact spelling
	// and the late-drop reason code were routed to arch and are now PINNED by
	// EXTENSION-CONTINUATION §3.5a (v1.21): `round_id` (§2.3) + reason `join_late`.
	RoundID uint64 `cbor:"round_id,omitempty"`
}

// IncompleteRound reports whether the join's current round has begun and
// exceeded its completion deadline at nowMs without filling every slot.
//
// False whenever no deadline is set (wait-forever), no round has started (an
// idle standing join has nothing to abandon — see the round-clock spec issue),
// or the round is already complete.
func (d ContinuationJoinData) IncompleteRound(nowMs uint64) bool {
	if d.CompletionDeadlineMs == nil || d.RoundStartedMs == nil {
		return false
	}
	if len(d.Received) >= len(d.Expected) {
		return false
	}
	deadline := *d.RoundStartedMs + *d.CompletionDeadlineMs
	return nowMs > deadline
}

// MissingSlots returns the expected slots absent from `received`, in `expected`
// order — the order every join read uses, so a marker naming them is stable
// across peers.
func (d ContinuationJoinData) MissingSlots() []string {
	missing := make([]string, 0, len(d.Expected))
	for _, slot := range d.Expected {
		if _, ok := d.Received[slot]; !ok {
			missing = append(missing, slot)
		}
	}
	return missing
}

// ErrorSlots returns the slots that arrived carrying a non-2xx status, in
// `expected` order (mechanism 1).
func (d ContinuationJoinData) ErrorSlots() []string {
	if len(d.ReceivedStatus) == 0 {
		return nil
	}
	var errored []string
	for _, slot := range d.Expected {
		if status, ok := d.ReceivedStatus[slot]; ok && (status < 200 || status >= 300) {
			errored = append(errored, slot)
		}
	}
	return errored
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

	// RoundID, when present, is the join round this slot advance targets
	// (STANDING-MODEL §4.1). Optional: absent → untracked (pre-§4.1 behavior,
	// admitted as today); present → the join admits the slot only if it matches
	// the join's current RoundID, else drops it loudly with a join_late marker.
	// Only meaningful for a join-slot advance on a deadline-carrying join.
	RoundID *uint64 `cbor:"round_id,omitempty"`
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
