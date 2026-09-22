package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure conditions.
var (
	// ErrHashMismatch indicates computed hash does not match claimed hash.
	ErrHashMismatch = errors.New("hash mismatch")

	// ErrInvalidHash indicates a malformed hash (wrong length, unknown algorithm).
	ErrInvalidHash = errors.New("invalid hash")

	// ErrInvalidEntity indicates a malformed entity (missing type or data).
	ErrInvalidEntity = errors.New("invalid entity")

	// ErrInvalidEnvelope indicates a malformed envelope.
	ErrInvalidEnvelope = errors.New("invalid envelope")

	// ErrUnknownAlgorithm indicates an unsupported hash algorithm byte.
	ErrUnknownAlgorithm = errors.New("unknown hash algorithm")

	// ErrDuplicateMapKey indicates a CBOR map with duplicate keys.
	ErrDuplicateMapKey = errors.New("duplicate map key")

	// ErrNonCanonicalECF indicates a received frame carries a construct ECF
	// forbids — a CBOR tag (major type 6) at any depth (ENTITY-CBOR-ENCODING
	// §6.3). Distinct from ErrHashMismatch: the bytes decode and self-verify,
	// but they are non-canonical, so the receive-boundary remedy is
	// "re-encode without the tag" (400 non_canonical_ecf), not a hash failure.
	ErrNonCanonicalECF = errors.New("non-canonical ECF")

	// ErrNotFound indicates an entity or path was not found.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates a path or tree already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrCapabilityDenied indicates an authorization failure.
	ErrCapabilityDenied = errors.New("capability denied")

	// ErrAuthenticationFailed indicates signature verification failure.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrChainUnreachable indicates a capability authority chain cannot be
	// fully walked because a parent link is absent from the available
	// included set or content store. Surfaced as 404 chain_unreachable by
	// create operations performing R1 chain-root checks.
	ErrChainUnreachable = errors.New("chain unreachable")

	// ErrChainTooDeep indicates a capability authority chain exceeds the
	// implementation's max-depth limit (default 64 per
	// PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §6.1). Bounds the cost of the
	// walk regardless of consumer (R1 check, dispatch validation, revocation).
	ErrChainTooDeep = errors.New("chain too deep")

	// ErrUnresolvableGrantee indicates a capability whose `grantee` field
	// does not resolve to a present `system/peer` entity in either
	// the local content store or the wire envelope's `included` map.
	// Closes the bearer-cap surface area per V7 v7.39 §3.6 + §5.5;
	// PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS PR-3. Wire status: 401
	// `unresolvable_grantee`. Resolution is per-link in the chain (every
	// cap's grantee MUST resolve, not just the leaf).
	ErrUnresolvableGrantee = errors.New("unresolvable grantee")

	// ErrCapabilityRevoked indicates a capability whose chain root has
	// been revoked (a `system/capability/revocation` marker bound at
	// `system/capability/revocations/{root_hash_hex}`, or — for path-bound
	// caps — its tree binding removed). V7 v7.71 §A4-AUTHZ pins this as
	// the EXTENSION-ROLE §5.5 in-flight cascade's own defined code, distinct
	// from the generic 403 `capability_denied` default. Wire status: 401
	// `capability_revoked` (the ROLE §5.5 carve-out alongside PR-3's
	// unresolvable_grantee 401).
	ErrCapabilityRevoked = errors.New("capability revoked")

	// ErrConnectionRequired indicates the connection has not been established.
	ErrConnectionRequired = errors.New("connection required")

	// ErrConnectionEstablished indicates the connection handshake was already completed.
	ErrConnectionEstablished = errors.New("connection already established")

	// ErrConnectionSequence indicates a connect operation the responder
	// implements arrived in a state that forbids it (ENTITY-CORE-PROTOCOL §4.7
	// out-of-order row → 409 connection_sequence_error). Distinct from
	// ErrConnectionEstablished (a second hello AFTER hello_done, row 9) — this
	// is the row-10 state half (e.g. a second hello mid-handshake, or a
	// pre-handshake ping).
	ErrConnectionSequence = errors.New("connection sequence error")

	// ErrTTLExhausted indicates the request TTL reached zero.
	ErrTTLExhausted = errors.New("TTL exhausted")

	// ErrBudgetExhausted indicates the request budget reached zero.
	ErrBudgetExhausted = errors.New("budget exhausted")

	// ErrCycleDetected indicates a cycle was detected in request routing.
	ErrCycleDetected = errors.New("cycle detected")

	// ErrUnsupportedContentHashFormat indicates a content_hash whose leading
	// format-code byte names a content_hash_format this peer does not
	// support. Surfaces at protocol boundary as
	// `400 unsupported_content_hash_format` (V7 §4.7 / v7.66 §7.1).
	// Returned by hash.DispatchContentHashFormat — the §5.2 normative
	// dispatch primitive.
	ErrUnsupportedContentHashFormat = errors.New("unsupported content_hash_format")

	// ErrFrameTooLarge indicates a wire frame whose length prefix exceeds the
	// peer's configured maximum payload size. V7 §4.10(a) — §9.1 floor MUST
	// as of v7.75 (arch fold `414b892`, gate landed 3-way GREEN).
	// Surfaces as 413 payload_too_large with a best-effort coded frame +
	// connection close — the body is never buffered, so the response has no
	// request_id to bind to. Distinct from ErrInvalidEnvelope so the serve
	// loop can choose to emit the coded response before tearing down the
	// connection rather than dropping silently.
	ErrFrameTooLarge = errors.New("frame too large")

	// ErrEnvelopeDecode indicates a wire frame that was read whole but could not
	// be decoded into an Envelope — un-parseable or non-canonical CBOR. This is
	// the "a frame that never becomes an Envelope at all" population of
	// ENTITY-CORE-PROTOCOL §4.11 (0.8.2.25), and it surfaces as
	// 400 invalid_request via a best-effort coded frame (a pre-admission
	// refusal). Distinct from ErrFrameTooLarge (413, detected at the length
	// prefix) and from a transport read error (EOF / reset): a complete frame
	// with an undecodable payload leaves the stream synchronized on the next
	// frame boundary, so the serve loop emits the coded frame and MAY keep
	// serving — §4.9(c) forbids destroying admitted in-flight requests on a
	// multiplexed connection over one bad frame.
	ErrEnvelopeDecode = errors.New("envelope decode")
)

// ValidationError carries field-level validation context.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
}

// ProtocolError maps to system/protocol/error entities.
type ProtocolError struct {
	Code    string
	Message string
	Status  uint
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("protocol error %d (%s): %s", e.Status, e.Code, e.Message)
}

// Re-export standard errors functions so callers can use errors.Is/As
// without importing both this package and the standard library.
var (
	Is  = errors.Is
	As  = errors.As
	New = errors.New
)
