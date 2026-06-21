package peer

import (
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// WireDirection distinguishes inbound from outbound frames.
type WireDirection int

const (
	// WireInbound: a frame was read from the network.
	WireInbound WireDirection = iota
	// WireOutbound: a frame was written to the network.
	WireOutbound
)

// WireEvent describes one envelope traversal across the network boundary.
// Per GUIDE-INSPECTABILITY v1.1 §2.1 #7. Fires after the wire I/O completes
// (post-decode for inbound, post-write for outbound).
//
// Security note: FrameBytes contains the full CBOR envelope as it traveled
// on the wire — including capability tokens, signatures, identity entities,
// and entity payloads. A wire recorder consuming this hook holds raw
// authority material; recordings must be treated as sensitive artifacts.
// See the GUIDE-inspectability core-go security addendum §2.
type WireEvent struct {
	Direction   WireDirection
	FrameBytes  []byte // the actual CBOR-encoded envelope; the consumer owns lifetime
	PeerAddress string // remote peer's network address
	RequestID   string // best-effort extracted from the envelope root; empty if not extractable
	RootType    string // envelope root entity type (for cheap classification without decoding)
	Timestamp   time.Time
}

// WireEventFn observes a wire event. Receives the event by value (FrameBytes
// is a slice — same lifetime caveat as any Go slice). Hook fires on the wire
// hot path (every envelope read/write); MUST be fast. If you need to retain
// FrameBytes past the hook return, copy them.
type WireEventFn func(WireEvent)

// NamedWireHook pairs a hook fn with a stable identifier.
type NamedWireHook struct {
	Name string
	Fn   WireEventFn
}

// bestEffortRequestID extracts request_id from the envelope root if the
// root type is one of the request/response shapes that carries it. Returns
// empty for handshake frames, error envelopes without request_id, or any
// shape we don't recognize. Cheap — type-prefix dispatch with one decode
// per known type.
func bestEffortRequestID(root entity.Entity) string {
	switch root.Type {
	case types.TypeExecute:
		if d, err := types.ExecuteDataFromEntity(root); err == nil {
			return d.RequestID
		}
	case types.TypeExecuteResponse:
		if d, err := types.ExecuteResponseDataFromEntity(root); err == nil {
			return d.RequestID
		}
	}
	return ""
}
