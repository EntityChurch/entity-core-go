package peer

import (
	"context"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
)

// remoteEndpoint abstracts the outbound side of a pooled remote-peer
// endpoint. The pool (remoteState.conns) stores values polymorphically:
// *Connection for TCP, *HTTPConnection for HTTP. Both implement the same
// envelope-exchange contract so remoteExecute stays transport-agnostic.
//
// This interface deliberately covers ONLY the outbound pool — it does NOT
// abstract server-side serve(), the multiplexed reader, wire hooks, or
// any of the Connection machinery the bidirectional-deadlock fix
// (F-WB28 / Class G) depends on. Server-side TCP stays specific to
// *Connection; HTTP inbound is handled by httplive.Server independently.
//
// Per cohort handoff §10 (Chunk D), A→B and B→A are separate independent
// outbound endpoints once both peers publish HTTP profiles — there is no
// shared in-flight state between them. The F-WB28 deadlock cannot recur
// on HTTP for that reason; HTTPConnection.Execute is therefore safe for
// concurrent callers without per-endpoint serialization.
type remoteEndpoint interface {
	Execute(ctx context.Context, uri, operation string,
		params entity.Entity, resource *types.ResourceTarget,
		async ...*protocol.AsyncDelivery) (entity.Envelope, error)
	Close() error
	IsClosed() bool
}
