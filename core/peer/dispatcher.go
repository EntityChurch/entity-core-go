package peer

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ConnectionDispatcher returns a handler.Dispatcher backed by an
// established Connection. AppPeer callers use this to drive SDK helpers
// (e.g. content.EnsureClosure) over the same cap-checked Execute path
// they would otherwise call directly via Connection.Execute.
//
// Per SDK-EXTENSION-OPERATIONS v0.8 §11 Content Extension: both AppPeer
// (this adapter) and HandlerContext satisfy the Dispatcher interface so
// the §7.2 closure-fetch algorithm lives in one place across both
// outer-caller and handler-internal use.
//
// The adapter decodes the wire envelope's Root entity (the
// system/protocol/execute/response wrapper) into ExecuteResponse{Status,
// Result, Included} so SDK callers receive the same decoded shape they
// would get from a HandlerContext-based dispatcher — no per-caller
// envelope-unwrapping boilerplate.
func ConnectionDispatcher(c *Connection) handler.Dispatcher {
	return connectionDispatcher{c: c}
}

type connectionDispatcher struct {
	c *Connection
}

// Store returns the local Peer's content store. SDK helpers
// (content.EnsureClosure) use this to read what's already local before
// dispatching cross-peer system/content:get. The cap-checked dispatch
// path remains the only writer.
func (d connectionDispatcher) Store() store.ContentStore {
	return d.c.peer.Store()
}

func (d connectionDispatcher) Execute(ctx context.Context, req handler.ExecuteRequest) (handler.ExecuteResponse, error) {
	env, err := d.c.Execute(ctx, req.URI, req.Operation, req.Params, req.Resource)
	if err != nil {
		return handler.ExecuteResponse{}, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return handler.ExecuteResponse{}, fmt.Errorf("decode execute response: %w", err)
	}
	// E4 / F64 (0.8.2.19): an EXECUTE_RESPONSE is a received envelope — ingest
	// its included signatures/identities so a later chain-walk resolves. Soft-
	// fail, matching the inbound EXECUTE and connect-response ingest sinks.
	if len(env.Included) > 0 {
		if ingestErr := protocol.IngestEnvelopeSignatures(d.c.peer.Store(), d.c.peer.LocationIndex(), env.Included); ingestErr != nil {
			_ = ingestErr
		}
	}
	var resultEnt entity.Entity
	if len(respData.Result) > 0 {
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return handler.ExecuteResponse{}, fmt.Errorf("decode result entity: %w", err)
		}
	}
	return handler.ExecuteResponse{
		Status:   respData.Status,
		Result:   resultEnt,
		Included: env.Included,
	}, nil
}
