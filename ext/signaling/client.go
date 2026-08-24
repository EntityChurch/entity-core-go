package signaling

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The client half — using a connection node from a peer. Calling
// system/signaling:{offer,collect,advertise} on a gated node is an ordinary
// cross-peer EXECUTE, so no new handler is needed to USE the service; this is a
// typed wrapper over dispatch. The client owns the two convergence obligations
// the node does not: key derivation (which key, key.go) and pool selection
// (which node, pool.go). Each dispatch is cap-checked at the transport, so the
// caller's grant must cover system/signaling:{op}; this adds no authority.

// Transport is the wire-side dependency the client needs — any RPC client that
// can dispatch authenticated EXECUTEs and report the remote peer's id. It is the
// same small interface ext/role/sdk uses; cmd/internal/validate.PeerClient
// satisfies it unmodified, so the client depends only on core, never the wire
// layer.
type Transport interface {
	SendExecute(ctx context.Context, uri, operation string, params entity.Entity, resource *types.ResourceTarget) (entity.Envelope, []byte, error)
	RemotePeerID() crypto.PeerID
}

// Client is a typed signaling client for one node. One Client targets one node
// (the URI is computed once from Transport.RemotePeerID()); the node normally
// comes from the pool member the peer selected (Select), not a config constant,
// because both peers must land on the same one.
type Client struct {
	t   Transport
	uri string
}

// NewClient constructs a signaling client targeting the node behind t.
func NewClient(t Transport) *Client {
	return &Client{
		t:   t,
		uri: fmt.Sprintf("entity://%s/%s", t.RemotePeerID().String(), HandlerPattern),
	}
}

// Offer deposits message at key (§5.1). Safe to call again with the same bytes:
// the node dedups by content hash, so a retry after a timeout is idempotent
// (§5.2). Peers MUST be prepared to re-offer, since the TTL is binding and a blob
// may have been reaped. Returns the node status; a non-200 is surfaced, not
// swallowed.
func (c *Client) Offer(ctx context.Context, key, message []byte) (uint, error) {
	params, err := types.OfferRequestData{RendezvousKey: key, Message: message}.ToEntity()
	if err != nil {
		return 0, fmt.Errorf("encode offer-request: %w", err)
	}
	status, _, err := c.execute(ctx, OpOffer, params)
	return status, err
}

// Collect reads what is at key (§5.1). Removes nothing, so both peers may
// collect and re-collect. An empty list means "nothing there yet" — not an error
// and not a reason to give up; a peer polling ahead of its counterpart is the
// normal case. An unknown key is an empty list and a 200, never a 404.
func (c *Client) Collect(ctx context.Context, key []byte) (uint, [][]byte, error) {
	params, err := types.CollectRequestData{RendezvousKey: key}.ToEntity()
	if err != nil {
		return 0, nil, fmt.Errorf("encode collect-request: %w", err)
	}
	status, resultEnt, err := c.execute(ctx, OpCollect, params)
	if err != nil || status != 200 {
		return status, nil, err
	}
	result, err := types.CollectResultDataFromEntity(resultEnt)
	if err != nil {
		return status, nil, fmt.Errorf("decode collect-result: %w", err)
	}
	return status, result.Messages, nil
}

// Advertise reads the node's endpoint and limits — including the optional
// lobby_constant override inside limits (§4.5). Worth calling before deriving a
// lobby key: if the node overrides the constant and the peer derives from
// LobbyDefault anyway, it lands in a bucket nobody else on that pool uses.
// advertise takes no arguments, but an EXECUTE still carries a params entity and
// an empty data is rejected — so we send an empty CBOR map.
func (c *Client) Advertise(ctx context.Context) (uint, types.AdvertiseResultData, error) {
	status, resultEnt, err := c.execute(ctx, OpAdvertise, emptyParams())
	if err != nil || status != 200 {
		return status, types.AdvertiseResultData{}, err
	}
	result, err := types.AdvertiseResultDataFromEntity(resultEnt)
	if err != nil {
		return status, types.AdvertiseResultData{}, fmt.Errorf("decode advertise-result: %w", err)
	}
	return status, result, nil
}

// OfferMessage deposits a coordination entity (§3) as an opaque blob (§4.4).
func (c *Client) OfferMessage(ctx context.Context, key []byte, e entity.Entity) (uint, error) {
	blob, err := ToBlob(e)
	if err != nil {
		return 0, fmt.Errorf("frame blob: %w", err)
	}
	return c.Offer(ctx, key, blob)
}

// CollectMessages collects a bucket and classifies every blob in it (§4.5).
// Unknown entries are kept rather than dropped so a caller can count what it
// skipped. INCLUDES your own offers (collect is non-destructive), which is why
// FindResponse / FindRequest both filter on peer-id.
func (c *Client) CollectMessages(ctx context.Context, key []byte) (uint, []CollectedMessage, error) {
	status, blobs, err := c.Collect(ctx, key)
	if err != nil || status != 200 {
		return status, nil, err
	}
	msgs := make([]CollectedMessage, 0, len(blobs))
	for _, b := range blobs {
		msgs = append(msgs, ClassifyBlob(b))
	}
	return status, msgs, nil
}

// execute runs one EXECUTE against the node and splits out the status and result
// entity — the same shape ext/role/sdk uses.
//
// NO resource target: a signaling op acts on no tree resource (the handler
// declares an empty internal scope; the rendezvous_key rides in the params, not
// the path), so it sends none — and the node's seed grant has an EMPTY resource
// scope precisely because "a signaling EXECUTE sends no resource target, so
// resources are never consulted." Sending a resource target (e.g. the handler
// pattern) makes the capability check test it against that empty scope and deny
// with 403. Verified live 2026-07-30 against the --open node.
func (c *Client) execute(ctx context.Context, op string, params entity.Entity) (uint, entity.Entity, error) {
	respEnv, _, err := c.t.SendExecute(ctx, c.uri, op, params, nil)
	if err != nil {
		return 0, entity.Entity{}, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, entity.Entity{}, fmt.Errorf("decode execute-response: %w", err)
	}
	var resultEnt entity.Entity
	if len(respData.Result) > 0 {
		if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
			return respData.Status, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
		}
	}
	return respData.Status, resultEnt, nil
}

// emptyParams builds the empty-map params EXECUTE requires where an operation
// takes no arguments (advertise) — an empty data is rejected by the node.
func emptyParams() entity.Entity {
	raw, _ := ecf.Encode(map[string]interface{}{})
	ent, _ := entity.NewEntity("primitive/any", raw)
	return ent
}
