package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Protocol type constants.
const (
	TypeHello           = "system/protocol/connect/hello"
	TypeAuthenticate    = "system/protocol/connect/authenticate"
	TypeResourceTarget  = "system/protocol/resource-target"
	TypeExecute         = "system/protocol/execute"
	TypeExecuteResponse = "system/protocol/execute/response"
	TypeError           = "system/protocol/error"
)

// HelloData is the data payload for system/protocol/connect/hello.
type HelloData struct {
	PeerID      string   `cbor:"peer_id"`
	Nonce       []byte   `cbor:"nonce"`
	Protocols   []string `cbor:"protocols"`
	Timestamp   uint64   `cbor:"timestamp"`
	HashFormats []string `cbor:"hash_formats,omitempty"`
	KeyTypes    []string `cbor:"key_types,omitempty"`
	Compression []string `cbor:"compression,omitempty"`
	Encryption  []string `cbor:"encryption,omitempty"`
}

// ToEntity creates a system/protocol/connect/hello entity.
func (d HelloData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHello, cbor.RawMessage(raw))
}

// HelloDataFromEntity decodes a hello entity's data.
func HelloDataFromEntity(e entity.Entity) (HelloData, error) {
	var d HelloData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HelloData{}, err
	}
	return d, nil
}

// AuthenticateData is the data payload for system/protocol/connect/authenticate.
type AuthenticateData struct {
	PeerID    string `cbor:"peer_id"`
	PublicKey []byte `cbor:"public_key"`
	KeyType   string `cbor:"key_type"`
	Nonce     []byte `cbor:"nonce"`
}

// ToEntity creates a system/protocol/connect/authenticate entity.
func (d AuthenticateData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeAuthenticate, cbor.RawMessage(raw))
}

// AuthenticateDataFromEntity decodes an authenticate entity's data.
func AuthenticateDataFromEntity(e entity.Entity) (AuthenticateData, error) {
	var d AuthenticateData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return AuthenticateData{}, err
	}
	return d, nil
}

// ResourceTarget specifies which resources an EXECUTE targets.
type ResourceTarget struct {
	Targets []string `cbor:"targets"`
	Exclude []string `cbor:"exclude,omitempty"`
}

// ExecuteData is the data payload for system/protocol/execute.
type ExecuteData struct {
	RequestID    string          `cbor:"request_id"`
	URI          string          `cbor:"uri"`
	Operation    string          `cbor:"operation"`
	Resource     *ResourceTarget `cbor:"resource,omitempty"`
	Params       cbor.RawMessage `cbor:"params"`
	Bounds       *BoundsData     `cbor:"bounds,omitempty"`
	Author       hash.Hash       `cbor:"author,omitzero"`
	Capability   hash.Hash       `cbor:"capability,omitzero"`
	DeliverTo    *DeliverySpec   `cbor:"deliver_to,omitempty"`
	DeliverToken hash.Hash       `cbor:"deliver_token,omitzero"`
	// DurabilityRequest is the optional request-side durability marker
	// (EXTENSION-DURABILITY §2 — exploratory extension extracted from
	// EXTENSION-INBOX §10). Independent of DeliverTo/DeliverToken.
	DurabilityRequest *DurabilityRequestData `cbor:"durability_request,omitempty"`
}

// ToEntity creates a system/protocol/execute entity.
func (d ExecuteData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeExecute, cbor.RawMessage(raw))
}

// ExecuteDataFromEntity decodes an execute entity's data.
func ExecuteDataFromEntity(e entity.Entity) (ExecuteData, error) {
	var d ExecuteData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ExecuteData{}, err
	}
	return d, nil
}

// ExecuteResponseData is the data payload for system/protocol/execute/response.
type ExecuteResponseData struct {
	RequestID string          `cbor:"request_id"`
	Status    uint            `cbor:"status"`
	Result    cbor.RawMessage `cbor:"result"`
	// Durability is the optional response durability verdict
	// (EXTENSION-DURABILITY §5 — exploratory extension). Additive:
	// durability-unaware consumers are unaffected.
	Durability *DurabilityResultData `cbor:"durability,omitempty"`
}

// ToEntity creates a system/protocol/execute/response entity.
func (d ExecuteResponseData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeExecuteResponse, cbor.RawMessage(raw))
}

// ExecuteResponseDataFromEntity decodes an execute response entity's data.
func ExecuteResponseDataFromEntity(e entity.Entity) (ExecuteResponseData, error) {
	var d ExecuteResponseData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ExecuteResponseData{}, err
	}
	return d, nil
}

// ErrorData is the data payload for system/protocol/error.
//
// RejectedMarker carries the content hash of a receiver-side chain-error
// rejected marker per EXTENSION-CONTINUATION v1.20 §3.10.4 mirror-pointer
// pattern. When the receiver binds a `rejected` chain-error marker (cap-
// rejected inbound chain dispatch), it SHOULD populate this field on the
// outgoing 403 response so the sender can bind a corresponding `lost`
// marker referencing the receiver-side marker hash. Additive, backward-
// compatible — absence is conformant; cross-peer audit walking the pair
// is best-effort.
type ErrorData struct {
	Code           string    `cbor:"code"`
	Message        string    `cbor:"message,omitempty"`
	RejectedMarker hash.Hash `cbor:"rejected_marker,omitzero"`
}

// ToEntity creates a system/protocol/error entity.
func (d ErrorData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeError, cbor.RawMessage(raw))
}

// ErrorDataFromEntity decodes an error entity's data.
func ErrorDataFromEntity(e entity.Entity) (ErrorData, error) {
	var d ErrorData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ErrorData{}, err
	}
	return d, nil
}
