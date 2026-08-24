package types

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypeConnection is the §3.13 operational connection-state entity —
// "how am I attached right now" (transport + address diagnostics), the
// read-on-demand complement to system/peer/status's subscribe-for-liveness
// "is the peer here". Per Amendment 12 rung-1 ruling C: MUST at full NETWORK
// conformance (§12.1), NOT part of the §A3 liveness floor — a consumer of a
// floor-only peer MUST NOT assume this entity exists.
//
// Write discipline is §3.13's write-on-transition: written on connection
// establishment (status "active"), updated on close or failure (status
// "closed") — never per-activity.
const TypeConnection = "system/connection"

// Connection lifecycle values (§3.13 enum).
const (
	ConnectionStatusActive   = "active"
	ConnectionStatusDraining = "draining"
	ConnectionStatusClosed   = "closed"
)

// ConnectionData is the system/connection entity payload (§3.13).
type ConnectionData struct {
	// PeerID is the remote peer's Base58 peer-id string.
	PeerID string `cbor:"peer_id"`
	// Transport is the substrate label: "tcp", "quic", "websocket", ….
	Transport string `cbor:"transport"`
	// Address is the remote endpoint, e.g. "192.168.1.42:4040".
	Address string `cbor:"address"`
	// Status is one of the ConnectionStatus* values.
	Status string `cbor:"status"`
	// EstablishedAt is ms since epoch at establishment.
	EstablishedAt uint64 `cbor:"established_at"`
	// Parameters carries negotiated details (protocol_version, hash_format,
	// compression, encryption) — optional.
	Parameters map[string]any `cbor:"parameters,omitempty"`
}

// ToEntity creates a system/connection entity.
func (d ConnectionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeConnection, cbor.RawMessage(raw))
}

// ConnectionDataFromEntity decodes a system/connection entity's data.
func ConnectionDataFromEntity(e entity.Entity) (ConnectionData, error) {
	var d ConnectionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ConnectionData{}, err
	}
	return d, nil
}

// ConnectionPath returns the canonical connection-entity path:
//
//	/{local_peer_id}/system/connection/{remote_peer_id_hex}
//
// Same path-encoding convention as PeerStatusPath: the non-root segment is
// the lowercase hex of the remote peer's system/peer content_hash (v7.64
// path-encoding alignment).
func ConnectionPath(localPeerID string, remoteIdentityHash hash.Hash) string {
	return "/" + localPeerID + "/" + TypeConnection + "/" + hex.EncodeToString(remoteIdentityHash.Bytes())
}
