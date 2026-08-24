package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// WriteConnectionState writes the §3.13 system/connection entity for a
// remote peer at /{local}/system/connection/{remote_hex} (Amendment 12
// rung-1 ruling C: MUST at full NETWORK conformance, NOT in the §A3
// liveness floor).
//
// Write-on-transition ONLY: establish (status "active") and close/failure
// (status "closed") — §3.13 pins the discipline precisely so this surface
// never becomes a per-activity write amplifier. data.PeerID must be the
// remote's Base58 peer-id.
func WriteConnectionState(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
	data types.ConnectionData,
) (hash.Hash, error) {
	// Same guards as WritePeerStatus: no self-entry, and the hex path key
	// requires a resolvable remote identity hash.
	if data.PeerID == localPeerID {
		return hash.Hash{}, nil
	}
	if remoteIdentityHash.IsZero() {
		return hash.Hash{}, fmt.Errorf("WriteConnectionState: remoteIdentityHash is zero (path key required); derive via ResolveRemoteIdentityHash")
	}
	ent, err := data.ToEntity()
	if err != nil {
		return hash.Hash{}, fmt.Errorf("connection-state encode: %w", err)
	}
	h, err := cs.Put(ent)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("connection-state store: %w", err)
	}
	if err := li.Set(types.ConnectionPath(localPeerID, remoteIdentityHash), h); err != nil {
		return hash.Hash{}, fmt.Errorf("connection-state bind: %w", err)
	}
	return h, nil
}

// MarkConnectionClosed is the close/failure transition (§3.13 "updated on
// close or failure"): read-modify-write the existing connection entity to
// status "closed", preserving transport/address/established_at so the
// closed record still answers "how WAS I attached". A missing entity is a
// no-op false — nothing was recorded at establish (e.g. a §6.11 reentry
// binding whose dialer is the remote), so there is no transition to record.
func MarkConnectionClosed(
	cs store.ContentStore,
	li store.LocationIndex,
	localPeerID string,
	remoteIdentityHash hash.Hash,
) (bool, error) {
	h, ok := li.Get(types.ConnectionPath(localPeerID, remoteIdentityHash))
	if !ok {
		return false, nil
	}
	ent, ok := cs.Get(h)
	if !ok {
		return false, nil
	}
	data, err := types.ConnectionDataFromEntity(ent)
	if err != nil {
		return false, fmt.Errorf("connection-state decode: %w", err)
	}
	if data.Status == types.ConnectionStatusClosed {
		return true, nil // idempotent under concurrent demotion
	}
	data.Status = types.ConnectionStatusClosed
	_, err = WriteConnectionState(cs, li, localPeerID, remoteIdentityHash, data)
	return err == nil, err
}
