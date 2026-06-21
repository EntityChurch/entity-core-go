package types

import (
	"encoding/hex"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// TypePeerSession is the R6 per-peer session entity — the durable per-peer
// AUTH record, sole answer to §10 dispatch's "do I already hold a valid
// capability to talk to this peer, or must I re-handshake?" Shape pinned by
// PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §9
// (Architecture rulings, commit 523cdc5):
//
//   - One path per peer: /{local_peer_id}/system/peer/session/{remote_peer_id}.
//   - Two cap fields on a single entity (§9.1 R6-a, Option A — Go's lean):
//     * held_capability — the cap remote granted me. Dispatch reads this.
//     * minted_capability (optional) — the cap I issued to remote.
//       Granter-side R3a idempotency anchor + revocation surface. NOT a
//       reverse-delivery cap (§9.1 R6-a reconciliation): back-direction
//       delivery still uses deliver_token, unchanged.
//   - DROPPED vs strawman: last_active (§9.1 R6-b — was liveness duplicating
//     system/peer/status.last_seen) and status (§9.1 R6-c — was lifecycle
//     duplicating system/peer/status, source of go/rust-vs-python divergence).
//
// In a bidirectional pair, the same cap-entity hash appears as A's
// minted_capability for B and B's held_capability from A. One cap, recorded
// from both ends. Each end keeps its own entity in its own tree.
//
// Grants-change on re-handshake: mint fresh + overwrite the held/minted
// hash in place (§9.1 R6-e). One entity per peer, mutable.
const TypePeerSession = "system/peer/session"

// SessionCapability is the cap-holding block of the session entity.
//
// Hash is the cap entity's content hash. Chain is the cap's authority
// chain as system/hash pointers, ordered leaf → root, length ≥ 1
// (§9.1 R6-d). Resolved via the content store at reuse — entities are
// not inlined (content-store-dedup model).
type SessionCapability struct {
	Hash  hash.Hash   `cbor:"hash"`
	Chain []hash.Hash `cbor:"chain"`
}

// SessionData is the §9.3 minimal session-entity schema.
//
// MintedCapability is a pointer so it serializes as omitempty when the
// session was only ever a dialer (we have a held cap but never minted
// one for this remote). Likewise the dialer's view of a brand-new remote
// has HeldCapability populated and MintedCapability nil.
type SessionData struct {
	RemotePeerID       string             `cbor:"remote_peer_id"`
	RemoteIdentityHash hash.Hash          `cbor:"remote_identity_hash"`
	RemotePublicKey    []byte             `cbor:"remote_public_key,omitempty"`
	HeldCapability     *SessionCapability `cbor:"held_capability,omitempty"`
	MintedCapability   *SessionCapability `cbor:"minted_capability,omitempty"`
	GrantedAt          uint64             `cbor:"granted_at"`
	ExpiresAt          uint64             `cbor:"expires_at,omitempty"`
}

// ToEntity creates a system/peer/session entity.
func (d SessionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypePeerSession, cbor.RawMessage(raw))
}

// SessionDataFromEntity decodes a system/peer/session entity's data.
func SessionDataFromEntity(e entity.Entity) (SessionData, error) {
	var d SessionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return SessionData{}, err
	}
	return d, nil
}

// SessionPath returns the single canonical session-entity path
// (§9.1 R6-a: one entity per peer, two cap fields).
//
//	/{local_peer_id}/system/peer/session/{remote_peer_id_hex}
//
// The leading `/{local_peer_id}/` is the universal-tree-root form (Base58 per
// V7 §1.4 positional rule). The `{remote_peer_id_hex}` non-root segment is the
// lowercase hex of the remote peer's `system/peer` content_hash (V7.64
// path-encoding alignment).
//
// Both dialer (held_capability) and granter (minted_capability) write to
// this path; the writer reads any existing session entity first and
// preserves the field it isn't touching.
func SessionPath(localPeerID string, remoteIdentityHash hash.Hash) string {
	return "/" + localPeerID + "/" + TypePeerSession + "/" + hex.EncodeToString(remoteIdentityHash.Bytes())
}
