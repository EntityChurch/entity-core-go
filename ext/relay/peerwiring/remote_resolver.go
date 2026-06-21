package peerwiring

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// RemoteTreeInboxRelayResolver reads §3.5 inbox-relay declarations from
// a remote peer's tree (the REGISTRY primary holder per §3.5, or any
// secondary holder that serves the canonical path). For each lookup it
// issues `system/tree:get` to one or more configured registry peers in
// order; the first verifying decl wins. All forged-redirection defenses
// from the local-tree resolver are repeated here — the response is
// returned only if the V7 §5.2 signature verifies against the destination
// peer-id.
//
// The resolver does not depend on any particular REGISTRY binding shape.
// It expects the registry peer to expose the same canonical path
// `system/peer/inbox-relay/{dest_peer_id}` + `system/signature/{decl_hash}`
// in its tree as the local-tree resolver does. Per spec §3.5 the
// REGISTRY is named as the primary HOLDER (not as a binding-shape), so
// any registry-substrate impl that exposes the standard tree under
// REGISTRY's namespace satisfies this contract.
//
// Use composed with the local-tree resolver via ChainedInboxRelayResolver
// to honor the §3.5 "REGISTRY primary, secondary holders may serve too"
// arrangement:
//
//	peer.WithRelayInboxRelayResolver(peerwiring.Chain(
//	    peerwiring.NewRemoteTreeInboxRelayResolver(p, registryPeerIDs...),
//	    peerwiring.NewTreeInboxRelayResolver(p),
//	))
type RemoteTreeInboxRelayResolver struct {
	peer        *peer.Peer
	registryIDs []string
	// timeout bounds each per-registry remote tree:get round-trip so a
	// slow/unreachable registry can't stall the relay handler. The full
	// chain may pay (len(registryIDs) × timeout) in the worst case.
	timeout time.Duration
}

// NewRemoteTreeInboxRelayResolver wires a remote-tree resolver to *peer.Peer
// targeting one or more registry peers (consulted in the given order).
// Default per-call timeout: 3 seconds.
func NewRemoteTreeInboxRelayResolver(p *peer.Peer, registryPeerIDs ...string) *RemoteTreeInboxRelayResolver {
	return &RemoteTreeInboxRelayResolver{
		peer:        p,
		registryIDs: append([]string(nil), registryPeerIDs...),
		timeout:     3 * time.Second,
	}
}

// SetTimeout overrides the per-call remote tree:get timeout.
func (r *RemoteTreeInboxRelayResolver) SetTimeout(d time.Duration) {
	if d > 0 {
		r.timeout = d
	}
}

var _ relay.InboxRelayResolver = (*RemoteTreeInboxRelayResolver)(nil)

// Resolve walks the configured registry chain in order; returns the first
// decl that passes V7 §5.2 verification, or (_, false) if none match.
func (r *RemoteTreeInboxRelayResolver) Resolve(destinationPeerID string) (types.InboxRelayData, bool) {
	if destinationPeerID == "" || len(r.registryIDs) == 0 {
		return types.InboxRelayData{}, false
	}
	for _, regID := range r.registryIDs {
		if decl, ok := r.resolveFrom(regID, destinationPeerID); ok {
			return decl, true
		}
	}
	return types.InboxRelayData{}, false
}

func (r *RemoteTreeInboxRelayResolver) resolveFrom(registryPeerID, destinationPeerID string) (types.InboxRelayData, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	// 1) Fetch the decl entity from the registry's tree at the canonical
	//    path. Peer-relative form — the registry namespaces it under its
	//    own peer-id.
	declPath := types.InboxRelayStoragePath(destinationPeerID)
	declEnt, err := r.fetchTree(ctx, registryPeerID, declPath)
	if err != nil {
		return types.InboxRelayData{}, false
	}
	if declEnt.Type != types.TypePeerInboxRelay {
		return types.InboxRelayData{}, false
	}
	decl, err := types.InboxRelayDataFromEntity(declEnt)
	if err != nil {
		return types.InboxRelayData{}, false
	}

	// 2) Fetch the V7 §5.2 signature for the decl from the registry's
	//    tree. Same convention as the local-tree resolver:
	//    system/signature/{decl_hash_hex}.
	sigPath := "system/signature/" + hex.EncodeToString(declEnt.ContentHash.Bytes())
	sigEnt, err := r.fetchTree(ctx, registryPeerID, sigPath)
	if err != nil {
		return types.InboxRelayData{}, false
	}
	sigData, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return types.InboxRelayData{}, false
	}
	if sigData.Target != declEnt.ContentHash {
		return types.InboxRelayData{}, false
	}

	// 3) Derive the destination's (public_key, key_type) from the peer-id
	//    multihash. Falls closed on SHA-256-form peer-ids (v7.67) without
	//    a stashed system/peer entity — same posture as the local-tree
	//    resolver.
	pub, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(destinationPeerID))
	if !ok {
		return types.InboxRelayData{}, false
	}

	// 4) Signer hash MUST equal the destination's canonical identity
	//    hash — forged-redirection defense (the registry could have
	//    served a decl signed by a look-alike peer).
	destHash, err := types.ComputePeerIdentityHash(pub, keyType)
	if err != nil {
		return types.InboxRelayData{}, false
	}
	if sigData.Signer != destHash {
		return types.InboxRelayData{}, false
	}

	// 5) V7 §5.2 fail-closed signature verification.
	if !crypto.Verify(keyType, pub, declEnt.ContentHash.Bytes(), sigData.Signature) {
		return types.InboxRelayData{}, false
	}

	return decl, true
}

func (r *RemoteTreeInboxRelayResolver) fetchTree(ctx context.Context, registryPeerID, path string) (entity.Entity, error) {
	params, resource, err := tree.CreateGetRequest(path, "entity")
	if err != nil {
		return entity.Entity{}, err
	}
	uri := "entity://" + registryPeerID + "/system/tree"
	resp, err := r.peer.RemoteExecute(ctx, uri, "get", params, resource)
	if err != nil {
		return entity.Entity{}, err
	}
	if resp.Status != 200 {
		return entity.Entity{}, fmt.Errorf("tree get %s on %s: status %d", path, registryPeerID, resp.Status)
	}
	return resp.Result, nil
}

// ChainedInboxRelayResolver tries each composed resolver in order and
// returns the first verified decl. Empty chain = "no declaration known"
// (equivalent to NopInboxRelayResolver).
//
// Use the Chain() helper to construct.
type ChainedInboxRelayResolver struct {
	resolvers []relay.InboxRelayResolver
}

// Chain returns a resolver that walks its children in order. Skipped if
// no children. Per spec §3.5 the recommended order is
// (REGISTRY-served, local-tree-fallback).
func Chain(resolvers ...relay.InboxRelayResolver) *ChainedInboxRelayResolver {
	return &ChainedInboxRelayResolver{
		resolvers: append([]relay.InboxRelayResolver(nil), resolvers...),
	}
}

var _ relay.InboxRelayResolver = (*ChainedInboxRelayResolver)(nil)

func (c *ChainedInboxRelayResolver) Resolve(destinationPeerID string) (types.InboxRelayData, bool) {
	for _, r := range c.resolvers {
		if r == nil {
			continue
		}
		if decl, ok := r.Resolve(destinationPeerID); ok {
			return decl, true
		}
	}
	return types.InboxRelayData{}, false
}
