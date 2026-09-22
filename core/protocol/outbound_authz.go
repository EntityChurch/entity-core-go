package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// authorizeOutboundSubdispatch implements the §6.8 / §5.2 dispatch gate for a
// locally-originated sub-dispatch, as corrected by 0.8.2.19 (Delta E1, the
// confused-deputy fix F67). It runs before the sub-dispatch leaves the peer and
// returns ("", "", true) when authorized; otherwise a (code, message) for a 403.
//
// ONE GATE, ONE EXEMPTION (ENTITY-CORE-PROTOCOL §1.4 line 315):
//
//	The executing handler's grant is the gate, on all four dimensions (§6.8
//	Level 1). A valid credential minted BY the target peer relaxes Dimension 4
//	(peers) — and only Dimension 4 — to the peers that credential covers, and
//	must additionally authorize the request on its own four dimensions. The
//	target answers WHERE; the handler's grant still answers WHAT.
//
// So the three authority states are:
//
//   - HANDLER GRANT ALONE (no valid credential) — Dimensions 1-4 all decided by
//     the executing handler's grant. A handler whose grant carries no peers
//     scope covering the target cannot reach a foreign peer. This is the
//     escalation Dimension 4 exists to close — the bootstrap grant is a ceiling
//     a caller must not steer past.
//   - HANDLER GRANT + TARGET-MINTED CREDENTIAL — Dimensions 1-3 still decided by
//     the handler grant; Dimension 4 (peers) relaxed to the target the
//     credential covers. The credential answers only WHERE the dispatch may go;
//     the handler's grant still answers WHAT it may do there.
//   - ABSENT — no handler grant at all. MUST deny (403). A target-minted
//     credential relaxes ONE dimension of a grant; it is NOT a grant, so it
//     cannot supply Dimensions 1-3 on its own. This is the heart of F67: a
//     credential is never a standalone authorizer.
//
// Why this is the confused-deputy fix. The presented credential arrives as a
// caller-supplied parameter (execOpts.Capability, from the scaffold's dispatch
// params). Before E1 a valid credential authorized the sub-dispatch on its own
// four dimensions, with the handler's grant never consulted — so a caller
// holding any target→this-peer capability could steer ANY handler past its own
// grant, using this peer as a deputy. E1 makes the handler grant the
// unconditional gate on what the dispatch may do, so the credential can only
// widen WHERE, never WHAT (§6.8; EXTENSION-CONTINUATION §3.6b Level-1/Level-2).
//
// It is disjoint from §6.2's confused-deputy rule on the caller_capability: the
// presented credential's chain ROOT must be the target (verifyRootGranter), so
// a propagated caller_capability rooted elsewhere does not relax Dimension 4 and
// the handler grant gates unrelaxed.
func (d *Dispatcher) authorizeOutboundSubdispatch(uri, operation string, resource *types.ResourceTarget, presentedCap entity.Entity, includedChain []entity.Entity, ambientGrant entity.Entity) (string, string, bool) {
	targetPeer := capability.ExtractPeer(uri, d.LocalPeerID)
	handlerPattern := entity.ExtractHandlerPath(uri)
	execData := types.ExecuteData{URI: uri, Operation: operation, Resource: resource}

	// Does a valid target-minted credential authorize reaching this target? If
	// so it relaxes Dimension 4 (peers) ONLY — it does NOT short-circuit the
	// gate and does NOT supply Dimensions 1-3. A credential failing any check
	// (not target-rooted, wrong grantee, revoked, out of its own scope) simply
	// does not relax anything; the handler grant then gates unrelaxed.
	relaxPeers := presentedCap.Type != "" &&
		d.presentedAuthorizes(presentedCap, includedChain, execData, handlerPattern, targetPeer)

	// The gate is the executing handler's grant. With no handler grant there is
	// nothing to authorize Dimensions 1-3, so even a valid credential cannot
	// authorize the sub-dispatch (§5.2 absent authority — a credential relaxes
	// one dimension of a grant, it is not a grant).
	if ambientGrant.Type == "" {
		return "capability_denied", fmt.Sprintf(
			"outbound sub-dispatch to peer %s refused: the executing handler holds no grant to authorize it (§6.8 Level 1 — the handler's grant is the dispatch gate; a target-minted credential relaxes only Dimension 4, it cannot supply the handler grant)",
			targetPeer), false
	}

	capData, err := types.CapabilityTokenDataFromEntity(ambientGrant)
	if err != nil {
		return "capability_denied", "outbound sub-dispatch: decode handler grant: " + err.Error(), false
	}
	granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, d.Store, d.LocalPeerID)
	if gerr != nil {
		return "capability_denied", "outbound sub-dispatch: handler-grant granter unresolvable: " + gerr.Error(), false
	}

	// The handler grant gates all four dimensions; Dimension 4 is relaxed iff a
	// valid target-minted credential covers the target (relaxPeers).
	if !capability.CheckPermissionRelaxPeers(execData, capData, handlerPattern, d.LocalPeerID, granterPeerID, relaxPeers) {
		if relaxPeers {
			// The credential relaxed WHERE, but the handler's own grant does not
			// authorize WHAT. This is exactly the confused-deputy case E1 closes:
			// before E1 the credential alone authorized it.
			return "capability_denied", fmt.Sprintf(
				"outbound sub-dispatch to peer %s refused: a valid target-minted credential relaxed the peers dimension, but the executing handler's grant does not authorize this operation/handler/resource (§6.8 — the handler's grant answers WHAT; a credential answers only WHERE, it cannot widen the handler's operations/handlers/resources)",
				targetPeer), false
		}
		return "capability_denied", fmt.Sprintf(
			"outbound sub-dispatch to peer %s not authorized by the executing handler's grant (§5.2/§6.8 — no target-minted credential relaxes Dimension 4, and the handler grant does not scope this operation/handler/resource/peer; a handler with no peers scope covering the target cannot reach a foreign peer)",
			targetPeer), false
	}
	return "", "", true
}

// presentedAuthorizes reports whether presentedCap is a valid target-minted
// credential that authorizes reaching the target — i.e. whether it relaxes
// Dimension 4 of the handler-grant gate (0.8.2.19 E1). It is NOT a standalone
// authorizer: its TRUE result relaxes only the peers dimension of the executing
// handler's grant (see authorizeOutboundSubdispatch); the handler grant still
// decides operations/handlers/resources. It verifies, in order: grantee =
// local peer, chain validity, chain ROOT is a SINGLE-sig granter == target
// (E3/F66 — a multi-sig K-of-N root that merely includes the target is not the
// target's sole authority and fails closed), not-revoked, and that the
// capability's own four dimensions cover the request.
//
// Coverage is evaluated with the TARGET peer as the local reference, because a
// self-rooted credential minted by the target is spent against the target's
// own namespace: extract_peer(uri) is the target, an absent peers scope
// defaults to {include:[target]} and therefore covers it, and resource
// patterns canonicalize against the target's namespace — mirroring exactly
// what the target itself computes when the request arrives.
func (d *Dispatcher) presentedAuthorizes(capEnt entity.Entity, includedChain []entity.Entity, execData types.ExecuteData, handlerPattern string, targetPeer crypto.PeerID) bool {
	capData, err := types.CapabilityTokenDataFromEntity(capEnt)
	if err != nil {
		return false
	}

	// Build the included map: the chain the caller carried in-band (granter
	// identity + signatures), the presented cap itself, and this peer's own
	// identity so the grantee resolves during chain validation.
	included := make(map[hash.Hash]entity.Entity, len(includedChain)+2)
	for _, e := range includedChain {
		included[e.ContentHash] = e
	}
	included[capEnt.ContentHash] = capEnt
	if localIdent, ok := d.Store.Get(d.LocalIdentityHash); ok {
		included[d.LocalIdentityHash] = localIdent
	}

	// grantee = local peer (§5.2). A cap not naming this peer as grantee is not
	// presented authority FOR this peer.
	if capData.Grantee != d.LocalIdentityHash {
		return false
	}

	// granter = target peer (§3.6) AND chain validity (§5.5), in one step.
	// "Minted by the target" is a property of the chain ROOT, not the leaf: a
	// re-attenuated credential (EXTENSION-CONTINUATION §4.2 case 3 — rooted at
	// the target, delegated down to a leaf granted to this peer) is still a
	// credential the target minted. VerifyChain with the target as the local
	// reference enforces exactly that — verifyRootGranter requires the chain's
	// ROOT granter to equal the passed peer — while also checking signatures,
	// temporal validity, linkage and attenuation. This is also what rejects the
	// confused-deputy caller_capability (§6.2/§6.20): a cap rooted at a peer
	// other than the target fails the root-granter check here and falls back to
	// the ambient arm.
	if err := capability.VerifyChain(capEnt, included, targetPeer); err != nil {
		return false
	}

	// E3 / F66 (0.8.2.19, fail-closed): "minted BY the target peer" (D1) means
	// the target SOLELY minted the credential — a single-sig chain ROOT whose
	// granter is the target. A multi-sig (K-of-N) root that merely INCLUDES the
	// target as one signer is NOT the target's sole authority (the co-signers
	// authorized it too), so it MUST NOT relax Dimension 4. VerifyChain's M6
	// (verifyRootGranter) accepts such a root when the frame peer is a signer —
	// correct for a peer participating in its OWN group root, but an
	// over-acceptance HERE, where the frame is the TARGET: a K-of-2 credential
	// merely including the target would relax. Reject at the gate (rust and py
	// fix the same place, not in M6). This was a LIVE over-acceptance the
	// cross-impl audit caught; go had it identically until this landed.
	chain, cerr := capability.CollectAuthorityChain(capEnt, capability.IncludedResolver(included))
	if cerr != nil || len(chain) == 0 {
		return false
	}
	rootData, rerr := types.CapabilityTokenDataFromEntity(chain[len(chain)-1])
	if rerr != nil {
		return false
	}
	if rootData.Granter.IsMulti() {
		return false
	}

	// The leaf cap's own granter peer_id, for PR-8 resource-pattern
	// canonicalization in the coverage check below (each cap's resources
	// canonicalize against ITS OWN granter's namespace, §5.5) — this is the
	// leaf delegator, not necessarily the target.
	leafGranterPeerID, gerr := capability.ResolveGranterPeerIDFromIncluded(capData.Granter, included, d.LocalPeerID)
	if gerr != nil {
		return false
	}

	// Not revoked (§6.2 Capability validity).
	if capability.IsRevoked(capEnt, capability.RevocationContext{
		ContentStore:    d.Store,
		LocationIndex:   d.LocationIndex,
		Included:        included,
		CapabilityIndex: d.CapabilityIndex,
	}) {
		return false
	}

	// Coverage: the cap's own four dimensions authorize the request. The peers
	// dimension and extract_peer use the TARGET as the local reference (a
	// self-rooted cap's absent peers scope defaults to {target} and therefore
	// covers it — mirroring what the target computes on receipt); resource
	// patterns canonicalize against the LEAF granter's namespace (PR-8).
	return capability.CheckPermission(execData, capData, handlerPattern, targetPeer, leafGranterPeerID)
}
