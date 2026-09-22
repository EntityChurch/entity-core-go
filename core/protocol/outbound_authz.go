package protocol

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// authorizeOutboundSubdispatch implements PD-2 (ENTITY-CORE-PROTOCOL §5.2,
// normative 0.8.2.17): check_permission MUST run before a locally-originated
// sub-dispatch leaves the peer, with all four dimensions applied and
// target_peer = extract_peer(uri, local_peer_id). It returns ("", "", true)
// when the sub-dispatch is authorized; otherwise a (code, message) for a 403.
//
// Which authority the check runs against depends on what the sub-dispatch
// spends (§5.2 "the two cases are different questions"):
//
//   - PRESENTED — a capability minted BY the target peer naming THIS peer as
//     grantee. Its OWN four dimensions authorize the sub-dispatch and the
//     handler's peers scope is not consulted. It MUST verify granter = target,
//     grantee = local, chain validity (§5.5), not-revoked, and coverage; a
//     capability failing any of these is not presented authority and falls
//     back to the ambient arm.
//   - AMBIENT — no presented capability; rides the executing handler's grant.
//     Dimension 4 (peers) binds that grant: a handler whose grant carries no
//     peers scope covering the target cannot sub-dispatch at a foreign peer.
//     This is the escalation the dimension exists to close — the bootstrap
//     grant is a ceiling a caller must not steer past.
//   - ABSENT — no presented capability AND no handler grant. MUST deny (403),
//     the §5.2 three-valued authority case (c).
//
// This is disjoint from §6.2's confused-deputy rule: the presented arm rejects
// the propagated caller_capability (its granter is not the target) and admits
// only a credential the target deliberately minted for this peer.
func (d *Dispatcher) authorizeOutboundSubdispatch(uri, operation string, resource *types.ResourceTarget, presentedCap entity.Entity, includedChain []entity.Entity, ambientGrant entity.Entity) (string, string, bool) {
	targetPeer := capability.ExtractPeer(uri, d.LocalPeerID)
	handlerPattern := entity.ExtractHandlerPath(uri)
	execData := types.ExecuteData{URI: uri, Operation: operation, Resource: resource}

	// Presented arm. Any failure falls through to ambient (a cap that is not
	// target-minted authority is treated as absent, not as a hard denial).
	if presentedCap.Type != "" {
		if d.presentedAuthorizes(presentedCap, includedChain, execData, handlerPattern, targetPeer) {
			return "", "", true
		}
	}

	// Absent authority: no presented cap survived and no handler grant.
	if ambientGrant.Type == "" {
		return "capability_denied", fmt.Sprintf(
			"outbound sub-dispatch to peer %s refused: no target-minted capability presented and the executing handler holds no grant (§5.2 absent authority)",
			targetPeer), false
	}

	// Ambient arm: the executing handler's grant, Dimension 4 binding.
	capData, err := types.CapabilityTokenDataFromEntity(ambientGrant)
	if err != nil {
		return "capability_denied", "outbound sub-dispatch: decode handler grant: " + err.Error(), false
	}
	granterPeerID, gerr := capability.ResolveGranterPeerID(capData.Granter, d.Store, d.LocalPeerID)
	if gerr != nil {
		return "capability_denied", "outbound sub-dispatch: handler-grant granter unresolvable: " + gerr.Error(), false
	}
	if !capability.CheckPermission(execData, capData, handlerPattern, d.LocalPeerID, granterPeerID) {
		return "capability_denied", fmt.Sprintf(
			"outbound sub-dispatch to peer %s not authorized by the executing handler's grant (§5.2 — the handler's grant does not scope this operation/handler/peer; a handler with no peers scope covering the target cannot reach a foreign peer)",
			targetPeer), false
	}
	return "", "", true
}

// presentedAuthorizes reports whether presentedCap is valid presented authority
// for the sub-dispatch (§5.2 presented arm). It verifies, in order: grantee =
// local peer, granter = target peer, chain validity (root granter = target),
// not-revoked, and that the capability's own four dimensions cover the request.
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
