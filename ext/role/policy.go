package role

import (
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
)

// EXTENSION-ROLE §4.7 / RA-6 — initial-grant policy and the AUTHENTICATE-
// time grant resolver.
//
// The deployment configures `system/role/initial-grant-policy` to control
// how unknown peers (peers with no explicit role assignment) are handled
// at AUTHENTICATE. Three modes:
//
//   anonymous-deny          (default; closed network)
//   anonymous-allow         (public-facing; everyone gets default_role)
//   recognize-on-attestation (identity-aware; only peers with a recognized
//                             agent-cert chain get default_role)
//
// This file provides:
//
//   - ReadInitialGrantPolicy: read the policy entity from the local tree;
//     returns sensible defaults (deny) when the entity isn't bound.
//
//   - GrantResolverFromPolicy: build a protocol.GrantResolver-compatible
//     closure that consults the policy at AUTHENTICATE time and returns
//     the connection cap's grants. Wired into the connect handler via
//     core/peer/builder.go's WithGrantResolver option.
//
//   - RecognizeIdentityCert: the recognize-on-attestation predicate.
//     Walks the local attestation index for a live agent-cert targeting
//     the connecting peer's identity hash, then verifies the agent cert's
//     attesting chain terminates at a controller cert signed by a quorum
//     listed in `system/identity/peer-config.trusts_quorum`.
//
// The resolver does NOT synthesize role:assign / mint role-derived caps
// in the role-derived storage path. The connection cap returned at
// AUTHENTICATE is itself a v2.0-shaped root cap (granter=local peer,
// grantee=remote, parent=nil) carrying the default_role's grants. This
// matches EXTENSION-ROLE.md §7.2 + §1027–1049 ("default_role names the
// role; mode governs whether default role is issued") — the role's
// grants drive the connection cap, not a separate role-derived binding.
// Layer-1 exclusion does NOT cascade to such connection caps; deployments
// wanting that semantic explicitly assign role-derived caps via :assign.

// PolicyDefault is the in-memory default returned when the policy entity
// isn't bound on the local tree. Per §4.7 the protocol default is
// `unknown_peer: "anonymous-deny"` with no `default_role`.
func PolicyDefault() types.RoleInitialGrantPolicyData {
	return types.RoleInitialGrantPolicyData{
		UnknownPeer: types.InitialGrantModeDeny,
	}
}

// ReadInitialGrantPolicy returns the deployment's initial-grant policy
// from the local tree, or PolicyDefault() if the policy entity isn't
// bound or fails to decode. The caller MAY treat decode failure as
// configuration drift and log a warning — the resolver itself fails
// closed (defaults to deny) in that case.
func ReadInitialGrantPolicy(cs store.ContentStore, li store.LocationIndex) (types.RoleInitialGrantPolicyData, bool) {
	h, ok := li.Get(initialGrantPolicyPath)
	if !ok {
		return PolicyDefault(), false
	}
	ent, ok := cs.Get(h)
	if !ok {
		return PolicyDefault(), false
	}
	policy, err := types.RoleInitialGrantPolicyDataFromEntity(ent)
	if err != nil {
		return PolicyDefault(), false
	}
	return policy, true
}

// ReadRoleDefinition returns the role-definition entity at the standard
// path system/role/{context}/{role_name}. Returns the decoded RoleData
// + the role-def entity hash + ok=true on success.
func ReadRoleDefinition(cs store.ContentStore, li store.LocationIndex, context, roleName string) (types.RoleData, hash.Hash, bool) {
	path := RoleDefinitionPath(context, roleName)
	h, ok := li.Get(path)
	if !ok {
		return types.RoleData{}, hash.Hash{}, false
	}
	ent, ok := cs.Get(h)
	if !ok {
		return types.RoleData{}, hash.Hash{}, false
	}
	roleDef, err := types.RoleDataFromEntity(ent)
	if err != nil {
		return types.RoleData{}, hash.Hash{}, false
	}
	return roleDef, h, true
}

// RecognizeIdentityCert walks the local attestation graph looking for a
// LIVE agent-cert (function=agent, kind=identity-cert) whose `attested`
// equals the connecting peer's identity-entity hash. If found, walks the
// agent-cert's `attesting` chain looking for a live controller-cert
// (function=controller) signed by a quorum listed in the local peer's
// peer-config.trusts_quorum.
//
// Returns (recognized=true, controllerCertHash) when the chain
// terminates at a recognized controller. Returns (false, zero-hash)
// otherwise.
//
// The recognition predicate filters by attestation properties; it does
// NOT verify K-of-N signatures on the controller cert itself — that
// validation is the substrate's job at controller-cert ingestion. By
// the time the cert is in our local attestation index AND its
// `attesting` matches our trusts_quorum, the controller cert is
// considered recognized.
//
// `asOfMillis` is the time-bound for liveness checks (typically
// nowMillis()); attestations expired at that time don't count as live.
func RecognizeIdentityCert(
	cs store.ContentStore,
	li store.LocationIndex,
	idx *attestation.Index,
	connectingPeerHash hash.Hash,
	asOfMillis uint64,
) (bool, hash.Hash) {
	// Read peer-config.trusts_quorum — the recognition root. Without a
	// configured trusts_quorum, the deployment hasn't installed identity
	// (Stage-1); recognize-on-attestation degenerates to "no recognition
	// possible" and the resolver falls back per policy.
	trustedQuorum, ok := readTrustedQuorum(cs, li)
	if !ok {
		return false, hash.Hash{}
	}

	// Step 1 — find live agent-certs targeting the connecting peer.
	agentCerts := attestation.FindAttestationsTargeting(cs, idx, connectingPeerHash, agentCertPredicate)
	for _, ac := range agentCerts {
		if !attestation.IsAttestationLive(cs, li, idx, ac.Hash, ac.Data, asOfMillis) {
			continue
		}
		// Step 2 — does this agent-cert's `attesting` resolve to a live
		// controller-cert under our trusted quorum?
		if recognized, ctrlHash := walkToTrustedController(cs, li, idx, ac.Data.Attesting, trustedQuorum, asOfMillis, attestation.DefaultMaxChainDepth); recognized {
			return true, ctrlHash
		}
	}
	return false, hash.Hash{}
}

// walkToTrustedController takes a peer-identity hash (the `attesting`
// from an agent-cert, which points to the controller's `system/peer`
// entity hash, NOT a cert hash) and looks for a LIVE controller-cert
// targeting that identity whose own `attesting` equals trustedQuorum.
// Recurses via sub-controller chains (controller A signed by sub-quorum
// signed by trustedQuorum).
//
// Returns (true, controllerCertHash) on match. Bounded by maxDepth.
func walkToTrustedController(
	cs store.ContentStore,
	li store.LocationIndex,
	idx *attestation.Index,
	candidatePeerHash hash.Hash,
	trustedQuorum hash.Hash,
	asOfMillis uint64,
	maxDepth int,
) (bool, hash.Hash) {
	if maxDepth <= 0 || candidatePeerHash.IsZero() {
		return false, hash.Hash{}
	}
	// Find controller-certs targeting this peer.
	controllerCerts := attestation.FindAttestationsTargeting(cs, idx, candidatePeerHash, controllerCertPredicate)
	for _, cert := range controllerCerts {
		if !attestation.IsAttestationLive(cs, li, idx, cert.Hash, cert.Data, asOfMillis) {
			continue
		}
		// Direct: controller-cert is signed by the trusted quorum.
		if cert.Data.Attesting == trustedQuorum {
			return true, cert.Hash
		}
		// Sub-controller: this controller-cert is signed by ANOTHER
		// peer (a parent controller). Recurse — does the parent chain
		// terminate at the trusted quorum?
		if recognized, hit := walkToTrustedController(cs, li, idx, cert.Data.Attesting, trustedQuorum, asOfMillis, maxDepth-1); recognized {
			return true, hit
		}
	}
	return false, hash.Hash{}
}

// controllerCertPredicate matches identity-cert attestations with
// function=controller. Used as the predicate for FindAttestationsTargeting
// when walking up from an agent-cert toward a trusted controller.
func controllerCertPredicate(_ hash.Hash, att types.AttestationData) bool {
	var props types.IdentityCertProperties
	if err := types.DecodeProperties(att.Properties, &props); err != nil {
		return false
	}
	return props.Kind == types.KindIdentityCert && props.Function == types.FunctionController
}

// agentCertPredicate matches identity-cert attestations with
// function=agent. Used as the predicate for FindAttestationsTargeting.
func agentCertPredicate(_ hash.Hash, att types.AttestationData) bool {
	var props types.IdentityCertProperties
	if err := types.DecodeProperties(att.Properties, &props); err != nil {
		return false
	}
	return props.Kind == types.KindIdentityCert && props.Function == types.FunctionAgent
}

// readTrustedQuorum reads peer-config.trusts_quorum from the local tree.
// Returns ok=false if peer-config isn't bound (Stage-1 / unconfigured peer).
func readTrustedQuorum(cs store.ContentStore, li store.LocationIndex) (hash.Hash, bool) {
	const peerConfigPath = "system/identity/peer-config"
	h, ok := li.Get(peerConfigPath)
	if !ok {
		return hash.Hash{}, false
	}
	ent, ok := cs.Get(h)
	if !ok {
		return hash.Hash{}, false
	}
	cfg, err := types.IdentityPeerConfigDataFromEntity(ent)
	if err != nil {
		return hash.Hash{}, false
	}
	if cfg.TrustsQuorum.IsZero() {
		return hash.Hash{}, false
	}
	return cfg.TrustsQuorum, true
}

// PolicyResolverDeps bundles the dependencies the AUTHENTICATE-time
// resolver needs. Constructed at peer startup; the resolver closure
// captures it.
type PolicyResolverDeps struct {
	Store          store.ContentStore
	Locations      store.LocationIndex
	AttestationIdx *attestation.Index
	NowMillis      func() uint64                    // injected for testability
	DebugLog       func(format string, args ...any) // optional debug trace
}

// ResolveGrants is the policy dispatch entry point. Given a connecting
// peer's identity entity, return the grants to embed in their connection
// capability — or nil to fall through to the connect handler's static
// fallback (DefaultConnectionGrants).
//
// Order of checks:
//
//  1. Read policy. If absent or decode-failed → defaults to deny.
//  2. Layer-2 exclusion: if the connecting peer is excluded in the
//     policy's default_context, return nil regardless of mode (per §6.1
//     "Layer 2 fires BEFORE the fallback policy").
//  3. Mode dispatch:
//     - deny  → nil (no grants).
//     - allow → grants from default_role definition.
//     - recognize-on-attestation → recognition predicate; if recognized
//     return default_role grants; if not recognized fall back per
//     IdentityRequired (true → nil, false → grants).
//  4. If default_role isn't defined on the local tree, return nil and
//     log: misconfigured policy (this fails closed rather than minting
//     a phantom cap with empty grants).
func (d PolicyResolverDeps) ResolveGrants(connectingPeerID crypto.PeerID, connectingPeerHash hash.Hash) []types.GrantEntry {
	policy, _ := ReadInitialGrantPolicy(d.Store, d.Locations)

	// Bare keypair handshake: we don't yet know connectingPeerHash if the
	// connect handler couldn't compute it. Guard anyway — zero hash means
	// no exclusion lookup possible (the path encoding requires hash).
	if !connectingPeerHash.IsZero() && policy.DefaultContext != "" {
		if isExcluded(d.Locations, policy.DefaultContext, connectingPeerHash) {
			return nil
		}
	}

	switch policy.UnknownPeer {
	case types.InitialGrantModeDeny:
		return nil
	case types.InitialGrantModeAllow:
		return d.grantsForDefaultRole(policy)
	case types.InitialGrantModeRecognizeOnAttest:
		if d.AttestationIdx == nil {
			// Identity substrate not installed on this peer; recognition
			// not possible. Fall back per identity_required.
			if policy.IdentityRequired {
				return nil
			}
			return d.grantsForDefaultRole(policy)
		}
		recognized, ctrlHash := RecognizeIdentityCert(d.Store, d.Locations, d.AttestationIdx, connectingPeerHash, d.now())
		if d.DebugLog != nil {
			d.DebugLog("role/policy: peer=%s recognized=%v controller=%s default_role=%q",
				connectingPeerID, recognized, ctrlHash, policy.DefaultRole)
		}
		if recognized {
			return d.grantsForDefaultRole(policy)
		}
		if policy.IdentityRequired {
			return nil
		}
		return d.grantsForDefaultRole(policy)
	default:
		// Unknown mode → fail closed.
		return nil
	}
}

func (d PolicyResolverDeps) grantsForDefaultRole(policy types.RoleInitialGrantPolicyData) []types.GrantEntry {
	if policy.DefaultRole == "" || policy.DefaultContext == "" {
		return nil
	}
	roleDef, _, ok := ReadRoleDefinition(d.Store, d.Locations, policy.DefaultContext, policy.DefaultRole)
	if !ok {
		return nil
	}
	// NOTE: template variables in the role's grants ({context}, {peer_id})
	// are resolved at issuance time per §5.2. Connection-cap-time
	// resolution: substitute {context} → policy.DefaultContext, leave
	// {peer_id} for the connect handler to substitute against the
	// remote identity (or skip {peer_id} substitution at this layer —
	// the connection cap's grantee is the remote peer, so {peer_id}
	// would always equal grantee). For now, we return grants verbatim;
	// substitution is a refinement that lands when a role definition
	// uses templates AND the deployment opts into recognize-on-attestation.
	return roleDef.Grants
}

func (d PolicyResolverDeps) now() uint64 {
	if d.NowMillis != nil {
		return d.NowMillis()
	}
	return nowMillis()
}

// publicKeyFromPeerIDForLookup is a placeholder — the connect handler
// computes the connecting peer's identity entity hash directly from the
// AUTHENTICATE envelope's PublicKey. The resolver receives the hash so it
// doesn't have to round-trip through PeerID decoding.
//
// (Documented here for the reader who wonders why the resolver takes a
// hash, not a public-key-derived identity. PeerID is base58 of
// `key_type || hash_type || SHA256(public_key)`; the SHA256 is over the
// raw key, not the PeerData entity, so we cannot derive PeerData hash
// from PeerID alone.)
// ConnectingPeerHashFromIdentity is a small helper for callers that have
// the remote identity entity but not its hash directly.
func ConnectingPeerHashFromIdentity(remote entity.Entity) hash.Hash {
	return remote.ContentHash
}

// GrantResolverFunc matches core/protocol.GrantResolver. Replicated as
// an unexported alias to keep this file independent of the protocol
// package (avoids the ext/role → core/protocol dependency edge that
// would tangle the module graph).
type GrantResolverFunc func(remotePeerID crypto.PeerID, remoteIdentityHash hash.Hash) []types.GrantEntry

// NewPolicyGrantResolver returns a GrantResolverFunc that consults the
// initial-grant policy + role definitions. Designed to be composed with
// other resolvers (static grants from grants.toml, etc.) — see
// ChainGrantResolvers for the typical wiring.
func NewPolicyGrantResolver(deps PolicyResolverDeps) GrantResolverFunc {
	return func(remotePeerID crypto.PeerID, remoteIdentityHash hash.Hash) []types.GrantEntry {
		return deps.ResolveGrants(remotePeerID, remoteIdentityHash)
	}
}

// ChainGrantResolvers returns a resolver that calls each child resolver
// in order, returning the first non-nil result. Returns nil when all
// children return nil (the connect handler then falls through to its
// static connectionGrants / DefaultConnectionGrants).
//
// Typical composition: static grants (per-peer-ID overrides from
// grants.toml) FIRST, then the role-policy resolver. This way explicit
// per-peer overrides win over the policy's default_role; unconfigured
// peers fall through to the policy's mode dispatch.
func ChainGrantResolvers(resolvers ...GrantResolverFunc) GrantResolverFunc {
	return func(remotePeerID crypto.PeerID, remoteIdentityHash hash.Hash) []types.GrantEntry {
		for _, r := range resolvers {
			if r == nil {
				continue
			}
			if grants := r(remotePeerID, remoteIdentityHash); grants != nil {
				return grants
			}
		}
		return nil
	}
}
