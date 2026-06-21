package role

import (
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// resolveGranterOrLocal returns the granter peer_id for a cap, falling back
// to the local peer if the cap has no granter (e.g., synthetic caps used in
// RL2 attenuation checks where the conceptual granter is the caller). The
// IsAttenuated check uses this for both child and parent — synthetic caps
// in role-extension RL2 share the caller's authority frame.
func resolveGranterOrLocal(hctx *handler.HandlerContext, capData types.CapabilityTokenData) crypto.PeerID {
	if capData.Granter.IsZero() {
		return hctx.LocalPeerID
	}
	pid, err := capability.ResolveGranterPeerID(capData.Granter, hctx.Store, hctx.LocalPeerID)
	if err != nil {
		return hctx.LocalPeerID
	}
	return pid
}

// nowMillis returns the current Unix time in milliseconds — the timestamp
// shape used across the spec (assigned_at, excluded_at, created_at).
func nowMillis() uint64 {
	return uint64(time.Now().UnixMilli())
}

// effectiveExpiresAt resolves the expiration to use on a role-derived
// capability token per EXTENSION-ROLE v2.0 §5.3 — MIN_DEFINED over the
// four bound sources (parent, role TTL, caller cap; the handler-policy
// source is collapsed into role TTL for this impl since it has no
// separate handler-policy plumb). Each source is *uint64 with nil
// meaning "no bound from this source"; the result is nil only if all
// three are nil. The conventional formula:
//
//	MIN_DEFINED(parent.expires_at, role.ttl, caller_capability.expires_at)
//
// Both the issued cap's ExpiresAt and the RL2 hypothetical use this
// helper so the attenuation check matches what would actually be minted
// (avoids "RL2 OK at issue, chain-invalid at use" surface — see V7 §5.6
// strict nil-vs-finite check).
func effectiveExpiresAt(parentExpires, roleTTL, callerExpires *uint64) *uint64 {
	var out *uint64
	for _, v := range []*uint64{parentExpires, roleTTL, callerExpires} {
		if v == nil {
			continue
		}
		if out == nil || *v < *out {
			out = v
		}
	}
	return out
}

// parentCapExpires returns the ExpiresAt of the handler-grant cap that
// authorized this dispatch, or nil if the cap is empty or undecodable.
// This is the `parent.expires_at` source in §5.3's MIN_DEFINED formula —
// the parent of the role-derived cap chain.
func parentCapExpires(hctx *handler.HandlerContext) *uint64 {
	if hctx == nil || hctx.HandlerGrant.ContentHash.IsZero() {
		return nil
	}
	data, err := types.CapabilityTokenDataFromEntity(hctx.HandlerGrant)
	if err != nil {
		return nil
	}
	return data.ExpiresAt
}

// roleMetadataTTL extracts the `ttl` field from a role definition's
// opaque metadata blob. Returns nil if metadata is empty, undecodable,
// or has no `ttl` key. The TTL is a convention — RoleData.Metadata is
// cbor.RawMessage to keep the role schema open to domain-specific
// fields; the spec singles out `ttl` as the conventional lifetime hint.
//
// Per §5.3 v2.0, this feeds the role-TTL source of MIN_DEFINED.
func roleMetadataTTL(meta cbor.RawMessage) *uint64 {
	if len(meta) == 0 {
		return nil
	}
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(meta, &m); err != nil {
		return nil
	}
	raw, ok := m["ttl"]
	if !ok {
		return nil
	}
	var ttl uint64
	if err := cbor.Unmarshal(raw, &ttl); err != nil {
		return nil
	}
	return &ttl
}

// isExcluded is the shared exclusion-check helper per §6.2. A single tree
// read against system/role/{context}/excluded/{peer_id_hex}. Called by:
//
//   - Runtime assign (§4.3 step 4b — layer 2 of R7).
//   - Startup-time L0 derivation (§4.5 — phase 7 wires this).
//   - Re-derive cascade (§5.5 — phase 5 wires this).
//
// Implementations MUST share this helper across the role handler, the L0
// path, and any opt-in layer-3 callers (per §6.2).
func isExcluded(li store.LocationIndex, context string, peerHash hash.Hash) bool {
	if li == nil {
		return false
	}
	return li.Has(ExclusionPath(context, peerHash))
}

// resolveTemplates substitutes {context} and {peer_id} in a grant entry's
// path values per §5.2. Template resolution is purely textual — no path
// normalization or validation. The resolved paths are validated as part
// of normal grant verification.
//
// Per v1.6 SI-1: the {peer_id} substitution uses lowercase hex of the
// assignee's system/peer content_hash (same form as the path-segment
// {peer_id_hex}). Earlier drafts used Base58 PeerID — that was wrong;
// every non-root peer reference in the system uses hex of system/hash.
func resolveTemplates(g types.GrantEntry, ctxValue string, peerHash hash.Hash) types.GrantEntry {
	repl := strings.NewReplacer(
		"{context}", ctxValue,
		"{peer_id}", HashHex(peerHash),
	)
	out := types.GrantEntry{
		Handlers:    resolveScope(g.Handlers, repl),
		Resources:   resolveScope(g.Resources, repl),
		Operations:  resolveScope(g.Operations, repl),
		Constraints: g.Constraints,
		Allowances:  g.Allowances,
	}
	if g.Peers != nil {
		s := resolveScope(*g.Peers, repl)
		out.Peers = &s
	}
	return out
}

func resolveScope(s types.CapabilityScope, repl *strings.Replacer) types.CapabilityScope {
	out := types.CapabilityScope{}
	if len(s.Include) > 0 {
		out.Include = make([]string, len(s.Include))
		for i, p := range s.Include {
			out.Include[i] = repl.Replace(p)
		}
	}
	if len(s.Exclude) > 0 {
		out.Exclude = make([]string, len(s.Exclude))
		for i, p := range s.Exclude {
			out.Exclude[i] = repl.Replace(p)
		}
	}
	return out
}

// resolveGrants applies resolveTemplates to a slice of grant entries.
func resolveGrants(grants []types.GrantEntry, ctxValue string, peerHash hash.Hash) []types.GrantEntry {
	out := make([]types.GrantEntry, len(grants))
	for i, g := range grants {
		out[i] = resolveTemplates(g, ctxValue, peerHash)
	}
	return out
}

// loadRoleDefinition reads a role definition from the local index/store.
// Returns (def, true) on success, or (zero, false) if the binding is
// missing or the entity is the wrong type. The path argument is peer-
// relative; NamespacedIndex canonicalizes during the lookup.
func loadRoleDefinition(cs store.ContentStore, li store.LocationIndex, path string) (types.RoleData, bool) {
	if cs == nil || li == nil {
		return types.RoleData{}, false
	}
	h, ok := li.Get(path)
	if !ok {
		return types.RoleData{}, false
	}
	ent, ok := cs.Get(h)
	if !ok || ent.Type != types.TypeRole {
		return types.RoleData{}, false
	}
	def, err := types.RoleDataFromEntity(ent)
	if err != nil {
		return types.RoleData{}, false
	}
	return def, true
}

// loadDerivedTokenLink reads the linkage entity for (peer, role) in
// `context`. Returns (link, true) on success or (zero, false) if no
// linkage exists. Used by re-derive (to find T_old) and delegate (to
// find the parent cap per SI-22).
func loadDerivedTokenLink(cs store.ContentStore, li store.LocationIndex, context string, peerHash hash.Hash, roleName string) (types.RoleDerivedTokenLinkData, bool) {
	if cs == nil || li == nil {
		return types.RoleDerivedTokenLinkData{}, false
	}
	h, ok := li.Get(DerivedTokenLinkPath(context, peerHash, roleName))
	if !ok {
		return types.RoleDerivedTokenLinkData{}, false
	}
	ent, ok := cs.Get(h)
	if !ok || ent.Type != types.TypeRoleDerivedTokenLink {
		return types.RoleDerivedTokenLinkData{}, false
	}
	link, err := types.RoleDerivedTokenLinkDataFromEntity(ent)
	if err != nil {
		return types.RoleDerivedTokenLinkData{}, false
	}
	return link, true
}

// issuedCap is the result of issueRoleDerivedCap: the cap entity, its
// content hash, the storage path the cap was bound at, and the V7 §3.5
// invariant pointer path its signature was bound at (the sole signature
// location for role-derived caps — no sibling copy; see
// issueRoleDerivedCap step 4). Rollback/sweep sites unbind both precisely.
type issuedCap struct {
	CapHash          hash.Hash
	CapPath          string
	SigInvariantPath string
}

// issueRoleDerivedCap creates and persists a role-derived capability
// token per §5.1 + R4 storage path (v1.6). Steps:
//
//  1. Build a CapabilityTokenData with the derived grants. Granter is
//     the local peer's identity (single-sig); grantee is `granteeHash`
//     (the recipient's system/peer content_hash, taken directly from
//     the path segment per SI-8 — no PeerID-to-hash resolution required).
//     Parent points at the handler's grant or the delegator's role-derived
//     cap (per §5.6).
//  2. Encode + put into the content store.
//  3. Bind the cap at system/capability/grants/role-derived/{context}/{peer_id_hex}/{token_hash_hex}.
//  4. Sign the cap's content hash with the local peer's keypair and
//     bind the signature ONLY at the V7 §3.5 invariant pointer path
//     /{signer}/system/signature/{target_hex}. ROLE deliberately does
//     not keep a sibling {capPath}/signature copy: EXTENSION-ROLE pins
//     the cap *storage* path but is silent on the signature path and
//     delegates chain verification to V7 (§ "Identity-entity
//     availability ... is V7's responsibility, not role's"), so V7 §3.5
//     governs and the invariant pointer is the single canonical
//     location. (Contrast EXTENSION-IDENTITY §6.0e/PI-10, which
//     normatively mandates the sibling for controller caps.) v7.44 MUST:
//     a role-derived cap is the B-rooted chain root for cross-peer
//     continuations (EXTENSION-CONTINUATION §4.2 case 3) and must be
//     discoverable to the standard chain-transport collector.
//
// The linkage entity (SI-5) is written separately by callers that
// need it — assign + re-derive call writeRoleDerivedTokenLink after
// this function. Delegate does NOT write linkage (the (C, role)
// linkage slot belongs to C's own assignment, if any; delegation caps
// don't participate in unassign-by-linkage lookup).
func issueRoleDerivedCap(
	hctx *handler.HandlerContext,
	kp crypto.Keypair,
	localIdentity entity.Entity,
	context string,
	granteeHash hash.Hash,
	derivedGrants []types.GrantEntry,
	parent hash.Hash,
	expiresAt *uint64,
) (issuedCap, error) {
	tok := types.CapabilityTokenData{
		Grants:    derivedGrants,
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   granteeHash,
		CreatedAt: nowMillis(),
		ExpiresAt: expiresAt,
	}
	if !parent.IsZero() {
		p := parent
		tok.Parent = &p
	}
	if err := tok.ValidateStructure(); err != nil {
		return issuedCap{}, err
	}
	capEnt, err := tok.ToEntity()
	if err != nil {
		return issuedCap{}, err
	}
	if _, err := hctx.Store.Put(capEnt); err != nil {
		return issuedCap{}, err
	}
	capPath := RoleDerivedTokenPath(context, granteeHash, capEnt.ContentHash)
	if _, err := hctx.TreeSet(capPath, capEnt.ContentHash, "role-derived-cap"); err != nil {
		return issuedCap{}, fmt.Errorf("bind role-derived cap %s: %w", capPath, err)
	}

	// Sign the cap and bind the signature at the V7 §3.5 invariant
	// pointer path only (v7.44 MUST for chain-participating caps; ROLE
	// keeps no sibling copy — see the function doc, step 4).
	sig := kp.Sign(capEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    localIdentity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return issuedCap{}, err
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return issuedCap{}, err
	}
	idData, err := types.PeerDataFromEntity(localIdentity)
	if err != nil {
		return issuedCap{}, fmt.Errorf("resolve local peer_id for invariant signature path: %w", err)
	}
	// v7.65 §1.5: peer_id derives from (public_key, key_type).
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return issuedCap{}, fmt.Errorf("resolve local peer_id: unsupported key_type %q", idData.KeyType)
	}
	localPID, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return issuedCap{}, fmt.Errorf("derive local peer_id: %w", err)
	}
	sigInvariantPath := types.InvariantSignaturePath(string(localPID), capEnt.ContentHash)
	if _, err := hctx.TreeSet(sigInvariantPath, sigEnt.ContentHash, "role-derived-cap-sig"); err != nil {
		return issuedCap{}, fmt.Errorf("bind role-derived cap signature (invariant path): %w", err)
	}

	return issuedCap{
		CapHash:          capEnt.ContentHash,
		CapPath:          capPath,
		SigInvariantPath: sigInvariantPath,
	}, nil
}

// writeRoleDerivedTokenLink writes the (peer, role) linkage entity
// pointing at capHash so unassign / re-derive can locate the cap by
// (peer, role) tuple per SI-5. Called by assign + re-derive; NOT
// called by delegate (delegation caps don't participate in this
// lookup — their lifecycle is governed by chain validation against
// the delegator's parent cap).
func writeRoleDerivedTokenLink(
	hctx *handler.HandlerContext,
	context string,
	peerHash hash.Hash,
	roleName string,
	capHash hash.Hash,
	issuedAt uint64,
) error {
	linkData := types.RoleDerivedTokenLinkData{
		TokenHash: capHash,
		IssuedAt:  issuedAt,
	}
	linkEnt, err := linkData.ToEntity()
	if err != nil {
		return err
	}
	if _, err := hctx.Store.Put(linkEnt); err != nil {
		return err
	}
	if _, err := hctx.TreeSet(DerivedTokenLinkPath(context, peerHash, roleName), linkEnt.ContentHash, "role-derived-token-link"); err != nil {
		return fmt.Errorf("bind role-derived token link: %w", err)
	}
	return nil
}

// roleDerivedCapSigInvariantPath returns the V7 §3.5 invariant pointer
// path the role-derived cap's signature was bound at by
// issueRoleDerivedCap (signer = the local peer; target = capHash). The
// sweeps bind/unbind via this so the invariant path is removed in
// lock-step with the cap, matching the bind side exactly (no drift —
// hctx.LocalPeerID is the same peer_id string issueRoleDerivedCap
// recovers from localIdentity).
func roleDerivedCapSigInvariantPath(hctx *handler.HandlerContext, capHash hash.Hash) string {
	return types.InvariantSignaturePath(hctx.LocalPeerID.String(), capHash)
}

// sweepRoleDerivedTokens deletes every role-derived cap binding for
// `peerHash` in `context` and returns the hashes of the removed tokens.
// Implements §6.1 layer 1 (exclusion → token revocation) and the §4.4
// IA12 step-3 sweep for unassign. Both flows converge on V7 §5.1's
// standard `is_revoked` mechanism for downstream rejection.
//
// Per v1.6 SI-7: broad sweep — deletes every cap bound at the subtree on
// this peer regardless of which fleet peer issued. Linkage entities at
// the sibling subtree are also removed (callers responsible for any
// per-role narrowing).
//
// The role-derived cap's signature lives only at the V7 §3.5 invariant
// pointer path (keyed by cap hash, in a different subtree — removed
// explicitly per cap). Returned hashes are the cap entity hashes (not
// signatures or linkage entities).
func sweepRoleDerivedTokens(hctx *handler.HandlerContext, context string, peerHash hash.Hash) []hash.Hash {
	if hctx == nil || hctx.LocationIndex == nil {
		return nil
	}
	prefix := RoleDerivedPeerPrefix(context, peerHash)
	entries := hctx.LocationIndex.List(prefix)
	revoked := make([]hash.Hash, 0, len(entries))
	for _, e := range entries {
		revoked = append(revoked, e.Hash)
		hctx.TreeRemove(e.Path, "role-derived-sweep")
		hctx.TreeRemove(roleDerivedCapSigInvariantPath(hctx, e.Hash), "role-derived-sweep-invariant-sig")
	}
	// Also clear linkage entities for this peer (all roles).
	linkPrefix := roleRoot + "/" + context + "/" + derivedSeg + "/" + HashHex(peerHash) + "/"
	for _, e := range hctx.LocationIndex.List(linkPrefix) {
		hctx.TreeRemove(e.Path, "role-derived-link-sweep")
	}
	return revoked
}

// sweepRoleDerivedTokensForRole revokes role-derived caps for a specific
// (peer, role) — used by unassign when a single role is being removed
// (per §4.4 IA12). Looks up the linkage entity to find the cap to
// revoke. Returns the hashes of caps whose bindings were removed.
//
// If no linkage exists for the (peer, role) tuple, returns an empty
// slice (no caps to revoke — assignment may have predated v1.6 linkage,
// or the cap was already revoked).
func sweepRoleDerivedTokensForRole(hctx *handler.HandlerContext, context string, peerHash hash.Hash, roleName string) []hash.Hash {
	if hctx == nil || hctx.LocationIndex == nil || hctx.Store == nil {
		return nil
	}
	link, ok := loadDerivedTokenLink(hctx.Store, hctx.LocationIndex, context, peerHash, roleName)
	if !ok {
		return nil
	}
	revoked := []hash.Hash{}
	capPath := RoleDerivedTokenPath(context, peerHash, link.TokenHash)
	if _, removed, _ := hctx.TreeRemove(capPath, "unassign-revoke"); removed {
		revoked = append(revoked, link.TokenHash)
	}
	hctx.TreeRemove(roleDerivedCapSigInvariantPath(hctx, link.TokenHash), "unassign-revoke-invariant-sig")
	hctx.TreeRemove(DerivedTokenLinkPath(context, peerHash, roleName), "unassign-link-remove")
	return revoked
}

// sweepRoleDerivedTokensExcluding is the variant used by re-derive
// (§5.5): delete every role-derived cap binding for `peerHash` in
// `context` EXCEPT the cap whose entity-hash equals `keep`. Used to
// revoke T_old while preserving the freshly-issued T_new during the
// per-assignee cascade leg.
func sweepRoleDerivedTokensExcluding(hctx *handler.HandlerContext, context string, peerHash hash.Hash, keep hash.Hash) []hash.Hash {
	if hctx == nil || hctx.LocationIndex == nil {
		return nil
	}
	prefix := RoleDerivedPeerPrefix(context, peerHash)
	entries := hctx.LocationIndex.List(prefix)
	revoked := make([]hash.Hash, 0, len(entries))
	keepPath := RoleDerivedTokenPath(context, peerHash, keep)
	for _, e := range entries {
		bare := barePath(e.Path)
		if bare == keepPath {
			continue
		}
		revoked = append(revoked, e.Hash)
		hctx.TreeRemove(e.Path, "re-derive-revoke")
		hctx.TreeRemove(roleDerivedCapSigInvariantPath(hctx, e.Hash), "re-derive-revoke-invariant-sig")
	}
	return revoked
}
