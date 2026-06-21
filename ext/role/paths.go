package role

import (
	"encoding/hex"
	"strings"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// Path conventions per EXTENSION-ROLE.md §3.1 (v1.6):
//
//	system/role/{context}/{role_name}                              — role definition
//	system/role/{context}/assignment/{peer_id_hex}/{role_name}     — assignment
//	system/role/{context}/excluded/{peer_id_hex}                   — exclusion
//	system/role/{context}/derived-tokens/{peer_id_hex}/{role_name} — token linkage (SI-5)
//
// Role-derived capability tokens are pinned at (per §3.1 R4):
//
//	system/capability/grants/role-derived/{context}/{peer_id_hex}/{token_hash_hex}
//
// All non-root path segments encoding peer references use lowercase hex
// of the peer's system/peer entity content_hash (v1.6 §3.1, SI-1).
// Base58 PeerID per V7 §7.4 is reserved for the universal-root segment
// `/{peer_id}/...` only — never used in role-extension non-root segments
// or templates.
//
// All non-root path segments encoding hashes (token_hash, etc.) use
// lowercase hex of the full 33-byte system/hash (format byte + digest)
// per V7 §3.5 invariant pointer convention (SI-2). Same form as identity
// v3.3 cert paths and quorum v1.1 event paths. The display form
// `ecfv1-sha256:<hex>` (V7 §1.2 line 117) is UI-only and MUST NOT
// appear in path segments.

const (
	roleRoot      = "system/role"
	assignmentSeg = "assignment"
	excludedSeg   = "excluded"
	derivedSeg    = "derived-tokens"

	// roleDerivedRoot is the pinned storage prefix for role-derived
	// capability tokens (§3.1 R4).
	roleDerivedRoot = "system/capability/grants/role-derived"

	// initialGrantPolicyPath is the reserved path for the deployment's
	// initial grant policy entity per §4.7 (renamed from
	// "bootstrap-policy" per SI-28).
	initialGrantPolicyPath = "system/role/initial-grant-policy"
)

// InitialGrantPolicyPath returns the singleton path for the deployment's
// initial grant policy entity. Exported for the AUTHENTICATE-time resolver
// (ext/role/policy.go) and for fixtures that bind the policy entity.
func InitialGrantPolicyPath() string {
	return initialGrantPolicyPath
}

// ReservedRoleNames per §3.2 R10. A role name equal to "assignment",
// "excluded", or "derived-tokens" collides with the dedicated subtree
// namespaces and MUST be rejected at content validation.
var reservedRoleNames = map[string]struct{}{
	assignmentSeg: {},
	excludedSeg:   {},
	derivedSeg:    {},
}

// IsReservedRoleName returns true if name is a R10 reserved role name.
func IsReservedRoleName(name string) bool {
	_, ok := reservedRoleNames[name]
	return ok
}

// HashHex returns the lowercase hex encoding of a system/hash (33 bytes:
// format byte + 32-byte digest). For ECFv1-SHA-256, this is 66 hex
// characters starting with `00`. Used for path-segment encoding of
// `{peer_id_hex}` and `{token_hash}` (per V7 §3.5, role v1.6 §3.1).
func HashHex(h hash.Hash) string {
	return hex.EncodeToString(h.Bytes())
}

// HashFromHex parses a path-segment hex string back into a system/hash.
// Returns the zero hash and false on malformed input. Inverse of HashHex.
func HashFromHex(s string) (hash.Hash, bool) {
	bs, err := hex.DecodeString(s)
	if err != nil {
		return hash.Hash{}, false
	}
	h, err := hash.FromBytes(bs)
	if err != nil {
		return hash.Hash{}, false
	}
	return h, true
}

// RoleDefinitionPath returns the canonical path for a role definition
// entity within `context`.
func RoleDefinitionPath(context, roleName string) string {
	return roleRoot + "/" + context + "/" + roleName
}

// AssignmentPath returns the canonical path for a role-assignment entity.
// peerHash is the assignee's system/peer content_hash; encoded as
// lowercase hex per §3.1 (v1.6 SI-1).
func AssignmentPath(context string, peerHash hash.Hash, roleName string) string {
	return roleRoot + "/" + context + "/" + assignmentSeg + "/" + HashHex(peerHash) + "/" + roleName
}

// ExclusionPath returns the canonical path for a role-exclusion entity.
func ExclusionPath(context string, peerHash hash.Hash) string {
	return roleRoot + "/" + context + "/" + excludedSeg + "/" + HashHex(peerHash)
}

// DerivedTokenLinkPath returns the canonical path for the linkage
// entity that maps an assignment to its issued role-derived cap (§3.1
// + §2.4, v1.6 SI-5). Sibling subtree to assignment/ and excluded/ —
// NOT nested under the assignment entity.
func DerivedTokenLinkPath(context string, peerHash hash.Hash, roleName string) string {
	return roleRoot + "/" + context + "/" + derivedSeg + "/" + HashHex(peerHash) + "/" + roleName
}

// RoleDerivedTokenPath returns the canonical storage path for a role-
// derived capability token (§3.1 R4). Both the {peer_id} and {token_hash}
// segments are lowercase hex (v1.6 SI-1 + SI-2).
func RoleDerivedTokenPath(context string, peerHash hash.Hash, tokenHash hash.Hash) string {
	return roleDerivedRoot + "/" + context + "/" + HashHex(peerHash) + "/" + HashHex(tokenHash)
}

// RoleDerivedPeerPrefix returns the prefix under which all role-derived
// tokens for `peerHash` in `context` are stored. Used by the layer-1
// exclusion sweep (§6.1) and unassign token-revocation flow (§4.4 IA12).
func RoleDerivedPeerPrefix(context string, peerHash hash.Hash) string {
	return roleDerivedRoot + "/" + context + "/" + HashHex(peerHash) + "/"
}

// RoleDerivedContextPrefix returns the prefix covering all role-derived
// tokens in `context` (across all peers). Used by re-derive (§5.5).
func RoleDerivedContextPrefix(context string) string {
	return roleDerivedRoot + "/" + context + "/"
}

// AssignmentPathInfo is the parsed shape of a role-assignment path.
// PeerHash is the assignee's system/peer content_hash decoded from
// the path's hex segment.
type AssignmentPathInfo struct {
	Context  string
	PeerHash hash.Hash
	Role     string // empty when the trailing role segment is omitted (per §4.4 unassign-all)
}

// PeerHashHex returns the lowercase hex string the path was constructed
// with. Used when callers want the path-segment form (e.g., to construct
// child paths under the same peer).
func (a AssignmentPathInfo) PeerHashHex() string {
	return HashHex(a.PeerHash)
}

// ParseAssignmentPath splits a peer-relative path of the form
// `system/role/{context}/assignment/{peer_id_hex}/{role_name}` (or with
// the role_name omitted, per §4.4 unassign all-roles-for-peer form).
//
// {context} MAY contain forward slashes — the entire segment up to
// `/assignment/` is treated as opaque.
func ParseAssignmentPath(path string) (AssignmentPathInfo, bool) {
	rest, ok := stripPrefix(path, roleRoot+"/")
	if !ok {
		return AssignmentPathInfo{}, false
	}
	idx := strings.Index(rest, "/"+assignmentSeg+"/")
	if idx < 0 {
		return AssignmentPathInfo{}, false
	}
	context := rest[:idx]
	tail := rest[idx+len("/"+assignmentSeg+"/"):]
	if context == "" || tail == "" {
		return AssignmentPathInfo{}, false
	}
	parts := strings.SplitN(tail, "/", 2)
	peerHex := parts[0]
	if peerHex == "" {
		return AssignmentPathInfo{}, false
	}
	peerHash, ok := HashFromHex(peerHex)
	if !ok {
		return AssignmentPathInfo{}, false
	}
	out := AssignmentPathInfo{Context: context, PeerHash: peerHash}
	if len(parts) == 2 {
		out.Role = parts[1]
	}
	return out, true
}

// ExclusionPathInfo is the parsed shape of a role-exclusion path.
type ExclusionPathInfo struct {
	Context  string
	PeerHash hash.Hash
}

// PeerHashHex returns the lowercase hex string for the exclusion target.
func (e ExclusionPathInfo) PeerHashHex() string {
	return HashHex(e.PeerHash)
}

// ParseExclusionPath splits a peer-relative path of the form
// `system/role/{context}/excluded/{peer_id_hex}`.
func ParseExclusionPath(path string) (ExclusionPathInfo, bool) {
	rest, ok := stripPrefix(path, roleRoot+"/")
	if !ok {
		return ExclusionPathInfo{}, false
	}
	idx := strings.Index(rest, "/"+excludedSeg+"/")
	if idx < 0 {
		return ExclusionPathInfo{}, false
	}
	context := rest[:idx]
	tail := rest[idx+len("/"+excludedSeg+"/"):]
	if context == "" || tail == "" {
		return ExclusionPathInfo{}, false
	}
	// The exclusion subtree pins exactly one segment under /excluded/.
	if strings.Contains(tail, "/") {
		return ExclusionPathInfo{}, false
	}
	peerHash, ok := HashFromHex(tail)
	if !ok {
		return ExclusionPathInfo{}, false
	}
	return ExclusionPathInfo{Context: context, PeerHash: peerHash}, true
}

// RoleDefinitionPathInfo is the parsed shape of a role-definition path.
type RoleDefinitionPathInfo struct {
	Context  string
	RoleName string
}

// ParseRoleDefinitionPath splits a peer-relative path of the form
// `system/role/{context}/{role_name}`. Rejects paths whose final segment
// is the reserved `assignment`, `excluded`, or `derived-tokens` (per
// §3.2 R10) — those are subtree roots, not role definitions.
//
// The {context} segment is taken to be everything between `system/role/`
// and the final `/{role_name}` segment. This means
// `system/role/group/team-alpha/member` parses as
// context="group/team-alpha", role_name="member".
func ParseRoleDefinitionPath(path string) (RoleDefinitionPathInfo, bool) {
	rest, ok := stripPrefix(path, roleRoot+"/")
	if !ok {
		return RoleDefinitionPathInfo{}, false
	}
	idx := strings.LastIndex(rest, "/")
	if idx <= 0 || idx == len(rest)-1 {
		return RoleDefinitionPathInfo{}, false
	}
	context := rest[:idx]
	roleName := rest[idx+1:]
	if IsReservedRoleName(roleName) {
		return RoleDefinitionPathInfo{}, false
	}
	// Reject paths that fall inside the reserved subtrees — those are
	// not role definitions.
	for _, seg := range []string{assignmentSeg, excludedSeg, derivedSeg} {
		if strings.Contains(context, "/"+seg+"/") || strings.HasSuffix(context, "/"+seg) {
			return RoleDefinitionPathInfo{}, false
		}
	}
	return RoleDefinitionPathInfo{Context: context, RoleName: roleName}, true
}

// IsRoleManagedPath reports whether `path` falls within the
// system/role/... namespace and is therefore subject to the
// handler-routes-only convention per §1.3 + §4 (v1.6 SI-10:
// "rejection" framing removed; now an informational discriminator
// for write-origin sync hooks per §6.5 SI-17).
func IsRoleManagedPath(path string) bool {
	return path == roleRoot ||
		strings.HasPrefix(path, roleRoot+"/")
}

func stripPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
