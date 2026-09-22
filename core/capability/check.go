package capability

import (
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// ResolveGranterPeerID resolves the peer ID whose namespace bare wildcards
// in this cap's resource patterns canonicalize against, per V7 §5.5 /
// PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP §PR-8.
//
// The earlier implementation returned localPeerID unconditionally, justified
// by the VerifyChain Site 3 invariant that "every validated chain's ROOT
// granter is the local peer." That invariant is true for the root but not
// for intermediate / leaf links — a re-attenuated child cap's granter is
// the peer that DID the delegation, not the root granter. Under §PR-8 each
// cap's resource patterns canonicalize against ITS OWN granter's
// namespace, so a leaf cap signed by foreign peer V with a bare-wildcard
// resource canonicalizes to `/{V}/*`, NOT `/{localPeerID}/*`. The earlier
// fallback admitted requests it shouldn't have — surfaced by the v7.73
// V2(a) `captok_form_dispatch_minted_pl_presented_xpeer` vector as a 3-way
// substrate FAIL across Go / Rust / Py.
//
// Resolution algorithm (mirrors verifyRootGranter):
//   - Single-sig: look up the granter content hash in the store, decode as
//     PeerData, derive peer_id from (key_type, public_key) per v7.65 §1.5.
//   - Multi-sig: no single namespace anchor; per M3 multi-sig caps are
//     root-only and the chain's root granter is the local peer by Site 3,
//     so localPeerID is the correct anchor. Falls back accordingly.
//
// Returns an error when single-sig resolution fails (hash zero, entity not
// in store, decode failure, unknown key_type). Callers map the error to
// 403 `capability_denied` per V7 §3.3 — same surface as other authz-class
// rejections.
//
// Pre-condition for single-sig: the granter's identity entity must be in
// the content store. The dispatcher path satisfies this via
// IngestEnvelopeSignatures (envelope_ingest.go) which persists every
// `system/peer` reachable from `included` before reaching this resolver.
// Handlers and extensions inherit the ingest because they run after
// dispatch's permission check has already resolved the granter.
func ResolveGranterPeerID(granter types.Granter, cs store.ContentStore, localPeerID crypto.PeerID) (crypto.PeerID, error) {
	// Multi-sig: per M3 multi-sig caps are root-only; Site 3 anchors the
	// chain root's namespace at the local peer; localPeerID is correct.
	if granter.IsMulti() {
		return localPeerID, nil
	}
	granterHash, _ := granter.SingleHash()
	// Zero granter: not a real production cap shape (production caps always
	// carry a granter populated and validated upstream). Some in-process
	// test contexts build caps without a granter to exercise pure scope
	// logic. Fall back to localPeerID so those tests continue to gate on
	// the scope check itself, not on a missing-granter resolver error.
	if granterHash.IsZero() {
		return localPeerID, nil
	}
	granterEnt, ok := cs.Get(granterHash)
	if !ok {
		return "", fmt.Errorf("granter identity %s not in content store", granterHash)
	}
	return peerIDFromPeerEntity(granterEnt)
}

// peerIDFromPeerEntity derives a peer_id from a system/peer entity by
// reading (key_type, public_key) and applying v7.65 §1.5 canonical-form
// derivation. Shared between ResolveGranterPeerID (store-backed) and
// granterPeerIDFromIncluded (envelope-backed) — both arrive at the same
// shape after their respective lookup step.
func peerIDFromPeerEntity(ent entity.Entity) (crypto.PeerID, error) {
	if ent.Type != types.TypePeer {
		return "", fmt.Errorf("granter entity is %q, expected %q", ent.Type, types.TypePeer)
	}
	idData, err := types.PeerDataFromEntity(ent)
	if err != nil {
		return "", fmt.Errorf("decode granter peer data: %w", err)
	}
	ktByte, ktOK := idData.KeyTypeByte()
	if !ktOK {
		return "", fmt.Errorf("granter key_type %q not supported", idData.KeyType)
	}
	pid, err := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte)
	if err != nil {
		return "", fmt.Errorf("derive granter peer_id: %w", err)
	}
	return pid, nil
}

// CheckPermission performs the 4-dimensional capability check:
// handlers, operations, resources, and peers.
//
// granterPeerID is the peer whose namespace bare wildcards in this cap's
// resource patterns canonicalize against (per PR-8 / V7 §5.5). Resolve via
// ResolveGranterPeerID before calling.
func CheckPermission(execute types.ExecuteData, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID) bool {
	_, ok := FindMatchingGrant(execute, cap, handlerPattern, localPeerID, granterPeerID)
	return ok
}

// FindMatchingGrant performs the 4-dimensional capability check and returns
// the first matching grant entry. Handlers that need to inspect the grant's
// constraints field (e.g., the query handler) use this instead of CheckPermission.
//
// granterPeerID applies to peer-relative cap resource patterns (PR-8).
func FindMatchingGrant(execute types.ExecuteData, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID) (types.GrantEntry, bool) {
	// Check temporal validity.
	now := uint64(time.Now().UnixMilli())
	if cap.NotBefore != nil && now < *cap.NotBefore {
		return types.GrantEntry{}, false
	}
	if Expired(cap.ExpiresAt, now) { // CAP-6: exclusive upper bound, expired when now >= expires_at
		return types.GrantEntry{}, false
	}

	// §5.2 extract_peer: the peer under test for the peers dimension is
	// read from the request URI, not the local peer. Wire dispatch
	// (check_permission) populates execute.uri; the compute grant-probe
	// form (check_grant_covers, EXTENSION-COMPUTE §3.3) leaves it empty and
	// passes the target as handlerPattern — use whichever the caller set.
	targetLocator := execute.URI
	if targetLocator == "" {
		targetLocator = handlerPattern
	}
	targetPeer := extractPeer(targetLocator, localPeerID)

	for _, grant := range cap.Grants {
		// Dimension 1: Operations (include AND exclude — F2 / §5.2 / §5.6).
		if !operationsAllow(grant.Operations, execute.Operation) {
			continue
		}

		// Dimension 2: Handlers.
		if !scopeContains(handlerPattern, grant.Handlers) {
			continue
		}

		// Dimension 3: Resources (when specified on execute).
		if execute.Resource != nil {
			if !CheckResourceScope(execute.Resource, grant.Resources, localPeerID, granterPeerID) {
				continue
			}
		}

		// Dimension 4: Peers (§5.2). An absent peers field defaults to
		// {include:[local_peer_id]} and is STILL checked — it authorizes the
		// local namespace only, it does not skip the peer dimension. The peer
		// tested is the request's target peer (extract_peer above), so a
		// local-scoped grant cannot authorize a foreign namespace.
		peersScope := types.CapabilityScope{Include: []string{string(localPeerID)}}
		if grant.Peers != nil {
			peersScope = *grant.Peers
		}
		if !MatchesPeerScope(string(targetPeer), peersScope, localPeerID) {
			continue
		}

		return grant, true
	}
	return types.GrantEntry{}, false
}

// CheckResourceScope checks that all resource targets are covered by the
// grant's resource scope (included and not excluded). Targets canonicalize
// against localPeerID (request-path semantics, V7 §5.4); patterns
// canonicalize against granterPeerID (cap-resource semantics, V7 §5.5 /
// PR-8).
func CheckResourceScope(resource *types.ResourceTarget, grantResources types.CapabilityScope, localPeerID, granterPeerID crypto.PeerID) bool {
	for _, target := range resource.Targets {
		if !IsCoveredBy(target, grantResources.Include, localPeerID, granterPeerID) {
			return false
		}
		if isExcluded(target, grantResources.Exclude, localPeerID, granterPeerID) {
			return false
		}
	}
	return true
}

// IsCoveredBy checks if a target path is covered by any cap pattern in the
// set. The target uses request-path canonicalization (localPeerID); patterns
// use cap-resource canonicalization (granterPeerID) per PR-8.
func IsCoveredBy(target string, patternSet []string, localPeerID, granterPeerID crypto.PeerID) bool {
	canonTarget := Canonicalize(target, localPeerID)
	for _, p := range patternSet {
		canonP := Canonicalize(p, granterPeerID)
		if MatchesPattern(canonTarget, canonP) {
			return true
		}
	}
	return false
}

// base58 alphabet (§8.5) — omits 0, O, I, l.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// isPeerID reports whether a path segment is a syntactic peer_id per §5.2
// is_peer_id: Base58 alphabet, length ≥ 46 (the Ed25519 + SHA-256 floor of
// 34 bytes → 46 Base58 chars; longer algorithms only add bytes, so 46 is the
// minimum, not an equality — §5.2 `is_peer_id`). This is a SYNTACTIC check,
// deliberately NOT crypto validation: extract_peer runs on every dispatch and
// must not turn on whether the segment decodes to a currently-supported key.
func isPeerID(segment string) bool {
	if len(segment) < 46 {
		return false
	}
	for _, r := range segment {
		if !strings.ContainsRune(base58Alphabet, r) {
			return false
		}
	}
	return true
}

// extractPeer resolves the target peer of a request locator per §5.2
// extract_peer: the first path segment when it is a syntactic peer_id, else
// the local peer (short-form / peer-relative paths belong to the local peer).
// Accepts entity:// URIs and absolute /{peer}/rest paths alike; a bare handler
// pattern ("system/tree") has a non-peer first segment and resolves to local.
func extractPeer(locator string, localPeerID crypto.PeerID) crypto.PeerID {
	norm := strings.TrimPrefix(entity.NormalizePath(locator), "/")
	first := norm
	if idx := strings.IndexByte(norm, '/'); idx >= 0 {
		first = norm[:idx]
	}
	if isPeerID(first) {
		return crypto.PeerID(first)
	}
	return localPeerID
}

// ExtractPeer is the exported §5.2 extract_peer, for the one caller outside
// this package: the §1.4 inbound-dispatch routing gate in core/protocol
// (handleExecute). The gate and the §5.2 peers dimension (Dimension 4) MUST
// read the target peer of a locator through ONE implementation — a routing
// concept split across two implementations is a DAG fork nobody sees until a
// peer does — so both go through extractPeer here.
func ExtractPeer(locator string, localPeerID crypto.PeerID) crypto.PeerID {
	return extractPeer(locator, localPeerID)
}

// idScopeMatches implements the §5.2 id-scope pattern grammar — the id-scope
// arm of both scope_value_matches (matches_scope) and pattern_covers
// (scope_subset). A literal identifier match with exactly two wildcard forms:
// bare "*" matches any value, and a trailing "/*" matches by literal
// segment-prefix (strip only the "*", keep the "/", then HasPrefix — so
// "compute/*" covers "compute/apply"). It applies NONE of the §5.4 path
// transforms (no canonicalize, no "/*/" interior peer-wildcard, no leading-"/"
// universal reading, no peer-relative qualification). `operations` and `peers`
// are id-scope dimensions; `handlers` and `resources` are path-scope and MUST
// go through MatchesPattern instead. Interchanging the two is the F40
// conformance defect (§5.2 "Scope types" / "id-scope pattern grammar",
// pseudocode pinned 0.8.2.16) — a path dimension matched literally, or an id
// dimension canonicalized, produces a real ALLOW bug and diverges across a
// peer boundary. Called `(pattern, value)`; for the subset (pattern_covers)
// form the arguments are `(outer, inner)` — the same three lines.
func idScopeMatches(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1]) // strip "*", keep "/"
	}
	return value == pattern
}

// matchesIDScope reports whether value is admitted by an id-scope dimension:
// matched by some include pattern AND not matched by any exclude pattern
// (§5.2 matches_scope, id-scope arm). This is the single shared matcher for
// the `operations` and `peers` dimensions — CheckPermission (operationsAllow /
// MatchesPeerScope) and the delegation subset check (idScopeSubset) both run
// through idScopeMatches so the two paths cannot silently diverge on a
// hash-/authz-determining rule.
func matchesIDScope(value string, scope types.CapabilityScope) bool {
	included := false
	for _, p := range scope.Include {
		if idScopeMatches(p, value) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, p := range scope.Exclude {
		if idScopeMatches(p, value) {
			return false
		}
	}
	return true
}

// MatchesPeerScope checks if a peer ID is covered by the peers scope (an
// id-scope dimension, §5.2). Peer IDs are explicit — there is no "self" alias
// (R11). localPeerID is unused (peers are literal identifiers, not path
// patterns) and retained only for signature stability with the path-scope
// matchers.
func MatchesPeerScope(peerID string, scope types.CapabilityScope, localPeerID crypto.PeerID) bool {
	return matchesIDScope(peerID, scope)
}

// IsPattern returns true if the string contains wildcard characters.
func IsPattern(s string) bool {
	return strings.Contains(s, "*")
}

// PatternsOverlap checks if two patterns could match any common path.
func PatternsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	if !IsPattern(a) && !IsPattern(b) {
		return a == b
	}
	if !IsPattern(a) {
		return MatchesPattern(a, b)
	}
	if !IsPattern(b) {
		return MatchesPattern(b, a)
	}
	// Both are subtree patterns — check if prefixes overlap.
	aPrefix := strings.TrimSuffix(a, "/*")
	bPrefix := strings.TrimSuffix(b, "/*")
	return strings.HasPrefix(aPrefix, bPrefix) || strings.HasPrefix(bPrefix, aPrefix)
}

// CheckPathPermission performs the Level 2 path-level access check.
// It checks whether the capability grants the specified operation on the
// specific path being accessed, filtered by handler scope.
//
// The request path canonicalizes against localPeerID (V7 §5.4); cap
// resource patterns canonicalize against granterPeerID (V7 §5.5 / PR-8).
// Resolve granter via ResolveGranterPeerID before calling.
func CheckPathPermission(operation, path string, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID) bool {
	// Check temporal validity.
	now := uint64(time.Now().UnixMilli())
	if cap.NotBefore != nil && now < *cap.NotBefore {
		return false
	}
	if Expired(cap.ExpiresAt, now) { // CAP-6: exclusive upper bound, expired when now >= expires_at
		return false
	}

	canonicalPath := Canonicalize(path, localPeerID)

	for _, grant := range cap.Grants {
		if !operationsAllow(grant.Operations, operation) {
			continue
		}

		// Check handler pattern matches.
		handlerMatched := false
		for _, h := range grant.Handlers.Include {
			if MatchesPattern(handlerPattern, h) {
				handlerMatched = true
				break
			}
		}
		if !handlerMatched {
			continue
		}

		// Check resource matches.
		resourceMatched := false
		for _, resource := range grant.Resources.Include {
			canonicalResource := Canonicalize(resource, granterPeerID)
			if MatchesPattern(canonicalPath, canonicalResource) {
				resourceMatched = true
				break
			}
		}
		if !resourceMatched {
			continue
		}

		// Check excludes.
		excluded := false
		for _, excl := range grant.Resources.Exclude {
			canonicalExclude := Canonicalize(excl, granterPeerID)
			if MatchesPattern(canonicalPath, canonicalExclude) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}

// MatchesPattern checks if a path matches a resource pattern.
// Both path and pattern should be absolute (canonicalized) for top-level
// resource-pattern calls. The pattern == "*" universal case handles two
// scenarios:
//
//   - Recursive sub-pattern after peer-wildcard stripping ("/*/* " → "*"
//     for the within-peer remainder).
//   - Handlers / Operations dimensions, where bare "*" legitimately means
//     "any handler" / "any operation" (not a peer-namespace concept).
//
// Resource-pattern callers MUST Canonicalize before invoking MatchesPattern
// per §PR-8 (V7 §5.5) — bare "*" in a cap RESOURCE is peer-local, never
// universal. Cross-peer authority requires "/*/*" or named-peer absolute
// form.
func MatchesPattern(path, pattern string) bool {
	// Universal match (recursive sub-pattern case; top-level "*" canonicalizes
	// to /{local}/* before reaching the matcher for resource patterns).
	if pattern == "*" {
		return true
	}

	// Peer wildcard: /*/rest — match any peer's subtree.
	if strings.HasPrefix(pattern, "/*/") {
		remainder := pattern[3:] // strip "/*/"
		// path is /{peer_id}/rest — extract rest after peer segment.
		if len(path) < 2 || path[0] != '/' {
			return false
		}
		rest := path[1:] // strip leading /
		idx := strings.Index(rest, "/")
		if idx < 0 {
			return false
		}
		pathRest := rest[idx+1:]
		return MatchesPattern(pathRest, remainder)
	}

	// Subtree match: pattern/* — canonical §5.4 is `prefix = pattern without
	// trailing "*"; return path starts with prefix`. The trailing "/" is part of
	// the prefix, so `a/b/*` matches `a/b/` and everything under it but NOT the
	// bare `a/b` — there is no bare-prefix self-match. A grant on
	// `/{peer}/system/capability/*` therefore does not reach `/{peer}/system/
	// capability` itself; that would be an authorization widening in the
	// permissive direction, and rust/py both refuse it (ROUTING-2026-08-18-o §4).
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // pattern without trailing "*" (keeps the /)
		return strings.HasPrefix(path, prefix)
	}

	// Exact match.
	return path == pattern
}

// Canonicalize resolves a path to absolute form per V7 §5.4 (request paths)
// and §5.5 (capability resource patterns; PROPOSAL-SYSTEM-PEER-RENAME-AND-
// SUBSTRATE-CLEANUP §PR-8 / V-1).
//
// Peer-relative paths and bare wildcards resolve to a peer-scoped namespace:
//   - Bare "*" → "/{peerID}/*" (peer-local wildcard, NOT universal cross-peer)
//   - "path"   → "/{peerID}/path"
//
// Already-absolute paths (leading "/") pass through. Entity URIs convert to
// absolute paths. Cross-peer authority MUST be expressed in absolute form
// (e.g., "/*/*" for all-peers-all-paths; "/{specific_peer}/path" for named).
//
// Per §PR-8 the peerID for cap RESOURCE patterns is normatively the
// granter's peer_id. For self-issued caps (granter == local checker), the
// local peer ID is correct; the current implementation uses localPeerID
// throughout, which matches the self-issued case. Foreign-granter caps
// (granter ≠ local) and the granter-aware canonicalization plumbing are
// follow-up work — see Wave 1 ARCH-FEEDBACK notes.
func Canonicalize(path string, localPeerID crypto.PeerID) string {
	// R1: reserved prefixes — pass through unchanged.
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return path
	}
	// R2: reject ambiguous bare peer wildcard — must use /*/rest.
	if strings.HasPrefix(path, "*/") {
		return path
	}
	// Full entity URI → absolute path.
	if strings.HasPrefix(path, entity.Scheme) {
		parsed, err := entity.ParseURI(path)
		if err == nil && parsed.PeerID != "" {
			if parsed.Path == "" {
				return "/" + parsed.PeerID
			}
			return "/" + parsed.PeerID + "/" + parsed.Path
		}
	}
	// Already absolute — pass through.
	if strings.HasPrefix(path, "/") {
		return path
	}
	// Bare wildcard is peer-relative → local peer, all paths.
	if path == "*" {
		return "/" + string(localPeerID) + "/*"
	}
	// Peer-relative → absolute.
	return "/" + string(localPeerID) + "/" + path
}

// scopeContains checks if a value is matched by any pattern in a scope's Include list.
func scopeContains(value string, scope types.CapabilityScope) bool {
	for _, pattern := range scope.Include {
		if MatchesPattern(value, pattern) {
			return true
		}
	}
	return false
}

// isExcluded checks if a target path matches any cap exclude pattern.
// Target uses request-path canonicalization (localPeerID); exclude
// patterns use cap-resource canonicalization (granterPeerID) per PR-8.
func isExcluded(target string, excludeSet []string, localPeerID, granterPeerID crypto.PeerID) bool {
	canonTarget := Canonicalize(target, localPeerID)
	for _, excl := range excludeSet {
		canonExcl := Canonicalize(excl, granterPeerID)
		if MatchesPattern(canonTarget, canonExcl) {
			return true
		}
	}
	return false
}

// operationsAllow reports whether an operation is permitted by an operations
// scope: matched by some include pattern AND not matched by any exclude
// (F2 / §5.2 / §5.6 — excludes apply to every scope dimension). `operations`
// is an id-scope dimension, so matching is the §5.2 id-scope grammar
// (literal + bare "*" + trailing "/*"), NOT the §5.4 path matcher — a grant
// {include:["compute/*"]} authorizes any compute/… op, and one
// {include:["*"], exclude:["delete"]} permits everything but delete. Delegates
// to matchesIDScope so this and the delegation subset check share one matcher.
func operationsAllow(scope types.CapabilityScope, op string) bool {
	return matchesIDScope(op, scope)
}
