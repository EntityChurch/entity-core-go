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

// CheckPermissionRelaxPeers is CheckPermission with Dimension 4 (peers)
// optionally exempted. It exists for ONE caller — the §6.8 / 0.8.2.19 (E1)
// outbound sub-dispatch gate: the executing handler's grant decides
// Dimensions 1-3 (operations, handlers, resources) unconditionally, and a
// valid credential minted BY the target peer relaxes Dimension 4 — and only
// Dimension 4 — to the peers that credential covers. When relaxPeers is true
// the peers dimension is treated as satisfied for the target under test; the
// other three dimensions are checked exactly as CheckPermission does.
//
// This is NOT a general-purpose skip: the relaxation is sound only when the
// caller has independently verified a target-minted credential that authorizes
// reaching the target (see core/protocol.presentedAuthorizes). With relaxPeers
// false it is identical to CheckPermission.
func CheckPermissionRelaxPeers(execute types.ExecuteData, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID, relaxPeers bool) bool {
	_, ok := findMatchingGrant(execute, cap, handlerPattern, localPeerID, granterPeerID, relaxPeers)
	return ok
}

// FindMatchingGrant performs the 4-dimensional capability check and returns
// the first matching grant entry. Handlers that need to inspect the grant's
// constraints field (e.g., the query handler) use this instead of CheckPermission.
//
// granterPeerID applies to peer-relative cap resource patterns (PR-8).
func FindMatchingGrant(execute types.ExecuteData, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID) (types.GrantEntry, bool) {
	return findMatchingGrant(execute, cap, handlerPattern, localPeerID, granterPeerID, false)
}

// findMatchingGrant is the shared 4-dimensional check body. relaxPeers exempts
// Dimension 4 for the E1 outbound gate (see CheckPermissionRelaxPeers); every
// other caller passes false, which is the full four-dimension check.
func findMatchingGrant(execute types.ExecuteData, cap types.CapabilityTokenData, handlerPattern string, localPeerID, granterPeerID crypto.PeerID, relaxPeers bool) (types.GrantEntry, bool) {
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
		//
		// relaxPeers (0.8.2.19 E1) exempts this dimension for the target under
		// test, when a valid target-minted credential has been verified to
		// authorize reaching the target. It relaxes ONLY Dimension 4 — the
		// three dimensions above still gate.
		if !relaxPeers {
			peersScope := types.CapabilityScope{Include: []string{string(localPeerID)}}
			if grant.Peers != nil {
				peersScope = *grant.Peers
			}
			if !MatchesPeerScope(string(targetPeer), peersScope, localPeerID) {
				continue
			}
		}

		return grant, true
	}
	return types.GrantEntry{}, false
}

// EffectiveTargets is the §5.2 named function (0.8.2.20): the targets a request
// ACTUALLY names, after the caller's own exclusions, one entry per surviving
// target. THE AUTHORIZER AND EVERY HANDLER MUST DERIVE THEIR SUBJECT FROM THIS
// ONE FUNCTION.
//
// It is a function rather than a rule restated in prose because the defect it
// closes (F68) is two layers computing the same set independently and drifting:
// CheckResourceScope skipped caller-excluded targets while every handler indexed
// resource.Targets[0], and WHICH targets differed was the caller's to choose —
// name the path you want, put the same path in exclude, clear the resource
// dimension vacuously, and be acted upon. A third statement of the rule would
// drift the same way; a function has one definition.
//
// Parameters are deliberately only values a handler already holds (ctx.Resource,
// ctx.LocalPeerID) — no grant, no capability, no dispatch state — so a handler
// specified in another document can call it. An absent resource yields the empty
// list: "absent" and "present but fully self-excluded" are the same answer to
// the same question (§3.3 gives them the same code, path_required).
//
// A caller-excluded target is redundant but valid and NOT a subject; the skip is
// correct and retained — demanding grant coverage for a path nobody requested
// would refuse legitimate traffic. The defect was never the skip; it was that
// only one layer performed it. Go did not honor caller excludes at all before
// 0.8.2.20; this makes both layers honor them together, so the exclude feature
// cannot arrive later without the skip (which would be the F68 bypass).
//
// The skip decision is made on CANONICAL forms (§5.4 matcher) so the authorizer
// and every handler agree on WHICH targets survive; the RAW survivor is returned
// so a handler retains its existing path semantics (LocationIndex.Get,
// QualifyPath) — canonicalizing the return would double-qualify a bare target
// through the non-idempotent QualifyPath. The subject a handler acts on is
// therefore raw effective[0], whose canonical form is a member of the canonical
// effective set, so `subject ⊆ effective_targets` holds and F68 is closed at
// both layers from one survivor set. A malformed/reserved target is NOT covered
// by any exclude (§5.4), so it stays in the list and is refused by
// CheckResourceScope's fail-closed validation.
func EffectiveTargets(resource *types.ResourceTarget, localPeerID crypto.PeerID) []string {
	if resource == nil {
		return nil
	}
	out := make([]string, 0, len(resource.Targets))
	for _, target := range resource.Targets {
		// Caller excludes are request-path fields: both target and exclude
		// canonicalize against localPeerID (granterPeerID == localPeerID here).
		ct := Canonicalize(target, localPeerID)
		if IsCoveredBy(ct, resource.Exclude, localPeerID, localPeerID) {
			continue
		}
		out = append(out, target)
	}
	return out
}

// validConcreteTarget reports whether a canonicalized concrete (non-pattern)
// resource target is a usable absolute path. A reserved-prefix ("./", "../"),
// bare-peer-wildcard ("*/") or otherwise non-absolute target is malformed;
// check_resource_scope MUST fail closed on it (G6 / §5.2, 0.8.2.20) rather than
// let a broad grant include (e.g. "*", which MatchesPattern admits for any
// string) match a path that is not a path.
//
// G6 is *"if validate_absolute_path(ct) is error: return false"* — so this
// consumes store.ValidateAbsolutePath, the full §5.4 validate_absolute_path
// (leading slash, no empty segment, control-char-free, AND a peer-id first
// segment). A chars-only check dropped the peer-id clause, which is not
// equivalent in practice: a target like "/short/x" is absolute and star-free
// (so NOT NEVER_MATCH), yet against a peer-wildcard grant ("/*/*") the matcher
// strips the first segment whatever it is and the remainder matches — covering
// a target rooted at a peer that cannot exist. Found cohort-wide (rust + py
// both routed the identical drop, 2026-09-11).
func validConcreteTarget(ct string) bool {
	return store.ValidateAbsolutePath(ct) == nil
}

// CheckResourceScope checks that every EFFECTIVE resource target (§5.2, caller
// excludes removed) is covered by the grant's resource scope (included and not
// excluded). Targets canonicalize against localPeerID (request-path semantics,
// V7 §5.4); patterns canonicalize against granterPeerID (cap-resource
// semantics, V7 §5.5 / PR-8). Behaviour is unchanged from 0.8.2.19 except that
// the effective set is now NAMED rather than computed inline, and that a
// malformed concrete target fails closed instead of proceeding on a discarded
// verdict (G6, 0.8.2.20).
func CheckResourceScope(resource *types.ResourceTarget, grantResources types.CapabilityScope, localPeerID, granterPeerID crypto.PeerID) bool {
	var callerExclude []string
	if resource != nil {
		callerExclude = resource.Exclude
	}
	for _, target := range EffectiveTargets(resource, localPeerID) {
		// Validate concrete path targets at the protocol boundary; pattern
		// targets go through pattern matching, not tree access. Validate on the
		// canonical form (the survivor is returned raw).
		ct := Canonicalize(target, localPeerID)
		if !IsPattern(ct) && !validConcreteTarget(ct) {
			return false
		}

		// Target must be covered by the grant include, for both target shapes.
		if !IsCoveredBy(target, grantResources.Include, localPeerID, granterPeerID) {
			return false
		}

		if IsPattern(ct) {
			// PATTERN target (§5.2 pattern arm). A concrete-style exclude test is
			// WRONG here: MatchesPattern("/{p}/data/*", "/{p}/data/secret") is a
			// literal inequality, so the target pattern re-spells straight past a
			// concrete grant exclude and is allowed where §5.2 denies (G-4, both
			// siblings routed 2026-09-11). The rule: for every grant exclude that
			// OVERLAPS this target, the caller must carry a corresponding exclude
			// that covers it — otherwise the effective target spans paths the grant
			// forbids. Grant patterns canonicalize against the granter (PR-8); the
			// caller exclude is a request-path field (localPeerID).
			//
			// The sentinel arm is FIRST and is a control-flow obligation, not a
			// line (§5.4 consumer table, 0.8.2.22): an unmatchable grant exclude
			// (§5.4 NEVER_MATCH — a `*/`, `./`, `../`-leading pattern) MUST deny
			// before the overlap test, because PatternsOverlap CONTINUEs on such a
			// pattern (it overlaps nothing), which would skip the deny. The concrete
			// arm below carries the same rule via isExcluded; this arm had it "one
			// line too late" — the coverage test at IsCoveredBy is correct in
			// isolation and was unreachable. (J1, arch ROUTING-2026-09-13-d. The
			// H1 validity gate refuses such a cap at mint, but a received cap that
			// was not minted locally reaches evaluation, so the deny must also live
			// here, per the same "a control must fail closed on its own input"
			// discipline the H1 exclude-matrix ratchet is built on.)
			for _, ge := range grantResources.Exclude {
				cge := Canonicalize(ge, granterPeerID)
				if IsUnmatchablePattern(cge) {
					return false
				}
				if !PatternsOverlap(ct, cge) {
					continue
				}
				if !IsCoveredBy(cge, callerExclude, localPeerID, localPeerID) {
					return false
				}
			}
		} else {
			// CONCRETE target: must not be in any grant exclude, with the H1
			// unmatchable-excludes-everything arm (isExcluded carries it).
			if isExcluded(target, grantResources.Exclude, localPeerID, granterPeerID) {
				return false
			}
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

// ExtractPeerStrict returns the target peer id of a locator ONLY when the
// locator actually carries a peer segment (an absolute `/{peer}/...` or an
// `entity://{peer}/...` URI); it returns ("", false) for a bare handler path
// like "system/network". Unlike ExtractPeer it never substitutes the local
// peer — the caller wants "which foreign machine", not "default to me". Same
// parse as extractPeer so the two do not diverge on what a peer segment is
// (the DAG-fork hazard extractPeer's own comment names).
//
// Used by the chain-error `lost` marker binders to fill §3.10.6 TargetPeerID:
// a marker for a dispatch aimed at `entity://{peer}/...` records that peer, and
// a marker for a bare-path failure records nothing (the field stays absent, and
// a consumer says "unknown" rather than inventing a peer).
func ExtractPeerStrict(locator string) (crypto.PeerID, bool) {
	norm := strings.TrimPrefix(entity.NormalizePath(locator), "/")
	first := norm
	if idx := strings.IndexByte(norm, '/'); idx >= 0 {
		first = norm[:idx]
	}
	if isPeerID(first) {
		return crypto.PeerID(first), true
	}
	return "", false
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
//
// Unlike the shared operations matcher, the peers dimension applies §3.6 rule 4
// (0.8.2.29): a received pattern is canonicalized for the comparison, and a
// value that CANNOT be canonicalized fails closed per position — this is what
// closes the exclude fail-open where a non-canonical `peers.exclude` silently
// failed to match the peer it named. It is a SEPARATE matcher from
// matchesIDScope so the operations dimension (op-name strings, not peer-ids) is
// never subjected to peer-id canonicalization.
func MatchesPeerScope(peerID string, scope types.CapabilityScope, localPeerID crypto.PeerID) bool {
	return matchesPeerScope(peerID, scope)
}

// peerMatch is the tri-state result of comparing one `peers:` pattern against
// the peer under test, per §3.6 rule 4.
type peerMatch int

const (
	peerMatchNo           peerMatch = iota // a canonical peer-id of a different peer
	peerMatchYes                           // `*`, an exact literal, or a same-identity cross-form match
	peerMatchUnresolvable                  // the value cannot be canonicalized (fail closed per position)
)

// peerPatternMatches compares one `peers:` IdScope pattern against the (canonical)
// peer under test with §3.6 rule-4 comparison-time canonicalization.
//
// The exact-literal and `*` fast paths preserve the prior behaviour byte for
// byte (the overwhelming common case: both sides already §1.5-canonical). Only a
// non-literal, non-wildcard pattern reaches canonicalization: a same-identity
// cross-form value matches, a different canonical peer-id does not, and a value
// that cannot be canonicalized (SHA-256-form of an uncontacted peer, path-shaped,
// malformed) is reported unresolvable for the caller to fail closed on.
func peerPatternMatches(pattern, comparand string) peerMatch {
	if pattern == "*" || pattern == comparand {
		return peerMatchYes
	}
	cpat, ok := crypto.CanonicalizePeerID(crypto.PeerID(pattern))
	if !ok {
		return peerMatchUnresolvable
	}
	if ccmp, okc := crypto.CanonicalizePeerID(crypto.PeerID(comparand)); okc && cpat == ccmp {
		return peerMatchYes
	}
	return peerMatchNo
}

// matchesPeerScope implements the §5.2 peers id-scope check: matched by some
// include AND not matched by any exclude, with the §3.6 rule-4 fail-closed
// dispositions — an include entry that cannot be canonicalized MUST NOT match
// (grant withheld); an exclude entry that cannot be canonicalized MUST match
// (peer excluded). comparand is the peer under test, canonical per §5.2
// (extract_peer + the wire-acceptance canonicalize-on-storage rule).
func matchesPeerScope(comparand string, scope types.CapabilityScope) bool {
	included := false
	for _, p := range scope.Include {
		// Only a definite match includes; an unresolvable include is withheld.
		if peerPatternMatches(p, comparand) == peerMatchYes {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, p := range scope.Exclude {
		// A definite match OR an unresolvable exclude both exclude (fail closed).
		switch peerPatternMatches(p, comparand) {
		case peerMatchYes, peerMatchUnresolvable:
			return false
		}
	}
	return true
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

		// Check handler scope (include AND exclude — §5.2 matches_scope, path-scope
		// arm). scopeContains is the shared handlers matcher, so this §6.3 check and
		// the dispatch check honor a handler exclude identically. Reading only
		// Handlers.Include here was a fail-open: a grant excluding a handler still
		// authorized it at the path level (G-3, both siblings routed 2026-09-11).
		if !scopeContains(handlerPattern, grant.Handlers) {
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

		// Check excludes. The subject PATH is usually concrete (a get/put on a
		// specific path), but EXTENSION-SUBSCRIPTION §2.3 routes a PATTERN subject
		// here (a subscription target like `data/*`). The two need different exclude
		// semantics, exactly as check_resource_scope's concrete/pattern split does:
		//
		//   - CONCRETE subject: an UNMATCHABLE grant exclude excludes EVERYTHING
		//     (H1, 0.8.2.21 — fail closed; a misspelled "*/secret" carves out
		//     nothing and the grant is silently wider than written), and a concrete
		//     exclude that matches the path excludes it. §6.3 is the SOLE resource
		//     enforcement when the dispatch resource dimension is absent (G-1).
		//   - PATTERN subject: the concrete exact test is a literal inequality, so a
		//     pattern re-spells straight past a concrete grant exclude — the G-4
		//     bypass one handler over (py routed 2026-09-12: an include_payload
		//     subscription on `data/*` under a grant excluding `data/secret` shipped
		//     the excluded body forever). There is no caller-exclude at this call
		//     site, so ANY grant exclude that OVERLAPS the pattern subject forbids it
		//     (the §5.2 pattern arm reduced to zero caller coverage). NEVER_MATCH is
		//     not special-cased in this arm (per §5.2 — it cannot overlap a real
		//     pattern and is caught by the FirstUnmatchableScopePattern validity gate
		//     at mint), matching check_resource_scope's pattern arm exactly.
		excluded := false
		if IsPattern(canonicalPath) {
			// J3 (§5.2, 0.8.2.22): the sentinel rule applies to the pattern
			// subject arm too — an unmatchable grant exclude denies BEFORE the
			// overlap test (PatternsOverlap CONTINUEs on it), matching
			// check_resource_scope's pattern arm (J1) fixed the same round. A
			// received cap not minted locally reaches evaluation, so the deny
			// must live here, not only at the mint-time validity gate.
			for _, excl := range grant.Resources.Exclude {
				cexcl := Canonicalize(excl, granterPeerID)
				if IsUnmatchablePattern(cexcl) {
					excluded = true
					break
				}
				if PatternsOverlap(canonicalPath, cexcl) {
					excluded = true
					break
				}
			}
		} else {
			for _, excl := range grant.Resources.Exclude {
				canonicalExclude := Canonicalize(excl, granterPeerID)
				if IsUnmatchablePattern(canonicalExclude) {
					excluded = true
					break
				}
				if MatchesPattern(canonicalPath, canonicalExclude) {
					excluded = true
					break
				}
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

// scopeContains reports whether a value is admitted by a path-scope dimension:
// matched by some include pattern AND not matched by any exclude (§5.2
// matches_scope, path-scope arm). It is the shared matcher for the handlers
// dimension — the dispatch check (findMatchingGrant Dimension 2) and the
// §6.3 handler-level check (CheckPathPermission) both go through it, so the two
// paths cannot silently diverge on whether a handler exclude is honored.
//
// The include-then-exclude shape mirrors matchesIDScope. The exclude arm carries
// the H1 (0.8.2.21) reading: an UNMATCHABLE exclude excludes EVERYTHING (fail
// closed). Without it a granter's misspelled handler exclude ("*/x") carves out
// nothing and the grant is silently wider than written. Handler patterns are
// matched raw (go does not canonicalize the handlers dimension); IsUnmatchable-
// Pattern is peer-independent, so the H1 arm is correct on the raw form.
func scopeContains(value string, scope types.CapabilityScope) bool {
	matched := false
	for _, pattern := range scope.Include {
		if MatchesPattern(value, pattern) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, pattern := range scope.Exclude {
		if IsUnmatchablePattern(pattern) {
			return false
		}
		if MatchesPattern(value, pattern) {
			return false
		}
	}
	return true
}

// IsUnmatchablePattern reports whether a canonicalized pattern is unmatchable
// by construction — the §5.4 forms the spec canonicalizes to NEVER_MATCH:
// a reserved-prefix ("./", "../") or bare-peer-wildcard ("*/") leading pattern.
// go has no NEVER_MATCH sentinel; Canonicalize passes these through unchanged
// and MatchesPattern returns false for them, which is fail-CLOSED in an include
// (covers nothing) but fail-OPEN in an exclude (carves out nothing → a grant
// wider than its author wrote). This predicate is how the exclude-evaluation
// and capability-validity layers detect the unmatchable case (§5.2/§5.4 H1,
// 0.8.2.21). The check is peer-independent: Canonicalize leaves these three
// prefixes unchanged and maps every other input to a "/"-leading path, so the
// verdict does not depend on which peer id is used to canonicalize.
func IsUnmatchablePattern(pattern string) bool {
	return strings.HasPrefix(pattern, "./") ||
		strings.HasPrefix(pattern, "../") ||
		strings.HasPrefix(pattern, "*/")
}

// FirstUnmatchableScopePattern returns the first PATH-SCOPE include/exclude
// pattern across all grants that is unmatchable (§5.4 NEVER_MATCH), or "" if
// every pattern is matchable. A capability carrying one is INVALID [MUST]
// (§5.2/§5.4 H1, 0.8.2.21): unmatchable in an include grants nothing, in an
// exclude carves out nothing (fail-open), and two conformant peers must not
// disagree on the same bytes — so it is refused at mint/delegate (400
// invalid_path, §6.2) and treated as invalid at verify (§5.5). The two readings
// diverge across a peer boundary, so this is a MUST, not a MAY.
//
// BOTH path-scope dimensions are walked: handlers AND resources. §3.6 types the
// handlers dimension as system/capability/path-scope, canonicalized and matched
// exactly as resources is, so an unmatchable handler pattern is the same invalid
// bytes — walking resources alone left a hole both siblings routed (G-2,
// 2026-09-11). operations/peers are id-scope (literal identifiers, no §5.4
// canonicalization) and are not walked. IsUnmatchablePattern is peer-independent,
// so a raw handler pattern is checked directly (go does not canonicalize the
// handlers dimension) — and no legitimate handler name begins with "./", "../"
// or "*/", so this cannot false-positive on a real handler pattern.
func FirstUnmatchableScopePattern(grants []types.GrantEntry) string {
	for _, g := range grants {
		for _, p := range g.Handlers.Include {
			if IsUnmatchablePattern(p) {
				return p
			}
		}
		for _, p := range g.Handlers.Exclude {
			if IsUnmatchablePattern(p) {
				return p
			}
		}
		for _, p := range g.Resources.Include {
			if IsUnmatchablePattern(p) {
				return p
			}
		}
		for _, p := range g.Resources.Exclude {
			if IsUnmatchablePattern(p) {
				return p
			}
		}
	}
	return ""
}

// isExcluded checks if a target path matches any cap exclude pattern.
// Target uses request-path canonicalization (localPeerID); exclude
// patterns use cap-resource canonicalization (granterPeerID) per PR-8.
func isExcluded(target string, excludeSet []string, localPeerID, granterPeerID crypto.PeerID) bool {
	canonTarget := Canonicalize(target, localPeerID)
	for _, excl := range excludeSet {
		canonExcl := Canonicalize(excl, granterPeerID)
		// H1 (0.8.2.21): an unmatchable grant-exclude excludes EVERYTHING —
		// fail closed. Without this arm a granter's misspelled exclude
		// ("*/secret") carves out nothing and the grant is silently wider than
		// written. This is the sentinel's fail-OPEN direction, and it is a
		// security verdict, not hygiene.
		if IsUnmatchablePattern(canonExcl) {
			return true
		}
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
