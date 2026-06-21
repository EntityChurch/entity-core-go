// Package capability implements the system/capability handler — V7 v7.62 §6.2.
//
// Four operations (all MUST per v7.62):
//
//   - request:   policy-table-bounded attenuation from the caller's
//                authenticated cap. Subset-validates the request payload
//                against BOTH the caller's cap AND any matching policy
//                entry at system/capability/policy/{caller_peer_hex} (or
//                the `default` fallback). Mints a token at the local peer
//                and returns it inline.
//   - revoke:    universal revocation entry point. Path-agnostic: tree-
//                unbinds the cap (if path-bound via capability_path_for)
//                AND writes a marker at system/capability/revocations/
//                {cap_hash_hex}. No cross-dispatch to role or any other
//                handler. Authorization is the standard "hold a cap
//                covering system/capability:revoke on the target."
//   - configure: writes a system/capability/policy/{peer_pattern} entry
//                under the handler's own grant.
//   - delegate:  caller-driven self-attenuation. Verifies the caller
//                holds the parent directly (parent.grantee == caller's
//                authenticated identity) and mints a narrowed child.
//                Self-attenuation only in v1 — grantee = caller always;
//                third-party handoff deferred to a future amendment.
//
// Result envelope (§7): request and delegate return inline. The included
// map carries the issued token, its signature, and the granter identity.
// SDKs MAY include the full parent-chain bundle for cross-peer use.
//
// Per §2a, all created_at / expires_at / revoked_at timestamps are
// handler-set wall-clock millis since Unix epoch; caller-supplied values
// are ignored (replay-surface defense).
//
// Authority is wired in after peer construction via SetupAuthority (same
// pattern as ext/handlers). Until then, request/delegate/configure fail
// closed with 503; revoke is allowed when the caller's cap covers it
// (the marker write is governed by the standard cap check, not the
// handler's signing identity).
package capability

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	corecap "go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

const (
	handlerPattern = "system/capability"

	// PolicyPathPrefix is the storage root for per-peer policy entries
	// (V7 v7.62 §4 + closeout F8: literal fallback segment is `default`,
	// not `*`, to remove the glyph collision with V7's glob-match `*`).
	// Entries are bound at PolicyPathPrefix + "/" + peer_pattern where
	// peer_pattern is either a 66-hex-char identity hash or the literal
	// segment "default".
	PolicyPathPrefix = "system/capability/policy"

	// policyFallbackSegment is the literal path segment used for the
	// default-for-unknown-peers entry (V7 closeout F8). Renamed from "*"
	// to "default" since `*` is V7's glob-match glyph everywhere else.
	policyFallbackSegment = "default"

	// peerPatternHexLenSHA256 is the V7 §3.5 invariant-pointer hex width
	// for ECFv1-SHA-256: 1 format-code byte + 32 digest bytes = 33 bytes =
	// 66 hex characters. peerPatternHexLenSHA384 is the SHA-384 width
	// (1 + 48 bytes = 98 hex). Width is format-relative per V7 v7.70 §1.2
	// (a peer's home format determines its content-hash widths).
	peerPatternHexLenSHA256 = 66
	peerPatternHexLenSHA384 = 98
)

// Handler implements the V7 v7.62 §6.2 capability handler.
type Handler struct {
	mu       sync.RWMutex
	keypair  crypto.Keypair
	identity entity.Entity
	ready    bool
	debugLog func(format string, args ...any) // nil → silent; v7.65 §3.6 lazy-canon event log
}

// NewHandler constructs a capability handler. SetupAuthority MUST be
// called before request/delegate/configure will succeed.
func NewHandler() *Handler { return &Handler{} }

// SetDebugLog wires a debug-log sink for v7.65 §3.6 rule 3 lazy-canonicalization
// mint events (Base58 peer_pattern minted while peer's pubkey is unknown).
// nil-safe; default silent.
func (h *Handler) SetDebugLog(fn func(format string, args ...any)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.debugLog = fn
}

// Name implements handler.Handler.
func (h *Handler) Name() string { return "capability" }

// SetupAuthority wires the peer's keypair and identity into the
// handler so request/delegate can sign the tokens they issue. Idempotent.
func (h *Handler) SetupAuthority(kp crypto.Keypair, identityEnt entity.Entity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keypair = kp
	h.identity = identityEnt
	h.ready = true
}

// Manifest returns the handler's self-description (V7 v7.62 §6.2).
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "capability",
		Operations: map[string]types.HandlerOperationSpec{
			"request": {
				InputType:  types.TypeCapRequest,
				OutputType: types.TypeCapGrant,
			},
			"revoke": {
				InputType: types.TypeCapRevokeRequest,
			},
			"configure": {
				InputType: types.TypeCapPolicyEntry,
			},
			"delegate": {
				InputType:  types.TypeCapDelegateRequest,
				OutputType: types.TypeCapGrant,
			},
		},
	}
}

// Handle dispatches to one of the four operations. Unknown operations
// return 501 unsupported_operation per V7 v7.62 §6.2 status-code semantic
// note (handler IS registered but does not implement the named operation —
// distinct from 404 handler_not_found and 403 capability_denied).
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "request":
		return h.handleRequest(ctx, req)
	case "delegate":
		return h.handleDelegate(ctx, req)
	case "revoke":
		return h.handleRevoke(ctx, req)
	case "configure":
		return h.handleConfigure(ctx, req)
	default:
		return handler.NewErrorResponse(501, "unsupported_operation",
			"system/capability does not implement operation: "+req.Operation)
	}
}

// handleRequest mints a token attenuated from the caller's authenticated
// cap, bounded ALSO by any matching policy entry per V7 v7.62 §4. The
// subset-validation pattern: the request payload IS the answer — the
// handler validates it as a subset of both ceilings (caller's cap AND
// policy entry) and mints exactly what was asked. On violation, returns
// 403 scope_exceeds_authority.
func (h *Handler) handleRequest(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	h.mu.RLock()
	ready := h.ready
	keypair := h.keypair
	identity := h.identity
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"capability handler authority not yet wired (SetupAuthority pending)")
	}

	if hctx.CallerCapability.ContentHash.IsZero() {
		return handler.NewErrorResponse(401, "unauthenticated",
			"request requires an authenticated caller capability")
	}

	var rr types.CapabilityRequestData
	if err := ecf.Decode(req.Params.Data, &rr); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode capability-request: "+err.Error())
	}
	if len(rr.Grants) == 0 {
		return handler.NewErrorResponse(400, "invalid_params",
			"capability-request must specify at least one grant entry")
	}

	parentCap, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to decode caller capability: "+err.Error())
	}

	// Step 1: subset-validate against the caller's authenticated cap
	// (attenuation floor — V7 §5.2 matches_scope).
	if err := requireAttenuation(rr.Grants, parentCap.Grants, hctx.LocalPeerID); err != nil {
		return handler.NewErrorResponse(403, "scope_exceeds_authority",
			"request grants exceed caller cap: "+err.Error())
	}

	// Step 2: subset-validate against the matched policy entry (per-peer
	// ceiling), if one exists. exact-match-or-`*`-fallback per §4. A
	// missing policy entry just skips this ceiling (pure attenuation
	// from the caller's cap still works without policy).
	if policy, ok := h.lookupPolicy(hctx, hctx.AuthorHash, hctx.Author); ok {
		if err := requireAttenuation(rr.Grants, policy.Grants, hctx.LocalPeerID); err != nil {
			return handler.NewErrorResponse(403, "scope_exceeds_authority",
				"request grants exceed policy entry: "+err.Error())
		}
	}

	createdAt := uint64(time.Now().UnixMilli())
	var expiresAt *uint64
	if rr.TTLMs != nil && *rr.TTLMs > 0 {
		exp := createdAt + *rr.TTLMs
		expiresAt = &exp
	}

	childData := types.CapabilityTokenData{
		Grants:    rr.Grants,
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   hctx.AuthorHash,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	return h.mintAndReturn(hctx, keypair, identity, childData)
}

// handleDelegate mints a child token via caller-driven self-attenuation
// (V7 v7.62 §9 + §11 + closeout F1). The caller MUST be the local peer
// (v1 is same-peer-only — cross-peer self-attenuation is structurally
// impossible because the handler signs the child with the local keypair,
// breaking §5.5 chain validation when the caller is remote). The caller
// MUST hold the parent directly (parent.grantee == caller's authenticated
// identity). The minted child has granter = grantee = caller's identity.
// Third-party handoff (grantee = some other peer) is deferred to a future
// amendment.
//
// Per closeout F1 §2.1-§2.2, the same-peer gate is the first substantive
// check after authority + caller-cap presence: cross-peer delegate is a
// "missing-mechanism" case (501 unsupported_operation), not a missing-
// authority case (403). 501 fires before payload validation, parent
// lookup, or direct-hold so remote callers are routed to client-side
// attenuation without leaking parent-existence side-channels.
func (h *Handler) handleDelegate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	h.mu.RLock()
	ready := h.ready
	keypair := h.keypair
	identity := h.identity
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"capability handler authority not yet wired (SetupAuthority pending)")
	}

	if hctx.CallerCapability.ContentHash.IsZero() {
		return handler.NewErrorResponse(401, "unauthenticated",
			"delegate requires an authenticated caller capability")
	}

	// Same-peer-only gate (V7 closeout F1) — fires before payload decode,
	// parent lookup, and direct-hold so remote callers get a clean 501
	// "this op doesn't exist in this dispatch context" without any
	// information about whether the named parent exists locally.
	if hctx.AuthorHash != identity.ContentHash {
		return handler.NewErrorResponse(501, "unsupported_operation",
			"delegate v1 is same-peer-only; cross-peer self-attenuation is unsupported (construct + sign the attenuated child client-side from the parent)")
	}

	var dr types.CapabilityDelegateRequestData
	if err := ecf.Decode(req.Params.Data, &dr); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode delegate-request: "+err.Error())
	}
	if dr.Parent.IsZero() {
		return handler.NewErrorResponse(400, "invalid_params",
			"delegate-request.parent MUST be a non-zero hash")
	}
	if len(dr.Grants) == 0 {
		return handler.NewErrorResponse(400, "invalid_params",
			"delegate-request must specify at least one grant entry")
	}

	parentEnt, ok := hctx.Store.Get(dr.Parent)
	if !ok && hctx.Included != nil {
		if e, includedOk := hctx.Included[dr.Parent]; includedOk {
			parentEnt = e
			ok = true
		}
	}
	if !ok {
		return handler.NewErrorResponse(404, "parent_not_found",
			"delegate parent token not in store: "+dr.Parent.String())
	}
	if parentEnt.Type != types.TypeCapToken {
		return handler.NewErrorResponse(400, "invalid_parent",
			"delegate parent must be system/capability/token, got: "+parentEnt.Type)
	}

	parentData, err := types.CapabilityTokenDataFromEntity(parentEnt)
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to decode parent token: "+err.Error())
	}

	// Direct-hold check (V7 v7.62 §9 + §15): caller MUST hold the parent
	// directly. Chain-walk authority (check_creator_authority) would
	// silently broaden authority and is explicitly NOT used here. Under
	// the same-peer gate above, caller == local peer, so direct-hold means
	// parent.grantee == local identity hash.
	if parentData.Grantee != hctx.AuthorHash {
		return handler.NewErrorResponse(403, "scope_exceeds_authority",
			"delegate requires direct-hold: parent.grantee MUST equal caller's authenticated identity")
	}

	if err := requireAttenuation(dr.Grants, parentData.Grants, hctx.LocalPeerID); err != nil {
		return handler.NewErrorResponse(403, "scope_exceeds_authority",
			"child grants exceed parent: "+err.Error())
	}

	createdAt := uint64(time.Now().UnixMilli())
	var expiresAt *uint64
	if dr.TTLMs != nil && *dr.TTLMs > 0 {
		exp := createdAt + *dr.TTLMs
		// MUST NOT exceed parent's remaining TTL.
		if parentData.ExpiresAt != nil && exp > *parentData.ExpiresAt {
			exp = *parentData.ExpiresAt
		}
		expiresAt = &exp
	} else if parentData.ExpiresAt != nil {
		exp := *parentData.ExpiresAt
		expiresAt = &exp
	}

	parentH := parentEnt.ContentHash
	childData := types.CapabilityTokenData{
		Grants:    dr.Grants,
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   hctx.AuthorHash,
		Parent:    &parentH,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	return h.mintAndReturn(hctx, keypair, identity, childData)
}

// handleRevoke is the universal revocation entry point (V7 v7.62 §5).
// Path-agnostic: looks up the cap's storage path via capability_path_for;
// if path-bound, tree-unbinds it; always writes a revocation marker at
// system/capability/revocations/{cap_hash_hex}.
//
// Authorization is uniform with every other handler op: the caller MUST
// hold a cap covering system/capability:revoke on the target. There is no
// granter-only carve-out (dropped in §15; broke operator use cases) and
// no cross-handler dispatch to role (also dropped; role's own ops cover
// context-level operations).
func (h *Handler) handleRevoke(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	h.mu.RLock()
	ready := h.ready
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"capability handler authority not yet wired (SetupAuthority pending)")
	}

	var rr types.CapabilityRevokeRequestData
	if err := ecf.Decode(req.Params.Data, &rr); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode revoke-request: "+err.Error())
	}
	if rr.Token.IsZero() {
		return handler.NewErrorResponse(400, "invalid_params",
			"revoke-request.token MUST be a non-zero hash")
	}

	// Build the marker. revoked_at is handler-set wall-clock millis per
	// §2a (caller-supplied values would be ignored even if the input
	// type carried one — it does not).
	marker := types.CapabilityRevocationData{
		Token:     rr.Token,
		Reason:    rr.Reason,
		RevokedAt: uint64(time.Now().UnixMilli()),
	}
	markerEnt, err := marker.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build revocation marker: "+err.Error())
	}
	if _, err := hctx.Store.Put(markerEnt); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store revocation marker: "+err.Error())
	}
	markerPath := corecap.RevocationPathFor(rr.Token)
	if _, err := hctx.TreeSet(markerPath, markerEnt.ContentHash, "capability-revoke"); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to bind revocation marker at "+markerPath+": "+err.Error())
	}

	// If the cap has a known storage path, tree-unbind it too (defense in
	// depth — covers both is_revoked checks). The capability_path_for
	// index returns the recorded binding; wire-only caps fall through with
	// nothing to unbind.
	if hctx.CapabilityIndex != nil {
		if capPath, ok := hctx.CapabilityIndex.PathFor(rr.Token); ok {
			hctx.TreeRemove(capPath, "capability-revoke")
		}
	}

	return handler.NewResponse(200, types.TypeCapRevocation, marker)
}

// handleConfigure writes a policy entry at
// system/capability/policy/{peer_pattern}.
//
// v7.65 §3.6 cap-pattern peer-reference canonicalization governs the
// peer_pattern semantics:
//
//   - **Hex form** (66 hex chars): canonical content_hash form per §1.5
//     mandate; stored as-is.
//   - **"default"**: literal fallback segment.
//   - **Base58 form** (Ed25519 wire peer_id): §3.6 rule 3 lazy-canonicalization
//     state. The mint succeeds with the pattern stored as Base58 (the
//     §3.6 `pending-canonicalization` state, represented in this impl as
//     "Base58-form entry exists; no hex-form entry exists yet"). On first
//     cap-match attempt, lookupPolicy + canonicalizePolicyEntry rewrite
//     the entry to hex form and delete the Base58 shadow (the §3.6
//     normative "canonicalize on first contact" event).
//
// The handler validates that peer_pattern is one of these three shapes;
// partial-prefix patterns, wildcards, and other malformed strings are
// rejected. Under §3.6 rule 3, Base58 mints for peers whose pubkey is
// not yet known to this peer emit a debug log advising the lazy-canon
// pending state.
func (h *Handler) handleConfigure(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context

	h.mu.RLock()
	ready := h.ready
	h.mu.RUnlock()
	if !ready {
		return handler.NewErrorResponse(503, "authority_not_ready",
			"capability handler authority not yet wired (SetupAuthority pending)")
	}

	var pe types.CapabilityPolicyEntryData
	if err := ecf.Decode(req.Params.Data, &pe); err != nil {
		return handler.NewErrorResponse(400, "invalid_params",
			"failed to decode policy-entry: "+err.Error())
	}
	if err := validatePeerPattern(pe.PeerPattern); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", err.Error())
	}
	if len(pe.Grants) == 0 {
		return handler.NewErrorResponse(400, "invalid_params",
			"policy-entry MUST specify at least one grant entry")
	}

	// v7.65 §3.6 rule 3 lazy-canonicalization: if the pattern is Base58
	// (wire peer_id form, not hex content_hash), check whether we can
	// canonicalize now. If the peer's public_key is reachable from the
	// pattern itself (identity-form PeerID), we could canonicalize at mint;
	// if not (SHA-256-form or pubkey-unknown identity-form), the entry stays
	// in pending state until first contact. Either way emit a debug log so
	// operators see the canonicalization trajectory.
	if h.debugLog != nil && pe.PeerPattern != policyFallbackSegment {
		isHexForm := (len(pe.PeerPattern) == peerPatternHexLenSHA256 || len(pe.PeerPattern) == peerPatternHexLenSHA384) && isHexString(pe.PeerPattern)
		if !isHexForm {
			// Pattern is Base58 (wire peer_id) — §3.6 lazy-canon mint.
			if pub, _, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(pe.PeerPattern)); ok {
				_ = pub
				h.debugLog("v7.65 §3.6 rule 3: Base58 identity-form peer_pattern minted; canonicalization deferred to first cap-match (lookupPolicy will rewrite hex+delete Base58); pattern=%s", pe.PeerPattern)
			} else {
				h.debugLog("v7.65 §3.6 rule 3: Base58 SHA-256-form peer_pattern minted for unknown peer; pending-canonicalization until handshake reveals public_key; pattern=%s", pe.PeerPattern)
			}
		}
	}

	entryEnt, err := pe.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build policy-entry: "+err.Error())
	}
	if _, err := hctx.Store.Put(entryEnt); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store policy-entry: "+err.Error())
	}
	policyPath := PolicyPathPrefix + "/" + pe.PeerPattern
	if _, err := hctx.TreeSet(policyPath, entryEnt.ContentHash, "capability-configure"); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to bind policy-entry at "+policyPath+": "+err.Error())
	}

	return handler.NewResponse(200, types.TypeCapPolicyEntry, pe)
}

// isHexString reports whether s consists only of lowercase hex digits.
// Used by handleConfigure to distinguish canonical hex peer_pattern from
// Base58 wire-form peer_pattern under v7.65 §3.6 rule 3.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// lookupPolicy resolves the policy entry for a caller. Returns (entry, false)
// when no policy applies.
//
// v7.65 §3.6 (canonicalization timing) supersedes the v7.64 dual-form
// semantics: the resolution order below is the legacy-decode site for §5
// wire-acceptance + §3.6 rule 3 lazy-canonicalization. Hex (canonical)
// always wins; Base58 fallback is the pending-canonicalization state and
// triggers canonicalizePolicyEntry on hit (rewrite hex, delete Base58).
//
// Per v7.65 §3.6, the resolution order is:
//
//  1. Hex form: PolicyPathPrefix/{caller_hex} — canonical, written when the
//     operator already has the peer's public_key / system/peer entity (always
//     available via DerivePeerFromPeerID for identity-form PeerIDs).
//  2. Base58 form: PolicyPathPrefix/{caller_peer_id_base58} — operator
//     convenience for SHA-256-form peers OR pre-tooling operator pasting a
//     handle before first contact. Resolves to the same peer; per §2.3
//     self-healing canonicalization, the handler MAY canonicalize on first
//     match (write hex, delete Base58 — both safe under partial failure).
//  3. Default: PolicyPathPrefix/default — fallback for unknown peers.
//
// If both hex and Base58 entries exist for the same peer (inconsistent state
// — should not happen with normal tooling), the hex form wins per §2.2.
func (h *Handler) lookupPolicy(hctx *handler.HandlerContext, caller hash.Hash, callerPeerID crypto.PeerID) (types.CapabilityPolicyEntryData, bool) {
	if hctx.LocationIndex == nil || hctx.Store == nil {
		return types.CapabilityPolicyEntryData{}, false
	}
	callerHex := hex.EncodeToString(caller.Bytes())
	// 1. Hex form: canonical precedence.
	if entry, ok := readPolicyEntry(hctx, callerHex); ok {
		return entry, true
	}
	// 2. Base58 form: pre-policy affordance for hash-form peers.
	if len(callerPeerID) > 0 {
		if entry, ok := readPolicyEntry(hctx, string(callerPeerID)); ok {
			// v7.65 §3.6 rule 3 lazy-canon canonicalization event:
			// the pattern was in pending state (Base58 form, no hex shadow);
			// first contact has revealed the caller's identity. Rewrite the
			// entry to canonical hex form and delete the Base58 shadow.
			// Both ops are idempotent; partial failure leaves the system in
			// a state where the next match heals it (hex precedence ensures
			// no double-apply). Emit a debug log so operators see the canon
			// trajectory.
			if h.debugLog != nil {
				h.debugLog("v7.65 §3.6 rule 3: canonicalizing peer_pattern on first cap-match (Base58=%s → hex=%s)", callerPeerID, callerHex)
			}
			canonicalizePolicyEntry(hctx, entry, callerHex, string(callerPeerID))
			return entry, true
		}
	}
	// 3. Default-for-unknown-peers entry.
	if entry, ok := readPolicyEntry(hctx, policyFallbackSegment); ok {
		return entry, true
	}
	return types.CapabilityPolicyEntryData{}, false
}

// canonicalizePolicyEntry implements §2.3 self-healing canonicalization:
// write an equivalent hex-form entry, then delete the Base58 entry. Both
// ops are idempotent. Soft-fail on any error — the precedence rule in
// lookupPolicy means a partial state is correctly resolved on the next
// match (hex wins; Base58 is a redundant shadow that the next call retries
// to delete).
func canonicalizePolicyEntry(hctx *handler.HandlerContext, entry types.CapabilityPolicyEntryData, hexPattern, base58Pattern string) {
	// Build a hex-form entry with the same grants/metadata; only PeerPattern
	// changes. The new entry's content_hash is different from the Base58 one
	// (different peer_pattern bytes), so the canonicalization produces a new
	// entity on the store.
	canonical := entry
	canonical.PeerPattern = hexPattern
	canonicalEnt, err := canonical.ToEntity()
	if err != nil {
		return
	}
	if _, err := hctx.Store.Put(canonicalEnt); err != nil {
		return
	}
	hexPath := PolicyPathPrefix + "/" + hexPattern
	if _, err := hctx.TreeSet(hexPath, canonicalEnt.ContentHash, "capability-canonicalize"); err != nil {
		// Hex write failed; leave Base58 entry in place — next match retries.
		return
	}
	// Idempotent delete of the Base58 entry. Failure is non-fatal — next
	// match will retry the delete.
	base58Path := PolicyPathPrefix + "/" + base58Pattern
	_, _, _ = hctx.TreeRemove(base58Path, "capability-canonicalize")
}

func readPolicyEntry(hctx *handler.HandlerContext, pattern string) (types.CapabilityPolicyEntryData, bool) {
	path := PolicyPathPrefix + "/" + pattern
	h, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return types.CapabilityPolicyEntryData{}, false
	}
	ent, ok := hctx.Store.Get(h)
	if !ok {
		return types.CapabilityPolicyEntryData{}, false
	}
	entry, err := types.CapabilityPolicyEntryDataFromEntity(ent)
	if err != nil {
		return types.CapabilityPolicyEntryData{}, false
	}
	return entry, true
}

// validatePeerPattern enforces V7 v7.64 §6.2 dual-form policy pattern
// validation: peer_pattern is exactly ONE of:
//
//  1. The literal segment "default" (F8, fallback for unknown peers).
//  2. A 66-hex-char identity-hash invariant pointer (canonical hex form).
//  3. A valid Base58 PeerID (PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION
//     §2.1 — operator pre-policy affordance; resolves to the same peer the
//     hex form would at handshake time).
//
// Partial-prefix patterns and glob wildcards are rejected. The hex and
// Base58 patterns are length-disjoint for Ed25519 (66 hex chars vs ~46
// Base58 chars) so resolution unambiguously dispatches to one branch.
//
// V7.64 §2.4: this is a MUST validation — invalid peer_pattern returns
// 400 invalid_peer_pattern at configure-time so the configure cannot
// silently accept garbage that later breaks resolution.
func validatePeerPattern(p string) error {
	if p == policyFallbackSegment {
		return nil
	}
	// Reject obvious glob attempts before the length checks.
	if strings.ContainsRune(p, '*') {
		return fmt.Errorf("policy-entry.peer_pattern partial-prefix wildcards are rejected per V7 §4")
	}
	// Hex form: V7 §3.5 invariant-pointer width — 66 hex (SHA-256) or 98
	// hex (SHA-384). Both are valid canonical content-hash forms under
	// v7.70 §1.2 (the home format determines width per peer).
	if len(p) == peerPatternHexLenSHA256 || len(p) == peerPatternHexLenSHA384 {
		for _, c := range p {
			if !isHexChar(c) {
				return fmt.Errorf("policy-entry.peer_pattern: %d-char value contains non-hex character %q (expected canonical hex identity hash)", len(p), c)
			}
		}
		return nil
	}
	// Base58 form: must decode to a valid PeerID under v7.64.
	if pid := crypto.PeerID(p); pid.Validate() == nil {
		return nil
	}
	return fmt.Errorf("policy-entry.peer_pattern MUST be one of: %q, a %d- or %d-hex-char identity hash, or a valid Base58 PeerID (got len=%d, neither valid hex nor a decodable PeerID) — invalid_peer_pattern",
		policyFallbackSegment, peerPatternHexLenSHA256, peerPatternHexLenSHA384, len(p))
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// mintAndReturn signs the supplied token data, persists token +
// signature into the content store, and returns a system/capability/grant
// result with the issued token + signature + granter identity in `included`
// (V7 v7.62 §7 result envelope shape).
func (h *Handler) mintAndReturn(
	hctx *handler.HandlerContext,
	keypair crypto.Keypair,
	identity entity.Entity,
	childData types.CapabilityTokenData,
) (*handler.Response, error) {
	capEnt, err := childData.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build token entity: "+err.Error())
	}
	sig := keypair.Sign(capEnt.ContentHash.Bytes())
	sigEnt, err := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeString(keypair.KeyType),
		Signature: sig,
	}.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to build signature entity: "+err.Error())
	}
	if _, err := hctx.Store.Put(identity); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store granter identity: "+err.Error())
	}
	if _, err := hctx.Store.Put(capEnt); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store token entity: "+err.Error())
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return handler.NewErrorResponse(500, "internal",
			"failed to store signature entity: "+err.Error())
	}

	resp, err := handler.NewResponse(200, types.TypeCapGrant, types.CapabilityGrantData{
		Token: capEnt.ContentHash,
	})
	if err != nil {
		return nil, err
	}
	resp.Included = map[hash.Hash]entity.Entity{
		capEnt.ContentHash:   capEnt,
		sigEnt.ContentHash:   sigEnt,
		identity.ContentHash: identity,
	}
	// SDK SHOULD include the full authority chain for cross-peer use
	// (V7 v7.62 §7). When the child has a parent, walk the chain and
	// include each cap + its signature + its granter identity. Errors
	// here are non-fatal — the minted token is still returned with at
	// least the leaf bundle.
	if childData.Parent != nil {
		chainResolver := capabilityChainResolver(hctx)
		if parentEnt, ok := chainResolver(*childData.Parent); ok {
			addChainToIncluded(resp.Included, parentEnt, chainResolver, hctx)
		}
	}
	return resp, nil
}

// capabilityChainResolver resolves cap-chain ancestors out of the local
// store first, falling back to the envelope's included map (the
// store-then-included precedence used elsewhere).
func capabilityChainResolver(hctx *handler.HandlerContext) func(hash.Hash) (entity.Entity, bool) {
	return func(h hash.Hash) (entity.Entity, bool) {
		if hctx.Store != nil {
			if ent, ok := hctx.Store.Get(h); ok {
				return ent, true
			}
		}
		if hctx.Included != nil {
			if ent, ok := hctx.Included[h]; ok {
				return ent, true
			}
		}
		return entity.Entity{}, false
	}
}

// addChainToIncluded walks parent links from the given cap and adds each
// cap + signature + granter identity to `included`. Bounded by
// corecap chain depth via the standard CollectAuthorityChain primitive.
func addChainToIncluded(
	included map[hash.Hash]entity.Entity,
	cap entity.Entity,
	resolve func(hash.Hash) (entity.Entity, bool),
	hctx *handler.HandlerContext,
) {
	chain, err := corecap.CollectAuthorityChain(cap, resolve)
	if err != nil {
		return
	}
	for _, link := range chain {
		included[link.ContentHash] = link
		capData, err := types.CapabilityTokenDataFromEntity(link)
		if err != nil {
			continue
		}
		// Granter identity.
		if granterHash, single := capData.Granter.SingleHash(); single {
			if granterEnt, ok := resolve(granterHash); ok {
				included[granterHash] = granterEnt
			}
		}
		// Signature lives at the V7 §3.5 invariant pointer path.
		if granterHash, single := capData.Granter.SingleHash(); single {
			if granterEnt, ok := resolve(granterHash); ok {
				if granterData, err := types.PeerDataFromEntity(granterEnt); err == nil {
					// v7.65 §1.5/§3.5: peer_id derives from (public_key, key_type).
					if ktByte, ktOK := granterData.KeyTypeByte(); ktOK {
						if granterPID, pidErr := crypto.PeerIDFromPublicKey(granterData.PublicKey, ktByte); pidErr == nil {
							sigPath := types.InvariantSignaturePath(string(granterPID), link.ContentHash)
							if hctx.LocationIndex != nil {
								if sigHash, ok := hctx.LocationIndex.Get(sigPath); ok {
									if sigEnt, ok := resolve(sigHash); ok {
										included[sigHash] = sigEnt
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// requireAttenuation verifies that every entry in `child` is covered by
// some entry in `parent` (subset-validation per V7 §5.2 matches_scope).
func requireAttenuation(child, parent []types.GrantEntry, localPeerID crypto.PeerID) error {
	parentToken := types.CapabilityTokenData{Grants: parent}
	childToken := types.CapabilityTokenData{Grants: child}
	if !corecap.IsAttenuated(childToken, parentToken, localPeerID, localPeerID) {
		return fmt.Errorf("requested scope is not a subset of the bounding capability")
	}
	return nil
}
