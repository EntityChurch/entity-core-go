package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// ConnectionState tracks per-connection handshake progress.
type ConnectionState struct {
	Completed    bool
	Phase        string // "init", "awaiting_authenticate", "completed"
	RemotePeerID crypto.PeerID
	OurNonce     []byte
	TheirNonce   []byte
	// GrantedCapability is the capability token granted during connection.
	GrantedCapability *entity.Entity
	// FrameBudget is the connection's configured maximum response frame
	// size in bytes. Zero means use wire.MaxFrameSize (16 MiB default).
	// Per CONTENT v3.6 Amendment 1 §6.2 / §4.2: implementations MUST
	// consult the connection's configured budget when constructing
	// responses; receivers serving system/content:get use this value to
	// frame-chunk responses (move overflow entities to `missing`).
	FrameBudget uint64
	// ActiveHashFormat is the connection's negotiated content_hash_format
	// per V7 v7.69 §4.5a — both peers MUST author every transmitted entity
	// under this format. Set on the responder side at handleHello after
	// the §4.5 intersection; mirrored to the initiator after it parses
	// the hello response. Zero (hash.AlgorithmSHA256, 0x00) is the v7.66
	// default and the floor pre-negotiation.
	ActiveHashFormat byte
}

// EffectiveFrameBudget returns the configured FrameBudget when set,
// otherwise the wire-layer default (16 MiB).
func (s *ConnectionState) EffectiveFrameBudget() uint64 {
	if s != nil && s.FrameBudget > 0 {
		return s.FrameBudget
	}
	return defaultFrameBudget
}

// defaultFrameBudget mirrors wire.MaxFrameSize so the handler doesn't
// need to import wire (avoiding the dispatch → wire import direction).
const defaultFrameBudget uint64 = 16 * 1024 * 1024

// NewConnectionState creates initial connection state.
func NewConnectionState() *ConnectionState {
	return &ConnectionState{Phase: "init"}
}

// GrantResolver returns grants for a specific remote peer, or nil to fall through
// to static connectionGrants / DefaultConnectionGrants(). The remoteIdentityHash
// parameter is the content_hash of the remote peer's identity entity (computed
// from PeerData = peer_id + public_key + key_type) — passed so resolvers can
// look up tree state keyed by identity hash (e.g., agent-cert lookups by
// `attested = remoteIdentityHash` for the role extension's recognize-on-
// attestation policy mode per EXTENSION-ROLE §4.7).
type GrantResolver func(remotePeerID crypto.PeerID, remoteIdentityHash hash.Hash) []types.GrantEntry

// HandlerRegisteredFn reports whether a handler pattern is registered on
// this peer. Used by the §3 advertisement discipline check to filter out
// grants that reference unregistered handlers at connection time.
type HandlerRegisteredFn func(pattern string) bool

// ConnectHandler handles the system/protocol/connect path.
type ConnectHandler struct {
	localKeypair       crypto.Keypair
	localPeerID        crypto.PeerID
	localIdentity      entity.Entity
	protocols          []string
	connectionGrants   []types.GrantEntry // nil means use DefaultConnectionGrants()
	grantResolver      GrantResolver      // nil means skip dynamic resolution
	handlerRegistered  HandlerRegisteredFn // nil means skip discipline check
	debugLog           func(format string, args ...any) // nil → silent; v7.65 §5 wire-acceptance debug

	// V7.69 §4.5 — what this peer advertises in hello negotiation.
	// hash_formats: preference-ordered list of content_hash_format strings
	// this peer can author/verify. First entry is the preferred format.
	// key_types: set of key_type strings this peer can verify signatures
	// for (NOT identity-bound; the peer's own key_type lives in
	// localKeypair). Both default to a derived set in DefaultAdvertisedSets
	// if NewConnectHandler does not get explicit overrides.
	advertisedHashFormats []string
	advertisedKeyTypes    []string

	// R6: granter-side idempotency anchor is now the per-peer session
	// entity at /{local}/system/peer/session/{remote}, written by
	// handleAuthenticate via WriteSessionEntity. The pre-R6 in-memory
	// (grantee, granter, grants) cache (mintedCaps map + mintedMu) was
	// removed when R6 landed — its role is fully subsumed by the session
	// entity, which additionally survives process restart on durable
	// stores.
}

// NewConnectHandler creates a connect handler.
func NewConnectHandler(kp crypto.Keypair, protocols []string) (*ConnectHandler, error) {
	identity, err := kp.IdentityEntity()
	if err != nil {
		return nil, err
	}
	if len(protocols) == 0 {
		protocols = []string{"entity-core/1.0"}
	}
	return &ConnectHandler{
		localKeypair:          kp,
		localPeerID:           kp.PeerID(),
		localIdentity:         identity,
		protocols:             protocols,
		advertisedHashFormats: DefaultAdvertisedHashFormats(),
		advertisedKeyTypes:    DefaultAdvertisedKeyTypes(),
	}, nil
}

// DefaultAdvertisedHashFormats returns the hash_formats list this peer
// advertises by default. Derived from entity.DefaultHashAlgorithm():
// when the peer is configured for SHA-384 it advertises [sha384, sha256]
// (prefers SHA-384, willing to negotiate down); when configured for
// SHA-256 it advertises [sha256] (matches the v7.66 spec default).
// SetAdvertisedHashFormats overrides this.
func DefaultAdvertisedHashFormats() []string {
	switch entity.DefaultHashAlgorithm() {
	case hash.AlgorithmSHA384:
		return []string{"ecfv1-sha384", "ecfv1-sha256"}
	default:
		return []string{"ecfv1-sha256"}
	}
}

// DefaultAdvertisedKeyTypes returns the key_types accept-set this peer
// advertises by default. Includes every key_type this impl can verify
// signatures for — currently Ed25519 (0x01) and Ed448 (0x02). Note:
// key_types is NOT identity-bound (the peer's own signing key_type is
// fixed in localKeypair); this list is the set of foreign key_types we
// can VERIFY (V7 v7.69 §4.5).
func DefaultAdvertisedKeyTypes() []string {
	return []string{
		crypto.KeyTypeString(crypto.KeyTypeEd25519),
		crypto.KeyTypeString(crypto.KeyTypeEd448),
	}
}

// SetAdvertisedHashFormats overrides the hello-advertised hash_formats.
// Preference order matters: first is preferred. Must include at least
// one format this peer implements; passing nil resets to
// DefaultAdvertisedHashFormats().
func (h *ConnectHandler) SetAdvertisedHashFormats(formats []string) {
	if formats == nil {
		h.advertisedHashFormats = DefaultAdvertisedHashFormats()
		return
	}
	h.advertisedHashFormats = formats
}

// SetAdvertisedKeyTypes overrides the hello-advertised key_types
// accept-set. nil resets to DefaultAdvertisedKeyTypes().
func (h *ConnectHandler) SetAdvertisedKeyTypes(kts []string) {
	if kts == nil {
		h.advertisedKeyTypes = DefaultAdvertisedKeyTypes()
		return
	}
	h.advertisedKeyTypes = kts
}

// hashFormatStringToAlgorithm maps the canonical hash_formats wire string
// to the algorithm byte. Returns 0xFF + false when the string is not
// supported by this impl.
func hashFormatStringToAlgorithm(s string) (byte, bool) {
	switch s {
	case "ecfv1-sha256":
		return hash.AlgorithmSHA256, true
	case "ecfv1-sha384":
		return hash.AlgorithmSHA384, true
	default:
		return 0xFF, false
	}
}

// firstMatchInOrder returns the first element of orderedList that also
// appears in acceptSet, or "" if there is no overlap. Per V7 v7.69 §4.5
// the "initiator's preference order" rule: the responder honors the
// first value the initiator lists that it also supports.
func firstMatchInOrder(orderedList []string, acceptSet []string) string {
	for _, v := range orderedList {
		for _, w := range acceptSet {
			if v == w {
				return v
			}
		}
	}
	return ""
}

// containsString reports whether s is in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (h *ConnectHandler) Name() string { return "connect" }

// SetConnectionGrants overrides the default connection grants.
func (h *ConnectHandler) SetConnectionGrants(grants []types.GrantEntry) {
	h.connectionGrants = grants
}

// SetDebugLog wires a debug-log sink for v7.65 §5 non-canonical wire
// acceptance and §6 lazy-canonicalization events. nil-safe; default silent.
func (h *ConnectHandler) SetDebugLog(fn func(format string, args ...any)) {
	h.debugLog = fn
}

// SetGrantResolver sets a dynamic grant resolver that is consulted before
// static connectionGrants. If the resolver returns nil, the handler falls
// through to connectionGrants or DefaultConnectionGrants().
func (h *ConnectHandler) SetGrantResolver(r GrantResolver) {
	h.grantResolver = r
}

// SetHandlerRegisteredFn wires the V7 v7.62 §3 "advertisement discipline"
// predicate: at authenticate-response build time, the resolved grant set is
// filtered so that any grant referencing a handler pattern NOT registered on
// this peer is dropped. Per §3, advertising an unbacked grant is non-
// conformant (the cross-peer 404_handler_not_found at dispatch breaks the
// contract the grant implies). Filtering at advertise time avoids the bogus
// promise rather than papering over the breakage.
//
// nil disables the check — the resolved grant set is delivered unmodified.
// The peer builder wires this with the dispatcher's registry.
func (h *ConnectHandler) SetHandlerRegisteredFn(fn HandlerRegisteredFn) {
	h.handlerRegistered = fn
}

// Manifest returns the handler's self-description for the system tree.
func (h *ConnectHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "system/protocol/connect",
		Name:    "connect",
		Operations: map[string]types.HandlerOperationSpec{
			"hello":        {InputType: types.TypeHello, OutputType: types.TypeHello},
			"authenticate": {InputType: types.TypeAuthenticate, OutputType: types.TypeCapGrant},
		},
	}
}

// RegisterTypes registers connect-specific types into the registry.
func (h *ConnectHandler) RegisterTypes(r *types.TypeRegistry) {
	r.ReflectType(types.TypeHello, reflect.TypeOf(types.HelloData{}))
	r.ReflectType(types.TypeAuthenticate, reflect.TypeOf(types.AuthenticateData{}))

	// Semantic type overrides for peer_id fields.
	r.OverrideField(types.TypeHello, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(types.TypeAuthenticate, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
}

// Handle processes connect operations (hello, authenticate).
func (h *ConnectHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "hello":
		return h.handleHello(ctx, req)
	case "authenticate":
		return h.handleAuthenticate(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation", "unknown connect operation: "+req.Operation)
	}
}

func (h *ConnectHandler) handleHello(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	// v7.66 §4.4 surface 6 / §7.1 + v7.67 §3: reject unsupported peer_id
	// key_types at the earliest handshake boundary. Accept the production
	// allocations Ed25519 (0x01) and Ed448 (0x02); reject the 0x03–0xEF
	// reserved range, the 0xF0–0xFE experimental range including the
	// v7.66 §4 test stub 0xFE, and 0xFF protocol-reserved. handleAuthenticate
	// has the same check as defense-in-depth.
	var helloDataIn types.HelloData
	helloDecoded := ecf.Decode(req.Params.Data, &helloDataIn) == nil
	if helloDecoded && helloDataIn.PeerID != "" {
		if h.debugLog != nil {
			h.debugLog("v7.66 §4.4 surface 6: handleHello inbound peer_id=%s", helloDataIn.PeerID)
		}
		claimedPeerID := crypto.PeerID(helloDataIn.PeerID)
		if dec, derr := claimedPeerID.Decode(); derr == nil {
			switch dec.KeyType {
			case crypto.KeyTypeEd25519, crypto.KeyTypeEd448:
				// supported
			default:
				return handler.NewErrorResponse(400, "unsupported_key_type",
					fmt.Sprintf("this peer supports sign/verify for key_type=0x%02x (Ed25519) and 0x%02x (Ed448) only; received hello with key_type=0x%02x (v7.66 §4.4 surface 6 / v7.67 §3)",
						crypto.KeyTypeEd25519, crypto.KeyTypeEd448, dec.KeyType))
			}
		}
	}

	// V7 v7.69 §4.5 — hash_formats: single-active-value negotiation.
	// Initiator's preference order, first match in responder's set is the
	// connection's active content_hash_format. Empty initiator set
	// defaults to ["ecfv1-sha256"] per the §4.5 default (v7.66 backward
	// compat: peers that don't advertise are treated as SHA-256-only).
	initiatorHashFormats := helloDataIn.HashFormats
	if len(initiatorHashFormats) == 0 {
		initiatorHashFormats = []string{"ecfv1-sha256"}
	}
	activeFormatString := firstMatchInOrder(initiatorHashFormats, h.advertisedHashFormats)
	if activeFormatString == "" {
		return handler.NewErrorResponse(400, "incompatible_hash_format",
			fmt.Sprintf("no common content_hash_format: initiator=%v responder=%v (V7 v7.69 §4.5)",
				initiatorHashFormats, h.advertisedHashFormats))
	}
	activeFormat, ok := hashFormatStringToAlgorithm(activeFormatString)
	if !ok {
		// firstMatchInOrder only returns strings we know we advertised,
		// so this should be unreachable — defensive.
		return handler.NewErrorResponse(400, "incompatible_hash_format",
			fmt.Sprintf("negotiated %q has no algorithm mapping", activeFormatString))
	}

	// V7 v7.69 §4.5 — key_types: accept-set with mutual-verifiability gate.
	// Each peer's own key_type MUST appear in the other's advertised set.
	// Initiator-advertised empty defaults to ["ed25519"] per §4.5 default.
	initiatorKeyTypes := helloDataIn.KeyTypes
	if len(initiatorKeyTypes) == 0 {
		initiatorKeyTypes = []string{"ed25519"}
	}
	ownKeyTypeString := crypto.KeyTypeString(h.localKeypair.KeyType)
	if !containsString(initiatorKeyTypes, ownKeyTypeString) {
		return handler.NewErrorResponse(400, "unsupported_key_type",
			fmt.Sprintf("responder's own key_type %q is not in initiator's key_types %v — mutual-verifiability violated (V7 v7.69 §4.5)",
				ownKeyTypeString, initiatorKeyTypes))
	}
	// Initiator's own key_type is reported on the wire via the peer_id
	// prefix (decoded above); if it's allocated (Ed25519 / Ed448) it is
	// in our accept-set by construction (DefaultAdvertisedKeyTypes covers
	// both), so the symmetric check is implicit. Custom-set deployments
	// using SetAdvertisedKeyTypes that omit one allocated type will
	// instead reject at the authenticate-side key_type switch.

	// Generate our nonce.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Update connection state. ActiveHashFormat is the per-§4.5a authoring
	// format used by handleAuthenticate when minting cap + cap-signature
	// + the local identity entity for this connection's response.
	if cs, ok := req.Context.ConnectionState.(*ConnectionState); ok && cs != nil {
		cs.OurNonce = nonce
		cs.Phase = "awaiting_authenticate"
		cs.ActiveHashFormat = activeFormat
	}

	helloData := types.HelloData{
		PeerID:      string(h.localPeerID),
		Nonce:       nonce,
		Protocols:   h.protocols,
		Timestamp:   uint64(time.Now().UnixMilli()),
		HashFormats: h.advertisedHashFormats,
		KeyTypes:    h.advertisedKeyTypes,
	}
	// Author the hello-response entity under the negotiated active format
	// (V7 v7.69 §4.5a item 1) — the responder knows the active format by
	// the time it builds its response.
	rawHello, err := ecf.Encode(helloData)
	if err != nil {
		return nil, err
	}
	helloEntity, err := entity.NewEntityFormat(activeFormat, types.TypeHello, cbor.RawMessage(rawHello))
	if err != nil {
		return nil, err
	}

	return &handler.Response{
		Status: 200,
		Result: helloEntity,
	}, nil
}

func (h *ConnectHandler) handleAuthenticate(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	// Decode authenticate params.
	var authenticateData types.AuthenticateData
	if err := ecf.Decode(req.Params.Data, &authenticateData); err != nil {
		return handler.NewErrorResponse(400, "invalid_authenticate", "could not decode authenticate data")
	}

	// v7.66 §4.4 surface 6 / §7.1: unsupported key_type rejection. This
	// peer implements sign/verify for the production-allocated key_types
	// only — Ed25519 (0x01) and Ed448 (0x02, v7.67 §3). Every other
	// allocated/unallocated key_type (the v7.66 §4.3 0x03–0xEF reserved
	// range, the 0xF0–0xFE experimental range including the test stub
	// 0xFE, and 0xFF protocol-reserved) returns `400 unsupported_key_type`
	// at the handshake boundary rather than reaching identity_mismatch.
	// This is the V7 §4.7 contract code; surface fires before peer_id
	// decode so an unsupported wire prefix never produces a misleading
	// "identity mismatch" error.
	claimedPeerID := crypto.PeerID(authenticateData.PeerID)
	var claimedKeyType byte
	if dec, decErr := claimedPeerID.Decode(); decErr == nil {
		claimedKeyType = dec.KeyType
		switch dec.KeyType {
		case crypto.KeyTypeEd25519, crypto.KeyTypeEd448:
			// supported
		default:
			return handler.NewErrorResponse(400, "unsupported_key_type",
				fmt.Sprintf("this peer supports sign/verify for key_type=0x%02x (Ed25519) and 0x%02x (Ed448) only; received 0x%02x (v7.66 §4.4 surface 6 / v7.67 §3)",
					crypto.KeyTypeEd25519, crypto.KeyTypeEd448, dec.KeyType))
		}
	}
	// Verify public key matches peer_id.
	if !claimedPeerID.VerifyPublicKey(authenticateData.PublicKey) {
		return handler.NewErrorResponse(401, "identity_mismatch", "public key does not match peer_id")
	}

	// v7.65 §5 wire-acceptance carve-out: impls SHOULD debug-log non-canonical
	// wire form acceptance. Canonical hash_type is per-key_type
	// (CanonicalHashType): Ed25519 → identity-multihash (0x00),
	// Ed448 → SHA-256-form (0x01).
	if dec, decErr := claimedPeerID.Decode(); decErr == nil {
		if canon, canonErr := crypto.CanonicalHashType(dec.KeyType); canonErr == nil && dec.HashType != canon {
			if h.debugLog != nil {
				h.debugLog("v7.65 §5: non-canonical wire peer_id (key_type=0x%02x, hash_type=0x%02x; canonical hash_type=0x%02x) accepted (peer_id=%s)",
					dec.KeyType, dec.HashType, canon, claimedPeerID)
			}
		}
	}

	// §4.6 proof-of-possession (SPEC-FINDING F12). The peer_id↔public_key
	// check above only proves internal consistency of *public* data — a
	// peer's identity is not secret, so on its own it authenticates nobody.
	// Two more checks are required, and were both missing pre-F12:
	//
	//   (a) The authenticate MUST echo the exact nonce we issued on hello,
	//       binding the proof to *this* connection's challenge. Without it,
	//       an authenticate captured on one connection replays on another.
	//   (b) The authenticate MUST carry a valid signature by the claimed
	//       key over the authenticate entity (which commits to that nonce),
	//       proving the connecting party holds the private key — not just
	//       knowledge of the (public) identity.
	//
	// Failures are authentication-class → 401 (identity not established).
	cs, _ := req.Context.ConnectionState.(*ConnectionState)
	if cs == nil || len(cs.OurNonce) == 0 {
		return handler.NewErrorResponse(401, "invalid_nonce", "no issued nonce to verify against (hello must precede authenticate)")
	}
	if !bytes.Equal(authenticateData.Nonce, cs.OurNonce) {
		return handler.NewErrorResponse(401, "invalid_nonce", "authenticate nonce does not echo the issued hello nonce")
	}
	authSig, ok := (entity.Envelope{Included: req.Context.Included}).FindSignatureFor(req.Params.ContentHash)
	if !ok {
		return handler.NewErrorResponse(401, "authentication_failed", "no signature found for authenticate entity")
	}
	authSigData, err := types.SignatureDataFromEntity(authSig)
	if err != nil {
		return handler.NewErrorResponse(401, "authentication_failed", "invalid authenticate signature entity")
	}
	if !crypto.Verify(claimedKeyType, authenticateData.PublicKey, req.Params.ContentHash.Bytes(), authSigData.Signature) {
		return handler.NewErrorResponse(401, "authentication_failed", "authenticate signature verification failed")
	}

	// Create connection capability for the remote peer.
	// V7.69 §1.8 application — identity references. The connecting peer's
	// authored identity content_hash is carried on the wire as
	// signature.signer (just verified at §5.2 above). We MUST use that
	// authored hash directly and MUST NOT rebuild the identity entity and
	// rehash it under our local format. Under §4.5a both peers author
	// under the connection's active format, so the wire-authored hash IS
	// the canonical reference. Re-deriving would manufacture a second
	// content_hash for one identity (the v7.69 trigger bug).
	remoteIdentityContentHash := authSigData.Signer

	// v7.65 §5 wire-acceptance carve-out: the remote's wire peer_id
	// (authenticateData.PeerID) is the presentation layer; the stored
	// system/peer entity is in v7.65 canonical shape ({public_key,
	// key_type}). The wire peer_id is still carried on the connection
	// for routing/display, but it is not part of the entity's hashable
	// basis.

	// Resolve grants: dynamic resolver → static overrides → defaults.
	// remoteIdentityContentHash is the connecting peer's `system/peer`
	// entity hash — what role / identity / quorum extensions key tree
	// state by (e.g., agent-cert lookups by `attested = remoteIdentityHash`
	// for the role extension's recognize-on-attestation policy mode).
	var grants []types.GrantEntry
	if h.grantResolver != nil {
		grants = h.grantResolver(claimedPeerID, remoteIdentityContentHash)
	}
	if grants == nil && h.connectionGrants != nil {
		grants = h.connectionGrants
	}
	if grants == nil {
		grants = DefaultConnectionGrants()
	}
	// V7 v7.62 §8: policy-table consultation at authenticate-response.
	// Initial grant scope delivered to A is the UNION of the §4.4 SHOULD
	// floor (whatever was resolved above) and any matching policy entry
	// at system/capability/policy/{caller_hex} (or `default` fallback).
	//
	// "No-op when capability handler is not installed" is satisfied by
	// construction: if the cap handler isn't installed, no policy entries
	// exist in the tree, so the lookup returns nothing and the union
	// reduces to the floor.
	//
	// Topology asymmetry (§8): handshake is UNION (initial grant builds
	// UP from nothing); runtime request is subset-validation (request
	// narrows DOWN from existing cap). Both consult the same policy
	// table — single source of truth, opposite assembly direction.
	if req.Context != nil && req.Context.LocationIndex != nil && req.Context.Store != nil {
		if policyGrants := readHandshakePolicyGrants(req.Context, remoteIdentityContentHash, claimedPeerID); len(policyGrants) > 0 {
			grants = append(append([]types.GrantEntry(nil), grants...), policyGrants...)
		}
	}
	// V7 v7.62 §3 advertisement discipline: drop any grant entry whose
	// `handlers.include` references a handler not registered on this peer.
	// Advertising an unbacked grant is non-conformant — the cross-peer
	// behavior is `404 handler_not_found` at the dispatch boundary, which
	// breaks the contract the grant implies. The peer builder wires
	// handlerRegistered with the dispatcher's registry.
	if h.handlerRegistered != nil {
		grants = filterAdvertisedGrants(grants, h.handlerRegistered)
	}
	// R3a idempotency, §9.1 R6-a form: read minted_capability from the
	// per-peer session entity at /{local}/system/peer/session/{remote}.
	// If the cached cap's resolved grants still match (ECF byte equality
	// over the GrantEntry list) and the cap is still live, reuse it —
	// same content hash on every handshake, no CreatedAt churn. On miss /
	// grant change / expiry, mint fresh and overwrite the entity in place
	// (§9.1 R6-e mint-fresh-overwrite). The session entity in the tree is
	// the authoritative idempotency anchor (in-memory mintedCaps deleted
	// in the pre-§9 R6 land; this is the §9.3 schema landing on top).
	now := uint64(time.Now().UnixMilli())
	var capEntity, capSigEntity entity.Entity
	// responseLocalIdentity is the local identity entity authored under
	// the connection's active format (v7.69 §4.5a). For the cached-cap
	// reuse path it stays as the peer-startup-time h.localIdentity (which
	// is the form the cached cap's Granter was minted under); for the
	// fresh-mint path it is re-derived under cs.ActiveHashFormat.
	responseLocalIdentity := h.localIdentity
	found := false
	if req.Context != nil && req.Context.Store != nil && req.Context.LocationIndex != nil {
		if mintedCap, ok := ReadMintedCapability(
			req.Context.Store,
			req.Context.LocationIndex,
			string(h.localPeerID),
			remoteIdentityContentHash,
		); ok {
			if cachedTok, decErr := types.CapabilityTokenDataFromEntity(mintedCap); decErr == nil {
				grantsMatch, _ := capGrantsEqual(cachedTok.Grants, grants)
				live := cachedTok.ExpiresAt == nil || now < *cachedTok.ExpiresAt
				// V7 v7.69 §4.5a item 5 — cap chains don't cross format
				// boundaries. A cached cap whose own content_hash format
				// differs from this connection's active format cannot be
				// transmitted on this connection. Mint fresh instead.
				formatMatches := mintedCap.ContentHash.Algorithm == cs.ActiveHashFormat
				if grantsMatch && live && formatMatches {
					sigPath := types.InvariantSignaturePath(string(h.localPeerID), mintedCap.ContentHash)
					if sigHash, sigOK := req.Context.LocationIndex.Get(sigPath); sigOK {
						if sigEnt, sigStoreOK := req.Context.Store.Get(sigHash); sigStoreOK {
							capEntity = mintedCap
							capSigEntity = sigEnt
							// Recompute responseLocalIdentity in the matching
							// format so its hash lines up with mintedCap.Granter.
							if rid, ridErr := h.localKeypair.IdentityEntityFormat(mintedCap.ContentHash.Algorithm); ridErr == nil {
								responseLocalIdentity = rid
							}
							found = true
						}
					}
				}
			}
		}
	}
	if !found {
		// V7 v7.69 §4.5a item 1 — every transmitted entity authored
		// under the connection's active format. Re-derive the local
		// identity entity under activeFormat so cap.Granter and
		// signature.Signer name the *same* identity-hash form as
		// anything we previously placed on the wire (the responder's
		// own hello-response was authored under activeFormat too). The
		// peer-startup-time h.localIdentity may be under a different
		// format (the process default) and would otherwise create a
		// cross-format Granter reference inside an active-format chain.
		localIdEntityForConn, lidErr := h.localKeypair.IdentityEntityFormat(cs.ActiveHashFormat)
		if lidErr != nil {
			return nil, lidErr
		}
		responseLocalIdentity = localIdEntityForConn

		capToken := types.CapabilityTokenData{
			Grants:    grants,
			Granter:   types.SingleSigGranter(localIdEntityForConn.ContentHash),
			Grantee:   remoteIdentityContentHash,
			CreatedAt: now,
		}
		capTokenRaw, ctErr := ecf.Encode(capToken)
		if ctErr != nil {
			return nil, ctErr
		}
		capEntity, err = entity.NewEntityFormat(cs.ActiveHashFormat, types.TypeCapToken, cbor.RawMessage(capTokenRaw))
		if err != nil {
			return nil, err
		}

		// Sign the capability token. Algorithm string tracks the local
		// keypair's key_type (v7.67 §3 crypto-agility); the entity is
		// hashed under the connection's active format (v7.69 §4.5a).
		capSig := h.localKeypair.Sign(capEntity.ContentHash.Bytes())
		capSigData := types.SignatureData{
			Target:    capEntity.ContentHash,
			Signer:    localIdEntityForConn.ContentHash,
			Algorithm: crypto.KeyTypeString(h.localKeypair.KeyType),
			Signature: capSig,
		}
		capSigRaw, csErr := ecf.Encode(capSigData)
		if csErr != nil {
			return nil, csErr
		}
		capSigEntity, err = entity.NewEntityFormat(cs.ActiveHashFormat, types.TypeSignature, cbor.RawMessage(capSigRaw))
		if err != nil {
			return nil, err
		}

		// §9.1 R6-e: persist cap + cap-signature + the session entity's
		// minted_capability so the next handshake from this peer reuses
		// the same cap hash. WriteMintedSession is read-modify-write so
		// any held_capability already at this path (from a prior dialer-
		// side write where we were the dialer) is preserved.
		if req.Context != nil && req.Context.Store != nil && req.Context.LocationIndex != nil {
			if _, putErr := req.Context.Store.Put(capEntity); putErr == nil {
				_, _ = req.Context.Store.Put(capSigEntity)
				sigPath := types.InvariantSignaturePath(string(h.localPeerID), capEntity.ContentHash)
				_ = req.Context.LocationIndex.Set(sigPath, capSigEntity.ContentHash)
				expiresAt := uint64(0)
				if capToken.ExpiresAt != nil {
					expiresAt = *capToken.ExpiresAt
				}
				_, _ = WriteMintedSession(
					req.Context.Store,
					req.Context.LocationIndex,
					string(h.localPeerID),
					string(claimedPeerID),
					authenticateData.PublicKey,
					remoteIdentityContentHash,
					capEntity,
					now,
					expiresAt,
				)
			}
		}
	}

	// Build capability grant result.
	grantData := types.CapabilityGrantData{
		Token: capEntity.ContentHash,
	}
	grantEntity, err := grantData.ToEntity()
	if err != nil {
		return nil, err
	}

	// Update connection state.
	cs.Completed = true
	cs.Phase = "completed"
	cs.RemotePeerID = claimedPeerID
	cs.GrantedCapability = &capEntity

	// Return the grant entity as result, with supporting entities in Included.
	// responseLocalIdentity is the active-format local identity entity
	// (v7.69 §4.5a) — its ContentHash is what cap.Granter / capSig.Signer
	// reference, so it must be the entity placed in Included.
	return &handler.Response{
		Status: 200,
		Result: grantEntity,
		Included: map[hash.Hash]entity.Entity{
			responseLocalIdentity.ContentHash: responseLocalIdentity,
			capEntity.ContentHash:             capEntity,
			capSigEntity.ContentHash:          capSigEntity,
		},
	}, nil
}

// capGrantsEqual compares two GrantEntry lists for byte-level equivalence
// over their ECF deterministic encoding. Used by R3a (in its R6 form) to
// decide whether a cached session's cap-grants still match the grants
// resolved on this handshake. Mismatch ⇒ mint fresh; match ⇒ reuse the
// session's existing cap (idempotent hash).
func capGrantsEqual(a, b []types.GrantEntry) (bool, error) {
	aRaw, err := ecf.Encode(a)
	if err != nil {
		return false, err
	}
	bRaw, err := ecf.Encode(b)
	if err != nil {
		return false, err
	}
	if len(aRaw) != len(bRaw) {
		return false, nil
	}
	for i := range aRaw {
		if aRaw[i] != bRaw[i] {
			return false, nil
		}
	}
	return true, nil
}


// CreateHelloExecute creates a connect hello EXECUTE envelope. Populates
// hash_formats and key_types per V7 v7.69 §4.5 — preference-ordered list
// of formats this peer supports (derived from
// entity.DefaultHashAlgorithm()) and the accept-set of key_types this
// peer can verify (Ed25519 + Ed448).
func CreateHelloExecute(kp crypto.Keypair, protocols []string) (entity.Envelope, []byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return entity.Envelope{}, nil, err
	}

	if len(protocols) == 0 {
		protocols = []string{"entity-core/1.0"}
	}

	helloData := types.HelloData{
		PeerID:      string(kp.PeerID()),
		Nonce:       nonce,
		Protocols:   protocols,
		Timestamp:   uint64(time.Now().UnixMilli()),
		HashFormats: DefaultAdvertisedHashFormats(),
		KeyTypes:    DefaultAdvertisedKeyTypes(),
	}
	helloEntity, err := helloData.ToEntity()
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	paramsRaw, err := ecf.Encode(helloEntity)
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	execData := types.ExecuteData{
		RequestID: "connect-hello",
		URI:       connectPath,
		Operation: "hello",
		Params:    cbor.RawMessage(paramsRaw),
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, nil, err
	}

	return entity.NewEnvelope(execEntity, nil), nonce, nil
}

// NegotiateActiveHashFormat applies the V7 v7.69 §4.5 single-active-value
// rule to the initiator's advertised hash_formats and the responder's
// hello-response hash_formats. The responder's hello-response carries
// the responder's advertised set; the initiator (which knows its own
// preference order) re-runs the first-match-in-initiator-order intersection
// to confirm the active format, then uses it for authoring authenticate
// and signature entities (§4.5a item 1).
//
// initiatorPrefs is the initiator's own advertised list (preference order);
// responderAdvertised is the list carried back in the responder's hello.
// Returns the algorithm byte and the wire-string. An empty intersection
// yields ok=false; callers should fail the handshake with
// incompatible_hash_format.
func NegotiateActiveHashFormat(initiatorPrefs, responderAdvertised []string) (byte, string, bool) {
	if len(initiatorPrefs) == 0 {
		initiatorPrefs = []string{"ecfv1-sha256"}
	}
	if len(responderAdvertised) == 0 {
		responderAdvertised = []string{"ecfv1-sha256"}
	}
	match := firstMatchInOrder(initiatorPrefs, responderAdvertised)
	if match == "" {
		return 0, "", false
	}
	alg, ok := hashFormatStringToAlgorithm(match)
	if !ok {
		return 0, match, false
	}
	return alg, match, true
}

// CreateAuthenticateExecute creates a connect authenticate EXECUTE envelope.
// Backward-compat wrapper: uses entity.DefaultHashAlgorithm() as the active
// format. Per V7 v7.69 §4.5a, callers that performed the §4.5 negotiation
// SHOULD invoke CreateAuthenticateExecuteFormat with the negotiated
// active format instead.
func CreateAuthenticateExecute(kp crypto.Keypair, theirNonce []byte) (entity.Envelope, error) {
	return CreateAuthenticateExecuteFormat(kp, theirNonce, entity.DefaultHashAlgorithm())
}

// CreateAuthenticateExecuteFormat creates a connect authenticate EXECUTE
// envelope with every entity (identity, authenticate, signature) authored
// under activeFormat per V7 v7.69 §4.5a. The caller is responsible for
// extracting activeFormat from the hello-response via
// NegotiateActiveHashFormat applied to its own advertised list and the
// responder's hello.HashFormats.
func CreateAuthenticateExecuteFormat(kp crypto.Keypair, theirNonce []byte, activeFormat byte) (entity.Envelope, error) {
	identity, err := kp.IdentityEntityFormat(activeFormat)
	if err != nil {
		return entity.Envelope{}, err
	}

	authenticateData := types.AuthenticateData{
		PeerID:    string(kp.PeerID()),
		PublicKey: kp.PublicKeyBytes(),
		KeyType:   crypto.KeyTypeString(kp.KeyType),
		Nonce:     theirNonce,
	}
	authRaw, err := ecf.Encode(authenticateData)
	if err != nil {
		return entity.Envelope{}, err
	}
	authenticateEntity, err := entity.NewEntityFormat(activeFormat, types.TypeAuthenticate, cbor.RawMessage(authRaw))
	if err != nil {
		return entity.Envelope{}, err
	}

	// Sign the authenticate entity. Algorithm string tracks the keypair's
	// key_type (v7.67 §3 crypto-agility); the entity is hashed under the
	// connection's active format (v7.69 §4.5a).
	sig := kp.Sign(authenticateEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    authenticateEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeString(kp.KeyType),
		Signature: sig,
	}
	sigRaw, err := ecf.Encode(sigData)
	if err != nil {
		return entity.Envelope{}, err
	}
	sigEntity, err := entity.NewEntityFormat(activeFormat, types.TypeSignature, cbor.RawMessage(sigRaw))
	if err != nil {
		return entity.Envelope{}, err
	}

	paramsRaw, err := ecf.Encode(authenticateEntity)
	if err != nil {
		return entity.Envelope{}, err
	}

	execData := types.ExecuteData{
		RequestID: "connect-authenticate",
		URI:       connectPath,
		Operation: "authenticate",
		Params:    cbor.RawMessage(paramsRaw),
	}
	execRaw, err := ecf.Encode(execData)
	if err != nil {
		return entity.Envelope{}, err
	}
	execEntity, err := entity.NewEntityFormat(activeFormat, types.TypeExecute, cbor.RawMessage(execRaw))
	if err != nil {
		return entity.Envelope{}, err
	}

	return entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		identity.ContentHash:  identity,
		sigEntity.ContentHash: sigEntity,
	}), nil
}

// filterAdvertisedGrants drops grant entries whose handlers.include list
// references at least one handler not registered on this peer (V7 v7.62 §3).
// A grant whose handlers.include is empty (rare but legal) is passed through
// unmodified — it advertises no handler authority and so cannot mislead.
// All handler patterns in a grant's include list must resolve; if any one
// is unbacked, the entry is dropped (advertising a partial promise has the
// same "404 at dispatch" failure mode as advertising a fully bogus one).
func filterAdvertisedGrants(grants []types.GrantEntry, registered HandlerRegisteredFn) []types.GrantEntry {
	if len(grants) == 0 {
		return grants
	}
	out := make([]types.GrantEntry, 0, len(grants))
	for _, g := range grants {
		if !grantHandlersAllRegistered(g, registered) {
			continue
		}
		out = append(out, g)
	}
	return out
}

func grantHandlersAllRegistered(g types.GrantEntry, registered HandlerRegisteredFn) bool {
	for _, pattern := range g.Handlers.Include {
		// Bare "*" is the universal — "any handler" — and is always backed
		// by construction. Used by OpenAccessGrants and operator
		// configurations that intentionally span the whole handler space.
		if pattern == "*" {
			continue
		}
		// Other patterns may be exact (`system/tree`) or subtree wildcards
		// (`system/handler/*`). The advertisement discipline only requires
		// SOME registered handler matches the pattern at connect time — not
		// that every theoretically-matching path is backed. Resolve via the
		// registry's longest-prefix logic by stripping a trailing `/*` for
		// subtree patterns.
		base := pattern
		if strings.HasSuffix(base, "/*") {
			base = base[:len(base)-2]
		}
		if !registered(base) {
			return false
		}
	}
	return true
}

// handshakePolicyPathPrefix is the tree prefix the connect handler reads when
// unioning the §4.4 SHOULD floor with the capability handler's per-peer policy
// table. Mirrors ext/capability.PolicyPathPrefix verbatim — duplicated here
// rather than imported to keep core/protocol → ext/* import direction clean.
const handshakePolicyPathPrefix = "system/capability/policy"

// handshakePolicyFallbackSegment is the literal fallback path segment
// per V7 closeout F8 (renamed from "*" to "default"). Mirrors
// ext/capability.policyFallbackSegment.
const handshakePolicyFallbackSegment = "default"

// readHandshakePolicyGrants resolves the policy entry for a connecting peer
// via v7.64 dual-form resolution (PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION
// §2.5): hex → Base58 → `default`. Returns the matched entry's grants for
// unioning with the §4.4 SHOULD floor; nil when no policy applies.
//
// The connect handler resolves policy at AUTHENTICATE time when both the
// caller's identity hash (canonical) and Base58 PeerID are known. Operators
// who pre-policied under either form get matched at handshake.
//
// Canonicalization is NOT performed here — the connect handler runs as a
// read-only consumer of the policy table during handshake. The capability
// handler's lookupPolicy performs canonicalization on its own subsequent
// matches (in the request-time path); the handshake-time read at this site
// is satisfied by the resolution-only fallback.
func readHandshakePolicyGrants(hctx *handler.HandlerContext, callerIdentityHash hash.Hash, callerPeerID crypto.PeerID) []types.GrantEntry {
	callerHex := hex.EncodeToString(callerIdentityHash.Bytes())
	if entry, ok := readHandshakePolicyEntry(hctx, callerHex); ok {
		return entry.Grants
	}
	if len(callerPeerID) > 0 {
		if entry, ok := readHandshakePolicyEntry(hctx, string(callerPeerID)); ok {
			return entry.Grants
		}
	}
	if entry, ok := readHandshakePolicyEntry(hctx, handshakePolicyFallbackSegment); ok {
		return entry.Grants
	}
	return nil
}

func readHandshakePolicyEntry(hctx *handler.HandlerContext, pattern string) (types.CapabilityPolicyEntryData, bool) {
	path := handshakePolicyPathPrefix + "/" + pattern
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

// DefaultConnectionGrants returns the default connection capability grants per §4.4.
// Each grant specifies which handlers it applies to, which resource paths those
// handlers can access, and which operations are allowed.
func DefaultConnectionGrants() []types.GrantEntry {
	return []types.GrantEntry{
		// Tree handler: read type definitions and handler manifests.
		{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"system/type/*", "system/handler/*"}},
			Operations: types.CapabilityScope{Include: []string{"get"}},
		},
		// Capability handler: request capabilities.
		{
			Handlers:   types.CapabilityScope{Include: []string{"system/capability"}},
			Resources:  types.CapabilityScope{Include: []string{}},
			Operations: types.CapabilityScope{Include: []string{"request"}},
		},
	}
}

// ValidateConnectionSequence checks that the connection handshake operations
// are being called in the correct order.
func ValidateConnectionSequence(state *ConnectionState, operation string) error {
	switch operation {
	case "hello":
		if state.Completed {
			return ecerrors.ErrConnectionEstablished
		}
		return nil
	case "authenticate":
		if state.Completed {
			return ecerrors.ErrConnectionEstablished
		}
		if state.Phase != "awaiting_authenticate" {
			return fmt.Errorf("%w: expected hello first", ecerrors.ErrConnectionRequired)
		}
		return nil
	default:
		return fmt.Errorf("unknown connect operation: %s", operation)
	}
}
