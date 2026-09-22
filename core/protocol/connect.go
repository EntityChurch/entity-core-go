package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// ConnectionState tracks per-connection handshake progress.
type ConnectionState struct {
	Completed    bool
	Phase        string // "init", "awaiting_authenticate", "completed"
	RemotePeerID crypto.PeerID
	// HelloPeerID is the peer_id advertised in this connection's hello,
	// retained so handleAuthenticate can enforce §4.6's "MUST also verify
	// authenticate.peer_id == hello.peer_id for the same connection" — the
	// identity does not change mid-handshake. A mismatch is 401
	// identity_mismatch (§4.7 step-3 row). Empty until a hello is processed.
	HelloPeerID string
	OurNonce    []byte
	TheirNonce  []byte
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
	// ObservedAddress is the transport-layer source IP:port this peer
	// observed for the remote on THIS connection — the remote's public NAT
	// mapping, as seen from here. It is the narrow, NETWORK-scoped accept-side
	// fact EXTENSION-NETWORK §6.7.1 (observe-address) reflects back, and the
	// dial-back target §6.7.2 (check-reachability) proves. Set responder-side
	// at accept from the underlying net.Conn.RemoteAddr(); empty on
	// initiator-side and in-process states (no accepted transport source).
	//
	// It is a RESPONDER-SIDE fact with no durable home: per §6.7.1 MUST 2 it
	// MUST NOT be persisted to system/connection.address, a
	// system/peer/transport/* profile, or system/peer/status — every durable
	// address field in this spec is dialer-side dialable-endpoint state, and
	// an ephemeral source port written there routes nowhere yet reads as
	// dialable to §10. It is read from the live connection and returned; it is
	// never connection-state-of-record.
	ObservedAddress string
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

// AdvertisedScopeFn returns what this peer advertises it SERVES, as grant
// entries — the parent side of the §3 advertisement-discipline subset check
// (`EXTENSION-SIGNALING.md` §6.5 (b) Contents; arch 977667f).
//
// It is a function rather than a stored slice because handlers register
// throughout the builder and extensions register after the connect handler
// itself; evaluating at authenticate-time is what makes a late registration
// visible, exactly as the HandlerRegisteredFn closure did.
type AdvertisedScopeFn func() []types.GrantEntry

// ConnectHandler handles the system/protocol/connect path.
type ConnectHandler struct {
	localKeypair      crypto.Keypair
	localPeerID       crypto.PeerID
	localIdentity     entity.Entity
	protocols         []string
	connectionGrants  []types.GrantEntry               // nil means use DefaultConnectionGrants()
	grantResolver     GrantResolver                    // nil means skip dynamic resolution
	handlerRegistered HandlerRegisteredFn              // nil means skip discipline check
	advertisedScope   AdvertisedScopeFn                // nil means skip the §3 subset filter
	debugLog          func(format string, args ...any) // nil → silent; v7.65 §5 wire-acceptance debug

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

// anyInBoth reports whether a and b share at least one element — a non-empty
// intersection. Used for §4.5 protocols negotiation (incompatible_protocol).
func anyInBoth(a, b []string) bool {
	for _, s := range a {
		if containsString(b, s) {
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

// SetAdvertisedScopeFn supplies the served-scope the §3 advertisement filter
// checks assembled grants against. Wired by the peer builder from the handler
// registry; nil leaves the filter off.
func (h *ConnectHandler) SetAdvertisedScopeFn(fn AdvertisedScopeFn) {
	h.advertisedScope = fn
}

// Manifest returns the handler's self-description for the system tree.
func (h *ConnectHandler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: "system/protocol/connect",
		Name:    "connect",
		Operations: map[string]types.HandlerOperationSpec{
			"hello":        {InputType: types.TypeHello, OutputType: types.TypeHello},
			"authenticate": {InputType: types.TypeAuthenticate, OutputType: types.TypeCapGrant},
			"ping":         {InputType: types.TypeNetworkPing, OutputType: types.TypeNetworkPong},
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

// Handle processes connect operations (hello, authenticate, ping).
func (h *ConnectHandler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "hello":
		return h.handleHello(ctx, req)
	case "authenticate":
		return h.handleAuthenticate(ctx, req)
	case "ping":
		return h.handlePing(req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation", "unknown connect operation: "+req.Operation)
	}
}

// handlePing is the responder side of the §5 application-level keepalive
// (EXTENSION-NETWORK §5.1): EXECUTE system/protocol/connect op "ping" with a
// system/network/ping params entity returns a system/network/pong echoing
// timestamp + sequence and stamping the responder's clock. Reaching this
// code at all is the liveness proof — the handler loop is dispatching, so
// the peer is protocol-responsive, not just TCP-alive (the distinction §5.1
// pins against transport-level WS pings). Sequencing (established
// connections only — the inverse gate of hello/authenticate) is enforced at
// the dispatch boundary via ValidateConnectionSequence.
func (h *ConnectHandler) handlePing(req *handler.Request) (*handler.Response, error) {
	if req.Params.Type != types.TypeNetworkPing {
		return handler.NewErrorResponse(400, "invalid_params",
			"ping params must be "+types.TypeNetworkPing+", got "+req.Params.Type)
	}
	var ping types.PingData
	if err := ecf.Decode(req.Params.Data, &ping); err != nil {
		return handler.NewErrorResponse(400, "invalid_params", "decode ping: "+err.Error())
	}
	return handler.NewResponse(200, types.TypeNetworkPong, types.PongData{
		Timestamp:  ping.Timestamp,
		Sequence:   ping.Sequence,
		ServerTime: uint64(time.Now().UnixMilli()),
	})
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

	// V7 §4.5 protocols negotiation — two refusals, folded into
	// ENTITY-CORE-PROTOCOL 0.8.2.4 (SA-PY-31 / SA-PY-32, §4.7 rows 1/10):
	//
	//  1. absent or empty set → 400 invalid_request (FM-2e). §4.5 marks
	//     protocols Required with NO default; SA-PY-31 was ruled reading 2 —
	//     a peer that names no version has made no incompatible-VERSION claim,
	//     so an absent/empty list is a malformed request, not
	//     incompatible_protocol (arch's own row-10 argument, one row up). This
	//     arm is DORMANT: every cohort peer emits a non-empty list (go's own
	//     initiator defaults to entity-core/1.0 in CreateHelloExecute), so it
	//     refuses no conformant peer — safe to land incrementally, no flag day.
	//  2. non-empty set disjoint from ours → 400 incompatible_protocol
	//     (§4.7 row 1; the §8.4 identifiers, per SA-PY-32). This was the live
	//     gap: go echoed hello.protocols back and never checked it.
	//
	// go previously shipped reading 1 (absent → unconstrained); arch ruled
	// reading 2 because keystone's csharp/typescript peers already require the
	// field and pass conformance (L16), so reading 1 was never the cohort
	// position.
	if len(helloDataIn.Protocols) == 0 {
		return handler.NewErrorResponse(400, "invalid_request",
			"hello protocols is required and must be non-empty (V7 §4.5, SA-PY-31)")
	}
	if !anyInBoth(helloDataIn.Protocols, h.protocols) {
		return handler.NewErrorResponse(400, "incompatible_protocol",
			fmt.Sprintf("no common protocol version: initiator=%v responder=%v (V7 §4.5)",
				helloDataIn.Protocols, h.protocols))
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
		cs.HelloPeerID = helloDataIn.PeerID // §4.6: bind authenticate.peer_id to this
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
	// §4.6 step 3 (the identity binding) runs AFTER step 2 (signature
	// verification), below — the step numbering is a normative ORDER (ruled
	// 2026-09-01-c). The check moved down from here; see the block after the
	// signature verify. claimedPeerID / claimedKeyType are already decoded above.

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

	// §4.6 step 3 — the identity binding, run AFTER step 2 per the normative
	// step order (ruled 2026-09-01-c). Step 2 proved possession of the private
	// key for authenticate.public_key; step 3 proves that key is the one the
	// claimed peer_id names. Ordering it last means an input that fails BOTH the
	// signature (step 2) and the binding (step 3) is reported as the step-2
	// authentication_failed, matching rust/py's numbered order — where before go
	// reached identity_mismatch first and diverged (§4.7 row 8).
	if !claimedPeerID.VerifyPublicKey(authenticateData.PublicKey) {
		return handler.NewErrorResponse(401, "identity_mismatch", "public key does not match peer_id")
	}

	// §4.6 "MUST also verify authenticate.peer_id == hello.peer_id for the same
	// connection" — the claimed identity does not change mid-handshake;
	// combined with step 3 above this binds the whole handshake to one key. A
	// mismatch is the §4.7 step-3 row → 401 identity_mismatch (same code as the
	// public-key binding, so the numbered order is preserved). Guarded on a
	// recorded hello peer_id: an authenticate that reached here passed the step-1
	// nonce check, so a hello was processed and HelloPeerID is set.
	if cs.HelloPeerID != "" && authenticateData.PeerID != cs.HelloPeerID {
		return handler.NewErrorResponse(401, "identity_mismatch",
			"authenticate.peer_id does not match the hello peer_id for this connection (§4.6)")
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
	var policyStore store.ContentStore
	var policyIndex store.LocationIndex
	if req.Context != nil {
		policyStore, policyIndex = req.Context.Store, req.Context.LocationIndex
	}
	grants := h.AssembleInboundGrants(policyStore, policyIndex, claimedPeerID, remoteIdentityContentHash)
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
	// responseLocalIdentity is the local `system/peer` identity entity.
	//
	// Under §4.5a item 1a (v7.77) it needs no per-connection derivation at
	// all: the identity entity is authored at the ECFv1-SHA-256 floor
	// unconditionally, so the peer-startup-time h.localIdentity, a re-derive
	// under the connection's active format, and a re-derive matching a cached
	// cap's format are all the SAME BYTES. This used to fork three ways to
	// keep those forms lined up — the cached-cap path kept the startup form,
	// the fresh-mint path re-derived under cs.ActiveHashFormat — which is the
	// two-derivation-function shape item 1a exists to collapse.
	//
	// Note what stays true: the cap token and signature around it are still
	// authored under the connection's ACTIVE format (§4.5a item 1). Only the
	// identity entity is pinned. An active-format cap carrying a floor-form
	// Granter reference is the intended shape, not a cross-format leak.
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
							// No re-derivation: under §4.5a item 1a the identity
							// entity is floor-authored whatever format the cached
							// cap was minted under, so h.localIdentity already
							// lines up with mintedCap.Granter by construction.
							found = true
						}
					}
				}
			}
		}
	}
	if !found {
		// §4.5a item 1a — the local identity entity is the floor-authored
		// one, full stop. This previously re-derived under
		// cs.ActiveHashFormat so cap.Granter and signature.Signer would name
		// the same identity-hash form as the hello-response had used; item 1a
		// makes that alignment automatic and network-wide instead of
		// per-connection, so the re-derive is removed rather than kept as a
		// no-op. h.localIdentity IS the value it would have produced.
		localIdEntityForConn := h.localIdentity
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
				// Amendment 12 §A1/§A3: responder-side connected liveness write,
				// symmetric with the dialer's write at connection.go. Both ends
				// of a completed handshake (§6.2) publish a status entity for
				// the peer, so either end's subscriber sees a baseline before a
				// transport-error/keepalive-miss demotes it. Soft-fail
				// (observability-only, must not fail the handshake).
				_, _ = WritePeerStatus(
					req.Context.Store,
					req.Context.LocationIndex,
					string(h.localPeerID),
					remoteIdentityContentHash,
					types.PeerStatusData{
						PeerID:      string(claimedPeerID),
						Status:      types.PeerStatusConnected,
						ConnectedAt: now,
					},
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
	// The identity entity is the ONE exception to this function's
	// "everything under activeFormat" rule: §4.5a item 1a pins `system/peer`
	// to the ECFv1-SHA-256 floor unconditionally. activeFormat still governs
	// the authenticate and signature entities below.
	identity, err := kp.IdentityEntity()
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

// AssembleInboundGrants returns the grant set this peer issues a remote peer
// that dials IN: the §4.4 SHOULD floor (dynamic resolver → static override →
// DefaultConnectionGrants), UNIONed with that peer's policy-table entry, then
// advertisement-filtered. It is the one grant assembly this peer performs, and
// it has exactly two callers:
//
//   - handleAuthenticate — the §6.6 handshake mint, acceptor → dialer;
//   - the §6.5 (b) reciprocal mint, dialer → acceptor, on a symmetric
//     rendezvous establishment.
//
// The second caller is why this is a method and not inline handshake code
// (arch f8f736a, Q2 contents ruling 2026-08-05). §6.5 (b) says the reciprocal
// grant is "the mirror of what an inbound dialer receives," and that names the
// grant an inbound dialer ACTUALLY receives — this assembled set — not the flat
// §4.4 floor. Minting the bare floor while an inbound dialer gets the assembled
// set gives the establishment whose whole justification is symmetry asymmetric
// authority: the reciprocal direction 403s on anything out-of-floor. Both Go
// and Rust shipped the flat floor; this is the fix.
//
// The mirror is symmetric CONSTRUCTION, not identical grant sets. Each peer
// runs its own assembly against the counterpart, so A→B and B→A differ exactly
// as A's and B's policy tables differ — correct, because authority is
// target-owned.
//
// store and index may be nil (in-process contexts with no tree): the policy
// union is then skipped and the result reduces to the floor, which is also what
// happens when the capability handler simply isn't installed — no policy
// entries exist, so the lookup misses.
func (h *ConnectHandler) AssembleInboundGrants(
	store store.ContentStore,
	index store.LocationIndex,
	remotePeerID crypto.PeerID,
	remoteIdentityHash hash.Hash,
) []types.GrantEntry {
	var grants []types.GrantEntry
	if h.grantResolver != nil {
		grants = h.grantResolver(remotePeerID, remoteIdentityHash)
	}
	if grants == nil && h.connectionGrants != nil {
		grants = h.connectionGrants
	}
	if grants == nil {
		grants = DefaultConnectionGrants()
	}
	// V7 v7.62 §8: policy-table consultation at authenticate-response.
	// Initial grant scope delivered to the remote is the UNION of the §4.4
	// SHOULD floor (whatever was resolved above) and any matching policy
	// entry at system/capability/policy/{caller_hex} (or `default`
	// fallback).
	//
	// Topology asymmetry (§8): handshake is UNION (initial grant builds
	// UP from nothing); runtime request is subset-validation (request
	// narrows DOWN from existing cap). Both consult the same policy
	// table — single source of truth, opposite assembly direction. The
	// reciprocal mint reuses this ONE union direction: there is no third,
	// reciprocal-only narrowing pass (Q2(b) — "MAY narrow by policy" was
	// dropped from §6.5 (b)). An operator wanting the reciprocal direction
	// narrower writes it as that peer's policy entry, in the one table.
	if store != nil && index != nil {
		if policyGrants := readHandshakePolicyGrants(store, index, remoteIdentityHash, remotePeerID); len(policyGrants) > 0 {
			grants = append(append([]types.GrantEntry(nil), grants...), policyGrants...)
		}
	}
	// V7 v7.62 §3 advertisement discipline: drop any grant entry whose
	// `handlers.include` references a handler not registered on this peer.
	// Advertising an unbacked grant is non-conformant — the cross-peer
	// behavior is `404 handler_not_found` at the dispatch boundary, which
	// breaks the contract the grant implies. The peer builder wires
	// handlerRegistered with the dispatcher's registry. Q2(a) makes this
	// binding on the reciprocal mint too: it is inherent in "the grant an
	// inbound dialer would receive," and both impls were skipping it there.
	if h.advertisedScope != nil {
		grants = filterAdvertisedGrants(grants, h.advertisedScope(), h.localPeerID)
	}
	return grants
}

// filterAdvertisedGrants applies the §3 advertisement discipline to an assembled
// grant set: an entry is retained iff this peer's advertised served-scope COVERS
// it, and an uncovered entry is DROPPED, not narrowed.
//
// The matching rule is pinned (`EXTENSION-SIGNALING.md` §6.5 (b) Contents, arch
// 977667f): coverage is the **same four-axis `scope_subset` relation the chain
// already uses for attenuation** — handlers ∧ operations ∧ resources ∧ peers,
// entry ⊆ advertised — reached here through the very same `capability.IsAttenuated`
// the delegation walk calls. That identity is the whole point of the ruling and
// the reason this does not roll its own comparison: any second relation is a
// place where two impls can silently disagree.
//
// What this replaces was exactly such a second relation. Go used to check the
// HANDLERS axis only, by stripping a trailing `/*` and asking the registry
// whether the base pattern resolved. The ruling names that shape non-conformant:
// namespace-prefix-match and exact-op-match both split across the seam (one impl
// drops `system/tree:put` on `foo/bar` against an advertised `foo/*`, another
// keeps it), which is the latent interop bug the MUST forecloses. Operations and
// resources were not consulted at all, so a grant naming an operation this peer
// does not serve survived and produced its 404 at the dispatch boundary — the
// failure the discipline exists to prevent.
//
// An empty `advertised` means the peer published no served-scope. That is
// treated as "advertises nothing," so everything drops — deliberately, and
// deliberately fail-closed: the alternative (pass everything through when the
// scope is unknown) reinstates the unfiltered behavior precisely when we know
// least, and the peer builder always supplies a scope.
func filterAdvertisedGrants(grants []types.GrantEntry, advertised []types.GrantEntry, localPeerID crypto.PeerID) []types.GrantEntry {
	if len(grants) == 0 {
		return grants
	}
	out := make([]types.GrantEntry, 0, len(grants))
	for _, g := range grants {
		if !advertisedCovers(advertised, g, localPeerID) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// advertisedCovers reports whether some advertised entry covers `g` under the
// chain's attenuation relation.
//
// Both sides canonicalize against the LOCAL peer-id: the advertised scope and
// the grant being minted are both authored by this peer, about its own
// namespace, so there is one granter here and not two (unlike a delegation
// walk, where parent and child have different granters — PR-8).
//
// The comparison is wrapped in a one-entry-each CapabilityTokenData so it runs
// through `capability.IsAttenuated` itself rather than a lookalike: `child ⊆
// parent` is exactly `entry ⊆ advertised`.
func advertisedCovers(advertised []types.GrantEntry, g types.GrantEntry, localPeerID crypto.PeerID) bool {
	// UNIVERSAL-GRANT CARVE-OUT — preserved deliberately, and routed.
	//
	// A peer's advertised served-scope is a finite set of registered handlers,
	// so NO union of advertised entries can cover a `handlers: ["*"]` claim.
	// Under the ruling's "uncovered entries drop, not narrow", a universal grant
	// is therefore deleted outright, and every open-access peer would hand its
	// counterparts exactly nothing.
	//
	// That is a consequence the ruling does not address — its worked example is
	// about a NARROWER mismatch (`system/tree:put` on `foo/bar` against an
	// advertised `foo/*`), which is the divergence the four-axis relation
	// genuinely closes. Applying "drop" to the universal case does not close a
	// divergence; it removes authority the peer demonstrably can serve, since a
	// `*` grant dispatched at a REGISTERED handler works and only 404s at an
	// unregistered one — the same outcome an absent grant produces, one layer
	// later.
	//
	// So the pre-existing carve-out stands until arch rules: bare `*` is backed
	// by construction, retained iff this peer serves anything at all. Every
	// non-universal entry goes through the ruled relation below. Filed at
	// docs/validation/spec-issues/ and routed — Rust has not hit this because
	// they discharge the discipline by construction rather than by filtering.
	if isUniversalHandlerClaim(g) {
		return len(advertised) > 0
	}
	for _, adv := range advertised {
		if coversFourAxes(adv, g, localPeerID) {
			return true
		}
	}
	return false
}

// coversFourAxes is the ruled relation, and it is exactly FOUR axes: handlers ∧
// operations ∧ resources ∧ peers, `entry ⊆ advertised`. Pattern semantics on
// each axis are the chain's own (`capability.MatchesPattern`, resources
// canonicalized via `capability.Canonicalize`) — that identity is what closes
// the prefix-vs-pattern divergence the ruling names.
//
// It deliberately does NOT run the full `capability.IsAttenuated`, though the
// ruling's phrase "the same scope_subset relation the chain uses" invites it.
// IsAttenuated additionally enforces exclude-inheritance, constraint and
// allowance attenuation, and expiry — the rest of a *delegation* check. Those
// have no meaning against an advertisement: an advertised scope is a statement
// about what this peer serves, not a parent capability, so it carries no
// constraints and no allowances. Running the full relation therefore fails any
// grant that HAS an allowance, since a child "adding an allowance key the parent
// does not have" is an attenuation violation — and it cost us the entire `query`
// category, whose v7.14 grant entries carry `constraints`/`allowances` by
// requirement. Four axes means four.
func coversFourAxes(advertised, g types.GrantEntry, localPeerID crypto.PeerID) bool {
	if !scopeCovered(g.Handlers.Include, advertised.Handlers.Include, nil) {
		return false
	}
	if !scopeCovered(g.Operations.Include, advertised.Operations.Include, nil) {
		return false
	}
	canon := func(s string) string { return capability.Canonicalize(s, localPeerID) }
	if !scopeCovered(g.Resources.Include, advertised.Resources.Include, canon) {
		return false
	}
	// The peers axis is optional on both sides. An advertisement that names no
	// peer scope constrains none, so anything the entry says is covered; an
	// entry that names none claims none.
	if g.Peers != nil && advertised.Peers != nil {
		if !scopeCovered(g.Peers.Include, advertised.Peers.Include, nil) {
			return false
		}
	}
	return true
}

// scopeCovered reports whether every pattern the entry claims is matched by some
// pattern the advertisement offers. canon, when non-nil, canonicalizes both
// sides before matching (resources are paths; handlers and operations are not).
func scopeCovered(entry, advertised []string, canon func(string) string) bool {
	for _, claimed := range entry {
		if canon != nil {
			claimed = canon(claimed)
		}
		matched := false
		for _, offered := range advertised {
			if canon != nil {
				offered = canon(offered)
			}
			if capability.MatchesPattern(claimed, offered) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// isUniversalHandlerClaim reports whether a grant entry claims the whole handler
// space — the one shape no finite advertised scope can cover.
func isUniversalHandlerClaim(g types.GrantEntry) bool {
	for _, pattern := range g.Handlers.Include {
		if pattern == "*" {
			return true
		}
	}
	return false
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
// Takes the store and index directly rather than a *handler.HandlerContext:
// the §6.5 (b) reciprocal mint runs the same assembly on the DIALER side, where
// there is no inbound request and so no handler context to carry them.
func readHandshakePolicyGrants(store store.ContentStore, index store.LocationIndex, callerIdentityHash hash.Hash, callerPeerID crypto.PeerID) []types.GrantEntry {
	callerHex := hex.EncodeToString(callerIdentityHash.Bytes())
	if entry, ok := readHandshakePolicyEntry(store, index, callerHex); ok {
		return entry.Grants
	}
	if len(callerPeerID) > 0 {
		if entry, ok := readHandshakePolicyEntry(store, index, string(callerPeerID)); ok {
			return entry.Grants
		}
	}
	if entry, ok := readHandshakePolicyEntry(store, index, handshakePolicyFallbackSegment); ok {
		return entry.Grants
	}
	return nil
}

func readHandshakePolicyEntry(store store.ContentStore, index store.LocationIndex, pattern string) (types.CapabilityPolicyEntryData, bool) {
	path := handshakePolicyPathPrefix + "/" + pattern
	h, ok := index.Get(path)
	if !ok {
		return types.CapabilityPolicyEntryData{}, false
	}
	ent, ok := store.Get(h)
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
		// Network handler: observe-address (§6.7.1 / §6.7.4 network-reflect).
		// A broad default grant is reasonable — the op only echoes the source
		// address the peer itself observed (no amplification, leaks nothing not
		// already implied by connecting). Empty resource scope: the fact rides
		// from the connection, not a resource target. check-reachability
		// (§6.7.2 network-dialback) is deliberately NOT here — it is restricted,
		// granted only to peers a host is actively connecting with.
		{
			Handlers:   types.CapabilityScope{Include: []string{"system/network"}},
			Resources:  types.CapabilityScope{Include: []string{}},
			Operations: types.CapabilityScope{Include: []string{"observe-address"}},
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
		// §4.7 out-of-order row (0.8.2.4): a SECOND hello mid-handshake (after
		// the first hello issued a nonce, before the connection completes) is an
		// operation the responder implements arriving in a state that forbids it
		// → 409 connection_sequence_error. Without this the second hello re-issues
		// a nonce and the state-conflict row is unreachable. The FIRST hello sees
		// Phase "init" and is allowed; a hello after completion is caught above
		// (connection_already_established, row 9).
		if state.Phase == "awaiting_authenticate" {
			return ecerrors.ErrConnectionSequence
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
	case "ping":
		// §5.1 keepalive is gated the INVERSE way from the handshake ops:
		// it probes an ESTABLISHED connection's protocol-level liveness, so
		// pre-handshake pings are rejected rather than riding the no-auth
		// connect window.
		if !state.Completed {
			return fmt.Errorf("%w: keepalive ping requires an established connection", ecerrors.ErrConnectionRequired)
		}
		return nil
	default:
		return fmt.Errorf("unknown connect operation: %s", operation)
	}
}
