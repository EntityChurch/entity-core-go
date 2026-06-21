// Package peerissued implements the peer-issued REGISTRY backend per
// PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND v0.3.
//
// The backend is TRUST LOGIC, not transport. Its only registry-specific
// work is verifying the binding's signature against a pinned registry
// key (step 3 of §2.1). The actual reads (tree:get / content:get) flow
// through a transport-agnostic Reader the operator wires at peer
// construction — the demo's static-coral-reef registry uses an http-poll
// Reader (sibling file httppoll.go); a live registry would supply a
// RemoteExecute-backed Reader and the backend code is unchanged.
//
// Twin of localname/: same Backend interface, same ResolutionResult
// shape — the SDK consumes both unchanged. The trust source differs:
// localname trusts the local user; peerissued trusts a pinned remote key.
//
// Storage shape per proposal §2.2 (mirrors localname §6.3 two-layer):
//   - binding body at `system/registry/binding/{binding_hash_hex}` —
//     content-addressed, immutable, shared with §3 universal location.
//   - tree pointer at `system/registry/binding/by-name/{nfc(name)}` —
//     the live name→hash index. PUBLISHED by the registry; READ by
//     resolvers; cached locally on first read.
//   - signature at the V7 §3.5 invariant pointer
//     `system/signature/{hex(binding_hash)}`, signed by the registry's
//     identity. Verified against the receiver-pinned key.
//
// Offline / precedes path (§2.1, §2.2): when the binding + signature
// are pre-cached in the local store, steps 1–2 read locally; step 3 is
// identical. Precedes are just a warm cache — same verification.
package peerissued

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"golang.org/x/text/unicode/norm"
)

// Reader does transport-agnostic reads against the registry peer. The
// transport layer (NETWORK §6.5) picks the wire — http-poll for a static
// coral-reef (the demo), a live socket for a running registry. The Backend
// does not know which.
//
// Implementations:
//   - HTTPPollReader (httppoll.go) — wraps ext/httplive.Outbound, the v1
//     demo wire (SUBSTITUTE §7 Mode S).
//   - (future) liveSocketReader — RemoteExecute tree:get / content:get.
//
// Returns ErrNotFound for absent bindings / content. Other errors are
// transport / decode failures and trip the backend's fail-closed
// chain-advance per §5.
type Reader interface {
	// TreeGet returns the system/hash bound at `path` in the registry
	// peer's tree. `path` is peer-relative (the transport layer prepends
	// `/{registry_peer_id}/`). Returns ErrNotFound when no binding exists.
	TreeGet(ctx context.Context, path string) (hash.Hash, error)

	// ContentGet returns the entity addressed by `h` with bytes hash-
	// verified against `h` (Mechanism A). Returns ErrNotFound when the
	// registry does not hold the content.
	ContentGet(ctx context.Context, h hash.Hash) (entity.Entity, error)
}

// ErrNotFound is the Reader sentinel for "no such tree binding / no such
// content at the registry." Callers may wrap.
var ErrNotFound = errors.New("peerissued: not found")

// Option configures a Backend at construction.
type Option func(*Backend)

// WithClock overrides the wall-clock used for TTL checks. Default: real
// time.UnixMilli().
func WithClock(c func() uint64) Option {
	return func(b *Backend) { b.clock = c }
}

// WithNegativeTTLMillis stamps `neg_ttl` on `not_found` results returned
// from this backend (the receiver's per-backend negative caching hint
// per §2.1).
func WithNegativeTTLMillis(ms uint64) Option {
	return func(b *Backend) {
		v := ms
		b.negTTL = &v
	}
}

// WithCacheOnResolve toggles whether a successful live resolve writes
// the fetched binding body + signature + by-name pointer into the local
// content store / location index. Default ON — turns precedes into a
// natural by-product of resolving, matching §2.1's "precedes are a warm
// cache" framing.
func WithCacheOnResolve(on bool) Option {
	return func(b *Backend) { b.cacheOnResolve = on }
}

// Backend implements ext/registry.Backend for one pinned registry peer.
// Multiple registries → multiple Backend instances, each registered with
// the meta-resolver under its own backend_id (the registry's base58
// peer-id).
type Backend struct {
	registryPeerID   string         // BackendID — matches resolver_chain[].backend_id
	registryPeer     entity.Entity  // pinned identity — signature trust root
	registryPeerHash hash.Hash      // canonical content_hash(registryPeer)
	publicKey        []byte
	keyType          byte

	reader Reader
	mu     sync.Mutex
	clock  func() uint64
	negTTL *uint64

	cacheOnResolve bool
}

// New constructs a Backend bound to one pinned registry identity.
//
// `registryPeer` is the registry's system/peer entity — the trust root.
// `registryPeerID` is the registry's base58 peer-id (V7 §1.5), used both
// as the BackendID for resolver-chain matching and as the {peer_id}
// segment the Reader's transport prepends to paths. The two MUST be
// consistent — New cross-checks by deriving the peer-id from the
// identity's public key + key type and rejecting a mismatch.
//
// `reader` is the transport-agnostic read primitive — the operator
// chooses the wire (http-poll for a coral-reef, live socket for a running
// registry); the backend does not.
func New(registryPeer entity.Entity, registryPeerID string, reader Reader, opts ...Option) (*Backend, error) {
	if reader == nil {
		return nil, errors.New("peerissued.New: reader is required")
	}
	if registryPeerID == "" {
		return nil, errors.New("peerissued.New: registryPeerID is required")
	}
	pd, err := types.PeerDataFromEntity(registryPeer)
	if err != nil {
		return nil, fmt.Errorf("peerissued.New: decode pinned identity: %w", err)
	}
	keyType, ok := crypto.KeyTypeByte(pd.KeyType)
	if !ok {
		return nil, fmt.Errorf("peerissued.New: pinned identity unsupported key_type %q", pd.KeyType)
	}
	derived, err := crypto.PeerIDFromPublicKey(pd.PublicKey, keyType)
	if err != nil {
		return nil, fmt.Errorf("peerissued.New: derive peer-id from pinned identity: %w", err)
	}
	if string(derived) != registryPeerID {
		return nil, fmt.Errorf(
			"peerissued.New: registryPeerID %q does not match pinned identity's derived peer-id %q",
			registryPeerID, derived)
	}
	b := &Backend{
		registryPeerID:   registryPeerID,
		registryPeer:     registryPeer,
		registryPeerHash: registryPeer.ContentHash,
		publicKey:        pd.PublicKey,
		keyType:          keyType,
		reader:           reader,
		clock:            defaultClock,
		cacheOnResolve:   true,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

func defaultClock() uint64 {
	return uint64(time.Now().UnixMilli())
}

// Kind returns the §2.4.1 backend_kind string ("peer-issued").
func (b *Backend) Kind() string { return types.BackendKindPeerIssued }

// ID returns the registry's base58 peer-id — the BackendID used by
// resolver_chain[].backend_id for routing this entry to this backend.
func (b *Backend) ID() string { return b.registryPeerID }

// Resolve executes the §2.1 six-step algorithm. The meta-resolver in
// ext/registry calls this with hctx (local store + location index) and
// the queried name; status semantics:
//
//   - resolved        → meta-resolver returns it (after its revocation check)
//   - not_found       → name absent from registry → meta-resolver advances
//                       the chain; carries neg_ttl when WithNegativeTTLMillis
//                       was set.
//   - error returned  → verify-fail / expired / revoked / decode-fail →
//                       fail-closed (REGISTRY §4.1 step 4); meta-resolver
//                       advances. Does NOT downgrade to a pin (§5).
//
// Offline / precedes path: a locally-cached binding at the by-name path
// + signature in the local store satisfies steps 1–2; step 3 is
// identical to live-fetch. Live-fetch is gated on no local cache, then
// caches its result for next-time (when WithCacheOnResolve is on, the
// default).
func (b *Backend) Resolve(hctx *handler.HandlerContext, name string) (types.ResolveResultData, error) {
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return types.ResolveResultData{}, errors.New("peerissued.Resolve: missing store / location index")
	}
	normalized, err := normalizeName(name)
	if err != nil {
		// Name-path safety failure → treat as not_found (we cannot route
		// this name to the registry); chain advances per §2.2.
		return b.notFoundResult(), nil
	}
	ctx := context.Background() // Backend interface carries no ctx in v1.

	// Step 1+2 — locate the binding (offline first, then live).
	bindingHash, bindingEnt, fromCache, err := b.lookupBinding(ctx, hctx, normalized)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return b.notFoundResult(), nil
		}
		return types.ResolveResultData{}, fmt.Errorf("peerissued: lookup binding: %w", err)
	}

	// Step 3 — verify signature against the pinned key.
	sigEnt, err := b.lookupSignature(ctx, hctx, bindingHash)
	if err != nil {
		return types.ResolveResultData{}, fmt.Errorf("peerissued: lookup signature: %w", err)
	}
	if err := b.verifyBinding(bindingHash, sigEnt); err != nil {
		return types.ResolveResultData{}, fmt.Errorf("peerissued: verify: %w", err)
	}

	// Decode body now — step 5 (TTL) + step 6 (surface) need it.
	body, err := types.BindingDataFromEntity(bindingEnt)
	if err != nil {
		return types.ResolveResultData{}, fmt.Errorf("peerissued: decode binding: %w", err)
	}

	// Step 4 — revocation. v1 cohort-pragmatic: read the registry's
	// by-target index path (one lookup). Absent → not revoked. Present
	// and verifying against the same registry → revoked, chain advances.
	if revoked, err := b.checkRevoked(ctx, hctx, bindingHash); err != nil {
		return types.ResolveResultData{}, fmt.Errorf("peerissued: revocation check: %w", err)
	} else if revoked {
		return types.ResolveResultData{}, fmt.Errorf("peerissued: binding revoked")
	}

	// Step 5 — TTL.
	if body.TTL != nil && *body.TTL > 0 {
		if body.IssuedAt+*body.TTL <= b.clock() {
			return types.ResolveResultData{}, fmt.Errorf("peerissued: binding expired")
		}
	}

	// Live-fetch warm-cache: if we read this binding off the wire, write
	// the body + signature + by-name pointer into the local store so the
	// next resolve runs the offline path. Mirrors the §2.2 "precedes are
	// a warm cache" framing.
	if !fromCache && b.cacheOnResolve {
		b.cacheBinding(hctx, normalized, bindingHash, bindingEnt, sigEnt)
	}

	bh := bindingHash
	return types.ResolveResultData{
		Status:      types.ResolutionStatusResolved,
		Binding:     &bh,
		PeerID:      body.TargetPeerID,
		Transports:  body.Transports,
		TrustAnchor: types.PeerIssuedTrustAnchor(b.registryPeerID),
		TTL:         body.TTL,
		BackendID:   b.registryPeerID,
	}, nil
}

// notFoundResult returns the §2.1 step-1 negative result.
func (b *Backend) notFoundResult() types.ResolveResultData {
	return types.ResolveResultData{
		Status:    types.ResolutionStatusNotFound,
		NegTTL:    b.negTTL,
		BackendID: b.registryPeerID,
	}
}

// lookupBinding resolves the by-name index, preferring the local cache
// (precedes path) and falling back to the registry over the Reader.
// Returns (bindingHash, bindingEntity, fromCache, err) — `fromCache=true`
// when the binding came out of the local store; `false` when it was
// just fetched from the registry. ErrNotFound when the registry has no
// pointer at by-name/{name}.
func (b *Backend) lookupBinding(ctx context.Context, hctx *handler.HandlerContext, name string) (hash.Hash, entity.Entity, bool, error) {
	pointerPath := types.PeerIssuedByNamePath(name)

	// Offline path — local store has the precede.
	if bindingHash, ok := hctx.LocationIndex.Get(pointerPath); ok {
		if ent, ok := hctx.Store.Get(bindingHash); ok {
			return bindingHash, ent, true, nil
		}
		// Pointer dangles — treat as miss; fall through to live fetch.
	}

	// Live path — read from the registry peer via Reader.
	bindingHash, err := b.reader.TreeGet(ctx, pointerPath)
	if err != nil {
		return hash.Hash{}, entity.Entity{}, false, err
	}
	bindingEnt, err := b.reader.ContentGet(ctx, bindingHash)
	if err != nil {
		return hash.Hash{}, entity.Entity{}, false, fmt.Errorf("content fetch: %w", err)
	}
	if bindingEnt.Type != types.TypeRegistryBinding {
		return hash.Hash{}, entity.Entity{}, false,
			fmt.Errorf("binding entity has wrong type %q (want %q)", bindingEnt.Type, types.TypeRegistryBinding)
	}
	return bindingHash, bindingEnt, false, nil
}

// lookupSignature resolves the signature entity for `bindingHash` at the
// V7 §3.5 invariant pointer `system/signature/{hex(bindingHash)}`. Local
// cache preferred; live fetch falls back. The verify check (target /
// signer / crypto) lives in verifyBinding.
func (b *Backend) lookupSignature(ctx context.Context, hctx *handler.HandlerContext, bindingHash hash.Hash) (entity.Entity, error) {
	sigPointerPath := types.LocalSignaturePath(bindingHash)

	if sigHash, ok := hctx.LocationIndex.Get(sigPointerPath); ok {
		if ent, ok := hctx.Store.Get(sigHash); ok {
			return ent, nil
		}
	}

	sigHash, err := b.reader.TreeGet(ctx, sigPointerPath)
	if err != nil {
		return entity.Entity{}, err
	}
	sigEnt, err := b.reader.ContentGet(ctx, sigHash)
	if err != nil {
		return entity.Entity{}, fmt.Errorf("signature content fetch: %w", err)
	}
	return sigEnt, nil
}

// verifyBinding is §2.1 step 3 — the trust check. Pure function over the
// fetched bytes; no I/O. Identical for online / offline (proposal §2.2
// "precedes path verify is identical").
func (b *Backend) verifyBinding(bindingHash hash.Hash, sigEnt entity.Entity) error {
	if sigEnt.Type != types.TypeSignature {
		return fmt.Errorf("signature entity has wrong type %q", sigEnt.Type)
	}
	sd, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if sd.Target != bindingHash {
		return fmt.Errorf("signature target %s ≠ binding hash %s", sd.Target, bindingHash)
	}
	if sd.Signer != b.registryPeerHash {
		return fmt.Errorf("signature signer %s ≠ pinned registry identity %s",
			sd.Signer, b.registryPeerHash)
	}
	if !crypto.Verify(b.keyType, b.publicKey, bindingHash.Bytes(), sd.Signature) {
		return fmt.Errorf("signature does not verify under pinned registry key")
	}
	return nil
}

// checkRevoked reads the registry's by-target revocation index for this
// binding. v1 cohort-pragmatic shape: one tree pointer at
// `system/registry/revocation/by-target/{hex(bindingHash)}` → revocation
// entity hash. Absent → not revoked. Present and verifying against the
// same registry's key → revoked. Verify failure → not revoked (defensive;
// don't let an unverified revocation poison a valid binding).
//
// Local-store first (precedes); then the registry. ErrNotFound at either
// layer means "no revocation."
func (b *Backend) checkRevoked(ctx context.Context, hctx *handler.HandlerContext, bindingHash hash.Hash) (bool, error) {
	idxPath := types.PeerIssuedRevocationByTargetPath(bindingHash)

	// Local first.
	if revHash, ok := hctx.LocationIndex.Get(idxPath); ok {
		if revEnt, ok := hctx.Store.Get(revHash); ok {
			return b.verifyRevocation(ctx, hctx, revHash, revEnt, bindingHash)
		}
	}

	// Live.
	revHash, err := b.reader.TreeGet(ctx, idxPath)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	revEnt, err := b.reader.ContentGet(ctx, revHash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return b.verifyRevocation(ctx, hctx, revHash, revEnt, bindingHash)
}

// verifyRevocation checks (a) the revocation entity targets the binding,
// (b) the revocation's signature verifies against the pinned registry.
// Returns true only when both hold.
func (b *Backend) verifyRevocation(ctx context.Context, hctx *handler.HandlerContext, revHash hash.Hash, revEnt entity.Entity, bindingHash hash.Hash) (bool, error) {
	if revEnt.Type != types.TypeRegistryRevocation {
		return false, nil
	}
	rev, err := types.RevocationDataFromEntity(revEnt)
	if err != nil {
		return false, nil
	}
	if rev.Revokes != bindingHash {
		return false, nil
	}
	// Revocation signature lives at the V7 invariant pointer for revHash.
	sigEnt, err := b.lookupSignature(ctx, hctx, revHash)
	if err != nil {
		return false, nil
	}
	if err := b.verifyBinding(revHash, sigEnt); err != nil {
		return false, nil
	}
	return true, nil
}

// cacheBinding writes a successfully-resolved live binding into the local
// store + location index so the next resolve runs the offline path.
// Failures are silently swallowed — cache is a performance optimization,
// not a correctness requirement.
func (b *Backend) cacheBinding(hctx *handler.HandlerContext, name string, bindingHash hash.Hash, bindingEnt entity.Entity, sigEnt entity.Entity) {
	if _, err := hctx.Store.Put(bindingEnt); err != nil {
		return
	}
	if _, err := hctx.Store.Put(sigEnt); err != nil {
		return
	}
	_, _ = hctx.TreeSet(types.BindingStoragePath(bindingHash), bindingHash, "peer-issued-cache-body")
	_, _ = hctx.TreeSet(types.PeerIssuedByNamePath(name), bindingHash, "peer-issued-cache-by-name")
	_, _ = hctx.TreeSet(types.LocalSignaturePath(bindingHash), sigEnt.ContentHash, "peer-issued-cache-sig")
}

// normalizeName applies NFC + REGISTRY §6.3 name-path safety (no `/`, no
// control chars). Dots are allowed (`billslab.com` is fine). No case-fold
// — registries deciding to apply case-fold do so before they author the
// by-name pointer.
func normalizeName(name string) (string, error) {
	if name == "" {
		return "", errors.New("name is empty")
	}
	if !norm.NFC.IsNormalString(name) {
		name = norm.NFC.String(name)
	}
	for _, r := range name {
		if r == '/' {
			return "", fmt.Errorf("name contains '/' (forbidden per REGISTRY §6.3)")
		}
		if (r >= 0x0000 && r <= 0x0020) || r == 0x007F {
			return "", fmt.Errorf("name contains control character U+%04X", r)
		}
	}
	return name, nil
}
