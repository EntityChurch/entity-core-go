package peerissued

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-REGISTRY §6a.7 — consuming the signed binding-manifest.
//
// The manifest short-circuits the LOOKUP half of resolution: one fetch
// yields the whole name→hash index instead of a per-name pointer fetch.
// It short-circuits nothing else. A hit still flows into the same
// signature / revocation / TTL checks the pointer path runs, because the
// value it produces is the same value the pointer holds — the content
// hash of the §3 binding body.
//
// Everything here is written so that a failure DEGRADES rather than
// denies. §6a.7: "a missing/stale/signature-invalid manifest MUST fall
// through to the §6a.3 per-name pointer." The single exception is
// coverage="complete", where a signature-valid, fresh manifest that does
// not list a name is an authoritative not_found — and that exception is
// load-bearing enough to be spelled out at its call site.

// ErrManifestSignatureInvalid / ErrManifestStaleSeq carry the §6a.7 wire
// codes (reused from SUBSTITUTE §7.2). They are returned for diagnosis;
// resolution treats both as "no manifest" and falls through.
var (
	ErrManifestSignatureInvalid = errors.New(types.RegistryErrManifestSignatureInvalid)
	ErrManifestStaleSeq         = errors.New(types.RegistryErrManifestStaleSeq)
)

// manifestCache holds the freshest manifest accepted from this registry,
// plus the highest seq ever seen — the §7.2 anti-replay high-water mark.
//
// highestSeq is deliberately NOT reset when a manifest is evicted: the
// point of the mark is that a seq we have already seen can never be
// re-accepted later, and forgetting it would reopen exactly the replay
// the gate exists to close.
type manifestCache struct {
	mu         sync.Mutex
	current    *types.RegistryBindingManifestData
	highestSeq uint64
	seenAny    bool
}

func (c *manifestCache) get() (types.RegistryBindingManifestData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return types.RegistryBindingManifestData{}, false
	}
	return *c.current, true
}

// admit applies the §7.2 freshness rule and stores the manifest if it
// passes: seq > seen → accept and supersede; seq == seen → accept
// (re-affirmation); seq < seen → reject stale. The first manifest ever
// seen from a registry is accepted at any seq — learn-by-observation,
// which buys authenticity plus monotonic-newest-seen, not
// guaranteed-latest.
func (c *manifestCache) admit(m types.RegistryBindingManifestData) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seenAny && m.Seq < c.highestSeq {
		return fmt.Errorf("%w: manifest seq %d < highest seen %d",
			ErrManifestStaleSeq, m.Seq, c.highestSeq)
	}
	cp := m
	c.current = &cp
	if !c.seenAny || m.Seq > c.highestSeq {
		c.highestSeq = m.Seq
	}
	c.seenAny = true
	return nil
}

// LoadManifest fetches, verifies and admits the registry's current
// binding-manifest. Callers use it to warm the cache; resolution never
// blocks on it.
//
// Verification mirrors SUBSTITUTE §7.2 verify_manifest, against the key
// already pinned at Backend construction — so a manifest is only ever as
// trusted as the registry identity the operator pinned, and a hostile
// mirror serving the URL gains nothing.
func (b *Backend) LoadManifest(ctx context.Context) (types.RegistryBindingManifestData, error) {
	if b.reader == nil {
		return types.RegistryBindingManifestData{}, errors.New("peerissued: no reader configured")
	}
	manifestHash, err := b.reader.TreeGet(ctx, types.RegistryManifestPath)
	if err != nil {
		return types.RegistryBindingManifestData{}, fmt.Errorf("fetch manifest pointer: %w", err)
	}
	ent, err := b.reader.ContentGet(ctx, manifestHash)
	if err != nil {
		return types.RegistryBindingManifestData{}, fmt.Errorf("fetch manifest body: %w", err)
	}
	if ent.Type != types.TypeRegistryBindingManifest {
		return types.RegistryBindingManifestData{}, fmt.Errorf(
			"%w: manifest entity has type %q, want %q",
			ErrManifestSignatureInvalid, ent.Type, types.TypeRegistryBindingManifest)
	}
	m, err := types.RegistryBindingManifestDataFromEntity(ent)
	if err != nil {
		return types.RegistryBindingManifestData{}, fmt.Errorf("decode manifest: %w", err)
	}
	// The manifest names the registry it speaks for. A mismatch means we
	// fetched someone else's index — reject before the signature check so
	// the failure reads as what it is rather than as a bad signature.
	if m.RegistryID != b.registryPeerID {
		return types.RegistryBindingManifestData{}, fmt.Errorf(
			"%w: manifest registry_id %q ≠ pinned registry %q",
			ErrManifestSignatureInvalid, m.RegistryID, b.registryPeerID)
	}
	if err := b.verifyManifestSignature(ctx, ent.ContentHash); err != nil {
		return types.RegistryBindingManifestData{}, err
	}
	if err := b.manifests.admit(m); err != nil {
		return types.RegistryBindingManifestData{}, err
	}
	return m, nil
}

// verifyManifestSignature resolves the invariant-pointer signature for
// the manifest hash and verifies it under the pinned registry key.
//
// Signature is a MUST here, for the same reason SUBSTITUTE §7.2 makes it
// one: the bindings map is an authority claim, and hash-verifying the
// manifest against its own hash proves only that the bytes are the bytes
// — it says nothing about who authored them. Anyone serving the URL can
// mint a well-formed manifest.
func (b *Backend) verifyManifestSignature(ctx context.Context, manifestHash hash.Hash) error {
	sigPath := types.LocalSignaturePath(manifestHash)
	sigHash, err := b.reader.TreeGet(ctx, sigPath)
	if err != nil {
		return fmt.Errorf("%w: no signature at %s: %v", ErrManifestSignatureInvalid, sigPath, err)
	}
	sigEnt, err := b.reader.ContentGet(ctx, sigHash)
	if err != nil {
		return fmt.Errorf("%w: signature body unreachable: %v", ErrManifestSignatureInvalid, err)
	}
	if sigEnt.Type != types.TypeSignature {
		return fmt.Errorf("%w: signature entity has type %q", ErrManifestSignatureInvalid, sigEnt.Type)
	}
	sd, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrManifestSignatureInvalid, err)
	}
	if sd.Target != manifestHash {
		return fmt.Errorf("%w: signature target %s ≠ manifest hash %s",
			ErrManifestSignatureInvalid, sd.Target, manifestHash)
	}
	if sd.Signer != b.registryPeerHash {
		return fmt.Errorf("%w: signature signer %s ≠ pinned registry identity %s",
			ErrManifestSignatureInvalid, sd.Signer, b.registryPeerHash)
	}
	if !crypto.Verify(b.keyType, b.publicKey, manifestHash.Bytes(), sd.Signature) {
		return fmt.Errorf("%w: signature does not verify under the pinned registry key",
			ErrManifestSignatureInvalid)
	}
	return nil
}

// manifestLookup consults the cached manifest for a normalized name.
//
// Returns:
//   - (hash, true, false)  — hit; use this binding hash.
//   - (zero, false, true)  — authoritative absence (coverage=complete):
//     the registry has signed a statement that it serves no such name,
//     so resolution reports not_found WITHOUT a pointer fetch.
//   - (zero, false, false) — no usable answer; fall through to §6a.3.
//
// The third case covers every failure mode §6a.7 enumerates — no
// manifest cached, partial coverage, malformed entry — because they all
// carry the same instruction: fall through. Collapsing them here keeps
// the caller from having to re-derive that rule per failure.
func (b *Backend) manifestLookup(name string) (hash.Hash, bool, bool) {
	m, ok := b.manifests.get()
	if !ok {
		return hash.Hash{}, false, false
	}
	if h, found := m.Bindings[name]; found {
		if h.IsZero() {
			// A zero hash is a malformed entry, not a deletion tombstone
			// — §6a.7 defines no tombstone. Treat it as no answer rather
			// than inventing semantics the spec does not grant.
			return hash.Hash{}, false, false
		}
		return h, true, false
	}
	if m.IsComplete() {
		return hash.Hash{}, false, true
	}
	return hash.Hash{}, false, false
}

// ManifestBindingCount reports how many names the cached manifest
// carries, and whether one is cached at all. For diagnostics and tests.
func (b *Backend) ManifestBindingCount() (int, bool) {
	m, ok := b.manifests.get()
	if !ok {
		return 0, false
	}
	return len(m.Bindings), true
}

// fetchBindingBody resolves a binding body by hash for a manifest hit —
// local store first (the manifest often names something already cached),
// then the registry. Mirrors lookupBinding's body half, minus the by-name
// pointer step the manifest just replaced.
//
// A type mismatch is reported as ErrNotFound rather than as an error, so
// the caller falls through to the pointer path: an index naming the wrong
// kind of entity is a bad index, not a reason to fail a name that the
// authoritative pointer may still resolve correctly.
func (b *Backend) fetchBindingBody(ctx context.Context, hctx *handler.HandlerContext, bindingHash hash.Hash) (entity.Entity, error) {
	if hctx != nil && hctx.Store != nil {
		if ent, ok := hctx.Store.Get(bindingHash); ok {
			if !entityHasType(ent, types.TypeRegistryBinding) {
				return entity.Entity{}, ErrNotFound
			}
			return ent, nil
		}
	}
	ent, err := b.reader.ContentGet(ctx, bindingHash)
	if err != nil {
		return entity.Entity{}, err
	}
	if !entityHasType(ent, types.TypeRegistryBinding) {
		return entity.Entity{}, ErrNotFound
	}
	return ent, nil
}

// entityHasType is a tiny guard used where a fetched entity's type is the
// only thing distinguishing a valid artifact from an unrelated one.
func entityHasType(e entity.Entity, want string) bool { return e.Type == want }
