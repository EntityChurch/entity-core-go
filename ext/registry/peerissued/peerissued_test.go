package peerissued

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// fakeReader is a programmable Reader for unit tests — it serves a fixed
// (path → hash, hash → entity) map, returning ErrNotFound otherwise. No
// network, no fixtures, no I/O.
type fakeReader struct {
	tree    map[string]hash.Hash
	content map[hash.Hash]entity.Entity
	// trackCalls captures every TreeGet / ContentGet path invoked, in
	// order — lets tests assert offline path didn't hit the wire.
	calls []string
}

func newFakeReader() *fakeReader {
	return &fakeReader{
		tree:    map[string]hash.Hash{},
		content: map[hash.Hash]entity.Entity{},
	}
}

func (r *fakeReader) TreeGet(_ context.Context, path string) (hash.Hash, error) {
	r.calls = append(r.calls, "tree:"+path)
	if h, ok := r.tree[path]; ok {
		return h, nil
	}
	return hash.Hash{}, ErrNotFound
}

func (r *fakeReader) ContentGet(_ context.Context, h hash.Hash) (entity.Entity, error) {
	r.calls = append(r.calls, "content:"+hex.EncodeToString(h.Bytes()))
	if ent, ok := r.content[h]; ok {
		return ent, nil
	}
	return entity.Entity{}, ErrNotFound
}

// publishBinding signs a binding entity with `signer`'s key and seeds the
// reader with body + signature + by-name pointer. Returns the binding's
// content_hash.
func publishBinding(t *testing.T, r *fakeReader, signer crypto.Keypair, body types.BindingData, name string) hash.Hash {
	t.Helper()
	// CAP registry D3: a peer-issued binding MUST carry a non-null ttl, else the
	// resolver refuses it. These positive-path fixtures are not about ttl, so
	// default a far-future one when the caller left it nil. The D3 negative case
	// (a genuinely null-ttl binding must be refused) is exercised by
	// TestResolve_NullTTLRefused, which seeds its binding directly to bypass this.
	if body.TTL == nil {
		d := uint64(1_000_000_000)
		body.TTL = &d
	}
	bindingEnt, err := body.ToEntity()
	if err != nil {
		t.Fatalf("encode binding: %v", err)
	}
	sigBytes := signer.Sign(bindingEnt.ContentHash.Bytes())
	signerEnt, err := signer.IdentityEntity()
	if err != nil {
		t.Fatalf("signer identity entity: %v", err)
	}
	sigData := types.SignatureData{
		Target:    bindingEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type, // not load-bearing for verify
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("encode signature: %v", err)
	}
	// Seed reader.
	r.tree[types.PeerIssuedByNamePath(name)] = bindingEnt.ContentHash
	r.tree[types.LocalSignaturePath(bindingEnt.ContentHash)] = sigEnt.ContentHash
	r.content[bindingEnt.ContentHash] = bindingEnt
	r.content[sigEnt.ContentHash] = sigEnt
	return bindingEnt.ContentHash
}

func publishRevocation(t *testing.T, r *fakeReader, signer crypto.Keypair, bindingHash hash.Hash, revokedAt uint64) hash.Hash {
	t.Helper()
	revData := types.RevocationData{Revokes: bindingHash, RevokedAt: revokedAt}
	revEnt, err := revData.ToEntity()
	if err != nil {
		t.Fatalf("encode revocation: %v", err)
	}
	sigBytes := signer.Sign(revEnt.ContentHash.Bytes())
	signerEnt, _ := signer.IdentityEntity()
	sigData := types.SignatureData{
		Target:    revEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}
	sigEnt, _ := sigData.ToEntity()
	r.tree[types.PeerIssuedRevocationByTargetPath(bindingHash)] = revEnt.ContentHash
	r.tree[types.LocalSignaturePath(revEnt.ContentHash)] = sigEnt.ContentHash
	r.content[revEnt.ContentHash] = revEnt
	r.content[sigEnt.ContentHash] = sigEnt
	return revEnt.ContentHash
}

// newHctx returns a HandlerContext backed by in-memory store + index.
func newHctx(t *testing.T, localPeer crypto.PeerID) *handler.HandlerContext {
	t.Helper()
	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localPeer))
	return &handler.HandlerContext{
		Store:         cs,
		LocationIndex: li,
		LocalPeerID:   localPeer,
	}
}

// helpers ----------------------------------------------------------------

func newRegistry(t *testing.T) (crypto.Keypair, entity.Entity, string) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate registry keypair: %v", err)
	}
	ent, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("registry identity: %v", err)
	}
	return kp, ent, string(kp.PeerID())
}

func newLocalPeer(t *testing.T) crypto.PeerID {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("local peer: %v", err)
	}
	return kp.PeerID()
}

// REG-PEERISSUED-RESOLVE-1 — happy path: by-name → binding → verify →
// resolved.
func TestResolve_HappyPath(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, registryKey, body, "billslab.com")

	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hctx := newHctx(t, newLocalPeer(t))

	r, err := backend.Resolve(hctx, "billslab.com", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		t.Fatalf("status: want resolved got %s", r.Status)
	}
	if r.Binding == nil || *r.Binding != bindingHash {
		t.Fatalf("binding: want %s got %v", bindingHash, r.Binding)
	}
	if r.PeerID != body.TargetPeerID {
		t.Fatalf("peer_id: want %s got %s", body.TargetPeerID, r.PeerID)
	}
	want := types.PeerIssuedTrustAnchor(registryPID)
	if r.TrustAnchor != want {
		t.Fatalf("trust_anchor: want %s got %s", want, r.TrustAnchor)
	}
	if r.BackendID != registryPID {
		t.Fatalf("backend_id: want %s got %s", registryPID, r.BackendID)
	}
}

// REG-PEERISSUED-NAME-SUBSTITUTION-1 (CAP registry F1/D1) — a validly-signed,
// current, unrevoked binding for name X, served at by-name/{Y}. The signature
// verifies (it is a real binding the registry issued), so the ONLY thing that
// catches the substitution is comparing body.Name to the queried name. The
// resolver MUST refuse and advance rather than surface X's target for a query
// for Y. This is the vector the existing four checks are blind to: every one of
// them queries the same name the binding was issued for.
func TestResolve_NameSubstitutionRefused(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	// A genuine, correctly-signed binding for billslab.com...
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	// ...but served under the by-name pointer for a DIFFERENT name (the hostile
	// static host's substitution). publishBinding keys the pointer on its `name`
	// argument, so passing "evil.example" here is exactly the swap.
	publishBinding(t, reader, registryKey, body, "evil.example")

	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "evil.example", nil)
	if err == nil {
		t.Fatalf("resolve of a substituted binding succeeded (status=%s peer=%s) — D1 name check missing: a query for evil.example was answered with billslab.com's target", r.Status, r.PeerID)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("refused, but not for the name mismatch: %v", err)
	}
}

// REG-PEERISSUED-NULL-TTL-1 (CAP registry F2/D3) — a peer-issued binding with a
// null ttl MUST be refused and the chain advanced. `issued_at + ttl` is the one
// check on this path a hostile byte-server cannot influence; a null ttl removes
// it, and withholding the revocation (which a static origin freely can) then
// makes the binding permanently unrevokable. Seeded directly to bypass
// publishBinding's positive-path ttl default.
func TestResolve_NullTTLRefused(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
		TTL:          nil, // the defect under test
	}
	bindingEnt, _ := body.ToEntity()
	sigBytes := registryKey.Sign(bindingEnt.ContentHash.Bytes())
	signerEnt, _ := registryKey.IdentityEntity()
	sigEnt, _ := types.SignatureData{
		Target:    bindingEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}.ToEntity()

	backend, _ := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	hctx := newHctx(t, newLocalPeer(t))
	hctx.Store.Put(bindingEnt)
	hctx.Store.Put(sigEnt)
	hctx.TreeSet(types.PeerIssuedByNamePath("billslab.com"), bindingEnt.ContentHash, "test-nullttl")
	hctx.TreeSet(types.LocalSignaturePath(bindingEnt.ContentHash), sigEnt.ContentHash, "test-nullttl")

	r, err := backend.Resolve(hctx, "billslab.com", nil)
	if err == nil {
		t.Fatalf("resolve of a null-ttl peer-issued binding succeeded (status=%s) — D3 refusal missing: the binding has no temporal bound and a withheld revocation makes it permanently unrevokable", r.Status)
	}
	if !strings.Contains(err.Error(), "null ttl") {
		t.Fatalf("refused, but not for the null ttl: %v", err)
	}
}

// Resolver-side TTL ceiling (REGISTRY §6a.9.1, ruled [v1.16]) — the ceiling is
// the durable resolver_chain[].hints.max_ttl, passed into Resolve at resolution
// (here as the localMaxTTL arg), making the resolver honor min(binding.ttl,
// local_max). This is the LOAD-BEARING ceiling:
// a ceiling the issuer enforces cannot protect a consumer from that same issuer,
// so only the resolver holding the cached binding can bound its own exposure.
// The clamp is computed at resolution and NEVER written back — the stored binding
// entity and its content hash are untouched; only the *effective* lifetime the
// resolver honors (expiry check + surfaced TTL) is bounded.
func TestResolve_LocalMaxTTL_Clamps(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)

	// A binding minted with a very long ttl, issued at t=1_000_000.
	longTTL := uint64(1_000_000_000)
	body := types.BindingData{
		Name:         "clamp.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeerClamp11111111111111111111111111111111",
		IssuedAt:     1_000_000,
		TTL:          &longTTL,
	}

	t.Run("clamped_ttl_surfaced_and_binding_unchanged", func(t *testing.T) {
		reader := newFakeReader()
		bindingHash := publishBinding(t, reader, registryKey, body, "clamp.example")
		localMax := uint64(5_000_000) // well below longTTL, still unexpired at the clock
		backend, err := New(registryEnt, registryPID, reader,
			WithClock(func() uint64 { return 2_000_000 }))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		hctx := newHctx(t, newLocalPeer(t))
		res, err := backend.Resolve(hctx, "clamp.example", &localMax)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.TTL == nil || *res.TTL != localMax {
			t.Fatalf("result ttl want clamped %d got %v — resolver ceiling not surfaced", localMax, res.TTL)
		}
		// Never written back: the stored binding still carries the original longTTL.
		ent, ok := hctx.Store.Get(bindingHash)
		if !ok {
			// live-fetch warm cache writes it; read from the reader's content instead
			ent, ok = reader.content[bindingHash]
		}
		if !ok {
			t.Fatalf("binding entity not found to check it was not rewritten")
		}
		bd, err := types.BindingDataFromEntity(ent)
		if err != nil {
			t.Fatalf("decode stored binding: %v", err)
		}
		if bd.TTL == nil || *bd.TTL != longTTL {
			t.Fatalf("stored binding ttl changed to %v — the clamp was written back (want unchanged %d)", bd.TTL, longTTL)
		}
	})

	t.Run("clamp_forces_expiry", func(t *testing.T) {
		reader := newFakeReader()
		_ = publishBinding(t, reader, registryKey, body, "clamp.example")
		// local_max so small that issued_at + local_max <= clock → expired under the
		// ceiling even though the binding's own ttl is far from lapsing.
		tight := uint64(500_000) // 1_000_000 + 500_000 = 1_500_000 <= 2_000_000
		backend, err := New(registryEnt, registryPID, reader,
			WithClock(func() uint64 { return 2_000_000 }))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		hctx := newHctx(t, newLocalPeer(t))
		_, err = backend.Resolve(hctx, "clamp.example", &tight)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("Resolve under a tight ceiling: want expired error, got %v", err)
		}
	})
}

// REG-PEERISSUED-VERIFY-FAIL-1 — non-pinned signer → rejected (error),
// chain advances. The binding's signature is from a DIFFERENT keypair
// than the one the receiver pinned.
func TestResolve_VerifyFail_NonPinnedSigner(t *testing.T) {
	_, pinnedEnt, pinnedPID := newRegistry(t)
	attackerKey, _, _ := newRegistry(t)

	reader := newFakeReader()
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeerAtt11111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	// Publish against attacker key.
	_ = publishBinding(t, reader, attackerKey, body, "billslab.com")

	backend, err := New(pinnedEnt, pinnedPID, reader)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hctx := newHctx(t, newLocalPeer(t))

	_, err = backend.Resolve(hctx, "billslab.com", nil)
	if err == nil {
		t.Fatalf("Resolve: want verify-fail error, got nil")
	}
}

// REG-PEERISSUED-REVOKED-1 — valid binding + verifying revocation →
// rejected, chain advances.
func TestResolve_Revoked(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, registryKey, body, "billslab.com")
	publishRevocation(t, reader, registryKey, bindingHash, 1_500_000)

	backend, _ := New(registryEnt, registryPID, reader,
		WithClock(func() uint64 { return 2_000_000 }))
	hctx := newHctx(t, newLocalPeer(t))

	_, err := backend.Resolve(hctx, "billslab.com", nil)
	if err == nil {
		t.Fatalf("Resolve: want revoked error, got nil")
	}
}

// REG-PEERISSUED-EXPIRED-1 — issued_at + ttl <= now → rejected.
func TestResolve_Expired(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	ttl := uint64(1000)
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
		TTL:          &ttl,
	}
	_ = publishBinding(t, reader, registryKey, body, "billslab.com")

	backend, _ := New(registryEnt, registryPID, reader,
		WithClock(func() uint64 { return 1_001_001 }))
	hctx := newHctx(t, newLocalPeer(t))

	_, err := backend.Resolve(hctx, "billslab.com", nil)
	if err == nil {
		t.Fatalf("Resolve: want expired error, got nil")
	}
}

// REG-PEERISSUED-PRECEDE-1 — binding pre-cached in the local store, the
// reader's wire is empty. Verify is identical to live-fetch.
func TestResolve_PrecedeOffline(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()    // empty — must not be touched
	ttl := uint64(1_000_000_000) // CAP registry D3: peer-issued binding needs non-null ttl
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
		TTL:          &ttl,
	}
	bindingEnt, _ := body.ToEntity()
	sigBytes := registryKey.Sign(bindingEnt.ContentHash.Bytes())
	signerEnt, _ := registryKey.IdentityEntity()
	sigEnt, _ := types.SignatureData{
		Target:    bindingEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}.ToEntity()

	backend, _ := New(registryEnt, registryPID, reader,
		WithClock(func() uint64 { return 2_000_000 }))
	hctx := newHctx(t, newLocalPeer(t))

	// Seed local store + tree.
	hctx.Store.Put(bindingEnt)
	hctx.Store.Put(sigEnt)
	hctx.TreeSet(types.PeerIssuedByNamePath("billslab.com"), bindingEnt.ContentHash, "test-precede")
	hctx.TreeSet(types.LocalSignaturePath(bindingEnt.ContentHash), sigEnt.ContentHash, "test-precede")

	r, err := backend.Resolve(hctx, "billslab.com", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		t.Fatalf("status: want resolved got %s", r.Status)
	}
	// Precedes path: revocation by-target check is the only thing that
	// MAY have touched the reader (one TreeGet that misses → not_found).
	for _, c := range reader.calls {
		if c[:5] == "tree:" && c[5:5+len("system/registry/binding/by-name")] == "system/registry/binding/by-name" {
			t.Fatalf("precedes path hit the wire for by-name: %s", c)
		}
		if c[:8] == "content:" {
			t.Fatalf("precedes path hit the wire for content: %s", c)
		}
	}
}

// REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name not in the by-name index →
// not_found + neg_ttl.
func TestResolve_OfflineNotFound(t *testing.T) {
	_, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	negTTL := uint64(30_000)
	backend, _ := New(registryEnt, registryPID, reader, WithNegativeTTLMillis(negTTL))
	hctx := newHctx(t, newLocalPeer(t))

	r, err := backend.Resolve(hctx, "nope.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusNotFound {
		t.Fatalf("status: want not_found got %s", r.Status)
	}
	if r.NegTTL == nil || *r.NegTTL != negTTL {
		t.Fatalf("neg_ttl: want %d got %v", negTTL, r.NegTTL)
	}
	if r.BackendID != registryPID {
		t.Fatalf("backend_id: want %s got %s", registryPID, r.BackendID)
	}
}

// New rejects identity / peer-id mismatch — cross-check on construction.
func TestNew_PeerIDMismatch(t *testing.T) {
	_, registryEnt, _ := newRegistry(t)
	_, err := New(registryEnt, "wrongPeerID", newFakeReader())
	if err == nil {
		t.Fatal("want construction error for peer-id mismatch")
	}
}

// Sanity — Kind / ID surface match the resolver-chain expectations.
func TestKindID(t *testing.T) {
	_, registryEnt, pid := newRegistry(t)
	b, err := New(registryEnt, pid, newFakeReader())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Kind() != types.BackendKindPeerIssued {
		t.Fatalf("Kind: want %s got %s", types.BackendKindPeerIssued, b.Kind())
	}
	if b.ID() != pid {
		t.Fatalf("ID: want %s got %s", pid, b.ID())
	}
}

// guard against accidental panic when an Reader misbehaves — sanity that
// errors propagate.
func TestResolve_ReaderError(t *testing.T) {
	_, registryEnt, pid := newRegistry(t)
	b, _ := New(registryEnt, pid, &errReader{err: errors.New("boom")})
	hctx := newHctx(t, newLocalPeer(t))
	_, err := b.Resolve(hctx, "billslab.com", nil)
	if err == nil {
		t.Fatal("want reader-error to surface")
	}
}

type errReader struct{ err error }

func (r *errReader) TreeGet(context.Context, string) (hash.Hash, error) {
	return hash.Hash{}, r.err
}
func (r *errReader) ContentGet(context.Context, hash.Hash) (entity.Entity, error) {
	return entity.Entity{}, r.err
}
