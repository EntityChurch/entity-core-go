package peerissued

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-REGISTRY §6a.7 — the signed binding-manifest.
//
// The through-line of these tests: the manifest is an OPTIMIZATION that
// must never become an authority upgrade. Every failure mode falls
// through to the §6a.3 per-name pointer, and the single case where it may
// answer negatively (coverage="complete") only holds because the
// signature was verified against the pinned key first.

// publishManifest signs a binding-manifest with `signer` and seeds the
// reader with body + signature + the current-manifest pointer.
func publishManifest(t *testing.T, r *fakeReader, signer crypto.Keypair, m types.RegistryBindingManifestData) hash.Hash {
	t.Helper()
	ent, err := m.ToEntity()
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	sigEnt, err := types.SignatureData{
		Target:    ent.ContentHash,
		Signer:    signerIdentityHash(t, signer),
		Algorithm: crypto.KeyTypeString(signer.KeyType),
		Signature: signer.Sign(ent.ContentHash.Bytes()),
	}.ToEntity()
	if err != nil {
		t.Fatalf("encode manifest signature: %v", err)
	}
	r.content[ent.ContentHash] = ent
	r.content[sigEnt.ContentHash] = sigEnt
	r.tree[types.RegistryManifestPath] = ent.ContentHash
	r.tree[types.LocalSignaturePath(ent.ContentHash)] = sigEnt.ContentHash
	return ent.ContentHash
}

func signerIdentityHash(t *testing.T, kp crypto.Keypair) hash.Hash {
	t.Helper()
	ent, err := kp.IdentityEntity()
	if err != nil {
		t.Fatalf("identity entity: %v", err)
	}
	return ent.ContentHash
}

// §6a.7 happy path: a signature-valid manifest answers the lookup, and
// the resolved binding is identical to what the pointer path yields.
func TestManifest_HitResolvesWithoutPointerFetch(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "billslab.com",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, registryKey, body, "billslab.com")
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: registryPID,
		Seq:        1,
		Coverage:   types.CoveragePartial,
		Bindings:   map[string]hash.Hash{"billslab.com": bindingHash},
	})

	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	reader.calls = nil
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "billslab.com", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved || r.Binding == nil || *r.Binding != bindingHash {
		t.Fatalf("resolve via manifest: status=%s binding=%v want resolved/%s", r.Status, r.Binding, bindingHash)
	}
	// The by-name pointer must NOT have been fetched — that saving is the
	// entire point of the manifest.
	for _, c := range reader.calls {
		if strings.Contains(c, "by-name") {
			t.Errorf("manifest hit still fetched the by-name pointer: %s", c)
		}
	}
}

// A manifest hit does not skip verification: a binding signed by someone
// other than the pinned registry is still rejected.
func TestManifest_HitStillVerifiesBindingSignature(t *testing.T) {
	_, pinnedEnt, pinnedPID := newRegistry(t)
	attackerKey, _, _ := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "evil.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, attackerKey, body, "evil.example")

	backend, err := New(pinnedEnt, pinnedPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Inject the manifest cache directly — the attacker cannot sign a
	// manifest under the pinned key, so this models the strictly harder
	// case where the index is somehow trusted and the BINDING is not.
	if err := backend.manifests.admit(types.RegistryBindingManifestData{
		RegistryID: pinnedPID, Seq: 1, Coverage: types.CoveragePartial,
		Bindings: map[string]hash.Hash{"evil.example": bindingHash},
	}); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if _, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "evil.example", nil); err == nil {
		t.Fatal("a manifest hit MUST still fail signature verification against the pinned key")
	}
}

// §6a.7: signature is a MUST. An unsigned manifest is not admitted.
func TestManifest_UnsignedRejected(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	m := types.RegistryBindingManifestData{
		RegistryID: registryPID, Seq: 1, Coverage: types.CoverageComplete,
		Bindings: map[string]hash.Hash{},
	}
	ent, err := m.ToEntity()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	reader.content[ent.ContentHash] = ent
	reader.tree[types.RegistryManifestPath] = ent.ContentHash // no signature published
	_ = registryKey

	backend, err := New(registryEnt, registryPID, reader)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = backend.LoadManifest(context.Background())
	if !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Fatalf("err = %v, want ErrManifestSignatureInvalid", err)
	}
	if _, cached := backend.ManifestBindingCount(); cached {
		t.Error("an unsigned manifest MUST NOT be cached")
	}
}

// A manifest signed by a key other than the pinned registry's is
// rejected — the case that makes signature verification worth doing,
// since anyone serving the URL can mint well-formed bytes.
func TestManifest_ForeignSignerRejected(t *testing.T) {
	_, pinnedEnt, pinnedPID := newRegistry(t)
	attackerKey, _, _ := newRegistry(t)
	reader := newFakeReader()
	publishManifest(t, reader, attackerKey, types.RegistryBindingManifestData{
		RegistryID: pinnedPID, Seq: 1, Coverage: types.CoverageComplete,
		Bindings: map[string]hash.Hash{},
	})
	backend, err := New(pinnedEnt, pinnedPID, reader)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Fatalf("err = %v, want ErrManifestSignatureInvalid", err)
	}
}

// A manifest naming a different registry is rejected before signature
// checking — it is someone else's index, however well signed.
func TestManifest_WrongRegistryIDRejected(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: "SomeOtherRegistry1111111111111111111111111111",
		Seq:        1, Coverage: types.CoveragePartial,
		Bindings: map[string]hash.Hash{},
	})
	backend, err := New(registryEnt, registryPID, reader)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); !errors.Is(err, ErrManifestSignatureInvalid) {
		t.Fatalf("err = %v, want ErrManifestSignatureInvalid", err)
	}
}

// §7.2 freshness: seq > seen accepts, seq == seen re-affirms, seq < seen
// is rejected stale and MUST NOT displace the cached manifest.
func TestManifest_FreshnessGate(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	backend, err := New(registryEnt, registryPID, reader)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mk := func(seq uint64, names int) types.RegistryBindingManifestData {
		b := map[string]hash.Hash{}
		for i := 0; i < names; i++ {
			var h hash.Hash
			h.Digest[0] = byte(i + 1)
			b[string(rune('a'+i))+".example"] = h
		}
		return types.RegistryBindingManifestData{
			RegistryID: registryPID, Seq: seq, Coverage: types.CoveragePartial, Bindings: b,
		}
	}
	publishManifest(t, reader, registryKey, mk(5, 2))
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("first load: %v", err)
	}
	// seq == seen — accepted as re-affirmation.
	publishManifest(t, reader, registryKey, mk(5, 3))
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("equal-seq load: %v", err)
	}
	if n, _ := backend.ManifestBindingCount(); n != 3 {
		t.Errorf("equal seq should re-affirm and replace: bindings=%d want 3", n)
	}
	// seq < seen — rejected, cache untouched.
	publishManifest(t, reader, registryKey, mk(4, 1))
	if _, err := backend.LoadManifest(context.Background()); !errors.Is(err, ErrManifestStaleSeq) {
		t.Fatalf("err = %v, want ErrManifestStaleSeq", err)
	}
	if n, _ := backend.ManifestBindingCount(); n != 3 {
		t.Errorf("a stale manifest MUST NOT displace the cached one: bindings=%d want 3", n)
	}
}

// coverage=partial: a name absent from bindings says NOTHING, so
// resolution MUST fall through to the per-name pointer and find it.
func TestManifest_PartialCoverageFallsThrough(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "unlisted.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, registryKey, body, "unlisted.example")
	// The manifest deliberately omits the name.
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: registryPID, Seq: 1, Coverage: types.CoveragePartial,
		Bindings: map[string]hash.Hash{"other.example": bindingHash},
	})
	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "unlisted.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		t.Fatalf("partial coverage MUST fall through to the pointer: status=%s want resolved", r.Status)
	}
}

// An EMPTY coverage string must behave as partial. Defaulting the other
// way would let a malformed manifest manufacture authoritative negative
// answers for every name the registry serves.
func TestManifest_EmptyCoverageDefaultsToPartial(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "defaulted.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	publishBinding(t, reader, registryKey, body, "defaulted.example")
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: registryPID, Seq: 1, // Coverage left empty
		Bindings: map[string]hash.Hash{},
	})
	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "defaulted.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		t.Fatalf("empty coverage must default to partial and fall through: status=%s", r.Status)
	}
}

// coverage=complete: absence IS authoritative not_found, and the pointer
// is NOT consulted. This is the one negative claim a manifest may make.
func TestManifest_CompleteCoverageIsAuthoritativeAbsence(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	// The pointer DOES exist — proving the not_found came from the
	// manifest's coverage claim and not from a missing binding.
	body := types.BindingData{
		Name:         "listed-elsewhere.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	publishBinding(t, reader, registryKey, body, "listed-elsewhere.example")
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: registryPID, Seq: 1, Coverage: types.CoverageComplete,
		Bindings: map[string]hash.Hash{},
	})
	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	reader.calls = nil
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "listed-elsewhere.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusNotFound {
		t.Fatalf("complete coverage: absence must be authoritative not_found, got %s", r.Status)
	}
	for _, c := range reader.calls {
		if strings.Contains(c, "by-name") {
			t.Errorf("authoritative absence still consulted the pointer: %s", c)
		}
	}
}

// A manifest naming a binding the registry will not serve must fall
// through to the pointer rather than reporting not_found off a stale
// index — the publishing-order race (SUBSTITUTE §7.3 analog).
func TestManifest_DanglingEntryFallsThrough(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "racy.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	realHash := publishBinding(t, reader, registryKey, body, "racy.example")
	var dangling hash.Hash
	dangling.Digest[0] = 0xDE
	publishManifest(t, reader, registryKey, types.RegistryBindingManifestData{
		RegistryID: registryPID, Seq: 1, Coverage: types.CoveragePartial,
		Bindings: map[string]hash.Hash{"racy.example": dangling},
	})
	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := backend.LoadManifest(context.Background()); err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "racy.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved || r.Binding == nil || *r.Binding != realHash {
		t.Fatalf("dangling manifest entry must fall through to the pointer: status=%s binding=%v",
			r.Status, r.Binding)
	}
}

// With no manifest loaded at all, resolution is unchanged — the feature
// is purely additive.
func TestManifest_AbsentIsPurelyAdditive(t *testing.T) {
	registryKey, registryEnt, registryPID := newRegistry(t)
	reader := newFakeReader()
	body := types.BindingData{
		Name:         "nomanifest.example",
		Kind:         types.BindingKindPeerIssued,
		TargetPeerID: "FakePeer11111111111111111111111111111111111111",
		IssuedAt:     1_000_000,
	}
	bindingHash := publishBinding(t, reader, registryKey, body, "nomanifest.example")
	backend, err := New(registryEnt, registryPID, reader, WithClock(func() uint64 { return 2_000_000 }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, err := backend.Resolve(newHctx(t, newLocalPeer(t)), "nomanifest.example", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != types.ResolutionStatusResolved || *r.Binding != bindingHash {
		t.Fatalf("no-manifest resolution regressed: status=%s", r.Status)
	}
}
