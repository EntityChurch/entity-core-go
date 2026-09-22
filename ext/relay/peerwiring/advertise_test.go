package peerwiring

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"
)

// buildBoundedRelayPeer starts a live relay peer configured with the given §8
// store bounds and returns it plus its handler and peer_id.
func buildBoundedRelayPeer(t *testing.T, retentionMs, maxBytes uint64) (*peer.Peer, *relay.Handler, string) {
	t.Helper()
	kp := mustGenerate(t)
	relayH := relay.NewHandler()
	rp, err := peer.New(
		peer.WithIdentity(kp),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		peer.WithHandler(relay.HandlerPattern, relayH),
	)
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	t.Cleanup(func() { _ = rp.Close() })
	peerID := string(kp.PeerID())
	relayH.SetupStore(peerID)
	if retentionMs > 0 {
		relayH.SetRelayStoreRetention(retentionMs)
	}
	if maxBytes > 0 {
		relayH.SetMaxStorageBytes(maxBytes)
	}
	return rp, relayH, peerID
}

// TestPublishSelfAdvertise_BindsSignedLimits is the §4.1 seam: a bounded relay
// publishes its own signed advertise carrying limits.max_retention_ms /
// max_storage_bytes, resolvable through the peer's namespaced index at the
// canonical path, with a signature that verifies against the relay's key.
func TestPublishSelfAdvertise_BindsSignedLimits(t *testing.T) {
	const retentionMs = 3_600_000
	const maxBytes = 1 << 20
	rp, relayH, peerID := buildBoundedRelayPeer(t, retentionMs, maxBytes)

	if !relayH.HasStoreBounds() {
		t.Fatal("HasStoreBounds must be true with a bound configured")
	}

	advEnt, err := PublishSelfAdvertise(rp, relayH)
	if err != nil {
		t.Fatalf("PublishSelfAdvertise: %v", err)
	}

	li := rp.LocationIndex()

	// The advertise resolves at the canonical path, and its limits reflect the
	// configured bounds.
	advPathAbs := "/" + peerID + "/" + types.RelayAdvertisePath(peerID)
	boundHash, ok := li.Get(advPathAbs)
	if !ok {
		t.Fatalf("advertise not bound at %s", advPathAbs)
	}
	if boundHash != advEnt.ContentHash {
		t.Fatalf("bound advertise hash %s != returned %s", boundHash, advEnt.ContentHash)
	}
	storedAdv, ok := rp.Store().Get(advEnt.ContentHash)
	if !ok {
		t.Fatal("advertise entity not in content store")
	}
	adv, err := types.AdvertiseDataFromEntity(storedAdv)
	if err != nil {
		t.Fatalf("decode advertise: %v", err)
	}
	if adv.Limits.MaxRetentionMs != retentionMs {
		t.Fatalf("limits.max_retention_ms: want %d, got %d", retentionMs, adv.Limits.MaxRetentionMs)
	}
	if adv.Limits.MaxStorageBytes != maxBytes {
		t.Fatalf("limits.max_storage_bytes: want %d, got %d", maxBytes, adv.Limits.MaxStorageBytes)
	}
	if len(adv.Modes) == 0 {
		t.Fatal("advertise MUST list at least one mode (§4.1)")
	}

	// The signature resolves at the invariant-pointer path and verifies against
	// the relay's public key over the advertise content hash (V7 §5.2).
	sigPathAbs := "/" + peerID + "/" + types.LocalSignaturePath(advEnt.ContentHash)
	sigHash, ok := li.Get(sigPathAbs)
	if !ok {
		t.Fatalf("advertise signature not bound at %s", sigPathAbs)
	}
	sigEnt, ok := rp.Store().Get(sigHash)
	if !ok {
		t.Fatal("signature entity not in content store")
	}
	sig, err := types.SignatureDataFromEntity(sigEnt)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if sig.Target != advEnt.ContentHash {
		t.Fatalf("signature.target %s != advertise hash %s", sig.Target, advEnt.ContentHash)
	}
	if sig.Signer != rp.Identity().ContentHash {
		t.Fatalf("signature.signer %s != identity hash %s", sig.Signer, rp.Identity().ContentHash)
	}
	kp := rp.Keypair()
	if !crypto.Verify(kp.KeyType, kp.PublicKey, advEnt.ContentHash.Bytes(), sig.Signature) {
		t.Fatal("advertise signature does not verify against the relay key")
	}
}

// TestPublishSelfAdvertise_RetentionOnlyOmitsStorageBytes proves the omitempty
// gate: a relay bounding retention alone advertises max_retention_ms and NOT
// max_storage_bytes (the §4.1 MUST-when-present rule per field).
func TestPublishSelfAdvertise_RetentionOnlyOmitsStorageBytes(t *testing.T) {
	rp, relayH, _ := buildBoundedRelayPeer(t, 60_000, 0)

	if got := relayH.ConfiguredLimits(); got.MaxStorageBytes != 0 {
		t.Fatalf("no storage bound configured: want max_storage_bytes 0, got %d", got.MaxStorageBytes)
	}
	advEnt, err := PublishSelfAdvertise(rp, relayH)
	if err != nil {
		t.Fatalf("PublishSelfAdvertise: %v", err)
	}
	storedAdv, _ := rp.Store().Get(advEnt.ContentHash)
	adv, _ := types.AdvertiseDataFromEntity(storedAdv)
	if adv.Limits.MaxRetentionMs != 60_000 {
		t.Fatalf("max_retention_ms: want 60000, got %d", adv.Limits.MaxRetentionMs)
	}
	if adv.Limits.MaxStorageBytes != 0 {
		t.Fatalf("max_storage_bytes must be absent when unbounded, got %d", adv.Limits.MaxStorageBytes)
	}
}

// TestHasStoreBounds_UnboundedRelay confirms the gate the peer-builder uses:
// no bound → no auto-advertise obligation.
func TestHasStoreBounds_UnboundedRelay(t *testing.T) {
	_, relayH, _ := buildBoundedRelayPeer(t, 0, 0)
	if relayH.HasStoreBounds() {
		t.Fatal("HasStoreBounds must be false with no bound configured")
	}
}
