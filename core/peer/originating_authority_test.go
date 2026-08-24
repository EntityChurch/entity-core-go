package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// mintOriginatingCap builds a capability token the counterpart would have
// granted us, plus a stand-in supporting entity for the chain that would
// travel with it. Only the identity of the entities matters here — this test
// is about which slot the origination path reads, not about chain validity.
func mintOriginatingCap(t *testing.T, granter, grantee hash.Hash) (entity.Entity, entity.Entity) {
	t.Helper()
	cap, err := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(granter),
		Grantee:   grantee,
		CreatedAt: 1,
	}.ToEntity()
	if err != nil {
		t.Fatalf("mint originating cap: %v", err)
	}
	raw, err := ecf.Encode(map[string]any{"supporting": "granter-identity-stand-in"})
	if err != nil {
		t.Fatalf("encode supporting: %v", err)
	}
	supporting, err := entity.NewEntity("primitive/any", raw)
	if err != nil {
		t.Fatalf("build supporting: %v", err)
	}
	return cap, supporting
}

// TestOriginatingCapabilityTakesPrecedence pins the PROPOSAL-SYMMETRIC-REENTRY
// §9 Q2 precedence pin: the connection-scoped originating authority is a
// DISTINCT SLOT from the session entity's durable held_capability, and the
// origination path consults it in addition to — and ahead of — the durable
// read.
//
// The pin exists because the reciprocal grant is deliberately never persisted
// (a stale grant reused on reconnect, without re-meeting at the rendezvous
// key, would authorize outside the establishment that justified it). An impl
// whose authority lookup reads only /{local}/system/peer/session/{remote}
// therefore cannot see it at all — "invisible to the one lookup that decides
// authority."
func TestOriginatingCapabilityTakesPrecedence(t *testing.T) {
	alice := newMultiplexTestPeer(t, 0)
	bob := newMultiplexTestPeer(t, 0)

	conn := connectClient(t, alice, bob)
	defer conn.Close()

	// Baseline: no connection-scoped grant installed, so the selection comes
	// from the durable/in-memory slots.
	baseline, baselineSupporting, _ := conn.selectOutboundCapability()
	if len(baselineSupporting) != 0 {
		t.Fatalf("baseline selection carried supporting entities; only a connection-scoped grant does that")
	}

	granterHash, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate granter: %v", err)
	}
	granterIdentity, err := granterHash.IdentityEntity()
	if err != nil {
		t.Fatalf("granter identity: %v", err)
	}
	cap, supporting := mintOriginatingCap(t, granterIdentity.ContentHash, alice.identity.ContentHash)
	if cap.ContentHash == baseline.ContentHash {
		t.Fatalf("test is vacuous: the minted cap collides with the baseline selection")
	}

	conn.SetOriginatingCapability(cap, map[hash.Hash]entity.Entity{supporting.ContentHash: supporting})

	got, gotSupporting, _ := conn.selectOutboundCapability()
	if got.ContentHash != cap.ContentHash {
		t.Fatalf("origination read the durable slot (%s), not the connection-scoped grant (%s) — an unpersisted reciprocal grant would be invisible",
			got.ContentHash, cap.ContentHash)
	}
	if _, ok := gotSupporting[supporting.ContentHash]; !ok {
		t.Fatalf("the grant's supporting chain did not come back with it — our handshake auth_included does not contain entities the counterpart authored, so the far side could not walk the chain")
	}
}

// TestOriginatingCapabilityReachesTheWire proves the selected grant is not just
// returned by the selector but actually authorizes the EXECUTE, and that its
// supporting entities ride in the envelope's included set.
func TestOriginatingCapabilityReachesTheWire(t *testing.T) {
	bob := newMultiplexTestPeer(t, 0)

	var mu sync.Mutex
	var frames [][]byte
	akp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	alice, err := New(
		WithIdentity(akp),
		WithListenAddr("127.0.0.1:0"),
		WithWireHook("capture", func(evt WireEvent) {
			if evt.Direction != WireOutbound || evt.RootType != types.TypeExecute {
				return
			}
			buf := make([]byte, len(evt.FrameBytes))
			copy(buf, evt.FrameBytes)
			mu.Lock()
			frames = append(frames, buf)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatalf("build alice: %v", err)
	}
	defer alice.Close()

	conn := connectClient(t, alice, bob)
	defer conn.Close()

	cap, supporting := mintOriginatingCap(t, bob.identity.ContentHash, alice.identity.ContentHash)
	conn.SetOriginatingCapability(cap, map[hash.Hash]entity.Entity{supporting.ContentHash: supporting})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The grant is a fabrication, so the far side is expected to refuse it.
	// What is under test is what went OUT, not the verdict that came back.
	_, _ = conn.Execute(ctx, "entity://"+string(bob.PeerID())+"/system/tree", "get", entity.Entity{}, nil)

	mu.Lock()
	captured := frames
	mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("no outbound EXECUTE observed on the wire")
	}

	var env entity.Envelope
	if err := ecf.Decode(captured[len(captured)-1], &env); err != nil {
		t.Fatalf("decode captured frame: %v", err)
	}
	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		t.Fatalf("decode EXECUTE: %v", err)
	}
	// The reference itself: the EXECUTE root still names the cap in its own
	// `capability` field. That field IS the carriage — no new params, no new
	// frame, which is why the flip needed no wire-core change.
	if execData.Capability != cap.ContentHash {
		t.Fatalf("EXECUTE.capability = %s, want the connection-scoped grant %s", execData.Capability, cap.ContentHash)
	}

	// EXTENSION-SIGNALING §6.5 (b) "Wielding" (arch 977667f), send half. This
	// assertion is INVERTED from the pre-flip shape, which required the chain
	// to ride along: the counterpart authored the cap, its signature, and the
	// granter identity, so sending them back is exactly what the ruling
	// removes. Both must be absent — stripping only the supporting set leaves
	// a partial reference frame that dies at the far side's §5.5 walk on
	// `no signature found` instead of resolving.
	if _, ok := env.Included[cap.ContentHash]; ok {
		t.Fatal("the cap entity is still inlined — this is the partial reference frame, and the far side fails it as missing-signature rather than resolving it")
	}
	if _, ok := env.Included[supporting.ContentHash]; ok {
		t.Fatal("the grant's supporting chain is still inlined — we are handing the counterpart back entities it authored, which is what wielding by reference removes")
	}

	// What MUST still travel: our author identity. The counterpart resolves
	// `author` from it and compares `grantee == author` against it, and it is
	// the one entity in this frame it did not author.
	if _, ok := env.Included[alice.identity.ContentHash]; !ok {
		t.Fatal("the author identity entity was stripped — the far side cannot resolve `author`, so grantee == author cannot be checked")
	}
}

// TestRendezvousKeyClassificationIsLocalAndOffByDefault pins §4.4 (rev 3):
// the discriminator is a locally-set flag, defaulting to the asymmetric case.
// A connection reached by dialing a resolved transport endpoint is NOT a
// rendezvous establishment, and nothing the counterpart says can make it one —
// the flag is never read off the wire.
func TestRendezvousKeyClassificationIsLocalAndOffByDefault(t *testing.T) {
	alice := newMultiplexTestPeer(t, 0)
	bob := newMultiplexTestPeer(t, 0)

	conn := connectClient(t, alice, bob)
	defer conn.Close()

	if conn.EstablishedViaRendezvousKey() {
		t.Fatal("a plain dial-by-address classified as a rendezvous establishment — §6.6's one-directional mint must stand alone here")
	}
	conn.MarkEstablishedViaRendezvousKey()
	if !conn.EstablishedViaRendezvousKey() {
		t.Fatal("local classification did not stick")
	}
}
