package peer

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestAcceptorOriginatesUnderReciprocalGrant is the §6.5 (b) conformance §8.1
// vector, run in-tree: after a rendezvous establishment, the ACCEPTOR
// originates a cross-peer dispatch to the DIALER over the same channel, and
// the dialer's verify_request accepts it.
//
// This is the check the whole arc exists to pass. Installing a capability
// proves nothing on its own — the question is whether the far side's chain
// walk accepts a cap it never saw before, rooted at its own identity, carried
// with supporting entities that were not in either peer's handshake
// auth_included.
//
// The acceptor has no transport profile for the dialer, so the dispatch
// resolves through the V7 §6.11 reentry seam — reusing the connection the
// dialer opened. Resolution is not authority: what authorizes it is the
// reciprocal grant, and nothing else.
func TestAcceptorOriginatesUnderReciprocalGrant(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	inbound := acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("reciprocal grant never landed")
	}

	// A path inside the §4.4 SHOULD floor's resource scope for system/tree:
	// `system/type/*`, operation `get`. If the grant authorizes anything at
	// all, it authorizes this.
	params, resource, err := tree.CreateGetRequest("system/type/system/peer", "hash")
	if err != nil {
		t.Fatalf("build get request: %v", err)
	}
	uri := "entity://" + string(dialer.PeerID()) + "/system/tree"

	resp, err := acceptor.RemoteExecute(ctx, uri, "get", params, resource)
	if err != nil {
		t.Fatalf("acceptor origination failed at the transport: %v", err)
	}
	if resp.Status == 401 || resp.Status == 403 {
		t.Fatalf("acceptor origination refused: status=%d — the reciprocal grant did not authorize the dispatch at the dialer, which is the whole point of the mechanism", resp.Status)
	}
	if resp.Status != 200 {
		t.Fatalf("acceptor origination status=%d, want 200", resp.Status)
	}
}

// TestAcceptorOriginationReachesTheAssembledGrant probes the REACH of the
// reciprocal grant, not merely that one exists.
//
// This is the flip. The question routed to arch — is "the mirror of what an
// inbound dialer receives" the flat §4.4 floor, or this peer's ASSEMBLED
// connection grants? — was ruled for the assembled reading (arch f8f736a, Q2).
// The reciprocal grant is the grant this peer would issue the counterpart as an
// inbound dialer: floor ∪ policy, advertisement-filtered.
//
// So the case this test used to record as an ASYMMETRY is now the assertion.
// The test peers are built WithConnectionGrants(OpenAccessGrants()) — an
// inbound dialer receives `*` — and the reciprocal direction must now reach
// exactly as far. A 403 here is the pre-ruling flat-floor mint returning.
func TestAcceptorOriginationReachesTheAssembledGrant(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	inbound := acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("reciprocal grant never landed")
	}

	// Outside the §4.4 floor's resource scope for system/tree (which covers
	// system/type/* and system/handler/* only), and a path that genuinely
	// exists on the dialer — the v7.74 §6.9a self-owner seed policy entry. A
	// non-existent path would answer 404 whether or not the grant authorized
	// it, which would make the test unable to tell reach from absence.
	ownerPolicyPath := "system/capability/policy/" + hex.EncodeToString(dialer.identity.ContentHash.Bytes())
	params, resource, err := tree.CreateGetRequest(ownerPolicyPath, "hash")
	if err != nil {
		t.Fatalf("build get request: %v", err)
	}
	uri := "entity://" + string(dialer.PeerID()) + "/system/tree"

	resp, err := acceptor.RemoteExecute(ctx, uri, "get", params, resource)
	if err != nil {
		// A transport-level failure is not the outcome under test either way.
		t.Fatalf("acceptor origination failed at the transport: %v", err)
	}

	// The dialer grants inbound peers OpenAccessGrants() — `*` on everything —
	// so under the Q2 ruling the reciprocal direction reaches just as far. The
	// policy path above is outside the flat §4.4 floor's system/tree resource
	// scope and inside `*`, which is exactly what makes it the discriminator
	// between the two readings.
	if resp.Status == 403 {
		t.Fatalf("out-of-floor origination refused (403) — the reciprocal grant is carrying the flat §4.4 floor " +
			"while an inbound dialer to this same peer receives `*`. That is the asymmetry the Q2 ruling removed: " +
			"the mint must run AssembleInboundGrants, not DefaultConnectionGrants")
	}
	if resp.Status != 200 {
		t.Fatalf("out-of-floor origination status=%d, want 200", resp.Status)
	}
}

// TestReciprocalGrantContentsAreTheAssembledGrant pins WHICH grant set Go
// mints, so a change of reading stays a test change and not a silent drift.
//
// The ambiguity this pin was written to catch is now ruled (arch f8f736a, Q2):
// "the mirror of what an inbound dialer receives" is this peer's ASSEMBLED
// connection grants (resolver → static → §4.4 defaults, ∪ policy,
// advertisement-filtered) — the set an inbound dialer actually receives — and
// not the flat §4.4 SHOULD floor. The pin is kept, pointed the other way: a
// regression to the floor is a named failure with the reason attached, because
// cross-impl this is a silent 403 and not a crash.
func TestReciprocalGrantContentsAreTheAssembledGrant(t *testing.T) {
	dialer := newMultiplexTestPeer(t, 0)
	acceptor := newMultiplexTestPeer(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	inbound := acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("reciprocal grant never landed")
	}

	cap, _, _ := inbound.OriginatingCapability()
	capData, err := types.CapabilityTokenDataFromEntity(cap)
	if err != nil {
		t.Fatalf("decode reciprocal grant: %v", err)
	}
	minted, err := ecf.Encode(capData.Grants)
	if err != nil {
		t.Fatalf("encode minted grants: %v", err)
	}

	// The reference set is MEASURED, not hardcoded: dial the same peer the
	// ordinary way and read the §6.6 cap it mints. That is, by definition,
	// "what an inbound dialer receives" — so comparing against it tests the
	// ruling itself rather than a copy of today's grant list, and it stays
	// honest when the assembly changes (policy seeds, advertisement filtering).
	reverse, err := acceptor.Connect(ctx, dialer.Addr().String())
	if err != nil {
		t.Fatalf("reverse connect: %v", err)
	}
	defer reverse.Close()
	if err := reverse.PerformConnect(ctx); err != nil {
		t.Fatalf("reverse handshake: %v", err)
	}
	if reverse.session.Capability == nil {
		t.Fatal("reverse handshake conferred no capability")
	}
	inboundData, err := types.CapabilityTokenDataFromEntity(*reverse.session.Capability)
	if err != nil {
		t.Fatalf("decode inbound-dialer grant: %v", err)
	}
	assembled, err := ecf.Encode(inboundData.Grants)
	if err != nil {
		t.Fatalf("encode inbound-dialer grants: %v", err)
	}
	flatFloor, err := ecf.Encode(protocol.DefaultConnectionGrants())
	if err != nil {
		t.Fatalf("encode flat floor: %v", err)
	}

	switch {
	case bytes.Equal(minted, assembled):
		t.Logf("reading pinned: the reciprocal grant is byte-identical to the grant this peer " +
			"hands an inbound dialer — symmetric construction, measured on both directions")
	case bytes.Equal(minted, flatFloor):
		t.Fatalf("the reciprocal mint regressed to the FLAT §4.4 SHOULD floor. Ruled against at " +
			"arch f8f736a (Q2): the mirror is the grant an inbound dialer actually receives — " +
			"floor ∪ policy, advertisement-filtered. Minting the floor gives the establishment " +
			"whose justification is symmetry asymmetric authority, and it fails cross-impl as a " +
			"silent 403. The mint must run ConnectHandler.AssembleInboundGrants.")
	default:
		t.Fatalf("the reciprocal grant matches neither this peer's assembled connection grants " +
			"nor the flat §4.4 floor — an unrecognized third grant set is a cross-impl hazard")
	}
}
