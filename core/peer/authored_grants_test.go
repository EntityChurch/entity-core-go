package peer

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// establishReciprocalPair brings up a rendezvous-classified establishment and
// returns the acceptor-side connection with the §6.5 (b) grant installed.
func establishReciprocalPair(t *testing.T, ctx context.Context) (dialer, acceptor *Peer, inbound *Connection) {
	t.Helper()
	dialer = newMultiplexTestPeer(t, 0)
	acceptor = newMultiplexTestPeer(t, 0)

	conn, err := dialer.Connect(ctx, acceptor.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.MarkEstablishedViaRendezvousKey()
	if err := conn.PerformConnect(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	inbound = acceptorConnFor(t, acceptor, dialer)
	if !inbound.AwaitOriginatingCapability(ctx, ReciprocalGrantVectorFloor) {
		t.Fatal("reciprocal grant never landed")
	}
	return dialer, acceptor, inbound
}

// originateBack drives the acceptor→dialer reach that the reciprocal grant
// authorizes: a §4.4-floor `system/tree:get` the grant covers if it covers
// anything.
func originateBack(t *testing.T, ctx context.Context, dialer, acceptor *Peer) (uint, error) {
	t.Helper()
	params, resource, err := tree.CreateGetRequest("system/type/system/peer", "hash")
	if err != nil {
		t.Fatalf("build get request: %v", err)
	}
	uri := "entity://" + string(dialer.PeerID()) + "/system/tree"
	resp, err := acceptor.RemoteExecute(ctx, uri, "get", params, resource)
	if err != nil {
		return 0, err
	}
	return resp.Status, nil
}

// TestWieldingByReferenceResolvesAtTheAuthor is the RECEIVE half of the
// EXTENSION-SIGNALING §6.5 (b) "Wielding" phase as ruled by arch 977667f: the
// acceptor names the §7a.2a triple as references and the dialer resolves them
// "from its own store, because it authored them."
//
// Stripping the supporting set is the closest a receive-side-only build can
// get to the ruled send shape: the EXECUTE still names the cap in
// `capability`, and the granter identity and granter signature no longer ride
// in `included`. Note it is NOT the full post-flip frame — Go's
// CreateAuthenticatedExecute inlines the cap entity unconditionally, so a true
// references-only sender needs a builder change too, not merely an empty
// supporting set. That gap is the send side, and it is held.
//
// The pre-change behavior of this exact vector is `403 capability_denied`
// ("no signature found for capability"), which is why it is worth having: it
// is the one measurement that says whether the ruling's central claim —
// resolve the triple at the author — is implementable as written, rather than
// merely plausible.
func TestWieldingByReferenceResolvesAtTheAuthor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer, acceptor, inbound := establishReciprocalPair(t, ctx)

	cap, supporting, ok := inbound.OriginatingCapability()
	if !ok {
		t.Fatal("grant reported ready but no capability installed")
	}
	if len(supporting) == 0 {
		t.Fatal("grant landed with no supporting entities — nothing to strip, so this vector would prove nothing")
	}

	// Wield by reference: keep the cap selected, carry none of its chain.
	inbound.SetOriginatingCapability(cap, nil)

	status, err := originateBack(t, ctx, dialer, acceptor)
	if err != nil {
		t.Fatalf("acceptor origination failed at the transport: %v", err)
	}
	if status == 401 || status == 403 {
		t.Fatalf("references-only origination refused: status=%d — the dialer did not resolve a cap IT AUTHORED, so the ruled wielding shape does not verify at the author", status)
	}
	if status != 200 {
		t.Fatalf("references-only origination status=%d, want 200", status)
	}
}

// TestWieldingByReferenceFailsClosedForUnauthoredCaps is the scoping vector,
// and the reason the supplier is not a content-store lookup.
//
// The ruling says the dialer resolves "from its own content store." Read
// literally, any cap sitting in the store becomes nameable — a counterpart
// could wield a grant that was minted for it but never delivered, because
// naming the hash would replace holding the entity. Here the peer's authored-
// grant set is cleared to stand in for "this peer did not hand you this," and
// the same references-only origination MUST fail closed.
//
// If this ever passes, resolution has stopped being scoped to what was
// actually granted and delivered.
func TestWieldingByReferenceFailsClosedForUnauthoredCaps(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer, acceptor, inbound := establishReciprocalPair(t, ctx)

	cap, _, ok := inbound.OriginatingCapability()
	if !ok {
		t.Fatal("grant reported ready but no capability installed")
	}

	// Forget that we ever minted it — the cap is still structurally valid and
	// still names the acceptor as grantee, so only the scoping stops it.
	dialer.authoredGrants.mu.Lock()
	dialer.authoredGrants.byCapHash = nil
	dialer.authoredGrants.mu.Unlock()

	inbound.SetOriginatingCapability(cap, nil)

	status, err := originateBack(t, ctx, dialer, acceptor)
	if err != nil {
		// A transport-level refusal is also fail-closed; the assertion is
		// only that this does not get authorized.
		return
	}
	if status == 200 {
		t.Fatal("a cap the dialer does not record as authored-and-delivered was wielded by reference — resolution is no longer scoped to what was granted, and delivery has stopped being a precondition for authority")
	}
	if status != 401 && status != 403 {
		t.Fatalf("unauthored reference status=%d, want a 401/403 authorization refusal", status)
	}
}

// TestInlinedChainStillVerifiesUnchanged is the additivity pin. Landing the
// receive half must be invisible to every peer that still inlines its chain —
// which is every shipped Go and Rust peer today. If this ever fails, the
// change stopped being additive and the flag day got harder, not easier.
func TestInlinedChainStillVerifiesUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer, acceptor, _ := establishReciprocalPair(t, ctx)

	status, err := originateBack(t, ctx, dialer, acceptor)
	if err != nil {
		t.Fatalf("acceptor origination failed at the transport: %v", err)
	}
	if status != 200 {
		t.Fatalf("inlined-chain origination status=%d, want 200 — the pre-ruling shape regressed", status)
	}
}

// TestAuthoredGrantSetRecordsOnlyAfterDelivery pins the record-after-send
// ordering directly, without needing a send failure to occur naturally.
//
// Mint and delivery are the same event for authority purposes: a grant we
// minted but failed to put on the wire leaves the counterpart unauthorized, so
// it must not be resolvable either. The set is keyed by the cap hash a
// counterpart would name, and an unminted hash must simply miss.
func TestAuthoredGrantSetRecordsOnlyAfterDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer, _, inbound := establishReciprocalPair(t, ctx)

	cap, _, ok := inbound.OriginatingCapability()
	if !ok {
		t.Fatal("grant reported ready but no capability installed")
	}

	// Delivered: resolvable, and the triple a chain walk needs is complete.
	supporting, authored := dialer.authoredGrants.supply(cap.ContentHash)
	if !authored {
		t.Fatal("a delivered reciprocal grant is not recorded as authored — wielding by reference cannot resolve")
	}
	if len(supporting) < 3 {
		t.Fatalf("authored grant supplies %d entities, want at least the cap + granter identity + granter signature", len(supporting))
	}

	// Never minted: a miss, not an empty-but-present entry. The cap's own
	// grantee hash is a real, structurally valid hash that is certainly not a
	// minted reciprocal cap.
	capData, err := types.CapabilityTokenDataFromEntity(cap)
	if err != nil {
		t.Fatalf("decode installed grant: %v", err)
	}
	if _, authored := dialer.authoredGrants.supply(capData.Grantee); authored {
		t.Fatal("an unminted hash resolved as an authored grant")
	}
}
