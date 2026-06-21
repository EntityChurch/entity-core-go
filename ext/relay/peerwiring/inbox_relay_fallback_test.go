// Build-test for PROPOSAL-DISPATCH-FALLBACK-SEAM-SENDER-SIDE-STORE-AND-
// FORWARD (DRAFT). Forcing vector named `INBOX-RELAY-
// FALLBACK-1` in the proposal §3 driver 1 ("deliver to an offline
// stranger"). Returns concrete signal to architecture about whether the
// seam shape "feels right in code" — per arch's posture: build-test the
// seam against one impl; if it runs, signal back; cohort mirrors.
//
// What this test proves (in-process, three keypairs S / R / D):
//
//  1. S's NETWORK §10 dispatch fails for D (no transport profile in S's
//     tree — D is "offline" / unknown to S).
//  2. S's installed DispatchFallback seam (`(*peer.Peer).SetDispatchFallback`)
//     fires at the §10 step-4 site (core/peer/remote.go:312-ish).
//  3. The seam resolves D's V7 §5.2-signed system/peer/inbox-relay
//     declaration via TreeInboxRelayResolver (the same resolver RELAY
//     wires for its own §6.2.1 fallback) — signature verifies against
//     D's pubkey derived from peer-id.
//  4. The seam dispatches `system/relay:put` at R (D's declared relay)
//     using S's normal outbound connection pool, with the inner envelope
//     riding in the EXECUTE's included set per §9 opacity.
//  5. R's relay handler stores the entry under D's namespace + binds it
//     under §3.2 paths (system/relay/store/{ns}/{entry_hash}).
//  6. The seam returns a synthetic `queued-fallback` Response to S; the
//     caller sees the same shape RELAY's §6.2.1 path surfaces for
//     relay-mediated traffic.
//
// What this test does NOT prove (acknowledged scope):
//
//   - Byte-identical inner envelope vs a direct dispatch. The proposal §3
//     names "verifies S's signature byte-identical to direct delivery" as
//     the gate; reproducing that contract requires extracting the
//     conn.Execute signing path into a reusable helper so the seam can
//     produce the same envelope bytes as a live connection would. This
//     test uses a minimal marker inner envelope to exercise the wire
//     shape; the signature-fidelity gate is the v1.x follow-on
//     `INBOX-RELAY-FALLBACK-1B`.
//   - D actually polls R and recovers. The seam contract ends at "R
//     stored the entry"; the receiver-side poll loop is exercised by
//     existing `relay` + `relay_offline_delivery` categories. A
//     full-loop variant can be layered later if cohort review wants it.
//   - Mode-F-via-home-relay (rung 3 of the proposal §4 ladder). This
//     test exercises rung 2 (direct Mode-S :put when S holds put
//     authority at R; in-process open-access gates that). Rung 3 is
//     the v1.x layering question and rides on a separate build-test.

package peerwiring

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/relay"

	"github.com/fxamacker/cbor/v2"
)

func TestInboxRelayFallback_SeamFiresAndRelayStores(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ---- 1) Keypairs for S, R, D. D is a keypair only (no listener).
	sKP := mustGenerate(t)
	rKP := mustGenerate(t)
	dKP := mustGenerate(t)

	sPeerID := string(sKP.PeerID())
	rPeerID := string(rKP.PeerID())
	dPeerID := string(dKP.PeerID())

	t.Logf("S = %s", sPeerID)
	t.Logf("R = %s", rPeerID)
	t.Logf("D = %s (offline — no listener)", dPeerID)

	// ---- 2) Start R as a live relay peer (open-access + relay handler).
	relayH := relay.NewHandler()
	rp, err := peer.New(
		peer.WithIdentity(rKP),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		peer.WithHandler(relay.HandlerPattern, relayH),
	)
	if err != nil {
		t.Fatalf("R: peer.New: %v", err)
	}
	relayH.SetupStore(rPeerID)
	// R's own outbound dispatcher (for §6.2.1 fallback paths, etc.). Not
	// strictly needed for this test but matches production wiring.
	relayH.SetDispatcher(New(rp))

	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	t.Cleanup(func() { listenerCancel(); rp.Close() })
	rReady := make(chan struct{})
	go func() { _ = rp.ListenReady(listenerCtx, rReady) }()
	<-rReady
	rAddr := rp.Addr().String()

	// ---- 3) Build D's signed inbox-relay declaration naming R.
	//
	// Namespace convention per StoreEntryData doc: the §6.2.1 fallback
	// rendezvous is the destination's peer_id. We pin the same convention
	// here so the receiver-side poll surface matches.
	customNamespace := dPeerID
	decl := types.InboxRelayData{
		Relays: []types.InboxRelayEntry{
			{Relay: rPeerID, Namespace: customNamespace, Priority: 10},
		},
	}
	declEnt, err := decl.ToEntity()
	if err != nil {
		t.Fatalf("decl ToEntity: %v", err)
	}
	dIdentityHash, err := types.ComputePeerIdentityHash(dKP.PublicKey, dKP.KeyType)
	if err != nil {
		t.Fatalf("D identity hash: %v", err)
	}
	sigData := types.SignatureData{
		Target:    declEnt.ContentHash,
		Signer:    dIdentityHash,
		Algorithm: crypto.KeyTypeString(dKP.KeyType),
		Signature: dKP.Sign(declEnt.ContentHash.Bytes()),
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		t.Fatalf("sig ToEntity: %v", err)
	}

	// ---- 4) Start S as a live peer. Pre-populate S's tree with D's
	// signed inbox-relay decl + signature, and register R's TCP profile
	// so S can dial R when the seam fires.
	sp, err := peer.New(
		peer.WithIdentity(sKP),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
		peer.WithRemotePeer(crypto.PeerID(rPeerID), rAddr),
	)
	if err != nil {
		t.Fatalf("S: peer.New: %v", err)
	}
	sListenerCtx, sCancel := context.WithCancel(context.Background())
	t.Cleanup(func() { sCancel(); sp.Close() })
	sReady := make(chan struct{})
	go func() { _ = sp.ListenReady(sListenerCtx, sReady) }()
	<-sReady

	// Bind D's decl + sig in S's local tree (this is what REGISTRY would
	// publish in production; we synthesize the local-tree resolver fallback).
	declPathLocal := "/" + sPeerID + "/" + types.InboxRelayStoragePath(dPeerID)
	sigPathLocal := "/" + sPeerID + "/" + types.LocalSignaturePath(declEnt.ContentHash)
	if _, err := sp.Store().Put(declEnt); err != nil {
		t.Fatalf("S.cs.Put(decl): %v", err)
	}
	if _, err := sp.Store().Put(sigEnt); err != nil {
		t.Fatalf("S.cs.Put(sig): %v", err)
	}
	if err := sp.LocationIndex().Set(declPathLocal, declEnt.ContentHash); err != nil {
		t.Fatalf("S.li.Set(decl): %v", err)
	}
	if err := sp.LocationIndex().Set(sigPathLocal, sigEnt.ContentHash); err != nil {
		t.Fatalf("S.li.Set(sig): %v", err)
	}

	// Sanity: the resolver finds D's signed decl in S's tree.
	resolver := NewTreeInboxRelayResolver(sp)
	if got, ok := resolver.Resolve(dPeerID); !ok {
		t.Fatal("TreeInboxRelayResolver(S) failed to resolve D — fixture wiring broken")
	} else if got.Relays[0].Relay != rPeerID || got.Relays[0].Namespace != customNamespace {
		t.Fatalf("resolved decl drift: got %+v", got.Relays[0])
	}

	// ---- 5) Wire S's DispatchFallback seam. Closure over S's content
	// store + the resolver + S's peer (for the outbound :put dispatch).
	// Implements rung 2 of proposal §4: direct Mode-S :put at the
	// destination's declared inbox-relay when the local peer holds put
	// authority there (open-access here).
	seamFired := 0
	var lastInnerHash hash.Hash
	sp.SetDispatchFallback(func(fctx context.Context, peerID crypto.PeerID,
		uri, operation string, params entity.Entity,
		resource *types.ResourceTarget) (*handler.Response, bool, error) {

		seamFired++

		decl, ok := resolver.Resolve(string(peerID))
		if !ok {
			// Seam declines — no declaration → NETWORK falls through to 502.
			return nil, false, nil
		}
		if len(decl.Relays) == 0 {
			return nil, false, nil
		}
		// v1 priority: lowest-priority entry first (sortByPriority lives
		// in ext/relay; matches a single-entry decl trivially).
		entry := decl.Relays[0]

		// Build the inner envelope. **Scope note:** this is a marker
		// envelope, NOT a byte-identical-to-direct signed wire envelope.
		// The proposal's "verifies S's signature byte-identical to direct
		// delivery" gate is the v1.x follow-on; reproducing it requires
		// extracting conn.Execute's signing path. For this seam-shape
		// build-test we carry enough fidelity (uri / operation / params
		// hash / sender peer-id) to assert the seam preserved S's
		// intent + that R stored the right shape under D's namespace.
		paramsHashHex := hex.EncodeToString(params.ContentHash.Bytes())
		marker, mErr := cbor.Marshal(map[string]any{
			"build_test":   "INBOX-RELAY-FALLBACK-1",
			"uri":          uri,
			"operation":    operation,
			"params_hash":  paramsHashHex,
			"sender":       sPeerID,
			"destination":  string(peerID),
		})
		if mErr != nil {
			return nil, true, mErr
		}
		innerEnt, ierr := entity.NewEntity(types.TypeEnvelope, cbor.RawMessage(marker))
		if ierr != nil {
			return nil, true, ierr
		}
		lastInnerHash = innerEnt.ContentHash

		storeEntry := types.StoreEntryData{
			Namespace:     entry.Namespace,
			PutBy:         sPeerID,
			EnvelopeInner: innerEnt.ContentHash,
		}
		entryEnt, eerr := storeEntry.ToEntity()
		if eerr != nil {
			return nil, true, eerr
		}

		// Dispatch the :put at R, riding the inner in included per §9.
		extras := map[hash.Hash]entity.Entity{
			innerEnt.ContentHash: innerEnt,
		}
		resp, derr := sp.RemoteExecuteWithIncluded(fctx,
			"entity://"+entry.Relay+"/system/relay",
			"put", entryEnt, nil, extras)
		if derr != nil {
			return nil, true, derr
		}

		// Surface a queued-fallback Response the caller can match on. Shape
		// mirrors RELAY §6.2.1 (handler.NewResponse with TypeRelayForwardResult
		// + queued-fallback status), reused for the sender-side seam path.
		fwd := types.ForwardResultData{
			Status:   types.ForwardStatusQueuedFallback,
			StoredAt: entry.Namespace,
		}
		fwdResp, herr := handler.NewResponse(200, types.TypeRelayForwardResult, fwd)
		if herr != nil {
			return nil, true, herr
		}
		_ = resp // R's :put-result is observable; we surface the relay-style summary.
		return fwdResp, true, nil
	})

	// ---- 6) Fire the seam by dispatching a direct EXECUTE to D.
	// D has no transport profile in S's tree → getRemoteConnection fails
	// → seam triggers.
	probeParams, err := entity.NewEntity("test/probe", cbor.RawMessage([]byte{0xa1, 0x65, 'h', 'e', 'l', 'l', 'o', 0x01}))
	if err != nil {
		t.Fatalf("build probe params: %v", err)
	}
	resp, err := sp.RemoteExecute(ctx,
		"entity://"+dPeerID+"/system/echo",
		"noop", probeParams, nil)
	if err != nil {
		t.Fatalf("RemoteExecute (seam path): unexpected error %v", err)
	}
	if seamFired != 1 {
		t.Fatalf("seam fired %d times, want 1 — dispatch ladder did not reach step-4 seam", seamFired)
	}
	if resp == nil || resp.Status != 200 {
		t.Fatalf("seam Response status: got %+v, want 200/queued-fallback", resp)
	}
	if resp.Result.Type != types.TypeRelayForwardResult {
		t.Fatalf("seam Response Result.Type %q != %s", resp.Result.Type, types.TypeRelayForwardResult)
	}
	fwdResult, err := types.ForwardResultDataFromEntity(resp.Result)
	if err != nil {
		t.Fatalf("decode forward-result: %v", err)
	}
	if fwdResult.Status != types.ForwardStatusQueuedFallback {
		t.Fatalf("forward-result.status = %q, want %q", fwdResult.Status, types.ForwardStatusQueuedFallback)
	}
	if fwdResult.StoredAt != customNamespace {
		t.Fatalf("forward-result.stored_at = %q, want namespace %q (D's peer_id)", fwdResult.StoredAt, customNamespace)
	}

	// ---- 7) Assert R stored the entry under D's namespace + the inner
	// envelope at §3.2 path. Reaches into R's location index — same
	// surface the existing relay_offline_delivery checks use.
	rIndex := rp.LocationIndex()

	// Walk RelayStorePath prefix to find the stored entry hash. We don't
	// know the entry hash in advance; iterate the prefix.
	storePrefix := "/" + rPeerID + "/" + types.RelayStorePath(customNamespace, hash.Hash{})
	// Hash{} renders as a fixed-length hex tail after RelayStorePath; chop
	// it off so we get the directory prefix.
	storePrefix = storePrefix[:strings.LastIndex(storePrefix, "/")+1]

	entries := rIndex.List(storePrefix)
	if len(entries) == 0 {
		t.Fatalf("R did not store any entry under %s — seam did not reach R's relay handler", storePrefix)
	}
	// The inner envelope is bound under the same namespace at a sibling
	// path (RelayInnerPath); skip those when finding the store-entry.
	innerPrefixSuffix := "/inner/"
	var storedEntryHash hash.Hash
	for _, e := range entries {
		if strings.Contains(e.Path, innerPrefixSuffix) {
			continue
		}
		storedEntryHash = e.Hash
		break
	}
	if storedEntryHash.IsZero() {
		t.Fatalf("R indexed bindings under %s but none looked like the store-entry: %+v", storePrefix, entries)
	}

	entryEntStored, ok := rp.Store().Get(storedEntryHash)
	if !ok {
		t.Fatalf("R indexed entry hash %s but content store missing the bytes", storedEntryHash)
	}
	if entryEntStored.Type != types.TypeRelayStoreEntry {
		t.Fatalf("stored entry type %q != %s", entryEntStored.Type, types.TypeRelayStoreEntry)
	}
	storedSE, err := types.StoreEntryDataFromEntity(entryEntStored)
	if err != nil {
		t.Fatalf("decode stored entry: %v", err)
	}
	if storedSE.Namespace != customNamespace {
		t.Fatalf("stored entry namespace = %q, want %q", storedSE.Namespace, customNamespace)
	}
	if storedSE.PutBy != sPeerID {
		t.Fatalf("stored entry put_by = %q, want S=%q (proves R authenticated S as the session peer)", storedSE.PutBy, sPeerID)
	}
	if storedSE.EnvelopeInner != lastInnerHash {
		t.Fatalf("stored entry envelope_inner = %s, want %s", storedSE.EnvelopeInner, lastInnerHash)
	}

	// Inner envelope is also tree-bound under §3.2 inner path + in R's content store.
	innerPathAbs := "/" + rPeerID + "/" + types.RelayInnerPath(customNamespace, lastInnerHash)
	if innerBoundHash, ok := rIndex.Get(innerPathAbs); !ok {
		t.Fatalf("R did not tree-bind inner envelope at %s", innerPathAbs)
	} else if innerBoundHash != lastInnerHash {
		t.Fatalf("R inner-path bound hash %s != expected %s", innerBoundHash, lastInnerHash)
	}
	innerEntStored, ok := rp.Store().Get(lastInnerHash)
	if !ok {
		t.Fatalf("R missing inner envelope bytes in content store")
	}
	if innerEntStored.Type != types.TypeEnvelope {
		t.Fatalf("stored inner type %q != %s", innerEntStored.Type, types.TypeEnvelope)
	}

	t.Logf("INBOX-RELAY-FALLBACK-1 PASS — seam fired once; R stored entry at %s under D's namespace with put_by=S, envelope_inner=%s",
		types.RelayStorePath(customNamespace, storedEntryHash), lastInnerHash)
}

// TestInboxRelayFallback_SeamDeclinesWhenNoDeclaration proves the
// "byte-identical to v1 for non-RELAY-or-no-declaration peers" property
// from proposal §4. With no inbox-relay decl for D in S's tree, the
// seam returns (nil, false, nil) and NETWORK falls through to today's
// unreachable error path.
func TestInboxRelayFallback_SeamDeclinesWhenNoDeclaration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sKP := mustGenerate(t)
	dKP := mustGenerate(t)

	sp, err := peer.New(
		peer.WithIdentity(sKP),
		peer.WithListenAddr("127.0.0.1:0"),
		peer.WithConnectionGrants(peer.OpenAccessGrants()),
	)
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	listenerCtx, lcancel := context.WithCancel(context.Background())
	t.Cleanup(func() { lcancel(); sp.Close() })
	ready := make(chan struct{})
	go func() { _ = sp.ListenReady(listenerCtx, ready) }()
	<-ready

	resolver := NewTreeInboxRelayResolver(sp)
	declines := 0
	sp.SetDispatchFallback(func(fctx context.Context, peerID crypto.PeerID,
		uri, operation string, params entity.Entity,
		resource *types.ResourceTarget) (*handler.Response, bool, error) {
		if _, ok := resolver.Resolve(string(peerID)); !ok {
			declines++
			return nil, false, nil
		}
		return nil, true, nil
	})

	probeParams, _ := entity.NewEntity("test/probe", cbor.RawMessage([]byte{0xa0}))
	_, err = sp.RemoteExecute(ctx,
		"entity://"+string(dKP.PeerID())+"/system/anything",
		"noop", probeParams, nil)
	if err == nil {
		t.Fatal("expected unreachable error after seam declined; got nil")
	}
	if !strings.Contains(err.Error(), "remote connection") {
		t.Fatalf("expected the v1 unreachable error to surface; got %v", err)
	}
	if declines != 1 {
		t.Fatalf("seam declines = %d, want 1", declines)
	}
}

// mustGenerate is a panic-free crypto.Generate wrapper for test setup.
func mustGenerate(t *testing.T) crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	return kp
}
