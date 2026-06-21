package validate

import (
	"context"
	"fmt"
	"math/rand"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runRelayMultiPrincipal is the multi-principal sub-piece of pre-release
// Test #3 (per RELAY-PRE-RELEASE-TESTS-STATUS §2 ¶2).
//
// The other half of Test #3 — the 5-peer relay-chain fixture — is
// Phase-2-blocked: v1 substrate has only terminal-hop (`next_hop ==
// destination`) routing (EXTENSION-RELAY §13 Q3, §11.2). See
// RELAY-PRE-RELEASE-ARCH-HANDOFF Item 1.
//
// What this proves. Today's relay validator drives every peer with ONE
// shared keypair (single-principal model — convenient for the cap-chain
// continuation tests). The real-world inbox-relay scenario has TWO
// principals: Alice authors the inner EXECUTE addressed to Eve (cap
// pre-arranged out-of-band), then *Bob* — a separate principal — opens
// the connection to the relay and submits the :forward.
//
// The relay's authz check is "may Bob forward through me," not "may
// Alice reach Eve" (the relay can't read the inner). The inner
// envelope's signature must verify against Alice's identity-hash
// — NOT Bob's — when the destination eventually fetches it from
// Mode-S.
//
// This category drives that distinction live:
//
//   - mpr1: setup. Generate a second ephemeral keypair (Alice).
//     Authenticate Alice against B (the relay) on a second connection.
//     Build an inner EXECUTE signed by Alice via that second client.
//     Submit :forward via the validator's normal connection (Bob's).
//     Gate: forward-result.status == queued-fallback (destination
//     unreachable; the §6.2.1 fallback fires, mirroring od2's shape).
//
//   - mpr2: the receive-side signer check. Fetch the inner envelope
//     out of B's relay-store tree (the path the receiver follows per
//     RULING-RECEIVE-SIDE-FETCH); decode it; locate the V7
//     §5.2 invariant-pointer signature over the inner EXECUTE; confirm
//     `signature.Signer == Alice's identity-hash`, and that it does
//     NOT match Bob's (the connection identity). Verifies the signature
//     against Alice's public key. This is the assertion the
//     single-principal model could never make.
func runRelayMultiPrincipal(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catRelayMultiPrincipal)

	const (
		nameMpr1 = "mpr1_two_principals_forward_via_bob_signed_by_alice"
		nameMpr2 = "mpr2_receive_side_signer_is_alice_not_bob"
	)
	r.Declare(nameMpr1,
		"RELAY §3.1 multi-principal: Alice (second principal, authenticated on a separate connection to B) authors the inner EXECUTE; Bob (validator's standard principal) submits :forward through B; §6.2.1 fallback fires (destination unreachable). Authorship and connection-identity are now distinct — the substrate must carry Alice's inner without claiming Bob signed it.")
	r.Declare(nameMpr2,
		"RELAY §3.2 + RULING-RECEIVE-SIDE-FETCH §6.4: the inner envelope fetched from B's relay-store tree (post-fallback) verifies against ALICE's invariant-pointer signature (signature.Signer == Alice's identity-hash, NOT Bob's). The §6.2.1 storage path preserved authorship faithfully across the connection-identity / wire-author divergence.")

	if len(clients) < 2 {
		for _, n := range []string{nameMpr1, nameMpr2} {
			name := n
			r.Run(name, func() CheckOutcome {
				return SkipCheck("requires 2 peers (clients[1] is the relay B; Alice authenticates against B on a second connection)")
			})
		}
		return r.Results()
	}

	bob, relayB := clients[0], clients[1]
	bobPeerID := string(bob.RemotePeerID())
	bPeerID := string(relayB.RemotePeerID())
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// State threaded across mpr1 → mpr2.
	var (
		destPeerID     string
		customNS       string
		aliceHash      hash.Hash
		bobHash        hash.Hash
		originalInner  entity.Entity
		aliceKP        crypto.Keypair
		storedAtNS     string
	)

	r.Run(nameMpr1, func() CheckOutcome {
		// 1) Generate Alice's keypair, distinct from the validator's shared
		//    principal (Bob). Open a second connection to B authenticated as
		//    Alice — same TCP listener, fresh AUTHENTICATE handshake, fresh
		//    connection-bound capability for Alice.
		akp, kerr := crypto.Generate()
		if kerr != nil {
			return FailCheck("generate Alice keypair: " + kerr.Error())
		}
		aliceKP = akp
		ah, ihErr := types.ComputePeerIdentityHash(akp.PublicKey, akp.KeyType)
		if ihErr != nil {
			return FailCheck("alice identity hash: " + ihErr.Error())
		}
		aliceHash = ah

		bh, ihErr := types.ComputePeerIdentityHashFromPeerID(bob.RemotePeerID())
		if ihErr != nil {
			return SkipCheck("bob identity-hash underivable from peer-id: " + ihErr.Error())
		}
		bobHash = bh
		if aliceHash == bobHash {
			return FailCheck("alice and bob produced the same identity-hash — keypair generation collided (improbable)")
		}

		aliceClient, cerr := NewPeerClientWithKeypair(relayB.addr, aliceKP)
		if cerr != nil {
			return FailCheck("open Alice's connection to B: " + cerr.Error())
		}
		defer aliceClient.Close()

		// 2) Inner EXECUTE: signed by ALICE, targeted at an ephemeral
		//    destination (mirrors od2's offline-destination shape so the
		//    §6.2.1 fallback fires). The destination keypair owns the
		//    inbox-relay decl naming B; the decl is published on B's local
		//    tree so the local-tree resolver picks it up (we already proved
		//    the REGISTRY chain elsewhere — this test isolates the
		//    multi-principal axis).
		if !relayB.GrantsAllow("system/peer/inbox-relay/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/inbox-relay/* — start B with --open-access")
		}
		destKP, dkErr := crypto.Generate()
		if dkErr != nil {
			return FailCheck("generate destination keypair: " + dkErr.Error())
		}
		destPeerID = string(destKP.PeerID())
		customNS = "multi-principal-ns-" + suffix
		if perr := publishSignedDeclTo(ctx, relayB, destKP, bPeerID, customNS); perr != nil {
			return FailCheck("publish decl on B: " + perr.Error())
		}

		// 3) Build the inner EXECUTE via Alice's client (so Alice's keypair
		//    signs the inner envelope's invariant-pointer signature).
		payload := mustCreateEntity("test/relay-multi-principal-payload", map[string]string{
			"alice": "authored-this-inner",
			"suffix": suffix,
		})
		inner, ierr := buildInnerExecute(
			aliceClient,
			"entity://"+destPeerID+"/system/tree",
			"put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/multi-principal/" + suffix}},
			"mpr1-"+suffix,
		)
		if ierr != nil {
			return FailCheck("build inner envelope (Alice authoring): " + ierr.Error())
		}
		originalInner = inner

		// 4) Submit :forward via Bob's connection — relay's authz check sees
		//    Bob, the inner contains Alice's signature. Destination is the
		//    ephemeral destPeerID (unreachable; §6.2.1 fallback fires).
		//    Use forwardInnerToUnreachable (NOT forwardToUnreachable, which
		//    would re-build a fresh inner under the connection's keypair and
		//    silently negate the multi-principal axis).
		fres, ferr := forwardInnerToUnreachable(ctx, relayB, inner, destPeerID)
		if ferr != nil {
			return FailCheck(ferr.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q, got %q",
				types.ForwardStatusQueuedFallback, fres.Status))
		}
		if fres.StoredAt != customNS {
			// Default-convention firing would mean Bob's local-tree resolver
			// didn't pick up the decl — fall back to default destPeerID.
			// That's a fallback-decl-resolution bug, not multi-principal,
			// but it would block mpr2.
			return FailCheck(fmt.Sprintf("stored_at=%q; expected decl ns %q (decl-resolution prerequisite for mpr2 failed)",
				fres.StoredAt, customNS))
		}
		storedAtNS = fres.StoredAt
		_ = inner.ContentHash // pinned by originalInner.ContentHash below
		return PassCheck(fmt.Sprintf("Bob's :forward through B carried Alice's inner; queued-fallback @ ns=%s; alice_identity_hash=%s, bob_identity_hash=%s",
			storedAtNS, aliceHash, bobHash))
	})

	r.Run(nameMpr2, func() CheckOutcome {
		if out, ok := r.Require(nameMpr1); !ok {
			return out
		}
		// Poll → tree:get(entry) → tree:get(inner) — same shape as od3.
		pollReq := types.PollRequestData{Namespace: storedAtNS}
		pollParams, _ := pollReq.ToEntity()
		pollStatus, pollResult, perr := relayExecute(ctx, relayB, "poll", pollParams, nil)
		if perr != nil || pollStatus != 200 {
			return FailCheck(fmt.Sprintf("poll on B: status=%d err=%v", pollStatus, perr))
		}
		pr, _ := types.PollResultDataFromEntity(pollResult)
		if len(pr.Entries) < 1 {
			return FailCheck("poll returned 0 entries on namespace " + storedAtNS)
		}
		entryHash := pr.Entries[0]
		entryEnt, _, gerr := relayB.TreeGet(ctx, types.RelayStorePath(storedAtNS, entryHash))
		if gerr != nil {
			return FailCheck("tree:get(store-entry): " + gerr.Error())
		}
		entry, derr := types.StoreEntryDataFromEntity(entryEnt)
		if derr != nil {
			return FailCheck("decode store-entry: " + derr.Error())
		}
		innerEnt, _, gerr := relayB.TreeGet(ctx, types.RelayInnerPath(storedAtNS, entry.EnvelopeInner))
		if gerr != nil {
			return FailCheck("tree:get(inner): " + gerr.Error())
		}
		if innerEnt.ContentHash != originalInner.ContentHash {
			return FailCheck(fmt.Sprintf("inner hash mismatch: tree=%s, original=%s — §9 opacity violated",
				innerEnt.ContentHash, originalInner.ContentHash))
		}

		// Decode and verify the inner's signature against Alice's identity.
		var innerEnv entity.Envelope
		if err := ecf.Decode(innerEnt.Data, &innerEnv); err != nil {
			return FailCheck("decode inner envelope: " + err.Error())
		}
		execHash := innerEnv.Root.ContentHash
		var sig types.SignatureData
		var found bool
		for _, e := range innerEnv.Included {
			if e.Type != types.TypeSignature {
				continue
			}
			s, derr := types.SignatureDataFromEntity(e)
			if derr != nil {
				continue
			}
			if s.Target == execHash {
				sig = s
				found = true
				break
			}
		}
		if !found {
			return FailCheck("inner envelope has no V7 §5.2 signature over the EXECUTE hash in its included set")
		}

		// The key assertion: signer is Alice, NOT Bob.
		if sig.Signer == bobHash {
			return FailCheck(fmt.Sprintf("MULTI-PRINCIPAL VIOLATED: signer=%s == bob_identity_hash. The relay rewrote / replaced Alice's signature with Bob's — §9 opacity + §3.1 invariant-pointer-signature contract broken. expected alice_identity_hash=%s",
				sig.Signer, aliceHash))
		}
		if sig.Signer != aliceHash {
			return FailCheck(fmt.Sprintf("signer=%s; expected alice_identity_hash=%s (bob_identity_hash=%s — distinct, but also unexpected)",
				sig.Signer, aliceHash, bobHash))
		}
		// Verify Alice's signature with her public key.
		if !crypto.Verify(aliceKP.KeyType, aliceKP.PublicKey, execHash.Bytes(), sig.Signature) {
			return FailCheck("Alice's V7 §5.2 signature FAILED to verify — the bytes B served are not what Alice signed")
		}
		_ = bobPeerID
		return PassCheck(fmt.Sprintf("inner signed by alice (signer=%s); bob's identity (%s) does NOT match — connection-author / wire-author cleanly distinct across §6.2.1 fallback storage",
			sig.Signer, bobHash))
	})

	return r.Results()
}

const catRelayMultiPrincipal = "relay_multi_principal"
