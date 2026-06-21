package validate

import (
	"context"
	"fmt"
	"math/rand"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runRelayOfflineDeliveryRegistry is the EXTENSION-RELAY §3.5
// REGISTRY-served inbox-relay decl gate (pre-release Test #2b per
// RELAY-PRE-RELEASE-TESTS-STATUS §1, Option A).
//
// Difference from relay_offline_delivery: that category publishes the
// signed decl into B's LOCAL tree (B's resolver = TreeInboxRelayResolver
// only). This category publishes the decl into R's tree — R is a
// separate "registry" peer that B has been configured to consult before
// its local-tree fallback (B started with
// `--inbox-relay-registry <R's peer-id>`).
//
// What this proves:
//
//   - odr1: setup. Ephemeral destination keypair; signed decl + sig
//     published on R's tree; R's transport profile published on B so B
//     can dial R.
//   - odr2: POSITIVE chain — remote resolver hits. A → B :forward(dest=
//     destPeerID) → B's chain consults R → tree:get on R returns the
//     decl + sig → V7 §5.2 verify ✔ → §6.2.1 fallback honors decl's
//     custom namespace (NOT the default destination convention). This is
//     the test that proves B "saw" R; if B wasn't started with the
//     registry chain, the resolver returns nothing and default
//     convention fires.
//   - odr3: NEGATIVE chain (forged-redirection defense). Different
//     destPeerID, decl on R, but sig is forged (signed by a stranger,
//     not destPeerID). B's resolver chain consults R, sig-verifies
//     fail-closed, falls through (local-tree empty too), §6.2.1 uses
//     default convention. This is the registry-side mirror of mp4 (and
//     proves R itself being compromised doesn't get a peer past the
//     V7 §5.2 check).
//   - odr4: CHAIN FALLTHROUGH. Different destPeerID, NO decl on R, but
//     a valid decl on B's local tree. B's chain consults R (miss),
//     falls through to local-tree (hit), honors the local decl's
//     namespace. Proves the (REMOTE → LOCAL) chain composes correctly.
//
// Setup requirement: clients[1] (B) must have been started with
// `--inbox-relay-registry <clients[0]'s peer-id>`. peer-manager's
// `--inbox-relay-registry <peer-name>` does the name → peer-id
// translation. If the flag is missing, odr2 will report
// `DEFAULT CONVENTION FIRED — B's chain returned nothing` which is the
// recognizable miswire signature.
func runRelayOfflineDeliveryRegistry(ctx context.Context, clients []*PeerClient, httpURLs, wsURLs []string) []CheckResult {
	r := NewCheckRunner(catRelayOfflineDeliveryRegistry)

	const (
		nameOdr1 = "odr1_setup_signed_decl_on_registry"
		nameOdr2 = "odr2_remote_resolver_honors_decl_namespace"
		nameOdr3 = "odr3_forged_sig_on_registry_fails_closed"
		nameOdr4 = "odr4_chain_falls_through_to_local_tree"
	)

	r.Declare(nameOdr1,
		"RELAY §3.5 REGISTRY-served decl setup: publish signed inbox-relay decl + V7 §5.2 sig on R's tree; publish R's transport profile in B so the remote resolver can dial")
	r.Declare(nameOdr2,
		"RELAY §3.5 + §6.2.1 POSITIVE chain: B (started with --inbox-relay-registry R) → A :forward to unreachable destPeerID → B's resolver chain consults R via remote tree:get → finds + sig-verifies decl → fallback stored_at == decl's CUSTOM namespace (NOT default destination — that signature == B's chain was miswired)")
	r.Declare(nameOdr3,
		"RELAY §3.5 + V7 §5.2 forged-redirection at the REGISTRY layer: forged decl on R signed by a stranger → B's chain queries R, sig-verify fail-closed, chain falls through (local-tree empty), §6.2.1 default convention fires")
	r.Declare(nameOdr4,
		"RELAY §3.5 chain composition: no decl on R → B's remote resolver misses → falls through to local-tree resolver → finds valid decl on B's own tree → honors that decl's custom namespace. Proves (REMOTE → LOCAL) Chain composes correctly.")

	if len(clients) < 2 {
		for _, n := range []string{nameOdr1, nameOdr2, nameOdr3, nameOdr4} {
			name := n
			r.Run(name, func() CheckOutcome {
				return SkipCheck("requires 2 peers (clients[0]=R registry, clients[1]=B relay started with --inbox-relay-registry <R's name>)")
			})
		}
		return r.Results()
	}

	regClient, b := clients[0], clients[1]
	bPeerID := string(b.RemotePeerID())
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// Per-vector state.
	var (
		destPositive  string
		destForged    string
		destFallthru  string
		nsPositive    = "registry-served-ns-" + suffix
		nsFallthrough = "local-fallback-ns-" + suffix
	)

	// --- odr1: setup decl + sig on R, transport profile on B ---------------
	r.Run(nameOdr1, func() CheckOutcome {
		if !regClient.GrantsAllow("system/peer/inbox-relay/*") ||
			!regClient.GrantsAllow("system/signature/*") {
			return SkipCheck("R's connection grants do not allow writes under system/peer/inbox-relay/* or system/signature/* — start R with --open-access")
		}
		if !b.GrantsAllow("system/peer/transport/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/transport/* — start B with --open-access")
		}

		// 1) R's transport profile published in B (B needs a route to dial R).
		// Thread H: HTTP profile when -http-peers is set for clients[0] (R),
		// else TCP. The remote tree:get B issues against R rides whichever
		// transport the profile names — Peer.SendRawFrameTo type-switches.
		rProfile := transportProfileForPeer(clients, 0, httpURLs, wsURLs)
		rHash, err := types.ComputePeerIdentityHashFromPeerID(regClient.RemotePeerID())
		if err != nil {
			return SkipCheck("R identity-hash underivable from peer-id (SHA-256-form not supported by remote resolver yet): " + err.Error())
		}
		rTransportPath := "system/peer/transport/" + types.PeerIdentityHashHex(rHash) + "/primary"
		if _, err := b.TreePut(ctx, rTransportPath, rProfile); err != nil {
			return FailCheck(fmt.Sprintf("publish R's transport profile on B at %s: %v", rTransportPath, err))
		}

		// 2) Ephemeral destination for the POSITIVE chain (odr2): signed decl
		//    + matching sig on R's tree.
		destKP, derr := crypto.Generate()
		if derr != nil {
			return FailCheck("generate destination keypair: " + derr.Error())
		}
		destPositive = string(destKP.PeerID())
		if perr := publishSignedDeclTo(ctx, regClient, destKP, bPeerID, nsPositive); perr != nil {
			return FailCheck("publish positive decl on R: " + perr.Error())
		}

		return PassCheck(fmt.Sprintf("R transport→B@%s ✔; signed decl(relay=B, ns=%s) for destPeerID=%s published on R",
			rTransportPath, nsPositive, destPositive))
	})

	// --- odr2: positive — chain hits remote, honors decl namespace ---------
	r.Run(nameOdr2, func() CheckOutcome {
		if out, ok := r.Require(nameOdr1); !ok {
			return out
		}
		fres, err := forwardToUnreachable(ctx, clients[0], b, destPositive, "odr2-"+suffix)
		if err != nil {
			return FailCheck(err.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q, got %q", types.ForwardStatusQueuedFallback, fres.Status))
		}
		if fres.StoredAt == destPositive {
			return FailCheck(fmt.Sprintf("DEFAULT CONVENTION FIRED — B's chain returned nothing. Likely B was NOT started with --inbox-relay-registry <R-name>, OR R is unreachable from B, OR the remote tree:get failed. stored_at=%q expected %q",
				fres.StoredAt, nsPositive))
		}
		if fres.StoredAt != nsPositive {
			return FailCheck(fmt.Sprintf("stored_at=%q; expected REGISTRY-served decl's namespace %q", fres.StoredAt, nsPositive))
		}
		return PassCheck(fmt.Sprintf("B's chain consulted R via remote tree:get, sig-verified, honored decl ns=%s (NOT default destPeerID=%s)",
			fres.StoredAt, destPositive))
	})

	// --- odr3: forged sig on R → fail-closed → default convention ----------
	r.Run(nameOdr3, func() CheckOutcome {
		if out, ok := r.Require(nameOdr1); !ok {
			return out
		}
		// Fresh destination identity.
		destKP, derr := crypto.Generate()
		if derr != nil {
			return FailCheck("generate destination keypair: " + derr.Error())
		}
		destForged = string(destKP.PeerID())

		// Build the decl naming B (same shape as the positive case).
		decl := types.InboxRelayData{
			Relays: []types.InboxRelayEntry{{Relay: bPeerID, Namespace: "forged-ns-" + suffix, Priority: 10}},
		}
		declEnt, derr := decl.ToEntity()
		if derr != nil {
			return FailCheck("build decl: " + derr.Error())
		}

		// Forge: sign with a STRANGER's key, not destKP. The signer-hash
		// cross-check in the resolver compares against destPeerID's identity
		// hash, so this is the canonical forged-redirection vector but at
		// the registry layer (R itself is compromised, in spirit).
		strangerKP, derr := crypto.Generate()
		if derr != nil {
			return FailCheck("generate stranger keypair: " + derr.Error())
		}
		strangerHash, ihErr := types.ComputePeerIdentityHash(strangerKP.PublicKey, strangerKP.KeyType)
		if ihErr != nil {
			return FailCheck("compute stranger identity hash: " + ihErr.Error())
		}
		sig := types.SignatureData{
			Target:    declEnt.ContentHash,
			Signer:    strangerHash,
			Algorithm: keyTypeToAlgorithmName(strangerKP.KeyType),
			Signature: strangerKP.Sign(declEnt.ContentHash.Bytes()),
		}
		sigEnt, derr := sig.ToEntity()
		if derr != nil {
			return FailCheck("build sig: " + derr.Error())
		}

		// Publish forged decl + sig on R's tree at the canonical paths.
		declPath := types.InboxRelayStoragePath(destForged)
		if _, err := regClient.TreePut(ctx, declPath, declEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish forged decl on R/%s: %v", declPath, err))
		}
		sigPath := types.LocalSignaturePath(declEnt.ContentHash)
		if _, err := regClient.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish forged sig on R/%s: %v", sigPath, err))
		}

		// Now :forward and gate. Default convention (stored_at == destForged)
		// is the EXPECTED outcome — the chain consulted R, sig-failed, fell
		// through to local-tree (empty), §6.2.1 default fires.
		fres, ferr := forwardToUnreachable(ctx, clients[0], b, destForged, "odr3-"+suffix)
		if ferr != nil {
			return FailCheck(ferr.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q, got %q", types.ForwardStatusQueuedFallback, fres.Status))
		}
		if fres.StoredAt != destForged {
			return FailCheck(fmt.Sprintf("FORGED DECL HONORED — V7 §5.2 forged-redirection defense at registry layer BROKEN. stored_at=%q (forged ns or other), expected default convention %q",
				fres.StoredAt, destForged))
		}
		return PassCheck(fmt.Sprintf("forged sig on R fail-closed; fallback default convention stored_at=%s (registry forged-redirection defense ✔)", fres.StoredAt))
	})

	// --- odr4: chain composition — miss on R, hit on local tree -----------
	r.Run(nameOdr4, func() CheckOutcome {
		if out, ok := r.Require(nameOdr1); !ok {
			return out
		}
		// Fresh destination identity. No decl published on R for this one.
		destKP, derr := crypto.Generate()
		if derr != nil {
			return FailCheck("generate destination keypair: " + derr.Error())
		}
		destFallthru = string(destKP.PeerID())

		// Publish a valid decl on B's LOCAL tree (the second link in the
		// chain). This is the same shape relay_offline_delivery uses.
		if err := publishSignedDeclTo(ctx, b, destKP, bPeerID, nsFallthrough); err != nil {
			return FailCheck("publish local-tree decl on B: " + err.Error())
		}

		fres, ferr := forwardToUnreachable(ctx, clients[0], b, destFallthru, "odr4-"+suffix)
		if ferr != nil {
			return FailCheck(ferr.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q, got %q", types.ForwardStatusQueuedFallback, fres.Status))
		}
		if fres.StoredAt == destFallthru {
			return FailCheck(fmt.Sprintf("DEFAULT CONVENTION FIRED — neither remote nor local resolver hit. Expected local decl's ns=%q, got default destPeerID=%q",
				nsFallthrough, fres.StoredAt))
		}
		if fres.StoredAt != nsFallthrough {
			return FailCheck(fmt.Sprintf("stored_at=%q; expected local-tree decl namespace %q", fres.StoredAt, nsFallthrough))
		}
		return PassCheck(fmt.Sprintf("chain composed: R miss → local-tree hit → honored ns=%s (Chain(REMOTE, LOCAL) walking in order ✔)",
			fres.StoredAt))
	})

	return r.Results()
}

const catRelayOfflineDeliveryRegistry = "relay_offline_delivery_registry"

// publishSignedDeclTo builds + signs an inbox-relay decl naming `relayPeerID`
// as the relay with the given namespace, signs it with destKP, and PUTs the
// decl + sig on `client`'s tree at the canonical paths.
func publishSignedDeclTo(ctx context.Context, client *PeerClient, destKP crypto.Keypair, relayPeerID, namespace string) error {
	destPeerID := string(destKP.PeerID())
	decl := types.InboxRelayData{
		Relays: []types.InboxRelayEntry{{Relay: relayPeerID, Namespace: namespace, Priority: 10}},
	}
	declEnt, err := decl.ToEntity()
	if err != nil {
		return fmt.Errorf("build decl entity: %w", err)
	}
	signerHash, err := types.ComputePeerIdentityHash(destKP.PublicKey, destKP.KeyType)
	if err != nil {
		return fmt.Errorf("compute identity hash: %w", err)
	}
	sig := types.SignatureData{
		Target:    declEnt.ContentHash,
		Signer:    signerHash,
		Algorithm: keyTypeToAlgorithmName(destKP.KeyType),
		Signature: destKP.Sign(declEnt.ContentHash.Bytes()),
	}
	sigEnt, err := sig.ToEntity()
	if err != nil {
		return fmt.Errorf("build sig entity: %w", err)
	}
	declPath := types.InboxRelayStoragePath(destPeerID)
	if _, err := client.TreePut(ctx, declPath, declEnt); err != nil {
		return fmt.Errorf("publish decl at %s: %w", declPath, err)
	}
	sigPath := types.LocalSignaturePath(declEnt.ContentHash)
	if _, err := client.TreePut(ctx, sigPath, sigEnt); err != nil {
		return fmt.Errorf("publish sig at %s: %w", sigPath, err)
	}
	return nil
}

// forwardToUnreachable builds an inner EXECUTE authored by `a` targeting a
// (presumed unreachable) destPeerID, sends it as a :forward on `b`, and
// returns the decoded forward-result. The TTL is high enough that B treats
// this as a terminal forward (next_hop == destination).
func forwardToUnreachable(ctx context.Context, a, b *PeerClient, destPeerID, requestSuffix string) (types.ForwardResultData, error) {
	payload := mustCreateEntity("test/relay-registry-payload", map[string]string{
		"suffix": requestSuffix,
	})
	inner, err := buildInnerExecute(
		a,
		"entity://"+destPeerID+"/system/tree",
		"put",
		payload,
		&types.ResourceTarget{Targets: []string{"system/relay-registry/" + requestSuffix}},
		requestSuffix,
	)
	if err != nil {
		return types.ForwardResultData{}, fmt.Errorf("build inner envelope: %w", err)
	}
	return forwardInnerToUnreachable(ctx, b, inner, destPeerID)
}

// forwardInnerToUnreachable submits a pre-built inner envelope as a :forward
// via b. Use this when the caller needs to control the inner's authorship
// (e.g., the multi-principal vector where the inner author and the
// connection author differ).
func forwardInnerToUnreachable(ctx context.Context, b *PeerClient, inner entity.Entity, destPeerID string) (types.ForwardResultData, error) {
	fr := types.ForwardRequestData{
		Destination:   destPeerID,
		NextHop:       destPeerID,
		TTLHops:       3,
		EnvelopeInner: inner.ContentHash,
	}
	params, _ := fr.ToEntity()
	included := map[hash.Hash]entity.Entity{inner.ContentHash: inner}
	status, result, err := relayExecute(ctx, b, "forward", params, included)
	if err != nil {
		return types.ForwardResultData{}, fmt.Errorf(":forward execute: %w", err)
	}
	if status != 200 {
		return types.ForwardResultData{}, fmt.Errorf(":forward want 200, got %d (code=%q)", status, relayErrCode(result))
	}
	fres, err := types.ForwardResultDataFromEntity(result)
	if err != nil {
		return types.ForwardResultData{}, fmt.Errorf("decode forward-result: %w", err)
	}
	return fres, nil
}
