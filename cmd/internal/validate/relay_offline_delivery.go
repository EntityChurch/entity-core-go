package validate

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runRelayOfflineDelivery is the EXTENSION-RELAY v1.0 offline-delivery /
// inbox-relay-fallback pre-release behavioral gate. Builds on the
// foundation laid by `relay_multi_peer` — same three-peer A/B/C topology
// and §6.2.1 fallback machinery — and adds the receive-side e2e flow
// that mp1-mp4 leave on the table.
//
// What mp1-mp4 already prove:
//   - mp2: live terminal-hop forwarding (Mode F raw-frame to a reachable C).
//   - mp3: §6.2.1 fallback FIRES when destination is unreachable, and the
//     entry surfaces in :poll. NO valid inbox-relay decl, NO decoding /
//     verifying of the inner envelope at the receiver — the poll just
//     confirms the count.
//   - mp4: forged-redirect rejection — bad signature on a §3.5 decl is
//     rejected (NEGATIVE resolver path).
//
// What this category newly proves:
//
//   - od1: setup with a VALIDLY-SIGNED inbox-relay decl that names B as
//     the relay and a custom namespace. (POSITIVE resolver path — the
//     only mirror of mp4's negative.)
//   - od2: A → B :forward(dest=destPeerID) where destPeerID is unreachable
//     → resolver finds + verifies decl → §6.2.1 fallback stores at the
//     decl's CUSTOM namespace, not the default destination convention.
//     Gate: forward-result.stored_at == decl's custom namespace.
//   - od3: two-hop post-poll fetch per spec §3.1.1 + EXTENSION-RELAY:272
//     (NETWORK §6.5.3.1 two-hop pointer discipline). Poll → store-entry
//     hash → system/content:get → store-entry entity → envelope_inner
//     hash → system/content:get → inner system/envelope bytes. Decode
//     the inner envelope; verify the embedded EXECUTE's V7 §5.2
//     invariant-pointer signature against the source (A) identity.
//   - od4: byte-identity-to-direct gate (§3.1.1 promise) — the inner
//     envelope bytes returned by B over the post-poll fetch are
//     byte-for-byte EQUAL to what A would have written on a direct
//     connection. No decode-then-re-encode at any hop, including the
//     §6.2.1 fallback storage path.
//
// Authoring model: the destination is an EPHEMERAL keypair the validator
// generates (the same shape mp3/mp4 use for strangers / forged peer-ids).
// destPeerID is never a running peer — that's the whole point: "C is
// offline" maps to "destPeerID has no live session anywhere." The
// validator owns destKP, so it can produce a VALIDLY-SIGNED decl whose
// signature the TreeInboxRelayResolver's V7 §5.2 verify accepts. The
// receive-side poll uses the validator's connection to B (B is
// --open-access in the standard cohort rig); the substrate behavior is
// what's under test, not the destination's cap-scoped session.
//
// The "no REGISTRY" path: this category publishes the decl directly into
// B's local tree (the same fixture pattern mp4 uses). REGISTRY-discovered
// delivery is a separate cycle once we extend the resolver to chain
// through REGISTRY before the local-tree fallback.
func runRelayOfflineDelivery(ctx context.Context, clients []*PeerClient) []CheckResult {
	r := NewCheckRunner(catRelayOfflineDelivery)

	r.Declare("od1_setup_signed_decl_b_open",
		"RELAY §3.5 offline-delivery setup: ephemeral destination keypair; signed inbox-relay decl naming B as relay + custom namespace published at B; B's transport profile published in the validator session for the poll path")
	r.Declare("od2_fallback_honors_declared_namespace",
		"RELAY §6.2.1 + §3.5 POSITIVE resolver path: forward to unreachable destPeerID → resolver finds + sig-verifies decl → fallback stored_at == decl's CUSTOM namespace, NOT default destination convention (mirror of mp4's NEGATIVE)")
	r.Declare("od3_post_poll_two_hop_fetch_decode_verify",
		"RELAY §3.2 + §4.2 two-hop receive-side flow: :poll → store-entry hash → tree:get on system/relay/store/{ns}/{entry_hex} → envelope_inner hash → tree:get on system/relay/store/{ns}/inner/{inner_hex} → decode inner system/envelope → verify A's V7 §5.2 invariant-pointer signature on the embedded EXECUTE (system/content is NOT a receive-side dependency)")
	r.Declare("od4_inner_bytes_byte_identical_to_direct",
		"RELAY §3.1.1 byte-identity-to-direct: inner envelope bytes fetched from B's Mode-S store are byte-for-byte EQUAL to what A built (no decode-then-re-encode in the fallback storage path — the §9 opaque-inner discipline holds across :forward and :put storage paths)")
	r.Declare("od5_receive_side_no_system_content_dependency",
		"RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE §6.4 conformance gate: the full poll → fetch → decode → verify flow (od3+od4) completed using only system/tree (no system/content:get invocations). A receiver with tree+relay but WITHOUT system/content can consume Mode-S traffic.")

	if len(clients) < 3 {
		for _, n := range []string{
			"od1_setup_signed_decl_b_open",
			"od2_fallback_honors_declared_namespace",
			"od3_post_poll_two_hop_fetch_decode_verify",
			"od4_inner_bytes_byte_identical_to_direct",
			"od5_receive_side_no_system_content_dependency",
		} {
			name := n
			r.Run(name, func() CheckOutcome { return SkipCheck("requires 3 peers (use -peers a,b,c)") })
		}
		return r.Results()
	}

	// We only need B as the relay + a third client to drive `c` for fixture
	// symmetry with mp1-mp4 (the cohort rig is always --peers a,b,c). The
	// destination is an ephemeral keypair, not a running peer.
	a, b := clients[0], clients[1]
	bPeerID := string(b.RemotePeerID())
	suffix := fmt.Sprintf("%d", rand.Intn(100000))

	// State threaded across od1 → od2 → od3 → od4.
	var (
		destPeerID    string
		destKP        crypto.Keypair
		customNS      string
		originalInner entity.Entity // the inner envelope A built; the byte-identity reference for od4
		storedAtNS    string        // the namespace fallback reported (set by od2; consumed by od3)
	)

	// --- od1 setup: ephemeral destination keypair + signed decl @ B ---------
	r.Run("od1_setup_signed_decl_b_open", func() CheckOutcome {
		if !b.GrantsAllow("system/peer/inbox-relay/*") {
			return SkipCheck("B's connection grants do not allow writes under system/peer/inbox-relay/* — start B with --open-access (peer-manager start --debug)")
		}
		if !b.GrantsAllow("system/signature/*") {
			return SkipCheck("B's connection grants do not allow writes under system/signature/* — start B with --open-access")
		}

		// 1) Generate the ephemeral destination identity. This stands in for
		//    C in real production — but we own the keypair, so the §5.2
		//    signature check in TreeInboxRelayResolver verifies.
		kp, kpErr := crypto.Generate()
		if kpErr != nil {
			return FailCheck("generate destination keypair: " + kpErr.Error())
		}
		destKP = kp
		destPeerID = string(kp.PeerID())
		customNS = "offline-delivery-ns-" + suffix

		// 2) Build the signed inbox-relay decl. Relay = B's peer-id so the
		//    resolveFallbackTarget loop matches localPeerID at B and uses
		//    decl's Namespace = customNS.
		decl := types.InboxRelayData{
			Relays: []types.InboxRelayEntry{
				{Relay: bPeerID, Namespace: customNS, Priority: 10},
			},
		}
		declEnt, err := decl.ToEntity()
		if err != nil {
			return FailCheck("build inbox-relay decl entity: " + err.Error())
		}

		// 3) Sign the decl with the DESTINATION's keypair (V7 §5.2 invariant-
		//    pointer signature; signature target = declEnt.ContentHash).
		signerHash, ihErr := types.ComputePeerIdentityHash(destKP.PublicKey, destKP.KeyType)
		if ihErr != nil {
			return FailCheck("compute destination identity hash: " + ihErr.Error())
		}
		sigBytes := destKP.Sign(declEnt.ContentHash.Bytes())
		sig := types.SignatureData{
			Target:    declEnt.ContentHash,
			Signer:    signerHash,
			Algorithm: keyTypeToAlgorithmName(destKP.KeyType),
			Signature: sigBytes,
		}
		sigEnt, err := sig.ToEntity()
		if err != nil {
			return FailCheck("build signature entity: " + err.Error())
		}

		// 4) Publish decl + sig at B. The TreeInboxRelayResolver looks up
		//    "/" + localPeerID + "/" + InboxRelayStoragePath(destPeerID) and
		//    the matching invariant-pointer signature at LocalSignaturePath.
		declPath := types.InboxRelayStoragePath(destPeerID)
		if _, err := b.TreePut(ctx, declPath, declEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish decl at B/%s: %v", declPath, err))
		}
		sigPath := types.LocalSignaturePath(declEnt.ContentHash)
		if _, err := b.TreePut(ctx, sigPath, sigEnt); err != nil {
			return FailCheck(fmt.Sprintf("publish signature at B/%s: %v", sigPath, err))
		}
		return PassCheck(fmt.Sprintf("ephemeral destPeerID=%s; signed decl(relay=B, namespace=%s) published at B/%s; sig at B/%s",
			destPeerID, customNS, declPath, sigPath))
	})

	// --- od2 forward: §6.2.1 fallback honors decl's custom namespace --------
	r.Run("od2_fallback_honors_declared_namespace", func() CheckOutcome {
		if out, ok := r.Require("od1_setup_signed_decl_b_open"); !ok {
			return out
		}

		// Build inner envelope A would send. Authored by A's keypair (= the
		// validator's shared keypair) so the embedded EXECUTE carries A's
		// V7 §5.2 signature on the wire-target hash. Resource targets a
		// path under destPeerID's tree (it will never actually be delivered
		// — destination unreachable — but the EXECUTE must be well-formed
		// for the byte-identity gate).
		payload := mustCreateEntity("test/relay-offline-payload", map[string]string{
			"content":   "offline-delivery-" + suffix,
			"namespace": customNS,
		})
		inner, err := buildInnerExecute(
			a,
			"entity://"+destPeerID+"/system/tree",
			"put",
			payload,
			&types.ResourceTarget{Targets: []string{"system/offline-delivery/" + suffix}},
			"od2-"+suffix,
		)
		if err != nil {
			return FailCheck("build inner envelope: " + err.Error())
		}
		originalInner = inner

		// Send :forward to B. destPeerID was never reachable from anywhere —
		// B has no transport profile for it; the dispatcher returns
		// ErrDestinationUnreachable; §6.2.1 fallback fires.
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
			return FailCheck(":forward execute: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf(":forward want 200, got %d (code=%q)", status, relayErrCode(result)))
		}
		fres, err := types.ForwardResultDataFromEntity(result)
		if err != nil {
			return FailCheck("decode forward-result: " + err.Error())
		}
		if fres.Status != types.ForwardStatusQueuedFallback {
			return FailCheck(fmt.Sprintf("forward-result.status: want %q (destination unreachable + decl honored), got %q",
				types.ForwardStatusQueuedFallback, fres.Status))
		}
		// THE positive-path gate: stored_at MUST equal the decl's CUSTOM
		// namespace, NOT the default destination peer-id (which is what mp3
		// observed without a decl).
		if fres.StoredAt == destPeerID {
			return FailCheck(fmt.Sprintf("DEFAULT CONVENTION FIRED: stored_at=%q (= destination peer-id) — the signed decl was IGNORED by the resolver. Expected decl's custom namespace %q. §3.5 POSITIVE resolver path broken.",
				fres.StoredAt, customNS))
		}
		if fres.StoredAt != customNS {
			return FailCheck(fmt.Sprintf("stored_at=%q; expected decl's custom namespace %q", fres.StoredAt, customNS))
		}
		storedAtNS = fres.StoredAt
		return PassCheck(fmt.Sprintf("decl honored: fallback stored_at=%s (custom decl namespace, NOT default destPeerID=%s)",
			storedAtNS, destPeerID))
	})

	// --- od3 receive-side e2e: two-hop fetch + decode + verify --------------
	r.Run("od3_post_poll_two_hop_fetch_decode_verify", func() CheckOutcome {
		if out, ok := r.Require("od2_fallback_honors_declared_namespace"); !ok {
			return out
		}

		// 1) Poll B at the decl's namespace; expect one entry.
		pollReq := types.PollRequestData{Namespace: storedAtNS}
		pollParams, _ := pollReq.ToEntity()
		pollStatus, pollResult, err := relayExecute(ctx, b, "poll", pollParams, nil)
		if err != nil {
			return FailCheck(":poll execute: " + err.Error())
		}
		if pollStatus != 200 {
			return FailCheck(fmt.Sprintf(":poll want 200, got %d (code=%q)", pollStatus, relayErrCode(pollResult)))
		}
		pr, err := types.PollResultDataFromEntity(pollResult)
		if err != nil {
			return FailCheck("decode poll-result: " + err.Error())
		}
		if len(pr.Entries) != 1 {
			return FailCheck(fmt.Sprintf(":poll returned %d entries; expected exactly 1 (the fallback put from od2)", len(pr.Entries)))
		}
		entryHash := pr.Entries[0]

		// 2) Two-hop fetch #1: tree:get on the store-entry's namespace-scoped
		//    relay path per RULING-RELAY-RECEIVE-SIDE-FETCH-SURFACE.
		//    The namespace-scoped tree-read cap governs this read; no
		//    system/content extension required on the receiver.
		entryPath := types.RelayStorePath(storedAtNS, entryHash)
		entryEnt, _, err := b.TreeGet(ctx, entryPath)
		if err != nil {
			return FailCheck("tree:get(store-entry @ " + entryPath + "): " + err.Error())
		}
		if entryEnt.Type != types.TypeRelayStoreEntry {
			return FailCheck(fmt.Sprintf("fetched entry type=%q; expected %q (path=%q)", entryEnt.Type, types.TypeRelayStoreEntry, entryPath))
		}
		entry, err := types.StoreEntryDataFromEntity(entryEnt)
		if err != nil {
			return FailCheck("decode store-entry: " + err.Error())
		}
		if entry.Namespace != storedAtNS {
			return FailCheck(fmt.Sprintf("store-entry.namespace=%q; expected %q", entry.Namespace, storedAtNS))
		}
		if entry.PutBy != bPeerID {
			return FailCheck(fmt.Sprintf("store-entry.put_by=%q; expected B's peer-id %q (§6.2.1: relay places on origin's behalf)", entry.PutBy, bPeerID))
		}

		// 3) Two-hop fetch #2: tree:get on the inner envelope's namespace-
		//    scoped relay path (§3.2 nested-namespace tree-binding). Same
		//    namespace-scoped tree-read cap; no system/content needed.
		innerPath := types.RelayInnerPath(storedAtNS, entry.EnvelopeInner)
		innerEnt, _, err := b.TreeGet(ctx, innerPath)
		if err != nil {
			return FailCheck("tree:get(inner-envelope @ " + innerPath + "): " + err.Error())
		}
		if innerEnt.Type != types.TypeEnvelope {
			return FailCheck(fmt.Sprintf("fetched inner type=%q; expected %q (§3.1: inner MUST be a full materialized system/envelope, path=%q)", innerEnt.Type, types.TypeEnvelope, innerPath))
		}

		// 4) Decode the inner envelope's .Data and verify A's V7 §5.2
		//    invariant-pointer signature on the embedded EXECUTE. The inner
		//    envelope's Root carries the EXECUTE; Included carries A's
		//    identity, capability, and signature entities.
		var innerEnv entity.Envelope
		if err := ecf.Decode(innerEnt.Data, &innerEnv); err != nil {
			return FailCheck("decode inner.Data as Envelope: " + err.Error())
		}
		if innerEnv.Root.Type != types.TypeExecute {
			return FailCheck(fmt.Sprintf("inner envelope's root type=%q; expected %q", innerEnv.Root.Type, types.TypeExecute))
		}

		// Locate the EXECUTE's V7 §5.2 invariant-pointer signature in the
		// included set. The signature target is the EXECUTE's content_hash
		// (= the wire target the source signed).
		execHash := innerEnv.Root.ContentHash
		var foundSig types.SignatureData
		var foundSignerKey []byte
		var foundKeyType byte
		var sigOk bool
		for _, e := range innerEnv.Included {
			if e.Type != types.TypeSignature {
				continue
			}
			s, decodeErr := types.SignatureDataFromEntity(e)
			if decodeErr != nil {
				continue
			}
			if s.Target != execHash {
				continue
			}
			foundSig = s
			sigOk = true
			break
		}
		if !sigOk {
			return FailCheck("inner envelope has no V7 §5.2 signature over the EXECUTE's content_hash in its included set")
		}

		// Recover the signer's (public_key, key_type) from the included
		// identity entity whose computed identity-hash matches signature.Signer.
		for _, e := range innerEnv.Included {
			if e.Type != types.TypePeer {
				continue
			}
			pd, decodeErr := types.PeerDataFromEntity(e)
			if decodeErr != nil {
				continue
			}
			keyType, ktOk := crypto.KeyTypeByte(pd.KeyType)
			if !ktOk {
				continue
			}
			ih, ihErr := types.ComputePeerIdentityHash(pd.PublicKey, keyType)
			if ihErr != nil {
				continue
			}
			if ih == foundSig.Signer {
				foundSignerKey = pd.PublicKey
				foundKeyType = keyType
				break
			}
		}
		if foundSignerKey == nil {
			return FailCheck(fmt.Sprintf("inner envelope's included set has no system/peer entity whose identity-hash matches signature.Signer=%s", foundSig.Signer))
		}
		if !crypto.Verify(foundKeyType, foundSignerKey, execHash.Bytes(), foundSig.Signature) {
			return FailCheck("V7 §5.2 signature verification FAILED on the inner EXECUTE — the bytes that traversed the relay path are NOT what A signed (or were corrupted)")
		}

		return PassCheck(fmt.Sprintf("two-hop fetch + decode + verify: entry@%s → envelope_inner=%s → EXECUTE@%s signed by %s ✔",
			entryHash, entry.EnvelopeInner, execHash, foundSig.Signer))
	})

	// --- od4 byte-identity: inner bytes from B == what A built --------------
	r.Run("od4_inner_bytes_byte_identical_to_direct", func() CheckOutcome {
		if out, ok := r.Require("od3_post_poll_two_hop_fetch_decode_verify"); !ok {
			return out
		}
		// Re-fetch by tree path (idempotent). The reference is
		// originalInner.Data — what A built and submitted in :forward's
		// included set. The relay path (intermediate dispatch → §6.2.1
		// fallback → tree-bind → :poll → tree:get) must round-trip the
		// inner.Data BYTES with no transformation.
		innerPath := types.RelayInnerPath(storedAtNS, originalInner.ContentHash)
		innerEnt, _, err := b.TreeGet(ctx, innerPath)
		if err != nil {
			return FailCheck("tree:get(inner by original hash @ " + innerPath + "): " + err.Error())
		}
		if !bytes.Equal([]byte(innerEnt.Data), []byte(originalInner.Data)) {
			return FailCheck(fmt.Sprintf("BYTE-IDENTITY VIOLATED: inner.Data bytes from relay (%d bytes) differ from A's original (%d bytes) — somewhere on the §6.2.1 storage path the relay decoded + re-encoded the inner. §9 + §3.1.1 broken.",
				len(innerEnt.Data), len(originalInner.Data)))
		}
		if innerEnt.ContentHash != originalInner.ContentHash {
			return FailCheck(fmt.Sprintf("inner content_hash drift: relay returned %s; A built %s", innerEnt.ContentHash, originalInner.ContentHash))
		}
		return PassCheck(fmt.Sprintf("byte-identity ✔: inner.Data (%d bytes) hash=%s — what A built is exactly what B returned after the Mode-S round-trip",
			len(innerEnt.Data), innerEnt.ContentHash))
	})

	// --- od5 receive-side conformance gate (no system/content dependency) ---
	r.Run("od5_receive_side_no_system_content_dependency", func() CheckOutcome {
		if out, ok := r.Require("od3_post_poll_two_hop_fetch_decode_verify"); !ok {
			return out
		}
		if out, ok := r.Require("od4_inner_bytes_byte_identical_to_direct"); !ok {
			return out
		}
		// od3 and od4 deliberately used only system/tree (TreeGet) for the
		// post-poll fetch surface — no system/content:get invocations
		// anywhere in this category. The pass-by-construction gate per
		// RULING §6.4: a receiver with tree+relay but WITHOUT system/content
		// can complete the full Mode-S consume flow.
		//
		// To make the assertion non-vacuous, re-run the full receive-side
		// flow (poll → tree:get(entry) → tree:get(inner) → byte-equal)
		// from a fresh poll, confirming the receiver invokes ONLY
		// system/tree + system/relay. system/content may still exist on
		// B — the gate is about the RECEIVER's dependency surface, not
		// B's installed-handler set.
		pollReq := types.PollRequestData{Namespace: storedAtNS}
		pollParams, _ := pollReq.ToEntity()
		pollStatus, pollResult, perr := relayExecute(ctx, b, "poll", pollParams, nil)
		if perr != nil || pollStatus != 200 {
			return FailCheck(fmt.Sprintf("re-poll for conformance gate failed: status=%d err=%v", pollStatus, perr))
		}
		pr, _ := types.PollResultDataFromEntity(pollResult)
		if len(pr.Entries) < 1 {
			return FailCheck("re-poll for conformance gate: 0 entries")
		}
		entryHash := pr.Entries[0]
		entryPath := types.RelayStorePath(storedAtNS, entryHash)
		entryEnt, _, err := b.TreeGet(ctx, entryPath)
		if err != nil {
			return FailCheck("tree:get(store-entry) under conformance gate: " + err.Error())
		}
		entry, err := types.StoreEntryDataFromEntity(entryEnt)
		if err != nil {
			return FailCheck("decode store-entry under conformance gate: " + err.Error())
		}
		innerPath := types.RelayInnerPath(storedAtNS, entry.EnvelopeInner)
		innerEnt, _, err := b.TreeGet(ctx, innerPath)
		if err != nil {
			return FailCheck("tree:get(inner) under conformance gate: " + err.Error())
		}
		if innerEnt.ContentHash != originalInner.ContentHash {
			return FailCheck("inner hash drift under conformance gate")
		}
		return PassCheck("§6.4 conformance ✔: full poll → tree:get(entry) → tree:get(inner) → byte-identity flow completed using only system/tree + system/relay (no system/content invoked)")
	})

	return r.Results()
}

const catRelayOfflineDelivery = "relay_offline_delivery"

// keyTypeToAlgorithmName maps a Keypair.KeyType byte to the legacy string
// the resolver's SignatureData.Algorithm field carries. Kept informational
// per resolver semantics — actual verify uses the key_type byte derived
// from the destination's peer-id, not this string.
func keyTypeToAlgorithmName(keyType byte) string {
	switch keyType {
	case crypto.KeyTypeEd25519:
		return "ed25519"
	case crypto.KeyTypeEd448:
		return "ed448"
	}
	return "unknown"
}
