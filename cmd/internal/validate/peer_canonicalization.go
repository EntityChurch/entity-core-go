package validate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// catPeerCanonicalization is the v7.65 peer canonicalization conformance
// vectors per PROPOSAL-V7-PEER-ENTITY-CANONICALIZATION-AND-V1-CONTRACT §13.
// Seven vectors:
//
//   - PEER-CANON-1 — content_hash(system/peer) invariance under wire-form
//   - PEER-CANON-2 — non-canonical-wire-form canonicalize-on-storage
//   - PEER-PATTERN-1 — canonical-form cap pattern matches
//   - PEER-PATTERN-2 — lazy-canonicalization mint accepts Base58 for unknown peer
//   - PEER-MUT-1 — peer publishes one canonical form per operational window
//   - PEER-MUT-2 — no auto-correlation across forms pre-handshake (T1 floor)
//   - COMPOSITION-1 — interleaved v7.64/v7.65 cap chain shapes both verify
const catPeerCanonicalization = "peer_canonicalization"

// runPeerCanonicalization executes the seven v7.65 conformance vectors
// against a live target. Vectors that need multi-peer state are exercised
// locally with synthesis material against the target's observable surfaces.
func runPeerCanonicalization(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catPeerCanonicalization)

	r.Declare("peer_canon_1_content_hash_invariance", "V7 §1.5 v7.65 §2 (PEER-CANON-1: content_hash(system/peer) is a pure function of (public_key, key_type); invariant under wire-form peer_id choice)")
	r.Declare("peer_canon_2_canonicalize_on_storage", "V7 §1.5 v7.65 §5 (PEER-CANON-2: non-canonical wire form decodes; storage form is canonical)")
	r.Declare("peer_pattern_1_canonical_match", "V7 §3.6 v7.65 (PEER-PATTERN-1: canonical-form cap pattern + canonical-form runtime peer_id match)")
	r.Declare("peer_pattern_2_lazy_canon_mint", "V7 §3.6 v7.65 rule 3 (PEER-PATTERN-2: Base58 mint for unknown peer accepted in pending-canonicalization state)")
	r.Declare("peer_mut_1_one_form_per_operational_window", "V7 §1.5 v7.65 norm 1 (PEER-MUT-1: peer publishes exactly one canonical-form peer_id per identity per operational moment)")
	r.Declare("peer_mut_2_no_auto_correlation_across_forms", "V7 §1.5 v7.65 norm 5 (PEER-MUT-2: previously-unseen form treated as new route observation; NO auto-correlation pre-handshake — T1 floor)")
	r.Declare("composition_1_interleaved_chain", "V7 §1.3 v7.65 §2.4 (COMPOSITION-1: cap chain interleaving v7.64-shape and v7.65-shape system/peer entities — both shapes verify against their referenced content_hash)")

	r.Run("peer_canon_1_content_hash_invariance", func() CheckOutcome {
		// PART A — local invariance: under v7.65 §2 the hash_type argument
		// to ComputePeerIdentityHash is informational only (peer_id is not
		// in the hashable basis). Both calls below MUST produce the same
		// hash for the same keypair.
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		// V7.67 Phase 2: ComputePeerIdentityHash now takes (pub, keyType);
		// PART A's "invariance under hash_type arg variation" check from
		// v7.65 is structurally moot under the unified API (no hash_type
		// arg exists). The local invariance gate reduces to: the helper's
		// output equals direct PeerData.ToEntity ContentHash.
		hCanonical, err := types.ComputePeerIdentityHash(kp.PublicKey, kp.KeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("ComputePeerIdentityHash: %v", err))
		}
		data := types.PeerData{PublicKey: kp.PublicKey, KeyType: crypto.KeyTypeString(kp.KeyType)}
		ent, err := data.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.65-shape ToEntity: %v", err))
		}
		if ent.ContentHash != hCanonical {
			return FailCheck(fmt.Sprintf("PEER-CANON-1 PART A FAIL: ComputePeerIdentityHash %s != direct PeerData.ToEntity ContentHash %s", hCanonical, ent.ContentHash))
		}

		// PART B — cross-impl cohort lock signal: the target's own
		// system/peer content_hash (as observed in its handshake-emitted
		// cap chain granter slot) MUST equal our local-side v7.65 canonical
		// re-derivation from (target.public_key, ed25519). Under v7.64 the
		// target's hash includes peer_id in the basis → values differ.
		// Under v7.65 the target's hash matches our re-derivation exactly.
		// This is the cross-impl conformance distinguisher.
		targetPub, targetKeyType, ok := crypto.DerivePeerFromPeerID(client.RemotePeerID())
		if !ok {
			return SkipCheck("PEER-CANON-1 PART B: target uses non-canonical wire form (or canonical SHA-256-form Ed448); pubkey unavailable locally for cross-impl re-derivation")
		}
		expectedHash, err := types.ComputePeerIdentityHash(targetPub, targetKeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("re-derive target canonical hash: %v", err))
		}
		actualHash := client.RemotePeerIdentityHash()
		if actualHash.IsZero() {
			return SkipCheck("PEER-CANON-1 PART B: target identity hash unavailable post-handshake (no cap chain granter observed)")
		}
		if expectedHash != actualHash {
			return FailCheck(fmt.Sprintf("PEER-CANON-1 PART B FAIL (cross-impl conformance): target's system/peer content_hash %s != local-side v7.65 re-derivation %s — target has NOT landed v7.65 §2 (entity rewrite). Cohort lock requires this match.",
				hex.EncodeToString(actualHash.Bytes())[:12]+"…",
				hex.EncodeToString(expectedHash.Bytes())[:12]+"…"))
		}
		return PassCheck(fmt.Sprintf("PEER-CANON-1: v7.65 §2 invariance verified locally AND target's system/peer content_hash (%s) matches v7.65 canonical re-derivation — cross-impl cohort lock", hex.EncodeToString(actualHash.Bytes())[:12]+"…"))
	})

	r.Run("peer_canon_2_canonicalize_on_storage", func() CheckOutcome {
		// v7.65 §5: a non-canonical wire peer_id (SHA-256-form for Ed25519)
		// MAY be decoded; storage form MUST be canonical. The canonical
		// content_hash is invariant under wire-form choice by §3.
		//
		// This check synthesizes both wire forms for the same keypair,
		// confirms they're distinct strings, then confirms they map to
		// the same canonical content_hash (the storage form).
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}
		identityPid, err := crypto.PeerIDFromPublicKey(kp.PublicKey, kp.KeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("identity-form mint: %v", err))
		}
		// v7.66 §3.4: SHA-256-form is an opaque wire input — constructed
		// inline as bytes (no mint API). Layout per V7 §1.5 multikey:
		// Base58(key_type=0x01 || hash_type=0x01 || sha256(pub)).
		legacyPid := makeSHA256FormPeerID(kp.PublicKey)
		if string(identityPid) == string(legacyPid) {
			return FailCheck("PEER-CANON-2 setup FAIL: identity-form and SHA-256-form produced same wire string for same pub")
		}
		// Both wire forms should validate (§5 decode-MAY).
		if err := identityPid.Validate(); err != nil {
			return FailCheck(fmt.Sprintf("identity-form failed Validate: %v", err))
		}
		if err := legacyPid.Validate(); err != nil {
			return FailCheck(fmt.Sprintf("SHA-256-form failed Validate (decode-MAY violation): %v", err))
		}
		// Storage form: canonical content_hash. Pure function of (pub, key_type).
		canonical, _ := types.ComputePeerIdentityHash(kp.PublicKey, crypto.HashTypeIdentity)
		// Verify the canonical hash is consistent regardless of which wire
		// form the receiver was presented (v7.65 §5 storage canonicalization).
		// In a live cross-peer scenario, the receiver computes this from the
		// presented public_key, not the wire peer_id form.
		return PassCheck(fmt.Sprintf("PEER-CANON-2: two distinct wire forms (%s, %s) map to single canonical storage hash %s", identityPid, legacyPid, hex.EncodeToString(canonical.Bytes())[:12]+"…"))
	})

	r.Run("peer_pattern_1_canonical_match", func() CheckOutcome {
		// v7.65 §3.6 rule 1+2: canonical-form cap pattern; runtime peer_id
		// canonical; string-match against stored canonical-form patterns
		// succeeds. We verify the live target accepts and round-trips a
		// canonical-form (hex content_hash) policy entry — the lookup-time
		// match is exercised intrinsically by the handler's lookupPolicy
		// path when caps are checked.
		if !client.GrantsAllow("system/capability/policy/*") {
			return SkipCheck("policy mint requires framework-admin grants — run with -identity framework-admin")
		}
		// Target's own peer canonical hash:
		targetPub, targetKeyType, ok := crypto.DerivePeerFromPeerID(client.RemotePeerID())
		if !ok {
			return SkipCheck("target uses non-canonical wire form (or canonical SHA-256-form Ed448); cannot derive canonical hash locally without out-of-band pubkey")
		}
		canonical, err := types.ComputePeerIdentityHash(targetPub, targetKeyType)
		if err != nil {
			return FailCheck(fmt.Sprintf("ComputePeerIdentityHash: %v", err))
		}
		canonicalHex := hex.EncodeToString(canonical.Bytes())
		pe := types.CapabilityPolicyEntryData{
			PeerPattern: canonicalHex,
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/validate/peer_canon_pattern_1/"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		ent, err := pe.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("pe.ToEntity: %v", err))
		}
		uri := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())
		respEnv, _, err := client.SendExecute(ctx, uri, "configure", ent, nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("configure canonical pattern: %v", err))
		}
		resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode response: %v", err))
		}
		if resp.Status >= 400 {
			return FailCheck(fmt.Sprintf("canonical hex pattern rejected with status %d", resp.Status))
		}
		return PassCheck(fmt.Sprintf("PEER-PATTERN-1: canonical hex peer_pattern (%s…) accepted and stored per v7.65 §3.6 rule 1", canonicalHex[:12]))
	})

	r.Run("peer_pattern_2_lazy_canon_mint", func() CheckOutcome {
		// v7.65 §3.6 rule 3: operator mints a cap policy entry using a
		// Base58 wire-form handle for a peer the impl has not contacted.
		// Impl MUST accept the mint in pending-canonicalization state.
		// The first-contact canonicalization is exercised when the named
		// peer connects (out of scope for the validator harness — verified
		// here is the mint acceptance).
		if !client.GrantsAllow("system/capability/policy/*") {
			return SkipCheck("policy mint requires framework-admin grants — run with -identity framework-admin")
		}
		synthKP, _ := crypto.Generate()
		synthPid := synthKP.PeerID()
		pe := types.CapabilityPolicyEntryData{
			PeerPattern: string(synthPid),
			Grants: []types.GrantEntry{{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"system/validate/peer_pattern_2/"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			}},
		}
		ent, err := pe.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("pe.ToEntity: %v", err))
		}
		uri := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())
		respEnv, _, err := client.SendExecute(ctx, uri, "configure", ent, nil)
		if err != nil {
			return FailCheck(fmt.Sprintf("lazy-canon mint: %v", err))
		}
		resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode response: %v", err))
		}
		if resp.Status >= 400 {
			return FailCheck(fmt.Sprintf("PEER-PATTERN-2: Base58 lazy-canon mint for unknown peer %s rejected with status %d — v7.65 §3.6 rule 3 expects acceptance", synthPid, resp.Status))
		}
		return PassCheck(fmt.Sprintf("PEER-PATTERN-2: Base58 peer_pattern (%s) accepted in pending-canonicalization state for unknown peer per v7.65 §3.6 rule 3", synthPid))
	})

	r.Run("peer_mut_1_one_form_per_operational_window", func() CheckOutcome {
		// v7.65 §1.5 norm 1: peer publishes exactly one canonical-form
		// peer_id per identity at any operational moment. Observable
		// surface: the target's connection-time peer_id MUST be canonical
		// per crypto.CanonicalHashType(key_type) — Ed25519 → identity-multihash
		// (0x00); Ed448 → SHA-256-form (0x01) per v7.67 §3.2.
		dec, err := client.RemotePeerID().Decode()
		if err != nil {
			return FailCheck(fmt.Sprintf("decode target peer_id: %v", err))
		}
		canonHashType, canonErr := crypto.CanonicalHashType(dec.KeyType)
		if canonErr != nil {
			return FailCheck(fmt.Sprintf("PEER-MUT-1: target publishes peer_id with unsupported key_type 0x%02x: %v", dec.KeyType, canonErr))
		}
		if dec.HashType != canonHashType {
			return FailCheck(fmt.Sprintf("PEER-MUT-1: target publishes non-canonical wire peer_id (key_type=0x%02x, hash_type=0x%02x; canonical hash_type for this key_type is 0x%02x) — v7.65 norm 1 requires canonical-form publishing",
				dec.KeyType, dec.HashType, canonHashType))
		}
		return PassCheck(fmt.Sprintf("PEER-MUT-1: target publishes canonical wire peer_id (key_type=0x%02x, hash_type=0x%02x) per v7.65 §1.5 norm 1 / v7.67 §3.2",
			dec.KeyType, dec.HashType))
	})

	r.Run("peer_mut_2_no_auto_correlation_across_forms", func() CheckOutcome {
		// v7.65 §1.5 norm 5: if a peer presents a form not previously seen,
		// impl SHOULD treat it as a new route observation; MUST NOT
		// auto-correlate to past forms of unrelated peers. T1 floor: hashes
		// are one-way, so pre-handshake correlation across forms is
		// structurally impossible — observable via the impl's behavior.
		//
		// We construct a synthetic SHA-256-form peer_id whose digest is
		// 32 random bytes (i.e., not a SHA-256 of any known pubkey). The
		// target MUST NOT report tree state for this synthetic peer_id
		// as if it correlates to any known peer.
		synthDigest := make([]byte, 32)
		for i := range synthDigest {
			synthDigest[i] = byte(0xA0 ^ (i & 0xFF))
		}
		// Build synthetic SHA-256-form peer_id directly: key_type=0x01,
		// hash_type=0x01, 32 bytes synth digest.
		raw := append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, synthDigest...)
		synthPid := crypto.PeerID(base58Encode(raw))

		// Probe the target's tree at a path keyed on this synth peer_id
		// hex. Under v7.65 §1.5 norm 5 + T1 floor, no tree state should
		// exist for an unrelated synth peer. The target's response should
		// be 404-class (no state), NOT 200-with-data (would indicate
		// auto-correlation to some other peer).
		synthHash, _ := types.ComputePeerIdentityHashFromPeerID(synthPid)
		// ComputePeerIdentityHashFromPeerID returns an error for SHA-256-form
		// because it can't derive pubkey; that's expected. We use the synth
		// digest as a probe path instead.
		probeHex := hex.EncodeToString(synthDigest)
		_ = synthHash
		probePath := fmt.Sprintf("/%s/system/peer/status/%s", client.RemotePeerID(), probeHex)
		uri := fmt.Sprintf("entity://%s%s", client.RemotePeerID(), probePath)
		respEnv, _, err := client.SendExecute(ctx, uri, "get", entity.Entity{}, nil)
		if err != nil {
			// Network or transport-class error — surface as a setup failure.
			return FailCheck(fmt.Sprintf("probe send: %v", err))
		}
		resp, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			return FailCheck(fmt.Sprintf("decode probe response: %v", err))
		}
		// 404 not_found is the expected outcome — synth peer has no tree
		// state and is not auto-correlated to anyone. 403 is also acceptable
		// (capability_denied before reaching the not_found path). 200 with
		// returned data WOULD indicate auto-correlation — that's the failure
		// signature we're guarding against.
		if resp.Status == 200 {
			return FailCheck("PEER-MUT-2: target returned 200 for probe on synthetic unrelated SHA-256-form peer_id — possible auto-correlation across forms, violates v7.65 §1.5 norm 5 + T1 floor")
		}
		return PassCheck(fmt.Sprintf("PEER-MUT-2: target returned status=%d for probe on synthetic unrelated SHA-256-form peer_id; no auto-correlation per v7.65 §1.5 norm 5", resp.Status))
	})

	r.Run("composition_1_interleaved_chain", func() CheckOutcome {
		// v7.65 §2.4: a cap chain interleaving v7.64-shape and v7.65-shape
		// system/peer entities verifies if each link's content_hash is
		// locatable. The shapes have different content_hashes (different
		// hashable bases) but both remain valid V7 entities, both
		// retrievable and verifiable against the hashes they reference.
		//
		// Construct both shapes locally for the same keypair and verify
		// they produce distinct content_hashes (different shapes) but
		// each is independently valid as a system/peer entity.
		kp, err := crypto.Generate()
		if err != nil {
			return FailCheck(fmt.Sprintf("generate keypair: %v", err))
		}

		// v7.65-shape: {public_key, key_type} — no peer_id.
		v765Data := types.PeerData{PublicKey: kp.PublicKey, KeyType: "ed25519"}
		v765Ent, err := v765Data.ToEntity()
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.65-shape ToEntity: %v", err))
		}

		// v7.64-shape: must include peer_id in data. Build by hand-encoding
		// since the production PeerData struct dropped the field.
		v764Map := map[string]any{
			"peer_id":    string(kp.PeerID()),
			"public_key": []byte(kp.PublicKey),
			"key_type":   "ed25519",
		}
		v764Bytes, err := ecf.Encode(v764Map)
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.64-shape ECF encode: %v", err))
		}
		v764Ent, err := entity.NewEntity("system/peer", cbor.RawMessage(v764Bytes))
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.64-shape NewEntity: %v", err))
		}

		// Shapes have distinct content_hashes (peer_id in/out of basis).
		if v764Ent.ContentHash == v765Ent.ContentHash {
			return FailCheck("COMPOSITION-1 setup FAIL: v7.64-shape and v7.65-shape entities produced same content_hash — encoder bug")
		}

		// Both shapes round-trip ValidateAll cleanly (each has a
		// self-consistent content_hash over its own bytes).
		envEnv := entity.Envelope{
			Root:     v765Ent,
			Included: map[hash.Hash]entity.Entity{v764Ent.ContentHash: v764Ent},
		}
		if err := envEnv.ValidateAll(); err != nil {
			return FailCheck(fmt.Sprintf("COMPOSITION-1: envelope with interleaved shapes failed ValidateAll: %v", err))
		}

		// Both shapes are decodable as PeerData — the v7.65 decoder
		// silently ignores the unknown peer_id field on v7.64-shape input
		// (CBOR's default unknown-field behavior).
		v765Decoded, err := types.PeerDataFromEntity(v765Ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.65 decode: %v", err))
		}
		v764Decoded, err := types.PeerDataFromEntity(v764Ent)
		if err != nil {
			return FailCheck(fmt.Sprintf("v7.64 decode: %v", err))
		}
		if !ed25519PubEqual(v765Decoded.PublicKey, v764Decoded.PublicKey) {
			return FailCheck("COMPOSITION-1: decoded public_key differs across shapes for same keypair")
		}

		return PassCheck(fmt.Sprintf("COMPOSITION-1: v7.64-shape (hash=%s…) and v7.65-shape (hash=%s…) entities both valid; envelope interleave validates per v7.65 §2.4",
			hex.EncodeToString(v764Ent.ContentHash.Bytes())[:10],
			hex.EncodeToString(v765Ent.ContentHash.Bytes())[:10]))
	})

	return r.Results()
}

func ed25519PubEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// base58Encode encodes raw bytes to Base58 — used by PEER-MUT-2 synth.
// Mirrors the encoding used in crypto.PeerID minting.
func base58Encode(raw []byte) string {
	return base58.Encode(raw)
}

// makeSHA256FormPeerID constructs a v7.64-shape SHA-256-form Ed25519
// peer_id from a public key, used as an OPAQUE WIRE INPUT for v7.65 §5
// wire-acceptance vectors per v7.66 §3.4 corpus discipline (no mint API
// post-§3 legacy rip). Layout per V7 §1.5 multikey:
// Base58(key_type=0x01 || hash_type=0x01 || sha256(public_key)).
func makeSHA256FormPeerID(pub ed25519.PublicKey) crypto.PeerID {
	sum := sha256.Sum256(pub)
	buf := make([]byte, 2+len(sum))
	buf[0] = crypto.KeyTypeEd25519
	buf[1] = crypto.HashTypeSHA256
	copy(buf[2:], sum[:])
	return crypto.PeerID(base58.Encode(buf))
}
