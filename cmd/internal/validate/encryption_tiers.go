// ENC-CERT-LIFECYCLE-1 at Tiers B and C, and ENC-TIER-INTEROP-1.
//
// §16 pins ENC-CERT-LIFECYCLE-1 as "one vector per tier (A/B/C); MUST
// pass at the tier-set the peer claims" — Tier A alone was built, so the
// two tiers that involve the ATTESTATION and IDENTITY substrates went
// unexercised. Together with ENC-TIER-INTEROP-1 these are the BLOCK-1
// end-to-end gate that closes v1.0; §16 is explicit that byte-equality
// of the primitive (BLOCK-0, locked 3-way) is necessary but not
// sufficient for a privacy primitive.
//
// The two tiers publish differently, and the difference is forced, not
// stylistic:
//
//   - Tier B writes its attestation with tree:put at the §4.2.b path.
//     ATTESTATION imposes no authority chain on an encryption-key
//     attestation, so the bytes tree:put stores are the bytes its
//     create op would store, and the peer's attestation handler indexes
//     them off the tree change either way. Routing through that op
//     would only make an ATTESTATION grant failure look like an
//     encryption conformance failure.
//
//   - Tier C CANNOT do that. IDENTITY's tree hook runs
//     IdentityVerifyCert over anything landing under
//     system/identity/*/cert/ and fail-closed UNBINDS what does not
//     validate — so a raw-written identity-cert reads back 404. That is
//     identity behaving correctly, and it means a Tier-C claim is only
//     real if identity is actually configured. The vector therefore
//     brings identity up (quorum → controller cert → configure) and
//     publishes the encryption cert through identity:create_attestation.
//     Discovered by writing it the Tier-B way first and watching the
//     read-back 404.
package validate

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/encvectors"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/encryption"
	identitysdk "go.entitychurch.org/entity-core-go/ext/identity/sdk"
)

// encPubkeyPath is the §4.2.a publication path, shared by Tiers A and B
// ("publish the system/encryption-pubkey entity at the same path as
// Tier A") and by the inner pubkey a Tier-C cert attests to.
func encPubkeyPath(h hash.Hash) string {
	return "system/encryption-pubkey/" + hex.EncodeToString(h.Bytes())
}

// encTierBAttestationPath is the §4.2.b publication path.
func encTierBAttestationPath(h hash.Hash) string {
	return "system/encryption/attestation/" + hex.EncodeToString(h.Bytes())
}

// encTierCCertPath is where a Tier-C encryption cert lands — IDENTITY's
// canonical mode-derived path, per the ruling of 2026-08-09 (arch
// `a19234e`).
//
// This shipped as a documented divergence with a filed spec issue; the
// ruling adopted it and went further. **ENCRYPTION MUST NOT define, name
// or write any path segment inside `system/identity/`** — IDENTITY owns
// that namespace. The cert is created through `identity:create_attestation`,
// so IDENTITY's canonical path function decides where it lands, and an
// encryption cert is found by enumerating certs at the mode-derived path
// and filtering `properties.function == "encryption"` — a filter, never a
// per-function subtree.
//
// Worth recording what the ruling corrected beyond what we filed: we
// reported two sites, arch found six. The other four are in unbuilt
// features (Tier-2 backup, Shamir shares) and would have surfaced one at
// a time as each was built. Our framing — "encryption depends on
// identity" — was also wrong: ENCRYPTION does not require IDENTITY (§1),
// the tier ladder is a deliberate optional-dependency design, and the
// defect was namespace ownership inside the optional tier, not a
// dependency. Naming it as a dependency would have pointed at
// re-architecting the ladder.
func encTierCCertPath(h hash.Hash) string {
	return "system/identity/public/cert/" + hex.EncodeToString(h.Bytes())
}

// encFunctionEncryption is ENCRYPTION §4.2.c's required cert function.
// IDENTITY §4.2 defines controller/agent/identifier and explicitly
// permits app-defined values; "encryption" is ENCRYPTION's.
const encFunctionEncryption = "encryption"

// mintEncPubkey authors one inner system/encryption-pubkey entity and
// returns it with its X25519 private key. `created` is a caller-chosen
// pin: §4.4 picks the most recent live key by this field, so a lifecycle
// that rotates needs to control it.
func mintEncPubkey(created uint64) (*ecdh.PrivateKey, entity.Entity, error) {
	priv, err := ecdh.X25519().GenerateKey(secureRand{})
	if err != nil {
		return nil, entity.Entity{}, fmt.Errorf("gen X25519: %w", err)
	}
	ent, err := encEntityFromData(types.TypeEncryptionPubkey, types.EncryptionPubkeyData{
		EncKeyType:       uint(types.EncKeyTypeX25519),
		PublicKey:        priv.PublicKey().Bytes(),
		SupportedAEADIDs: []uint{uint(types.AEADIDXChaCha20Poly1305)},
		SupportedKDFIDs:  []uint{uint(types.KDFIDHKDFSHA256)},
		Created:          created,
	})
	if err != nil {
		return nil, entity.Entity{}, fmt.Errorf("build pubkey entity: %w", err)
	}
	return priv, ent, nil
}

// publishSigned puts an entity at a path and binds the V7
// invariant-pointer signature that authorizes it (§4.2.a / V7 §5.2).
func publishSigned(ctx context.Context, client *PeerClient, path string, ent entity.Entity) error {
	if _, err := client.TreePut(ctx, path, ent); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	if err := publishInvariantSig(ctx, client, ent.ContentHash); err != nil {
		return fmt.Errorf("sign %s: %w", path, err)
	}
	return nil
}

// --- ENC-CERT-LIFECYCLE-1, Tier B (+ATTESTATION) ---

// runEncCertLifecycleTierB exercises §4.2.b: the inner pubkey is
// published exactly as at Tier A, and publication AUTHORITY is carried
// by a system/attestation with properties.kind="encryption-key".
// Rotation is the substrate `supersedes` chain (§4.0); revocation is the
// universal ATTESTATION revocation kind rather than encryption's own
// revocation entity.
func runEncCertLifecycleTierB(ctx context.Context, client *PeerClient) CheckOutcome {
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise lifecycle")
	}
	peerEnt := client.IdentityEntity()

	// Publish — inner pubkey + the encryption-key attestation over it.
	_, pkEnt, err := mintEncPubkey(10)
	if err != nil {
		return FailCheck(err.Error())
	}
	if err := publishSigned(ctx, client, encPubkeyPath(pkEnt.ContentHash), pkEnt); err != nil {
		return FailCheck(err.Error())
	}
	attProps, err := types.EncodeProperties(struct {
		Kind string `cbor:"kind"`
	}{Kind: "encryption-key"})
	if err != nil {
		return FailCheck("encode attestation properties: " + err.Error())
	}
	attData := types.AttestationData{
		Attesting:  peerEnt.ContentHash,
		Attested:   pkEnt.ContentHash,
		Properties: attProps,
	}
	attEnt, err := attData.ToEntity()
	if err != nil {
		return FailCheck("build attestation: " + err.Error())
	}
	if err := publishSigned(ctx, client, encTierBAttestationPath(attEnt.ContentHash), attEnt); err != nil {
		return FailCheck(err.Error())
	}

	// Rotate — a fresh pubkey with a newer `created`, attested by a
	// successor that names the old attestation in `supersedes`.
	_, newPkEnt, err := mintEncPubkey(20)
	if err != nil {
		return FailCheck(err.Error())
	}
	if err := publishSigned(ctx, client, encPubkeyPath(newPkEnt.ContentHash), newPkEnt); err != nil {
		return FailCheck(err.Error())
	}
	prev := attEnt.ContentHash
	newAttData := types.AttestationData{
		Attesting:  peerEnt.ContentHash,
		Attested:   newPkEnt.ContentHash,
		Properties: attProps,
		Supersedes: &prev,
	}
	newAttEnt, err := newAttData.ToEntity()
	if err != nil {
		return FailCheck("build successor attestation: " + err.Error())
	}
	if err := publishSigned(ctx, client, encTierBAttestationPath(newAttEnt.ContentHash), newAttEnt); err != nil {
		return FailCheck(err.Error())
	}

	// Revoke the ORIGINAL pubkey via the universal revocation kind. The
	// attestation revoking it attests over the pubkey hash, so a
	// resolver that keys revocation by inner pubkey (as §4.4 requires,
	// since that is the value senders bind) sees it.
	revProps, err := types.EncodeProperties(struct {
		Kind   string `cbor:"kind"`
		Reason string `cbor:"reason,omitempty"`
	}{Kind: "revocation", Reason: "rotated"})
	if err != nil {
		return FailCheck("encode revocation properties: " + err.Error())
	}
	revEnt, err := types.AttestationData{
		Attesting:  peerEnt.ContentHash,
		Attested:   pkEnt.ContentHash,
		Properties: revProps,
	}.ToEntity()
	if err != nil {
		return FailCheck("build revocation attestation: " + err.Error())
	}
	if err := publishSigned(ctx, client, encTierBAttestationPath(revEnt.ContentHash), revEnt); err != nil {
		return FailCheck(err.Error())
	}

	// Everything must have been accepted and be readable back.
	for _, p := range []string{
		encPubkeyPath(pkEnt.ContentHash), encPubkeyPath(newPkEnt.ContentHash),
		encTierBAttestationPath(attEnt.ContentHash), encTierBAttestationPath(newAttEnt.ContentHash),
		encTierBAttestationPath(revEnt.ContentHash),
	} {
		if _, _, err := client.TreeGet(ctx, p); err != nil {
			return FailCheck("post-write resolve " + p + ": " + err.Error())
		}
	}

	// Behavioral half — a sender walking §4.4 must land on the rotated
	// key, not the revoked one. Anything less and "revoke" is a write
	// with no consequence.
	// The attestations are the CARRIERS; the ordering keys come off the
	// pubkey entities they attest (§4.4, ruled 2026-08-09-b) — an
	// attestation has no `created` to order by.
	pubs := encryption.RecipientPublications{
		TierB: []encryption.Carrier{
			{Hash: attEnt.ContentHash, Pubkey: pkEnt.ContentHash, Live: true},
			{Hash: newAttEnt.ContentHash, Pubkey: newPkEnt.ContentHash, Live: true},
		},
		Pubkeys: map[hash.Hash]encryption.PubkeyEntity{
			pkEnt.ContentHash:    {Created: 10},
			newPkEnt.ContentHash: {Created: 20},
		},
		RevokedPubkeys: map[hash.Hash]bool{pkEnt.ContentHash: true},
	}
	res, err := encryption.ResolveRecipientKey(pubs)
	if err != nil {
		return FailCheck("Tier-B §4.4 resolution: " + err.Error())
	}
	if res.Tier != encryption.TierB {
		return FailCheck(fmt.Sprintf("Tier-B resolution landed at tier %q, want B", res.Tier))
	}
	if res.Pubkey != newPkEnt.ContentHash {
		return FailCheck(fmt.Sprintf("Tier-B resolution bound %s, want rotated key %s",
			res.Pubkey, newPkEnt.ContentHash))
	}
	if res.Dropped.PubkeyRevoked != 1 {
		return FailCheck(fmt.Sprintf("Tier-B resolution dropped %d key-revoked, want 1 — revocation was not consulted",
			res.Dropped.PubkeyRevoked))
	}
	// And a sender that names the revoked key explicitly is refused
	// outright (§11 / §15), not silently redirected to the successor.
	if _, err := encryption.ResolveCurrentRecipient(pkEnt.ContentHash,
		[]types.EncryptionRevocationData{{Revokes: pkEnt.ContentHash, Reason: "rotated", Created: 30}},
		nil,
	); !errors.Is(err, encryption.ErrEncryptionKeyRevoked) {
		return FailCheck("Tier-B explicit request for revoked key MUST fail encryption_key_revoked, got: " +
			fmt.Sprint(err))
	}
	return PassCheck("Tier-B encryption-key attestation published, superseded, and revoked; §4.4 binds the rotated key and refuses the revoked one")
}

// --- ENC-CERT-LIFECYCLE-1, Tier C (+IDENTITY) ---

// runEncCertLifecycleTierC exercises §4.2.c: publication authority is an
// identity-cert attestation with properties.function="encryption",
// attesting the inner pubkey up to the peer's own key as controller.
// Rotation is the identity-rotation-handoff chain; revocation is the
// universal kind under controller authority.
//
// The single-peer shape used here is Tier C's degenerate case (one agent
// under one controller). Multi-device — several agents each publishing
// their own encryption cert under one logical identity — is Tier C's
// distinguishing feature and is NOT covered by this vector; it needs a
// second peer holding a second private key. Called out rather than
// quietly folded in, because "Tier C passes" would otherwise read as a
// multi-device claim.
func runEncCertLifecycleTierC(ctx context.Context, client *PeerClient) CheckOutcome {
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise lifecycle")
	}

	// Tier C means IDENTITY is not merely compiled in but CONFIGURED: a
	// peer with no controller has no authority chain for a cert to
	// validate against, and identity's fail-closed tree hook unbinds any
	// cert written without one — which is why publishing a Tier-C cert
	// by raw tree:put reads back 404. So the vector brings identity up
	// first (quorum → controller cert → configure), then publishes the
	// encryption cert through identity's own op. That is the only shape
	// in which a Tier-C claim is real.
	idClient := identitysdk.NewClient(client)
	controllerHash := client.IdentityEntity().ContentHash

	founders, err := makeNAuxSigners(3)
	if err != nil {
		return FailCheck("create founders: " + err.Error())
	}
	for i, f := range founders {
		p := fmt.Sprintf("validate/encryption/tier-c/founder-%d-identity", i)
		if _, err := client.TreePut(ctx, p, f.identity); err != nil {
			return FailCheck(fmt.Sprintf("stage founder %d identity: %v", i, err))
		}
	}
	statusQ, qResult, err := idClient.CreateQuorum(ctx,
		[]hash.Hash{founders[0].identity.ContentHash, founders[1].identity.ContentHash,
			founders[2].identity.ContentHash}, 2, "encryption-tier-c-founders")
	if err != nil || statusQ != 200 {
		return FailCheck(fmt.Sprintf("create_quorum: status=%d err=%v", statusQ, err))
	}
	if _, err := mintAndSignControllerCert(ctx, client, idClient, qResult.QuorumID,
		controllerHash, []multiSigSigner{founders[0], founders[1]}); err != nil {
		return FailCheck("controller cert: " + err.Error())
	}
	statusC, cfgResult, err := idClient.Configure(ctx, types.IdentityConfigureRequestData{
		TrustsQuorum: qResult.QuorumID,
		ControllerGrants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"*"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
	})
	if err != nil || statusC != 200 {
		return FailCheck(fmt.Sprintf("configure: status=%d err=%v", statusC, err))
	}
	if cfgResult.PeerConfigPath == "" {
		return FailCheck("configure returned an empty peer_config_path — the peer does not claim Tier C")
	}

	props, err := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: encFunctionEncryption,
		Mode:     types.ModePublic,
	})
	if err != nil {
		return FailCheck("encode identity-cert properties: " + err.Error())
	}

	// Publish — the inner pubkey at §4.2.a, the cert through identity.
	_, pkEnt, err := mintEncPubkey(10)
	if err != nil {
		return FailCheck(err.Error())
	}
	if err := publishSigned(ctx, client, encPubkeyPath(pkEnt.ContentHash), pkEnt); err != nil {
		return FailCheck(err.Error())
	}
	statusCert, certResult, err := idClient.CreateAttestation(ctx, types.AttestationData{
		Attesting:  controllerHash,
		Attested:   pkEnt.ContentHash,
		Properties: props,
	})
	if err != nil || statusCert != 200 {
		return FailCheck(fmt.Sprintf("create encryption cert: status=%d err=%v", statusCert, err))
	}
	if certResult.AttestationHash.IsZero() {
		return FailCheck("create_attestation returned a zero attestation_hash for the encryption cert")
	}

	// It MUST be readable at identity's canonical public-cert path, and
	// MUST NOT be readable at the retracted `public/encryption/` segment.
	// Both directions are asserted so the ruling is re-tested every run
	// rather than assumed — and so a regression that reintroduced the
	// invented segment would fail here rather than silently resolving.
	certPath := encTierCCertPath(certResult.AttestationHash)
	if _, _, err := client.TreeGet(ctx, certPath); err != nil {
		return FailCheck("encryption cert not readable at identity's canonical public-cert path " +
			certPath + ": " + err.Error())
	}
	if _, _, err := client.TreeGet(ctx,
		"system/identity/public/encryption/"+hex.EncodeToString(certResult.AttestationHash.Bytes()),
	); err == nil {
		return FailCheck("cert ALSO resolved at the RETRACTED system/identity/public/encryption/ segment — " +
			"arch a19234e ruled ENCRYPTION defines no path inside system/identity/; something has reintroduced it")
	}

	// Rotate — a fresh pubkey under a successor cert.
	_, newPkEnt, err := mintEncPubkey(20)
	if err != nil {
		return FailCheck(err.Error())
	}
	if err := publishSigned(ctx, client, encPubkeyPath(newPkEnt.ContentHash), newPkEnt); err != nil {
		return FailCheck(err.Error())
	}
	statusNew, newCertResult, err := idClient.CreateAttestation(ctx, types.AttestationData{
		Attesting:  controllerHash,
		Attested:   newPkEnt.ContentHash,
		Properties: props,
	})
	if err != nil || statusNew != 200 {
		return FailCheck(fmt.Sprintf("create successor encryption cert: status=%d err=%v", statusNew, err))
	}

	// Revoke the original cert under controller authority.
	statusRev, _, err := idClient.RevokeAttestation(ctx, certResult.AttestationHash, "rotated")
	if err != nil || statusRev != 200 {
		return FailCheck(fmt.Sprintf("revoke encryption cert: status=%d err=%v", statusRev, err))
	}

	if out := assertTierCLadder(pkEnt.ContentHash, certResult.AttestationHash,
		newPkEnt.ContentHash, newCertResult.AttestationHash); out.Severity() != Pass {
		return out
	}
	return PassCheck("Tier-C brought up end-to-end (quorum → controller cert → configure), encryption identity-cert created via identity:create_attestation, rotated, and revoked under controller authority; §4.4 prefers the cert chain over a newer lower-tier key (multi-device NOT covered — needs a second peer)")
}

// runEncTierCResolution is the half of Tier C that does not depend on the
// peer having IDENTITY configured: the §4.4 ordering rule itself.
//
// Split out deliberately. When a peer does not claim Tier C the
// publication vector skips, and if the ladder assertions lived only
// inside it, a resolver regression that made a lower tier outrank the
// cert chain would go unnoticed on every peer in the cohort — the skip
// would be reported as "not applicable" while silently covering a real
// gap. The ordering rule is implementation behavior, not deployment
// configuration, so it is gated unconditionally.
//
// It runs the PINNED ENC-RESOLVE-ORDER rows rather than assertions written
// here, for two reasons. The rows are the artifact rust and python consume, so
// gating on anything else lets the file we hand them drift from the thing we
// actually check. And this check contacts no peer: it is declared with
// DeclareSelf and reports as [self], because a PASS here in a run against rust
// measured core-go's resolver, not rust's. §4.4 is tagged as a cross-peer seam
// but has no wire surface — resolution happens sender-side before anything is
// sent — so the crossing can only happen through the vector file, in each
// implementation's own suite. This check is our half of it.
func runEncTierCResolution() CheckOutcome {
	rows := encvectors.Rows()
	rep := encvectors.VerifyRows(rows, encryption.ResolveRecipientKey)
	if rep.Fail > 0 {
		return FailCheck(fmt.Sprintf("ENC-RESOLVE-ORDER: %d/%d pinned rows failed:%s",
			rep.Fail, len(rows), strings.Join(rep.Lines, "")))
	}
	return PassCheck(fmt.Sprintf(
		"§4.4 resolution order: %d/%d pinned ENC-RESOLVE-ORDER rows (tier ladder, created-descending, "+
			"content_hash-ascending tie-break, revoked fallthrough, both step-4 errors), each also "+
			"re-checked with candidates enumerated in reverse. SELF-CHECK — exercises this validator's "+
			"resolver, not the peer's; the cross-impl crossing is the vector file, not this row",
		rep.Pass, len(rows)))
}

// assertTierCLadder is the shared §4.4 assertion: with a revoked
// original, a rotated successor at Tier C, and a newer key at Tier A,
// resolution MUST land on the Tier-C successor. Tier order beats
// recency — that is what makes §4.4 a ladder rather than a sort, and a
// resolver that got it backwards would silently bind a key the
// recipient's identity layer has superseded.
func assertTierCLadder(oldPubkey, oldCert, newPubkey, newCert hash.Hash) CheckOutcome {
	staleTierA := hash.Hash{}
	if _, aEnt, err := mintEncPubkey(999); err == nil {
		staleTierA = aEnt.ContentHash
	}
	// The identity-certs are carriers; ordering keys come from the pubkey
	// entities they attest (§4.4, ruled 2026-08-09-b).
	pubs := encryption.RecipientPublications{
		TierC: []encryption.Carrier{
			{Hash: oldCert, Pubkey: oldPubkey, Live: true},
			{Hash: newCert, Pubkey: newPubkey, Live: true},
		},
		TierA: []encryption.Carrier{{Hash: staleTierA, Pubkey: staleTierA, Live: true}},
		Pubkeys: map[hash.Hash]encryption.PubkeyEntity{
			oldPubkey:  {Created: 10},
			newPubkey:  {Created: 20},
			staleTierA: {Created: 999},
		},
		RevokedPubkeys: map[hash.Hash]bool{oldPubkey: true},
	}
	res, err := encryption.ResolveRecipientKey(pubs)
	if err != nil {
		return FailCheck("Tier-C §4.4 resolution: " + err.Error())
	}
	if res.Tier != encryption.TierC {
		return FailCheck(fmt.Sprintf("Tier-C resolution landed at tier %q, want C — a lower tier outranked the cert chain", res.Tier))
	}
	if res.Pubkey != newPubkey {
		return FailCheck(fmt.Sprintf("Tier-C resolution bound %s, want rotated key %s", res.Pubkey, newPubkey))
	}
	if res.Dropped.PubkeyRevoked != 1 {
		return FailCheck(fmt.Sprintf("Tier-C resolution dropped %d key-revoked, want 1", res.Dropped.PubkeyRevoked))
	}
	return PassCheck("ladder ok")
}

// --- ENC-TIER-INTEROP-1 ---

// runEncTierInterop is §16's cross-tier vector, and the thing it really
// guards is F2-3: interop holds only because every tier binds the
// BYTE-IDENTICAL inner pubkey entity. content_hash(pubkey) is a pure
// function of its fields, so a peer that re-mints an "equivalent" key at
// a second tier — same public key, different `created`, or a differently
// ordered suite array — produces a different hash, a different HKDF
// info, a different AEAD key, and interop fails.
//
// So the vector publishes ONE authored pubkey entity at Tier A and at
// Tier C, asserts the resolved recipient_key is byte-equal from both,
// and round-trips peer mode in both directions. Then it re-mints an
// equivalent-but-not-identical pubkey and asserts the hash MOVES —
// without that half, a resolver that ignored `created` entirely would
// pass the first half and still be broken.
func runEncTierInterop(ctx context.Context, client *PeerClient) CheckOutcome {
	if client.Keypair().IsZero() {
		return SkipCheck("client has no signing keypair — start validate-peer with -identity to exercise interop")
	}
	peerEnt := client.IdentityEntity()

	// ONE authored inner pubkey entity, published at two tiers.
	priv, pkEnt, err := mintEncPubkey(42)
	if err != nil {
		return FailCheck(err.Error())
	}
	var pkData types.EncryptionPubkeyData
	if err := ecf.Decode(pkEnt.Data, &pkData); err != nil {
		return FailCheck("decode authored pubkey: " + err.Error())
	}
	if err := publishSigned(ctx, client, encPubkeyPath(pkEnt.ContentHash), pkEnt); err != nil {
		return FailCheck(err.Error())
	}
	props, err := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: encFunctionEncryption,
		Mode:     types.ModePublic,
	})
	if err != nil {
		return FailCheck("encode identity-cert properties: " + err.Error())
	}
	certEnt, err := types.AttestationData{
		Attesting:  peerEnt.ContentHash,
		Attested:   pkEnt.ContentHash, // the SAME entity, not a re-mint
		Properties: props,
	}.ToEntity()
	if err != nil {
		return FailCheck("build identity-cert: " + err.Error())
	}
	if err := publishSigned(ctx, client, encTierCCertPath(certEnt.ContentHash), certEnt); err != nil {
		return FailCheck(err.Error())
	}

	// A Tier-A-only sender sees just the pubkey subtree; a Tier-C-aware
	// sender sees the cert. Both MUST bind the same recipient_key.
	// One authored pubkey entity, two carriers — at Tier A the carrier IS
	// the pubkey, at Tier C it is the cert attesting it. Projection is what
	// makes both bind the same recipient_key.
	oneKey := map[hash.Hash]encryption.PubkeyEntity{pkEnt.ContentHash: {Created: 42}}
	tierAView := encryption.RecipientPublications{
		TierA:   []encryption.Carrier{{Hash: pkEnt.ContentHash, Pubkey: pkEnt.ContentHash, Live: true}},
		Pubkeys: oneKey,
	}
	tierCView := encryption.RecipientPublications{
		TierC:   []encryption.Carrier{{Hash: certEnt.ContentHash, Pubkey: pkEnt.ContentHash, Live: true}},
		Pubkeys: oneKey,
	}
	aRes, err := encryption.ResolveRecipientKey(tierAView)
	if err != nil {
		return FailCheck("Tier-A sender resolution: " + err.Error())
	}
	cRes, err := encryption.ResolveRecipientKey(tierCView)
	if err != nil {
		return FailCheck("Tier-C sender resolution: " + err.Error())
	}
	if aRes.Pubkey != cRes.Pubkey {
		return FailCheck(fmt.Sprintf(
			"ENC-TIER-INTEROP-1: recipient_key differs by tier — Tier-A sender binds %s, Tier-C sender binds %s (F-GO-1)",
			aRes.Pubkey, cRes.Pubkey))
	}
	if aRes.Tier != encryption.TierA || cRes.Tier != encryption.TierC {
		return FailCheck(fmt.Sprintf("interop views resolved at unexpected tiers: %q / %q", aRes.Tier, cRes.Tier))
	}

	// Round-trip both directions over the shared binding. "Both
	// directions" here is sender-tier, which is what §4.0 says varies —
	// the recipient is the peer holding the private key either way.
	for _, dir := range []struct {
		name string
		key  hash.Hash
	}{
		{"Tier-A sender → Tier-C recipient", aRes.Pubkey},
		{"Tier-C sender → Tier-A recipient", cRes.Pubkey},
	} {
		plaintext := []byte("ENC-TIER-INTEROP-1 " + dir.name)
		wrapper, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
			RecipientPubkey:     pkData.PublicKey,
			RecipientPubkeyHash: dir.key,
			Plaintext:           plaintext,
		})
		if err != nil {
			return FailCheck(dir.name + ": PeerEncrypt: " + err.Error())
		}
		got, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
			Wrapper: wrapper, RecipientPriv: priv.Bytes(),
		})
		if err != nil {
			return FailCheck(dir.name + ": PeerDecrypt: " + err.Error())
		}
		if string(got) != string(plaintext) {
			return FailCheck(dir.name + ": round-trip plaintext mismatch")
		}
	}

	// F2-3 negative half — re-minting an equivalent key MUST move the
	// hash. If this passes silently, the vector above proved nothing
	// about byte-identity.
	_, reminted, err := mintEncPubkeyFrom(pkData, 43) // same public key, different `created`
	if err != nil {
		return FailCheck(err.Error())
	}
	if reminted.ContentHash == pkEnt.ContentHash {
		return FailCheck("F2-3: a re-minted pubkey with a different `created` produced the SAME content_hash — content_hash is not binding its fields")
	}

	return PassCheck(fmt.Sprintf(
		"ENC-TIER-INTEROP-1: one authored pubkey published at Tier A + Tier C binds byte-equal recipient_key %s from both sender tiers; peer mode round-trips both directions; F2-3 re-mint moves the hash",
		aRes.Pubkey))
}

// mintEncPubkeyFrom re-mints a pubkey entity carrying the same public key
// as `base` but a different `created` — the F2-3 "equivalent but not
// identical" case.
func mintEncPubkeyFrom(base types.EncryptionPubkeyData, created uint64) (types.EncryptionPubkeyData, entity.Entity, error) {
	next := base
	next.Created = created
	ent, err := encEntityFromData(types.TypeEncryptionPubkey, next)
	if err != nil {
		return next, entity.Entity{}, fmt.Errorf("re-mint pubkey: %w", err)
	}
	return next, ent, nil
}

// --- multi-device Tier C ---

// runEncMultiDeviceTierC is Tier C's *distinguishing* feature: several
// agents under one logical identity, each publishing its own encryption
// key, with the sender picking ONE and the receiving agent being whoever
// holds that key's private half (§4.4 multi-device).
//
// The lifecycle vector covers the degenerate single-agent case and says
// so in its own PASS message. This is the case the three 2026-08-09
// rulings were actually about, and the only configuration where a
// divergent §4.4 order does something worse than pick a different key:
// it routes ciphertext to a different DEVICE, with every peer behaving
// correctly and nothing erroring anywhere.
//
// So the assertion is not "decryption succeeded" — that would pass with
// either device chosen, which is exactly the non-measurement this vector
// exists to avoid. It is:
//
//  1. the resolver picks the key the §4.4 order names, computed here by
//     direct byte comparison rather than by asking the resolver (a check
//     that re-derives its expectation from the code under test proves
//     only that the code agrees with itself), and
//  2. THAT key's private half opens the ciphertext, and
//  3. the OTHER device's private half does NOT.
//
// The two keys are authored with an IDENTICAL `created` so the tie-break
// is load-bearing: with recency unable to separate them, the content_hash
// ordering is the only thing deciding which device receives. That is the
// ruling under test, in the configuration where getting it wrong is
// silent.
//
// It does NOT need a second running peer. A device here is a private-key
// holder (§4.4: "a device is a private-key holder, not a cert"), and the
// validator holds both halves — which is what makes this buildable today
// rather than blocked on multi-peer harness work, as a previous handoff
// wrongly recorded.
func runEncMultiDeviceTierC(ctx context.Context, client *PeerClient) CheckOutcome {
	idClient := identitysdk.NewClient(client)
	controllerHash := client.IdentityEntity().ContentHash

	props, err := types.EncodeProperties(types.IdentityCertProperties{
		Kind:     types.KindIdentityCert,
		Function: encFunctionEncryption,
		Mode:     types.ModePublic,
	})
	if err != nil {
		return FailCheck("encode identity-cert properties: " + err.Error())
	}

	// Two agents, two independent X25519 keys, ONE authored `created`.
	const sharedCreated = 500
	privA, entA, err := mintEncPubkey(sharedCreated)
	if err != nil {
		return FailCheck("mint device-A pubkey: " + err.Error())
	}
	privB, entB, err := mintEncPubkey(sharedCreated)
	if err != nil {
		return FailCheck("mint device-B pubkey: " + err.Error())
	}
	if entA.ContentHash == entB.ContentHash {
		return FailCheck("both devices minted the same pubkey entity — the fixture is not multi-device")
	}

	certs := map[hash.Hash]hash.Hash{} // pubkey hash → its cert hash
	for _, dev := range []struct {
		name string
		ent  entity.Entity
	}{{"A", entA}, {"B", entB}} {
		if err := publishSigned(ctx, client, encPubkeyPath(dev.ent.ContentHash), dev.ent); err != nil {
			return FailCheck("publish device-" + dev.name + " pubkey: " + err.Error())
		}
		status, res, err := idClient.CreateAttestation(ctx, types.AttestationData{
			Attesting:  controllerHash,
			Attested:   dev.ent.ContentHash,
			Properties: props,
		})
		if err != nil || status != 200 {
			return FailCheck(fmt.Sprintf("create device-%s encryption cert: status=%d err=%v",
				dev.name, status, err))
		}
		if res.AttestationHash.IsZero() {
			return FailCheck("device-" + dev.name + " cert has a zero attestation_hash")
		}
		certPath := encTierCCertPath(res.AttestationHash)
		if _, _, err := client.TreeGet(ctx, certPath); err != nil {
			return FailCheck("device-" + dev.name + " cert not readable at " + certPath + ": " + err.Error())
		}
		certs[dev.ent.ContentHash] = res.AttestationHash
	}

	// The expectation, derived WITHOUT the resolver: §4.4 ties on `created`
	// and breaks by the full multihash-prefixed content_hash ascending.
	wantPubkey, wantPriv, otherPriv := entA.ContentHash, privA, privB
	if bytes.Compare(entB.ContentHash.Bytes(), entA.ContentHash.Bytes()) < 0 {
		wantPubkey, wantPriv, otherPriv = entB.ContentHash, privB, privA
	}

	pubs := encryption.RecipientPublications{
		TierC: []encryption.Carrier{
			{Hash: certs[entA.ContentHash], Pubkey: entA.ContentHash, Live: true},
			{Hash: certs[entB.ContentHash], Pubkey: entB.ContentHash, Live: true},
		},
		Pubkeys: map[hash.Hash]encryption.PubkeyEntity{
			entA.ContentHash: {Created: sharedCreated},
			entB.ContentHash: {Created: sharedCreated},
		},
	}
	res, err := encryption.ResolveRecipientKey(pubs)
	if err != nil {
		return FailCheck("multi-device §4.4 resolution: " + err.Error())
	}
	if res.Tier != encryption.TierC {
		return FailCheck(fmt.Sprintf("multi-device resolution landed at tier %q, want C", res.Tier))
	}
	if res.Pubkey != wantPubkey {
		return FailCheck(fmt.Sprintf(
			"multi-device resolution bound %s, want %s — the two devices tie on `created`, so the "+
				"content_hash-ascending tie-break decides WHICH DEVICE receives; binding the other one "+
				"delivers ciphertext to an agent the reader is not watching, with nothing erroring",
			res.Pubkey, wantPubkey))
	}

	// Now the part that makes the selection mean something on the wire.
	recipientPub := wantPriv.PublicKey().Bytes()
	if bytes.Equal(recipientPub, otherPriv.PublicKey().Bytes()) {
		return FailCheck("the two devices share a public key — the fixture cannot distinguish them")
	}
	plaintext := []byte("multi-device tier-c routing probe")
	wrapper, err := encryption.PeerEncrypt(encryption.PeerEncryptInput{
		RecipientPubkey:     recipientPub,
		RecipientPubkeyHash: res.Pubkey,
		Plaintext:           plaintext,
	})
	if err != nil {
		return FailCheck("peer-encrypt to the resolved device: " + err.Error())
	}

	got, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
		Wrapper: wrapper, RecipientPriv: wantPriv.Bytes(),
	})
	if err != nil {
		return FailCheck("the resolved device could not decrypt its own ciphertext: " + err.Error())
	}
	if !bytes.Equal(got, plaintext) {
		return FailCheck("resolved device decrypted to different bytes than were encrypted")
	}

	// The negative half. Without it the check passes whichever device was
	// chosen, and "multi-device works" would mean only "some key round-trips."
	if _, err := encryption.PeerDecrypt(encryption.PeerDecryptInput{
		Wrapper: wrapper, RecipientPriv: otherPriv.Bytes(),
	}); err == nil {
		return FailCheck("the OTHER device's private key also decrypted the wrapper — " +
			"§4.4's multi-device rule makes the receiving agent the holder of the CHOSEN key's " +
			"private half; if both open it, device selection is not doing anything")
	}

	return PassCheck(fmt.Sprintf(
		"multi-device Tier C: two agents under one controller, both certs live at identity's canonical "+
			"path, keys tied on `created` so the §4.4 tie-break selects the device — resolver bound %s "+
			"(the lexicographically smaller content_hash), that device's private half decrypts, and the "+
			"other device's does NOT", res.Pubkey))
}
