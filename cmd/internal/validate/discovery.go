// Category: discovery. Probes the EXTENSION-DISCOVERY v1.0 surface — the
// substrate (`:scan` / `:announce` / `:announce-stop`), the candidate /
// decision / identity-claim / scan-result entity types, the §3.0
// watchable-prefix convention, the §3.1 truncation surface, and the §3.2
// mDNS wire pin.
//
// Ten vectors:
//
//	v1  candidate_round_trip          — system/discovery/candidate ECF
//	                                    round-trip + Base58 peer_id nullable
//	v2  decision_no_silent_admit      — :ignore decision encodes with
//	                                    grant: null (§2.1, §8.4)
//	v3  identity_claim_round_trip     — system/discovery/identity-claim ECF
//	                                    round-trip + non-zero content_hash
//	v4  scan_result_flat_shape        — ScanResult is a flat entity,
//	                                    NOT wrapped under system/protocol/status
//	                                    (Ruling-3 generalizes — cohort
//	                                    discipline #3)
//	v5  scan_invocation_handler_live  — :scan against `mdns` returns 200 +
//	                                    a valid ScanResult shape (candidate
//	                                    list may be empty on a quiet
//	                                    network — that is the conformant
//	                                    quiet-network behavior)
//	v6  scan_unknown_backend            — :scan against an unregistered
//	                                    backend MUST return 400 with code
//	                                    `unknown_backend` per §3.3 (arch
//	                                    Ruling-5 erratum:
//	                                    V7 §3.3 maps unknown enum value
//	                                    to 400; `backend` is a parameter
//	                                    value, not a resource path).
//	v7  announce_stop_idempotent      — :announce-stop on a never-
//	                                    announced profile returns 200
//	                                    (§3, §8.1 symmetric lifecycle)
//	v8  watchable_prefix_storage_path — CandidateStoragePath helper round
//	                                    trips and §3.0 prefix matches
//	v9  successor_pattern_supersedes  — §2.2 supersedes-chain encoding:
//	                                    successor candidate carries
//	                                    PeerID + Supersedes hash; original
//	                                    candidate left immutable (§8.4
//	                                    MUST NOT mutate to populate
//	                                    peer_id post-IDENTIFY)
//	v10 dnssd_wire_pin                — §3.2 PIN: ServiceType +
//	                                    {version, peer_id_hint, profile_ref}
//	                                    TXT keys MUST be exact strings
//	                                    (the cohort's silent-divergence anchor)
//
// Vectors v1-v4, v8-v10 are pure-Go probes (types + helpers); v5-v7
// require a live discovery handler reachable over the wire (Go peer with
// system/discovery registered).

package validate

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/discovery/mdns"
)

const catDiscovery = "discovery"

func runDiscovery(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catDiscovery)

	r.Declare("v1_candidate_round_trip", "DISCOVERY §2.1 — system/discovery/candidate ECF round-trip; Base58 peer_id nullable (Ruling-1)")
	r.Declare("v2_decision_no_silent_admit", "DISCOVERY §2.1, §8.4 — :ignore decision encodes with grant: null (no silent admit)")
	r.Declare("v3_identity_claim_round_trip", "DISCOVERY §2.2.1 — system/discovery/identity-claim ECF round-trip; non-zero content_hash for fail-closed compare")
	r.Declare("v4_scan_result_flat_shape", "DISCOVERY §3, cohort discipline #3 — ScanResult is a flat entity, NOT system/protocol/status-wrapped")
	r.Declare("v5_scan_invocation_handler_live", "DISCOVERY §3 — :scan against mdns returns 200 + ScanResult shape (snapshot list may be empty on quiet net)")
	r.Declare("v6_scan_unknown_backend", "DISCOVERY §3.3 (Ruling-5 erratum) — :scan against unregistered backend MUST return 400 + code `unknown_backend` (V7 §3.3 unknown enum class)")
	r.Declare("v7_announce_stop_idempotent", "DISCOVERY §3, §8.1 — :announce-stop on never-announced profile returns 200 (idempotent symmetric lifecycle)")
	r.Declare("v8_watchable_prefix_storage_path", "DISCOVERY §3.0 — CandidateStoragePath helper round-trips, watchable prefix matches `system/discovery/candidate/{backend}/`")
	r.Declare("v9_successor_pattern_supersedes", "DISCOVERY §2.2 — successor candidate carries PeerID + Supersedes hash; original left immutable")
	r.Declare("v10_dnssd_wire_pin", "DISCOVERY §3.2 PIN — ServiceType + {version, peer_id_hint, profile_ref} TXT keys MUST be exact strings (cohort's silent-divergence anchor)")

	r.Run("v1_candidate_round_trip", runDiscCandidateRoundTrip)
	r.Run("v2_decision_no_silent_admit", runDiscDecisionNoSilentAdmit)
	r.Run("v3_identity_claim_round_trip", runDiscIdentityClaimRoundTrip)
	r.Run("v4_scan_result_flat_shape", runDiscScanResultFlatShape)
	r.Run("v5_scan_invocation_handler_live", func() CheckOutcome { return runDiscScanInvocationLive(ctx, client) })
	r.Run("v6_scan_unknown_backend", func() CheckOutcome { return runDiscScanUnknownBackend(ctx, client) })
	r.Run("v7_announce_stop_idempotent", func() CheckOutcome { return runDiscAnnounceStopIdempotent(ctx, client) })
	r.Run("v8_watchable_prefix_storage_path", runDiscWatchablePrefixStoragePath)
	r.Run("v9_successor_pattern_supersedes", runDiscSuccessorPatternSupersedes)
	r.Run("v10_dnssd_wire_pin", runDiscDNSSDWirePin)

	return r.Results()
}

// discExecute runs a `:op` against system/discovery on the target peer.
func discExecute(ctx context.Context, client *PeerClient, op string, params entity.Entity) (uint, entity.Entity, error) {
	uri := fmt.Sprintf("entity://%s/system/discovery", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, op, params, nil)
	if err != nil {
		return 0, entity.Entity{}, err
	}
	resp, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, entity.Entity{}, fmt.Errorf("decode execute-response: %w", err)
	}
	if len(resp.Result) == 0 {
		return resp.Status, entity.Entity{}, nil
	}
	var result entity.Entity
	if err := ecf.Decode(resp.Result, &result); err != nil {
		return resp.Status, entity.Entity{}, fmt.Errorf("decode result entity: %w", err)
	}
	return resp.Status, result, nil
}

// --- Vectors ----------------------------------------------------------------

const discFakePeerID = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func discFakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

func runDiscCandidateRoundTrip() CheckOutcome {
	hint := discFakeHash(0x10)
	supersedes := discFakeHash(0x20)
	d := types.CandidateData{
		PeerID:       discFakePeerID,
		Backend:      types.DiscoveryBackendMDNS,
		ObservedAt:   1_730_000_000_000,
		IdentityHint: &hint,
		Supersedes:   &supersedes,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.Type != types.TypeDiscoveryCandidate {
		return FailCheck(fmt.Sprintf("type drift: got %q", e.Type))
	}
	if err := e.Validate(); err != nil {
		return FailCheck("hash validate: " + err.Error())
	}
	dec, err := types.CandidateDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if dec.PeerID != discFakePeerID || dec.Backend != types.DiscoveryBackendMDNS ||
		dec.ObservedAt != 1_730_000_000_000 {
		return FailCheck("decoded fields drifted")
	}
	if dec.IdentityHint == nil || *dec.IdentityHint != hint {
		return FailCheck("IdentityHint drift")
	}
	if dec.Supersedes == nil || *dec.Supersedes != supersedes {
		return FailCheck("Supersedes drift")
	}

	// Pre-IDENTIFY shape: TOFU + no supersedes + null peer_id (the §2.2
	// gate). Omitempty MUST drop all three fields.
	tofu := types.CandidateData{Backend: types.DiscoveryBackendMDNS, ObservedAt: 1}
	tofuEnt, _ := tofu.ToEntity()
	tofuDec, _ := types.CandidateDataFromEntity(tofuEnt)
	if tofuDec.PeerID != "" || tofuDec.IdentityHint != nil || tofuDec.Supersedes != nil {
		return FailCheck("omitempty did not drop TOFU/pre-IDENTIFY fields")
	}
	return PassCheck(fmt.Sprintf("candidate hash=%s; TOFU shape clean", e.ContentHash))
}

func runDiscDecisionNoSilentAdmit() CheckOutcome {
	// §2.1: ignore + track encode grant: null. §8.4 MUST NOT silently admit;
	// the wire shape itself is the gate (no grant field present = no
	// authority issued).
	d := types.DecisionData{
		Candidate: discFakeHash(0x33),
		Outcome:   types.DiscoveryOutcomeIgnore,
		DecidedAt: 1_730_000_000_000,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	dec, err := types.DecisionDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if dec.Grant != nil {
		return FailCheck("§8.4: :ignore decision MUST NOT carry a grant hash")
	}
	if dec.Outcome != types.DiscoveryOutcomeIgnore {
		return FailCheck("Outcome drift: " + dec.Outcome)
	}

	// Grant-limited carries a grant hash — refless target-matching (V7
	// §975), NOT a refs: block (the §8.4 MUST NOT we pin elsewhere).
	grant := discFakeHash(0x44)
	limited := types.DecisionData{
		Candidate: discFakeHash(0x33),
		Outcome:   types.DiscoveryOutcomeGrantLimited,
		Grant:     &grant,
		DecidedAt: 1_730_000_000_100,
	}
	limitedEnt, _ := limited.ToEntity()
	limitedDec, _ := types.DecisionDataFromEntity(limitedEnt)
	if limitedDec.Grant == nil || *limitedDec.Grant != grant {
		return FailCheck("grant-limited Grant drift")
	}
	return PassCheck("decision wire shape gates no-silent-admit (grant:null on ignore, bare hash on grant-limited)")
}

func runDiscIdentityClaimRoundTrip() CheckOutcome {
	digest := []byte{0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	d := types.IdentityClaimData{
		PeerID:          discFakePeerID,
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: digest,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.ContentHash.IsZero() {
		return FailCheck("identity-claim content_hash zero — fail-closed compare would not work")
	}
	dec, err := types.IdentityClaimDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if dec.PeerID != discFakePeerID || dec.KeyType != 1 || dec.HashType != 0 {
		return FailCheck("scalar field drift")
	}
	if string(dec.PublicKeyDigest) != string(digest) {
		return FailCheck("public_key_digest drift")
	}

	// Distinct PublicKeyDigest → distinct content_hash (the gate the §2.2.1
	// fail-closed compare rides on).
	d2 := d
	d2.PublicKeyDigest = append([]byte(nil), digest...)
	d2.PublicKeyDigest[0] ^= 0xFF
	e2, _ := d2.ToEntity()
	if e.ContentHash == e2.ContentHash {
		return FailCheck("§2.2.1: identity-claim hash collision across distinct PublicKeyDigest")
	}
	return PassCheck(fmt.Sprintf("identity-claim hash=%s; fail-closed compare gate live", e.ContentHash))
}

func runDiscScanResultFlatShape() CheckOutcome {
	overflow := types.DiscoveryErrScanOverflow
	d := types.ScanResultData{
		Candidates: []hash.Hash{discFakeHash(0x55), discFakeHash(0x66)},
		Truncated:  true,
		Code:       &overflow,
	}
	e, err := d.ToEntity()
	if err != nil {
		return FailCheck("ToEntity: " + err.Error())
	}
	if e.Type != types.TypeDiscoveryScanResult {
		return FailCheck(fmt.Sprintf("§3 PIN: ScanResult type drift to %q (expected %q — cohort would diverge on slug)",
			e.Type, types.TypeDiscoveryScanResult))
	}
	dec, err := types.ScanResultDataFromEntity(e)
	if err != nil {
		return FailCheck("FromEntity: " + err.Error())
	}
	if !dec.Truncated {
		return FailCheck("Truncated drift")
	}
	if dec.Code == nil || *dec.Code != types.DiscoveryErrScanOverflow {
		return FailCheck(fmt.Sprintf("§3.1 PIN: code must be %q, got %+v",
			types.DiscoveryErrScanOverflow, dec.Code))
	}
	if len(dec.Candidates) != 2 {
		return FailCheck("Candidates drift")
	}
	return PassCheck("ScanResult is flat entity (no system/protocol/status wrap); truncated+code surface non-silent")
}

func runDiscScanInvocationLive(ctx context.Context, client *PeerClient) CheckOutcome {
	req := types.ScanRequestData{Backend: types.DiscoveryBackendMDNS}
	ent, err := req.ToEntity()
	if err != nil {
		return FailCheck("encode scan-request: " + err.Error())
	}
	status, result, err := discExecute(ctx, client, "scan", ent)
	if err != nil {
		return FailCheck("scan dispatch: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf(":scan(mdns) status=%d, want 200", status))
	}
	scan, err := types.ScanResultDataFromEntity(result)
	if err != nil {
		return FailCheck("decode scan-result: " + err.Error())
	}
	// Truncated → must surface code. Non-truncated → code SHOULD be nil
	// (`:scan` only surfaces overflow code in the truncation case per §3.1).
	if scan.Truncated && scan.Code == nil {
		return FailCheck("§3.1 + §8.4: truncated:true MUST surface code (non-silent truncation)")
	}
	if !scan.Truncated && scan.Code != nil && *scan.Code != "" {
		return FailCheck(fmt.Sprintf("§3.1: non-truncated scan surfaced unexpected code %q", *scan.Code))
	}
	return PassCheck(fmt.Sprintf("scan returned %d candidates (truncated=%v); quiet-network behavior conformant",
		len(scan.Candidates), scan.Truncated))
}

func runDiscScanUnknownBackend(ctx context.Context, client *PeerClient) CheckOutcome {
	// §3.3 — Ruling-5 erratum: MUST return 400 + code
	// `unknown_backend`. V7 §3.3 maps unknown enum value to 400; `backend`
	// is a parameter value, not a resource path. Cohort previously split
	// (Go=404, Rust+Py=400); arch pinned 400 with the `unknown_backend`
	// code string to match other forward-compat patterns
	// (`unknown_binding_kind`, `unknown_backend_kind`).
	req := types.ScanRequestData{Backend: "this-backend-does-not-exist"}
	ent, _ := req.ToEntity()
	status, errEnt, err := discExecute(ctx, client, "scan", ent)
	if err != nil {
		return FailCheck("scan dispatch: " + err.Error())
	}
	if status != 400 {
		return FailCheck(fmt.Sprintf("§3.3 Ruling-5: status MUST be 400 (was %d) — V7 §3.3 unknown-enum class", status))
	}
	// Decode error body and verify code string.
	if errEnt.Type != types.TypeError {
		return FailCheck(fmt.Sprintf("expected %s result, got %q", types.TypeError, errEnt.Type))
	}
	ed, derr := types.ErrorDataFromEntity(errEnt)
	if derr != nil {
		return FailCheck("decode error: " + derr.Error())
	}
	if ed.Code != "unknown_backend" {
		return FailCheck(fmt.Sprintf("§3.3 Ruling-5: code MUST be \"unknown_backend\" (was %q)", ed.Code))
	}
	return PassCheck("scan on unregistered backend → 400 unknown_backend (V7 §3.3 class)")
}

func runDiscAnnounceStopIdempotent(ctx context.Context, client *PeerClient) CheckOutcome {
	req := types.AnnounceStopRequestData{
		Backend:    types.DiscoveryBackendMDNS,
		ProfileRef: "validate-peer-never-announced-profile",
	}
	ent, _ := req.ToEntity()
	status, _, err := discExecute(ctx, client, "announce-stop", ent)
	if err != nil {
		return FailCheck("announce-stop dispatch: " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("§3, §8.1: announce-stop MUST be idempotent (200 on never-announced), got %d", status))
	}
	return PassCheck("announce-stop is idempotent on never-announced profile (200)")
}

func runDiscWatchablePrefixStoragePath() CheckOutcome {
	h := discFakeHash(0xAB)
	got := types.CandidateStoragePath(types.DiscoveryBackendMDNS, h)
	want := "system/discovery/candidate/mdns/" + types.PeerIdentityHashHex(h)
	if got != want {
		return FailCheck(fmt.Sprintf("CandidateStoragePath: want %q got %q", want, got))
	}
	prefix := types.CandidatePrefix(types.DiscoveryBackendMDNS)
	if !strings.HasPrefix(got, prefix) {
		return FailCheck(fmt.Sprintf("storage path %q not under prefix %q (§3.0 watchable surface broken)", got, prefix))
	}
	return PassCheck("watchable prefix + storage path canonical (§3.0)")
}

func runDiscSuccessorPatternSupersedes() CheckOutcome {
	// §2.2: successor candidate is a *new* entity with PeerID populated +
	// Supersedes pointing at the original. The original entity remains
	// immutable in the store (§8.4 MUST NOT mutate).
	original := types.CandidateData{Backend: types.DiscoveryBackendMDNS, ObservedAt: 1_730_000_000_000}
	originalEnt, err := original.ToEntity()
	if err != nil {
		return FailCheck("encode original: " + err.Error())
	}
	successor := types.CandidateData{
		PeerID:       discFakePeerID,
		Backend:      original.Backend,
		ObservedAt:   1_730_000_000_001,
		EndpointHint: original.EndpointHint,
		Supersedes:   &originalEnt.ContentHash,
	}
	successorEnt, err := successor.ToEntity()
	if err != nil {
		return FailCheck("encode successor: " + err.Error())
	}
	if successorEnt.ContentHash == originalEnt.ContentHash {
		return FailCheck("§2.2 GATE: successor MUST be a distinct entity (distinct content_hash) from original")
	}
	dec, _ := types.CandidateDataFromEntity(successorEnt)
	if dec.PeerID != discFakePeerID {
		return FailCheck("successor PeerID drift")
	}
	if dec.Supersedes == nil || *dec.Supersedes != originalEnt.ContentHash {
		return FailCheck("successor Supersedes MUST reference original.content_hash")
	}
	// Re-encode original — same fields, MUST produce same content_hash
	// (immutability).
	originalEnt2, _ := original.ToEntity()
	if originalEnt2.ContentHash != originalEnt.ContentHash {
		return FailCheck("§8.4: original candidate must be immutable; re-encode produced different hash")
	}
	return PassCheck("successor-candidate pattern: distinct hash, PeerID populated, Supersedes refs original; original immutable")
}

func runDiscDNSSDWirePin() CheckOutcome {
	// §3.2 PIN: the load-bearing cross-impl-convergence anchor. Failure here
	// means Rust + Py would silently fail to discover each other on the LAN
	// (no error to catch — the spec flagged this as the WORST splinter mode).
	if mdns.ServiceType != "_entity-core._udp.local." {
		return FailCheck(fmt.Sprintf("§3.2 PIN: ServiceType drifted to %q — silent cross-impl LAN-discovery failure", mdns.ServiceType))
	}
	if mdns.TXTKeyVersion != "version" {
		return FailCheck(fmt.Sprintf("§3.2 PIN: TXTKeyVersion drifted to %q", mdns.TXTKeyVersion))
	}
	if mdns.TXTKeyPeerIDHint != "peer_id_hint" {
		return FailCheck(fmt.Sprintf("§3.2 PIN: TXTKeyPeerIDHint drifted to %q", mdns.TXTKeyPeerIDHint))
	}
	if mdns.TXTKeyProfileRef != "profile_ref" {
		return FailCheck(fmt.Sprintf("§3.2 PIN: TXTKeyProfileRef drifted to %q", mdns.TXTKeyProfileRef))
	}
	if mdns.CurrentVersion != "1" {
		return FailCheck(fmt.Sprintf("§3.2 PIN: CurrentVersion drifted to %q (only bump on a breaking wire change)", mdns.CurrentVersion))
	}
	if mdns.BackendKind != types.DiscoveryBackendMDNS {
		return FailCheck(fmt.Sprintf("BackendKind %q != types.DiscoveryBackendMDNS %q", mdns.BackendKind, types.DiscoveryBackendMDNS))
	}
	return PassCheck(fmt.Sprintf("§3.2 PIN intact: %s + {%s, %s, %s} TXT keys; CurrentVersion=%s",
		mdns.ServiceType, mdns.TXTKeyVersion, mdns.TXTKeyPeerIDHint, mdns.TXTKeyProfileRef, mdns.CurrentVersion))
}
