package types

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func dxFakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

// dxFakePeerID — deterministic Base58-shaped string for fixture use. Same
// convention as published_root_test.go (no cryptographic derivation; the
// cross-impl cohort byte-equal fixture lives in cmd/internal/validate).
const dxFakePeerID = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// -----------------------------------------------------------------------
// system/discovery/candidate
// -----------------------------------------------------------------------

func TestCandidateRoundtrip(t *testing.T) {
	// Post-IDENTIFY successor: peer_id populated, supersedes pointing at the
	// prior observation. identity_hint present (non-TOFU). endpoint_hint
	// carries opaque CBOR (modeled as primitive/any per spec).
	endpointHint, err := ecf.Encode(map[string]any{
		"addr": "192.0.2.7",
		"port": uint64(9002),
	})
	if err != nil {
		t.Fatalf("encode endpoint_hint: %v", err)
	}
	identityHint := dxFakeHash(0x11)
	supersedes := dxFakeHash(0x22)
	d := CandidateData{
		PeerID:       dxFakePeerID,
		Backend:      DiscoveryBackendMDNS,
		ObservedAt:   1_730_000_000_000,
		EndpointHint: cbor.RawMessage(endpointHint),
		IdentityHint: &identityHint,
		Supersedes:   &supersedes,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeDiscoveryCandidate {
		t.Fatalf("type: want %s got %s", TypeDiscoveryCandidate, e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	dec, err := CandidateDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.PeerID != dxFakePeerID {
		t.Fatalf("PeerID drift: %q", dec.PeerID)
	}
	if dec.Backend != DiscoveryBackendMDNS {
		t.Fatalf("Backend drift: %q", dec.Backend)
	}
	if dec.ObservedAt != 1_730_000_000_000 {
		t.Fatalf("ObservedAt drift: %d", dec.ObservedAt)
	}
	if !bytes.Equal(dec.EndpointHint, cbor.RawMessage(endpointHint)) {
		t.Fatalf("EndpointHint drift")
	}
	if dec.IdentityHint == nil || !bytes.Equal(dec.IdentityHint.Bytes(), identityHint.Bytes()) {
		t.Fatalf("IdentityHint drift")
	}
	if dec.Supersedes == nil || !bytes.Equal(dec.Supersedes.Bytes(), supersedes.Bytes()) {
		t.Fatalf("Supersedes drift")
	}
}

func TestCandidateNullPeerIDTOFU(t *testing.T) {
	// §2.2 + §2.2.1: backend just observed a peer presence — peer_id null
	// (pre-IDENTIFY), identity_hint nil (TOFU), supersedes nil (first
	// observation, no chain). Omitempty MUST drop all three from the wire so
	// first-observation hashes don't collide with later-observation null
	// encodings.
	d := CandidateData{
		Backend:    DiscoveryBackendMDNS,
		ObservedAt: 1_730_000_000_000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	dec, err := CandidateDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.PeerID != "" {
		t.Fatalf("PeerID should be empty (TOFU pre-IDENTIFY), got %q", dec.PeerID)
	}
	if dec.IdentityHint != nil {
		t.Fatalf("IdentityHint should be nil (TOFU), got %+v", dec.IdentityHint)
	}
	if dec.Supersedes != nil {
		t.Fatalf("Supersedes should be nil (first observation), got %+v", dec.Supersedes)
	}
}

func TestCandidateHashStability(t *testing.T) {
	// Same fields → same content_hash. Guards ECF determinism (deterministic
	// CBOR option must be in effect; map-key sort + uint canonicalization).
	mk := func() CandidateData {
		return CandidateData{
			PeerID:     dxFakePeerID,
			Backend:    DiscoveryBackendMDNS,
			ObservedAt: 1_730_000_000_000,
		}
	}
	e1, _ := mk().ToEntity()
	e2, _ := mk().ToEntity()
	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("hash drift across equal inputs: %x vs %x",
			e1.ContentHash.Bytes(), e2.ContentHash.Bytes())
	}
	// Backend change → distinct hash (no field collapse).
	d3 := mk()
	d3.Backend = "qr"
	e3, _ := d3.ToEntity()
	if e1.ContentHash == e3.ContentHash {
		t.Fatal("hash collision across distinct Backend values")
	}
}

func TestCandidateStoragePathHelpers(t *testing.T) {
	h := dxFakeHash(0xAB)
	got := CandidateStoragePath(DiscoveryBackendMDNS, h)
	want := "system/discovery/candidate/mdns/" + PeerIdentityHashHex(h)
	if got != want {
		t.Fatalf("CandidateStoragePath: want %q got %q", want, got)
	}
	if got := CandidatePrefix(DiscoveryBackendMDNS); got != "system/discovery/candidate/mdns/" {
		t.Fatalf("CandidatePrefix: %q", got)
	}
}

// -----------------------------------------------------------------------
// system/discovery/decision
// -----------------------------------------------------------------------

func TestDecisionGrantLimitedRoundtrip(t *testing.T) {
	candidateHash := dxFakeHash(0x33)
	grantHash := dxFakeHash(0x44)
	d := DecisionData{
		Candidate: candidateHash,
		Outcome:   DiscoveryOutcomeGrantLimited,
		Grant:     &grantHash,
		DecidedAt: 1_730_000_001_500,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeDiscoveryDecision {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dec, err := DecisionDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if !bytes.Equal(dec.Candidate.Bytes(), candidateHash.Bytes()) {
		t.Fatal("Candidate drift")
	}
	if dec.Outcome != DiscoveryOutcomeGrantLimited {
		t.Fatalf("Outcome drift: %q", dec.Outcome)
	}
	if dec.Grant == nil || !bytes.Equal(dec.Grant.Bytes(), grantHash.Bytes()) {
		t.Fatal("Grant drift")
	}
	if dec.DecidedAt != 1_730_000_001_500 {
		t.Fatalf("DecidedAt drift: %d", dec.DecidedAt)
	}
}

func TestDecisionIgnoreNoGrant(t *testing.T) {
	// `ignore` and `track` carry grant: null per §2.1. Omitempty MUST drop
	// the field on the wire — present-null and absent are distinct shapes on
	// ECF (length.1 vs primitive.1 corpus pin) and the absent form is
	// canonical for "no grant."
	d := DecisionData{
		Candidate: dxFakeHash(0x55),
		Outcome:   DiscoveryOutcomeIgnore,
		DecidedAt: 1_730_000_002_000,
	}
	e, _ := d.ToEntity()
	dec, err := DecisionDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.Grant != nil {
		t.Fatalf("Grant must drop on ignore; got %+v", dec.Grant)
	}
	if dec.Outcome != DiscoveryOutcomeIgnore {
		t.Fatalf("Outcome drift: %q", dec.Outcome)
	}
}

// -----------------------------------------------------------------------
// system/discovery/identity-claim
// -----------------------------------------------------------------------

func TestIdentityClaimRoundtrip(t *testing.T) {
	digest := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF}
	d := IdentityClaimData{
		PeerID:          dxFakePeerID,
		KeyType:         1, // Ed25519 — V7 §1.5 key-type byte (illustrative)
		HashType:        0, // SHA-256 — V7 §1.5 hash-type byte (illustrative)
		PublicKeyDigest: digest,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeDiscoveryIdentityClaim {
		t.Fatalf("type drift: %q", e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dec, err := IdentityClaimDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if dec.PeerID != dxFakePeerID {
		t.Fatalf("PeerID drift: %q", dec.PeerID)
	}
	if dec.KeyType != 1 || dec.HashType != 0 {
		t.Fatalf("key_type/hash_type drift: kt=%d ht=%d", dec.KeyType, dec.HashType)
	}
	if !bytes.Equal(dec.PublicKeyDigest, digest) {
		t.Fatalf("PublicKeyDigest drift")
	}
}

func TestIdentityClaimComparisonFailClosed(t *testing.T) {
	// §2.2.1: post-IDENTIFY the receiver constructs an IdentityClaim from
	// the actual IDENTIFY result and compares its content_hash with the
	// candidate's advertised identity_hint. Different field values MUST
	// produce different content_hashes — that's the substrate primitive the
	// fail-closed check rides on (D3 wires the check itself).
	a, _ := IdentityClaimData{
		PeerID:          dxFakePeerID,
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0x01, 0x02, 0x03},
	}.ToEntity()
	b, _ := IdentityClaimData{
		PeerID:          dxFakePeerID,
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0x01, 0x02, 0x04}, // single-byte digest delta
	}.ToEntity()
	if a.ContentHash == b.ContentHash {
		t.Fatal("identity-claim hash collision across distinct public_key_digest — fail-closed compare would not work")
	}
	// Equal-fields → equal hash (the gate for the compare).
	c, _ := IdentityClaimData{
		PeerID:          dxFakePeerID,
		KeyType:         1,
		HashType:        0,
		PublicKeyDigest: []byte{0x01, 0x02, 0x03},
	}.ToEntity()
	if a.ContentHash != c.ContentHash {
		t.Fatal("identity-claim hash drift across equal inputs — ECF determinism broken")
	}
}

// -----------------------------------------------------------------------
// system/discovery/scan-result
// -----------------------------------------------------------------------

func TestScanResultEmptyNoTruncation(t *testing.T) {
	// Empty scan, not truncated, code: null. The canonical happy-path shape
	// — flat envelope per cohort discipline #3 (NOT wrapped in
	// system/protocol/status).
	d := ScanResultData{
		Candidates: []hash.Hash{},
		Truncated:  false,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeDiscoveryScanResult {
		t.Fatalf("type drift: %q", e.Type)
	}
	dec, err := ScanResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if len(dec.Candidates) != 0 {
		t.Fatalf("candidates not empty: %d", len(dec.Candidates))
	}
	if dec.Truncated {
		t.Fatal("Truncated drift")
	}
	if dec.Code != nil {
		t.Fatalf("Code should be nil on non-truncated, got %+v", dec.Code)
	}
}

func TestScanResultTruncationCodeSurface(t *testing.T) {
	// §3.1 + §8.4: when over-bound, MUST surface as truncated: true + code:
	// "discovery_scan_overflow" — NOT silent truncation. This is the gate
	// D4 will probe behaviorally; here we just pin the round-trip.
	overflow := DiscoveryErrScanOverflow
	d := ScanResultData{
		Candidates: []hash.Hash{dxFakeHash(0x01), dxFakeHash(0x02)},
		Truncated:  true,
		Code:       &overflow,
	}
	e, _ := d.ToEntity()
	dec, err := ScanResultDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if !dec.Truncated {
		t.Fatal("Truncated drift")
	}
	if dec.Code == nil || *dec.Code != DiscoveryErrScanOverflow {
		t.Fatalf("Code must surface %q, got %+v", DiscoveryErrScanOverflow, dec.Code)
	}
	if len(dec.Candidates) != 2 {
		t.Fatalf("Candidates drift: %d", len(dec.Candidates))
	}
}

// -----------------------------------------------------------------------
// Registry wiring
// -----------------------------------------------------------------------

func TestDiscoveryTypesRegistered(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)
	for _, name := range []string{
		TypeDiscoveryCandidate,
		TypeDiscoveryDecision,
		TypeDiscoveryIdentityClaim,
		TypeDiscoveryScanResult,
	} {
		if _, ok := r.Get(name); !ok {
			t.Errorf("type %q not registered", name)
		}
	}

	// candidate.peer_id is nullable Base58 (system/peer-id, Optional) per
	// Ruling-1 generalizes — not the bare primitive/string the reflected
	// struct field renders to.
	def, _ := r.Get(TypeDiscoveryCandidate)
	if fs, ok := def.Fields["peer_id"]; !ok || fs.TypeRef != "system/peer-id" || !fs.Optional {
		t.Errorf("candidate.peer_id override missing/wrong: %+v", fs)
	}
	// identity-claim.peer_id is always-present Base58.
	def, _ = r.Get(TypeDiscoveryIdentityClaim)
	if fs, ok := def.Fields["peer_id"]; !ok || fs.TypeRef != "system/peer-id" || fs.Optional {
		t.Errorf("identity-claim.peer_id override missing/wrong: %+v", fs)
	}
	// decision: `grant` must be Optional (nil for ignore/track per §2.1).
	def, _ = r.Get(TypeDiscoveryDecision)
	if fs, ok := def.Fields["grant"]; !ok || !fs.Optional {
		t.Errorf("decision.grant must be present + optional, got %+v", fs)
	}
	// scan-result: `code` must be Optional (null normally per §3).
	def, _ = r.Get(TypeDiscoveryScanResult)
	if fs, ok := def.Fields["code"]; !ok || !fs.Optional {
		t.Errorf("scan-result.code must be present + optional, got %+v", fs)
	}
}
