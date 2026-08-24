package main

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

// A vector harness that only ever verifies its own emission proves a round trip
// and nothing else — the same trap as a punch that passes on loopback. These
// tests are the negative controls: each one mutates a row the way a real
// divergence would and asserts the verifier CATCHES it. If a mutation here
// passes, the corresponding cross-impl check is decorative.

func TestEmissionIsDeterministic(t *testing.T) {
	// The file has to be re-derivable or the commit pin in it means nothing.
	// Anything reaching for a random source or a clock breaks this.
	a, err := emitEntities()
	if err != nil {
		t.Fatalf("emitEntities: %v", err)
	}
	b, err := emitEntities()
	if err != nil {
		t.Fatalf("emitEntities: %v", err)
	}
	for i := range a {
		if string(a[i].Blob) != string(b[i].Blob) {
			t.Fatalf("row %q is not deterministic across emissions", a[i].Name)
		}
	}
	s1, err := emitSignatures()
	if err != nil {
		t.Fatalf("emitSignatures: %v", err)
	}
	s2, err := emitSignatures()
	if err != nil {
		t.Fatalf("emitSignatures: %v", err)
	}
	for i := range s1 {
		if string(s1[i].Signature) != string(s2[i].Signature) {
			t.Fatalf("signature row %q is not deterministic — a fixed seed was not used", s1[i].Name)
		}
	}
}

// The row the whole exercise turns on: an unset OPTIONAL that a sibling encodes
// as "" or null round-trips fine on its own side and is wrong on the wire.
func TestVerifierCatchesUfragPresentWhenExpectedAbsent(t *testing.T) {
	ufrag := "sneaked-in"
	e, err := types.WebRTCCandidateData{
		Candidate: "candidate:1 1 udp 1 192.0.2.1 1 typ host", SDPMid: "0",
		SessionID: sid(0x10, 16), UsernameFragment: &ufrag,
	}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	blob, err := signaling.ToBlob(e)
	if err != nil {
		t.Fatalf("ToBlob: %v", err)
	}
	// The row CLAIMS the field is absent; the blob carries it.
	rows := []EntityVector{{
		Name: "mutant", Kind: "candidate", Blob: blob,
		SessionID: sid(0x10, 16), Candidate: "candidate:1 1 udp 1 192.0.2.1 1 typ host", SDPMid: "0",
		ExpectAbsent: []string{"username_fragment"},
	}}
	if r := verifyEntities(rows); r.fail != 1 {
		t.Fatalf("verifier accepted a present ufrag where expect_absent said absent (%d fail)", r.fail)
	}
}

func TestVerifierCatchesWrongFieldValues(t *testing.T) {
	rows, err := emitEntities()
	if err != nil {
		t.Fatalf("emitEntities: %v", err)
	}
	// Same blob, a sibling that claims a different sdp_mid — the shape of a real
	// field-name or field-order divergence.
	for i := range rows {
		if rows[i].Kind == "candidate" {
			rows[i].SDPMid = "99"
			break
		}
	}
	if r := verifyEntities(rows); r.fail == 0 {
		t.Fatal("verifier accepted a mismatched sdp_mid")
	}
}

func TestVerifierCatchesFlippedRoleAndNonConvergence(t *testing.T) {
	yes, no := true, false

	// A single flipped decision: the sibling says the higher-sorting id is
	// impolite.
	flipped := []RoleVector{{Name: "flipped", Self: "2Ka", Other: "2KZ", Impolite: &yes, PairSuppress: &no}}
	if r := verifyRoles(flipped); r.fail == 0 {
		t.Fatal("verifier accepted an inverted offerer decision")
	}

	// Individually-plausible rows that are jointly fatal: both sides impolite,
	// so both keep their offer and the RTCPeerConnection state machine breaks.
	// Each row on its own looks like an ordinary claim.
	both := []RoleVector{
		{Name: "a", Self: "2KZ", Other: "2Ka", Impolite: &yes, PairSuppress: &no},
		{Name: "b", Self: "2Ka", Other: "2KZ", Impolite: &yes, PairSuppress: &no},
	}
	if why := checkRoleConvergence(both); why == "" {
		t.Fatal("convergence check passed a file where both peers are impolite")
	}
	// ...and the mirror bug: neither impolite, which deadlocks instead.
	neither := []RoleVector{
		{Name: "a", Self: "2KZ", Other: "2Ka", Impolite: &no, PairSuppress: &yes},
		{Name: "b", Self: "2Ka", Other: "2KZ", Impolite: &no, PairSuppress: &yes},
	}
	if why := checkRoleConvergence(neither); why == "" {
		t.Fatal("convergence check passed a file where neither peer is impolite")
	}
	// The honest file converges.
	good, err := emitRoles()
	if err != nil {
		t.Fatalf("emitRoles: %v", err)
	}
	if why := checkRoleConvergence(good); why != "" {
		t.Fatalf("Go's own rows are non-convergent: %s", why)
	}
}

// §6.4's skip-own failing open is the exact bug rust found by reading Go's code:
// a plausible role returned for a peer negotiating with itself, where every step
// then reports success.
func TestVerifierCatchesSelfNegotiationAnsweredWithARole(t *testing.T) {
	yes := true
	rows := []RoleVector{{Name: "self-answered", Self: "2KZ", Other: "2KZ", Impolite: &yes}}
	if r := verifyRoles(rows); r.fail == 0 {
		t.Fatal("verifier accepted a role for equal peer-ids instead of requiring a refusal")
	}
}

func TestVerifierCatchesSessionFloorDisagreement(t *testing.T) {
	rows := []SessionIDVector{
		{Name: "15-accepted", Bytes: sid(0x30, 15), Accept: true},  // sibling accepts below the floor
		{Name: "16-rejected", Bytes: sid(0x40, 16), Accept: false}, // sibling rejects at the floor
	}
	if r := verifySessionIDs(rows); r.fail != 2 {
		t.Fatalf("session-floor disagreements caught: %d, want 2", r.fail)
	}
}

func TestVerifierCatchesSignatureExpectationsBeingWrong(t *testing.T) {
	rows, err := emitSignatures()
	if err != nil {
		t.Fatalf("emitSignatures: %v", err)
	}
	if r := verifySignatures(rows); r.fail != 0 {
		t.Fatalf("honest signature rows failed: %d", r.fail)
	}

	// A stub verifier's file: every row claims ok, including the forged ones.
	// This is the mutation that a positives-only vector suite cannot catch,
	// which is why the negatives are in the contract.
	stub := make([]SignatureVector, len(rows))
	copy(stub, rows)
	caught := 0
	for i := range stub {
		if stub[i].Expect != expectOK {
			stub[i].Expect = expectOK
			caught++
		}
	}
	r := verifySignatures(stub)
	if r.fail != caught {
		t.Fatalf("relabelling %d negative rows as ok produced %d failures, want %d", caught, r.fail, caught)
	}

	// And a wrong expected signer — the shape a stale §6.3 derivation produces
	// (SHA-256-form vs the canonical identity-form Ed25519 peer-id).
	wrong := make([]SignatureVector, len(rows))
	copy(wrong, rows)
	for i := range wrong {
		if wrong[i].Expect == expectOK && wrong[i].ExpectSigner != "" {
			wrong[i].ExpectSigner = "2KnotTheRealSigner"
			break
		}
	}
	if r := verifySignatures(wrong); r.fail == 0 {
		t.Fatal("verifier accepted a row whose expected signer does not match the derivation")
	}
}
