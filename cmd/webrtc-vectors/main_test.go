package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"

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

// --- surface 5: the §6.3 container ------------------------------------------

func signedBlobRows(t *testing.T) []SignedBlobVector {
	t.Helper()
	rows, err := emitSignedBlobs()
	if err != nil {
		t.Fatalf("emitSignedBlobs: %v", err)
	}
	return rows
}

func findBlobRow(t *testing.T, rows []SignedBlobVector, name string) *SignedBlobVector {
	t.Helper()
	for i := range rows {
		if rows[i].Name == name {
			return &rows[i]
		}
	}
	t.Fatalf("no %q row", name)
	return nil
}

func TestSignedBlobEmissionIsDeterministic(t *testing.T) {
	a, b := signedBlobRows(t), signedBlobRows(t)
	for i := range a {
		if string(a[i].Blob) != string(b[i].Blob) {
			t.Fatalf("row %q is not deterministic — a fixed seed was not used", a[i].Name)
		}
	}
}

func TestSignedBlobRowsVerifyAsEmitted(t *testing.T) {
	if r := verifySignedBlobs(signedBlobRows(t)); r.fail != 0 {
		t.Fatalf("own emission failed %d rows: %v", r.fail, r.lines)
	}
}

// The single most important control. If a sibling does not bind the rendezvous
// key, its verifier ignores it and the replayed blob verifies. Re-point the row
// at the bucket it was actually signed for: it MUST flip to ok. Without this,
// a replay row failing for some unrelated reason would look like a working
// binding check forever.
func TestTheReplayRowIsActuallyExercised(t *testing.T) {
	rows := signedBlobRows(t)
	valid := findBlobRow(t, rows, "ed25519/valid")
	replay := findBlobRow(t, rows, "ed25519/replayed-into-another-bucket")

	if string(valid.Blob) != string(replay.Blob) {
		t.Fatal("the replay row must be the valid row's bytes verbatim, or it tests something else")
	}
	if string(valid.RendezvousKey) == string(replay.RendezvousKey) {
		t.Fatal("the replay row uses the SAME bucket as the valid row — it proves nothing")
	}

	replay.RendezvousKey = valid.RendezvousKey
	replay.Expect = expectOK
	replay.ExpectSigner = valid.ExpectSigner
	replay.ExpectInnerBlob = valid.ExpectInnerBlob
	if r := verifySignedBlobs(rows); r.fail != 0 {
		t.Fatalf("the replayed blob must verify at its OWN bucket; it failed: %v", r.lines)
	}
}

// The ratchet guard: if the emission ever stops crossing a non-Ed25519 envelope,
// that must be loud. The Ed448 hardcode was silent for exactly this reason.
func TestTheEd448ContainerRowIsActuallyExercised(t *testing.T) {
	row := findBlobRow(t, signedBlobRows(t), "ed448/valid")
	if row.Expect != expectOK || row.ExpectSigner == "" {
		t.Fatal("the ed448 container row is not exercised — the parametric key_type path is uncrossed")
	}
	if _, _, err := signaling.OpenBlobBytes(row.Blob, row.RendezvousKey); err != nil {
		t.Fatalf("the ed448 row must actually open: %v", err)
	}
}

// A missing surface must be ABSENT, never a silent 0/0 that a green summary
// reads as crossed. That is the §11.5.1 blindness this proposal exists to end.
func TestAMissingContainerSurfaceIsAbsentNotPassed(t *testing.T) {
	r := verifySignedBlobs(nil)
	if r.pass != 0 || r.fail != 0 {
		t.Errorf("absent surface counted %d/%d; it must count nothing", r.pass, r.fail)
	}
	if len(r.lines) == 0 || !strings.Contains(r.lines[0], "ABSENT") {
		t.Errorf("absent surface must say so out loud, got %v", r.lines)
	}
}

func TestVerifierCatchesMislabelledContainerOutcomes(t *testing.T) {
	for _, name := range []string{
		"ed25519/replayed-into-another-bucket",
		"ed25519/non-canonical-hash-type",
		"ed25519/signer-names-another-peer",
		"ed25519/tampered-inner-entity",
		"ed25519/bare-content-hash-signature",
		"ed25519/signed-by-another-key",
	} {
		t.Run(name, func(t *testing.T) {
			rows := signedBlobRows(t)
			findBlobRow(t, rows, name).Expect = expectOK
			if r := verifySignedBlobs(rows); r.fail == 0 {
				t.Errorf("a negative row relabelled ok was accepted — %s is not really checked", name)
			}
		})
	}
}

// unusable_key and bad_signature must not be interchangeable: one never reached
// the signature check. Collapsing them sends a diagnostician after the key
// material when the fault is in the key type — the Ed448 defect's shape.
func TestContainerTaxonomyNamesAreNotInterchangeable(t *testing.T) {
	rows := signedBlobRows(t)
	findBlobRow(t, rows, "ed25519/non-canonical-hash-type").Expect = expectBadSignature
	if r := verifySignedBlobs(rows); r.fail == 0 {
		t.Error("unusable_key was accepted as bad_signature")
	}

	rows2 := signedBlobRows(t)
	findBlobRow(t, rows2, "ed25519/tampered-inner-entity").Expect = expectUnusableKey
	if r := verifySignedBlobs(rows2); r.fail == 0 {
		t.Error("bad_signature was accepted as unusable_key")
	}
}

func TestVerifierCatchesWrongContainerSignerAndInnerBlob(t *testing.T) {
	rows := signedBlobRows(t)
	findBlobRow(t, rows, "ed25519/valid").ExpectSigner = "peer-nobody"
	if r := verifySignedBlobs(rows); r.fail == 0 {
		t.Error("a row claiming the wrong signer passed — the verifier returns ok without checking WHO signed")
	}

	// Byte fidelity THROUGH the container. A verifier that decodes and
	// re-encodes the inner entity silently invalidates the signature it
	// carries, and this is the row that would catch it.
	rows2 := signedBlobRows(t)
	row := findBlobRow(t, rows2, "ed25519/valid")
	corrupted := append([]byte{}, row.ExpectInnerBlob...)
	corrupted[len(corrupted)-1] ^= 0xff
	row.ExpectInnerBlob = corrupted
	if r := verifySignedBlobs(rows2); r.fail == 0 {
		t.Error("a wrong expect_inner_blob passed — byte preservation through the container is unchecked")
	}
}

// The signing input is the one thing that must match byte-for-byte across impls,
// and it is the cohort-agreed layout rather than whatever this package happens
// to do. Re-derived here independently of ext/signaling for that reason.
// Run per content_hash_format: the layout claim is that the ONE variable
// component is last, so it must hold for every allocated format, not just the
// one this cohort happens to run (EXTENSION-SIGNALING §6.3 as corrected
// 2026-08-10; GUIDE-CONFORMANCE §5.2b — a configuration axis is covered only
// when the suite exercises it per value). The rendezvous key stays 33 in both
// rows: §3.1 pins its format to the SHA-256 floor deliberately.
func TestTheSigningInputIsTheCohortAgreedBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alg      byte
		hashSize int
	}{
		{"sha256-home", 0x00, 33},
		{"sha384-home", 0x01, 49},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, 33)
			for i := range key {
				key[i] = byte(i)
			}
			hash := make([]byte, tc.hashSize)
			hash[0] = tc.alg
			for i := 1; i < len(hash); i++ {
				hash[i] = byte(0x80 + i)
			}
			got := coordinationSigningInput(key, hash)

			want := append([]byte("entity:sigblob:v1"), 0x1F)
			want = append(want, key...)
			want = append(want, hash...)
			if string(got) != string(want) {
				t.Fatalf("signing input diverged from the routed layout\n got %x\nwant %x", got, want)
			}
			// The expected length follows the content hash's own format byte.
			if wantLen := signaling.SigningInputLen(tc.alg); len(got) != wantLen {
				t.Errorf("signing input is %d bytes, package says %d (format 0x%02x)", len(got), wantLen, tc.alg)
			}
		})
	}
}

// --- the artifact is not the emitter ----------------------------------------

// The committed vector file and the emitter that produces it are independent
// facts, and nothing forced them to agree. entity-core-rust shipped a routing
// doc asserting their file carried a surface it did not — the emitter had grown
// it, the artifact was stale, the suite was green, and nothing compared them
// (their 0dd1ba3, caught by our verifier). Go has the identical exposure: our
// commit-code-then-emit-then-commit-artifact sequence is a DISCIPLINE, not a
// mechanism, and disciplines fail quietly.
//
// Compares CANONICAL BYTES, not decoded values — their correction, and it is
// the comparison that matters anyway since bytes are what a sibling reads.
// (Decoded maps come back ECF-sorted; freshly built ones are in insertion
// order, so a value-tree comparison fails on map ordering alone.)
func TestTheCommittedVectorFileIsNotStale(t *testing.T) {
	const path = "../../docs/validation/vectors/webrtc-coordination-go.cbor"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed artifact: %v (the file is the deliverable; a missing one is a failure, not a skip)", err)
	}
	var committed VectorFile
	if err := ecf.Decode(raw, &committed); err != nil {
		t.Fatalf("decode committed artifact: %v", err)
	}

	entities, err := emitEntities()
	if err != nil {
		t.Fatalf("emitEntities: %v", err)
	}
	sigs, err := emitSignatures()
	if err != nil {
		t.Fatalf("emitSignatures: %v", err)
	}
	blobs, err := emitSignedBlobs()
	if err != nil {
		t.Fatalf("emitSignedBlobs: %v", err)
	}

	compareCanonical(t, "entities", committed.Entities, entities)
	compareCanonical(t, "roles", committed.Roles, emitRoles2(t))
	compareCanonical(t, "session_ids", committed.SessionIDs, emitSessionIDs())
	compareCanonical(t, "signatures", committed.Signatures, sigs)
	compareCanonical(t, "signed_blobs", committed.SignedBlobs, blobs)
	compareCanonical(t, "signing_input", committed.SigningInput, emitSigningInput())
}

func emitRoles2(t *testing.T) []RoleVector {
	t.Helper()
	roles, err := emitRoles()
	if err != nil {
		t.Fatalf("emitRoles: %v", err)
	}
	return roles
}

// compareCanonical reports lengths and the first differing byte offset rather
// than dumping two multi-kilobyte hex blobs. Also rust's note, and a good one:
// a guard nobody can read is a guard that gets muted.
func compareCanonical(t *testing.T, name string, committed, fresh any) {
	t.Helper()
	a, err := ecf.Encode(committed)
	if err != nil {
		t.Fatalf("%s: encode committed: %v", name, err)
	}
	b, err := ecf.Encode(fresh)
	if err != nil {
		t.Fatalf("%s: encode fresh: %v", name, err)
	}
	if bytes.Equal(a, b) {
		return
	}
	offset := -1
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			offset = i
			break
		}
	}
	if offset == -1 {
		offset = min(len(a), len(b))
	}
	t.Errorf("%s: the committed artifact is STALE — re-run `go run ./cmd/webrtc-vectors -emit "+
		"docs/validation/vectors/webrtc-coordination-go.cbor` and commit it.\n"+
		"  committed: %d bytes\n  emitter:   %d bytes\n  first differing byte at offset %d",
		name, len(a), len(b), offset)
}
