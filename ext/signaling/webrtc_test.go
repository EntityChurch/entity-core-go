package signaling

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/mr-tron/base58"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
)

// §6.5 WebRTC-substrate coordination.
//
// The tests that matter here are the CONVERGENCE ones. A single implementation
// can satisfy a role rule trivially by agreeing with itself; what the rule has
// to survive is two peers running it independently on the same two inputs and
// reaching complementary conclusions. So the glare tests always run BOTH sides
// and assert exactly one offerer — never one side's answer against a constant.

func testKeypair(t *testing.T) (crypto.Keypair, string) {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp, crypto.PeerIDFromKeypair(kp).String()
}

// --- session_id (§6.5 MUST) -------------------------------------------------

func TestGenerateSessionIDLengthAndFreshness(t *testing.T) {
	a, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	if len(a) != SessionIDMinLen {
		t.Fatalf("session_id length = %d, want %d", len(a), SessionIDMinLen)
	}
	b, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	// Not a randomness test — it cannot be one. It catches the specific bug of a
	// constant or zero-valued session_id, which is the shape that splices two
	// pairings together.
	if bytes.Equal(a, b) {
		t.Fatal("two generated session_ids are identical — session_id is not fresh")
	}
	if bytes.Equal(a, make([]byte, SessionIDMinLen)) {
		t.Fatal("session_id is all zeros")
	}
}

func TestValidateSessionIDRejectsShort(t *testing.T) {
	for _, n := range []int{0, 1, 8, 15} {
		if err := ValidateSessionID(make([]byte, n)); !errors.Is(err, ErrSessionIDTooShort) {
			t.Errorf("ValidateSessionID(%d bytes) = %v, want ErrSessionIDTooShort", n, err)
		}
	}
	if err := ValidateSessionID(make([]byte, SessionIDMinLen)); err != nil {
		t.Errorf("ValidateSessionID(16 bytes) = %v, want nil", err)
	}
}

// A short session_id is a MUST violation, and §6.4's disposition for a message
// that fails a check is SKIP — the same as undecodable. Classified as
// KindUnknown so no caller can act on one by forgetting to check.
func TestClassifySkipsShortSessionID(t *testing.T) {
	e, err := types.WebRTCOfferData{SDP: "v=0", SessionID: []byte("tooshort")}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if got := Classify(e).Kind; got != KindUnknown {
		t.Fatalf("Classify(short session_id) kind = %v, want KindUnknown (§6.4 skip)", got)
	}
}

// --- the offerer rule (§6.5, W3C perfect negotiation) -----------------------

// The convergence property: both peers run the resolver independently and
// exactly one keeps its offer. Asserted over id pairs chosen to exercise the
// byte-wise compare, including a prefix pair where a length-first or
// lexicographic-by-rune ordering would disagree.
func TestGlareConvergesOnExactlyOneOfferer(t *testing.T) {
	pairs := [][2]string{
		{"2K4c23upg34cKuk2sjoiHkPdn6LmeARntwruwWJLb6tqdG", "2KHGQS5Ur314WoEaVdKH2G4baXcgJDqLLiXGoBN5FsxgcD"},
		{"aaa", "aab"},
		{"aa", "aaa"}, // prefix: shorter sorts first byte-wise
		{"zzz", "aaa"},
	}
	for _, p := range pairs {
		mine, err := ResolveGlare(p[0], p[1])
		if err != nil {
			t.Fatalf("ResolveGlare(%q,%q): %v", p[0], p[1], err)
		}
		theirs, err := ResolveGlare(p[1], p[0])
		if err != nil {
			t.Fatalf("ResolveGlare(%q,%q): %v", p[1], p[0], err)
		}
		keepers := 0
		for _, o := range []GlareOutcome{mine, theirs} {
			if o == GlareKeepMine {
				keepers++
			}
		}
		if keepers != 1 {
			t.Errorf("pair (%q,%q): %d peers kept their offer, want exactly 1 (a glare that both keep is fatal to the RTCPeerConnection; one that neither keeps deadlocks)", p[0], p[1], keepers)
		}
	}
}

// The winner is `lo` — the lower-sorting id — and it is the SAME ordering
// PairKey derives the rendezvous key with. Asserted against PairKey rather than
// against a duplicated compare, so a drift in either shows up here.
func TestGlareWinnerIsTheKeyDerivationsLoPeer(t *testing.T) {
	a, b := "aab", "aaa" // b sorts lower
	out, err := ResolveGlare(a, b)
	if err != nil {
		t.Fatalf("ResolveGlare: %v", err)
	}
	if out != GlareRollBack {
		t.Errorf("higher-sorting peer outcome = %v, want GlareRollBack (hi is polite)", out)
	}
	impolite, err := Impolite(b, a)
	if err != nil {
		t.Fatalf("Impolite: %v", err)
	}
	if !impolite {
		t.Error("lower-sorting peer is not impolite — the offerer rule and the §3.2 sort disagree")
	}
	// pair(A,B) == pair(B,A) is the same sort's other consequence; if the two
	// ever diverged, one of these two assertions would be the one that failed.
	k1, err := PairKey(a, b)
	if err != nil {
		t.Fatalf("PairKey: %v", err)
	}
	k2, err := PairKey(b, a)
	if err != nil {
		t.Fatalf("PairKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("PairKey is not order-independent")
	}
}

// pair mode pre-assigns: hi waits, lo offers. Exactly one side waits — a rule
// where both wait is a deadlock and one where neither waits is the glare the
// optimization exists to skip.
func TestPairModePreAssignsExactlyOneWaiter(t *testing.T) {
	a, b := "aaa", "bbb"
	aWaits, err := PairShouldWaitForOffer(a, b)
	if err != nil {
		t.Fatalf("PairShouldWaitForOffer: %v", err)
	}
	bWaits, err := PairShouldWaitForOffer(b, a)
	if err != nil {
		t.Fatalf("PairShouldWaitForOffer: %v", err)
	}
	if aWaits == bWaits {
		t.Fatalf("both peers waiting=%v — want exactly one waiter", aWaits)
	}
	if aWaits {
		t.Error("the lower-sorting peer is waiting; lo offers, hi waits")
	}
}

// §6.4's skip-own is upstream of all of this. Reaching a negotiation against
// one's own id means it was missed, and there is no correct role to return.
func TestSelfNegotiationIsRefusedNotGuessed(t *testing.T) {
	if _, err := ResolveGlare("same", "same"); !errors.Is(err, ErrSelfNegotiation) {
		t.Errorf("ResolveGlare(self) = %v, want ErrSelfNegotiation", err)
	}
	if _, err := Impolite("same", "same"); !errors.Is(err, ErrSelfNegotiation) {
		t.Errorf("Impolite(self) = %v, want ErrSelfNegotiation", err)
	}
	if _, err := PairShouldWaitForOffer("same", "same"); !errors.Is(err, ErrSelfNegotiation) {
		t.Errorf("PairShouldWaitForOffer(self) = %v, want ErrSelfNegotiation", err)
	}
}

// --- §6.3 checks ------------------------------------------------------------

func TestVerifyCoordinationSignatureRoundTrip(t *testing.T) {
	kp, peerID := testKeypair(t)
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	e, err := types.WebRTCOfferData{SDP: "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n", SessionID: sid}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sig := kp.Sign(e.ContentHash.Bytes())

	signer, err := VerifyCoordinationSignature(e, kp.PublicKeyBytes(), kp.KeyType, sig)
	if err != nil {
		t.Fatalf("VerifyCoordinationSignature: %v", err)
	}
	if signer.PeerID != peerID {
		t.Fatalf("derived signer %q, want %q", signer.PeerID, peerID)
	}
}

func TestVerifyCoordinationSignatureRejectsWrongKeyAndTamper(t *testing.T) {
	kp, _ := testKeypair(t)
	other, _ := testKeypair(t)
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	e, err := types.WebRTCOfferData{SDP: "v=0", SessionID: sid}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sig := kp.Sign(e.ContentHash.Bytes())

	// A signature verified against someone else's public key must fail. This is
	// the whole self-contained-verification claim: a stranger with no key lookup
	// distinguishes the real signer from an impostor.
	if _, err := VerifyCoordinationSignature(e, other.PublicKeyBytes(), other.KeyType, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("verify with wrong public key = %v, want ErrBadSignature", err)
	}

	// Tampered SDP: the attacker rewrites the offer (a different DTLS
	// fingerprint, hence its own channel) but cannot re-sign it. The content
	// hash moves, so the old signature no longer verifies.
	tampered, err := types.WebRTCOfferData{SDP: "v=0 EVIL", SessionID: sid}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if _, err := VerifyCoordinationSignature(tampered, kp.PublicKeyBytes(), kp.KeyType, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("verify over tampered SDP = %v, want ErrBadSignature", err)
	}
}

// One key MUST yield exactly one peer-id, and verification MUST derive it
// rather than decode it from the wire.
//
// This pins Go against a procedure the DRAFT coordination-envelope proposal
// specifies literally: "decode `signer` → (key_type, hash_type, digest); check
// digest == Hash_{hash_type}(public_key)". Taking hash_type from the envelope
// makes the peer-id MALLEABLE — one Ed25519 key satisfies that check under both
// `0x01‖0x00‖pk` (identity, canonical) and `0x01‖0x01‖SHA-256(pk)`. Two ids,
// one key, and the holder picks which. Everything downstream sorts peer-ids:
// PairKey picks the bucket, Impolite picks the glare winner, §6.4 skip-own
// decides whether an entity is your own. A peer that can choose its id can
// choose its negotiation role, split the rendezvous bucket, and fail to
// recognize its own offer.
//
// Go is immune because VerifyCoordinationSignature derives via
// PeerIDFromPublicKey, which uses CanonicalHashType(key_type) and never reads a
// wire-supplied hash_type. That immunity is incidental today — nothing states
// it — so it gets a test before we build the envelope parser to that text.
func TestPeerIDIsDerivedCanonicallyNotDecodedFromTheWire(t *testing.T) {
	kp, canonical := testKeypair(t)
	pub := kp.PublicKeyBytes()

	// The alternate encoding, hand-built: Go has NO exported API that mints it
	// (PeerIDFromPublicKeyWithHashType refuses a non-identity hash_type for
	// Ed25519), which is the SPEC-AMBIGUITIES #67 finding in executable form —
	// an id §6.3's literal names and this implementation cannot produce.
	sum := sha256.Sum256(pub)
	alt := base58.Encode(append([]byte{crypto.KeyTypeEd25519, crypto.HashTypeSHA256}, sum[:]...))

	if alt == canonical {
		t.Fatal("the two encodings collided; this test's premise is gone")
	}
	// Logged so `go test -run ... -v` doubles as the reproduction routed to
	// arch: one key, two ids that both satisfy the draft's step 2.
	t.Logf("one Ed25519 key, two §1.5 encodings that both satisfy a wire-hash_type check:")
	t.Logf("  canonical (0x01||0x00||pk)      = %s", canonical)
	t.Logf("  alternate (0x01||0x01||sha(pk)) = %s", alt)

	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	e, err := types.WebRTCOfferData{SDP: "v=0", SessionID: sid}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sig := kp.Sign(e.ContentHash.Bytes())

	// A genuinely-signed blob still resolves to the canonical id and nothing
	// else. There is no input by which a holder of this key reaches `alt`.
	signer, err := VerifyCoordinationSignature(e, pub, kp.KeyType, sig)
	if err != nil {
		t.Fatalf("VerifyCoordinationSignature: %v", err)
	}
	if signer.PeerID != canonical {
		t.Fatalf("derived %q, want the canonical %q", signer.PeerID, canonical)
	}
	if signer.PeerID == alt {
		t.Fatal("verification resolved to the SHA-256-form id — the wire hash_type was honored")
	}

	// And the §6.1 claim path refuses the alternate rather than accepting it as
	// an equally-valid spelling of the same identity.
	if _, err := VerifyClaimedSigner(e, pub, kp.KeyType, sig, alt); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("claim under the alternate encoding = %v, want ErrSignerMismatch", err)
	}

	// The consequence, stated where it bites. Both encodings are the same
	// length, so neither is a prefix of the other and one strictly precedes the
	// other; a counterpart sorting between them therefore yields OPPOSITE glare
	// roles for the same key. Constructed rather than sampled — a random
	// counterpart lands between them only sometimes, and a test that only
	// sometimes demonstrates its point is not a test.
	lo, hi := canonical, alt
	if hi < lo {
		lo, hi = hi, lo
	}
	between := lo + "\x00" // > lo, and < hi since they differ before the end
	if !(between > lo && between < hi) {
		t.Fatalf("constructed counterpart is not between the two encodings")
	}
	asLo, err := Impolite(lo, between)
	if err != nil {
		t.Fatalf("Impolite: %v", err)
	}
	asHi, err := Impolite(hi, between)
	if err != nil {
		t.Fatalf("Impolite: %v", err)
	}
	if asLo == asHi {
		t.Fatalf("both encodings gave impolite=%v; the sort divergence should be total here", asLo)
	}
	// asLo=true, asHi=false: one key, two ids, and the holder picks whether its
	// offer wins the glare. That is what a wire-supplied hash_type would buy.
}

// The native §6.1 path additionally cross-checks the payload's claimed
// initiator/responder against the derived id. The §6.5 payloads have no such
// field, which is exactly why the signature is their only identity source.
func TestVerifyClaimedSignerCatchesAMismatchedClaim(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, otherID := testKeypair(t)
	e, err := types.ConnectRequestData{Initiator: otherID, Nonce: []byte("n")}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sig := kp.Sign(e.ContentHash.Bytes())

	if _, err := VerifyClaimedSigner(e, kp.PublicKeyBytes(), kp.KeyType, sig, otherID); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("claim of another peer's id = %v, want ErrSignerMismatch", err)
	}
	if _, err := VerifyClaimedSigner(e, kp.PublicKeyBytes(), kp.KeyType, sig, peerID); err != nil {
		t.Errorf("honest claim = %v, want nil", err)
	}
}

// --- the channel-identity guard (§6.5 MUST NOT) -----------------------------

func TestAcceptRemoteDescriptionRefusesUnverified(t *testing.T) {
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	offer := CollectedMessage{Kind: KindWebRTCOffer, WebRTCOffer: &types.WebRTCOfferData{SDP: "v=0", SessionID: sid}}

	if _, err := AcceptRemoteDescription(offer, VerifiedSigner{}, "me"); !errors.Is(err, ErrUnverifiedSDP) {
		t.Errorf("unverified signer = %v, want ErrUnverifiedSDP", err)
	}
	if _, err := AcceptRemoteDescription(offer, VerifiedSigner{PeerID: "me"}, "me"); !errors.Is(err, ErrSelfNegotiation) {
		t.Errorf("own offer = %v, want ErrSelfNegotiation", err)
	}
	sdp, err := AcceptRemoteDescription(offer, VerifiedSigner{PeerID: "them"}, "me")
	if err != nil {
		t.Fatalf("verified signer = %v, want nil", err)
	}
	if sdp != "v=0" {
		t.Fatalf("SDP = %q, want the entity's own bytes verbatim", sdp)
	}
	// A candidate is not a remote description; handing its fields to
	// setRemoteDescription would be a category error.
	cand := CollectedMessage{Kind: KindWebRTCCandidate, WebRTCCandidate: &types.WebRTCCandidateData{SessionID: sid}}
	if _, err := AcceptRemoteDescription(cand, VerifiedSigner{PeerID: "them"}, "me"); !errors.Is(err, ErrUnverifiedSDP) {
		t.Errorf("candidate as remote description = %v, want refusal", err)
	}
}

// --- bucket reads, session-scoped (§6.4 + §6.5) -----------------------------

// A shared bucket holds several pairings at once. Correlating by session_id is
// what keeps two concurrent handshakes from splicing — the failure this rule
// exists for is silent, so the test builds the mixture explicitly.
func TestBucketReadsAreSessionScoped(t *testing.T) {
	mine, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	theirs, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	ufrag := "ufrag1"
	bucket := []CollectedMessage{
		{Kind: KindWebRTCOffer, WebRTCOffer: &types.WebRTCOfferData{SDP: "theirs", SessionID: theirs}},
		{Kind: KindWebRTCOffer, WebRTCOffer: &types.WebRTCOfferData{SDP: "mine", SessionID: mine}},
		{Kind: KindWebRTCAnswer, WebRTCAnswer: &types.WebRTCAnswerData{SDP: "answer-theirs", SessionID: theirs}},
		{Kind: KindWebRTCAnswer, WebRTCAnswer: &types.WebRTCAnswerData{SDP: "answer-mine", SessionID: mine}},
		{Kind: KindWebRTCCandidate, WebRTCCandidate: &types.WebRTCCandidateData{Candidate: "c-mine-1", SessionID: mine, SDPMid: "0", UsernameFragment: &ufrag}},
		{Kind: KindWebRTCCandidate, WebRTCCandidate: &types.WebRTCCandidateData{Candidate: "c-theirs", SessionID: theirs}},
		{Kind: KindWebRTCCandidate, WebRTCCandidate: &types.WebRTCCandidateData{Candidate: "c-mine-2", SessionID: mine, SDPMid: "0", SDPMLineIndex: 1}},
		{Kind: KindUnknown}, // a newer impl's message type — MUST-ignore, not a fault
	}

	off, ok := FindWebRTCOffer(bucket, mine)
	if !ok || off.SDP != "mine" {
		t.Fatalf("FindWebRTCOffer = %v, %v; want the offer for MY session", off, ok)
	}
	ans, ok := FindWebRTCAnswer(bucket, mine)
	if !ok || ans.SDP != "answer-mine" {
		t.Fatalf("FindWebRTCAnswer = %v, %v; want the answer for MY session", ans, ok)
	}

	// Trickle ICE means candidates keep arriving: all of mine, none of theirs.
	cands := CollectWebRTCCandidates(bucket, mine)
	if len(cands) != 2 {
		t.Fatalf("collected %d candidates, want 2 (a reader that stops at the first strands the gathering)", len(cands))
	}
	for _, c := range cands {
		if !bytes.Equal(c.SessionID, mine) {
			t.Errorf("candidate from another session leaked in: %q", c.Candidate)
		}
	}

	// No match must be an empty result, not someone else's session.
	absent, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	if _, ok := FindWebRTCOffer(bucket, absent); ok {
		t.Error("FindWebRTCOffer matched an unrelated session")
	}
	if got := CollectWebRTCCandidates(bucket, absent); got == nil || len(got) != 0 {
		t.Errorf("CollectWebRTCCandidates(absent) = %v, want a non-nil empty slice", got)
	}
}

// --- trickle gating (the provisional-session window) ------------------------

// The predicate, stated as the table of every state a peer can actually be in.
// The row that matters is offered+rollback: a two-term `offered || answered`
// gate passes it, which is the gap this test exists to hold closed.
func TestMayTrickleOnlyUnderASettledSession(t *testing.T) {
	cases := []struct {
		name  string
		state TrickleState
		want  bool
		why   string
	}{
		{"prospective answerer, nothing sent", TrickleState{}, false,
			"session is provisional; the counterpart will never query it"},
		{"offered, no glare", TrickleState{Offered: true}, true,
			"my offer carries my session; the counterpart correlates on it"},
		{"answered after adopting theirs", TrickleState{Answered: true}, true,
			"adopted the offerer's session; final"},
		{"offered, glare, I am polite and conceding", TrickleState{Offered: true, Rollback: true}, false,
			"my session is already abandoned; `offered || answered` would let these out"},
		{"rolled back and answered", TrickleState{Offered: true, Answered: true, Rollback: true}, true,
			"adoption completed; Rollback is stale once Answered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayTrickle(tc.state); got != tc.want {
				t.Errorf("MayTrickle(%+v) = %v, want %v — %s", tc.state, got, tc.want, tc.why)
			}
		})
	}
}

// The consequence itself, pinned independently of the predicate. This is the
// test that would still fail if MayTrickle were deleted and its callers went
// back to posting eagerly: a candidate posted under a session that is later
// abandoned is not late, it is gone — the settled-session read cannot see it,
// and nothing anywhere reports an error.
func TestCandidatesPostedUnderAnAbandonedSessionAreLostNotLate(t *testing.T) {
	mine, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	theirs, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}

	// I offered, so `offered || answered` is already true. Then I collect their
	// offer and ResolveGlare makes me the polite one: my session is abandoned.
	lo, hi := "peer-aaa", "peer-zzz"
	outcome, err := ResolveGlare(hi, lo)
	if err != nil {
		t.Fatalf("ResolveGlare: %v", err)
	}
	if outcome != GlareRollBack {
		t.Fatalf("ResolveGlare(hi, lo) = %v, want GlareRollBack — the premise of this test", outcome)
	}
	if MayTrickle(TrickleState{Offered: true, Rollback: true}) {
		t.Fatal("MayTrickle allowed a post under the session being rolled back")
	}

	// Post anyway — this is the defect being reproduced, not the intended path.
	bucket := []CollectedMessage{
		{Kind: KindWebRTCOffer, WebRTCOffer: &types.WebRTCOfferData{SDP: "theirs", SessionID: theirs}},
		{Kind: KindWebRTCCandidate, WebRTCCandidate: &types.WebRTCCandidateData{Candidate: "c-premature", SessionID: mine}},
	}

	// After adoption the exchange is correlated by THEIR session.
	if got := CollectWebRTCCandidates(bucket, theirs); len(got) != 0 {
		t.Fatalf("collected %d candidates under the adopted session, want 0 — "+
			"the premature post is stranded under the abandoned one", len(got))
	}
	// And it is not an error anywhere: the offer still reads fine. That silence
	// is the whole hazard.
	if _, ok := FindWebRTCOffer(bucket, theirs); !ok {
		t.Fatal("the counterpart's offer must still be found — the loss is silent, not a fault")
	}
}

// --- wire shape -------------------------------------------------------------

// The candidate is a STRUCTURED tuple because addIceCandidate() rejects a bare
// line, and the optional ufrag must stay ABSENT when unset — an empty string
// would be read as a real (wrong) ufrag.
func TestCandidateRoundTripsStructuredWithOptionalUfragAbsent(t *testing.T) {
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	in := types.WebRTCCandidateData{
		Candidate:     "candidate:1 1 udp 2130706431 192.0.2.1 41000 typ host",
		SDPMid:        "0",
		SDPMLineIndex: 3,
		SessionID:     sid,
	}
	e, err := in.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != types.TypeSignalingWebRTCCandidate {
		t.Fatalf("type = %q, want %q", e.Type, types.TypeSignalingWebRTCCandidate)
	}
	out, err := types.WebRTCCandidateDataFromEntity(e)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if out.Candidate != in.Candidate || out.SDPMid != in.SDPMid || out.SDPMLineIndex != in.SDPMLineIndex {
		t.Fatalf("round trip lost fields: %+v", out)
	}
	if out.UsernameFragment != nil {
		t.Errorf("absent username_fragment decoded as %q — it must stay absent, not become empty", *out.UsernameFragment)
	}
	if !bytes.Contains(e.Data, []byte("sdp_mline_index")) {
		t.Error("sdp_mline_index is not on the wire under its spec name")
	}
	if bytes.Contains(e.Data, []byte("username_fragment")) {
		t.Error("absent username_fragment was encoded anyway")
	}
}

// A blob round trip through the carrier must not disturb the entity — §6.2
// embeds data verbatim because a re-encode silently invalidates the §6.3
// signature. Asserted as: sign, serialize, classify, and the signature still
// verifies over the reconstructed entity.
func TestBlobRoundTripPreservesTheSignature(t *testing.T) {
	kp, peerID := testKeypair(t)
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	e, err := types.WebRTCAnswerData{SDP: "v=0\r\na=fingerprint:sha-256 AA\r\n", SessionID: sid}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sig := kp.Sign(e.ContentHash.Bytes())

	blob, err := ToBlob(e)
	if err != nil {
		t.Fatalf("ToBlob: %v", err)
	}
	got := ClassifyBlob(blob)
	if got.Kind != KindWebRTCAnswer {
		t.Fatalf("kind after round trip = %v, want KindWebRTCAnswer", got.Kind)
	}

	// Rebuild the entity the way a receiver would and re-verify.
	rebuilt, err := types.WebRTCAnswerData{SDP: got.WebRTCAnswer.SDP, SessionID: got.WebRTCAnswer.SessionID}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	signer, err := VerifyCoordinationSignature(rebuilt, kp.PublicKeyBytes(), kp.KeyType, sig)
	if err != nil {
		t.Fatalf("signature did not survive the carrier round trip: %v", err)
	}
	if signer.PeerID != peerID {
		t.Fatalf("signer = %q, want %q", signer.PeerID, peerID)
	}
}
