package signaling

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"
)

// The §6.1 half of the flag day: the native punch seals what it deposits and
// verifies what it collects.
//
// §6.1 is where §6.3 step 3 finally has something to do. connect-request and
// connect-response name their author IN A WIRE FIELD, so a signature that is
// entirely valid under a false `initiator` satisfies every other check — the key
// derives its own id honestly, the signature covers this bucket, nothing is
// forged. Only the claim comparison catches it. The §6.5 payloads carry no
// peer-id at all, which is why the container could cross both ways at 38·0F
// with step 3 sitting unwired.

// mkRequest builds a connect-request naming initiator.
func mkRequest(t *testing.T, initiator string, nonce []byte) types.ConnectRequestData {
	t.Helper()
	return types.ConnectRequestData{
		Candidates: []types.NetworkCandidateData{
			{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: "203.0.113.7:9000"},
		},
		Initiator: initiator,
		Nonce:     nonce,
	}
}

// sealRequest seals a connect-request naming `claims` with kp's key, into bucket.
// When claims != kp's own id the result is the false-claim blob: valid in every
// respect except the identity it asserts.
func sealRequest(t *testing.T, kp crypto.Keypair, claims string, bucket []byte) []byte {
	t.Helper()
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	e, err := mkRequest(t, claims, nonce).ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sealed, err := SealBlob(e, kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}
	return blob
}

// TestAValidSignatureUnderAFalseInitiatorIsRefused is the step-3 fence.
//
// The load-bearing half is the SECOND assertion: OpenBlobBytes must SUCCEED on
// the very blob the classifier rejects. Without it the test would pass just as
// happily if the claim comparison were never reached and the signature check
// were doing all the work — which is precisely the state this repo was in, and
// the reason a test that only asserts "bad blob rejected" is not evidence that
// step 3 exists.
func TestAValidSignatureUnderAFalseInitiatorIsRefused(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	lying := sealRequest(t, kp, other, bucket) // signed by us, names them

	if _, err := ClassifyCollected(lying, bucket); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf("a request signed by %s but naming %s = %v, want ErrSignerMismatch", peerID, other, err)
	}

	// The signature itself is fine — nothing about this blob is forged. If this
	// assertion ever fails, the rejection above stopped proving what it claims.
	signer, _, err := OpenBlobBytes(lying, bucket)
	if err != nil {
		t.Fatalf("OpenBlobBytes on the same blob = %v, want success — step 3 must be the check that caught it", err)
	}
	if signer.PeerID != peerID {
		t.Fatalf("signature is by %q, want %q", signer.PeerID, peerID)
	}

	// The honest one passes and carries its verified identity.
	truthful := sealRequest(t, kp, peerID, bucket)
	m, err := ClassifyCollected(truthful, bucket)
	if err != nil || m.Kind != KindConnectRequest {
		t.Fatalf("truthful request = (%v, %v), want a connect-request", m.Kind, err)
	}
	if m.Signer.PeerID != peerID {
		t.Errorf("signer = %q, want %q", m.Signer.PeerID, peerID)
	}
}

// TestPunchSyncNamesNobodySoStep3HasNothingToCompare — punch-sync's correlation
// is the nonce echo alone, the position all three §6.5 payloads are in. A
// sealed one must pass on step 2 without a claim to check, or the comparison has
// been applied to a message that never had an author field and every sync would
// be skipped.
func TestPunchSyncNamesNobodySoStep3HasNothingToCompare(t *testing.T) {
	kp, peerID := testKeypair(t)
	_, other := testKeypair(t)
	bucket := testBucket(t, peerID, other)

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	e, err := types.PunchSyncData{FireAt: 250, Nonce: nonce}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	sealed, err := SealBlob(e, kp, bucket)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}
	blob, err := SealedToBlob(sealed)
	if err != nil {
		t.Fatalf("SealedToBlob: %v", err)
	}

	m, err := ClassifyCollected(blob, bucket)
	if err != nil || m.Kind != KindPunchSync {
		t.Fatalf("sealed punch-sync = (%v, %v), want a punch-sync", m.Kind, err)
	}
	if m.Signer.PeerID != peerID {
		t.Errorf("signer = %q, want %q — the signature is the only identity a sync has", m.Signer.PeerID, peerID)
	}
}

// TestSkipOwnUsesTheVerifiedSignerNotTheClaimedField.
//
// §6.4's skip-own protects against answering yourself — a failure where every
// step reports success and two peers never meet. Run against the CLAIMED field
// it is a check anyone can force: deposit a request naming the victim as its own
// initiator and the victim skips it, so the request it should have answered
// disappears from its bucket. With a verified signer present, the claim is not
// consulted at all.
func TestSkipOwnUsesTheVerifiedSignerNotTheClaimedField(t *testing.T) {
	kp, attacker := testKeypair(t)
	_, victim := testKeypair(t)
	bucket := testBucket(t, attacker, victim)

	// A blob the attacker signed, naming the victim. ClassifyCollected refuses
	// it outright (step 3), so the message never reaches the finder — the
	// strongest form of the guarantee.
	if _, err := ClassifyCollected(sealRequest(t, kp, victim, bucket), bucket); !errors.Is(err, ErrSignerMismatch) {
		t.Fatalf("impersonating request = %v, want ErrSignerMismatch", err)
	}

	// And directly at the finder: a message whose claim says "you" but whose
	// signature says otherwise is NOT skipped as the victim's own. Constructed
	// by hand here because the classifier will not produce one.
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	req := mkRequest(t, victim, nonce) // claims to be the victim…
	msgs := []CollectedMessage{{
		Kind:    KindConnectRequest,
		Request: &req,
		Signer:  VerifiedSigner{PeerID: attacker}, // …but is signed by the attacker
	}}
	got, signer, ok := FindRequest(msgs, victim)
	if !ok {
		t.Fatal("FindRequest skipped a request that only CLAIMS to be mine — skip-own is still reading the wire field")
	}
	if signer.PeerID != attacker {
		t.Errorf("signer = %q, want %q", signer.PeerID, attacker)
	}
	if got.Initiator != victim {
		t.Errorf("the claimed field is preserved for inspection, got %q", got.Initiator)
	}

	// The genuine self-skip still works: my own signed request is mine.
	own := []CollectedMessage{{
		Kind:    KindConnectRequest,
		Request: &req,
		Signer:  VerifiedSigner{PeerID: victim},
	}}
	if _, _, ok := FindRequest(own, victim); ok {
		t.Error("FindRequest answered my own signed request (§6.4 skip-own)")
	}
}

// TestTheBareWindowStillFallsBackToTheClaimedField — during the migration a
// counterpart that has not flipped arrives with no signer at all, and skip-own
// has nothing but the claimed field to work with. That is weaker, and it is the
// posture VerifyRequire exists to end; what it must not be is broken.
func TestTheBareWindowStillFallsBackToTheClaimedField(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	mine := mkRequest(t, "me", nonce)
	theirs := mkRequest(t, "them", nonce)
	msgs := []CollectedMessage{
		{Kind: KindConnectRequest, Request: &mine},
		{Kind: KindConnectRequest, Request: &theirs},
	}
	got, signer, ok := FindRequest(msgs, "me")
	if !ok || got.Initiator != "them" {
		t.Fatalf("FindRequest = (%v, %v), want the unsigned request from them", got, ok)
	}
	if signer.PeerID != "" {
		t.Errorf("an unsigned message must report no signer, got %q", signer.PeerID)
	}
}

// --- the punch itself --------------------------------------------------------

// punchTestParty is a party wired onto an in-memory carrier with the tight
// loopback tunables, parameterised on the two things this file is about.
func punchTestParty(carrier Carrier, key []byte, identity crypto.Keypair, trust VerificationPolicy, local *net.TCPAddr) *PunchParty {
	return &PunchParty{
		Carrier:  carrier,
		Key:      key,
		Identity: identity,
		Trust:    trust,
		LocalCands: []types.NetworkCandidateData{
			{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: local.String()},
		},
		LocalAddr:       local,
		Poll:            20 * time.Millisecond,
		CrossingRetries: 40,
		DialTimeout:     300 * time.Millisecond,
		ExchangeTimeout: 3 * time.Second,
	}
}

// TestAPunchUnderRequireOnBothSidesCompletes is the inversion of the old
// Require test, which could only ever assert that the policy refused everything
// because nothing sealed existed to satisfy it. Both parties now seal, so
// Require is a posture a real exchange survives — this is what the flag day
// converges on.
func TestAPunchUnderRequireOnBothSidesCompletes(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33)
	kpA, kpB := orderedKeypairs(t)
	aAddr, bAddr := freeLoopbackPort(t), freeLoopbackPort(t)

	aParty := punchTestParty(carrier, key, kpA, VerifyRequire, aAddr)
	bParty := punchTestParty(carrier, key, kpB, VerifyRequire, bAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type result struct {
		conn   net.Conn
		remote string
		err    error
	}
	aCh, bCh := make(chan result, 1), make(chan result, 1)
	go func() {
		c, err := aParty.Initiate(ctx, kpB.PeerID().String())
		aCh <- result{conn: c, err: err}
	}()
	go func() {
		c, remote, err := bParty.Respond(ctx)
		bCh <- result{conn: c, remote: remote, err: err}
	}()

	aRes, bRes := <-aCh, <-bCh
	if aRes.conn != nil {
		defer aRes.conn.Close()
	}
	if bRes.conn != nil {
		defer bRes.conn.Close()
	}
	if aRes.err != nil {
		if errors.Is(aRes.err, ErrReusePortUnsupported) {
			t.Skip("SO_REUSEPORT not supported on this platform")
		}
		t.Fatalf("initiator under Require: %v", aRes.err)
	}
	if bRes.err != nil {
		t.Fatalf("responder under Require: %v", bRes.err)
	}
	if bRes.remote != kpA.PeerID().String() {
		t.Errorf("responder saw initiator %q, want %q", bRes.remote, kpA.PeerID().String())
	}
}

// TestEverythingThePunchDepositsIsBoundToItsOwnBucket — the deposits are not
// merely signed, they are signed FOR THIS BUCKET. A blob lifted out and replayed
// into another key must fail there, which is the property that makes the
// signature worth having: without it a valid offer replays verbatim into any
// bucket and induces a peer nobody addressed to attempt a connection.
func TestEverythingThePunchDepositsIsBoundToItsOwnBucket(t *testing.T) {
	carrier := newMemCarrier()
	kpA, kpB := orderedKeypairs(t)
	key, err := PairKey(kpA.PeerID().String(), kpB.PeerID().String())
	if err != nil {
		t.Fatalf("PairKey: %v", err)
	}
	_, stranger := testKeypair(t)
	elsewhere := testBucket(t, kpA.PeerID().String(), stranger)

	// Drive one initiator far enough to deposit a connect-request. Nobody
	// answers, so it ends in the exchange timeout — the deposit is what we want.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	party := punchTestParty(carrier, key, kpA, VerifyRequire, freeLoopbackPort(t))
	if _, err := party.Initiate(ctx, kpB.PeerID().String()); err == nil {
		t.Fatal("expected the unanswered exchange to time out")
	}

	carrier.mu.Lock()
	blobs := append([][]byte(nil), carrier.buckets[string(key)]...)
	carrier.mu.Unlock()
	if len(blobs) == 0 {
		t.Fatal("the punch deposited nothing")
	}
	for i, b := range blobs {
		if _, _, err := OpenBlobBytes(b, key); err != nil {
			t.Errorf("deposit %d does not open under its own bucket: %v — it was not sealed", i, err)
		}
		if _, _, err := OpenBlobBytes(b, elsewhere); err == nil {
			t.Errorf("deposit %d verifies in a bucket it was not sealed for — the binding is missing", i)
		}
	}
}

// TestRequireRefusesABareCounterpartLoudlyNotByTimingOut.
//
// The refusal has to arrive BY NAME and AT THE MOMENT the answer lands. A silent
// skip is not a safe default here: it leaves the initiator polling a bucket that
// already holds its reply and eventually reporting a timeout, which reads as
// "nobody replied", which reads as a NAT problem — a diagnosis one word from the
// truth and days from the cause. This is the difference between the two error
// values, so asserting merely that it failed would assert nothing.
func TestRequireRefusesABareCounterpartLoudlyNotByTimingOut(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33)
	kpA, kpB := orderedKeypairs(t)

	// A bare (pre-flag-day) responder deposits the answer A is waiting for.
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	respEnt, err := types.ConnectResponseData{
		Candidates: []types.NetworkCandidateData{
			{Type: types.CandidateTypeSrflx, Substrate: types.CandidateSubstrateTCP, Address: "198.51.100.4:7000"},
		},
		Nonce:     nonce,
		Responder: kpB.PeerID().String(),
	}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	bare, err := ecf.Encode(respEnt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := carrier.Offer(context.Background(), key, bare); err != nil {
		t.Fatalf("Offer: %v", err)
	}

	party := punchTestParty(carrier, key, kpA, VerifyRequire, freeLoopbackPort(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = party.awaitResponse(ctx, nonce, kpB.PeerID().String())
	if !errors.Is(err, ErrUnverifiedCounterpart) {
		t.Fatalf("awaitResponse = %v, want ErrUnverifiedCounterpart — an unsealed answer must be refused by name, not reported as a timeout", err)
	}
	if elapsed := time.Since(start); elapsed >= party.ExchangeTimeout {
		t.Errorf("the refusal took %v — it must arrive when the answer does, not at the deadline", elapsed)
	}

	// The same bucket under the tolerant posture: accepted, because that is what
	// the migration window is for.
	party.Trust = VerifyTolerant
	if _, err := party.awaitResponse(ctx, nonce, kpB.PeerID().String()); err != nil {
		t.Errorf("tolerant awaitResponse = %v, want the bare answer accepted", err)
	}
}

// TestAStrangersUnsealedBlobIsSkippedNotRaised — the other half of the rule, and
// the reason policy is applied AFTER the correlation filters. A message that was
// never ours must not be able to end our exchange: otherwise anyone who knows a
// lobby bucket kills every punch in it by depositing one bare entity. Here the
// stranger's response echoes a DIFFERENT nonce, so it is skipped under §6.4 and
// the poll runs to its own deadline.
func TestAStrangersUnsealedBlobIsSkippedNotRaised(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33)
	kpA, _ := orderedKeypairs(t)
	_, stranger := testKeypair(t)

	theirNonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	respEnt, err := types.ConnectResponseData{
		Candidates: []types.NetworkCandidateData{
			{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "192.0.2.9:1000"},
		},
		Nonce:     theirNonce,
		Responder: stranger,
	}.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	bare, err := ecf.Encode(respEnt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := carrier.Offer(context.Background(), key, bare); err != nil {
		t.Fatalf("Offer: %v", err)
	}

	myNonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	party := punchTestParty(carrier, key, kpA, VerifyRequire, freeLoopbackPort(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = party.awaitResponse(ctx, myNonce, "")
	if errors.Is(err, ErrUnverifiedCounterpart) {
		t.Fatal("a stranger's unsealed blob ended our exchange — policy is being applied before the correlation filters")
	}
	if err == nil {
		t.Fatal("awaitResponse returned a response that was never ours")
	}
}

// TestAPartyMustChooseItsIdentityAndItsPolicy — both are fields a struct literal
// leaves zeroed when forgotten, and both are refused before the first deposit
// rather than surfacing later as "nobody replied".
func TestAPartyMustChooseItsIdentityAndItsPolicy(t *testing.T) {
	carrier := newMemCarrier()
	key := make([]byte, 33)
	kp, _ := orderedKeypairs(t)
	ctx := context.Background()

	noPolicy := punchTestParty(carrier, key, kp, VerifyUnset, freeLoopbackPort(t))
	if _, err := noPolicy.Initiate(ctx, "whoever"); !errors.Is(err, ErrPolicyUnset) {
		t.Errorf("Initiate with the zero policy = %v, want ErrPolicyUnset — the zero value must not be the tolerant posture", err)
	}
	if _, _, err := noPolicy.Respond(ctx); !errors.Is(err, ErrPolicyUnset) {
		t.Errorf("Respond with the zero policy = %v, want ErrPolicyUnset", err)
	}

	noIdentity := punchTestParty(carrier, key, crypto.Keypair{}, VerifyRequire, freeLoopbackPort(t))
	if _, err := noIdentity.Initiate(ctx, "whoever"); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Initiate with no identity = %v, want ErrNoIdentity", err)
	}

	// Nothing was deposited by either refusal.
	carrier.mu.Lock()
	n := len(carrier.buckets[string(key)])
	carrier.mu.Unlock()
	if n != 0 {
		t.Errorf("a refused party deposited %d blob(s) — preflight must run before the first deposit", n)
	}
}

// TestTheDepositedIdentityIsTheSignedIdentity — the skew class, closed
// structurally rather than by a check. A party derives its own id from the key
// it signs with, so the `initiator` field it writes and the signer a counterpart
// derives are the same value by construction; there is no second source to
// disagree. entity-core-rust refuses the disagreement at runtime (`IdentitySkew`)
// because their party takes both; this asserts Go cannot express it.
func TestTheDepositedIdentityIsTheSignedIdentity(t *testing.T) {
	carrier := newMemCarrier()
	kpA, kpB := orderedKeypairs(t)
	key, err := PairKey(kpA.PeerID().String(), kpB.PeerID().String())
	if err != nil {
		t.Fatalf("PairKey: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	party := punchTestParty(carrier, key, kpA, VerifyRequire, freeLoopbackPort(t))
	if _, err := party.Initiate(ctx, kpB.PeerID().String()); err == nil {
		t.Fatal("expected the unanswered exchange to time out")
	}

	carrier.mu.Lock()
	blobs := append([][]byte(nil), carrier.buckets[string(key)]...)
	carrier.mu.Unlock()

	sawRequest := false
	for _, b := range blobs {
		m, err := ClassifyCollected(b, key)
		if err != nil {
			t.Fatalf("our own deposit does not survive our own read path: %v", err)
		}
		if m.Signer.PeerID != kpA.PeerID().String() {
			t.Errorf("deposit signed as %q, want %q", m.Signer.PeerID, kpA.PeerID().String())
		}
		if m.Kind == KindConnectRequest {
			sawRequest = true
			if m.Request.Initiator != m.Signer.PeerID {
				t.Errorf("`initiator` says %q but the signature says %q", m.Request.Initiator, m.Signer.PeerID)
			}
		}
	}
	if !sawRequest {
		t.Fatal("no connect-request among the deposits")
	}
}
