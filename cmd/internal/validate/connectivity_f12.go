package validate

import (
	"context"
	"crypto/rand"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// connectURI is the peer-relative handler path for the connect handshake.
// Hardcoded here because the protocol package keeps its const unexported;
// the validator constructs raw handshake frames for negative probes.
const connectURI = "system/protocol/connect"

// runHandshakeProofChecks drives the SPEC-FINDING F12 negative probes: a
// conformant responder MUST perform proof-of-possession at §4.6 — it must
// reject an authenticate that (a) echoes a nonce it never issued (replay
// across connections) or (b) carries a signature that does not verify (the
// connecting party does not hold the private key). A peer that accepts either
// authenticates nobody — a peer's identity (peer_id + public_key) is public,
// so without these checks any party can complete the handshake as anyone.
//
// The probes assert ONLY that the authenticate is rejected (status != 200) —
// NOT a specific status code. Whether request-time/handshake rejections are
// 401 vs 403 is unpinned (ask A1, still with architecture); the oracle must
// not encode that decision. Each probe uses a fresh connection because the
// main handshake locks the connection state.
func runHandshakeProofChecks(ctx context.Context, addr string) []CheckResult {
	var checks []CheckResult

	// Positive control: a VALID authenticate on a fresh connection must be
	// accepted (200). Without this baseline a peer that drops every fresh
	// probe connection for unrelated reasons would silently "pass" the
	// negative probes via the connection-closed branch — a false negative
	// the oracle must not produce. The baseline result gates how we read an
	// ambiguous connection-close below.
	baselineOK, baselineCheck := probeBaseline(ctx, addr)
	checks = append(checks, baselineCheck)

	checks = append(checks, probeAuthRejected(ctx, addr, baselineOK,
		"handshake_nonce_echo_enforced", "V7 §4.6 / F12", "",
		"authenticate echoing a nonce the responder never issued",
		func(pc *PeerClient, _ []byte) (entity.Envelope, error) {
			bogus := make([]byte, 32)
			if _, err := rand.Read(bogus); err != nil {
				return entity.Envelope{}, err
			}
			// Valid signature over a valid authenticate — but the echoed
			// nonce is not the one the responder issued.
			return protocol.CreateAuthenticateExecute(pc.keypair, bogus)
		}))

	checks = append(checks, probeAuthRejected(ctx, addr, baselineOK,
		"handshake_authenticate_signature_enforced", "V7 §4.6 / F12", "",
		"authenticate whose signature does not verify",
		func(pc *PeerClient, issuedNonce []byte) (entity.Envelope, error) {
			// Correct nonce, structurally valid signature entity, but the
			// signature is over the wrong bytes so it cannot verify against
			// the claimed public key.
			return buildAuthenticateBadSig(pc.keypair, issuedNonce)
		}))

	// Probe (proposal §6.2): impersonation by a different key. Claim a
	// victim's peer_id + public_key, sign with the attacker's own key. The
	// signature cannot verify against the claimed (victim's) public key →
	// MUST be rejected. Distinct code path from the wrong-message bad-sig
	// probe above (right key / wrong message vs wrong key / right message).
	//
	// CRITICAL: the hello MUST claim the victim's peer_id too. Impls that
	// check authenticate.peer_id == hello.peer_id (e.g. Python) would
	// otherwise reject on that consistency check and never reach the
	// signature verification — a false pass. Sharing the peer_id forces the
	// rejection to come from PoP.
	if victim, err := crypto.Generate(); err == nil {
		if attacker, err := crypto.Generate(); err == nil {
			victimID := string(victim.PeerID())
			checks = append(checks, probeAuthRejected(ctx, addr, baselineOK,
				"handshake_impersonation_rejected", "V7 §4.6 / §1.2", victimID,
				"authenticate claiming a victim's identity but signed by another key",
				func(_ *PeerClient, issuedNonce []byte) (entity.Envelope, error) {
					return buildAuthenticateCustom(victimID, victim.PublicKeyBytes(), attacker, issuedNonce)
				}))
		}
	}

	// Probe (proposal §6.3): peer_id↔public_key binding. A self-consistent,
	// validly-signed authenticate whose peer_id does NOT derive from its
	// public_key MUST be rejected (§1.5 construction). This is the probe that
	// would have caught the Python G-A spoofing gap — its absence is why the
	// divergence shipped. Proof-of-possession alone (valid sig over the
	// presented key) is not enough; the key must bind to the claimed identity,
	// because grants resolve by remote_peer_id.
	//
	// CRITICAL: hello and authenticate both claim `claimed`'s peer_id, while
	// the presented public_key (and signing key) is `real`'s. So peer_id ↔
	// hello is consistent and the signature verifies — the ONLY thing left to
	// reject on is peer_id != derive(public_key). An impl that skips the
	// binding check (Python G-A) accepts this and is caught.
	if claimed, err := crypto.Generate(); err == nil {
		if real, err := crypto.Generate(); err == nil {
			claimedID := string(claimed.PeerID())
			checks = append(checks, probeAuthRejected(ctx, addr, baselineOK,
				"handshake_peer_id_binding_enforced", "V7 §4.6 / §1.3", claimedID,
				"authenticate whose peer_id does not derive from its public_key",
				func(_ *PeerClient, issuedNonce []byte) (entity.Envelope, error) {
					return buildAuthenticateCustom(claimedID, real.PublicKeyBytes(), real, issuedNonce)
				}))
		}
	}

	// Probe (proposal §6.1): cross-connection replay — the literal F12
	// threat. A *valid* authenticate captured for one connection's nonce,
	// replayed verbatim on a fresh connection that issued a different nonce,
	// MUST be rejected. Unlike the random-bogus-nonce probe, this proves the
	// nonce is bound per-connection against a genuinely valid authenticate.
	checks = append(checks, probeReplayCrossConnection(ctx, addr, baselineOK))

	return checks
}

// probeReplayCrossConnection builds a fully valid authenticate against
// connection A's issued nonce, then replays it on a fresh connection B (which
// issued a different nonce). A conformant responder rejects it because the
// echoed nonce is not B's challenge.
func probeReplayCrossConnection(ctx context.Context, addr string, baselineOK bool) CheckResult {
	const cat = catConnectivity
	const name = "handshake_replay_cross_connection"
	const ref = "V7 §4.6 / §6.1 / F12"
	const desc = "a valid authenticate captured for another connection's nonce, replayed"

	// Connection A: obtain a valid authenticate bound to A's nonce.
	capKP, err := crypto.Generate()
	if err != nil {
		return warn(cat, name, ref, "could not generate probe keypair: "+err.Error())
	}
	pcA, err := NewPeerClient(addr)
	if err != nil {
		return warn(cat, name, ref, "could not create probe client A: "+err.Error())
	}
	defer pcA.Close()
	if err := pcA.Connect(ctx); err != nil {
		return warn(cat, name, ref, "probe A connect failed: "+err.Error())
	}
	// Both connections' hellos claim capKP's peer_id so that the only
	// difference the replayed authenticate presents on B is the nonce —
	// otherwise an impl's authenticate.peer_id == hello.peer_id consistency
	// check (e.g. Python) would reject on peer_id and pre-empt the nonce
	// check, giving a false pass.
	capID := string(capKP.PeerID())
	nonceA, err := probeHelloNonceAs(ctx, pcA, capID)
	if err != nil {
		return warn(cat, name, ref, "probe A hello failed: "+err.Error())
	}
	capturedAuth, err := protocol.CreateAuthenticateExecute(capKP, nonceA)
	if err != nil {
		return warn(cat, name, ref, "could not build captured authenticate: "+err.Error())
	}

	// Connection B: a fresh connection issues a different nonce.
	pcB, err := NewPeerClient(addr)
	if err != nil {
		return warn(cat, name, ref, "could not create probe client B: "+err.Error())
	}
	defer pcB.Close()
	if err := pcB.Connect(ctx); err != nil {
		return warn(cat, name, ref, "probe B connect failed: "+err.Error())
	}
	if _, err := probeHelloNonceAs(ctx, pcB, capID); err != nil {
		return warn(cat, name, ref, "probe B hello failed: "+err.Error())
	}

	// Replay A's authenticate on B.
	status, ok := sendAuthAndReadStatus(ctx, pcB, capturedAuth)
	if !ok {
		if baselineOK {
			return pass(cat, name, ref, desc+" rejected (connection closed; baseline holds, so the close is attributable to the replay)")
		}
		return warn(cat, name, ref, desc+" got no decodable response, but the valid-authenticate baseline did not hold — cannot attribute the close")
	}
	if status == 200 {
		return fail(cat, name, ref,
			desc+" was ACCEPTED (status 200) — the issued nonce is not bound per-connection; handshake is replay-vulnerable (F12)")
	}
	return pass(cat, name, ref, fmt.Sprintf("%s rejected (status %d)", desc, status))
}

// probeBaseline confirms a valid hello+authenticate on a fresh connection is
// accepted (status 200). Returns whether the baseline held, plus an
// informative check result.
func probeBaseline(ctx context.Context, addr string) (bool, CheckResult) {
	const cat = catConnectivity
	const name = "handshake_probe_baseline"
	const ref = "V7 §4.6 / F12"

	pc, err := NewPeerClient(addr)
	if err != nil {
		return false, warn(cat, name, ref, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return false, warn(cat, name, ref, "probe connect failed: "+err.Error())
	}
	issuedNonce, err := probeHelloNonce(ctx, pc)
	if err != nil {
		return false, warn(cat, name, ref, "probe hello failed: "+err.Error())
	}
	authEnv, err := protocol.CreateAuthenticateExecute(pc.keypair, issuedNonce)
	if err != nil {
		return false, warn(cat, name, ref, "could not build valid authenticate: "+err.Error())
	}
	status, ok := sendAuthAndReadStatus(ctx, pc, authEnv)
	if ok && status == 200 {
		return true, pass(cat, name, ref, "valid authenticate on a fresh connection accepted (200) — negative probes are attributable")
	}
	if ok {
		return false, warn(cat, name, ref, fmt.Sprintf("valid authenticate returned status %d (expected 200) — connection-close rejections cannot be attributed to the tamper", status))
	}
	return false, warn(cat, name, ref, "valid authenticate on a fresh connection got no decodable response — connection-close rejections cannot be attributed to the tamper")
}

// probeAuthRejected opens a fresh connection, completes the hello leg to learn
// the responder's issued nonce, then sends a tampered authenticate built by
// `build`. An explicit non-200 status is an unambiguous rejection → PASS; an
// explicit 200 is acceptance of a forgery → FAIL. A connection-close with no
// decodable response is only treated as a rejection when `baselineOK` proved a
// valid authenticate succeeds on a fresh connection (so the close is
// attributable to the tamper); otherwise it is inconclusive → WARN.
// helloPeerID selects the peer_id claimed in the probe's hello: empty uses the
// probe client's own keypair (the right choice when the tamper is on the nonce
// or signature); a non-empty value forges the hello peer_id so it matches a
// forged authenticate's peer_id (required for impersonation / binding probes,
// so an impl's hello-consistency check cannot pre-empt the PoP check).
func probeAuthRejected(ctx context.Context, addr string, baselineOK bool, name, ref, helloPeerID, desc string,
	build func(pc *PeerClient, issuedNonce []byte) (entity.Envelope, error)) CheckResult {
	const cat = catConnectivity

	pc, err := NewPeerClient(addr)
	if err != nil {
		return warn(cat, name, ref, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(cat, name, ref, "probe connect failed: "+err.Error())
	}

	issuedNonce, err := probeHelloNonceAs(ctx, pc, helloPeerID)
	if err != nil {
		return warn(cat, name, ref, "probe hello failed: "+err.Error())
	}

	authEnv, err := build(pc, issuedNonce)
	if err != nil {
		return warn(cat, name, ref, "could not build probe authenticate: "+err.Error())
	}

	status, ok := sendAuthAndReadStatus(ctx, pc, authEnv)
	if !ok {
		// No decodable EXECUTE_RESPONSE — connection closed / undecodable.
		if baselineOK {
			return pass(cat, name, ref, desc+" rejected (connection closed; valid authenticate succeeds on a fresh connection, so the close is attributable to the tamper)")
		}
		return warn(cat, name, ref, desc+" got no decodable response, but the valid-authenticate baseline did not hold — cannot attribute the close to proof-of-possession enforcement")
	}
	if status == 200 {
		return fail(cat, name, ref,
			desc+" was ACCEPTED (status 200) — responder performs no proof-of-possession at §4.6; handshake is forgeable/replay-vulnerable (F12)")
	}
	return pass(cat, name, ref, fmt.Sprintf("%s rejected (status %d)", desc, status))
}

// sendAuthAndReadStatus writes an authenticate envelope and reads one response
// frame, returning the EXECUTE_RESPONSE status. ok is false when the write
// fails, the read fails, or the response is not a decodable EXECUTE_RESPONSE
// (connection closed / garbage).
func sendAuthAndReadStatus(ctx context.Context, pc *PeerClient, authEnv entity.Envelope) (status uint, ok bool) {
	if err := pc.writeEnvelope(ctx, authEnv); err != nil {
		return 0, false
	}
	respBytes, err := pc.readFrame(ctx)
	if err != nil {
		return 0, false
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		return 0, false
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return 0, false
	}
	return respData.Status, true
}

// probeHelloNonce runs the hello leg on a fresh probe client (claiming the
// client's own peer_id) and returns the nonce the responder issued.
func probeHelloNonce(ctx context.Context, pc *PeerClient) ([]byte, error) {
	return probeHelloNonceAs(ctx, pc, "")
}

// probeHelloNonceAs runs the hello leg claiming helloPeerID (empty → the
// client's own keypair peer_id) and returns the responder's issued nonce.
func probeHelloNonceAs(ctx context.Context, pc *PeerClient, helloPeerID string) ([]byte, error) {
	var helloEnv entity.Envelope
	var err error
	if helloPeerID == "" {
		helloEnv, _, err = protocol.CreateHelloExecute(pc.keypair, nil)
	} else {
		helloEnv, err = buildHelloExecute(helloPeerID)
	}
	if err != nil {
		return nil, err
	}
	if err := pc.writeEnvelope(ctx, helloEnv); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}
	respBytes, err := pc.readFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("read hello response: %w", err)
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		return nil, fmt.Errorf("decode hello response: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return nil, fmt.Errorf("decode hello response data: %w", err)
	}
	var helloResult entity.Entity
	if err := ecf.Decode(respData.Result, &helloResult); err != nil {
		return nil, fmt.Errorf("decode hello result: %w", err)
	}
	helloData, err := types.HelloDataFromEntity(helloResult)
	if err != nil {
		return nil, fmt.Errorf("decode hello data: %w", err)
	}
	return helloData.Nonce, nil
}

// buildAuthenticateBadSig builds an authenticate envelope that echoes the
// correct nonce and carries a structurally valid signature entity (its own
// content hash is correct, so envelope hash-validation passes), but whose
// signature is computed over the wrong bytes — it cannot verify against the
// claimed public key. This isolates the signature-verification check from
// envelope integrity.
// buildHelloExecute builds an unsigned hello EXECUTE claiming an arbitrary
// peer_id. Leg 1 is pre-auth, so the peer_id is just a claimed string — which
// is exactly the spoofing surface the binding probe exercises. The initiator
// nonce is random; the responder echoes its own issued nonce regardless.
func buildHelloExecute(peerID string) (entity.Envelope, error) {
	initNonce := make([]byte, 32)
	if _, err := rand.Read(initNonce); err != nil {
		return entity.Envelope{}, err
	}
	helloEntity, err := types.HelloData{
		PeerID:    peerID,
		Nonce:     initNonce,
		Protocols: []string{"entity-core/1.0"},
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	paramsRaw, err := ecf.Encode(helloEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	execEntity, err := types.ExecuteData{
		RequestID: "connect-hello",
		URI:       connectURI,
		Operation: "hello",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(execEntity, nil), nil
}

// buildAuthenticateCustom builds an authenticate envelope with an arbitrary
// claimed (peerID, publicKey) signed by signKP, echoing nonce. This lets a
// probe decouple the claimed identity, the presented key, and the signing key
// — to forge impersonation (claim victim's key, sign with attacker's) or
// peer_id↔pubkey mismatch (claim a peer_id that does not derive from the
// presented key). The included identity entity is built to match the claimed
// (peerID, publicKey) so the envelope is otherwise self-consistent.
func buildAuthenticateCustom(peerID string, publicKey []byte, signKP crypto.Keypair, nonce []byte) (entity.Envelope, error) {
	authData := types.AuthenticateData{
		PeerID:    peerID,
		PublicKey: publicKey,
		KeyType:   "ed25519",
		Nonce:     nonce,
	}
	authEntity, err := authData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	_ = peerID // v7.65: peer_id is wire presentation, not part of system/peer hashable basis
	claimedIdentity, err := types.PeerData{
		PublicKey: publicKey,
		KeyType:   "ed25519",
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	signIdentity, err := signKP.IdentityEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	sig := signKP.Sign(authEntity.ContentHash.Bytes())
	sigEntity, err := types.SignatureData{
		Target:    authEntity.ContentHash,
		Signer:    signIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	paramsRaw, err := ecf.Encode(authEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	execEntity, err := types.ExecuteData{
		RequestID: "connect-authenticate",
		URI:       connectURI,
		Operation: "authenticate",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		claimedIdentity.ContentHash: claimedIdentity,
		sigEntity.ContentHash:       sigEntity,
	}), nil
}

func buildAuthenticateBadSig(kp crypto.Keypair, nonce []byte) (entity.Envelope, error) {
	identity, err := kp.IdentityEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	authData := types.AuthenticateData{
		PeerID:    string(kp.PeerID()),
		PublicKey: kp.PublicKeyBytes(),
		KeyType:   "ed25519",
		Nonce:     nonce,
	}
	authEntity, err := authData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	// Sign the WRONG message — a valid Ed25519 signature that does not
	// authenticate the authenticate entity.
	badSig := kp.Sign([]byte("not-the-authenticate-content-hash"))
	sigEntity, err := types.SignatureData{
		Target:    authEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: badSig,
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	paramsRaw, err := ecf.Encode(authEntity)
	if err != nil {
		return entity.Envelope{}, err
	}
	execEntity, err := types.ExecuteData{
		RequestID: "connect-authenticate",
		URI:       connectURI,
		Operation: "authenticate",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		identity.ContentHash:  identity,
		sigEntity.ContentHash: sigEntity,
	}), nil
}
