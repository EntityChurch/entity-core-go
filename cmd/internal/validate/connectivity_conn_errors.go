package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// The ENTITY-CORE-PROTOCOL §4.7 connection-error probe family (G-28 / FM-1g).
//
// §4.7 is a normative MUST-emit contract: for each connect-handshake failure the
// (code, status) pair is fixed across impls. The wire suite covered only a
// fraction of its ten rows; this closes the gap for the rows that are cleanly
// wire-constructible AND on which the spec and the Go impl agree:
//
//   - row 1  incompatible_protocol  / 400  (a hello whose protocols are disjoint from ours)
//   - row 7  authentication_failed / 401  (an authenticate with an invalid signature)
//   - row 8  identity_mismatch     / 401  (authenticate.peer_id not derived from public_key)
//   - row 9  connection_already_established / 409  (a second hello after the handshake completes)
//   - row 10 invalid_request       / 400  (a connect EXECUTE naming an unknown operation —
//            gated pre-handshake AND on an established connection: row 10 is "in any state",
//            and a probe that only dials into one state leaves the clause half-tested cohort-wide)
//   - §4.5  invalid_request       / 400  (a hello carrying an empty protocols set — SA-PY-31 / FM-2e)
//   - CE-1  authentication_failed / 401  (a NON-connect EXECUTE before establishment — §4.2 third
//            pre-authorization rule + §5.2a auth-class; 0.8.2.5 note under §4.7. Was measured three-way
//            then RULED; 403 connection_required / 400 handshake_failed are named non-conformant)
//
// Already covered elsewhere, not duplicated here: row 2 (incompatible_hash_format,
// negotiation.format_disjoint_reject), row 4 (unsupported_key_type,
// format_agility.AGILITY-UNKNOWN-1 + negotiation.keytype_disjoint_reject), row 6
// (invalid_nonce, connect_prehello_authenticate / FM-1).
//
// Rows 1 and 10 moved into the gate 2026-09-01 when arch RULED them (spec-issue
// 2026-09-01-b): row 1 is a live gap all three seats owe (§4.5 pins protocols as
// a non-empty intersection; go now rejects a disjoint hello), and row 10's
// unknown-op input is 400 invalid_request (the sequence-conflict input stays 409;
// PD-1g closed). A cross-impl run may FAIL a sibling that has not yet landed the
// ruling — that FAIL is the owed work, not a contested-semantic artifact.
//
// TWO rows remain DELIBERATELY NOT gated (still §4.7-table-vs-impl discrepancies,
// spec-issue 2026-09-01-b): a wire check on either would test one reading of a
// contested semantic (the standing "a wire check MUST NOT discriminate on an
// unruled/divergent semantic" rule):
//
//   - row 3  incompatible_key_type: RETIRED by arch's ruling (predated §4.5); a
//     disjoint key_types hello is unsupported_key_type (v7.69 §4.5), which go
//     already emits and negotiation.keytype_disjoint_reject already gates.
//   - row 5  unsupported_content_hash_format: not wire-constructible on the connect
//     path (no connect ingest calls DispatchContentHashFormat; the entity builders
//     refuse an unallocated format byte). Covered library-level only
//     (crypto_agility.VARINT-MULTIBYTE-1). Surface scoped to §1.2 ingest.
//
// Scoring uses the FM-1 three-outcome taxonomy: a bare close is a distinct FAIL
// from a wrong (status, code); a setup failure is a WARN, never a false FAIL.

const catConnErrRef = "V7 §4.7"

// connErrOutcome is the observed result of driving a §4.7 failing input.
type connErrOutcome struct {
	status     uint
	code       string
	noResponse bool   // a bare connection close with no EXECUTE_RESPONSE
	warn       string // non-empty ⇒ setup failure, score as WARN
}

// scoreConnErr applies the §4.7 MUST-emit contract to an observed outcome.
func scoreConnErr(name, desc string, wantStatus uint, wantCode string, o connErrOutcome) CheckResult {
	const cat = catConnectivity
	if o.warn != "" {
		return warn(cat, name, catConnErrRef, o.warn)
	}
	if o.noResponse {
		return fail(cat, name, catConnErrRef, "FAIL:no-response — "+desc+
			" got a connection CLOSE with no EXECUTE_RESPONSE frame; §4.7 + §4.6 require the coded error be emitted BEFORE the close. Scored distinctly from wrong-status.")
	}
	if o.status == wantStatus && o.code == wantCode {
		return pass(cat, name, catConnErrRef, fmt.Sprintf("%s rejected with (%d %s) (§4.7 satisfied)", desc, wantStatus, wantCode))
	}
	return fail(cat, name, catConnErrRef, fmt.Sprintf(
		"FAIL:wrong-status — %s got (%d %q); §4.7 pins (%d %s). The (code, status) pair is a normative MUST-emit contract.",
		desc, o.status, o.code, wantStatus, wantCode))
}

// helloLeg opens the transport and sends a valid hello for kp, returning the
// peer-issued nonce. The client is left transport-open with NO background reader
// (manual framing), so the caller drives the authenticate leg with
// writeEnvelope/readFrame directly. On any setup failure it returns a non-nil
// warn.
func helloLeg(ctx context.Context, addr string, kp crypto.Keypair) (pc *PeerClient, peerNonce []byte, warnMsg string) {
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return nil, nil, "could not create probe client: " + err.Error()
	}
	if err := pc.Connect(ctx); err != nil {
		pc.Close()
		return nil, nil, "probe connect failed: " + err.Error()
	}
	helloEnv, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		pc.Close()
		return nil, nil, "could not build hello: " + err.Error()
	}
	if err := pc.writeEnvelope(ctx, helloEnv); err != nil {
		pc.Close()
		return nil, nil, "could not send hello: " + err.Error()
	}
	respBytes, err := pc.readFrame(ctx)
	if err != nil {
		pc.Close()
		return nil, nil, "hello got no response: " + err.Error()
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		pc.Close()
		return nil, nil, "could not decode hello response: " + err.Error()
	}
	status, _, respData, err := extractStatusAndCode(respEnv)
	if err != nil {
		pc.Close()
		return nil, nil, "could not decode hello response status: " + err.Error()
	}
	if status != 200 {
		pc.Close()
		return nil, nil, fmt.Sprintf("hello was not accepted (status %d) — cannot reach the authenticate step", status)
	}
	var helloResult entity.Entity
	if err := ecf.Decode(respData.Result, &helloResult); err != nil {
		pc.Close()
		return nil, nil, "could not decode hello result: " + err.Error()
	}
	helloResultData, err := types.HelloDataFromEntity(helloResult)
	if err != nil {
		pc.Close()
		return nil, nil, "could not decode hello result data: " + err.Error()
	}
	return pc, helloResultData.Nonce, ""
}

// sendConnectAndRead writes a connect-op envelope and reads one response frame,
// returning the observed outcome (noResponse on a bare close).
func sendConnectAndRead(ctx context.Context, pc *PeerClient, env entity.Envelope) connErrOutcome {
	if err := pc.writeEnvelope(ctx, env); err != nil {
		return connErrOutcome{warn: "could not send frame: " + err.Error()}
	}
	respBytes, err := pc.readFrame(ctx)
	if err != nil {
		return connErrOutcome{noResponse: true}
	}
	var respEnv entity.Envelope
	if err := ecf.Decode(respBytes, &respEnv); err != nil {
		return connErrOutcome{warn: "could not decode response envelope: " + err.Error()}
	}
	status, code, _, err := extractStatusAndCode(respEnv)
	if err != nil {
		return connErrOutcome{warn: "could not decode response status/code: " + err.Error()}
	}
	return connErrOutcome{status: status, code: code}
}

// buildAuthenticateEnvelope hand-assembles an authenticate envelope for the
// given fields, signing authData's content hash with signKP. Mirrors
// core/protocol.CreateAuthenticateExecute's shape (identity + signature +
// authenticate in the included set) so the ONLY thing a probe varies is the
// field it means to make hostile. corruptSig flips the first signature byte
// (an invalid but present signature).
func buildAuthenticateEnvelope(authData types.AuthenticateData, identity entity.Entity, signKP crypto.Keypair, corruptSig bool) (entity.Envelope, error) {
	authEnt, err := authData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	sig := signKP.Sign(authEnt.ContentHash.Bytes())
	if corruptSig && len(sig) > 0 {
		sig[0] ^= 0xFF
	}
	sigData := types.SignatureData{
		Target:    authEnt.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: crypto.KeyTypeStringEd25519,
		Signature: sig,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	authParamsRaw, err := ecf.Encode(authEnt)
	if err != nil {
		return entity.Envelope{}, err
	}
	authExecEnt, err := types.ExecuteData{
		RequestID: "connect-error-authenticate",
		URI:       connectURI,
		Operation: "authenticate",
		Params:    cbor.RawMessage(authParamsRaw),
	}.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	return entity.NewEnvelope(authExecEnt, map[hash.Hash]entity.Entity{
		identity.ContentHash: identity,
		sigEnt.ContentHash:   sigEnt,
		authEnt.ContentHash:  authEnt,
	}), nil
}

// probeAuthenticateBadSignature — §4.7 row 7. A valid hello, then an
// authenticate whose signature does not verify → 401 authentication_failed.
// The signature is present but corrupted, so the responder reaches and fails
// the §4.6 step-2 verification rather than short-circuiting on an absent one.
func probeAuthenticateBadSignature(ctx context.Context, addr string) CheckResult {
	const name = "connect_authenticate_bad_signature"
	const desc = "an authenticate with an invalid (non-verifying) signature"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp)
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	identity, err := kp.IdentityEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "identity entity: "+err.Error())
	}
	authData := types.AuthenticateData{
		PeerID:    string(kp.PeerID()),
		PublicKey: kp.PublicKeyBytes(),
		KeyType:   crypto.KeyTypeStringEd25519,
		Nonce:     peerNonce,
	}
	env, err := buildAuthenticateEnvelope(authData, identity, kp, true /* corrupt the signature */)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build authenticate: "+err.Error())
	}
	return scoreConnErr(name, desc, 401, "authentication_failed", sendConnectAndRead(ctx, pc, env))
}

// probeAuthenticateIdentityMismatch — §4.7 row 8. A valid hello, then an
// authenticate that is SIGNED with `other` and PRESENTS `other`'s public_key,
// but CLAIMS `kp`'s peer_id. The claimed peer_id is a valid Ed25519-prefixed id,
// so the §4.6 step-0 key-type gate clears; the signature verifies against the
// presented public_key, so step 2 (signature verification) passes on its own
// terms; only the step-3 binding — `peer_id` derived from `public_key` — fails,
// because kp's id is not derived from other's key → 401 identity_mismatch.
//
// This input isolates step 3 under EITHER handshake ordering: a peer that runs
// the numbered steps (signature before the identity binding) passes step 2 and
// rejects at step 3, and a peer that runs the identity binding first rejects
// there — both land on identity_mismatch. The earlier form of this probe signed
// with `kp` while presenting `other`'s key, which fails step 2 under the numbered
// order (a signature by kp does not verify against other's key) and so
// discriminated CHECK ORDER — a freedom §4.6 pins only as "0 before 3" (rust
// 411bee4, py; ordering routed to arch, docs/validation/spec-issues/2026-09-01-c).
func probeAuthenticateIdentityMismatch(ctx context.Context, addr string) CheckResult {
	const name = "connect_authenticate_identity_mismatch"
	const desc = "an authenticate whose peer_id is not derived from its (validly-signed) public_key"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	other, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate second keypair: "+err.Error())
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp)
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	// The signer is `other`, so the identity entity that carries the signer must
	// be other's too — the signature verifies against the presented public_key
	// (other's) and step 2 passes on its own terms. The authenticate CLAIMS kp's
	// peer_id, which does not derive from other's key → the step-3 binding fails.
	otherIdentity, err := other.IdentityEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "identity entity: "+err.Error())
	}
	authData := types.AuthenticateData{
		PeerID:    string(kp.PeerID()),
		PublicKey: other.PublicKeyBytes(),
		KeyType:   crypto.KeyTypeStringEd25519,
		Nonce:     peerNonce,
	}
	env, err := buildAuthenticateEnvelope(authData, otherIdentity, other, false)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build authenticate: "+err.Error())
	}
	return scoreConnErr(name, desc, 401, "identity_mismatch", sendConnectAndRead(ctx, pc, env))
}

// probeSecondHelloAfterEstablished — §4.7 row 9. Complete a full valid handshake
// (hello + valid authenticate), then send a SECOND hello on the established
// connection → 409 connection_already_established. A second authenticate is NOT
// used: §4.6/RT-6 special-cases it to 401 invalid_nonce, which is a different row.
func probeSecondHelloAfterEstablished(ctx context.Context, addr string) CheckResult {
	const name = "connect_second_hello_after_established"
	const desc = "a second hello after the handshake has completed"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp)
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	// Complete the handshake with a VALID authenticate.
	authEnv, err := protocol.CreateAuthenticateExecute(kp, peerNonce)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build authenticate: "+err.Error())
	}
	authOut := sendConnectAndRead(ctx, pc, authEnv)
	if authOut.warn != "" {
		return warn(catConnectivity, name, catConnErrRef, "authenticate leg: "+authOut.warn)
	}
	if authOut.noResponse {
		return warn(catConnectivity, name, catConnErrRef, "authenticate leg got a bare close — cannot reach the established state this row needs")
	}
	if authOut.status != 200 {
		return warn(catConnectivity, name, catConnErrRef, fmt.Sprintf("handshake did not complete (authenticate %d %s) — cannot test the post-established path", authOut.status, authOut.code))
	}
	// Established. A second hello MUST be refused as already-established.
	secondHello, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build second hello: "+err.Error())
	}
	return scoreConnErr(name, desc, 409, "connection_already_established", sendConnectAndRead(ctx, pc, secondHello))
}

// probeIncompatibleProtocol — §4.7 row 1. A hello advertising ONLY a protocol
// version the responder does not speak (entity-core/99.0) → 400
// incompatible_protocol. §4.5 pins protocols as a non-empty intersection, so a
// peer that completes this handshake speaks no version in common (ruled
// 2026-09-01: the row is a live gap, not aspirational). No authenticate leg —
// the reject is at hello. A conformant peer that does not yet implement the
// check completes the hello at 200 and FAILs this row; that FAIL is the owed
// work (all three seats), not a probe artifact.
func probeIncompatibleProtocol(ctx context.Context, addr string) CheckResult {
	const name = "connect_incompatible_protocol"
	const desc = "a hello advertising only an unsupported protocol version"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(catConnectivity, name, catConnErrRef, "probe connect failed: "+err.Error())
	}
	helloEnv, _, err := protocol.CreateHelloExecute(kp, []string{"entity-core/99.0"})
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build hello: "+err.Error())
	}
	return scoreConnErr(name, desc, 400, "incompatible_protocol", sendConnectAndRead(ctx, pc, helloEnv))
}

// probeUnknownConnectOperation — §4.7 row 10. A connect EXECUTE naming an
// operation that is not hello/authenticate/ping → 400 invalid_request (ruled
// 2026-09-01, closes PD-1g): an unknown op is a malformed request, distinct from
// the 409 state-conflict rows. No hello leg needed — the unknown-op reject is at
// the top of the connect branch, ahead of any sequence check.
func probeUnknownConnectOperation(ctx context.Context, addr string) CheckResult {
	const name = "connect_unknown_operation"
	const desc = "a connect EXECUTE naming an unknown operation"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(catConnectivity, name, catConnErrRef, "probe connect failed: "+err.Error())
	}
	execEnt, err := types.ExecuteData{
		RequestID: "connect-error-unknown-op",
		URI:       connectURI,
		Operation: "frobnicate",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build execute: "+err.Error())
	}
	return scoreConnErr(name, desc, 400, "invalid_request", sendConnectAndRead(ctx, pc, entity.NewEnvelope(execEnt, nil)))
}

// probeUnknownConnectOperationEstablished — §4.7 row 10, the "in any state" arm.
// The pre-handshake probe above reaches row 10 only on a FRESH connection, and a
// conformance probe DIALS IN, so by construction every seat exercises row 10 in
// exactly one state and the "in any state" half of the clause goes untested across
// the whole cohort — no cross-impl run can catch a regression on the established
// side (routed by entity-core-py, ROUTING-2026-09-02-b, after they found their own
// established boundary answered an unknown op with 409 for the connection's STATE
// when the defect was the operation's NAME). go classifies correctly today
// (execute.go: the unknown-op switch runs AHEAD of the Completed/state branch), so
// this gates that ordering against regression rather than reporting a defect.
//
// Drive the established side: complete a full handshake, then send an unknown
// connect op → still 400 invalid_request. TEETH CONTROL, in-probe: a hello on the
// SAME established connection MUST return 409 connection_already_established
// (row 9). Two regressions this discriminates — (i) the unknown-op switch moved
// BELOW the state branch → the unknown op returns 409, scored directly as a FAIL;
// (ii) the whole established branch degenerates to 400 → the control hello also
// returns 400, so the check WARNs (unattributable) rather than falsely PASSing, and
// connect_second_hello_after_established (row 9) owns that FAIL. A hostile-input
// check whose valid-input control is not asserted is a candidate false-pass
// (carry-the-teeth).
func probeUnknownConnectOperationEstablished(ctx context.Context, addr string) CheckResult {
	const name = "connect_unknown_operation_established"
	const desc = "an unknown connect operation on an ESTABLISHED connection"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp)
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	// Complete the handshake with a VALID authenticate → established.
	authEnv, err := protocol.CreateAuthenticateExecute(kp, peerNonce)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build authenticate: "+err.Error())
	}
	authOut := sendConnectAndRead(ctx, pc, authEnv)
	if authOut.warn != "" {
		return warn(catConnectivity, name, catConnErrRef, "authenticate leg: "+authOut.warn)
	}
	if authOut.noResponse {
		return warn(catConnectivity, name, catConnErrRef, "authenticate leg got a bare close — cannot reach the established state this row needs")
	}
	if authOut.status != 200 {
		return warn(catConnectivity, name, catConnErrRef, fmt.Sprintf("handshake did not complete (authenticate %d %s) — cannot test the established path", authOut.status, authOut.code))
	}
	// Input under test: an unknown connect op on the established connection.
	unknownEnt, err := types.ExecuteData{
		RequestID: "connect-error-unknown-op-established",
		URI:       connectURI,
		Operation: "frobnicate",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build execute: "+err.Error())
	}
	unknownOut := sendConnectAndRead(ctx, pc, entity.NewEnvelope(unknownEnt, nil))
	// Teeth control: a hello on the SAME established connection must discriminate
	// state from name — 409 connection_already_established. If it does not, the
	// established branch is degenerate and the unknown-op result is unattributable.
	secondHello, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build control hello: "+err.Error())
	}
	ctrl := sendConnectAndRead(ctx, pc, secondHello)
	if ctrl.warn != "" || ctrl.noResponse || ctrl.status != 409 || ctrl.code != "connection_already_established" {
		return warn(catConnectivity, name, catConnErrRef, fmt.Sprintf(
			"control did not hold — a hello on the established connection returned (%d %q), want (409 connection_already_established); the established branch does not discriminate operation-name from state, so the unknown-op result is unattributable. connect_second_hello_after_established (row 9) owns that FAIL.",
			ctrl.status, ctrl.code))
	}
	return scoreConnErr(name, desc, 400, "invalid_request", unknownOut)
}

// pingServedOnceEstablished completes a full handshake on a fresh connection and
// sends a §5.1 keepalive ping, reporting whether the peer answers 200. It is the
// APPLICABILITY control for the pre-hello-ping row: the "implemented op, forbidden
// state → 409" discrimination holds ONLY for a peer that implements ping; a peer
// that does not answers a pre-hello ping with row 10's 400 invalid_request and is
// conformant in doing so. keepalive_ping_pong is the §5.1/§12.1 conformance check
// for the pong shape, but it skips under --profile core, so it cannot back this row
// there — hence a self-contained control. Returns a warn on any setup failure.
func pingServedOnceEstablished(ctx context.Context, addr string) (served bool, warnMsg string) {
	kp, err := crypto.Generate()
	if err != nil {
		return false, "generate keypair: " + err.Error()
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp)
	if w != "" {
		return false, w
	}
	defer pc.Close()
	authEnv, err := protocol.CreateAuthenticateExecute(kp, peerNonce)
	if err != nil {
		return false, "build authenticate: " + err.Error()
	}
	authOut := sendConnectAndRead(ctx, pc, authEnv)
	if authOut.warn != "" {
		return false, "authenticate leg: " + authOut.warn
	}
	if authOut.noResponse || authOut.status != 200 {
		return false, fmt.Sprintf("handshake did not complete (authenticate %d %s)", authOut.status, authOut.code)
	}
	pingEnt, err := types.PingData{Timestamp: 1, Sequence: 1}.ToEntity()
	if err != nil {
		return false, "build ping params: " + err.Error()
	}
	pingParamsRaw, err := ecf.Encode(pingEnt)
	if err != nil {
		return false, "encode ping params: " + err.Error()
	}
	pingExec, err := types.ExecuteData{
		RequestID: "connect-ping-served-control",
		URI:       connectURI,
		Operation: "ping",
		Params:    cbor.RawMessage(pingParamsRaw),
	}.ToEntity()
	if err != nil {
		return false, "build ping execute: " + err.Error()
	}
	out := sendConnectAndRead(ctx, pc, entity.NewEnvelope(pingExec, nil))
	if out.warn != "" {
		return false, "ping control: " + out.warn
	}
	return out.status == 200, ""
}

// probeAbsentProtocols — §4.5 SA-PY-31 / FM-2e, folded into ENTITY-CORE-PROTOCOL
// 0.8.2.4. A hello whose protocols set is EMPTY (or absent) is a malformed
// request → 400 invalid_request, NOT incompatible_protocol: a peer that names no
// version has made no incompatible-VERSION claim (arch's row-10 argument, one row
// up). arch ruled reading 2 here (over the reading-1 go/py first shipped),
// because keystone's csharp/typescript peers already require the field and pass
// conformance. The probe sends an otherwise-valid hello — valid Ed25519 peer_id,
// default hash_formats/key_types — carrying only an empty protocols list, so the
// refusal is isolated to the empty-set guard (which sits ahead of the
// hash_formats/key_types checks in handleHello). A conformant peer that has not
// yet landed FM-2e completes the hello at 200 (reading 1) and FAILs this row;
// that FAIL is the owed work (rust + py), not a probe artifact.
func probeAbsentProtocols(ctx context.Context, addr string) CheckResult {
	const name = "connect_absent_protocols"
	const desc = "a hello carrying an empty protocols set"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(catConnectivity, name, catConnErrRef, "probe connect failed: "+err.Error())
	}
	helloEnt, err := types.HelloData{
		PeerID:      string(kp.PeerID()),
		Nonce:       make([]byte, 32),
		Protocols:   []string{}, // the input under test
		HashFormats: protocol.DefaultAdvertisedHashFormats(),
		KeyTypes:    protocol.DefaultAdvertisedKeyTypes(),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build hello: "+err.Error())
	}
	paramsRaw, err := ecf.Encode(helloEnt)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not encode hello: "+err.Error())
	}
	execEnt, err := types.ExecuteData{
		RequestID: "connect-error-absent-protocols",
		URI:       connectURI,
		Operation: "hello",
		Params:    cbor.RawMessage(paramsRaw),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build execute: "+err.Error())
	}
	return scoreConnErr(name, desc, 400, "invalid_request", sendConnectAndRead(ctx, pc, entity.NewEnvelope(execEnt, nil)))
}

// probeSecondHelloMidHandshake — §4.7 out-of-order row (0.8.2.4). A valid hello
// (connection now mid-handshake, awaiting authenticate), then a SECOND hello on
// the same connection → 409 connection_sequence_error: an operation the responder
// implements, arriving in a state that forbids it. This is §4.7's own worked
// example ("a second hello after hello_done"). Distinct from
// connect_second_hello_after_established (row 9, post-completion → 409
// connection_already_established): this fires BEFORE authenticate. Unambiguous —
// hello is implemented by definition, so a non-conformant peer scores a re-issued
// nonce at 200 (routed as owed work, ROUTING-2026-09-02-f), never a different code.
func probeSecondHelloMidHandshake(ctx context.Context, addr string) CheckResult {
	const name = "connect_second_hello_mid_handshake"
	const desc = "a second hello mid-handshake (before authenticate)"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, _, w := helloLeg(ctx, addr, kp) // first hello -> awaiting_authenticate
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	secondHello, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build second hello: "+err.Error())
	}
	return scoreConnErr(name, desc, 409, "connection_sequence_error", sendConnectAndRead(ctx, pc, secondHello))
}

// probePingBeforeHello — §4.7 out-of-order row (0.8.2.4). A well-formed ping as
// the FIRST connect frame, before any hello → 409 connection_sequence_error: ping
// is an operation the responder implements, arriving in a state (pre-handshake)
// that forbids it. (go previously answered 403 connection_required, a code in no
// spec.) CAVEAT: this discriminates "implemented op, forbidden state" only for a
// peer that implements ping; a peer that does not would answer row 10's 400
// invalid_request and look like a different failure — so a FAIL here is read
// alongside whether the peer serves ping at all (connect_second_hello_mid_handshake
// is the unambiguous sibling probe for this row). That caveat is now an ASSERTED
// control rather than prose: pingServedOnceEstablished runs first, and a peer that
// does not serve ping SKIPs this row (its 400 is conformant) instead of the 409
// assertion quietly failing a peer that never claimed to answer ping. So if §5.1
// keepalive ever leaves this peer, the control fails first (candidate discipline,
// entity-core-py ROUTING-2026-09-02-b).
func probePingBeforeHello(ctx context.Context, addr string) CheckResult {
	const name = "connect_ping_before_hello"
	const desc = "a ping sent before any hello (pre-handshake)"
	// Applicability control: the "implemented op, forbidden state → 409"
	// discrimination holds only for a peer that serves ping. If it does not, a
	// pre-hello ping is row 10's unknown-op 400 and this row does not apply.
	served, cw := pingServedOnceEstablished(ctx, addr)
	if cw != "" {
		return warn(catConnectivity, name, catConnErrRef, "ping-served control: "+cw)
	}
	if !served {
		return skip(catConnectivity, name, catConnErrRef,
			"peer does not serve §5.1 ping once established, so a pre-hello ping is an UNKNOWN operation to it → row 10's 400 invalid_request, not the 409 this row asserts; the 'implemented op, forbidden state' discrimination does not apply.")
	}
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(catConnectivity, name, catConnErrRef, "probe connect failed: "+err.Error())
	}
	pingEnt, err := types.PingData{Timestamp: 1, Sequence: 1}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build ping params: "+err.Error())
	}
	pingParamsRaw, err := ecf.Encode(pingEnt)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "encode ping params: "+err.Error())
	}
	execEnt, err := types.ExecuteData{
		RequestID: "connect-error-ping-prehello",
		URI:       connectURI,
		Operation: "ping",
		Params:    cbor.RawMessage(pingParamsRaw),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build ping execute: "+err.Error())
	}
	return scoreConnErr(name, desc, 409, "connection_sequence_error", sendConnectAndRead(ctx, pc, entity.NewEnvelope(execEnt, nil)))
}

// probeAuthenticatePeerIDMismatchHello — §4.6 "MUST also verify
// authenticate.peer_id == hello.peer_id" → 401 identity_mismatch. A valid hello
// for kp, then a FULLY-VALID authenticate for `other` (peer_id, public_key and
// signature all internally consistent for other, correct nonce — steps 0–3 all
// pass on their own terms), but other's peer_id ≠ the hello's kp. Distinct from
// connect_authenticate_identity_mismatch (step 3, peer_id not derived from the
// presented key): a peer that binds the key to its own id but does NOT check the
// hello/authenticate equality PASSES that probe and completes THIS one at 200 —
// the cross-frame identity switch the "MUST also" clause exists to close.
func probeAuthenticatePeerIDMismatchHello(ctx context.Context, addr string) CheckResult {
	const name = "connect_authenticate_peer_id_mismatch_hello"
	const desc = "an authenticate whose (valid) peer_id differs from the hello's peer_id"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	other, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate second keypair: "+err.Error())
	}
	pc, peerNonce, w := helloLeg(ctx, addr, kp) // hello.peer_id = kp
	if w != "" {
		return warn(catConnectivity, name, catConnErrRef, w)
	}
	defer pc.Close()
	// A fully-valid authenticate for `other`: its peer_id derives from its own
	// key and its signature verifies, so steps 0–3 pass — only the cross-frame
	// equality (other ≠ kp) fails.
	otherIdentity, err := other.IdentityEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "identity entity: "+err.Error())
	}
	authData := types.AuthenticateData{
		PeerID:    string(other.PeerID()),
		PublicKey: other.PublicKeyBytes(),
		KeyType:   crypto.KeyTypeStringEd25519,
		Nonce:     peerNonce,
	}
	env, err := buildAuthenticateEnvelope(authData, otherIdentity, other, false)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "build authenticate: "+err.Error())
	}
	return scoreConnErr(name, desc, 401, "identity_mismatch", sendConnectAndRead(ctx, pc, env))
}

// probeExecuteBeforeEstablished — CE-1, RULED (arch ROUTING-2026-09-02-h;
// ENTITY-CORE-PROTOCOL 0.8.2.5 note under §4.7). A non-connect EXECUTE arriving
// before the handshake completes carries no verified signer, so §4.2's third
// pre-authorization rule + §5.2a's discriminator make it AUTH-class → 401
// authentication_failed. Ruled at 0.8.1 (F32 retired the blanket 403 this bullet
// once said); the 0.8.2.5 note restates it because §4.7 — the table an implementer
// reads for this surface — had no row and the rule lives in pre-authorization
// vocabulary. The note NAMES connection_required (go's old code) and handshake_failed
// (rust's) non-conformant. This probe measured the three-way divergence that surfaced
// the two-release-old gap; now that it is ruled it ASSERTS the pair.
//
// The EXECUTE targets the responder's OWN namespace (peer-relative system/tree), so
// the only ground for refusal is the un-established connection — not a foreign
// peer_id (§1.4/§9.1, which is 400 invalid_request) and not a malformed request:
// the non-connect auth gate fires ahead of handler resolution. A conformant peer
// that has not yet landed the ruling FAILs here (rust still 400 handshake_failed, py
// still 403 capability_denied as of 2026-09-02) — that FAIL is the owed work
// (arch's relay -h §5/§6), not a probe artifact.
func probeExecuteBeforeEstablished(ctx context.Context, addr string) CheckResult {
	const name = "execute_before_established_refused"
	const desc = "a non-connect EXECUTE (system/tree:get) before the handshake completes"
	kp, err := crypto.Generate()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "generate keypair: "+err.Error())
	}
	pc, err := NewPeerClientWithKeypair(addr, kp)
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not create probe client: "+err.Error())
	}
	defer pc.Close()
	if err := pc.Connect(ctx); err != nil {
		return warn(catConnectivity, name, catConnErrRef, "probe connect failed: "+err.Error())
	}
	execEnt, err := types.ExecuteData{
		RequestID: "execute-before-established",
		URI:       "system/tree",
		Operation: "get",
		Params:    cbor.RawMessage(nil),
	}.ToEntity()
	if err != nil {
		return warn(catConnectivity, name, catConnErrRef, "could not build execute: "+err.Error())
	}
	return scoreConnErr(name, desc, 401, "authentication_failed", sendConnectAndRead(ctx, pc, entity.NewEnvelope(execEnt, nil)))
}

// runConnectErrorChecks drives the §4.7 rows this suite gates on the wire.
func runConnectErrorChecks(ctx context.Context, addr string) []CheckResult {
	return []CheckResult{
		probeAuthenticateBadSignature(ctx, addr),
		probeAuthenticateIdentityMismatch(ctx, addr),
		probeSecondHelloAfterEstablished(ctx, addr),
		probeIncompatibleProtocol(ctx, addr),
		probeUnknownConnectOperation(ctx, addr),
		probeUnknownConnectOperationEstablished(ctx, addr),
		probeAbsentProtocols(ctx, addr),
		probeSecondHelloMidHandshake(ctx, addr),
		probePingBeforeHello(ctx, addr),
		probeAuthenticatePeerIDMismatchHello(ctx, addr),
		probeExecuteBeforeEstablished(ctx, addr),
	}
}
