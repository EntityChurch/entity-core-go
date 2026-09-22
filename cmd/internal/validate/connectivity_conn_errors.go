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
//   - row 7  authentication_failed / 401  (an authenticate with an invalid signature)
//   - row 8  identity_mismatch     / 401  (authenticate.peer_id not derived from public_key)
//   - row 9  connection_already_established / 409  (a second hello after the handshake completes)
//
// Already covered elsewhere, not duplicated here: row 2 (incompatible_hash_format,
// negotiation.format_disjoint_reject), row 4 (unsupported_key_type,
// format_agility.AGILITY-UNKNOWN-1 + negotiation.keytype_disjoint_reject), row 6
// (invalid_nonce, connect_prehello_authenticate / FM-1).
//
// FOUR rows are DELIBERATELY NOT gated on the wire, each a §4.7-table-vs-impl
// discrepancy routed as spec-issue 2026-09-01-b rather than shipped as a check.
// A wire check discriminating on any of them would test one reading of a
// contested semantic, not the spec (the standing "a wire check MUST NOT
// discriminate on an unruled/divergent semantic" rule):
//
//   - row 1  incompatible_protocol: the Go responder never validates the hello's
//     protocol version — the code is emitted nowhere in the tree. A probe would
//     get 200, not 400. The row has no defined trigger while entity-core/1.0 is
//     the only version.
//   - row 3  incompatible_key_type: for a disjoint key_types hello the Go peer
//     emits unsupported_key_type (v7.69 §4.5), not the table's incompatible_key_type.
//     The two spec surfaces disagree on the code.
//   - row 5  unsupported_content_hash_format: not wire-constructible on the connect
//     path (no connect ingest calls DispatchContentHashFormat; the entity builders
//     refuse an unallocated format byte). Covered library-level only
//     (crypto_agility.VARINT-MULTIBYTE-1).
//   - row 10 connection_sequence_error: the Go peer emits status 409, the §4.7
//     table pins 400 (the code matches).
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

// runConnectErrorChecks drives the §4.7 rows this suite gates on the wire.
func runConnectErrorChecks(ctx context.Context, addr string) []CheckResult {
	return []CheckResult{
		probeAuthenticateBadSignature(ctx, addr),
		probeAuthenticateIdentityMismatch(ctx, addr),
		probeSecondHelloAfterEstablished(ctx, addr),
	}
}
