// Validator-side §7a wire probes.
//
// GUIDE-CONFORMANCE §7a defines two test handlers (system/validate/echo +
// system/validate/dispatch-outbound) the target peer exposes behind its
// --validate opt-in. The validator drives them black-box:
//
//   - §7a echo:               validator → target(echo) → assert verbatim
//   - §7a dispatch-outbound:  validator → target(dispatch) → target reentries
//                              EXECUTE → validator(echo) over the SAME
//                              connection → response round-trips
//
// The reentry leg makes the validator play B-role on the inbound side of
// the connection it dialed out on — that is the §6.11 reentry surface
// (the substantive finding behind A-013). The validator therefore needs
// a minimal echo handler armed in its background reader for the
// dispatch-outbound probe; when armed, the bg reader serves the inbound
// EXECUTE and writes back an EXECUTE_RESPONSE.
//
// Cap-passing convention (§7a.2a, Go ruling — shape (a) in-band params): the
// reentry-authority entities travel in-band, nested in the dispatch-outbound
// EXECUTE's params (reentry_capability / reentry_granters /
// reentry_cap_signatures — the granter/signature carriers plural per 0.8.2.19
// §7a.1). NOT via envelope `included`. See the V7.74-A013 Go cap-passing ruling.

package validate

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/conformance"

	"github.com/fxamacker/cbor/v2"
)

// reentryEchoState is the validator-side echo handler armed for the
// duration of a §7a.2a dispatch-outbound probe. Detection is by URI +
// operation match (system/validate/echo:echo); the body is verbatim
// passthrough of req.Params into respData.Result.
//
// Hits is incremented every time the bg reader services a matching
// inbound EXECUTE — the probe reads it to assert exactly-one reentry.
type reentryEchoState struct {
	hits atomic.Int32
}

// ArmReentryEcho installs the validator-side B-role echo handler. The
// bg reader will service inbound system/validate/echo EXECUTEs on the
// same connection until DisarmReentryEcho is called. Returns the
// armed state so the caller can read hit count.
//
// Idempotent: re-arming resets the hit counter.
func (c *PeerClient) ArmReentryEcho() *reentryEchoState {
	st := &reentryEchoState{}
	c.reentryEcho = st
	return st
}

// DisarmReentryEcho removes the validator-side echo handler. The bg
// reader returns to drain-and-skip behavior for inbound EXECUTEs.
func (c *PeerClient) DisarmReentryEcho() { c.reentryEcho = nil }

// Hits reports how many inbound system/validate/echo EXECUTEs the bg
// reader serviced since the state was armed.
func (s *reentryEchoState) Hits() int32 {
	if s == nil {
		return 0
	}
	return s.hits.Load()
}

// handleReentryEcho is the bg reader's per-frame hook. Returns true
// when the frame matched the armed echo handler and the response was
// (best-effort) written back; the caller skips the drain log line.
//
// Failure modes (decode, write) are non-fatal here — the bg reader has
// no error channel to surface them on, and a failed reentry-response
// shows up as a probe-side timeout regardless. We log under -verbose.
func (c *PeerClient) handleReentryEcho(env entity.Envelope) bool {
	st := c.reentryEcho
	if st == nil {
		return false
	}
	execData, err := types.ExecuteDataFromEntity(env.Root)
	if err != nil {
		return false
	}
	// Match URI + operation. The URI is normally entity://<validator-peer-id>/system/validate/echo
	// but we accept any URI whose handler path is system/validate/echo so
	// peer-id rewrites don't desync the match.
	//
	// We serve TWO operations verbatim: "echo" (the §7a.2a reentry contract)
	// and reentryOutOfScopeOp (the F63 discriminator's out-of-scope operation).
	// The second exists so the compose-vs-bypass mutation is genuine: a peer
	// whose credential path bypasses the narrow handler grant would reach THIS
	// handler and get a 200 — the refusal under test is only meaningful if the
	// bypassed dispatch would otherwise succeed (carry-the-teeth). A conformant
	// target refuses the out-of-scope op before reentry, so this handler is
	// never contacted for it and the hit counter stays where the discriminator
	// expects.
	handlerPath := entity.ExtractHandlerPath(execData.URI)
	if handlerPath != conformance.PatternEcho ||
		(execData.Operation != "echo" && execData.Operation != reentryOutOfScopeOp) {
		return false
	}

	st.hits.Add(1)

	// Build EXECUTE_RESPONSE. Per §7a.1 the echo contract is verbatim —
	// the result entity IS the params entity. ExecuteResponseData.Result
	// is cbor.RawMessage of the ECF-encoded result entity; execData.Params
	// is already the same encoding of the params entity, so we copy it
	// through unchanged.
	respData := types.ExecuteResponseData{
		RequestID: execData.RequestID,
		Status:    200,
		Result:    execData.Params,
	}
	respEnt, err := respData.ToEntity()
	if err != nil {
		if c.verbose {
			fmt.Fprintf(progressOut, "  [reentry-echo] build response entity: %v\n", err)
		}
		return true
	}
	respEnv := entity.Envelope{Root: respEnt}

	// Best-effort write. The bg reader runs without a request context;
	// use a short deadline so a stuck socket doesn't park this goroutine
	// indefinitely.
	wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.writeEnvelope(wctx, respEnv); err != nil {
		if c.verbose {
			fmt.Fprintf(progressOut, "  [reentry-echo] write response: %v\n", err)
		}
		return true
	}
	if c.verbose {
		fmt.Fprintf(progressOut, "  [reentry-echo] served inbound %s:%s request_id=%s\n",
			handlerPath, execData.Operation, execData.RequestID)
	}
	return true
}

// MintReentryCapability mints a validator-rooted capability granting
// the target peer the right to dispatch system/validate/echo:echo back
// at the validator. Used by the §7a.2a dispatch-outbound probe — the
// three returned entities (cap, granter, sig) ride in-band in the
// dispatch-outbound EXECUTE's params per the Go cap-passing ruling.
//
// Shape mirrors CreateDeliveryToken (B-rooted child cap, parent=
// connection grant): granter=validator identity, grantee=target peer
// identity, parent=connection cap, scoped to system/validate/echo:echo.
// 5-minute TTL.
func (c *PeerClient) MintReentryCapability() (cap, granter, sig entity.Entity, err error) {
	return c.mintReentryCapForOps([]string{"echo"})
}

// reentryOutOfScopeOp is the operation the F63 wire discriminator sub-dispatches
// to prove the narrow-grant refusal. It is deliberately NOT in the
// dispatch-outbound handler's declared InternalScope (which is echo-only), so a
// conformant target refuses it on Dimension 1 even when a covering credential is
// presented. The validator's own B-role echo handler answers it verbatim, so the
// bypass mutation (credential authorizes alone) reaches a 200 rather than a 404.
const reentryOutOfScopeOp = "reentry-oos-probe"

// mintReentryCapForOps mints a validator-rooted, single-sig capability granting
// the target peer the given operation set on system/validate/echo, granted to
// the target, rooted at (and signed by) the validator. The chain ROOT granter is
// the validator = the reentry sub-dispatch TARGET, so presentedAuthorizes reads
// it as target-minted and it relaxes Dimension 4 (§5.2/§6.8 E1).
func (c *PeerClient) mintReentryCapForOps(ops []string) (cap, granter, sig entity.Entity, err error) {
	if c.identityEntity.ContentHash.IsZero() {
		return entity.Entity{}, entity.Entity{}, entity.Entity{},
			fmt.Errorf("validator identity not initialized")
	}
	if c.remotePeerIdentityHash.IsZero() {
		return entity.Entity{}, entity.Entity{}, entity.Entity{},
			fmt.Errorf("target peer identity not known (handshake incomplete?)")
	}

	now := uint64(time.Now().UnixMilli())
	expiresMs := now + uint64((5 * time.Minute).Milliseconds())

	// The validator owns the resource (`system/validate/echo`) at its
	// peer-id; the cap grants the target the right to invoke it. Scope:
	// handler = system/validate/echo, operation = echo, resource = the
	// validator-rooted absolute path.
	resourcePath := fmt.Sprintf("/%s/%s", c.identityPeerIDString(), conformance.PatternEcho)
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{conformance.PatternEcho}},
				Operations: types.CapabilityScope{Include: ops},
				Resources:  types.CapabilityScope{Include: []string{resourcePath}},
			},
		},
		Granter:   types.SingleSigGranter(c.identityEntity.ContentHash),
		Grantee:   c.remotePeerIdentityHash,
		CreatedAt: now,
		ExpiresAt: &expiresMs,
	}
	capEnt, encErr := tokenData.ToEntity()
	if encErr != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{},
			fmt.Errorf("build reentry capability entity: %w", encErr)
	}

	sigBytes := c.keypair.Sign(capEnt.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    capEnt.ContentHash,
		Signer:    c.identityEntity.ContentHash,
		Algorithm: "ed25519",
		Signature: sigBytes,
	}
	sigEnt, encErr := sigData.ToEntity()
	if encErr != nil {
		return entity.Entity{}, entity.Entity{}, entity.Entity{},
			fmt.Errorf("build reentry cap signature entity: %w", encErr)
	}

	return capEnt, c.identityEntity, sigEnt, nil
}

// identityPeerIDString returns the validator's peer-id as Base58.
func (c *PeerClient) identityPeerIDString() string {
	return string(c.keypair.PeerID())
}

// SendEchoProbe sends one system/validate/echo:echo EXECUTE and asserts
// the verbatim-echo §7a.1 contract.
//
// Returns nil when the round-trip succeeded and the result.value
// bytes-equal the params.value bytes. The CheckOutcome wrapper is the
// caller's job — keeping this pure-error so it composes with both the
// §10.1 spec-ref strand and a standalone §7a probe.
func (c *PeerClient) SendEchoProbe(ctx context.Context, payload interface{}) error {
	paramsRaw, err := ecf.Encode(map[string]interface{}{"value": payload})
	if err != nil {
		return fmt.Errorf("encode echo params: %w", err)
	}
	paramsEnt, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return fmt.Errorf("build echo params entity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", c.remotePeerID, conformance.PatternEcho)
	env, _, err := c.SendExecute(ctx, uri, "echo", paramsEnt, nil)
	if err != nil {
		return fmt.Errorf("send echo: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("decode echo response: %w", err)
	}
	if respData.Status != 200 {
		return fmt.Errorf("echo returned status %d (expected 200)", respData.Status)
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return fmt.Errorf("decode echo result entity: %w", err)
	}
	// Verbatim §7a.1: result.data must byte-equal params.data.
	if !bytesEqRawMessages(resultEnt.Data, paramsEnt.Data) {
		return fmt.Errorf("echo result.data does not byte-equal params.data (§7a.1 verbatim contract)")
	}
	return nil
}

// SendDispatchOutboundProbe sends one system/validate/dispatch-outbound
// EXECUTE and asserts that target reentries to the validator-side
// echo handler exactly once, round-tripping the embedded value.
//
// Caller must have armed reentry echo via ArmReentryEcho beforehand;
// otherwise the inbound reentry would be drained and the probe would
// time out.
//
// Returns nil + a hit count on success. The check-outcome wrapping is
// the caller's job.
func (c *PeerClient) SendDispatchOutboundProbe(ctx context.Context, value interface{}, echoSt *reentryEchoState) (int32, error) {
	if echoSt == nil {
		return 0, fmt.Errorf("reentry echo not armed (call ArmReentryEcho before this probe)")
	}
	capEnt, granterEnt, sigEnt, err := c.MintReentryCapability()
	if err != nil {
		return 0, fmt.Errorf("mint reentry capability: %w", err)
	}

	// In-band-nested-entity carriage per §7a.2a Go ruling: each authority
	// entity is encoded as its own ECF blob and nested under the named
	// key in the primitive/any params object.
	capRaw, err := ecf.Encode(capEnt)
	if err != nil {
		return 0, fmt.Errorf("encode reentry_capability: %w", err)
	}
	granterRaw, err := ecf.Encode(granterEnt)
	if err != nil {
		return 0, fmt.Errorf("encode reentry_granter: %w", err)
	}
	sigRaw, err := ecf.Encode(sigEnt)
	if err != nil {
		return 0, fmt.Errorf("encode reentry_cap_signature: %w", err)
	}
	// Per GUIDE-CONFORMANCE §7a.1 (clarified in RULINGS-CONCURRENCY-GATE-7b-
	// MATRIX ruling #2): echo's params shape is {value: X}, and
	// dispatch-outbound is a generic relay (no unwrap of result). So the
	// outbound `value` field sent to dispatch-outbound is the bytes of
	// {value: X} — a relay forwards those bytes as the outbound EXECUTE's
	// params data, which echo recognizes as its expected shape, and returns
	// verbatim.
	valueRaw, err := ecf.Encode(map[string]interface{}{"value": value})
	if err != nil {
		return 0, fmt.Errorf("encode echo params shape: %w", err)
	}

	// Target the validator-as-B's echo handler. Same connection — the
	// peer dispatches outbound to entity://<validator-peer-id>/... and
	// the §6.11 reentry sender uses the inbound connection it received
	// this EXECUTE on.
	validatorURI := fmt.Sprintf("entity://%s/%s",
		c.identityPeerIDString(), conformance.PatternEcho)

	paramsRaw, err := ecf.Encode(map[string]interface{}{
		"target":                 validatorURI,
		"operation":              "echo",
		"value":                  cbor.RawMessage(valueRaw),
		"reentry_capability":     cbor.RawMessage(capRaw),
		"reentry_granters":       []cbor.RawMessage{cbor.RawMessage(granterRaw)},
		"reentry_cap_signatures": []cbor.RawMessage{cbor.RawMessage(sigRaw)},
	})
	if err != nil {
		return 0, fmt.Errorf("encode dispatch-outbound params: %w", err)
	}
	paramsEnt, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return 0, fmt.Errorf("build dispatch-outbound params entity: %w", err)
	}

	uri := fmt.Sprintf("entity://%s/%s", c.remotePeerID, conformance.PatternDispatchOutbound)
	env, _, err := c.SendExecute(ctx, uri, "dispatch", paramsEnt, nil)
	if err != nil {
		return echoSt.Hits(), fmt.Errorf("send dispatch-outbound: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return echoSt.Hits(), fmt.Errorf("decode dispatch-outbound response: %w", err)
	}
	if respData.Status != 200 {
		return echoSt.Hits(), fmt.Errorf("dispatch-outbound returned status %d (expected 200)", respData.Status)
	}

	// Result is a primitive/any entity wrapping {status, result}.
	var outerResult entity.Entity
	if err := ecf.Decode(respData.Result, &outerResult); err != nil {
		return echoSt.Hits(), fmt.Errorf("decode dispatch-outbound result entity: %w", err)
	}
	var inner conformance.DispatchOutboundResult
	if err := ecf.Decode(outerResult.Data, &inner); err != nil {
		return echoSt.Hits(), fmt.Errorf("decode dispatch-outbound inner result: %w", err)
	}
	if inner.Status != 200 {
		return echoSt.Hits(), fmt.Errorf("downstream echo status %d (expected 200)", inner.Status)
	}

	// §7a.1 round-trip assertion: result.value == sent. inner.Result is
	// the downstream echo's result entity verbatim (relay-faithful per the
	// concurrency-gate ruling); for echo that's the params entity whose data is
	// {value: X}. Decode the map and compare the value field bytes against
	// what we sent. Only string is asserted today because that's what the
	// validator passes in; if the value interface becomes structured later,
	// shift to a bytes comparison instead.
	if sentStr, ok := value.(string); ok {
		var echoedEnt entity.Entity
		if err := ecf.Decode(inner.Result, &echoedEnt); err != nil {
			return echoSt.Hits(), fmt.Errorf("decode echoed result entity: %w", err)
		}
		var echoed struct {
			Value string `cbor:"value"`
		}
		if err := ecf.Decode(echoedEnt.Data, &echoed); err != nil {
			return echoSt.Hits(), fmt.Errorf("decode echoed {value: X} map: %w", err)
		}
		if echoed.Value != sentStr {
			return echoSt.Hits(), fmt.Errorf("§7a.1 round-trip: dispatch sent value %q, downstream result.value replied %q", sentStr, echoed.Value)
		}
	}

	hits := echoSt.Hits()
	if hits == 0 {
		return hits, fmt.Errorf("validator-side echo never received the reentry EXECUTE (§7a.2a reentry surface not exercised)")
	}
	if hits != 1 {
		return hits, fmt.Errorf("§7a.1 'exactly one outbound EXECUTE' violated: validator-side echo received %d reentries", hits)
	}
	return hits, nil
}

// SendDispatchOutboundProbeAmbient drives the target's dispatch-outbound
// handler with NO reentry capability, so the handler's outbound sub-dispatch
// to a FOREIGN peer (the validator) rides only the target's ambient handler
// grant. This is the PD-2 (§5.2, 0.8.2.17) negative arm: a handler whose grant
// carries no peers scope covering the target MUST be refused before the
// sub-dispatch leaves the peer.
//
// Returns (outerStatus, outerCode, innerStatus). The ambient Dimension-4
// refusal surfaces in one of two scaffold shapes, BOTH of which the caller
// treats as a pass (the §7a scaffold does not pin which):
//   - WRAPPED (go, rust): the handler returns outer 200 and the refusal rides
//     the INNER (sub-dispatch) status — inner 403.
//   - RELAYED (py): the handler relays the refusal as the OUTER status —
//     outer 403 capability_denied, inner 0.
// A peer that keeps the §7a.2a triple MANDATORY refuses the omitted-triple
// probe at PARAM VALIDATION (outer 400 invalid_params) — a refusal BEFORE any
// dispatch, so the ambient arm is NOT reachable over this probe and the outcome
// is UNMEASURED, not a defect (the caller SKIPs it). outerCode disambiguates a
// 403 Dimension-4 refusal from a 400 param-validation refusal — distinguishing
// them is the "early refusal reads as unmeasurability, not strictness" lesson.
func (c *PeerClient) SendDispatchOutboundProbeAmbient(ctx context.Context) (outerStatus int, outerCode string, innerStatus int, err error) {
	// Point the sub-dispatch at the validator's own echo handler — a foreign
	// namespace from the target's perspective. No capability is presented.
	valueRaw, err := ecf.Encode(map[string]interface{}{"value": "pd2-ambient-negative-probe"})
	if err != nil {
		return 0, "", 0, fmt.Errorf("encode echo params shape: %w", err)
	}
	validatorURI := fmt.Sprintf("entity://%s/%s", c.identityPeerIDString(), conformance.PatternEcho)
	paramsRaw, err := ecf.Encode(map[string]interface{}{
		"target":    validatorURI,
		"operation": "echo",
		"value":     cbor.RawMessage(valueRaw),
		// reentry_capability / reentry_granter / reentry_cap_signature omitted
		// on purpose — this exercises the ambient authority arm.
	})
	if err != nil {
		return 0, "", 0, fmt.Errorf("encode dispatch-outbound params: %w", err)
	}
	paramsEnt, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return 0, "", 0, fmt.Errorf("build dispatch-outbound params entity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", c.remotePeerID, conformance.PatternDispatchOutbound)
	env, _, err := c.SendExecute(ctx, uri, "dispatch", paramsEnt, nil)
	if err != nil {
		return 0, "", 0, fmt.Errorf("send dispatch-outbound (ambient): %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound response: %w", err)
	}
	// Outer non-200: either the ambient refusal RELAYED as the outer status (py:
	// 403 capability_denied), or a strict handler refusing the omitted triple at
	// PARAM VALIDATION (400 invalid_params). The outer code tells them apart; the
	// caller treats the former as the refusal (pass) and the latter as unmeasured
	// (skip). inner is 0 — there is no wrapped result to read.
	if respData.Status != 200 {
		code, _ := decodeResultErrorCode(respData)
		return int(respData.Status), code, 0, nil
	}
	// Outer 200: the WRAPPED shape (go, rust) — the refusal rides the inner status.
	var outerResult entity.Entity
	if err := ecf.Decode(respData.Result, &outerResult); err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound result entity: %w", err)
	}
	var inner conformance.DispatchOutboundResult
	if err := ecf.Decode(outerResult.Data, &inner); err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound inner result: %w", err)
	}
	return 200, "", int(inner.Status), nil
}

// sendDispatchOutboundPresented sends ONE dispatch-outbound EXECUTE presenting
// the given reentry authority (credential + plural granter identities + plural
// signatures, §7a.1 in-band) for the given operation, and returns the outer
// status/code plus, for the wrapped shape, the inner sub-dispatch status. It
// does not assert the value round-trip — the callers that discriminate on
// authorization (F63, E3) need the status, not the payload.
//
// The sub-dispatch target is always the validator's own echo pattern; the
// OPERATION is the discriminating axis (the narrow dispatch-outbound grant
// covers echo only, §7a.1). Both scaffold refusal shapes are surfaced verbatim:
// RELAYED (outer 403) and WRAPPED (outer 200 + inner status) — the caller
// classifies.
func (c *PeerClient) sendDispatchOutboundPresented(ctx context.Context, op string, capEnt entity.Entity, granters, sigs []entity.Entity) (outerStatus int, outerCode string, innerStatus int, err error) {
	capRaw, err := ecf.Encode(capEnt)
	if err != nil {
		return 0, "", 0, fmt.Errorf("encode reentry_capability: %w", err)
	}
	granterRaws := make([]cbor.RawMessage, len(granters))
	for i, g := range granters {
		raw, e := ecf.Encode(g)
		if e != nil {
			return 0, "", 0, fmt.Errorf("encode reentry_granters[%d]: %w", i, e)
		}
		granterRaws[i] = cbor.RawMessage(raw)
	}
	sigRaws := make([]cbor.RawMessage, len(sigs))
	for i, s := range sigs {
		raw, e := ecf.Encode(s)
		if e != nil {
			return 0, "", 0, fmt.Errorf("encode reentry_cap_signatures[%d]: %w", i, e)
		}
		sigRaws[i] = cbor.RawMessage(raw)
	}
	valueRaw, err := ecf.Encode(map[string]interface{}{"value": "presented-authz-probe"})
	if err != nil {
		return 0, "", 0, fmt.Errorf("encode echo params shape: %w", err)
	}
	validatorURI := fmt.Sprintf("entity://%s/%s", c.identityPeerIDString(), conformance.PatternEcho)
	paramsRaw, err := ecf.Encode(map[string]interface{}{
		"target":                 validatorURI,
		"operation":              op,
		"value":                  cbor.RawMessage(valueRaw),
		"reentry_capability":     cbor.RawMessage(capRaw),
		"reentry_granters":       granterRaws,
		"reentry_cap_signatures": sigRaws,
	})
	if err != nil {
		return 0, "", 0, fmt.Errorf("encode dispatch-outbound params: %w", err)
	}
	paramsEnt, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return 0, "", 0, fmt.Errorf("build dispatch-outbound params entity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", c.remotePeerID, conformance.PatternDispatchOutbound)
	env, _, err := c.SendExecute(ctx, uri, "dispatch", paramsEnt, nil)
	if err != nil {
		return 0, "", 0, fmt.Errorf("send dispatch-outbound (op=%s): %w", op, err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound response: %w", err)
	}
	if respData.Status != 200 {
		code, _ := decodeResultErrorCode(respData)
		return int(respData.Status), code, 0, nil
	}
	var outerResult entity.Entity
	if err := ecf.Decode(respData.Result, &outerResult); err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound result entity: %w", err)
	}
	var inner conformance.DispatchOutboundResult
	if err := ecf.Decode(outerResult.Data, &inner); err != nil {
		return 0, "", 0, fmt.Errorf("decode dispatch-outbound inner result: %w", err)
	}
	return 200, "", int(inner.Status), nil
}

// f63Outcome carries the two arms of the F63 compose-vs-bypass discriminator so
// the origination check can assert both against ONE credential.
type f63Outcome struct {
	inScopeOuterStatus int   // op=echo, in the narrow grant: expect 200
	inScopeInnerStatus int   // downstream echo: expect 200
	hitsAfterInScope   int32 // expect 1 (the reentry reached the validator)
	oosOuterStatus     int   // op=out-of-scope: 403 (relayed) or 200 (wrapped)
	oosOuterCode       string
	oosInnerStatus     int   // wrapped shape: expect 403
	hitsAfterOOS       int32 // expect STILL 1 (the refusal fired before reentry)
}

// SendDispatchOutboundF63Discriminator drives the F63 compose-vs-bypass
// discriminator on the wire (the missing E1 evidence, GUIDE-CONFORMANCE §7a.1
// ⛔). It mints ONE target-minted credential covering BOTH echo (in the
// dispatch-outbound handler's narrow grant) and reentryOutOfScopeOp (outside
// it), then sub-dispatches each:
//
//   - in-scope (echo):  Dims 1-3 covered by the narrow grant, Dim 4 relaxed by
//     the credential → 200, one reentry. This is the positive control — it
//     proves the credential is VALID and COVERING, so the out-of-scope refusal
//     below cannot be blamed on a bad credential (the false-pass trap the
//     0.8.2.19 close-out warns about).
//   - out-of-scope:     the narrow grant does NOT cover the operation (Dim 1),
//     so a conformant peer refuses even though the SAME credential covers it —
//     the credential answers WHERE, the handler grant answers WHAT (§6.8). A
//     peer whose credential path bypasses the handler grant SUCCEEDS here (the
//     F67 confused-deputy shape), which is the defect this vector exists to
//     catch.
//
// Mutation witness (documented, not run in CI): restoring the pre-E1 bypass in
// core/protocol.presentedAuthorizes (authorize on the credential alone) flips
// the out-of-scope arm from refused to 200 with a second reentry hit — which is
// why the validator's B-role echo handler answers reentryOutOfScopeOp verbatim
// (carry-the-teeth: the bypassed dispatch must be able to reach a 200).
func (c *PeerClient) SendDispatchOutboundF63Discriminator(ctx context.Context, echoSt *reentryEchoState) (f63Outcome, error) {
	var out f63Outcome
	if echoSt == nil {
		return out, fmt.Errorf("reentry echo not armed (call ArmReentryEcho before this probe)")
	}
	capEnt, granterEnt, sigEnt, err := c.mintReentryCapForOps([]string{"echo", reentryOutOfScopeOp})
	if err != nil {
		return out, fmt.Errorf("mint discriminator reentry capability: %w", err)
	}
	granters := []entity.Entity{granterEnt}
	sigs := []entity.Entity{sigEnt}

	os1, _, is1, err := c.sendDispatchOutboundPresented(ctx, "echo", capEnt, granters, sigs)
	if err != nil {
		return out, fmt.Errorf("in-scope control (op=echo): %w", err)
	}
	out.inScopeOuterStatus, out.inScopeInnerStatus, out.hitsAfterInScope = os1, is1, echoSt.Hits()

	os2, oc2, is2, err := c.sendDispatchOutboundPresented(ctx, reentryOutOfScopeOp, capEnt, granters, sigs)
	if err != nil {
		return out, fmt.Errorf("out-of-scope discriminator (op=%s): %w", reentryOutOfScopeOp, err)
	}
	out.oosOuterStatus, out.oosOuterCode, out.oosInnerStatus, out.hitsAfterOOS = os2, oc2, is2, echoSt.Hits()
	return out, nil
}

// mintMultiSigReentryCap mints a K-of-2 multi-sig-ROOTED reentry credential over
// {validator, ephemeral co-signer}, threshold 2, both signing, granted to the
// target, scoped to echo. The validator (the reentry sub-dispatch TARGET) is one
// of the two signers and DOES sign — so VerifyChain's M6, run with the target as
// the frame, ACCEPTS it. It is nonetheless NOT "minted BY the target peer" (D1):
// the co-signer authorized it too. E3/F66 (0.8.2.19) makes the presented arm
// reject it fail-closed. Returns the cap, both granter identities, both
// signatures (the §7a.1 plural carrier).
func (c *PeerClient) mintMultiSigReentryCap() (cap entity.Entity, granters, sigs []entity.Entity, err error) {
	if c.identityEntity.ContentHash.IsZero() {
		return entity.Entity{}, nil, nil, fmt.Errorf("validator identity not initialized")
	}
	if c.remotePeerIdentityHash.IsZero() {
		return entity.Entity{}, nil, nil, fmt.Errorf("target peer identity not known (handshake incomplete?)")
	}
	coKP, err := crypto.Generate()
	if err != nil {
		return entity.Entity{}, nil, nil, fmt.Errorf("generate co-signer keypair: %w", err)
	}
	coIdent, err := coKP.IdentityEntity()
	if err != nil {
		return entity.Entity{}, nil, nil, fmt.Errorf("build co-signer identity: %w", err)
	}

	now := uint64(time.Now().UnixMilli())
	expiresMs := now + uint64((5 * time.Minute).Milliseconds())
	resourcePath := fmt.Sprintf("/%s/%s", c.identityPeerIDString(), conformance.PatternEcho)
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{conformance.PatternEcho}},
				Operations: types.CapabilityScope{Include: []string{"echo"}},
				Resources:  types.CapabilityScope{Include: []string{resourcePath}},
			},
		},
		Granter: types.MultiSigGranter(types.MultiGranter{
			Signers:   []hash.Hash{c.identityEntity.ContentHash, coIdent.ContentHash},
			Threshold: 2,
		}),
		Grantee:   c.remotePeerIdentityHash,
		CreatedAt: now,
		ExpiresAt: &expiresMs,
	}
	capEnt, encErr := tokenData.ToEntity()
	if encErr != nil {
		return entity.Entity{}, nil, nil, fmt.Errorf("build multi-sig reentry capability: %w", encErr)
	}

	mkSig := func(kp crypto.Keypair, signer hash.Hash) (entity.Entity, error) {
		sigBytes := kp.Sign(capEnt.ContentHash.Bytes())
		return types.SignatureData{
			Target:    capEnt.ContentHash,
			Signer:    signer,
			Algorithm: "ed25519",
			Signature: sigBytes,
		}.ToEntity()
	}
	valSig, encErr := mkSig(c.keypair, c.identityEntity.ContentHash)
	if encErr != nil {
		return entity.Entity{}, nil, nil, fmt.Errorf("build validator signature: %w", encErr)
	}
	coSig, encErr := mkSig(coKP, coIdent.ContentHash)
	if encErr != nil {
		return entity.Entity{}, nil, nil, fmt.Errorf("build co-signer signature: %w", encErr)
	}
	return capEnt, []entity.Entity{c.identityEntity, coIdent}, []entity.Entity{valSig, coSig}, nil
}

// e3Outcome carries the two arms of the E3/F66 fail-closed wire differential so
// the origination check can assert a deny with its own antecedent established
// (GUIDE-CONFORMANCE §2.4b — a deny-only check MUST establish its own antecedent).
// The single-sig arm is the positive control; the granter form is the ONLY
// variable between the two arms.
type e3Outcome struct {
	singleSigOuterStatus int   // single-sig target-minted, echo: expect 200
	singleSigInnerStatus int   // downstream echo: expect 200
	hitsAfterSingleSig   int32 // expect 1 (single-sig relaxes Dim 4, reentry reached the validator)
	multiSigOuterStatus  int   // K-of-2 over the identical request: 403 (relayed) or 200 (wrapped)
	multiSigOuterCode    string
	multiSigInnerStatus  int   // wrapped shape: expect 403
	hitsAfterMultiSig    int32 // expect STILL 1 (the fail-closed refusal fired before reentry)
}

// SendDispatchOutboundE3MultiSig drives the E3/F66 fail-closed rule on the wire
// (GUIDE-CONFORMANCE §7a.1 plural carrier, 0.8.2.19) as a differential with its
// own positive control, per the F70 ruling (keystone's option (b),
// ROUTING-2026-09-10-c §2). Two presented sends over the SAME echo operation,
// target and scope, through sendDispatchOutboundPresented — the GRANTER FORM the
// only variable:
//
//   - single-signature, target-minted, covering (mintReentryCapForOps) → MUST
//     succeed (200/200) and reach the validator's B-role echo exactly once. This
//     is the positive control: it proves the credential family is otherwise valid
//     and covering, so the multi-sig refusal below is attributable to the granter
//     form and not to any unrelated defect in the mint (a malformed granter, a
//     signature over the wrong bytes, a grantee mismatch, a resource that does
//     not cover). Without it a green three-way measures nothing about E3.
//   - K-of-2 multi-sig-ROOTED (mintMultiSigReentryCap; the target is one of two
//     signers) over the identical request → VerifyChain accepts the root (the
//     target signed), but a multi-sig root is not the target's SOLE authority, so
//     it MUST NOT relax Dimension 4. The sub-dispatch falls to ambient authority
//     and the foreign target is refused (the narrow grant carries no peers scope).
//
// mintReentryCapForOps and mintMultiSigReentryCap are byte-parallel except the
// Granter field (same grants, handler/operation/resource scope, grantee, expiry
// window), so the single-sig arm is a true control for the multi-sig arm.
//
// Mutation witness: removing the IsMulti root check in presentedAuthorizes lets
// the multi-sig root relax Dimension 4, its echo sub-dispatch then succeeds, and
// the multi-sig arm flips from refused to 200 + a second reentry hit — while the
// single-sig control is unaffected, so ONLY E3 reddens.
func (c *PeerClient) SendDispatchOutboundE3MultiSig(ctx context.Context, echoSt *reentryEchoState) (e3Outcome, error) {
	var out e3Outcome
	if echoSt == nil {
		return out, fmt.Errorf("reentry echo not armed (call ArmReentryEcho before this probe)")
	}

	// Positive control: single-sig target-minted covering credential over echo.
	scCap, scGranter, scSig, err := c.mintReentryCapForOps([]string{"echo"})
	if err != nil {
		return out, fmt.Errorf("mint single-sig control credential: %w", err)
	}
	os1, _, is1, err := c.sendDispatchOutboundPresented(ctx, "echo", scCap, []entity.Entity{scGranter}, []entity.Entity{scSig})
	if err != nil {
		return out, fmt.Errorf("single-sig positive control (op=echo): %w", err)
	}
	out.singleSigOuterStatus, out.singleSigInnerStatus, out.hitsAfterSingleSig = os1, is1, echoSt.Hits()

	// The E3 vector proper: K-of-2 multi-sig root over the identical request,
	// granter form the only variable.
	msCap, msGranters, msSigs, err := c.mintMultiSigReentryCap()
	if err != nil {
		return out, fmt.Errorf("mint multi-sig credential: %w", err)
	}
	os2, oc2, is2, err := c.sendDispatchOutboundPresented(ctx, "echo", msCap, msGranters, msSigs)
	if err != nil {
		return out, fmt.Errorf("multi-sig arm (op=echo): %w", err)
	}
	out.multiSigOuterStatus, out.multiSigOuterCode, out.multiSigInnerStatus, out.hitsAfterMultiSig = os2, oc2, is2, echoSt.Hits()
	return out, nil
}

// HasConformanceHandlers does a cheap wire probe to detect whether the
// target peer has the §7a test handlers wired (i.e. was started with
// --validate). Tree-gets the echo handler interface entity; presence
// means the handler is registered. Cheaper than a full EXECUTE probe.
//
// Caveat: a peer can mount the handler entity at the spec path without
// supplying a body, which would make HasConformanceHandlers return true
// while SendEchoProbe FAILs at dispatch. The honest path stays "let the
// probe FAIL if the body misbehaves"; this helper only catches the
// happy-path SKIP case (handlers never installed at all).
func (c *PeerClient) HasConformanceHandlers(ctx context.Context) bool {
	probePath := "system/handler/" + conformance.PatternDispatchOutbound
	_, _, err := c.TreeGet(ctx, probePath)
	return err == nil
}

// bytesEqRawMessages compares two cbor.RawMessage byte slices for byte
// equality. Used to assert the §7a.1 verbatim-echo contract.
func bytesEqRawMessages(a, b cbor.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// suppress unused-import compiler errors when this file is built before
// all consumers land.
var _ = hash.Hash{}
