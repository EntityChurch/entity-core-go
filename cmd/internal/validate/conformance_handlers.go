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
// Cap-passing convention (§7a.2a, Go ruling): the three
// reentry-authority entities travel in-band, nested in the
// dispatch-outbound EXECUTE's params (reentry_capability /
// reentry_granter / reentry_cap_signature). NOT via envelope `included`.
// See the V7.74-A013 Go cap-passing ruling.

package validate

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

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
	handlerPath := entity.ExtractHandlerPath(execData.URI)
	if handlerPath != conformance.PatternEcho || execData.Operation != "echo" {
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
				Operations: types.CapabilityScope{Include: []string{"echo"}},
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
		"reentry_granter":        cbor.RawMessage(granterRaw),
		"reentry_cap_signature":  cbor.RawMessage(sigRaw),
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
