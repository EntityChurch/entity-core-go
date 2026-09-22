package validate

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/wire"
)

const catPreadmissionRefusal = "preadmission_refusal"

// runPreadmissionRefusal drives CORE-PREADMISSION-REFUSAL-1 (ENTITY-CORE-PROTOCOL
// §4.11, 0.8.2.25; arch ROUTING-2026-09-14-e §5). §4.11 names a class of frame
// refused BEFORE it is admitted as a request. For every arm the peer MUST put a
// coded frame on the wire (a bare CLOSE and a silent DROP are two distinct
// non-conformances, scored by the same arm), and the code is the CAUSE's, not the
// class's:
//
//	(a1) whole-but-undecodable CBOR     -> 400 invalid_request   [survives: §4.9(c)]
//	(b)  root is a third entity type    -> 400 invalid_request   [survives]
//	(c)  oversize (length prefix > max) -> 413 payload_too_large [close is the peer's choice]
//	(d)  mis-keyed included entry       -> 400 hash_mismatch     [§1.8, F79]
//	(f)  (a1) on a MULTIPLEXED connection carrying an admitted in-flight request
//	     -> that request STILL gets its response (§4.9(c) — a framing refusal MUST
//	        NOT destroy unrelated admitted work). arch §5: "the one arm nothing else
//	        implies and it has never been driven anywhere."
//
// SA-PY-62 (py + rust converged, routed): §4.11 arm (a) bundles two frames with
// OPPOSITE dispositions — (a1) whole-but-undecodable, where a complete frame was
// consumed so the stream is synchronized and the peer CAN survive; and (a2) a
// genuinely truncated frame, where the sender declared a length and sent fewer
// bytes, leaving no next boundary so the close is FORCED. This oracle drives only
// (a1) — the satisfiable half — and asserts survival. It MUST NOT be "fixed" to
// send a truncated frame at the survival arms, or it scores a conformant peer red
// (go's own serve() forces the close on truncated). (a2) — truncated -> best-
// effort 400 then forced close — is OWED: PeerClient is envelope-level and cannot
// half-close a partial frame (the tapping-proxy / SHUT_WR limitation rust and py
// hit too). Pinned in-tree at core/peer.TestClassifyRecvError until arch splits
// the arm (SA-PY-62 ask) and the harness gains a raw half-close.
//
// Arm (e) (connect-auth -> coded 401) is covered by the `connectivity` category
// (it needs pre-handshake control this category does not set up) and is not
// duplicated here.
//
// Each arm runs on its OWN freshly-handshaked dedicated connection: (c) and (d)
// close the connection after the coded frame, (a)/(b)/(f) keep it, and isolating
// each removes any ordering coupling. Requires single-peer mode (newClient
// present); SKIP otherwise (a bad frame's refusal must not leak into the shared
// suite connection).
func runPreadmissionRefusal(ctx context.Context, newClient func() (*PeerClient, error)) []CheckResult {
	r := NewCheckRunner(catPreadmissionRefusal)

	r.Declare("preadmission_undecodable_cbor_invalid_request",
		"ENTITY-CORE-PROTOCOL §4.11 (0.8.2.25) arm (a1): a WHOLE frame whose payload will not decode into an Envelope (un-parseable / non-canonical CBOR — NOT a truncated frame; see SA-PY-62) MUST be refused 400 invalid_request with a coded frame, and the connection MUST survive (the frame was consumed whole so the stream is synchronized on the next boundary; §4.9(c) forbids destroying admitted in-flight work over one bad frame). A bare close / silent drop is the pre-0.8.2.25 non-conformance. Survival is asserted by a SECOND bad frame getting the same coded answer. The truncated half (a2) has the opposite disposition — a forced close — and is NOT driven here (PeerClient cannot half-close a partial frame).")
	r.Declare("preadmission_wrong_root_type_invalid_request",
		"ENTITY-CORE-PROTOCOL §3.3 / §4.11 (0.8.2.25) arm (b): a well-formed frame whose ROOT entity is neither EXECUTE nor EXECUTE_RESPONSE MUST be refused 400 invalid_request with a coded frame (the pre-0.8.2.25 corpus mandated a bare close here).")
	r.Declare("preadmission_oversize_payload_too_large",
		"ENTITY-CORE-PROTOCOL §4.10(a) / §4.11 (0.8.2.25) arm (c): a frame whose length prefix exceeds the configured maximum MUST be refused 413 payload_too_large with a coded frame BEFORE any close (0.8.2.25 removed the MAY-close-silently latitude — the over-size is detected at the length prefix with the connection intact). Detected at the prefix, so no request_id to correlate; a best-effort coded frame, then the peer MAY close.")
	r.Declare("preadmission_miskeyed_included_refused",
		"ENTITY-CORE-PROTOCOL §1.8 / §4.11 (0.8.2.25) arm (d): an otherwise-valid authenticated EXECUTE carrying a RESOLVED included entry (a granter identity / cap sig the authority decision looks up by hash) whose key no longer binds to its content hash — the §1.8 forgery vector at the framing boundary — MUST be REFUSED with a coded frame (a non-200; a bare close / silent drop is the pre-N4 non-conformance), a clean authenticated get returning 200 as the positive control so the refusal is attributable to the key binding. The mis-key targets a RESOLVED entry on purpose: §1.8 item 1 names two conformant mechanisms — (a) bind the key (map-wide at the receive boundary: go/rust, F79 ValidateAll) or (b) discard the key and address only by validated content_hash (py, whose `included` is a LIST). An UNREFERENCED mis-keyed entry is undetectable under (b) by construction, so §5.2a already rules a uniform verdict MUST NOT be required — testing it would score a conformant (b) peer non-conformant. A resolved-entry forgery is the AGREED property both mechanisms MUST refuse. The refusal CODE is a cross-impl-divergent slot (routed, ROUTING-2026-09-15-a) — recorded, NOT discriminated on. The exact go code (400 hash_mismatch, F79) is pinned in-tree at core/peer.TestServe_N4_DecodeBoundaryRefusalEmitsCodedFrameBeforeClose.")
	r.Declare("preadmission_multiplex_inflight_survives",
		"ENTITY-CORE-PROTOCOL §4.9(c) / §4.11 (0.8.2.25) arm (f) — arch §5, 'the one arm nothing else implies and it has never been driven anywhere': a framing refusal (arm a) injected on a MULTIPLEXED connection that is carrying an admitted in-flight request MUST NOT destroy that request — it still gets its response. A bare close on the bad frame destroys unrelated admitted work; this arm is what makes the difference between close and coded-frame-continue observable. The bad frame's empty-request_id coded response is dropped (a sacrificial waiter keeps bgWaiters>=2) so the in-flight request keeps its own id-matched routing; the survival of the in-flight 200 is the witness.")

	names := []string{
		"preadmission_undecodable_cbor_invalid_request",
		"preadmission_wrong_root_type_invalid_request",
		"preadmission_oversize_payload_too_large",
		"preadmission_miskeyed_included_refused",
		"preadmission_multiplex_inflight_survives",
	}

	if newClient == nil {
		skip := "preadmission_refusal needs a dedicated connection (single-peer mode / newClient): a refused bad frame must not leak into the shared suite connection"
		for _, name := range names {
			r.Run(name, func() CheckOutcome { return SkipCheck(skip) })
		}
		return r.Results()
	}

	// fresh returns a connected + handshaked dedicated client (and its closer), or
	// a non-empty error string. Each arm gets its own so the closing arms (c, d)
	// never affect the others.
	fresh := func() (*PeerClient, func(), string) {
		c, err := newClient()
		if err != nil {
			return nil, func() {}, "new dedicated client: " + err.Error()
		}
		if cErr := c.Connect(ctx); cErr != nil {
			c.Close()
			return nil, func() {}, "connect dedicated client: " + cErr.Error()
		}
		if _, ok := runConnectivity(ctx, c); !ok {
			c.Close()
			return nil, func() {}, "handshake on dedicated client failed"
		}
		return c, func() { c.Close() }, ""
	}

	treeURIOf := func(c *PeerClient) string {
		return fmt.Sprintf("entity://%s/system/tree", c.RemotePeerID())
	}
	// frame wraps a payload in the 4-byte big-endian length prefix, producing a
	// complete on-wire frame the peer reads whole (so the framing arm continues).
	frame := func(payload []byte) []byte {
		b := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(b[:4], uint32(len(payload)))
		copy(b[4:], payload)
		return b
	}
	// {0xA1, 0x00}: CBOR opens a 1-pair map (0xA1) with a first key (0x00) and no
	// value — valid framing, a complete frame, but undecodable as an Envelope.
	undecodableCBOR := func() []byte { return frame([]byte{0xA1, 0x00}) }

	// (a1) whole-but-undecodable CBOR -> 400 invalid_request, connection survives.
	r.Run("preadmission_undecodable_cbor_invalid_request", func() CheckOutcome {
		c, done, se := fresh()
		if se != "" {
			return FailCheck(se)
		}
		defer done()
		raw, err := c.SendRawBytesSingleAwait(ctx, undecodableCBOR())
		if err != nil {
			return FailCheck("undecodable-CBOR frame got no coded response (a bare close / silent drop is the pre-0.8.2.25 non-conformance): " + err.Error())
		}
		st, code := decodeRawStatusCode(raw)
		if st != 400 || code != "invalid_request" {
			return FailCheck(fmt.Sprintf("undecodable CBOR: got status=%d code=%q; want 400 invalid_request", st, code))
		}
		// Survival: a second bad frame is answered the same way (the framing arm
		// continues rather than closing). This is arm (a1) — the whole-frame half;
		// a truncated frame (a2) would force a close and is not driven (SA-PY-62).
		raw2, err2 := c.SendRawBytesSingleAwait(ctx, undecodableCBOR())
		if err2 != nil {
			return FailCheck("first bad frame answered 400 invalid_request but the connection did NOT survive a second (a close, not the §4.9(c) continue): " + err2.Error())
		}
		st2, code2 := decodeRawStatusCode(raw2)
		if st2 == 400 && code2 == "invalid_request" {
			return PassCheck("whole-but-undecodable CBOR -> 400 invalid_request coded frame, and the connection survives a second bad frame (§4.11 arm a1 + §4.9(c) continue, not a bare close)")
		}
		return FailCheck(fmt.Sprintf("second bad frame not 400 invalid_request: status=%d code=%q", st2, code2))
	})

	// (b) wrong root type -> 400 invalid_request. A valid third-typed envelope.
	r.Run("preadmission_wrong_root_type_invalid_request", func() CheckOutcome {
		c, done, se := fresh()
		if se != "" {
			return FailCheck(se)
		}
		defer done()
		payload, err := ecf.Encode(map[string]string{"k": "v"})
		if err != nil {
			return FailCheck("encode payload: " + err.Error())
		}
		third, err := entity.NewEntity("system/validate/preadmission", cbor.RawMessage(payload))
		if err != nil {
			return FailCheck("build third-type root: " + err.Error())
		}
		encoded, err := ecf.Encode(entity.NewEnvelope(third, nil))
		if err != nil {
			return FailCheck("encode third-type envelope: " + err.Error())
		}
		raw, err := c.SendRawBytesSingleAwait(ctx, frame(encoded))
		if err != nil {
			return FailCheck("wrong-root-type frame got no coded response (a bare close is the pre-0.8.2.25 non-conformance): " + err.Error())
		}
		st, code := decodeRawStatusCode(raw)
		if st == 400 && code == "invalid_request" {
			return PassCheck("wrong root type -> 400 invalid_request coded frame (§3.3 / §4.11)")
		}
		return FailCheck(fmt.Sprintf("wrong root type: got status=%d code=%q; want 400 invalid_request", st, code))
	})

	// (c) oversize -> 413. A bare 4-byte length prefix over the max: the peer
	// rejects at the prefix with the connection intact and nothing spent. CLOSES.
	r.Run("preadmission_oversize_payload_too_large", func() CheckOutcome {
		c, done, se := fresh()
		if se != "" {
			return FailCheck(se)
		}
		defer done()
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, uint32(wire.MaxFrameSize)+1)
		raw, err := c.SendRawBytesSingleAwait(ctx, prefix)
		if err != nil {
			return FailCheck("oversize frame got no coded response (a silent close is the non-conformance 0.8.2.25 removed): " + err.Error())
		}
		st, code := decodeRawStatusCode(raw)
		if st == 413 && code == "payload_too_large" {
			return PassCheck("oversize length prefix -> 413 payload_too_large coded frame before close (§4.10(a) / §4.11)")
		}
		return FailCheck(fmt.Sprintf("oversize: got status=%d code=%q; want 413 payload_too_large", st, code))
	})

	// (d) mis-keyed included -> refused with a coded frame. Valid EXECUTE root (so
	// the request_id correlates), one included entry filed under the wrong key. The
	// refusal CODE is cross-impl-divergent (go/rust 400 hash_mismatch; py 401
	// authentication_failed) and is RECORDED, not asserted — a wire check must not
	// discriminate on an unruled slot (the standing "deceptive-green wearing a
	// conformance badge" rule; the go↔py drive on 2026-09-15 is what exposed it).
	r.Run("preadmission_miskeyed_included_refused", func() CheckOutcome {
		c, done, se := fresh()
		if se != "" {
			return FailCheck(se)
		}
		defer done()
		params, resource, perr := buildSimpleGetParams()
		if perr != nil {
			return FailCheck("build get params: " + perr.Error())
		}
		// Positive control: the SAME authenticated tree:get with NO mis-keyed entry
		// MUST succeed (200). Without it, the forgery arm's refusal is unattributable
		// — a peer that refuses the mis-keyed frame for an UNRELATED reason (an
		// unauthenticated root -> 401 auth) reads identically to one enforcing the
		// §1.8 key binding (K1 carry-the-teeth; the go↔py drive on 2026-09-15 showed
		// an unauthenticated-root construction scored py's auth arm, not its binding).
		ctrlEnv, _, cErr := c.SendExecute(ctx, treeURIOf(c), "get", params, resource)
		if cErr != nil {
			return SkipCheck("positive control (clean authenticated tree:get) errored, so a mis-keyed refusal is unattributable: " + cErr.Error())
		}
		if cst, _, _, cde := extractStatusAndCode(ctrlEnv); cde != nil || cst != 200 {
			return SkipCheck(fmt.Sprintf("positive control (clean authenticated tree:get) did not return 200 (status=%d) — a mis-keyed refusal would be unattributable to the key binding", cst))
		}
		// The forgery: the identical authenticated EXECUTE, plus ONE extra included
		// entry filed under the wrong key. The root's own author/cap binding stays
		// valid, so the ONLY defect is the mis-key — every conformant peer must refuse
		// on the §1.8 key binding, not on authentication.
		reqID := c.NextRequestID()
		env, err := c.BuildAuthenticatedExecute(reqID, treeURIOf(c), "get", params, resource)
		if err != nil {
			return FailCheck("build authenticated execute: " + err.Error())
		}
		otherRaw, err := ecf.Encode("x")
		if err != nil {
			return FailCheck("encode other: " + err.Error())
		}
		other, err := entity.NewEntity("test/x", cbor.RawMessage(otherRaw))
		if err != nil {
			return FailCheck("build other: " + err.Error())
		}
		// The mis-key targets a RESOLVED included entry (a granter identity / cap sig
		// the server looks up by hash during chain verification), NOT an unreferenced
		// one. This is deliberate: §1.8 item 1 names TWO conformant mechanisms —
		// (a) bind the key (reject a mis-keyed entry map-wide at the receive boundary:
		// go/rust, F79 ValidateAll) and (b) discard the key (drop wire keys, address
		// only by validated content_hash: py, whose `included` is a LIST with no key
		// to mis-key). An UNREFERENCED mis-keyed entry is undetectable under (b) BY
		// CONSTRUCTION (there is no key), so §5.2a already rules a uniform verdict MUST
		// NOT be required across the three resolution-integrity rows — testing the
		// unreferenced case would score a conformant (b) peer non-conformant (AP-2).
		// A mis-key on a RESOLVED entry is the AGREED forgery both mechanisms MUST
		// refuse (the wrong entity resolves for the authority decision). Pick the
		// target deterministically (min hash bytes) for a reproducible recorded code.
		// (formalization ROUTING-2026-09-16-a corrected go's earlier "enforcement-point"
		// framing to this mechanism framing; only a one-sentence §1.8 note for the
		// unreferenced case remains owed by arch.)
		var target hash.Hash
		haveTarget := false
		for k := range env.Included {
			if !haveTarget || string(k.Bytes()) < string(target.Bytes()) {
				target, haveTarget = k, true
			}
		}
		if !haveTarget {
			return SkipCheck("no resolved included entry to mis-key (authenticate response carried none) — cannot build a resolved-hash forgery that both boundary and resolve-time peers must refuse")
		}
		env.Included[target] = other // key stays `target`, value now hashes elsewhere
		respEnv, _, err := c.SendRawEnvelope(env)
		if err != nil {
			// A bare close / silent drop: the forgery IS refused (fail-closed), but
			// §4.11 / N4 owe a CODED frame here. A peer that has not adopted N4 still
			// refuses the forgery; treat that as a pass with a note rather than
			// scoring a secure peer as a defect (mirrors resolution_integrity).
			return PassCheck("mis-keyed included REFUSED fail-closed (connection closed, no coded response) — the forgery is not resolved. N4 (0.8.2.24) makes the bare close non-conformant (a coded frame is owed); recorded: " + err.Error())
		}
		st, code, _, derr := extractStatusAndCode(respEnv)
		if derr != nil {
			return FailCheck("extract response: " + derr.Error())
		}
		if st == 200 {
			return FailCheck(fmt.Sprintf("mis-keyed included ACCEPTED (status=200 code=%q): a RESOLVED included entry (granter identity / cap sig) whose key no longer binds to its content hash was honored — the §1.8 key binding is bypassed for an entity the authority decision resolves. The forgery would resolve as the substituted entity", code))
		}
		return PassCheck(fmt.Sprintf("mis-keyed included (on a RESOLVED entry) REFUSED with a coded frame (status=%d code=%q), the clean control having returned 200 so the refusal is attributable to the key binding — §1.8 / §4.11 arm (d). The code slot is cross-impl-divergent (recorded, not discriminated on). §1.8 item 1 blesses two mechanisms — (a) bind the key, (b) discard it — so an UNREFERENCED mis-keyed entry is mechanism-determined (undetectable under (b), §5.2a: uniform verdict MUST NOT be required), NOT a discriminator; this arm targets a resolved entry both mechanisms must refuse", st, code))
	})

	// (f) multiplex: a framing refusal MUST NOT destroy an admitted in-flight
	// request on the same connection (§4.9(c)). arch §5 — never driven before.
	r.Run("preadmission_multiplex_inflight_survives", func() CheckOutcome {
		c, done, se := fresh()
		if se != "" {
			return FailCheck(se)
		}
		defer done()
		params, resource, perr := buildSimpleGetParams()
		if perr != nil {
			return FailCheck("build get params: " + perr.Error())
		}
		reqID := c.NextRequestID()
		env, err := c.BuildAuthenticatedExecute(reqID, treeURIOf(c), "get", params, resource)
		if err != nil {
			return FailCheck("build in-flight execute: " + err.Error())
		}
		// A sacrificial waiter so the bad frame's empty-request_id 400 is DROPPED
		// (bgWaiters>=2) rather than misrouted to the in-flight request's waiter by
		// the single-in-flight fallback.
		sink := c.ReservePreadmissionSink()
		defer sink()
		await, cleanup, aerr := c.SendEnvelopeAwaitable(ctx, reqID, env)
		if aerr != nil {
			return FailCheck("send in-flight execute: " + aerr.Error())
		}
		defer cleanup()
		// Inject a framing refusal while the request is admitted and in flight.
		if werr := c.writeRawBytes(ctx, undecodableCBOR()); werr != nil {
			return FailCheck("inject bad frame: " + werr.Error())
		}
		raw, rerr := await()
		if rerr != nil {
			return FailCheck("the admitted in-flight request did NOT survive the framing refusal — a bare close destroyed unrelated admitted work (§4.9(c) violated): " + rerr.Error())
		}
		var respEnv entity.Envelope
		if err := ecf.Decode(raw, &respEnv); err != nil {
			return FailCheck("decode in-flight response: " + err.Error())
		}
		st, code, _, derr := extractStatusAndCode(respEnv)
		if derr != nil {
			return FailCheck("extract in-flight response: " + derr.Error())
		}
		if st != 200 {
			return FailCheck(fmt.Sprintf("in-flight request survived the bad frame but did not return 200: status=%d code=%q", st, code))
		}
		// The DISCRIMINATOR. A bare close still drains already-dispatched work via
		// serve()'s deferred wg.Wait, so the in-flight 200 above passes even under a
		// bare close — it does NOT tell continue from drain-then-close. What only a
		// §4.11 CONTINUE gives is a connection that keeps serving NEW requests after
		// the bad frame: send a fresh tree:get on the SAME connection and require
		// 200. A bare-close peer has closed by now → this send fails.
		aEnv, _, nerr := c.SendExecute(ctx, treeURIOf(c), "get", params, resource)
		if nerr != nil {
			return FailCheck("a NEW request after the framing refusal failed — the connection did not keep serving (a bare close, not the §4.11 continue): " + nerr.Error())
		}
		nst, ncode, _, nde := extractStatusAndCode(aEnv)
		if nde == nil && nst == 200 {
			return PassCheck("multiplex: the admitted in-flight tree:get survived the framing refusal (200) AND a NEW request on the same connection after it also returned 200 — the connection kept serving, distinguishing §4.11 continue from drain-then-close (§4.9(c); arch §5 arm (f))")
		}
		return FailCheck(fmt.Sprintf("new request after the bad frame did not return 200: status=%d code=%q", nst, ncode))
	})

	return r.Results()
}

// decodeRawStatusCode decodes a raw response frame into an EXECUTE_RESPONSE and
// returns (status, code). Returns (0, "") on any decode miss — the caller treats
// that as a failed refusal.
func decodeRawStatusCode(raw []byte) (uint, string) {
	var env entity.Envelope
	if err := ecf.Decode(raw, &env); err != nil {
		return 0, ""
	}
	st, code, _, _ := extractStatusAndCode(env)
	return st, code
}
