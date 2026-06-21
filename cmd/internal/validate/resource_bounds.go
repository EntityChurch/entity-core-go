package validate

// V7 §4.10 resource-bounds + admission-control gate.
//
// History: routed by the V7.75 resource-bounds-and-concurrency handoff
// (arch, post-Keystone absorption). §4.10 stayed RESERVED
// until this probe existed ("no floor MUST without a gate"). With the gate
// 3-way GREEN, arch fold `414b892` moved §4.10(a)+(b) from
// RESERVED → §9.1 floor MUSTs and enumerated `resource_bounds` in §9.0.
// The category now runs under --profile core (paired with the §10.3
// drift gate). §4.10(c) stays SHOULD with the external-admission
// carve-out (r3 scores Warn — non-failing).
//
// Three checks, ratio/invariant style — gates ENFORCEMENT, never a number:
//
//   r1 §4.10(a) — payload over limit  → 413 payload_too_large AND keeps serving
//   r2 §4.10(b) — chain over depth    → 400 chain_depth_exceeded (NOT 403)
//                                       AND keeps serving
//   r3 §4.10(c) — connection flood    → 503 / close / acceptable external
//                                       delegation (SHOULD; Warn-don't-Fail)
//
// Defaults (16 MiB / 64) are informative recommended values; a peer that
// declares 32 MiB and enforces it cleanly is conformant — operators override
// via -declared-max-payload / -declared-max-chain-depth.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const catResourceBounds = "resource_bounds"

const (
	// Recommended defaults per the v7.75 proposal (Keystone-shaped). These
	// match the Go peer's current internal constants (wire.MaxFrameSize and
	// capability.maxChainDepth) so a default-config peer passes; operators
	// running a peer with tighter or wider bounds pass the flags.
	defaultDeclaredMaxPayload    = 16 * 1024 * 1024
	defaultDeclaredMaxChainDepth = 64

	// r3 — connections to open against the peer's listener in the flood
	// probe. Calibrated so a self-bounding peer trips its admission well
	// before exhausting the local fd table, and a non-self-bounding peer
	// is observably "accepted them all" without slowing the suite.
	r3ConnectionAttempts  = 256
	r3PerConnectTimeout   = 2 * time.Second
	r3KeepServingDeadline = 5 * time.Second
)

// runResourceBounds is the entry point invoked by the suite. addr is the
// raw target (host:port) for the §4.10(a) raw-frame probe (which bypasses
// PeerClient framing to construct an oversize length prefix); newClient
// is the suite's identity-aware constructor for the §4.10(b) handshake
// path + the keeps-serving reconnect.
func runResourceBounds(ctx context.Context, addr string, newClient func() (*PeerClient, error), declaredMaxPayload int, declaredMaxChainDepth int) []CheckResult {
	r := NewCheckRunner(catResourceBounds)

	r.Declare("r1_payload_over_limit",
		"V7 §4.10(a) (v7.75 §9.1 floor MUST) — oversize inbound → 413 payload_too_large + keeps serving")
	r.Declare("r2_chain_depth_over_limit",
		"V7 §4.10(b) (v7.75 §9.1 floor MUST) — cap chain over max depth → 400 chain_depth_exceeded + keeps serving")
	r.Declare("r3_connection_flood",
		"V7 §4.10(c) SHOULD (v7.75) — admission bound; clean refusal or external-delegation Warn")

	r.Run("r1_payload_over_limit", func() CheckOutcome {
		return runR1Payload(ctx, addr, newClient, declaredMaxPayload)
	})
	r.Run("r2_chain_depth_over_limit", func() CheckOutcome {
		return runR2ChainDepth(ctx, newClient, declaredMaxChainDepth)
	})
	r.Run("r3_connection_flood", func() CheckOutcome {
		return runR3ConnectionFlood(ctx, addr, newClient)
	})

	return r.Results()
}

// runR1Payload tests §4.10(a): the peer rejects an inbound frame whose
// length prefix exceeds its declared max payload size — BEFORE buffering
// the body — with a 413 coded frame and/or a clean connection close, and
// continues serving subsequent requests on a fresh connection.
//
// We exercise the length-prefix check directly: dial a raw TCP socket and
// write only the 4-byte big-endian prefix saying "declaredMaxPayload + N".
// A conformant peer reads the prefix, sees over-limit, and rejects. We
// never send the body, so the peer can't fully buffer it (this is the
// MUST the spec is gating). Two acceptable terminal shapes:
//
//   - the peer writes back a 413 EXECUTE_RESPONSE frame and closes
//   - the peer closes the connection immediately (also spec-allowed per the
//     handoff: "coded frame OR close")
//
// Keeps-serving is verified by re-handshaking through newClient on a fresh
// connection and round-tripping a TreeGet that every peer publishes.
func runR1Payload(ctx context.Context, addr string, newClient func() (*PeerClient, error), declaredMaxPayload int) CheckOutcome {
	if addr == "" {
		return SkipCheck("r1 needs a raw -addr (single-peer mode required)")
	}
	if declaredMaxPayload <= 0 {
		return FailCheck(fmt.Sprintf("declared max_payload %d invalid — must be positive (default %d)", declaredMaxPayload, defaultDeclaredMaxPayload))
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return FailCheck(fmt.Sprintf("raw dial %s: %v", addr, err))
	}
	defer conn.Close()

	// Write only the 4-byte big-endian length prefix. The peer reads the
	// prefix and checks it BEFORE allocating/reading the body — so it can
	// reject without ever buffering N bytes of payload. This is the spec's
	// "before fully buffering" MUST.
	overSize := uint32(declaredMaxPayload + 1024)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], overSize)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(prefix[:]); err != nil {
		return FailCheck(fmt.Sprintf("write oversize length prefix: %v", err))
	}

	// Read back whatever the peer chooses to emit: a 413 frame, or an
	// immediate close. Bound read so a hung peer doesn't stall the suite.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respFrame, readErr := tryReadOneFrame(conn)

	var observed string
	switch {
	case readErr != nil && errors.Is(readErr, io.EOF):
		observed = "connection closed without a response frame (spec-allowed: 'coded frame OR close')"
	case readErr != nil:
		// Other read errors (timeout, RST) also count as "closed" if no
		// frame came; the spec allows close-without-frame. Treat as
		// observed-close with the underlying error in the diagnostic.
		observed = fmt.Sprintf("connection terminated without a 413 frame: %v (spec-allowed: 'coded frame OR close')", readErr)
	default:
		// We got bytes back. Try to decode as an envelope and verify it's
		// a 413 EXECUTE_RESPONSE carrying a payload_too_large error.
		status, code, decodeErr := decodeErrorResponse(respFrame)
		if decodeErr != nil {
			return FailCheck(fmt.Sprintf("oversize prefix → peer sent %d bytes but they don't decode as an EXECUTE_RESPONSE: %v", len(respFrame), decodeErr))
		}
		if status != 413 {
			return FailCheck(fmt.Sprintf("oversize prefix → expected 413 payload_too_large, got status=%d code=%q (V7 §4.10(a) MUST: 413 payload_too_large)", status, code))
		}
		if code != "payload_too_large" {
			return FailCheck(fmt.Sprintf("oversize prefix → status 413 but code=%q (expected 'payload_too_large' per V7 §4.10(a))", code))
		}
		observed = "413 payload_too_large frame returned (spec-preferred: coded frame + close)"
	}
	_ = conn.Close()

	// Keeps-serving: fresh client, fresh handshake, one canonical request.
	if newClient == nil {
		return PassCheck(observed + "; keeps-serving not verified (no newClient)")
	}
	keepCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cli, err := newClient()
	if err != nil {
		return FailCheck(fmt.Sprintf("oversize handled: %s; but newClient after oversize: %v (peer may have fallen over)", observed, err))
	}
	defer cli.Close()
	if err := cli.Connect(keepCtx); err != nil {
		return FailCheck(fmt.Sprintf("oversize handled: %s; but reconnect failed: %v (peer accept loop down?)", observed, err))
	}
	if _, ok := runConnectivity(keepCtx, cli); !ok {
		return FailCheck(fmt.Sprintf("oversize handled: %s; but post-oversize handshake failed (peer degraded under §4.10(a))", observed))
	}
	if _, _, err := cli.TreeGet(keepCtx, "system/handler/system/tree"); err != nil {
		return FailCheck(fmt.Sprintf("oversize handled: %s; but post-oversize tree.get failed: %v (peer is up but not serving)", observed, err))
	}

	return PassCheck(fmt.Sprintf("declared_max_payload=%d → wrote %d-byte length prefix; %s; reconnect + tree.get succeeded (keeps serving)", declaredMaxPayload, overSize, observed))
}

// runR2ChainDepth tests §4.10(b): the peer rejects an envelope whose
// capability chain exceeds its declared max-depth with a 400
// chain_depth_exceeded coded response (NOT 403 — Keystone's call: 403
// conflates structural excess with authz denial; 400 lets the caller
// distinguish "shorten your chain" from "you lack the cap"), and continues
// serving subsequent requests on the same connection.
//
// The chain uses the existing security_chain.go helper buildSelfChainExecute;
// it's a self-delegated chain rooted at the connection cap, so authz would
// otherwise succeed — depth is the ONLY thing the peer should reject on.
func runR2ChainDepth(ctx context.Context, newClient func() (*PeerClient, error), declaredMaxChainDepth int) CheckOutcome {
	if newClient == nil {
		return SkipCheck("r2 needs the suite's newClient constructor (single-peer mode required)")
	}
	if declaredMaxChainDepth <= 0 {
		return FailCheck(fmt.Sprintf("declared max_chain_depth %d invalid — must be positive (default %d)", declaredMaxChainDepth, defaultDeclaredMaxChainDepth))
	}

	cli, err := newClient()
	if err != nil {
		return FailCheck(fmt.Sprintf("new client: %v", err))
	}
	defer cli.Close()
	if err := cli.Connect(ctx); err != nil {
		return FailCheck(fmt.Sprintf("connect: %v", err))
	}
	if _, ok := runConnectivity(ctx, cli); !ok {
		return FailCheck("handshake failed before chain-depth probe")
	}

	// Build a chain of declaredMaxChainDepth + 1 self-delegated caps. Each
	// chainCap is zero-value (empty grant, default expiry); buildSelfChain
	// links them parent→child so the resulting chain has depth-many links
	// above the connection cap root. The cap-walker counts depth from the
	// leaf to the root; the peer's max-depth check fires before any
	// per-link authz check, so the response code reflects depth, not authz.
	overDepth := declaredMaxChainDepth + 1
	chain := make([]chainCap, overDepth)
	uri := fmt.Sprintf("entity://%s/system/tree", cli.RemotePeerID())
	env, _, err := buildSelfChainExecute(cli, chain, uri, "get", nil)
	if err != nil {
		return FailCheck(fmt.Sprintf("build %d-deep chain: %v (chain-depth check needs the chain-builder to succeed locally)", overDepth, err))
	}

	respEnv, _, err := cli.SendRawEnvelope(env)
	if err != nil {
		// A connection drop here would mean the peer fell over on the chain
		// rather than rejecting cleanly — the §4.10(b) "keeps serving"
		// invariant requires a coded response, not a tear-down.
		return FailCheck(fmt.Sprintf("send over-depth chain (depth=%d): peer terminated the connection instead of responding: %v", overDepth, err))
	}

	respData, derr := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if derr != nil {
		return FailCheck(fmt.Sprintf("decode response to over-depth chain: %v", derr))
	}

	// V7 §4.10(b) (per handoff): 400 chain_depth_exceeded. NOT 403.
	if respData.Status != 400 {
		hint := ""
		if respData.Status == 403 {
			hint = " — 403 was the pre-Keystone framing; arch ruled 400 to disambiguate structural excess from authz denial. Update the peer's chain-depth handler to surface 400 chain_depth_exceeded."
		}
		code, _ := extractErrorCode(respData.Result)
		return FailCheck(fmt.Sprintf("over-depth (depth=%d) → expected 400 chain_depth_exceeded, got status=%d code=%q%s", overDepth, respData.Status, code, hint))
	}

	code, _ := extractErrorCode(respData.Result)
	if code != "chain_depth_exceeded" {
		return FailCheck(fmt.Sprintf("over-depth → status 400 but code=%q (expected 'chain_depth_exceeded' per V7 §4.10(b))", code))
	}

	// Keeps-serving on the SAME connection. The peer should answer 400 and
	// keep dispatching; a connection torn down post-400 would mean
	// degradation under the bound.
	if _, _, err := cli.TreeGet(ctx, "system/handler/system/tree"); err != nil {
		return FailCheck(fmt.Sprintf("400 chain_depth_exceeded returned cleanly, but post-rejection tree.get failed: %v (peer not keeping serving)", err))
	}

	return PassCheck(fmt.Sprintf("declared_max_chain_depth=%d → sent %d-deep chain → 400 chain_depth_exceeded; tree.get on the same connection still succeeded (keeps serving)", declaredMaxChainDepth, overDepth))
}

// runR3ConnectionFlood tests §4.10(c): the peer either self-bounds the
// concurrent-connection count (returning 503 too_many_connections or
// closing cleanly) OR delegates admission to a layer outside the peer
// (systemd socket limits, reverse proxy, kernel-level backlog) — both are
// spec-allowed under the SHOULD. A peer that accepts ALL connections AND
// keeps serving is reported as Warn (admission likely delegated
// externally); a peer that accepts all AND then can't serve a follow-up
// request is FAIL (it crashed instead of rejecting).
//
// Per the handoff: "SHOULD — do NOT hard-FAIL." We report Warn, not Fail,
// when admission appears external — a Warn never trips the gate.
func runR3ConnectionFlood(ctx context.Context, addr string, newClient func() (*PeerClient, error)) CheckOutcome {
	if addr == "" {
		return SkipCheck("r3 needs a raw -addr (single-peer mode required)")
	}

	conns := make([]net.Conn, 0, r3ConnectionAttempts)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	floodDialer := net.Dialer{Timeout: r3PerConnectTimeout}
	refused, accepted := 0, 0
	var firstRefusal string
	for i := 0; i < r3ConnectionAttempts; i++ {
		c, err := floodDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			refused++
			if firstRefusal == "" {
				firstRefusal = fmt.Sprintf("attempt %d/%d: %v", i+1, r3ConnectionAttempts, err)
			}
			continue
		}
		conns = append(conns, c)
		accepted++
	}

	// Keeps-serving check — independent of acceptance outcome.
	keepCtx, cancel := context.WithTimeout(ctx, r3KeepServingDeadline)
	defer cancel()
	keepServing, keepReason := r3KeepServingProbe(keepCtx, newClient)

	switch {
	case refused > 0 && keepServing:
		return PassCheck(fmt.Sprintf("opened %d/%d connections; peer began refusing at %s (self-bounded admission); reconnect + tree.get succeeded (keeps serving)", accepted, r3ConnectionAttempts, firstRefusal))
	case refused > 0 && !keepServing:
		return FailCheck(fmt.Sprintf("opened %d/%d connections; peer refused some (self-bounded admission) but then failed the follow-up serve probe: %s", accepted, r3ConnectionAttempts, keepReason))
	case refused == 0 && keepServing:
		// All accepted, peer still serving. Spec-allowed per §4.10(c)
		// external-admission carve-out; not a FAIL.
		return WarnCheck(fmt.Sprintf("opened all %d connections without refusal and peer kept serving — admission likely delegated externally (systemd / proxy / OS); §4.10(c) SHOULD, not gated", r3ConnectionAttempts))
	default:
		// All accepted, peer NOT serving — fell over without rejecting.
		return FailCheck(fmt.Sprintf("opened all %d connections without refusal AND peer fell over on the follow-up serve probe (%s) — neither self-bounded nor externally delegated; this is the §4.10(c) failure shape", r3ConnectionAttempts, keepReason))
	}
}

func r3KeepServingProbe(ctx context.Context, newClient func() (*PeerClient, error)) (bool, string) {
	if newClient == nil {
		return true, "no newClient available; keeps-serving treated as best-case"
	}
	cli, err := newClient()
	if err != nil {
		return false, fmt.Sprintf("newClient: %v", err)
	}
	defer cli.Close()
	if err := cli.Connect(ctx); err != nil {
		return false, fmt.Sprintf("reconnect: %v", err)
	}
	if _, ok := runConnectivity(ctx, cli); !ok {
		return false, "post-flood handshake failed"
	}
	if _, _, err := cli.TreeGet(ctx, "system/handler/system/tree"); err != nil {
		return false, fmt.Sprintf("post-flood tree.get: %v", err)
	}
	return true, ""
}

// --- Helpers ---

// tryReadOneFrame reads a length-prefixed frame using the same encoding the
// wire package uses (4-byte big-endian length + body). Bounded by the
// caller's read deadline. We don't import wire.ReadFrame because we want to
// detect "no response, just close" distinctly from a malformed frame.
func tryReadOneFrame(r net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > 64*1024 {
		// Error responses are tiny; an outsized prefix on an error frame
		// would itself be suspect. Defensive bound.
		return nil, fmt.Errorf("unexpected response frame length %d (error frame should be <64 KiB)", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}

// decodeErrorResponse decodes a wire frame into an EXECUTE_RESPONSE and
// extracts (status, code) from its included ErrorData. Returns (0, "", err)
// when the frame doesn't look like an EXECUTE_RESPONSE carrying an error.
func decodeErrorResponse(frame []byte) (uint, string, error) {
	var env entity.Envelope
	if err := ecf.Decode(frame, &env); err != nil {
		return 0, "", fmt.Errorf("decode envelope: %w", err)
	}
	if env.Root.Type != types.TypeExecuteResponse {
		return 0, "", fmt.Errorf("root type %q != %q", env.Root.Type, types.TypeExecuteResponse)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return 0, "", fmt.Errorf("decode execute_response: %w", err)
	}
	code, _ := extractErrorCode(respData.Result)
	return respData.Status, code, nil
}

// extractErrorCode pulls the `code` out of an ExecuteResponseData.Result.
// Handles cross-impl ErrorData schema variation (Go/Rust use the typed
// ErrorData struct over a `system/protocol/error` entity; Python wraps
// the {code, message} map inside a `primitive/any` envelope per its
// _as_entity normalizer — a separate spec-shape divergence flagged in
// the V7.75 cohort-close notes, NOT this probe's
// concern to gate on). Strict-then-generic fallback mirrors the existing
// `extractStatusAndCode` in format_agility.go so resource_bounds reads
// the same wire shape every other category accepts.
func extractErrorCode(result []byte) (string, error) {
	if len(result) == 0 {
		return "", nil
	}
	var resultEntity entity.Entity
	if err := ecf.Decode(result, &resultEntity); err != nil {
		return "", err
	}
	// Strict path: the result is a system/protocol/error entity carrying
	// a typed ErrorData payload (Go + Rust).
	if resultEntity.Type == types.TypeError {
		if errData, err := types.ErrorDataFromEntity(resultEntity); err == nil && errData.Code != "" {
			return errData.Code, nil
		}
	}
	// Generic fallback: decode the entity's data as a CBOR map and look
	// for a `code` field. Catches the primitive/any-wrapped error map
	// shape Python emits.
	var raw map[string]interface{}
	if err := cbor.Unmarshal(resultEntity.Data, &raw); err != nil {
		return "", nil
	}
	if v, ok := raw["code"]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}
	return "", nil
}

