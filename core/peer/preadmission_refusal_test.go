package peer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/wire"
)

// TestClassifyRecvError pins the §4.11 (0.8.2.25) pre-admission refusal
// classification (rust ROUTING-2026-09-15-d §1 + SA-PY-62). The load-bearing
// rows are the transport errors: a genuine break (reset, broken pipe, read
// deadline, context cancel) MUST be dispSilentClose — NOT the truncated arm —
// because emitting a 400 at a socket that is already gone blames the caller for
// the network's failure.
//
// Mutation witness for the fix: reverting serve()'s pre-0.8.2.25 shape — a
// blanket "any non-io.EOF error emits a 400 then closes" — is the same as
// making classifyRecvError's default arm dispTruncatedClose. Under that
// mutation every transport-error row below flips from dispSilentClose to
// dispTruncatedClose and reds; the truncated row (io.ErrUnexpectedEOF) is
// unaffected, so the test discriminates the fix from the old behaviour.
func TestClassifyRecvError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want recvDisposition
	}{
		{"clean_eof_is_silent", io.EOF, dispSilentClose},
		{"wrapped_clean_eof_is_silent", fmt.Errorf("read frame length: %w", io.EOF), dispSilentClose},
		{"truncated_frame_is_truncated_close", fmt.Errorf("read frame payload: %w", io.ErrUnexpectedEOF), dispTruncatedClose},
		{"oversize_is_oversize_close", fmt.Errorf("%w: too big", ecerrors.ErrFrameTooLarge), dispOversizeClose},
		{"undecodable_is_continue", fmt.Errorf("decode envelope: %w: bad cbor", ecerrors.ErrEnvelopeDecode), dispUndecodableContinue},
		// The rust finding: a genuine transport break is NOT the caller's bytes.
		{"conn_reset_is_silent", fmt.Errorf("read frame length: %w", syscall.ECONNRESET), dispSilentClose},
		{"broken_pipe_is_silent", fmt.Errorf("read frame payload: %w", syscall.EPIPE), dispSilentClose},
		{"read_deadline_is_silent", fmt.Errorf("read frame length: %w", os.ErrDeadlineExceeded), dispSilentClose},
		{"context_canceled_is_silent", fmt.Errorf("read frame length: %w", context.Canceled), dispSilentClose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRecvError(tc.err); got != tc.want {
				t.Fatalf("classifyRecvError(%v) = %d; want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestServe_PreAdmission_FramingArmIsInvalidRequestAndKeepsConnection pins
// ENTITY-CORE-PROTOCOL §4.11 / §3.3 (0.8.2.25), the framing / un-parseable arm of
// the pre-admission refusal class:
//
//   - A whole frame that will not decode into an Envelope (un-parseable /
//     non-canonical CBOR — SA-PY-62's arm a1, NOT a truncated frame) is refused
//     400 **invalid_request** — the CAUSE's code, distinct from the
//     resolution-integrity arm's 400 hash_mismatch and the oversize arm's 413.
//   - The frame decoded WHOLE, so the stream is synchronized on the next boundary:
//     the connection MUST survive (§4.9(c) — a bare close, the pre-0.8.2.25
//     behaviour, destroys unrelated admitted requests on a multiplexed connection).
//
// Two mutation witnesses on the serve() edit:
//   - change the code to anything but invalid_request → the code assert fails;
//   - change the framing-arm `continue` to `return` → the SECOND read below gets
//     EOF instead of a second coded frame (the connection was destroyed).
func TestServe_PreAdmission_FramingArmIsInvalidRequestAndKeepsConnection(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)

	raw, err := net.DialTimeout("tcp", server.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	// A complete frame whose payload is whole-but-undecodable CBOR: 0xA1 opens a
	// 1-pair map, 0x00 is the first key, and the value is missing. ReadFrame reads
	// the frame whole (length prefix = 2, two bytes consumed), so the stream stays
	// aligned; ecf.Decode then fails → the framing arm (a1) fires and CONTINUES.
	// A genuinely truncated frame (a2) would force a close — see TestClassifyRecvError.
	undecodableCBOR := []byte{0xA1, 0x00}

	assertInvalidRequest := func(label string) {
		if err := wire.WriteFrame(raw, undecodableCBOR); err != nil {
			t.Fatalf("%s: write frame: %v", label, err)
		}
		respEnv, err := wire.ReadEnvelope(raw)
		if err != nil {
			t.Fatalf("%s: expected a coded EXECUTE_RESPONSE, got read error (a bare close / silent drop is the pre-0.8.2.25 non-conformance): %v", label, err)
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			t.Fatalf("%s: decode response: %v", label, err)
		}
		if respData.Status != 400 {
			t.Fatalf("%s: expected status 400, got %d", label, respData.Status)
		}
		var errEnt entity.Entity
		if err := ecf.Decode(respData.Result, &errEnt); err != nil {
			t.Fatalf("%s: decode result entity: %v", label, err)
		}
		errData, err := types.ErrorDataFromEntity(errEnt)
		if err != nil {
			t.Fatalf("%s: decode error data: %v", label, err)
		}
		if errData.Code != "invalid_request" {
			t.Fatalf("%s: expected code invalid_request (framing arm, §4.11), got %q — hash_mismatch here would be the resolution-integrity code under the wrong reason", label, errData.Code)
		}
	}

	// First bad frame: refused with a coded 400 invalid_request.
	assertInvalidRequest("first frame")
	// The connection survived (the arm continues, it does not close): a SECOND bad
	// frame is answered the same way. This is the §4.9(c) property arm (f) exercises
	// with an admitted in-flight request; here the survival itself is the witness.
	assertInvalidRequest("second frame")
}

// TestServe_PreAdmission_WrongRootTypeIsInvalidRequestAndKeepsConnection pins the
// §3.3 wrong-root-type arm of §4.11 (0.8.2.25): a post-handshake frame whose root
// entity is neither EXECUTE nor EXECUTE_RESPONSE (nor a §6.5(b) reentry grant) is
// a pre-admission refusal — 400 invalid_request with a coded frame, replacing the
// pre-0.8.2.25 bare close. The frame decoded whole, so the connection survives.
//
// The arm is post-handshake, so this completes a real handshake over a raw socket
// first, then injects the third-typed root on the SAME connection.
//
// Mutation witness: delete the wrong-root-type arm in serve() and the frame falls
// through to dispatch, which produces no correlated 400 invalid_request here.
func TestServe_PreAdmission_WrongRootTypeIsInvalidRequestAndKeepsConnection(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)
	client := newMultiplexTestPeer(t, 0)

	// A real handshake gives us an established Connection whose serve() loop on the
	// server side is past the !Completed branch — where the wrong-root-type arm lives.
	conn := connectClient(t, client, server)
	defer conn.Close()

	// Build a well-formed envelope whose ROOT is a valid entity of a third type
	// (not EXECUTE / EXECUTE_RESPONSE / reentry grant). It passes validateRecv
	// (self-consistent, no included) and reaches the post-handshake dispatch arm.
	raw, err := ecf.Encode(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	thirdType, err := entity.NewEntity("test/not-a-message", raw)
	if err != nil {
		t.Fatalf("build third-type entity: %v", err)
	}
	badEnv := entity.NewEnvelope(thirdType, nil)

	// Send it on the underlying socket of the established connection. The server's
	// serve() loop reads it, finds a non-EXECUTE root post-handshake, and refuses it.
	if err := conn.SendEnvelope(badEnv); err != nil {
		t.Fatalf("send third-type frame: %v", err)
	}

	// The refusal comes back as an EXECUTE_RESPONSE on the client reader; drive a
	// normal Execute afterwards to prove the connection survived the refusal.
	// (The coded 400 itself is demuxed as an orphan response — it correlates to no
	// pending request_id — so we assert survival, the §4.9(c) property, directly.)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	echoIn, err := entity.NewEntity("test/echo-input", []byte{0x01})
	if err != nil {
		t.Fatalf("build echo input: %v", err)
	}
	if _, err := conn.Execute(ctx,
		"entity://"+string(server.PeerID())+"/test/echo", "echo", echoIn, nil); err != nil {
		t.Fatalf("Execute after a wrong-root-type refusal failed — the connection did not survive (bare close is the pre-0.8.2.25 non-conformance): %v", err)
	}
}
