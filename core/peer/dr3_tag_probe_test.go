package peer

import (
	"context"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TestDR3_TagInDataFieldRefused pins ENTITY-CBOR-ENCODING §6.3 / 0.8.2.26 DR-3
// at the wire: a received frame carrying a CBOR tag (major type 6) in a
// data-field position is refused 400 non_canonical_ecf, and its untagged twin —
// otherwise identical — succeeds (200). It is the gate for the drive rust
// ROUTING-2026-09-16-a §3 and py item A asked go for, and it answers SA-PY-66's
// width question (below): go implements the WIDE reading (any depth), matching
// entity-core-{rust,py}.
//
// The echo handler decodes {marker} and ignores unknown map keys. Every request
// carries a valid marker, so the handler would answer 200; the ONLY variable is
// a tag, so a 400 is attributable to the tag policy and nothing else. The
// untagged control proving 200 is the carry-the-teeth guard: without it, a 400
// for an unrelated reason would read as a pass.
//
// Mutation witness: delete the ecf.ForbidTags calls in Envelope.ValidateAll and
// every tagged row below is admitted (200) — the pre-fix state, measured before
// this fix landed (both rows 200). The untagged controls are unaffected.
func TestDR3_TagInDataFieldRefused(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)
	client := newMultiplexTestPeer(t, 0)

	// {"t": <v>, "marker": "x"} in canonical ECF key order ("t" before "marker").
	// The handler reads "marker" and ignores "t"; <v> is where a tag rides.
	prefix := []byte{0xA2, 0x61, 0x74}                                     // map(2), key "t"
	suffix := []byte{0x66, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x72, 0x61, 0x78} // key "marker", value "x"
	with := func(v []byte) []byte {
		return append(append(append([]byte{}, prefix...), v...), suffix...)
	}

	// A fresh connection per drive: go's serve() emits the coded 400 and then
	// closes on a validateRecv refusal (the landed N4 behaviour), so a reused
	// connection is dead after the first tagged frame. The close is a separate,
	// pre-existing choice (whether a whole-decoded semantic-validation failure
	// should survive per §4.9(c) is the .25 pre-admission question, not DR-3);
	// this gate isolates the tag verdict from it.
	drive := func(t *testing.T, data []byte) (uint, string) {
		t.Helper()
		conn := connectClient(t, client, server)
		defer conn.Close()
		params, err := entity.NewEntity("test/echo-input", data)
		if err != nil {
			t.Fatalf("build params: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		respEnv, err := conn.Execute(ctx,
			"entity://"+string(server.PeerID())+"/test/echo", "echo", params, nil)
		if err != nil {
			t.Fatalf("Execute transport error: %v", err)
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		code := ""
		if respData.Status != 200 {
			var errEnt entity.Entity
			if err := ecf.Decode(respData.Result, &errEnt); err == nil {
				if errData, err := types.ErrorDataFromEntity(errEnt); err == nil {
					code = errData.Code
				}
			}
		}
		return respData.Status, code
	}

	cases := []struct {
		name    string
		data    []byte
		want400 bool // true = expect 400 non_canonical_ecf; false = expect 200
	}{
		// Untagged control: the value is plain text "y" → handler answers 200.
		{"untagged_control", with([]byte{0x61, 0x79}), false},
		// Tag 0 ("y") at a data-field position → refused.
		{"tag0_at_field", with([]byte{0xC0, 0x61, 0x79}), true},
		// Tag 0 nested one array deeper ([0("y")]) → refused (any depth).
		{"tag0_nested_in_array", with([]byte{0x81, 0xC0, 0x61, 0x79}), true},
		// SA-PY-66 / item A: tag 55799 (the CBOR self-describe marker, the one
		// real encoders emit by accident) wrapping the WHOLE data value. Under the
		// narrow row-(5a) "data-field position" reading this is arguably not in a
		// data-field position; under §6.3 "any depth" it is forbidden. go answers
		// the WIDE reading — 400 non_canonical_ecf.
		{"tag55799_wrapping_payload", append([]byte{0xD9, 0xD9, 0xF7}, with([]byte{0x61, 0x79})...), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code := drive(t, tc.data)
			t.Logf("%s -> status=%d code=%q", tc.name, status, code)
			if tc.want400 {
				if status != 400 || code != "non_canonical_ecf" {
					t.Fatalf("%s: want 400 non_canonical_ecf, got %d %q", tc.name, status, code)
				}
			} else {
				if status != 200 {
					t.Fatalf("%s: control must succeed (else a 400 is unattributable), got %d %q", tc.name, status, code)
				}
			}
		})
	}
}

// TestDR3_TagRefusalKeepsConnection pins §4.9(c) / the .25 stream-synchronized
// property for the DR-3 refusal: a tagged frame decoded WHOLE, so the connection
// MUST survive the coded 400 non_canonical_ecf — a subsequent untagged request on
// the SAME connection succeeds. This is what makes go match entity-core-{rust,py}
// (whose tag rejection continues) and is the fix for the release-gate cascade: the
// CAP-6a ingest check mints an out-of-range temporal field, which go's ECF encoder
// serialises as a CBOR bignum tag; a close there would destroy the shared
// connection and cascade to every later category.
//
// Mutation witness: change serve()'s ErrNonCanonicalECF arm from `continue` back
// to `return` (the N4 close) and the second Execute below fails with a transport
// error — the connection did not survive.
func TestDR3_TagRefusalKeepsConnection(t *testing.T) {
	server := newMultiplexTestPeer(t, 0)
	client := newMultiplexTestPeer(t, 0)
	conn := connectClient(t, client, server)
	defer conn.Close()

	echoURI := "entity://" + string(server.PeerID()) + "/test/echo"
	marker := []byte{0xA1, 0x66, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x72, 0x61, 0x78} // {"marker":"x"}
	tagged := []byte{0xC0, 0x61, 0x78}                                           // 0("x") — a bare tag

	send := func(data []byte) (uint, string, error) {
		params, err := entity.NewEntity("test/echo-input", data)
		if err != nil {
			t.Fatalf("build params: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		respEnv, err := conn.Execute(ctx, echoURI, "echo", params, nil)
		if err != nil {
			return 0, "", err
		}
		respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		code := ""
		if respData.Status != 200 {
			var errEnt entity.Entity
			if err := ecf.Decode(respData.Result, &errEnt); err == nil {
				if ed, err := types.ErrorDataFromEntity(errEnt); err == nil {
					code = ed.Code
				}
			}
		}
		return respData.Status, code, nil
	}

	// 1. A tagged frame is refused 400 non_canonical_ecf without a transport error.
	status, code, err := send(tagged)
	if err != nil {
		t.Fatalf("tagged send: transport error (a close BEFORE the coded frame is non-conformant): %v", err)
	}
	if status != 400 || code != "non_canonical_ecf" {
		t.Fatalf("tagged: want 400 non_canonical_ecf, got %d %q", status, code)
	}

	// 2. The SAME connection still serves a normal request — it was not closed.
	status2, _, err := send(marker)
	if err != nil {
		t.Fatalf("post-refusal send: the connection did not survive the tag refusal (§4.9(c) violation — the pre-fix N4 close): %v", err)
	}
	if status2 != 200 {
		t.Fatalf("post-refusal request: want 200, got %d", status2)
	}
}
