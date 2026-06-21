package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/tree"
)

// runRequestIDEchoProbe verifies V7 §6.11(b) / §3.3:742 — the peer MUST echo
// the EXECUTE's request_id on its EXECUTE_RESPONSE. request_id is the
// demultiplexing key responses are correlated by; a peer that blanks, drops,
// or rewrites it breaks out-of-order response routing (the §6.11 reentry
// contract) for any caller demuxing by id.
//
// Scope note (audit S2): this probes the PEER's echo behavior — the half
// that is a spec MUST and contained. The complementary CLIENT-side
// robustness — validate-peer's own PeerClient tolerating out-of-order /
// unsolicited frames by demuxing on request_id instead of strict
// write-then-read (the desync that mis-reported the C# leg-3 case) — is a
// PeerClient async-reader rework. It is FLAGGED for review, not done here:
// it touches ~10 Send* call sites and changes the read model, which is the
// "big refactoring" class the operator asked to surface rather than land
// silently.
func runRequestIDEchoProbe(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catConnectivity)
	r.Declare("request_id_echoed", "V7 §6.11(b) / §3.3:742 (request_id correlation)")

	if !client.Connected() {
		r.Run("request_id_echoed", func() CheckOutcome {
			return SkipCheck("client not connected/handshaked — cannot send authenticated EXECUTE")
		})
		return r.Results()
	}

	r.Run("request_id_echoed", func() CheckOutcome {
		// A benign read any conformant peer answers; status is irrelevant to
		// the echo property (even a 404 carries request_id). The id is
		// distinctive so an echo proves reflection of the *sent* id, not a
		// coincidental match against validate-peer's validate-N counter.
		const sentID = "rid-echo-probe-7f3a2c91"
		params, resource, err := tree.CreateGetRequest("system/tree", "entity")
		if err != nil {
			return FailCheck("build tree:get params: " + err.Error())
		}
		uri := fmt.Sprintf("entity://%s/system/tree", client.remotePeerID)
		gotID, status, err := client.SendExecuteWithExplicitID(ctx, sentID, uri, "get", params, resource)
		if err != nil {
			return FailCheck("request_id echo probe send/recv failed: " + err.Error())
		}
		if gotID == "" {
			return FailCheck(fmt.Sprintf("EXECUTE_RESPONSE carried an empty request_id (status %d) — breaks §6.11(b) demux-by-id", status))
		}
		if gotID != sentID {
			return FailCheck(fmt.Sprintf("request_id not echoed: sent %q, response carried %q (status %d) — §3.3:742 correlation broken", sentID, gotID, status))
		}
		return PassCheck(fmt.Sprintf("request_id echoed on EXECUTE_RESPONSE (%q, status %d)", gotID, status))
	})

	return r.Results()
}
