package validate

import "context"

const catConnectivity = "connectivity"

// RunConnectivity is the exported alias; external callers (e.g.,
// validate-peer main wiring a non-suite category like
// conformance_passthrough) use this. The internal callers continue to
// use the unexported runConnectivity to keep the call graph stable.
func RunConnectivity(ctx context.Context, client *PeerClient) ([]CheckResult, bool) {
	return runConnectivity(ctx, client)
}

// runConnectivity performs connection and handshake checks.
// Returns the check results and whether the client is ready for further checks.
func runConnectivity(ctx context.Context, client *PeerClient) ([]CheckResult, bool) {
	r := NewCheckRunner(catConnectivity)

	// --- Declare all checks ---

	r.Declare("tcp_connect", "V7 §8")

	// --- Run checks ---

	r.Run("tcp_connect", func() CheckOutcome {
		if err := client.Connect(ctx); err != nil {
			return FailCheck("TCP connection failed: " + err.Error())
		}
		return PassCheck("TCP connection established")
	})

	// Handshake sub-checks are produced by PerformHandshake (in client.go).
	// These use the old CheckResult API directly — append them after our
	// runner-managed checks.
	results := r.Results()

	if !r.Passed("tcp_connect") {
		return results, false
	}

	connectChecks := client.PerformHandshake(ctx)
	results = append(results, connectChecks...)

	// SPEC-FINDING F12: negative proof-of-possession probes (nonce-echo +
	// signature verification at §4.6). These use fresh connections, so they
	// run independent of the main handshake's success.
	results = append(results, runHandshakeProofChecks(ctx, client.Addr())...)

	// S2: request_id correlation — the peer MUST echo the EXECUTE's
	// request_id (§6.11(b)/§3.3:742). Runs on the established connection.
	results = append(results, runRequestIDEchoProbe(ctx, client)...)

	return results, client.Connected()
}
