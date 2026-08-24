package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

// runKeepalivePingProbe probes the §5.1 application-level keepalive exchange
// (EXTENSION-NETWORK §12.1 MUST — Amendment 12 rung 2, the escalation half
// of the §A3 liveness floor): EXECUTE system/protocol/connect op "ping" on
// the ESTABLISHED session returns 200 with a system/network/pong echoing the
// ping's timestamp + sequence and stamping server_time (§5.2/§5.3).
//
// Full-profile only: the V7 §9.0 core profile scores the connect handler's
// handshake pair; keepalive is NETWORK-extension conformance. A peer that
// has not built rung 2 FAILs here — that is the §D convergence signal, not a
// gate (route it into the per-peer report, don't block the cycle on it).
func runKeepalivePingProbe(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catConnectivity)
	r.Declare("keepalive_ping_pong", "EXTENSION-NETWORK §5.1/§12.1 (Amendment 12 rung 2)")

	if client.Profile() == ProfileCore {
		r.Run("keepalive_ping_pong", func() CheckOutcome {
			return SkipCheck("outside --profile core (NETWORK-extension keepalive, V7 §9.0)")
		})
		return r.Results()
	}
	if !client.Connected() {
		r.Run("keepalive_ping_pong", func() CheckOutcome {
			return SkipCheck("client not connected/handshaked — keepalive rides an established session")
		})
		return r.Results()
	}

	r.Run("keepalive_ping_pong", func() CheckOutcome {
		// Distinctive values so the echo proves reflection, not defaults.
		const sentTS, sentSeq = uint64(1709740800123), uint64(42)
		ping, err := types.PingData{Timestamp: sentTS, Sequence: sentSeq}.ToEntity()
		if err != nil {
			return FailCheck("build ping params: " + err.Error())
		}
		uri := fmt.Sprintf("entity://%s/system/protocol/connect", client.RemotePeerID())
		respEnv, _, err := client.SendExecute(ctx, uri, "ping", ping, nil)
		if err != nil {
			return FailCheck("ping send/recv failed: " + err.Error())
		}
		status, code, resp, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("decode ping response: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("ping returned status %d code %q — §12.1 makes the §5.1 keepalive exchange MUST", status, code))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
			return FailCheck("decode ping result entity: " + err.Error())
		}
		if resultEnt.Type != types.TypeNetworkPong {
			return FailCheck(fmt.Sprintf("ping result type %q, want %q (§5.3)", resultEnt.Type, types.TypeNetworkPong))
		}
		var pong types.PongData
		if err := ecf.Decode(resultEnt.Data, &pong); err != nil {
			return FailCheck("decode pong data: " + err.Error())
		}
		if pong.Timestamp != sentTS || pong.Sequence != sentSeq {
			return FailCheck(fmt.Sprintf("pong did not echo ping (§5.3): sent ts=%d seq=%d, got ts=%d seq=%d", sentTS, sentSeq, pong.Timestamp, pong.Sequence))
		}
		if pong.ServerTime == 0 {
			return FailCheck("pong missing server_time (§5.3 required field)")
		}
		return PassCheck(fmt.Sprintf("§5.1 ping/pong exchange conformant (seq %d echoed, server_time %d)", pong.Sequence, pong.ServerTime))
	})

	return r.Results()
}
