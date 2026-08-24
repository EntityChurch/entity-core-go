package validate

import (
	"context"
	"fmt"
	"net"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
)

const catReachability = "reachability"

// bogusReachAddr is a body-supplied address a conformant peer MUST ignore
// (§6.7.1 MUST 1 / §6.7.2 anti-reflector MUST). If a peer ever echoes the
// request body, these checks see it.
const bogusReachAddr = "6.6.6.6:6666"

// runReachability drives EXTENSION-NETWORK §6.7 reachability facts against the
// live target peer:
//
//   - observe-address (§6.7.1): the peer reflects OUR transport source, never a
//     body-supplied value. Gated by network-reflect, which §6.7.4 makes a broad
//     default grant — so a conformant peer answers 200.
//   - check-reachability (§6.7.2): the peer dials back OUR observed source
//     (never a body value) — but network-dialback is §6.7.4-restricted, so a
//     peer that has not granted it answers 403. Both are conformant posture;
//     only a body-echoed address or a 5xx is a failure.
//
// The full §6.7.5 gate (reachable=true across a real NAT, cross-impl) is beyond
// a single-target validator; this pins the wire shape and the two security
// MUSTs. Go-green today; run it against Rust/Py the moment they build §6.7.
func runReachability(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catReachability)
	r.Declare("reachability_observe_address", "§6.7.1 — observe-address reflects our transport source, never a body value")
	r.Declare("reachability_dialback_posture", "§6.7.2/§6.7.4 — check-reachability dials our observed source, or is restricted (403)")

	if client == nil || !client.Connected() {
		r.Run("reachability_observe_address", func() CheckOutcome {
			return SkipCheck("client not connected — reachability facts ride an established connection")
		})
		r.Run("reachability_dialback_posture", func() CheckOutcome {
			return SkipCheck("client not connected")
		})
		return r.Results()
	}

	uri := fmt.Sprintf("entity://%s/system/network", client.RemotePeerID())

	// A body-supplied address the handler must ignore, on both ops.
	bogus, err := types.ObserveAddressResultData{ObservedAddress: bogusReachAddr}.ToEntity()
	if err != nil {
		r.Run("reachability_observe_address", func() CheckOutcome { return FailCheck("build params: " + err.Error()) })
		r.Run("reachability_dialback_posture", func() CheckOutcome { return SkipCheck("params build failed") })
		return r.Results()
	}

	r.Run("reachability_observe_address", func() CheckOutcome {
		respEnv, _, err := client.SendExecute(ctx, uri, "observe-address", bogus, nil)
		if err != nil {
			return FailCheck("observe-address send/recv: " + err.Error())
		}
		status, code, resp, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("decode observe-address response: " + err.Error())
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("observe-address returned %d code %q — §6.7.4 makes network-reflect a broad default grant, so a conformant peer answers 200", status, code))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
			return FailCheck("decode observe-address result entity: " + err.Error())
		}
		if resultEnt.Type != types.TypeNetworkObserveAddressResult {
			return FailCheck(fmt.Sprintf("result type %q, want %q (§6.7.1)", resultEnt.Type, types.TypeNetworkObserveAddressResult))
		}
		obs, err := types.ObserveAddressResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode observe-address-result: " + err.Error())
		}
		if obs.ObservedAddress == bogusReachAddr {
			return FailCheck(fmt.Sprintf("observed_address echoed the body-supplied %q — §6.7.1 MUST 1 violation (the peer is a laundering service)", bogusReachAddr))
		}
		if _, _, err := net.SplitHostPort(obs.ObservedAddress); err != nil {
			return FailCheck(fmt.Sprintf("observed_address %q is not a valid host:port — §6.7.1 returns the transport source", obs.ObservedAddress))
		}
		return PassCheck(fmt.Sprintf("§6.7.1 observe-address reflected our real transport source %s (body-supplied address ignored)", obs.ObservedAddress))
	})

	r.Run("reachability_dialback_posture", func() CheckOutcome {
		respEnv, _, err := client.SendExecute(ctx, uri, "check-reachability", bogus, nil)
		if err != nil {
			return FailCheck("check-reachability send/recv: " + err.Error())
		}
		status, code, resp, err := extractStatusAndCode(respEnv)
		if err != nil {
			return FailCheck("decode check-reachability response: " + err.Error())
		}
		if status == 403 {
			return SkipCheck("check-reachability 403 — network-dialback is §6.7.4-restricted and this connection was not granted it; conformant posture, grant it to exercise the dial-back")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("check-reachability returned %d code %q — want 200 (dial-back) or 403 (restricted); nothing else is conformant", status, code))
		}
		var resultEnt entity.Entity
		if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
			return FailCheck("decode check-reachability result entity: " + err.Error())
		}
		if resultEnt.Type != types.TypeNetworkCheckReachabilityResult {
			return FailCheck(fmt.Sprintf("result type %q, want %q (§6.7.2)", resultEnt.Type, types.TypeNetworkCheckReachabilityResult))
		}
		chk, err := types.CheckReachabilityResultDataFromEntity(resultEnt)
		if err != nil {
			return FailCheck("decode check-reachability-result: " + err.Error())
		}
		if chk.AddressTested == bogusReachAddr {
			return FailCheck(fmt.Sprintf("address_tested is the body-supplied %q — §6.7.2 anti-reflector MUST violation (every dial-back peer becomes a DDoS reflector)", bogusReachAddr))
		}
		if _, _, err := net.SplitHostPort(chk.AddressTested); err != nil {
			return FailCheck(fmt.Sprintf("address_tested %q is not a valid host:port", chk.AddressTested))
		}
		return PassCheck(fmt.Sprintf("§6.7.2 check-reachability dialed our observed source %s (reachable=%t; body-supplied address ignored)", chk.AddressTested, chk.Reachable))
	})

	return r.Results()
}
