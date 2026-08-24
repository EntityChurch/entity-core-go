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
//     body-supplied value.
//   - check-reachability (§6.7.2): the peer dials back OUR observed source
//     (never a body value) — but network-dialback is §6.7.4-restricted, so a
//     peer that has not granted it answers 403.
//
// §6.7 IS OPTIONAL AS A WHOLE and these checks MUST NOT treat its absence as a
// failure. §12.3: "a peer MAY offer observe-address, check-reachability, both,
// or neither. Offering neither is fully conformant: a requester that gets a 403
// or an unimplemented response proceeds to another reflector." What is not
// optional is getting them right WHEN OFFERED (§12.1) — every rule inside §6.7
// is a MUST for a peer that offers it, because each is a cross-peer seam.
//
// So the shape of these checks is: an unimplemented response ends the check as a
// SKIP (conformant, but nothing was exercised — and Skip rather than Pass so a
// peer regressing from a working 200 to an unimplemented response cannot read as
// green); anything that IS an answer is then held to every §6.7 MUST.
//
// This was got wrong here, and both siblings were reported against it. The
// original checks demanded 200-or-403 and called an unimplemented response
// non-conformant, which produced a FAIL against rust (400 unknown_operation)
// and two against py (501 unsupported_operation) in the 2026-08-07 sweep.
// core-rust caught it and routed it back with the §12.3 citation. The bias
// worth naming: this validator encodes Go's reading of the spec, Go HAS both
// operations, and a check written from a feature you already have quietly
// promotes "I implement this" into "you must." Reserved for MUSTs.
//
// The full §6.7.5 gate (reachable=true across a real NAT, cross-impl) is beyond
// a single-target validator; this pins the wire shape and the two security
// MUSTs.
func runReachability(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catReachability)
	r.Declare("reachability_observe_address", "§6.7.1 — observe-address reflects our transport source, never a body value (§12.3: offering it at all is OPTIONAL)")
	r.Declare("reachability_observed_not_persisted", "§6.7.1 MUST 2 — the observed address MUST NOT be persisted to any durable per-peer address field (system/connection.address, system/peer/transport/*, system/peer/status). A responder-side fact written into dialer-side state corrupts §10 dispatch for every other reader")
	r.Declare("reachability_dialback_posture", "§6.7.2/§6.7.4 — check-reachability dials our observed source, or is restricted (403) (§12.3: offering it at all is OPTIONAL)")

	if client == nil || !client.Connected() {
		r.Run("reachability_observe_address", func() CheckOutcome {
			return SkipCheck("client not connected — reachability facts ride an established connection")
		})
		r.Run("reachability_observed_not_persisted", func() CheckOutcome {
			return SkipCheck("client not connected")
		})
		r.Run("reachability_dialback_posture", func() CheckOutcome {
			return SkipCheck("client not connected")
		})
		return r.Results()
	}

	uri := fmt.Sprintf("entity://%s/system/network", client.RemotePeerID())

	// Filled in by the MUST 1 check below and consumed by MUST 2.
	var observedAddr string

	// A body-supplied address the handler must ignore, on both ops.
	bogus, err := types.ObserveAddressResultData{ObservedAddress: bogusReachAddr}.ToEntity()
	if err != nil {
		r.Run("reachability_observe_address", func() CheckOutcome { return FailCheck("build params: " + err.Error()) })
		r.Run("reachability_observed_not_persisted", func() CheckOutcome { return SkipCheck("params build failed") })
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
		if decl, ok := declinesSection67(status, code); ok {
			return SkipCheck("§6.7.1 observe-address NOT OFFERED (" + decl + ") — §12.3 makes §6.7 optional as a whole and an unimplemented response fully conformant, so this is NOT a failure. Skip rather than Pass: nothing about reflection was exercised, and a peer regressing from a working 200 to an unimplemented response must not read as green.  THIS PROJECT IMPLEMENTS EVERYTHING: an unimplemented surface is an UNTESTED surface, so this counts toward the run's FAIL gate and must be closed by building §6.7 — do NOT wave it through with -allow-skip.")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("observe-address returned %d code %q — neither a §6.7.1 answer (200) nor a §12.3 decline (403 / unimplemented)", status, code))
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
		observedAddr = obs.ObservedAddress
		return PassCheck(fmt.Sprintf("§6.7.1 observe-address reflected our real transport source %s (body-supplied address ignored)", obs.ObservedAddress))
	})

	// MUST 2 reuses MUST 1's answer: the value the peer told us it observed is
	// exactly the value that must not appear in durable state.
	r.Run("reachability_observed_not_persisted", func() CheckOutcome {
		return runReachabilityObservedNotPersisted(ctx, client, observedAddr)
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
		if decl, ok := declinesSection67(status, code); ok {
			return SkipCheck("§6.7.2 check-reachability NOT OFFERED (" + decl + ") — §12.3 makes §6.7 optional as a whole and an unimplemented response fully conformant, so this is NOT a failure. Skip rather than Pass: nothing about dial-back was exercised.  THIS PROJECT IMPLEMENTS EVERYTHING: an unimplemented surface is an UNTESTED surface, so this counts toward the run's FAIL gate and must be closed by building §6.7 — do NOT wave it through with -allow-skip.")
		}
		if status != 200 {
			return FailCheck(fmt.Sprintf("check-reachability returned %d code %q — neither a §6.7.2 answer (200) nor a §12.3 decline (403 / unimplemented)", status, code))
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

// declinesSection67 reports whether a response is an EXTENSION-NETWORK §12.3
// "unimplemented response" — a peer conformantly declining to offer a §6.7
// operation — and returns a short human description of the form it took.
//
// The spec names the class ("a 403 or an unimplemented response") without
// enumerating status codes, so this accepts every shape a peer can decline in:
//
//   - 501 unsupported_operation — the canonical form (ENTITY-CORE-PROTOCOL:
//     "a handler IS registered at the path, but does not implement the named
//     operation"). entity-core-py answers this.
//   - 400 unknown_operation — the same meaning from a handler that validates
//     the operation name before dispatch. entity-core-rust answered this.
//   - 404 handler_not_found — no system/network handler at all, which is a
//     stronger decline than either of the above.
//
// 403 is handled separately by each check, because for check-reachability it
// means something more specific (network-dialback is §6.7.4-restricted and was
// not granted on this connection) than "not offered."
func declinesSection67(status uint, code string) (string, bool) {
	switch {
	case status == 501:
		return fmt.Sprintf("%d %s", status, code), true
	case status == 404:
		return fmt.Sprintf("%d %s — no system/network handler", status, code), true
	case status == 400 && (code == "unknown_operation" || code == "unsupported_operation"):
		return fmt.Sprintf("%d %s", status, code), true
	}
	return "", false
}
