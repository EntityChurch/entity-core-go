package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"

	"github.com/fxamacker/cbor/v2"
)

// Reachability facts — EXTENSION-NETWORK §6.7 (Amendment 13). Three pure
// transport facts a peer needs to reason about its own reachability, plus the
// two capabilities that gate the two operations. The punch-coordination
// protocol that exchanges and acts on these facts is deliberately NOT here
// (§6.7.3: "gathering is a local fact, exchanging is a protocol").
const (
	// TypeNetworkObserveAddressResult is the §6.7.1 observe-address output:
	// the transport source IP:port the responder observed on THIS connection
	// (the requester's public NAT mapping). NEVER a body-echoed value.
	TypeNetworkObserveAddressResult = "system/network/observe-address-result"
	// TypeNetworkCheckReachabilityResult is the §6.7.2 check-reachability
	// output: whether the responder's dial-back to the requester's observed
	// source succeeded, and which address was proved.
	TypeNetworkCheckReachabilityResult = "system/network/check-reachability-result"
	// TypeNetworkCandidate is the §6.7.3 typed candidate address a peer might
	// be reached at. Session-scoped and ephemeral — MUST NOT be modeled as a
	// durable system/peer/transport/* profile (§6.7.3 MUST).
	TypeNetworkCandidate = "system/network/candidate"
)

const (
	// CapNetworkReflect gates observe-address (§6.7.1 / §6.7.4). A broad
	// default grant is reasonable — the op only echoes the source address the
	// peer itself observed, leaking nothing the requester does not already
	// imply by connecting. Still rate-limited. Wired into
	// DefaultConnectionGrants (protocol §4.4).
	CapNetworkReflect = "system/capability/network-reflect"
	// CapNetworkDialback gates check-reachability (§6.7.2 / §6.7.4).
	// Restricted — dial-back causes the responder to emit traffic at an
	// address, so it is NOT an open default grant; a peer SHOULD grant it only
	// to peers it is actively connecting with. Always rate-limited per
	// requester.
	CapNetworkDialback = "system/capability/network-dialback"
)

// Candidate type values (§6.7.3). Ordering host → srflx → relay is the
// session-scoped extension of §10's (priority asc, profile-id lex) try order.
const (
	CandidateTypeHost  = "host"  // local/LAN address — highest priority (cheapest)
	CandidateTypeSrflx = "srflx" // server-reflexive: the §6.7.1 observed mapping — the punch target
	CandidateTypeRelay = "relay" // a public relay address — the always-works fallback
)

// Candidate substrate values (§6.7.3) — which transport this candidate is
// punchable on.
const (
	CandidateSubstrateTCP    = "tcp"
	CandidateSubstrateQUIC   = "quic"
	CandidateSubstrateWebRTC = "webrtc"
)

// CandidatePriority returns the try-order rank for a candidate type: lower is
// tried first (§6.7.3 host → srflx → relay). Unknown types sort last.
func CandidatePriority(candidateType string) int {
	switch candidateType {
	case CandidateTypeHost:
		return 0
	case CandidateTypeSrflx:
		return 1
	case CandidateTypeRelay:
		return 2
	default:
		return 3
	}
}

// ObserveAddressResultData is the system/network/observe-address-result
// payload (§6.7.1).
type ObserveAddressResultData struct {
	// ObservedAddress is the source IP:port the responder observed on the
	// connection this request arrived on, e.g. "203.0.113.7:51820". It is the
	// transport-layer source and NEVER a value echoed from the request body
	// (§6.7.1 MUST 1).
	ObservedAddress string `cbor:"observed_address"`
}

// ToEntity creates a system/network/observe-address-result entity.
func (d ObserveAddressResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkObserveAddressResult, cbor.RawMessage(raw))
}

// ObserveAddressResultDataFromEntity decodes a
// system/network/observe-address-result entity's data.
func ObserveAddressResultDataFromEntity(e entity.Entity) (ObserveAddressResultData, error) {
	var d ObserveAddressResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return ObserveAddressResultData{}, err
	}
	return d, nil
}

// CheckReachabilityResultData is the system/network/check-reachability-result
// payload (§6.7.2).
type CheckReachabilityResultData struct {
	// Reachable reports whether the dial-back to AddressTested succeeded.
	Reachable bool `cbor:"reachable"`
	// AddressTested is the observed source address the responder dialed back —
	// the same value observe-address would return on this connection. Reported
	// so the requester can confirm WHICH address was proved (§6.7.2); the
	// value is the responder's, never one the requester supplied.
	AddressTested string `cbor:"address_tested"`
}

// ToEntity creates a system/network/check-reachability-result entity.
func (d CheckReachabilityResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkCheckReachabilityResult, cbor.RawMessage(raw))
}

// CheckReachabilityResultDataFromEntity decodes a
// system/network/check-reachability-result entity's data.
func CheckReachabilityResultDataFromEntity(e entity.Entity) (CheckReachabilityResultData, error) {
	var d CheckReachabilityResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return CheckReachabilityResultData{}, err
	}
	return d, nil
}

// NetworkCandidateData is the system/network/candidate payload (§6.7.3).
type NetworkCandidateData struct {
	// Address is the candidate's IP:port.
	Address string `cbor:"address"`
	// Type is one of CandidateType{Host,Srflx,Relay}.
	Type string `cbor:"type"`
	// Substrate is which transport this candidate is punchable on
	// (CandidateSubstrate{TCP,QUIC,WebRTC}).
	Substrate string `cbor:"substrate"`
}

// ToEntity creates a system/network/candidate entity.
func (d NetworkCandidateData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeNetworkCandidate, cbor.RawMessage(raw))
}

// NetworkCandidateDataFromEntity decodes a system/network/candidate entity's data.
func NetworkCandidateDataFromEntity(e entity.Entity) (NetworkCandidateData, error) {
	var d NetworkCandidateData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return NetworkCandidateData{}, err
	}
	return d, nil
}
