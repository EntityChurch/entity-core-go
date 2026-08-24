// Package punchwire assembles the cmd-layer inputs the §7 punch coordinator
// (ext/signaling/peerwiring) deliberately does NOT decide for itself. peerwiring
// keeps candidate gathering injected so it need not import ext/network; this
// package is where that injection is built — starting with the srflx (server-
// reflexive) candidate gatherer, which composes ext/signaling's reflector dial,
// core/peer's handshake+dispatch, and ext/network's candidate typing.
package punchwire

import (
	"context"
	"fmt"
	"net"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
	extnetwork "go.entitychurch.org/entity-core-go/ext/network"
	"go.entitychurch.org/entity-core-go/ext/signaling"
	"go.entitychurch.org/entity-core-go/ext/signaling/peerwiring"
)

// SRFLXGatherer returns a peerwiring.GatherFunc that discovers this peer's srflx
// candidate from reflectorAddr via EXTENSION-NETWORK §6.7.1 observe-address and
// returns the §6.7.3 candidate set (host → srflx [→ relay]) bound to the reflector
// socket's local address — so the punch dials from the SAME NAT mapping the srflx
// names (§6.7.3 / §7.3). This is the client half whose responder Go already ships;
// it is what carries a peer past host-only candidates.
//
// The reflector is dialed from a REUSEPORT socket and handshaked as the initiator
// (the client half, SIGNALING §7.4.1); the observed source it reports is this
// peer's public mapping. relay (may be "") is a configured public relay candidate,
// typed through as the §6.7.3 relay candidate.
//
// On any failure — reflector unreachable, sockopt unsupported, observe-address
// declined or malformed — the gatherer returns an error, which the §10.3 seam maps
// to the relay fallback (traversal is best-effort; correctness is the fallback's
// job). Host-only punching without any reflector is a separate gatherer, not a
// silent degrade here: no reflector means no reflexive candidate, and for a NAT'd
// peer that is precisely the relay case.
func SRFLXGatherer(p *peer.Peer, reflectorAddr, relay string) peerwiring.GatherFunc {
	return func(ctx context.Context) (*net.TCPAddr, []types.NetworkCandidateData, error) {
		raw, local, err := signaling.DialReflector(ctx, reflectorAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("srflx gather: dial reflector %s: %w", reflectorAddr, err)
		}
		conn := p.ConnectVia(raw)
		// Done with the reflector after the observation; the punch re-binds `local`
		// (REUSEPORT), so this connection must not linger holding the port.
		defer conn.Close()
		if err := conn.PerformConnect(ctx); err != nil {
			return nil, nil, fmt.Errorf("srflx gather: handshake to reflector %s: %w", reflectorAddr, err)
		}
		srflx, err := observeAddress(ctx, conn)
		if err != nil {
			return nil, nil, fmt.Errorf("srflx gather: %w", err)
		}
		cands := extnetwork.GatherCandidates(local.Port, srflx, relay)
		return local, cands, nil
	}
}

// observeAddress runs the §6.7.1 observe-address op over an established reflector
// connection and returns this peer's observed public source. The op takes no input
// (the fact rides from the accepted connection, never the body), so params is a
// well-formed empty entity; the reflector's peer-id for the URI is read from the
// completed session rather than pre-supplied.
func observeAddress(ctx context.Context, conn *peer.Connection) (string, error) {
	reflectorID := conn.Session().RemotePeerID
	uri := fmt.Sprintf("entity://%s/system/network", reflectorID)

	// observe-address declares no InputType and reads nothing from the body; an
	// empty CBOR map (0xa0) under a request-shaped type is a valid, ignored body.
	params, err := entity.NewEntity("system/network/observe-address-request", cbor.RawMessage{0xa0})
	if err != nil {
		return "", fmt.Errorf("build observe-address params: %w", err)
	}

	respEnv, err := conn.Execute(ctx, uri, "observe-address", params, nil)
	if err != nil {
		return "", fmt.Errorf("observe-address to %s: %w", reflectorID, err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return "", fmt.Errorf("decode execute response: %w", err)
	}
	if respData.Status != 200 {
		return "", fmt.Errorf("reflector returned status %d (want 200; §6.7.4 network-reflect is a broad default grant)", respData.Status)
	}
	if len(respData.Result) == 0 {
		return "", fmt.Errorf("reflector returned an empty result")
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		return "", fmt.Errorf("decode result entity: %w", err)
	}
	if resultEnt.Type != types.TypeNetworkObserveAddressResult {
		return "", fmt.Errorf("result type %q, want %q (§6.7.1)", resultEnt.Type, types.TypeNetworkObserveAddressResult)
	}
	obs, err := types.ObserveAddressResultDataFromEntity(resultEnt)
	if err != nil {
		return "", fmt.Errorf("decode observe-address-result: %w", err)
	}
	if obs.ObservedAddress == "" {
		return "", fmt.Errorf("reflector reported an empty observed address")
	}
	return obs.ObservedAddress, nil
}
