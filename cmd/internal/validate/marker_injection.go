package validate

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Marker path injection — EXTENSION-CONTINUATION §3.10 + arch ruling 13.
//
// The §3.10.3 `rejected` marker path interpolates two values the SENDER
// chooses, straight off the wire:
//
//	system/runtime/chain-errors/rejected/{chain_id}/{step_index}/{reason}/{marker_hash}
//	                                     └ bounds.chain_id ┘ └ request_id ┘
//
// This probe is the sharpest reachable form of the vector, and needs no
// continuation setup: the rejected marker is bound BECAUSE the sender's cap
// check failed, so an UNAUTHORIZED caller reaches the binding site by
// construction. We send a deliberately over-scope EXECUTE (guaranteed 403)
// carrying hostile values in both coordinates, then read the peer's marker
// tree back and check where the marker actually landed.
//
// Why the assertion is on the CLEANED path, not the literal one: the escape is
// NOT the leading-"../" form a path cleaner rejects. These values land in the
// MIDDLE of the path, and a normalizer RESOLVES an interior ".." rather than
// rejecting it — walking the marker back OUT of the chain-errors subtree.
// Storing it literally is safe only for exactly as long as nothing normalizes
// it, and "system/…/rejected/{X}/.." is inside the sink by string prefix while
// naming somewhere else entirely. Go shipped this defect and fixed it in
// 24d618c; on Go's own wire the request_id form put the marker under
// system/authority/keys/ once cleaned, and the chain_id form left system/
// altogether.
//
// Outcomes are deliberately graded so a peer is never FAILed for a shape this
// probe merely fails to understand:
//   - marker bound, contained          → PASS
//   - marker bound, escapes the sink   → FAIL (this is the real defect)
//   - no marker bound                  → WARN (not injectable via this path;
//     the peer may not implement §3.10.3, which is a different question)
//   - marker tree unreadable           → WARN (cannot verify; not a verdict)
const markerInjectionEscape = "../../../../authority/keys"

const rejectedSink = "system/runtime/chain-errors/rejected/"

// buildHostileDelegatedExecute mirrors buildDelegatedExecute but lets the
// caller poison the two wire-supplied marker coordinates: request_id (which
// becomes {step_index}) and bounds.chain_id (which becomes {chain_id}).
//
// bounds.chain_id must be non-empty or §3.10.3's scope rule means no rejected
// marker is bound at all — the marker fires for chain dispatches only.
func buildHostileDelegatedExecute(
	client *PeerClient,
	childCap, childCapSig entity.Entity,
	uri, operation string,
	params entity.Entity,
	resource *types.ResourceTarget,
	requestID, chainID string,
) (entity.Envelope, error) {
	kp := client.Keypair()
	identity := client.IdentityEntity()

	raw, err := ecf.Encode(params)
	if err != nil {
		return entity.Envelope{}, err
	}

	execData := types.ExecuteData{
		RequestID:  requestID,
		URI:        uri,
		Operation:  operation,
		Params:     cbor.RawMessage(raw),
		Author:     identity.ContentHash,
		Capability: childCap.ContentHash,
		Resource:   resource,
		Bounds:     &types.BoundsData{ChainID: chainID},
	}

	execEntity, err := execData.ToEntity()
	if err != nil {
		return entity.Envelope{}, err
	}
	execSig, err := signEntity(execEntity.ContentHash, kp, identity)
	if err != nil {
		return entity.Envelope{}, err
	}

	included := map[hash.Hash]entity.Entity{
		identity.ContentHash:    identity,
		childCap.ContentHash:    childCap,
		childCapSig.ContentHash: childCapSig,
		execSig.ContentHash:     execSig,
	}
	// The parent chain: connection cap + its sig + granter identity.
	parentCap := client.CapEntity()
	included[parentCap.ContentHash] = parentCap
	for h, ent := range client.AuthenticateIncluded() {
		included[h] = entity.Entity{Type: ent.Type, Data: ent.Data, ContentHash: h}
	}
	return entity.NewEnvelope(execEntity, included), nil
}

// checkMarkerPathInjection runs the probe described above.
func checkMarkerPathInjection(ctx context.Context, client *PeerClient) CheckOutcome {
	kp := client.Keypair()
	identity := client.IdentityEntity()
	parentCap := client.CapEntity()

	// A child cap scoped to system/tree only; we then dispatch to
	// system/capability. Same guaranteed-403 shape the security category's
	// handler_scope_denied_core_1 uses — reused rather than reinvented so the
	// probe's denial can't be the thing that breaks.
	now := uint64(time.Now().UnixMilli())
	fiveMin := now + 5*60*1000
	tokenData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{{
			Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
			Resources:  types.CapabilityScope{Include: []string{"*"}},
			Operations: types.CapabilityScope{Include: []string{"*"}},
		}},
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		Parent:    &parentCap.ContentHash,
		CreatedAt: now,
		ExpiresAt: &fiveMin,
	}
	childCap, childCapSig, err := createCapabilityToken(tokenData, kp, identity)
	if err != nil {
		return FailCheck("setup: create child cap: " + err.Error())
	}
	params, _, err := buildSimpleGetParams()
	if err != nil {
		return FailCheck("setup: " + err.Error())
	}

	uri := fmt.Sprintf("entity://%s/system/capability", client.RemotePeerID())
	env, err := buildHostileDelegatedExecute(
		client, childCap, childCapSig, uri, "request", params,
		&types.ResourceTarget{Targets: []string{"system/validate/marker-injection"}},
		markerInjectionEscape, markerInjectionEscape,
	)
	if err != nil {
		return FailCheck("setup: build hostile execute: " + err.Error())
	}

	respEnv, _, err := client.SendRawEnvelope(env)
	if err != nil {
		return FailCheck(fmt.Sprintf("peer crashed or closed the connection on a hostile-coordinate EXECUTE: %v", err))
	}
	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		return WarnCheck("could not decode the response: " + err.Error())
	}
	if status := respData.Status; status != 403 {
		// Not a verdict on injection: if the request wasn't denied, the
		// rejected marker never had a reason to bind.
		return WarnCheck(fmt.Sprintf(
			"hostile EXECUTE returned %d, expected a 403 — the §3.10.3 rejected marker only binds on cap-rejection, so this probe cannot reach the binding site on this peer",
			status))
	}

	// Read the marker tree back. Walk generously: the whole point is that a
	// hostile value ADDS depth, so a tight cap would miss the very thing we
	// are looking for and silently PASS.
	var paths []string
	walkTreePaths(ctx, client, rejectedSink, 0, &paths)
	if len(paths) == 0 {
		return WarnCheck(
			"no marker found under " + rejectedSink + " — either this peer does not bind §3.10.3 rejected markers, or the tree is not readable with this identity. Not injectable via this path; not a verdict on the peer")
	}

	for _, p := range paths {
		bare := strings.TrimPrefix(p, "/")
		// Skip the peer_id prefix if the listing returned absolute paths.
		if i := strings.Index(bare, "system/runtime/chain-errors"); i > 0 {
			bare = bare[i:]
		}
		cleaned := path.Clean(bare)
		if !strings.HasPrefix(cleaned, strings.TrimSuffix(rejectedSink, "/")) {
			return FailCheck(fmt.Sprintf(
				"MARKER PATH INJECTION: a wire-supplied coordinate escaped the chain-errors sink.\n"+
					"      bound at:   %s\n"+
					"      resolves to: %s\n"+
					"      An unauthorized peer chose that location (the rejected marker binds BECAUSE the cap check failed). "+
					"Sanitize bounds.chain_id / request_id / result.data.code before interpolating them into the marker path — "+
					"hash unsafe values, do not drop them (arch ruling 13).",
				p, cleaned))
		}
		if strings.Contains(bare, "/../") || strings.HasSuffix(bare, "/..") {
			return FailCheck(fmt.Sprintf(
				"MARKER PATH INJECTION: a reserved dot-dot token from the wire was stored as a path segment: %s\n"+
					"      It is contained only while nothing normalizes this path; any consumer that cleans it walks the marker out of the sink.",
				p))
		}
	}

	return PassCheck(fmt.Sprintf(
		"hostile bounds.chain_id + request_id (%q) denied 403 and contained: %d marker path(s) under the sink, none escaping under normalization",
		markerInjectionEscape, len(paths)))
}
