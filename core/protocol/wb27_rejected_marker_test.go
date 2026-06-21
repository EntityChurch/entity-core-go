package protocol

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestWB27_ChainCapDeniedBindsReceiverSideRejectedMarker pins the WB-27
// receiver-side dispatcher bind per EXTENSION-CONTINUATION v1.20 §3.10.3
// + §3.10.4. When an inbound EXECUTE carrying Bounds.ChainID is refused
// on cap-check, the dispatcher MUST:
//
//   (1) Bind a receiver-side `rejected` chain-error marker at
//       system/runtime/chain-errors/rejected/{chain_id}/{step_index}/
//       capability_denied/{marker_hash} (v1.20 path, V7 §3.5 hex form).
//   (2) Populate the outgoing 403 response's ErrorData.RejectedMarker
//       with the marker's content_hash (mirror-pointer per §3.10.4).
//   (3) Use the canonical V7 §3.3 code `capability_denied` (NOT the
//       withdrawn `cap_denied` that Amendment 1 invented and Unified
//       Design corrected).
//
// Pre-fix: cap-rejected chain dispatches silently failed at the
// dispatcher; workbench's Stage 4 cap-discipline-mesh test surfaced 0
// markers across 3 peers despite 0/6 deliveries succeeding.
func TestWB27_ChainCapDeniedBindsReceiverSideRejectedMarker(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()

	reg := handler.NewRegistry()
	reg.Register("test/echo", &echoHandler{})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)

	// Build a capability that does NOT include "ping" in Operations
	// (restricted to "get" only). The chain dispatch targets ping → cap
	// rejected.
	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}}, // ping is NOT here
			},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target: capEntity.ContentHash, Signer: localIdentity.ContentHash,
		Algorithm: "ed25519", Signature: capSig,
	}.ToEntity()

	if _, err := cs.Put(capEntity); err != nil {
		t.Fatalf("put cap entity: %v", err)
	}

	paramsRaw, _ := ecf.Encode("test-params")
	paramsEntity, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))
	encodedParams, _ := ecf.Encode(paramsEntity)

	// Bounds carries the ChainID — this is what makes the request a
	// "chain dispatch" per §3.10.3 scope rule.
	cascadeDepth := uint64(1)
	bounds := &types.BoundsData{
		ChainID:      "test-chain-42",
		CascadeDepth: &cascadeDepth,
	}

	execData := types.ExecuteData{
		RequestID:  "req-wb27",
		URI:        "entity://" + string(localKP.PeerID()) + "/test/echo",
		Operation:  "ping", // NOT in the cap's allowed ops → 403
		Params:     cbor.RawMessage(encodedParams),
		Author:     remoteIdentity.ContentHash,
		Capability: capEntity.ContentHash,
		Bounds:     bounds,
	}
	execEntity, _ := execData.ToEntity()
	execSig := remoteKP.Sign(execEntity.ContentHash.Bytes())
	execSigEntity, _ := types.SignatureData{
		Target: execEntity.ContentHash, Signer: remoteIdentity.ContentHash,
		Algorithm: "ed25519", Signature: execSig,
	}.ToEntity()

	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		remoteIdentity.ContentHash: remoteIdentity,
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		execSigEntity.ContentHash:  execSigEntity,
	})

	respEnv, err := d.DispatchEnvelope(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respData.Status != 403 {
		t.Fatalf("expected 403 cap-rejected, got %d", respData.Status)
	}

	// Decode the ErrorData and verify code + RejectedMarker mirror.
	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	var ed types.ErrorData
	if err := ecf.Decode(resultEntity.Data, &ed); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if ed.Code != "capability_denied" {
		t.Fatalf("ErrorData.Code: got %q, want %q (V7 §3.3 canonical 403 code)", ed.Code, "capability_denied")
	}
	if ed.RejectedMarker.IsZero() {
		t.Fatal("v1.20 §3.10.4: chain-dispatch cap-rejection MUST populate ErrorData.RejectedMarker mirror-pointer; got zero hash")
	}

	// Verify the receiver-side marker is bound at the v1.20 path under
	// the LOCAL peer's namespace.
	prefix := "/" + string(localKP.PeerID()) + "/system/runtime/chain-errors/rejected/test-chain-42/req-wb27/capability_denied/"
	rawIdx := li.Inner()
	entries := rawIdx.List(prefix)
	if len(entries) != 1 {
		t.Fatalf("v1.20 §3.10.3: expected exactly 1 receiver-side rejected marker under %s, got %d", prefix, len(entries))
	}
	if entries[0].Hash != ed.RejectedMarker {
		t.Fatalf("§3.10.4: receiver-side marker hash %s != response.ErrorData.RejectedMarker %s",
			entries[0].Hash, ed.RejectedMarker)
	}

	// Verify the path's terminal segment is the V7 §3.5 hex form of the
	// marker hash (lowercase, format-code-included, 66 chars).
	segs := strings.Split(entries[0].Path, "/")
	terminal := segs[len(segs)-1]
	if len(terminal) != 66 {
		t.Fatalf("terminal {marker_hash} segment length: got %d, want 66 (V7 §3.5 hex form)", len(terminal))
	}
	if strings.Contains(terminal, ":") {
		t.Fatal("terminal segment contains ':' — that's V7 §1.2 UI-only Hash.String() form; MUST use V7 §3.5 hex form on paths")
	}
	expected := hex.EncodeToString(ed.RejectedMarker.Bytes())
	if terminal != expected {
		t.Fatalf("terminal segment %q != hex(rejected_marker.Bytes()) %q", terminal, expected)
	}

	// Verify the marker body shape per §3.10.6.
	markerEnt, ok := cs.Get(ed.RejectedMarker)
	if !ok {
		t.Fatal("marker entity not in content store")
	}
	if markerEnt.Type != types.TypeChainErrorLost {
		t.Fatalf("marker entity type: got %s, want %s", markerEnt.Type, types.TypeChainErrorLost)
	}
	var body types.ChainErrorLostData
	if err := ecf.Decode(markerEnt.Data, &body); err != nil {
		t.Fatalf("decode marker body: %v", err)
	}
	if body.Reason != "capability_denied" {
		t.Errorf("body.Reason: got %q, want %q", body.Reason, "capability_denied")
	}
	if body.ChainID != "test-chain-42" {
		t.Errorf("body.ChainID: got %q, want %q", body.ChainID, "test-chain-42")
	}
	if body.StepIndex != "req-wb27" {
		t.Errorf("body.StepIndex: got %q, want %q", body.StepIndex, "req-wb27")
	}
	if body.AttemptedURI != execData.URI {
		t.Errorf("body.AttemptedURI: got %q, want %q", body.AttemptedURI, execData.URI)
	}
	if body.Timestamp == 0 {
		t.Error("body.Timestamp: MUST be set (§3.10.6 timestamp-capture discipline)")
	}
}

// TestWB27_OrdinaryEXECUTECapDeniedDoesNotBindRejectedMarker pins the
// §3.10.3 scope rule: the `rejected` variant fires ONLY when the inbound
// EXECUTE carries Bounds.ChainID. Ordinary point-to-point EXECUTEs
// continue to surface 403 via the synchronous response only — no
// receiver-side marker (the caller sees the rejection in the response;
// no fire-and-forget observability gap to close).
func TestWB27_OrdinaryEXECUTECapDeniedDoesNotBindRejectedMarker(t *testing.T) {
	localKP, _ := crypto.Generate()
	remoteKP, _ := crypto.Generate()

	localIdentity, _ := localKP.IdentityEntity()
	remoteIdentity, _ := remoteKP.IdentityEntity()

	reg := handler.NewRegistry()
	reg.Register("test/echo", &echoHandler{})

	cs := store.NewMemoryContentStore()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(localKP.PeerID()))
	if err := SeedHandlersFromRegistry(cs, li, reg); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(reg, cs, li, localKP, nil)

	capData := types.CapabilityTokenData{
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"*"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get"}},
			},
		},
		Granter:   types.SingleSigGranter(localIdentity.ContentHash),
		Grantee:   remoteIdentity.ContentHash,
		CreatedAt: 1000,
	}
	capEntity, _ := capData.ToEntity()
	capSig := localKP.Sign(capEntity.ContentHash.Bytes())
	capSigEntity, _ := types.SignatureData{
		Target: capEntity.ContentHash, Signer: localIdentity.ContentHash,
		Algorithm: "ed25519", Signature: capSig,
	}.ToEntity()
	_, _ = cs.Put(capEntity)

	paramsRaw, _ := ecf.Encode("test-params")
	paramsEntity, _ := entity.NewEntity("test/params", cbor.RawMessage(paramsRaw))
	encodedParams, _ := ecf.Encode(paramsEntity)

	// NO Bounds — this is an ordinary EXECUTE, not a chain dispatch.
	execData := types.ExecuteData{
		RequestID:  "req-ordinary",
		URI:        "entity://" + string(localKP.PeerID()) + "/test/echo",
		Operation:  "ping",
		Params:     cbor.RawMessage(encodedParams),
		Author:     remoteIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, _ := execData.ToEntity()
	execSig := remoteKP.Sign(execEntity.ContentHash.Bytes())
	execSigEntity, _ := types.SignatureData{
		Target: execEntity.ContentHash, Signer: remoteIdentity.ContentHash,
		Algorithm: "ed25519", Signature: execSig,
	}.ToEntity()

	env := entity.NewEnvelope(execEntity, map[hash.Hash]entity.Entity{
		remoteIdentity.ContentHash: remoteIdentity,
		localIdentity.ContentHash:  localIdentity,
		capEntity.ContentHash:      capEntity,
		capSigEntity.ContentHash:   capSigEntity,
		execSigEntity.ContentHash:  execSigEntity,
	})

	respEnv, err := d.DispatchEnvelope(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	respData, _ := types.ExecuteResponseDataFromEntity(respEnv.Root)
	if respData.Status != 403 {
		t.Fatalf("expected 403, got %d", respData.Status)
	}

	// Decode the ErrorData — RejectedMarker MUST be the zero hash
	// (omitzero) because §3.10.3 scope limits the rejected variant to
	// chain dispatches.
	var resultEntity entity.Entity
	_ = ecf.Decode(respData.Result, &resultEntity)
	var ed types.ErrorData
	_ = ecf.Decode(resultEntity.Data, &ed)
	if !ed.RejectedMarker.IsZero() {
		t.Fatalf("v1.20 §3.10.3 scope violation: ordinary (non-chain) EXECUTE cap-rejection MUST NOT bind a rejected marker; got mirror hash %s", ed.RejectedMarker)
	}

	// Verify no marker was bound anywhere under chain-errors/rejected/.
	rawIdx := li.Inner()
	entries := rawIdx.List("/" + string(localKP.PeerID()) + "/system/runtime/chain-errors/rejected/")
	if len(entries) != 0 {
		t.Fatalf("scope violation: %d rejected markers bound for an ordinary EXECUTE; expected 0", len(entries))
	}
}
