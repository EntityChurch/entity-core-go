package interop

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/wire"

	"github.com/fxamacker/cbor/v2"
)

// TestInteropConnect connects to a running Python peer and performs
// the full connect handshake.
//
// Run with: INTEROP_ADDR=127.0.0.1:9001 go test -run TestInteropConnect -v
func TestInteropConnect(t *testing.T) {
	addr := os.Getenv("INTEROP_ADDR")
	if addr == "" {
		t.Skip("INTEROP_ADDR not set; skipping interop test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate our keypair.
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Our PeerID: %s", kp.PeerID())

	// Connect.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	t.Logf("Connected to %s", addr)

	// === Phase 1: Send HELLO ===
	helloEnv, ourNonce, err := protocol.CreateHelloExecute(kp, []string{"entity-core/1.0"})
	if err != nil {
		t.Fatalf("create hello: %v", err)
	}
	t.Logf("Sending hello (nonce=%s)", hex.EncodeToString(ourNonce[:8]))

	// Debug: dump the raw envelope bytes.
	helloBytes, _ := ecf.Encode(helloEnv)
	t.Logf("Hello envelope CBOR (%d bytes): %s...", len(helloBytes), hex.EncodeToString(helloBytes[:min(64, len(helloBytes))]))

	if err := wire.WriteEnvelope(conn, helloEnv); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	t.Log("Hello sent, waiting for response...")

	// === Phase 2: Receive HELLO response ===
	_ = ctx
	helloResp, err := readEnvelopeRaw(conn)
	if err != nil {
		t.Fatalf("recv hello response: %v", err)
	}
	t.Logf("Received response: root.type=%s", helloResp.Root.Type)
	dumpEnvelope(t, "HelloResp", helloResp)

	// Extract their nonce from the response.
	var theirNonce []byte
	if helloResp.Root.Type == types.TypeExecuteResponse {
		respData, err := types.ExecuteResponseDataFromEntity(helloResp.Root)
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		t.Logf("Response status: %d", respData.Status)

		// The result should contain a hello entity with a nonce.
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			// Try decoding as raw hello data.
			var helloData types.HelloData
			if err2 := ecf.Decode(respData.Result, &helloData); err2 != nil {
				t.Logf("Could not decode result as entity (%v) or hello data (%v)", err, err2)
				// Try as a generic map.
				var raw map[string]interface{}
				if err3 := ecf.Decode(respData.Result, &raw); err3 != nil {
					t.Fatalf("Could not decode result at all: %v", err3)
				}
				t.Logf("Result as map: %+v", raw)
			} else {
				t.Logf("Their PeerID: %s, nonce: %s", helloData.PeerID, hex.EncodeToString(helloData.Nonce[:min(8, len(helloData.Nonce))]))
				theirNonce = helloData.Nonce
			}
		} else {
			t.Logf("Result entity type: %s", resultEntity.Type)
			if resultEntity.Type == types.TypeHello {
				helloData, _ := types.HelloDataFromEntity(resultEntity)
				t.Logf("Their PeerID: %s, nonce: %s", helloData.PeerID, hex.EncodeToString(helloData.Nonce[:min(8, len(helloData.Nonce))]))
				theirNonce = helloData.Nonce
			}
		}
	} else if helloResp.Root.Type == types.TypeExecute {
		// Python might send back an EXECUTE (their hello).
		execData, _ := types.ExecuteDataFromEntity(helloResp.Root)
		t.Logf("Got EXECUTE back: op=%s uri=%s", execData.Operation, execData.URI)
		var helloEntity entity.Entity
		if err := ecf.Decode(execData.Params, &helloEntity); err == nil {
			helloData, _ := types.HelloDataFromEntity(helloEntity)
			theirNonce = helloData.Nonce
			t.Logf("Their PeerID: %s", helloData.PeerID)
		}
	} else {
		t.Logf("Unexpected root type: %s", helloResp.Root.Type)
		// Dump raw data.
		var raw interface{}
		ecf.Decode(helloResp.Root.Data, &raw)
		t.Logf("Root data: %+v", raw)
	}

	if theirNonce == nil {
		t.Fatal("Could not extract their nonce from hello response")
	}

	// === Phase 3: Send AUTHENTICATE ===
	t.Log("Sending authenticate...")
	authEnv, err := protocol.CreateAuthenticateExecute(kp, theirNonce)
	if err != nil {
		t.Fatalf("create authenticate: %v", err)
	}

	if err := wire.WriteEnvelope(conn, authEnv); err != nil {
		t.Fatalf("send authenticate: %v", err)
	}
	t.Log("Authenticate sent, waiting for response...")

	// === Phase 4: Receive AUTHENTICATE response (with capability grant) ===
	authResp, err := readEnvelopeRaw(conn)
	if err != nil {
		t.Fatalf("recv authenticate response: %v", err)
	}
	t.Logf("Authenticate response: root.type=%s", authResp.Root.Type)
	dumpEnvelope(t, "AuthResp", authResp)

	// Extract capability token.
	if authResp.Root.Type == types.TypeExecuteResponse {
		respData, _ := types.ExecuteResponseDataFromEntity(authResp.Root)
		t.Logf("Authenticate response status: %d", respData.Status)
		if respData.Status != 200 {
			var errData types.ErrorData
			ecf.Decode(respData.Result, &errData)
			t.Fatalf("Authenticate failed: %d - %s: %s", respData.Status, errData.Code, errData.Message)
		}
	}

	t.Log("=== Connect complete! ===")
	t.Logf("Included entities in authenticate response: %d", len(authResp.Included))
	for h, ent := range authResp.Included {
		t.Logf("  %s: type=%s", h, ent.Type)
	}

	// Find the capability token and our identity from the response.
	var capEntity entity.Entity
	var theirIdentity entity.Entity
	var ourIdentityHash hash.Hash
	for _, ent := range authResp.Included {
		switch ent.Type {
		case types.TypeCapToken:
			capEntity = ent
		case "system/peer":
			var idData types.PeerData
			if err := ecf.Decode(ent.Data, &idData); err == nil {
				// v7.65 §1.5: peer_id derives from public_key.
				entPID := crypto.PeerIDFromEd25519PublicKey(idData.PublicKey)
				if entPID == kp.PeerID() {
					ourIdentityHash = ent.ContentHash
				} else {
					theirIdentity = ent
				}
			}
		}
	}

	if capEntity.ContentHash.IsZero() {
		t.Fatal("No capability token in authenticate response")
	}
	t.Logf("Capability token: %s", capEntity.ContentHash)

	// Decode the cap to see what grants we got.
	capData, err := types.CapabilityTokenDataFromEntity(capEntity)
	if err != nil {
		t.Fatalf("decode cap: %v", err)
	}
	t.Logf("Grants: %d", len(capData.Grants))
	for i, g := range capData.Grants {
		t.Logf("  grant[%d]: resources=%v ops=%v", i, g.Resources, g.Operations)
	}

	// Get our identity entity (we need it for signing).
	ourIdentity, err := kp.IdentityEntity()
	if err != nil {
		t.Fatal(err)
	}
	// Use the hash the server knows us by (might differ if encoding differs).
	if !ourIdentityHash.IsZero() {
		t.Logf("Server knows our identity as: %s", ourIdentityHash)
		t.Logf("We compute our identity as:   %s", ourIdentity.ContentHash)
	}
	_ = theirIdentity

	// === Phase 5: Authenticated tree get (listing) ===
	t.Log("Sending authenticated tree get (listing)...")

	// Build get-request params.
	getReqData := types.GetRequestData{}
	getReqEntity, err := getReqData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	paramsRaw, _ := ecf.Encode(getReqEntity)
	theirPeerID := capData.Granter // The granter's identity hash
	_ = theirPeerID

	// Determine the remote peer ID from included identities.
	var remotePeerIDStr string
	for _, ent := range authResp.Included {
		if ent.Type == "system/peer" {
			var idData types.PeerData
			if err := ecf.Decode(ent.Data, &idData); err == nil {
				// v7.65 §1.5: peer_id derives from public_key.
				entPID := crypto.PeerIDFromEd25519PublicKey(idData.PublicKey)
				if entPID != kp.PeerID() {
					remotePeerIDStr = string(entPID)
					break
				}
			}
		}
	}
	t.Logf("Remote peer ID: %s", remotePeerIDStr)

	// Build the execute message.
	execData := types.ExecuteData{
		RequestID:  "interop-tree-get-1",
		URI:        "entity://" + remotePeerIDStr + "/system/tree",
		Operation:  "get",
		Resource:   &types.ResourceTarget{Targets: []string{"system/"}},
		Params:     cbor.RawMessage(paramsRaw),
		Author:     ourIdentity.ContentHash,
		Capability: capEntity.ContentHash,
	}
	execEntity, err := execData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	// Sign the execute.
	sig := kp.Sign(execEntity.ContentHash.Bytes())
	sigData := types.SignatureData{
		Target:    execEntity.ContentHash,
		Signer:    ourIdentity.ContentHash,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigEntity, err := sigData.ToEntity()
	if err != nil {
		t.Fatal(err)
	}

	// Build the capability signature entities.
	// We need to include: our identity, the capability, and signatures for both
	// the execute and the capability.
	// The capability's signatures should already be in the authenticate response included.
	included := map[hash.Hash]entity.Entity{
		ourIdentity.ContentHash: ourIdentity,
		capEntity.ContentHash:   capEntity,
		sigEntity.ContentHash:   sigEntity,
	}
	// Also include all entities from the authenticate response (cap signatures, identities).
	for h, ent := range authResp.Included {
		included[h] = ent
	}

	treeEnv := entity.NewEnvelope(execEntity, included)

	if err := wire.WriteEnvelope(conn, treeEnv); err != nil {
		t.Fatalf("send tree get: %v", err)
	}
	t.Log("Tree get sent, waiting for response...")

	treeResp, err := readEnvelopeRaw(conn)
	if err != nil {
		t.Fatalf("recv tree response: %v", err)
	}
	t.Logf("Tree response: root.type=%s", treeResp.Root.Type)
	dumpEnvelope(t, "TreeResp", treeResp)

	if treeResp.Root.Type == types.TypeExecuteResponse {
		respData, _ := types.ExecuteResponseDataFromEntity(treeResp.Root)
		t.Logf("Tree response status: %d", respData.Status)

		if respData.Status == 200 {
			t.Log("=== Tree get successful! ===")
			// Try to decode the result.
			var resultMap map[string]interface{}
			if err := ecf.Decode(respData.Result, &resultMap); err == nil {
				t.Logf("Result: %+v", resultMap)
			} else {
				var resultEntity entity.Entity
				if err := ecf.Decode(respData.Result, &resultEntity); err == nil {
					t.Logf("Result entity type: %s", resultEntity.Type)
					var raw interface{}
					ecf.Decode(resultEntity.Data, &raw)
					t.Logf("Result data: %+v", raw)
				}
			}
		} else {
			var errResult interface{}
			ecf.Decode(respData.Result, &errResult)
			t.Logf("Tree get failed: status=%d result=%+v", respData.Status, errResult)
		}
	}
}

// readEnvelopeRaw reads a frame and decodes without hash validation
// (useful for debugging interop issues).
func readEnvelopeRaw(conn net.Conn) (entity.Envelope, error) {
	data, err := wire.ReadFrame(conn)
	if err != nil {
		return entity.Envelope{}, fmt.Errorf("read frame: %w", err)
	}

	fmt.Printf("  Raw frame (%d bytes): %s...\n", len(data), hex.EncodeToString(data[:min(80, len(data))]))

	var env entity.Envelope
	if err := ecf.Decode(data, &env); err != nil {
		// Try decoding as a generic map to see what's there.
		var raw map[string]cbor.RawMessage
		if err2 := ecf.Decode(data, &raw); err2 != nil {
			return entity.Envelope{}, fmt.Errorf("decode envelope: %w (raw decode also failed: %v)", err, err2)
		}
		fmt.Printf("  Raw envelope keys: ")
		for k := range raw {
			fmt.Printf("%q ", k)
		}
		fmt.Println()

		// Try to manually decode root.
		if rootRaw, ok := raw["root"]; ok {
			var rootEntity entity.Entity
			if err := ecf.Decode(rootRaw, &rootEntity); err != nil {
				fmt.Printf("  Could not decode root entity: %v\n", err)
				var rootMap map[string]interface{}
				ecf.Decode(rootRaw, &rootMap)
				fmt.Printf("  Root as map: %+v\n", rootMap)
			} else {
				env.Root = rootEntity
			}
		}

		// Try included.
		if incRaw, ok := raw["included"]; ok {
			var included map[hash.Hash]entity.Entity
			if err := ecf.Decode(incRaw, &included); err != nil {
				fmt.Printf("  Could not decode included: %v\n", err)
			} else {
				env.Included = included
			}
		}

		return env, nil
	}

	return env, nil
}

func dumpEnvelope(t *testing.T, label string, env entity.Envelope) {
	t.Helper()
	t.Logf("[%s] root: type=%q hash=%s", label, env.Root.Type, env.Root.ContentHash)

	// Dump raw root data as hex (first 100 bytes).
	if len(env.Root.Data) > 0 {
		n := min(100, len(env.Root.Data))
		t.Logf("[%s] root.data (%d bytes): %s", label, len(env.Root.Data), hex.EncodeToString(env.Root.Data[:n]))
	}

	// Validate root hash.
	if err := env.Root.Validate(); err != nil {
		t.Logf("[%s] root hash validation: %v", label, err)
	} else {
		t.Logf("[%s] root hash: VALID", label)
	}

	for h, ent := range env.Included {
		t.Logf("[%s] included %s: type=%q", label, h, ent.Type)
		if err := ent.Validate(); err != nil {
			t.Logf("[%s]   hash validation: %v", label, err)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestInteropEncodingCheck verifies our encoding matches expected patterns
// without needing a running peer.
func TestInteropEncodingCheck(t *testing.T) {
	// Verify our ECF encoding produces correct key order.
	data, err := ecf.Encode(map[string]string{"key": "val"})
	if err != nil {
		t.Fatal(err)
	}

	// Encode hashable: "data" before "type".
	hashable, err := ecf.EncodeHashable("test/type", cbor.RawMessage(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Hashable encoding: %s", hex.EncodeToString(hashable))

	// Verify it's a 2-key map with "data" before "type".
	if hashable[0] != 0xA2 {
		t.Fatalf("expected map(2) = 0xA2, got 0x%02x", hashable[0])
	}

	// Verify hash wire format.
	h, _ := hash.Compute("test/type", cbor.RawMessage(data))
	marshaled, _ := h.MarshalCBOR()
	t.Logf("Hash CBOR: %s", hex.EncodeToString(marshaled))
	// Should be 0x58 0x21 (byte string, length 33) followed by 33 bytes.
	if marshaled[0] != 0x58 || marshaled[1] != 0x21 {
		t.Fatalf("wrong hash wire format: expected 58 21, got %02x %02x", marshaled[0], marshaled[1])
	}

	// Test entity encoding.
	ent, _ := entity.NewEntity("test/type", cbor.RawMessage(data))
	entBytes, _ := ecf.Encode(ent)
	t.Logf("Entity CBOR (%d bytes): %s", len(entBytes), hex.EncodeToString(entBytes))

	// Roundtrip.
	var decoded entity.Entity
	if err := ecf.Decode(entBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ContentHash != ent.ContentHash {
		t.Fatal("hash mismatch after roundtrip")
	}

	// Test envelope encoding.
	env := entity.NewEnvelope(ent, nil)
	envBytes, _ := ecf.Encode(env)
	t.Logf("Envelope CBOR (%d bytes): %s", len(envBytes), hex.EncodeToString(envBytes))

	// Decode back.
	var decodedEnv entity.Envelope
	if err := ecf.Decode(envBytes, &decodedEnv); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	t.Logf("Decoded envelope root type: %s", decodedEnv.Root.Type)

	// Verify a full hello envelope.
	kp, _ := crypto.Generate()
	helloEnv, _, _ := protocol.CreateHelloExecute(kp, []string{"entity-core/1.0"})
	helloBytes, _ := ecf.Encode(helloEnv)
	t.Logf("Hello envelope (%d bytes): %s...", len(helloBytes), hex.EncodeToString(helloBytes[:min(80, len(helloBytes))]))

	// Frame it.
	var buf bytes.Buffer
	wire.WriteEnvelope(&buf, helloEnv)
	t.Logf("Framed hello (%d bytes): %s...", buf.Len(), hex.EncodeToString(buf.Bytes()[:min(80, buf.Len())]))
}
