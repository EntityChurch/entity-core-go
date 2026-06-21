// dump-messages builds real protocol messages and renders them with full
// type annotations showing how entity types nest through the system.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	kp, _ := crypto.Generate()
	identity, _ := kp.IdentityEntity()

	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("ENTITY PROTOCOL MESSAGE EXAMPLES")
	fmt.Println("Showing full type nesting as entities flow through the system")
	fmt.Println("=" + strings.Repeat("=", 79))

	// 1. Hello
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("1. CONNECT HELLO — opening handshake")
	fmt.Println(strings.Repeat("─", 80))
	helloEnv, _, _ := protocol.CreateHelloExecute(kp, nil)
	renderEnvelope(helloEnv, 0)

	// 2. Authenticate
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("2. CONNECT AUTHENTICATE — proving identity")
	fmt.Println(strings.Repeat("─", 80))
	theirNonce := make([]byte, 32)
	rand.Read(theirNonce)
	authEnv, _ := protocol.CreateAuthenticateExecute(kp, theirNonce)
	renderEnvelope(authEnv, 0)

	// 3. Tree GET
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("3. TREE GET — reading system/type/system/peer")
	fmt.Println(strings.Repeat("─", 80))
	getParams, getResource, _ := tree.CreateGetRequest("system/type/system/peer", "entity")
	capToken := makeDemoCapToken(kp, identity)
	capEntity, _ := capToken.ToEntity()
	getEnv, _ := protocol.CreateAuthenticatedExecute(
		kp, identity, capEntity,
		"req-001", "system/tree", "get",
		getParams, getResource,
	)
	renderEnvelope(getEnv, 0)

	// 4. Tree PUT
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("4. TREE PUT — storing an entity at a path")
	fmt.Println(strings.Repeat("─", 80))
	demoEntity, _ := entity.NewEntity("custom/example", cbor.RawMessage(mustEncode(map[string]string{"name": "test"})))
	putParams, putResource, _ := tree.CreatePutRequest("custom/data/test", &demoEntity)
	putEnv, _ := protocol.CreateAuthenticatedExecute(
		kp, identity, capEntity,
		"req-002", "system/tree", "put",
		putParams, putResource,
	)
	renderEnvelope(putEnv, 0)

	// 5. Show what comes back — EXECUTE_RESPONSE
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("5. EXECUTE RESPONSE — what the peer sends back")
	fmt.Println(strings.Repeat("─", 80))
	// Simulate a tree get response with a type definition result
	typeDef := types.TypeDefinition{
		Name: "system/peer",
		Fields: map[string]types.FieldSpec{
			"peer_id":    {TypeRef: "system/peer-id"},
			"public_key": {TypeRef: "primitive/bytes"},
			"key_type":   {TypeRef: "primitive/string"},
		},
	}
	typeEntity, _ := entity.NewEntity("system/type", cbor.RawMessage(mustEncode(typeDef)))
	respData := types.ExecuteResponseData{
		RequestID: "req-001",
		Status:    200,
		Result:    cbor.RawMessage(mustEncode(typeEntity)),
	}
	respEntity, _ := respData.ToEntity()
	respEnv := entity.NewEnvelope(respEntity, nil)
	renderEnvelope(respEnv, 0)

	// 6. Show an authenticate response with capability grant
	fmt.Println("\n" + strings.Repeat("─", 80))
	fmt.Println("6. AUTHENTICATE RESPONSE — capability grant chain")
	fmt.Println(strings.Repeat("─", 80))
	grantData := types.CapabilityGrantData{Token: capEntity.ContentHash}
	grantEntity, _ := grantData.ToEntity()
	authRespData := types.ExecuteResponseData{
		RequestID: "connect-authenticate",
		Status:    200,
		Result:    cbor.RawMessage(mustEncode(grantEntity)),
	}
	authRespEntity, _ := authRespData.ToEntity()
	// Include the capability token and signature
	capSig := kp.Sign(capEntity.ContentHash.Bytes())
	capSigData := types.SignatureData{
		Target:    capEntity.ContentHash,
		Signer:    identity.ContentHash,
		Algorithm: "ed25519",
		Signature: capSig,
	}
	capSigEntity, _ := capSigData.ToEntity()
	authRespEnv := entity.NewEnvelope(authRespEntity, map[hash.Hash]entity.Entity{
		capEntity.ContentHash:    capEntity,
		capSigEntity.ContentHash: capSigEntity,
		identity.ContentHash:     identity,
	})
	renderEnvelope(authRespEnv, 0)
}

func renderEnvelope(env entity.Envelope, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s┌─ ENVELOPE (system/protocol/envelope extends core/envelope)\n", indent)
	fmt.Printf("%s│\n", indent)
	fmt.Printf("%s├─ root:\n", indent)
	renderEntity(env.Root, depth+1, true)

	if len(env.Included) > 0 {
		fmt.Printf("%s│\n", indent)
		fmt.Printf("%s├─ included: (%d entities)\n", indent, len(env.Included))
		i := 0
		for h, e := range env.Included {
			i++
			last := i == len(env.Included)
			prefix := "├"
			if last {
				prefix = "└"
			}
			fmt.Printf("%s│  %s─ [%s]:\n", indent, prefix, shortHash(h))
			renderEntity(e, depth+2, last)
		}
	}
	fmt.Printf("%s└─\n", indent)
}

func renderEntity(e entity.Entity, depth int, _ bool) {
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s  type: %q\n", indent, e.Type)
	fmt.Printf("%s  hash: %s\n", indent, shortHash(e.ContentHash))

	// Decode and render data based on type
	switch e.Type {
	case types.TypeExecute:
		var d types.ExecuteData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/protocol/execute)\n", indent)
		fmt.Printf("%s    request_id: %q           ← primitive/string\n", indent, d.RequestID)
		fmt.Printf("%s    uri:        %q        ← system/tree/path\n", indent, d.URI)
		fmt.Printf("%s    operation:  %q              ← primitive/string\n", indent, d.Operation)
		if d.Resource != nil {
			fmt.Printf("%s    resource:                     ← system/protocol/resource-target\n", indent)
			fmt.Printf("%s      targets: %v   ← []system/tree/path\n", indent, d.Resource.Targets)
			if len(d.Resource.Exclude) > 0 {
				fmt.Printf("%s      exclude: %v   ← []system/tree/path?\n", indent, d.Resource.Exclude)
			}
		}
		if !d.Author.IsZero() {
			fmt.Printf("%s    author:     %s  ← system/hash\n", indent, shortHash(d.Author))
		}
		if !d.Capability.IsZero() {
			fmt.Printf("%s    capability: %s  ← system/hash\n", indent, shortHash(d.Capability))
		}
		fmt.Printf("%s    params:     <cbor bytes>       ← primitive/any (contains entity)\n", indent)
		// Try to decode params as entity
		var paramEntity entity.Entity
		if err := ecf.Decode(d.Params, &paramEntity); err == nil {
			fmt.Printf("%s    ┌─ params decoded:\n", indent)
			renderEntity(paramEntity, depth+2, true)
		}

	case types.TypeHello:
		var d types.HelloData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/protocol/connect/hello)\n", indent)
		fmt.Printf("%s    peer_id:    %q  ← system/peer-id\n", indent, truncate(d.PeerID, 20))
		fmt.Printf("%s    nonce:      %s...      ← primitive/bytes (32 bytes)\n", indent, hex.EncodeToString(d.Nonce[:8]))
		fmt.Printf("%s    protocols:  %v    ← []primitive/string\n", indent, d.Protocols)
		fmt.Printf("%s    timestamp:  %d              ← primitive/uint\n", indent, d.Timestamp)

	case types.TypeAuthenticate:
		var d types.AuthenticateData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/protocol/connect/authenticate)\n", indent)
		fmt.Printf("%s    peer_id:    %q  ← system/peer-id\n", indent, truncate(d.PeerID, 20))
		fmt.Printf("%s    public_key: %s...      ← primitive/bytes (32 bytes)\n", indent, hex.EncodeToString(d.PublicKey[:8]))
		fmt.Printf("%s    key_type:   %q            ← primitive/string\n", indent, d.KeyType)
		fmt.Printf("%s    nonce:      %s...      ← primitive/bytes (32 bytes)\n", indent, hex.EncodeToString(d.Nonce[:8]))

	case types.TypeExecuteResponse:
		var d types.ExecuteResponseData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/protocol/execute/response)\n", indent)
		fmt.Printf("%s    request_id: %q  ← primitive/string\n", indent, d.RequestID)
		fmt.Printf("%s    status:     %d                  ← primitive/uint\n", indent, d.Status)
		fmt.Printf("%s    result:     <cbor bytes>       ← primitive/any (contains entity)\n", indent)
		var resultEntity entity.Entity
		if err := ecf.Decode(d.Result, &resultEntity); err == nil {
			fmt.Printf("%s    ┌─ result decoded:\n", indent)
			renderEntity(resultEntity, depth+2, true)
		}

	case "system/peer":
		var d types.PeerData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/peer) — v7.65: peer_id derived from public_key (not in hashable basis)\n", indent)
		fmt.Printf("%s    public_key: %s...      ← primitive/bytes\n", indent, hex.EncodeToString(d.PublicKey[:8]))
		fmt.Printf("%s    key_type:   %q            ← primitive/string\n", indent, d.KeyType)

	case "system/signature":
		var d types.SignatureData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/signature)\n", indent)
		fmt.Printf("%s    target:    %s  ← system/hash\n", indent, shortHash(d.Target))
		fmt.Printf("%s    signer:    %s  ← system/hash (identity entity hash)\n", indent, shortHash(d.Signer))
		fmt.Printf("%s    algorithm: %q            ← primitive/string\n", indent, d.Algorithm)
		fmt.Printf("%s    signature: %s...  ← primitive/bytes (64 bytes)\n", indent, hex.EncodeToString(d.Signature[:12]))

	case types.TypeCapToken:
		var d types.CapabilityTokenData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/capability/token)\n", indent)
		fmt.Printf("%s    granter:    %s  ← system/hash | multi-granter\n", indent, granterDisplay(d.Granter))
		fmt.Printf("%s    grantee:    %s  ← system/hash\n", indent, shortHash(d.Grantee))
		fmt.Printf("%s    created_at: %d              ← primitive/uint\n", indent, d.CreatedAt)
		fmt.Printf("%s    grants: (%d entries)          ← []system/capability/grant-entry\n", indent, len(d.Grants))
		for i, g := range d.Grants {
			fmt.Printf("%s      [%d]:\n", indent, i)
			fmt.Printf("%s        handlers:   %v  ← system/capability/path-scope\n", indent, g.Handlers.Include)
			fmt.Printf("%s        resources:  %v  ← system/capability/path-scope\n", indent, g.Resources.Include)
			fmt.Printf("%s        operations: %v  ← system/capability/id-scope\n", indent, g.Operations.Include)
		}

	case types.TypeCapGrant:
		var d types.CapabilityGrantData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/capability/grant)\n", indent)
		fmt.Printf("%s    token: %s  ← system/hash (→ capability/token entity)\n", indent, shortHash(d.Token))

	case "system/type":
		var d types.TypeDefinition
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/type)\n", indent)
		fmt.Printf("%s    name:    %q  ← system/type/name\n", indent, d.Name)
		if d.Extends != "" {
			fmt.Printf("%s    extends: %q  ← system/type/name\n", indent, d.Extends)
		}
		if len(d.Fields) > 0 {
			fmt.Printf("%s    fields:              ← map<string, system/type/field-spec>\n", indent)
			for name, f := range d.Fields {
				renderFieldSpec(indent+"      ", name, f)
			}
		}

	case "system/tree/get-request":
		var d types.GetRequestData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/tree/get-request)\n", indent)
		fmt.Printf("%s    mode: %q  ← primitive/string\n", indent, d.Mode)

	case "system/tree/put-request":
		var d types.PutRequestData
		ecf.Decode(e.Data, &d)
		fmt.Printf("%s  data: (system/tree/put-request)\n", indent)
		if d.Entity != nil {
			fmt.Printf("%s    entity: <cbor bytes>  ← core/entity?\n", indent)
		}

	default:
		fmt.Printf("%s  data: <%d bytes of CBOR>\n", indent, len(e.Data))
	}
}

func renderFieldSpec(indent, name string, f types.FieldSpec) {
	opt := ""
	if f.Optional {
		opt = "?"
	}
	if f.TypeRef != "" {
		fmt.Printf("%s%s: %s%s\n", indent, name, f.TypeRef, opt)
	} else if f.ArrayOf != nil {
		fmt.Printf("%s%s: [%s]%s\n", indent, name, f.ArrayOf.TypeRef, opt)
	} else if f.MapOf != nil {
		fmt.Printf("%s%s: map<%s>%s\n", indent, name, f.MapOf.TypeRef, opt)
	}
}

func shortHash(h hash.Hash) string {
	d := h.EffectiveDigest()
	if len(d) < 8 {
		return fmt.Sprintf("ecf:%x", d)
	}
	return fmt.Sprintf("ecf-sha256:%s..%s", hex.EncodeToString(d[:4]), hex.EncodeToString(d[len(d)-2:]))
}

func granterDisplay(g types.Granter) string {
	if h, single := g.SingleHash(); single {
		return shortHash(h)
	}
	mg, _ := g.Multi()
	return fmt.Sprintf("multi-sig(%d-of-%d)", mg.Threshold, len(mg.Signers))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func mustEncode(v interface{}) []byte {
	b, err := ecf.Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func makeDemoCapToken(kp crypto.Keypair, identity entity.Entity) types.CapabilityTokenData {
	return types.CapabilityTokenData{
		Granter:   types.SingleSigGranter(identity.ContentHash),
		Grantee:   identity.ContentHash,
		CreatedAt: 1708700000000,
		Grants: []types.GrantEntry{
			{
				Handlers:   types.CapabilityScope{Include: []string{"system/tree"}},
				Resources:  types.CapabilityScope{Include: []string{"*"}},
				Operations: types.CapabilityScope{Include: []string{"get", "put"}},
			},
		},
	}
}
