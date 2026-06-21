// probe-grant — diagnostic for the cross-impl handler-grant interop gap.
//
// Connects to a peer, registers a minimal entity-native handler via
// system/handler:register, then reads back the grant entity the handlers
// handler installed at system/capability/grants/{pattern} and dumps:
//   - entity type and content hash
//   - raw CBOR data (hex)
//   - decoded CapabilityTokenData with all fields visible
//
// Used to compare what each impl (Go, Python, Rust) actually emits for a
// handler grant and identify where the validation gap is.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	addr := flag.String("addr", "", "peer address (host:port)")
	pattern := flag.String("pattern", "app/probe-grant/sample", "pattern to register at")
	flag.Parse()
	if *addr == "" {
		log.Fatal("usage: probe-grant -addr host:port [-pattern path]")
	}

	ctx := context.Background()
	c, err := validate.NewPeerClient(*addr)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		log.Fatalf("tcp connect: %v", err)
	}
	for _, check := range c.PerformHandshake(ctx) {
		if check.Severity == validate.Fail {
			log.Fatalf("handshake check %q failed: %s", check.Name, check.Message)
		}
	}
	if !c.Connected() {
		log.Fatal("handshake did not complete")
	}

	peerID := string(c.RemotePeerID())
	fmt.Fprintf(os.Stdout, "Peer: %s @ %s\n\n", peerID, *addr)

	// Plant a tiny expression at {pattern}/expr (literal 1).
	exprPath := *pattern + "/expr"
	litEnt, _ := types.ComputeLiteralData{Value: uint64(1)}.ToEntity()
	if _, err := c.TreePut(ctx, exprPath, litEnt); err != nil {
		log.Fatalf("plant expression: %v", err)
	}

	// Register a handler with a wildcard requested_scope. Best-effort
	// unregister first so this script is idempotent across runs.
	// V7 §3.2: pattern lives in resource; unregister params is empty.
	emptyData, _ := ecf.Encode(map[string]interface{}{})
	emptyParams, _ := entity.NewEntity("primitive/any", emptyData)
	uri := fmt.Sprintf("entity://%s/system/handler", peerID)
	handlerResource := &types.ResourceTarget{Targets: []string{"system/handler/" + *pattern}}
	c.SendExecute(ctx, uri, "unregister", emptyParams, handlerResource)

	scope := []types.GrantEntry{{
		Operations: types.CapabilityScope{Include: []string{"*"}},
		Handlers:   types.CapabilityScope{Include: []string{"*"}},
		Resources:  types.CapabilityScope{Include: []string{"*"}},
	}}
	manifest := types.HandlerManifestData{
		Pattern: *pattern,
		Name:    "probe",
		Operations: map[string]types.HandlerOperationSpec{
			"compute": {InputType: "primitive/any", OutputType: "primitive/any"},
		},
		ExpressionPath: exprPath,
		InternalScope:  scope,
	}
	regReq := types.RegisterRequestData{Manifest: manifest, RequestedScope: scope}
	regEnt, _ := regReq.ToEntity()
	env, _, err := c.SendExecute(ctx, uri, "register", regEnt, handlerResource)
	if err != nil {
		log.Fatalf("register: %v", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil || respData.Status != 200 {
		log.Fatalf("register status %d (err=%v)", respData.Status, err)
	}
	fmt.Fprintf(os.Stdout, "Registered handler at %s\n\n", *pattern)

	// Read back the grant entity at system/capability/grants/{pattern}.
	grantPath := "system/capability/grants/" + *pattern
	grantEnt, _, err := c.TreeGet(ctx, grantPath)
	if err != nil {
		log.Fatalf("get grant: %v", err)
	}

	fmt.Fprintf(os.Stdout, "── Grant entity at %s ──\n", grantPath)
	fmt.Fprintf(os.Stdout, "type:         %s\n", grantEnt.Type)
	fmt.Fprintf(os.Stdout, "content_hash: %s\n", grantEnt.ContentHash)
	fmt.Fprintf(os.Stdout, "data (hex):   %s\n", hex.EncodeToString(grantEnt.Data))
	fmt.Fprintln(os.Stdout)

	// Try strict-decode as CapabilityTokenData.
	var typedCap types.CapabilityTokenData
	if err := ecf.Decode(grantEnt.Data, &typedCap); err == nil {
		fmt.Fprintf(os.Stdout, "── Decoded as system/capability/token ──\n")
		dumpToken(os.Stdout, typedCap)
	} else {
		fmt.Fprintf(os.Stdout, "(strict decode as CapabilityTokenData failed: %v)\n", err)
	}

	// Also dump as a raw map so we can see any extra fields the strict decoder
	// skipped (e.g., signature, granter set by another impl).
	var asMap map[string]any
	if err := cbor.Unmarshal(grantEnt.Data, &asMap); err == nil {
		fmt.Fprintf(os.Stdout, "\n── Raw CBOR map keys ──\n")
		printMap(os.Stdout, asMap, 0)
	}

	// Resolve granter identity if single-sig hash is set.
	granterHash, single := typedCap.Granter.SingleHash()
	switch {
	case single && !granterHash.IsZero():
		fmt.Fprintf(os.Stdout, "\n── Following granter hash %s ──\n", granterHash)
		identity, found := tryFetchByHash(ctx, c, granterHash, *pattern)
		if found {
			fmt.Fprintf(os.Stdout, "granter identity entity type: %s\n", identity.Type)
			var idData types.PeerData
			if err := ecf.Decode(identity.Data, &idData); err == nil {
				// v7.65 §1.5: peer_id derives from (public_key, key_type).
				if ktByte, ktOK := idData.KeyTypeByte(); ktOK {
					if granterPID, pidErr := crypto.PeerIDFromPublicKey(idData.PublicKey, ktByte); pidErr == nil {
						fmt.Fprintf(os.Stdout, "granter peer_id (derived): %s\n", granterPID)
						fmt.Fprintf(os.Stdout, "granter is local peer? %v\n", string(granterPID) == peerID)
					}
				}
			}
		} else {
			fmt.Fprintln(os.Stdout, "granter identity entity not retrievable via tree/content lookup")
		}
	case !single:
		mg, _ := typedCap.Granter.Multi()
		fmt.Fprintf(os.Stdout, "\n── Multi-sig granter (%d-of-%d) ──\n", mg.Threshold, len(mg.Signers))
		for i, s := range mg.Signers {
			fmt.Fprintf(os.Stdout, "  signer[%d]: %s\n", i, s)
		}
	default:
		fmt.Fprintln(os.Stdout, "\nGranter is unset (anonymous grant).")
	}

	// Cleanup: unregister.
	c.SendExecute(ctx, uri, "unregister", emptyParams, handlerResource)
}

func dumpToken(w *os.File, t types.CapabilityTokenData) {
	fmt.Fprintf(w, "  granter:    %s\n", t.Granter.String())
	fmt.Fprintf(w, "  grantee:    %s\n", hashOrEmpty(t.Grantee))
	fmt.Fprintf(w, "  created_at: %d\n", t.CreatedAt)
	if t.NotBefore != nil {
		fmt.Fprintf(w, "  not_before: %d\n", *t.NotBefore)
	}
	if t.ExpiresAt != nil {
		fmt.Fprintf(w, "  expires_at: %d\n", *t.ExpiresAt)
	}
	fmt.Fprintf(w, "  grants:     %d entries\n", len(t.Grants))
	for i, g := range t.Grants {
		fmt.Fprintf(w, "    [%d] ops=%v handlers=%v resources=%v\n", i,
			g.Operations.Include, g.Handlers.Include, g.Resources.Include)
	}
}

func hashOrEmpty(h hash.Hash) string {
	if h.IsZero() {
		return "(zero)"
	}
	return h.String()
}

func printMap(w *os.File, m map[string]any, depth int) {
	indent := strings.Repeat("  ", depth+1)
	for k, v := range m {
		switch val := v.(type) {
		case []byte:
			fmt.Fprintf(w, "%s%s: bytes(%d) %s\n", indent, k, len(val), hex.EncodeToString(val))
		case map[any]any:
			fmt.Fprintf(w, "%s%s:\n", indent, k)
			for kk, vv := range val {
				fmt.Fprintf(w, "%s  %v: %v\n", indent, kk, vv)
			}
		case map[string]any:
			fmt.Fprintf(w, "%s%s:\n", indent, k)
			printMap(w, val, depth+1)
		default:
			fmt.Fprintf(w, "%s%s: %v\n", indent, k, v)
		}
	}
}

// tryFetchByHash makes a best-effort attempt to retrieve an entity by hash via
// system/content:get if available; returns (entity, found).
func tryFetchByHash(ctx context.Context, c *validate.PeerClient, h hash.Hash, scratchPath string) (entity.Entity, bool) {
	// system/content/get takes a hash list and returns matching entities.
	type contentGetReq struct {
		Hashes []hash.Hash `cbor:"hashes"`
	}
	reqRaw, err := ecf.Encode(contentGetReq{Hashes: []hash.Hash{h}})
	if err != nil {
		return entity.Entity{}, false
	}
	reqEnt, err := entity.NewEntity("system/content/get-request", cbor.RawMessage(reqRaw))
	if err != nil {
		return entity.Entity{}, false
	}
	uri := fmt.Sprintf("entity://%s/system/content", c.RemotePeerID())
	env, _, err := c.SendExecute(ctx, uri, "get", reqEnt, nil)
	if err != nil {
		return entity.Entity{}, false
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil || respData.Status != 200 {
		return entity.Entity{}, false
	}
	// Result envelope holds the included entities; pick the one matching hash.
	for hh, ent := range env.Included {
		if hh == h {
			return ent, true
		}
	}
	return entity.Entity{}, false
}
