// probe-ingest — connect to a peer over TCP, ingest a chunk entity
// under a configured content-namespace, print the resulting hex
// hash. Used to seed cohort cross-impl Chunk E poll testing:
//
//	GO_HASH=$(go run ./cmd/probe-ingest -addr 127.0.0.1:9101 \
//	  -namespace system/content/public -payload "hello cohort")
//	export ENTITY_CROSS_IMPL_GO_POLL_HASH=$GO_HASH
//
// The ingest binds the chunk at `{namespace}/{hex(H)}` per CONTENT
// §6.4.2 Hash Tree Presence — exactly the binding the live peer's
// NamespaceScope predicate matches. With matching `--serve-namespace`
// on the peer, the poll URL `/content/{hex(H)}` then 200s.
//
// The TCP address is the peer's TCP listener, NOT the poll URL — we
// need the live protocol to drive the ingest. Once the chunk is
// bound, the poll URL serves it.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	addr := flag.String("addr", "", "peer TCP address (e.g. 127.0.0.1:9001)")
	namespace := flag.String("namespace", "system/content/public", "content namespace to bind under")
	payload := flag.String("payload", "", "chunk payload bytes (string); empty = use default greeting")
	identity := flag.String("identity", "", "named identity from ~/.entity/identities/ (optional)")
	bindFallback := flag.Bool("bind-fallback", false, "if the target impl's system/content:ingest doesn't yet do CONTENT §6.4.2 Hash Tree Presence, also call system/tree:put at {namespace}/{hex(H)} so namespace-scoped serving-mode can find the entity. Go ≥ this commit binds natively; toggle for Rust/Python until they land.")
	timeout := flag.Duration("timeout", 30*time.Second, "overall timeout")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "Error: -addr is required (peer TCP listener)")
		os.Exit(2)
	}

	body := []byte(*payload)
	if len(body) == 0 {
		body = []byte("cohort cross-impl Chunk E pin matrix payload — seeded by probe-ingest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var client *validate.PeerClient
	var err error
	if *identity != "" {
		client, err = validate.NewPeerClientWithIdentity(*addr, *identity)
	} else {
		client, err = validate.NewPeerClient(*addr)
	}
	if err != nil {
		fatal("new client", err)
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		fatal("connect", err)
	}
	for _, r := range client.PerformHandshake(ctx) {
		if r.Severity == validate.Fail {
			fatal("handshake "+r.Name, fmt.Errorf("%s", r.Message))
		}
	}

	// Build the chunk entity, wrap in ingest-request, send.
	chunkEnt, err := types.ContentChunkData{Payload: body}.ToEntity()
	if err != nil {
		fatal("encode chunk", err)
	}
	chunkBytes, err := ecf.Encode(chunkEnt)
	if err != nil {
		fatal("ecf chunk", err)
	}
	chunkRaw := cbor.RawMessage(chunkBytes)
	ingestReq, err := types.ContentIngestRequestData{Entity: &chunkRaw}.ToEntity()
	if err != nil {
		fatal("encode ingest-request", err)
	}

	// The resource target is the namespace path (per V7 §3.2 path-as-
	// resource MUST). The handler reads the namespace from resource,
	// binds the chunk at NAMESPACE/{hex(H)}.
	resource := &types.ResourceTarget{Targets: []string{*namespace}}
	contentURI := fmt.Sprintf("entity://%s/system/content", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, contentURI, "ingest", ingestReq, resource)
	if err != nil {
		fatal("SendExecute ingest", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		fatal("decode response", err)
	}
	if respData.Status != 200 {
		var resultEnt entity.Entity
		_ = ecf.Decode(respData.Result, &resultEnt)
		fmt.Fprintf(os.Stderr, "ingest returned status %d (body type %q)\n", respData.Status, resultEnt.Type)
		if errData, derr := types.ErrorDataFromEntity(resultEnt); derr == nil {
			fmt.Fprintf(os.Stderr, "  error.code=%q\n  error.message=%q\n", errData.Code, errData.Message)
		}
		os.Exit(1)
	}

	// Decode ingest-result for the chunk hash.
	var resultEnt entity.Entity
	if err := ecf.Decode(respData.Result, &resultEnt); err != nil {
		fatal("decode result entity", err)
	}
	var result types.ContentIngestResultData
	if err := ecf.Decode(resultEnt.Data, &result); err != nil {
		fatal("decode ingest-result", err)
	}
	H := result.RootHash
	// 66-hex form: algorithm byte + 32-byte digest per V7 §3.5 and
	// RULING-SERVING-MODE-CONTENT-BODY-SHAPE §5 B. This is the
	// canonical URL/binding/ETag hex shape; consumers `$(...)`-
	// capture this string and paste it into /content/{hex}.
	hexH := fmt.Sprintf("%x", H.Bytes())

	// Per CONTENT §6.4.1/§6.4.2 the ingest handler itself binds the
	// entity at {namespace}/{hex(H)} in the tree (Hash Tree Presence).
	// Go landed this fix following arch ruling 1b5c125 §2; Rust + Python
	// are following. While any impl is still missing it, this probe
	// optionally re-binds via system/tree:put to keep the cross-impl
	// matrix runnable — guarded by -bind-fallback (default off) so the
	// path stays clean once cohort fully converges.
	if *bindFallback {
		bindingPath := *namespace + "/" + hexH
		putReq, perr := types.PutRequestData{Entity: cbor.RawMessage(chunkBytes)}.ToEntity()
		if perr != nil {
			fatal("encode tree-put-request", perr)
		}
		treeURI := fmt.Sprintf("entity://%s/system/tree", client.RemotePeerID())
		bindResource := &types.ResourceTarget{Targets: []string{bindingPath}}
		bindEnv, _, berr := client.SendExecute(ctx, treeURI, "put", putReq, bindResource)
		if berr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: bind-fallback tree:put at %s failed: %v\n", bindingPath, berr)
		} else {
			bindResp, _ := types.ExecuteResponseDataFromEntity(bindEnv.Root)
			if bindResp.Status != 200 {
				var bindResultEnt entity.Entity
				_ = ecf.Decode(bindResp.Result, &bindResultEnt)
				fmt.Fprintf(os.Stderr, "WARNING: bind-fallback tree:put returned status %d (type %q)\n",
					bindResp.Status, bindResultEnt.Type)
			}
		}
	}

	// Two outputs: stdout is just the hex (so callers can `$(...)`
	// capture it); stderr carries the human summary.
	fmt.Fprintf(os.Stderr, "ingested %d entity under %q on %s -> %s\n",
		result.IngestedCount, *namespace, *addr, H)
	fmt.Println(hexH)
}

func fatal(stage string, err error) {
	fmt.Fprintf(os.Stderr, "Error (%s): %v\n", stage, err)
	os.Exit(1)
}
