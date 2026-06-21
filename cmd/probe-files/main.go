// Command probe-files issues a single local/files operation against a peer for
// diagnostics.
//
// Usage: probe-files <addr> <operation> <tree-path> [content].
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/localfiles"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: probe-files <addr> <operation> <tree-path> [content]\n")
		fmt.Fprintf(os.Stderr, "\nOperations:\n")
		fmt.Fprintf(os.Stderr, "  list   <tree-path>              List directory contents\n")
		fmt.Fprintf(os.Stderr, "  read   <tree-path>              Read a file\n")
		fmt.Fprintf(os.Stderr, "  write  <tree-path> <content>    Write content to a file\n")
		fmt.Fprintf(os.Stderr, "  delete <tree-path>              Delete a file\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  probe-files localhost:9002 list local/files/shared/\n")
		fmt.Fprintf(os.Stderr, "  probe-files localhost:9002 read local/files/shared/readme.txt\n")
		fmt.Fprintf(os.Stderr, "  probe-files localhost:9002 write local/files/shared/new.txt 'hello world'\n")
		os.Exit(2)
	}
	addr := os.Args[1]
	operation := os.Args[2]
	treePath := os.Args[3]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := validate.NewPeerClientWithIdentity(addr, "framework-admin")
	if err != nil {
		// Fall back to ephemeral identity.
		client, err = validate.NewPeerClient(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			os.Exit(1)
		}
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	client.PerformHandshake(ctx)
	if !client.Connected() {
		fmt.Fprintf(os.Stderr, "handshake failed\n")
		os.Exit(1)
	}

	peerID := client.RemotePeerID()
	fmt.Printf("Connected to %s (PeerID: %s)\n\n", addr, peerID)

	// Build params entity.
	var paramsEntity entity.Entity
	switch operation {
	case "write":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "write requires content argument\n")
			os.Exit(2)
		}
		body := []byte(os.Args[4])
		raw, _ := ecf.Encode(localfiles.WriteRequestData{
			Bytes:      body,
			CreateDirs: true,
		})
		paramsEntity, _ = entity.NewEntity(localfiles.TypeWriteRequest, cbor.RawMessage(raw))
	default:
		raw, _ := ecf.Encode(map[string]interface{}{})
		paramsEntity, _ = entity.NewEntity("primitive/map", cbor.RawMessage(raw))
	}

	resource := &types.ResourceTarget{Targets: []string{treePath}}
	uri := fmt.Sprintf("entity://%s/local/files", peerID)

	env, _, err := client.SendExecute(ctx, uri, operation, paramsEntity, resource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execute error: %v\n", err)
		os.Exit(1)
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Status: %d\n", respData.Status)

	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		fmt.Printf("(raw result, could not decode as entity)\n")
		return
	}

	fmt.Printf("Type:   %s\n", resultEntity.Type)

	var decoded interface{}
	ecf.Decode(resultEntity.Data, &decoded)
	if decoded != nil {
		var b strings.Builder
		entity.FormatCBORValue(&b, "  ", decoded)
		fmt.Print(b.String())
	}
}
