// Quick diagnostic: connect to a peer, send hello, dump the raw CBOR of the result field.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/core/wire"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	addr := "localhost:9000"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer conn.Close()

	kp, _ := crypto.Generate()
	helloEnv, _, err := protocol.CreateHelloExecute(kp, nil)
	if err != nil {
		log.Fatal("create hello:", err)
	}
	if err := wire.WriteEnvelope(conn, helloEnv); err != nil {
		log.Fatal("send hello:", err)
	}

	respBytes, err := wire.ReadFrame(conn)
	if err != nil {
		log.Fatal("read frame:", err)
	}

	fmt.Printf("=== Raw envelope frame (%d bytes) ===\n", len(respBytes))

	// Decode envelope
	var env entity.Envelope
	if err := ecf.Decode(respBytes, &env); err != nil {
		fmt.Printf("Failed to decode envelope: %v\n", err)
		fmt.Printf("Raw hex:\n%s\n", hex.Dump(respBytes[:min(len(respBytes), 512)]))
		return
	}

	fmt.Printf("Root type: %s\n", env.Root.Type)
	fmt.Printf("Included count: %d\n", len(env.Included))

	// Decode execute response data
	if env.Root.Type != types.TypeExecuteResponse {
		fmt.Printf("Unexpected root type (expected %s)\n", types.TypeExecuteResponse)
		return
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		fmt.Printf("Failed to decode response data: %v\n", err)
		fmt.Printf("Root data hex:\n%s\n", hex.Dump(env.Root.Data))
		return
	}

	fmt.Printf("Status: %d\n", respData.Status)
	fmt.Printf("\n=== Result field raw CBOR (%d bytes) ===\n", len(respData.Result))
	fmt.Printf("%s\n", hex.Dump(respData.Result))

	// Identify CBOR major type
	if len(respData.Result) > 0 {
		majorType := respData.Result[0] >> 5
		additionalInfo := respData.Result[0] & 0x1f
		typeNames := []string{"unsigned int", "negative int", "byte string", "text string", "array", "map", "tag", "simple/float"}
		fmt.Printf("CBOR major type: %d (%s), additional info: %d\n", majorType, typeNames[majorType], additionalInfo)

		if majorType == 2 {
			fmt.Println("\n*** PROBLEM: Result is a CBOR byte string (major type 2).")
			fmt.Println("    It SHOULD be a CBOR map (major type 5) representing an Entity {type, data, content_hash}.")
			fmt.Println("    The entity is being double-encoded: serialized to bytes, then wrapped in a byte string.")
			fmt.Println("    Fix: embed the entity as a CBOR map directly, not as a byte-string-encoded blob.")

			// Try to decode the inner bytes
			var innerBytes []byte
			if err := ecf.Decode(respData.Result, &innerBytes); err == nil {
				fmt.Printf("\n=== Inner byte string content (%d bytes) ===\n", len(innerBytes))
				fmt.Printf("%s\n", hex.Dump(innerBytes[:min(len(innerBytes), 512)]))
				// Try decoding that as an entity
				var innerEntity entity.Entity
				if err := ecf.Decode(innerBytes, &innerEntity); err == nil {
					fmt.Printf("Inner entity decodes OK! Type: %q\n", innerEntity.Type)
					fmt.Println("Confirmed: entity is double-encoded.")
				} else {
					fmt.Printf("Inner bytes don't decode as entity either: %v\n", err)
				}
			}
		} else if majorType == 5 {
			fmt.Println("Result is a CBOR map (correct major type).")
			// Try decoding
			var ent entity.Entity
			if err := ecf.Decode(respData.Result, &ent); err != nil {
				fmt.Printf("But failed to decode as Entity: %v\n", err)

				// Dump the map keys
				var raw map[string]cbor.RawMessage
				if err2 := ecf.Decode(respData.Result, &raw); err2 == nil {
					fmt.Printf("Map keys: ")
					for k := range raw {
						fmt.Printf("%q ", k)
					}
					fmt.Println()
					for k, v := range raw {
						fmt.Printf("  %s (%d bytes): %s\n", k, len(v), hex.EncodeToString(v[:min(len(v), 64)]))
					}
				}
			} else {
				fmt.Printf("Entity type: %q\n", ent.Type)
				fmt.Println("Result decodes fine — issue may be elsewhere.")
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
