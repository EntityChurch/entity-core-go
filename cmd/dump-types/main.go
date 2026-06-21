// One-off diagnostic: fetch the 5 hash-divergent type defs from Go & Rust
// peers and dump them side-by-side for the Rust team to inspect.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/types"
)

var typesToDiff = []string{
	"compute/apply",
	"compute/lookup/hash",
	"compute/lookup/tree",
	"system/capability/token",
	"system/compute/subgraph",
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: dump-types <go_addr> <rust_addr>")
		os.Exit(2)
	}
	goAddr, rustAddr := os.Args[1], os.Args[2]

	ctx := context.Background()
	goClient, err := validate.NewPeerClientWithIdentity(goAddr, "framework-admin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "go client: %v\n", err)
		os.Exit(1)
	}
	defer goClient.Close()
	if err := goClient.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "go connect: %v\n", err)
		os.Exit(1)
	}
	for _, c := range goClient.PerformHandshake(ctx) {
		if c.Severity == validate.Fail {
			fmt.Fprintf(os.Stderr, "go handshake fail: %s\n", c.Message)
		}
	}
	rustClient, err := validate.NewPeerClientWithIdentity(rustAddr, "framework-admin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "rust client: %v\n", err)
		os.Exit(1)
	}
	defer rustClient.Close()
	if err := rustClient.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "rust connect: %v\n", err)
		os.Exit(1)
	}
	for _, c := range rustClient.PerformHandshake(ctx) {
		if c.Severity == validate.Fail {
			fmt.Fprintf(os.Stderr, "rust handshake fail: %s\n", c.Message)
		}
	}
	for _, t := range typesToDiff {
		fmt.Printf("\n========== %s ==========\n", t)
		treePath := "system/type/" + t

		goEnt, _, err := goClient.TreeGet(ctx, treePath)
		if err != nil {
			fmt.Printf("go fetch %s: %v\n", treePath, err)
			continue
		}
		rustEnt, _, err := rustClient.TreeGet(ctx, treePath)
		if err != nil {
			fmt.Printf("rust fetch %s: %v\n", treePath, err)
			continue
		}

		var goDef, rustDef types.TypeDefinition
		_ = ecf.Decode(goEnt.Data, &goDef)
		_ = ecf.Decode(rustEnt.Data, &rustDef)

		fmt.Printf("Go    content_hash: %s  (%d bytes data)\n", goEnt.ContentHash, len(goEnt.Data))
		fmt.Printf("Rust  content_hash: %s  (%d bytes data)\n", rustEnt.ContentHash, len(rustEnt.Data))
		fmt.Printf("Go    raw CBOR:    %s\n", hex.EncodeToString(goEnt.Data))
		fmt.Printf("Rust  raw CBOR:    %s\n", hex.EncodeToString(rustEnt.Data))
		fmt.Printf("Go    decoded:     %s extends=%q fields=%d\n",
			goDef.Name, goDef.Extends, len(goDef.Fields))
		fmt.Printf("Rust  decoded:     %s extends=%q fields=%d\n",
			rustDef.Name, rustDef.Extends, len(rustDef.Fields))

		// Field-by-field diff (string-render to dodge struct-with-slice incomparability).
		allFields := map[string]bool{}
		for k := range goDef.Fields {
			allFields[k] = true
		}
		for k := range rustDef.Fields {
			allFields[k] = true
		}
		for k := range allFields {
			gf, gok := goDef.Fields[k]
			rf, rok := rustDef.Fields[k]
			gs := fmt.Sprintf("%+v", gf)
			rs := fmt.Sprintf("%+v", rf)
			if gok && rok {
				if gs == rs {
					fmt.Printf("  [%s] same: %s\n", k, gs)
				} else {
					fmt.Printf("  [%s] DIFF\n    go:   %s\n    rust: %s\n", k, gs, rs)
				}
			} else if gok {
				fmt.Printf("  [%s] go-only: %s\n", k, gs)
			} else {
				fmt.Printf("  [%s] rust-only: %s\n", k, rs)
			}
		}
	}
}
