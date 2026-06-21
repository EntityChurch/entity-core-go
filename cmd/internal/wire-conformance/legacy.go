package main

// Pre-Appendix-E "envelope on the f16 boundary" fixture writer. Kept as the
// `legacy-envelope` subcommand for the W2 regression flow (cbor2 C-extension
// non-conformance at f16-boundary values). The Appendix E conformance gate
// runs through build-fixture + emit-canonical against the v1 corpus instead.

import (
	"fmt"
	"math"
	"os"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

func runLegacyEnvelope(args []string) error {
	out := "/tmp/ecf-conform/envelope_go.bin"
	if len(args) > 0 {
		out = args[0]
	}

	mkEntity := func(typ string, data interface{}) entity.Entity {
		raw, err := ecf.Encode(data)
		if err != nil {
			panic(err)
		}
		e, err := entity.NewEntity(typ, cbor.RawMessage(raw))
		if err != nil {
			panic(err)
		}
		return e
	}

	included := make(map[hash.Hash]entity.Entity, 30)
	var firstHash hash.Hash
	for i := 0; i < 30; i++ {
		data := map[string]interface{}{
			"index":   i,
			"content": fmt.Sprintf("content-%03d", i),
			"meta": map[string]string{
				"a": "alpha",
				"z": "omega",
			},
		}
		if i%2 == 0 {
			data["weight"] = 65504.0
			data["scale"] = 1.5
			data["fudge"] = 1.1
		} else {
			data["weight"] = math.Copysign(0, -1)
			data["scale"] = math.Inf(1)
		}
		e := mkEntity("test/doc", data)
		included[e.ContentHash] = e
		if i == 0 {
			firstHash = e.ContentHash
		}
	}

	root := mkEntity("system/tree/merge-request", map[string]interface{}{
		"source":        firstHash,
		"target_tree":   "/peer/inbox",
		"strategy":      "auto",
		"source_prefix": "merge-30-",
		"target_prefix": "merge-30-",
	})

	env := entity.NewEnvelope(root, included)

	bytes, err := ecf.Encode(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, bytes, 0644); err != nil {
		return err
	}

	fmt.Printf("wrote %s: %d bytes, %d included\n", out, len(bytes), len(included))
	fmt.Printf("root hash:  %s\n", root.ContentHash)
	fmt.Printf("first inc:  %s\n", firstHash)
	return nil
}
