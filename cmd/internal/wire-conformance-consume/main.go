// wire-conformance-consume reads a Python-produced envelope and validates
// every entity's content hash using the real entity-core-go ECF path.
package main

import (
	"fmt"
	"os"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

func main() {
	bytes, err := os.ReadFile("/tmp/ecf-conform/envelope_py.bin")
	if err != nil {
		panic(err)
	}
	fmt.Printf("read %d bytes\n", len(bytes))

	var env entity.Envelope
	if err := ecf.Decode(bytes, &env); err != nil {
		fmt.Fprintf(os.Stderr, "decode failed: %v\n", err)
		os.Exit(1)
	}

	// Round-trip check: re-encode the decoded envelope, compare to original.
	reenc, err := ecf.Encode(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-encode failed: %v\n", err)
		os.Exit(1)
	}
	if len(reenc) == len(bytes) {
		match := true
		for i := range bytes {
			if bytes[i] != reenc[i] {
				match = false
				fmt.Printf("ENVELOPE round-trip DIFFERS at byte %d: orig=0x%02x reenc=0x%02x\n",
					i, bytes[i], reenc[i])
				break
			}
		}
		if match {
			fmt.Println("ENVELOPE round-trip: byte-identical ✓")
		}
	} else {
		fmt.Printf("ENVELOPE round-trip: LENGTH DIFFERS — orig=%d reenc=%d\n", len(bytes), len(reenc))
	}

	pass, fail := 0, 0
	if err := env.Root.Validate(); err != nil {
		fmt.Printf("ROOT hash: FAIL — %v\n", err)
		fail++
	} else {
		fmt.Printf("ROOT hash: PASS (type=%s)\n", env.Root.Type)
		pass++
	}
	for h, ent := range env.Included {
		if err := ent.Validate(); err != nil {
			fmt.Printf("INCLUDED %s type=%s: FAIL — %v\n",
				hash.Hash(h).String()[:30], ent.Type, err)
			fail++
		} else {
			pass++
		}
	}
	fmt.Printf("\n=== SUMMARY: %d pass, %d fail ===\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}
