// Command corpus-sig-verify mechanizes the ecf-conformance corpus `signature`
// category under the CQ-22 ruling (ENTITY-CORE-PROTOCOL §7.3, 0.8.2.26):
//
//	a signature is computed over the target entity's FULL content_hash
//	(format code byte ‖ digest) — NOT over the raw canonical-ECF bytes.
//
// WHY GO OWNS THIS. `GUIDE-EXTENSION-DEVELOPMENT` §7 Stage 4 assigns vector
// production to the implementations, and arch is not a vector author. The
// corpus `signature` values were computed once by hand and never mechanized,
// which is how a wrong sign construction (signing ECF bytes) sat inside a
// locked artifact for its whole life — reading a normative artifact and
// running it are different acts, and only one is a measurement. This tool is
// the measurement, standing.
//
// It reads the corpus `.diag` (read-only; the artifact lives in
// entity-core-protocol and committing it is that repo's, not go's), and for
// every `signature.*` vector recomputes the §7.3 canonical from the vector's
// own (seed, entity) input using the Go ECF encoder + core/hash + RFC-8032
// Ed25519, then:
//
//   - compares it to the stored `canonical`, and
//   - independently verifies the stored signature against the content_hash
//     message with the seed's public key (a second, construction-independent
//     arm — a matching-but-invalid signature cannot pass both).
//
//	go run ./cmd/corpus-sig-verify              # print stored vs recomputed
//	go run ./cmd/corpus-sig-verify -verify      # exit 1 on any mismatch (gate)
//	go run ./cmd/corpus-sig-verify -diag <path> # a corrected copy, e.g. pre-land
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/cmd/internal/diagcodec"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"
)

const defaultDiag = "../entity-core-protocol/specs/test-vectors/ecf-conformance/conformance-vectors.diag"

func main() {
	diagPath := flag.String("diag", defaultDiag, "ecf-conformance corpus .diag to check")
	verify := flag.Bool("verify", false, "exit 1 if any signature vector does not match the §7.3 recompute")
	flag.Parse()

	src, err := os.ReadFile(*diagPath)
	if err != nil {
		die(err)
	}
	tree, err := diagcodec.ParseDiag(diagcodec.StripDiagComments(string(src)))
	if err != nil {
		die(err)
	}
	arr, ok := tree.([]interface{})
	if !ok {
		die(fmt.Errorf("corpus top level is not an array"))
	}

	var checked, bad int
	for _, v := range arr {
		vec, _ := v.(map[interface{}]interface{})
		id, _ := vec["id"].(string)
		if len(id) < 10 || id[:10] != "signature." {
			continue
		}
		checked++
		stored, _ := vec["canonical"].([]byte)
		want, msg, err := recompute(vec)
		if err != nil {
			fmt.Printf("  %-13s ERROR %v\n", id, err)
			bad++
			continue
		}
		match := hex.EncodeToString(stored) == hex.EncodeToString(want)
		// Second arm: the stored signature must itself verify over the
		// content_hash message under the seed's public key.
		seed := vec["input"].(map[interface{}]interface{})["seed"].([]byte)
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		valid := len(stored) == ed25519.SignatureSize && ed25519.Verify(pub, msg, stored)
		if !match || !valid {
			bad++
		}
		fmt.Printf("  %-13s match=%-5v verifies=%-5v\n", id, match, valid)
		if !match {
			fmt.Printf("                stored     = %s\n                recomputed = %s\n", hex.EncodeToString(stored), hex.EncodeToString(want))
		}
	}

	fmt.Printf("\n%d signature vectors checked, %d bad\n", checked, bad)
	if *verify && bad > 0 {
		fmt.Println("FAIL: signature category does not match the §7.3 recompute (message must be the full content_hash, not the ECF bytes)")
		os.Exit(1)
	}
	if checked == 0 {
		die(fmt.Errorf("no signature.* vectors found in %s", *diagPath))
	}
}

// recompute returns the §7.3 canonical (sign the full content_hash) and the
// message that was signed, from a vector's (seed, entity) input.
func recompute(vec map[interface{}]interface{}) (sig, msg []byte, err error) {
	in, ok := vec["input"].(map[interface{}]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("no input map")
	}
	seed, ok := in["seed"].([]byte)
	if !ok || len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("bad seed")
	}
	ent, ok := in["entity"].(map[interface{}]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("no entity map")
	}
	etype, _ := ent["type"].(string)
	dataRaw, err := ecf.Encode(ent["data"])
	if err != nil {
		return nil, nil, fmt.Errorf("encode data: %w", err)
	}
	h, err := hash.Compute(etype, cbor.RawMessage(dataRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("content hash: %w", err)
	}
	msg = h.Bytes() // §7.3: format code byte ‖ digest
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg), msg, nil
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "corpus-sig-verify:", err)
	os.Exit(2)
}
