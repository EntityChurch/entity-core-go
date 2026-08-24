// Command encryption-vectors emits and verifies the ENC-RESOLVE-ORDER
// differential vector file for EXTENSION-ENCRYPTION §4.4's recipient-key
// resolution order.
//
// The rows, the verifier, and the reason the vector exists at all live in
// cmd/internal/encvectors — this is the CLI shell around them.
//
// Our half lives in testdata/ beside this command — a build input, not
// documentation. The sibling's half is THEIR artifact in THEIR tree; name the
// file, never guess their path.
//
//	go run ./cmd/encryption-vectors -emit   cmd/encryption-vectors/testdata/encryption-resolve-order-go.cbor
//	go run ./cmd/encryption-vectors -verify <entity-core-rust>/encryption-resolve-order-rust.cbor
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/encvectors"
)

func main() {
	emit := flag.String("emit", "", "write this implementation's vector file to PATH")
	verify := flag.String("verify", "", "verify a vector file at PATH")
	flag.Parse()

	switch {
	case *emit != "" && *verify != "":
		fail("pick one of -emit / -verify")
	case *emit != "":
		if err := encvectors.Emit(*emit, headCommit(*emit), os.Stdout); err != nil {
			fail("emit: %v", err)
		}
	case *verify != "":
		ok, err := encvectors.Verify(*verify, os.Stdout)
		if err != nil {
			fail("verify: %v", err)
		}
		if !ok {
			os.Exit(1)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "encryption-vectors: "+format+"\n", args...)
	os.Exit(1)
}

// headCommit records provenance, with the same "-dirty" discipline as
// cmd/webrtc-vectors: a file naming a commit whose code is not what produced it
// is unreproducible while looking reproducible. Untracked files are not counted
// (a new vector file is untracked until added, and a marker that always fires
// is one nobody reads).
//
// outPath — the artifact about to be written — is excluded for exactly that
// second reason, one step later in the file's life. cmd/webrtc-vectors excludes
// untracked files so a NEW vector does not mark itself dirty; once that vector
// is committed the same problem returns, because re-emitting necessarily starts
// from a tree where the previous emission is a modified tracked file. Every
// re-emission would then be "-dirty" forever, and a marker that always fires is
// one nobody reads. The marker is a claim about the EMITTER's code, not about
// the artifact it is replacing.
//
// Caught by hitting it: the /2 re-emission pinned `f2f3941-dirty` when the only
// modified file was the vector being overwritten.
func headCommit(outPath string) string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	commit := strings.TrimSpace(string(out))
	if treeIsDirty(outPath) {
		commit += "-dirty"
	}
	return commit
}

func treeIsDirty(outPath string) bool {
	out, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Porcelain v1: "XY path". Compare on the path only.
		fields := strings.Fields(line)
		if len(fields) >= 2 && sameFile(fields[len(fields)-1], outPath) {
			continue
		}
		return true
	}
	return false
}

// sameFile compares two repo paths that may be spelled differently (./x vs x).
func sameFile(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}
