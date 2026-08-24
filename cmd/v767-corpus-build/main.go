// Command v767-corpus-build produces the v7.67 corpus `.cbor` build artifact
// from its `.diag` source, using the Go ECF encoder.
//
// WHY GO OWNS THIS. `SEEDS.md` §5 step 2 assigns it: *"produce
// conformance-vectors-v1.cbor from the .diag using the Go ECF encoder."* The
// `.diag` header says the same from the other side — *"the sibling
// conformance-vectors-v1.cbor is the canonical-ECF-encoded build artifact
// produced from this file by any conformant ECF encoder; the encoder MUST
// produce byte-identical output."* Architecture rules the vector VALUES; the
// artifact is a build output, and this is the build.
//
// WHY IT EXISTS NOW (2026-08-12 f). Architecture landed the M3/M6 re-stamp at
// entity-core-protocol `8545661` — the step-4 fold that three prior rulings had
// described and none had performed. That commit edits the `.diag` files. The
// `.cbor` artifacts were NOT rebuilt, because **no regeneration tool existed in
// any repo**: the original artifacts were produced once, by hand, and the
// procedure was never mechanized. So the corpus shipped for one commit in a
// state where source and artifact disagree by construction, and arch marked it
// loudly in both files rather than leaving it silent.
//
// THE SELF-CHECK IS THE POINT, NOT A COURTESY. `-verify-legacy` re-encodes the
// PRE-re-stamp `.diag` (entity-core-protocol `56d4de4`, or any older copy) and
// asserts the result is byte-identical to the artifact that shipped with it —
// sha256 `8e7c5232…e31f982e`. Without that, this tool would be an unverified
// encoder producing an oracle: whatever bytes it emitted would become "the
// corpus," and any divergence from the hand-built original would be
// indistinguishable from the re-stamp. Reproducing the old pair first is what
// makes the new pair evidence instead of assertion.
//
// TWO COPIES, ONE INVARIANT. `crypto-agility/agility-vectors-v1.{diag,cbor}` is
// the de-versioned public release form of the same corpus. Architecture ruled
// (`3042bd8`) that the two `.cbor` files stay byte-identical — *"if the two
// shas ever differ after this, that is the defect, and it is worth a check."*
// `-both` builds both and enforces exactly that, so the invariant is checked by
// the tool that could otherwise break it.
//
// Usage:
//
//	go run ./cmd/v767-corpus-build -verify-legacy <old.diag> <expected-sha>
//	go run ./cmd/v767-corpus-build -both -n          # dry run: show shas, write nothing
//	go run ./cmd/v767-corpus-build -both             # write both artifacts
//
// This tool WRITES INTO entity-core-protocol, which this repo does not
// otherwise touch, and it writes the artifact ONLY — never a spec file, never a
// `.diag`, and it runs no git. Committing is architecture's. The boundary in
// AGENTS.md is about authoring spec content; a build output whose ownership the
// spec itself assigns to Go is not that. `-n` exists so the shas can be handed
// over without writing anything at all.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/diagcodec"
)

// The two copies of the corpus, source → artifact. Relative to this repo, which
// sits beside entity-core-protocol.
type corpusCopy struct {
	name string
	diag string
	cbor string
}

var copies = []corpusCopy{
	{
		name: "v767 (versioned)",
		diag: "../entity-core-protocol/specs/test-vectors/v767/conformance-vectors-v1.diag",
		cbor: "../entity-core-protocol/specs/test-vectors/v767/conformance-vectors-v1.cbor",
	},
	{
		name: "crypto-agility (public release form)",
		diag: "../entity-core-protocol/specs/test-vectors/crypto-agility/agility-vectors-v1.diag",
		cbor: "../entity-core-protocol/specs/test-vectors/crypto-agility/agility-vectors-v1.cbor",
	},
}

var (
	flagCheck        = flag.Bool("check", false, "re-encode both sources and assert the COMMITTED .cbor match; writes nothing (the source-produces-artifact gate)")
	flagBoth         = flag.Bool("both", false, "build both copies and enforce .cbor byte-identity between them (arch 3042bd8)")
	flagDry          = flag.Bool("n", false, "dry run — report the shas that WOULD be written, write nothing")
	flagDiag         = flag.String("diag", "", "build a single .diag (with -out)")
	flagOut          = flag.String("out", "", "output path for -diag")
	flagVerifyLegacy = flag.String("verify-legacy", "", "re-encode this .diag and assert its sha256 equals -expect; writes nothing")
	flagExpect       = flag.String("expect", "", "expected sha256 for -verify-legacy")
)

func main() {
	flag.Parse()

	switch {
	case *flagVerifyLegacy != "":
		if *flagExpect == "" {
			die("-verify-legacy requires -expect")
		}
		verifyLegacy(*flagVerifyLegacy, *flagExpect)
	case *flagCheck:
		checkBoth()
	case *flagBoth:
		buildBoth()
	case *flagDiag != "":
		if *flagOut == "" {
			die("-diag requires -out")
		}
		b := encodeFile(*flagDiag)
		report(*flagDiag, b)
		write(*flagOut, b)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// verifyLegacy is the encoder's own conformance check: encode a .diag whose
// artifact is already pinned and assert we reproduce it byte-for-byte.
func verifyLegacy(path, expect string) {
	b := encodeFile(path)
	got := shaHex(b)
	fmt.Printf("re-encoded: %s\n", path)
	fmt.Printf("size:       %d B\n", len(b))
	fmt.Printf("sha256:     %s\n", got)
	fmt.Printf("expected:   %s\n", expect)
	if got != expect {
		die("ENCODER MISMATCH — this encoder does not reproduce the pinned artifact, so nothing it produces can be trusted as the corpus")
	}
	fmt.Println("            ✓ byte-identical — the encoder reproduces the pinned artifact")
}

// checkBoth re-encodes both sources and asserts the COMMITTED .cbor files are
// exactly what those sources produce. It writes nothing and is safe to run in
// any gate, against a tree it does not own.
//
// THIS IS THE CHECK WHOSE ABSENCE CAUSED A-3, and it is worth naming precisely
// because the existing verifier does NOT cover it. `v767-corpus-verify` asserts
// the artifact against a pinned sha — it proves the artifact is the one we
// expect, and says nothing about whether the SOURCE still produces it. That is
// exactly the gap the corpus fell through: the F16 correction was applied to
// the .cbor and never to the .diag, both files stayed internally plausible, the
// corpus verified 52/0 against itself for two months, and the drift was
// invisible to every check that reads the artifact.
//
// Source-produces-artifact is a different assertion from artifact-is-expected,
// and only the second one existed.
func checkBoth() {
	type built struct {
		copy  corpusCopy
		bytes []byte
	}
	var out []built
	for _, c := range copies {
		out = append(out, built{c, encodeFile(c.diag)})
	}

	if len(out) == 2 && shaHex(out[0].bytes) != shaHex(out[1].bytes) {
		die("the two SOURCES encode to different bytes (%s vs %s) — arch 3042bd8 makes .cbor byte-identity the standing invariant, so the .diag files have diverged in encoded content (id/description are encoded; comments are not)",
			shaHex(out[0].bytes), shaHex(out[1].bytes))
	}

	drift := false
	for _, b := range out {
		onDisk, err := os.ReadFile(b.copy.cbor)
		if err != nil {
			die("read %s: %v", b.copy.cbor, err)
		}
		got, want := shaHex(onDisk), shaHex(b.bytes)
		if got == want {
			fmt.Printf("  ✓ %-42s %d B  sha256 %s\n", b.copy.name, len(onDisk), got)
			continue
		}
		drift = true
		fmt.Printf("  ✗ %-42s DRIFT\n", b.copy.name)
		fmt.Printf("      committed .cbor : %d B  sha256 %s\n", len(onDisk), got)
		fmt.Printf("      .diag encodes to: %d B  sha256 %s\n", len(b.bytes), want)
		fmt.Printf("      source: %s\n", b.copy.diag)
	}
	if drift {
		die("the committed artifact is NOT what the committed source produces.\n" +
			"Do not 'fix' this by rebuilding until you know WHICH SIDE is right — that is the\n" +
			"decision the June regen skipped. The .cbor was correct and the .diag stale once\n" +
			"already (the F16 widths), so rebuilding blindly would have destroyed the good copy.\n" +
			"Diff the two, decide, then run -both.")
	}
	fmt.Println("\n✓ both artifacts are exactly what their sources produce, and are byte-identical to each other")
}

func buildBoth() {
	type built struct {
		copy  corpusCopy
		bytes []byte
	}
	var out []built
	for _, c := range copies {
		b := encodeFile(c.diag)
		report(c.name, b)
		out = append(out, built{c, b})
	}

	// Arch 3042bd8: byte-identity between the two .cbor copies is the standing
	// invariant, and the divergence would be CREATED by re-stamping one copy.
	// Enforced BEFORE writing, so a mismatch cannot half-land.
	if len(out) == 2 && shaHex(out[0].bytes) != shaHex(out[1].bytes) {
		die("the two copies encoded to DIFFERENT bytes (%s vs %s) — arch 3042bd8 makes .cbor byte-identity the standing invariant; the .diag files have diverged in substance, not just de-versioning cosmetics",
			shaHex(out[0].bytes), shaHex(out[1].bytes))
	}
	fmt.Println("✓ both copies encode to identical bytes (arch 3042bd8 invariant holds)")

	if *flagDry {
		fmt.Println("\n-n given: nothing written.")
		return
	}
	for _, b := range out {
		write(b.copy.cbor, b.bytes)
	}
	fmt.Println("\nWritten. Committing is architecture's — this tool runs no git.")
}

func encodeFile(path string) []byte {
	src, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	val, err := diagcodec.ParseDiag(string(src))
	if err != nil {
		die("parse %s: %v", path, err)
	}
	arr, ok := val.([]interface{})
	if !ok {
		die("%s: top-level value is %T, want an array of vectors", path, val)
	}
	preflightF16(path, arr)
	b, err := diagcodec.EncodeCanonical(arr)
	if err != nil {
		die("encode %s: %v", path, err)
	}
	return b
}

// preflightF16 refuses to build a corpus whose SOURCE carries input widths the
// F16 correction already superseded.
//
// THIS GUARD IS WHY THE TOOL DID NOT SHIP A REGRESSION ON ITS FIRST RUN.
// The F16 re-stamp (2026-06-10) fixed three input-side defects: 58-byte Ed448
// secret seeds (RFC 8032 SeedSize is 57), a 63-byte `experimental-test` public
// key (v7.66 §4.2 pins 64), and Phase-2 `expected_*` fields carrying the text
// placeholder "TBD-COHORT-ROUND-TRIP" instead of bytes. It was applied to the
// `.cbor` — where `v767-corpus-verify` confirms 57 / 64 to this day — and
// **never folded back into the `.diag`**, which still carries 58 and 63.
//
// So the two files have been out of sync since June, in OPPOSITE directions,
// and each is authoritative for a different half:
//
//	.diag  correct M3/M6 expectations (arch 8545661) · SUPERSEDED input widths
//	.cbor  correct F16 input widths                  · stale M3/M6 expectations
//
// A plain rebuild is therefore not "one command": it would fold in the six
// re-stamped values and silently regress the three F16 fixes with them. The
// `.diag` header even claims the artifact was "Regenerated … from this .diag
// via tools/regen-v767-cbor.py" — which cannot be true of this file's bytes,
// and is the clue that the June regen ran on a corrected input nobody saved.
//
// The invariants below are exactly the three `v767-corpus-verify` §1 asserts
// against the artifact. Checking them on the SOURCE before encoding is what
// makes the two tools a closed loop instead of two opinions.
func preflightF16(path string, arr []interface{}) {
	var problems []string
	note := func(format string, a ...any) {
		problems = append(problems, fmt.Sprintf(format, a...))
	}

	for _, v := range arr {
		m, ok := v.(map[interface{}]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)

		// (A) RFC 8032 Ed448 SeedSize — and ONLY for ed448. The seed width is
		// key-type-dependent (Ed25519 is 32), so this reads the `key_type`
		// sitting beside each `secret_seed` rather than asserting one width on
		// every seed in the file. The first cut of this check did the latter and
		// flagged four correct Ed25519 seeds; a preflight that cries wolf gets
		// switched off, which would have cost more than it saved.
		// A vector under the `key-type-ed448.*` family is ed448 by its id; the
		// matrix vectors instead carry an explicit sibling `key_type`. Both
		// routes are needed: key-type-ed448.4.signature has a `secret_seed` and
		// NO `key_type` beside it, so a purely sibling-driven check walks past
		// the 58-byte seed sitting in it.
		idIsEd448 := strings.HasPrefix(id, "key-type-ed448.")
		walkMaps(m, func(mm map[interface{}]interface{}) {
			seed, hasSeed := mm["secret_seed"].([]byte)
			kt, _ := mm["key_type"].(string)
			if hasSeed && (kt == "ed448" || (kt == "" && idIsEd448)) && len(seed) != 57 {
				note("%s: ed448 secret_seed is %d bytes, want 57 (RFC 8032 SeedSize; F16)", id, len(seed))
			}
			// (B) v7.66 §4.2 experimental-test public key width.
			if pub, ok := mm["public_key"].([]byte); ok && len(pub) == 63 {
				note("%s: public_key is 63 bytes, want 64 (v7.66 §4.2 experimental-test; F16)", id)
			}
		})
		// key-type-ed448.1.pubkey carries the seed bare at `input`, with the
		// key type in the vector id rather than a sibling field.
		if id == "key-type-ed448.1.pubkey" {
			if in, ok := m["input"].([]byte); ok && len(in) != 57 {
				note("%s: input (ed448 seed) is %d bytes, want 57 (RFC 8032 SeedSize; F16)", id, len(in))
			}
		}

		// (C) Phase-2 expectations must be bytes, not the F16 placeholder.
		for k, val := range m {
			ks, ok := k.(string)
			if !ok || len(ks) < 9 || ks[:9] != "expected_" {
				continue
			}
			if s, isText := val.(string); isText && s == "TBD-COHORT-ROUND-TRIP" {
				note("%s: %s is still the F16 placeholder %q", id, ks, s)
			}
		}
	}

	if len(problems) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nv767-corpus-build: REFUSING TO BUILD %s\n\n", path)
	fmt.Fprintf(os.Stderr, "  The .diag carries input widths the F16 correction superseded. The shipped\n")
	fmt.Fprintf(os.Stderr, "  .cbor already has them right, so encoding this source would REGRESS the\n")
	fmt.Fprintf(os.Stderr, "  artifact while folding in the M3/M6 re-stamp — a net loss disguised as a\n")
	fmt.Fprintf(os.Stderr, "  build. Correct the .diag first; that is a vector edit, and architecture's.\n\n")
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "    - %s\n", p)
	}
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

// walkMaps visits every map in the tree, including the root, so a check can
// read sibling fields (a seed and the key_type that fixes its width) together.
func walkMaps(v interface{}, fn func(map[interface{}]interface{})) {
	switch t := v.(type) {
	case map[interface{}]interface{}:
		fn(t)
		for _, val := range t {
			walkMaps(val, fn)
		}
	case []interface{}:
		for _, e := range t {
			walkMaps(e, fn)
		}
	}
}

func report(label string, b []byte) {
	fmt.Printf("%-40s %6d B  sha256 %s\n", label, len(b), shaHex(b))
}

func write(path string, b []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		die("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		die("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s\n", path)
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "v767-corpus-build: "+format+"\n", args...)
	os.Exit(1)
}
