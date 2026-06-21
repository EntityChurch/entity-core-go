// wire-conformance is the Go-side harness binary for ECF conformance.
//
// Subcommands:
//
//	build-fixture     translate .diag → canonical-ECF .cbor (the corpus
//	                  every impl loads in emit-canonical)
//	emit-canonical    encode each vector through Go's canonical encoder
//	                  and write the per-impl emission CBOR file
//	legacy-envelope   the pre-Appendix-E W2 regression fixture writer
//
// See:
//   - ENTITY-CBOR-ENCODING.md Appendix E (normative)
//   - core-protocol-domain/guides/GUIDE-CONFORMANCE.md
//   - core-protocol-domain/specs/test-vectors/ecf-conformance/conformance-vectors-v1.diag
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "build-fixture":
		err = runBuildFixture(args)
	case "emit-canonical":
		err = runEmitCanonical(args)
	case "legacy-envelope":
		err = runLegacyEnvelope(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", sub)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `wire-conformance — ECF conformance harness

Usage:
  wire-conformance <subcommand> [flags]

Subcommands:
  build-fixture     --diag <path> --out <path>
                    Translate CBOR diagnostic notation to canonical-ECF .cbor.
                    The output is the corpus every impl loads in emit-canonical.

  emit-canonical    --input <path> --out <path> [--impl-version <ver>]
                    Encode each vector through Go's canonical encoder and write
                    the per-impl emission file. Shape per GUIDE-CONFORMANCE
                    §3.1: {impl, impl_version, corpus_version, spec_version,
                    encode_results, decode_results, errors}.

  legacy-envelope   [output-path]
                    Pre-Appendix-E W2 regression fixture (deprecated; kept
                    so the older interop scripts still work).

Examples:
  wire-conformance build-fixture \
    --diag ../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/test-vectors/ecf-conformance/conformance-vectors-v1.diag \
    --out  ./test-vectors/v1/conformance-vectors-v1.cbor

  wire-conformance emit-canonical \
    --input ./test-vectors/v1/conformance-vectors-v1.cbor \
    --out   ./test-vectors/v1/emit-go.cbor
`)
}

func parseFlags(name string, args []string, def map[string]*string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	for k, v := range def {
		fs.StringVar(v, k, *v, k)
	}
	return fs.Parse(args)
}
