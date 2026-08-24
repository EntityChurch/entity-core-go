// Command corpus-check holds every registered conformance corpus to the same
// contract: the committed artifact is the one we expect, the committed source
// still produces it, and where a corpus has several copies they agree byte for
// byte.
//
// One command over all corpora, rather than a process per corpus. The registry
// is `cmd/internal/corpus`; adding a corpus is an entry there.
//
// It writes nothing. Building an artifact has an owner and is a deliberate act
// (SEEDS.md §4) — a gate that could rewrite what it checks would turn a drift
// into a pass.
//
// Usage:
//
//	go run ./cmd/corpus-check              # every registered corpus
//	go run ./cmd/corpus-check -corpus ecf-conformance
//	go run ./cmd/corpus-check -list
//
// Exit 0 only if every corpus passes. Wired into scripts/validate-complete.sh as
// part of PASS 0, before any peer starts: a corpus defect invalidates every
// cross-impl claim made against it, and finding that out after four peer passes
// is four passes too late.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"go.entitychurch.org/entity-core-go/cmd/internal/corpus"
)

var (
	flagCorpus = flag.String("corpus", "", "check only this corpus (default: all registered)")
	flagList   = flag.Bool("list", false, "list the registered corpora and exit")
)

func main() {
	flag.Parse()

	if *flagList {
		for _, c := range corpus.All() {
			fmt.Printf("%-18s %s\n", c.Name, c.Subject)
			for _, cp := range c.Copies {
				fmt.Printf("  %-16s %s\n", cp.Label, cp.Cbor)
			}
			fmt.Printf("  %-16s %s\n\n", "pinned sha256", c.ExpectedSHA)
		}
		return
	}

	set := corpus.All()
	if *flagCorpus != "" {
		c, ok := corpus.ByName(*flagCorpus)
		if !ok {
			fmt.Fprintf(os.Stderr, "corpus-check: no registered corpus %q; -list shows the set\n", *flagCorpus)
			os.Exit(2)
		}
		set = []corpus.Corpus{c}
	}

	failed, absent, drift := 0, 0, false
	for _, c := range set {
		fmt.Printf("%s — %s\n", c.Name, c.Subject)
		res, err := c.Check()
		if errors.Is(err, corpus.ErrAbsent) {
			// A loud skip. The spec repo is arch's and a standalone clone will
			// not have it; that is an absent input, not a passing check and not
			// a corpus defect.
			fmt.Printf("  SKIPPED — %v\n", err)
			fmt.Printf("            Clone ../entity-core-protocol to check this corpus.\n\n")
			absent++
			continue
		}
		if err != nil {
			fmt.Printf("  ERROR   %v\n\n", err)
			failed++
			continue
		}

		for _, cp := range c.Copies {
			mark := "✓"
			if res.OnDisk[cp.Label] != res.Encoded[cp.Label] {
				mark = "✗"
			}
			fmt.Printf("  %s %-38s %6d B  sha256 %s\n", mark, cp.Label, res.Sizes[cp.Label], res.OnDisk[cp.Label])
		}
		fmt.Printf("    %d vectors · artifact-is-expected: pinned · source-produces-artifact: re-encoded", res.Vectors)
		if len(c.Copies) > 1 {
			fmt.Printf(" · %d copies agree", len(c.Copies))
		}
		fmt.Println()

		if !res.OK() {
			failed++
			for _, f := range res.Failures {
				fmt.Printf("  FAIL  %s\n", f)
				drift = true
			}
		}
		fmt.Println()
	}

	if drift {
		fmt.Println(corpus.DriftAdvice)
		fmt.Println()
	}
	switch {
	case failed > 0:
		fmt.Printf("corpus-check: %d of %d corpora FAILED\n", failed, len(set))
		os.Exit(1)
	case absent == len(set):
		fmt.Println("corpus-check: every corpus skipped — the spec repo is not checked out.")
		fmt.Println("Reported rather than passed: nothing was verified.")
		os.Exit(0)
	default:
		fmt.Printf("corpus-check: %d corpora pass the contract", len(set)-absent)
		if absent > 0 {
			fmt.Printf(" (%d skipped, absent)", absent)
		}
		fmt.Println()
	}
}
