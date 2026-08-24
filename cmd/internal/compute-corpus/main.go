// compute-corpus is the Go-side harness for the portable cross-impl compute
// conformance corpus (GUIDE-CONFORMANCE §7c).
//
// It mirrors the wire-conformance pipeline's shape — build a frozen artifact,
// have each impl emit against it, cross-bless the emissions — with the one
// stage compute needs and wire does not: an evaluator (§7c.2).
//
//	generate     seeded generator → frozen corpus artifact + MANIFEST
//	emit         evaluate the corpus through core-go → per-impl emission
//	verify       run the anti-vacuity guards over an emission
//	cross-bless  compare 2+ emissions; lock only when byte-identical
//
// Go is the fixture-BUILDER, not the oracle (§7c.5(b)). `generate` freezes
// inputs only; the expected answers are whatever the impls agree on, arbitrated
// by the spec. Nothing in this tool treats core-go's emission as correct.
//
// WHERE THE ARTIFACT ULTIMATELY LIVES. §7c.5 puts the frozen corpus and its
// MANIFEST in entity-core-protocol/specs/test-vectors/compute-conformance/,
// vendored into keystone. That repo is operator-coordinated and not writable
// from here, which is the expected split — "arch guides; the impl work lands in
// the cohort repos." The artifact is built and pinned here and routed there.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
)

// resolveGitCommit picks the revision to stamp on an emission (ADR-0012), in
// precedence order: an explicit --git-commit, then $GIT_COMMIT (how a
// containerized build injects it), then `git rev-parse HEAD` for a local run.
// Returns "" if none resolve — an unstamped emission is honest about being
// unpublishable rather than inventing a revision.
func resolveGitCommit(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("GIT_COMMIT"); env != "" {
		return env
	}
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "generate":
		err = runGenerate(args)
	case "emit":
		err = runEmit(args)
	case "verify":
		err = runVerify(args)
	case "cross-bless":
		err = runCrossBless(args)
	case "show":
		err = runShow(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `compute-corpus — the cross-impl compute conformance harness (GUIDE-CONFORMANCE §7c)

Usage:
  compute-corpus <subcommand> [flags]

Subcommands:
  generate     --out <path> [--seed N] [--cases N] [--worked-only]
               [--profile inproc|wire]
               Build the frozen corpus (inputs only — no expected answers) and
               write <out> plus <out>.MANIFEST. The "wire" profile inlines the
               root bindings so every expression is closed and the corpus can be
               driven against a live peer, whose eval scope is empty (§3.2).

  emit         --corpus <path> --out <path> [--impl-version V]
               [--engine NAME] [--engine-role reference|alternate]
               [--peer host:port] [--identity NAME] [--impl NAME]
               Evaluate every vector and write the emission. Without --peer this
               runs core-go in-process. With --peer it drives a LIVE peer over
               system/compute:eval, which needs a "wire"-profile corpus and lets
               any conformant peer produce an emission with no code on its side.

  verify       --corpus <path> --emission <path> [--require-alternate]
               Run the anti-vacuity guards. Non-zero exit if any guard fails.

  cross-bless  --corpus <path> --emission <path> [--emission <path> ...]
               Compare emissions. Non-zero exit unless every vector is
               byte-identical across all of them.

  show         --corpus <path> --id <vector-id> [--emission <path> ...]
               Render one vector's IR as a tree, plus each emission's outcome
               for it. This is how a cross-bless divergence gets triaged.

Examples:
  compute-corpus generate --out ./compute-corpus-v1.cbor
  compute-corpus emit     --corpus ./compute-corpus-v1.cbor --out ./emit-go.cbor
  compute-corpus verify   --corpus ./compute-corpus-v1.cbor --emission ./emit-go.cbor
  compute-corpus cross-bless --corpus ./compute-corpus-v1.cbor \
      --emission ./emit-go.cbor --emission ./emit-rust.cbor --emission ./emit-py.cbor
`)
}

// --- generate ---

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "", "output path for the frozen corpus")
	seed := fs.Uint64("seed", defaultSeed, "generator seed")
	cases := fs.Int("cases", defaultCases, "sweep case count")
	workedOnly := fs.Bool("worked-only", false, "emit only the worked-lowering vectors")
	profile := fs.String("profile", profileInproc,
		"inproc (§7c.3 shape, root bindings supplied) | wire (bindings inlined; drivable against a live peer)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("generate: --out is required")
	}
	if *profile != profileInproc && *profile != profileWire {
		return fmt.Errorf("generate: --profile must be %q or %q", profileInproc, profileWire)
	}

	// Worked lowerings first, then the sweep — §7c.5(a)'s order, preserved in
	// the artifact so a reader meets the named vectors before the random ones.
	vectors, err := buildWorked(*profile)
	if err != nil {
		return fmt.Errorf("build worked vectors: %w", err)
	}
	sweepCases := 0
	if !*workedOnly {
		sweep, err := buildSweep(*seed, *cases, *profile)
		if err != nil {
			return fmt.Errorf("build sweep: %w", err)
		}
		vectors = append(vectors, sweep...)
		sweepCases = *cases
	}

	if err := checkVectorIDsUnique(vectors); err != nil {
		return err
	}

	c := &Corpus{
		CorpusVersion:    corpusVersion,
		GeneratorVersion: generatorVersion,
		PRNG:             prngName,
		Seed:             *seed,
		SweepCases:       sweepCases,
		Profile:          *profile,
		SpecVersion:      specVersion,
		Vectors:          vectors,
	}

	raw, sum, err := encodeCorpus(c)
	if err != nil {
		return err
	}
	// Round-trip before publishing: §3.1(6) says decode the artifact, not just
	// its SHA. A corpus that cannot be re-read is worse than no corpus, and it
	// is cheap to find out here rather than in another impl.
	if _, err := decodeCorpus(raw); err != nil {
		return fmt.Errorf("corpus failed its own round-trip: %w", err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		return fmt.Errorf("write corpus: %w", err)
	}

	manifest := buildManifest(c, sum, raw)
	manifestPath := *out + ".MANIFEST"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	fmt.Printf("wrote %s (%d vectors, %d bytes)\n", *out, len(vectors), len(raw))
	fmt.Printf("wrote %s\n", manifestPath)
	fmt.Printf("sha256 %s\n", hex.EncodeToString(sum[:]))
	return nil
}

func checkVectorIDsUnique(vectors []Vector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}

// buildManifest writes the hash-pin (§7c.5(e)) plus the reproducibility triple
// (§7c.4(6)): seed, case count, generator version. Without all three a failure
// cannot be reproduced from (seed, case-index), which is the whole point of a
// generator-seeded corpus.
func buildManifest(c *Corpus, sum [32]byte, raw []byte) string {
	tags := map[string]int{}
	kinds := map[string]int{}
	for _, v := range c.Vectors {
		kind := "sweep"
		if strings.HasPrefix(v.ID, "worked/") {
			kind = "worked"
		}
		kinds[kind]++
		for _, t := range v.Requires {
			tags[t]++
		}
	}

	var sb strings.Builder
	sb.WriteString("# compute-conformance corpus MANIFEST\n")
	sb.WriteString("# GUIDE-CONFORMANCE §7c. Inputs only — expected answers are\n")
	sb.WriteString("# established by cross-bless, not by the fixture-builder.\n\n")
	fmt.Fprintf(&sb, "corpus_version:    %s\n", c.CorpusVersion)
	fmt.Fprintf(&sb, "generator_version: %s\n", c.GeneratorVersion)
	fmt.Fprintf(&sb, "prng:              %s\n", c.PRNG)
	fmt.Fprintf(&sb, "seed:              %d\n", c.Seed)
	fmt.Fprintf(&sb, "sweep_cases:       %d\n", c.SweepCases)
	fmt.Fprintf(&sb, "profile:           %s\n", c.Profile)
	fmt.Fprintf(&sb, "spec_version:      %s\n", c.SpecVersion)
	fmt.Fprintf(&sb, "vectors:           %d (worked %d, sweep %d)\n",
		len(c.Vectors), kinds["worked"], kinds["sweep"])
	fmt.Fprintf(&sb, "bytes:             %d\n", len(raw))
	fmt.Fprintf(&sb, "sha256:            %s\n", hex.EncodeToString(sum[:]))
	sb.WriteString("\n# feature coverage (vectors carrying each tag)\n")
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, "  %-28s %d\n", k, tags[k])
	}
	return sb.String()
}

// --- emit ---

func runEmit(args []string) error {
	fs := flag.NewFlagSet("emit", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "path to the frozen corpus")
	out := fs.String("out", "", "output path for the emission")
	implVersion := fs.String("impl-version", "unspecified", "impl version string")
	engine := fs.String("engine", "stage1", "evaluator name")
	// Default reference, and it must stay the default: core-go's Stage-1 IS the
	// reference evaluator, and a flag that let a run claim "alternate" by
	// omission would defeat guard 6 (§7c.4(2)) exactly when it matters.
	engineRole := fs.String("engine-role", RoleReference, "reference|alternate")
	peer := fs.String("peer", "",
		"drive a live peer at host:port over system/compute:eval instead of evaluating in-process (requires a --profile wire corpus)")
	identity := fs.String("identity", "", "identity name for the peer connection")
	implLabel := fs.String("impl", "", "impl name to record; defaults to core-go, or the peer address when --peer is used")
	gitCommit := fs.String("git-commit", "", "source revision to stamp (ADR-0012); defaults to $GIT_COMMIT, then `git rev-parse HEAD`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *out == "" {
		return fmt.Errorf("emit: --corpus and --out are required")
	}
	if *engineRole != RoleReference && *engineRole != RoleAlternate {
		return fmt.Errorf("emit: --engine-role must be %q or %q", RoleReference, RoleAlternate)
	}

	c, sum, err := loadCorpus(*corpusPath)
	if err != nil {
		return err
	}

	name := implName
	if *implLabel != "" {
		name = *implLabel
	}
	engineName := *engine

	var run func(Vector) (Outcome, error)
	if *peer == "" {
		run = evalVector
	} else {
		// A wire-driven emission over an inproc corpus would return not_found
		// for every free variable and look like a catastrophic divergence.
		// Refuse rather than produce that.
		if c.Profile != profileWire {
			return fmt.Errorf("emit --peer needs a %q-profile corpus, got %q — "+
				"EXTENSION-COMPUTE §3.2 evaluates from an empty scope, so a peer cannot receive root bindings; "+
				"regenerate with --profile wire", profileWire, c.Profile)
		}
		ctx := context.Background()
		d, err := newPeerDriver(ctx, *peer, *identity)
		if err != nil {
			return err
		}
		defer d.Close()
		if *implLabel == "" {
			name = "peer@" + *peer
		}
		// Recorded, not inferred: a reader must be able to tell a driven
		// emission from a self-reported one without knowing how it was produced.
		engineName = "wire:" + *peer
		run = func(v Vector) (Outcome, error) { return d.evalVectorOnPeer(ctx, v) }
	}

	em := &Emission{
		Impl:          name,
		ImplVersion:   *implVersion,
		GitCommit:     resolveGitCommit(*gitCommit),
		Engine:        engineName,
		EngineRole:    *engineRole,
		Fallbacks:     0,
		CorpusSHA256:  sum[:],
		CorpusVersion: c.CorpusVersion,
		SpecVersion:   specVersion,
		Results:       make(map[string]Outcome, len(c.Vectors)),
		Skipped:       map[string]string{},
	}

	for _, v := range c.Vectors {
		o, err := run(v)
		if err != nil {
			// A harness failure is recorded as a SKIP, never as an outcome.
			// Recording it as an outcome would let a broken run cross-bless
			// against a working one and look like a semantic divergence; a skip
			// counts as a failure (§3.1(2)) and the guards will say so.
			em.Skipped[v.ID] = err.Error()
			continue
		}
		em.Results[v.ID] = o
	}

	raw, err := ecf.Encode(em)
	if err != nil {
		return fmt.Errorf("encode emission: %w", err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		return fmt.Errorf("write emission: %w", err)
	}
	commit := em.GitCommit
	if commit == "" {
		commit = "UNSTAMPED (not publishable per ADR-0012)"
	}
	fmt.Printf("wrote %s — %d answered, %d skipped (%s/%s, role %s) @ %s\n",
		*out, len(em.Results), len(em.Skipped), em.Impl, em.Engine, em.EngineRole, commit)
	for _, id := range sortedKeys(em.Skipped) {
		fmt.Printf("  SKIP %s: %s\n", id, em.Skipped[id])
	}
	return nil
}

// --- verify ---

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "path to the frozen corpus")
	emissionPath := fs.String("emission", "", "path to an emission")
	requireAlternate := fs.Bool("require-alternate", false,
		"enforce guard 6 — the emitting engine must be the alternate one (AE-1 admission runs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *emissionPath == "" {
		return fmt.Errorf("verify: --corpus and --emission are required")
	}

	c, sum, err := loadCorpus(*corpusPath)
	if err != nil {
		return err
	}
	em, err := loadEmission(*emissionPath, sum)
	if err != nil {
		return err
	}

	rep := runGuards(c, em, *requireAlternate)
	fmt.Printf("guards for %s/%s over corpus %s:\n", em.Impl, em.Engine, hex.EncodeToString(sum[:8]))
	fmt.Print(rep.String())
	if rep.Failed() {
		return fmt.Errorf("anti-vacuity guards failed — the corpus or this run proves less than it appears to")
	}
	fmt.Println("all guards passed")
	return nil
}

// --- cross-bless ---

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func runCrossBless(args []string) error {
	fs := flag.NewFlagSet("cross-bless", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "path to the frozen corpus")
	var emissions multiFlag
	fs.Var(&emissions, "emission", "path to an emission (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || len(emissions) < 2 {
		return fmt.Errorf("cross-bless: --corpus and at least two --emission are required")
	}

	c, sum, err := loadCorpus(*corpusPath)
	if err != nil {
		return err
	}
	ems := make([]*Emission, 0, len(emissions))
	for _, p := range emissions {
		em, err := loadEmission(p, sum)
		if err != nil {
			return err
		}
		ems = append(ems, em)
	}

	verdicts, err := crossBless(c, ems, sum[:])
	if err != nil {
		return err
	}
	// Provenance first (ADR-0012): a lock is a claim about specific revisions, so
	// print which impl/engine @ commit each emission came from before the verdict.
	// An UNSTAMPED emission makes the lock un-citable — surfaced, not hidden.
	fmt.Printf("emissions over corpus %s:\n", hex.EncodeToString(sum[:8]))
	for _, em := range ems {
		commit := em.GitCommit
		if commit == "" {
			commit = "UNSTAMPED (not publishable per ADR-0012)"
		}
		fmt.Printf("  %s/%s (role %s) @ %s\n", em.Impl, em.Engine, em.EngineRole, commit)
	}
	report, locked := summarize(verdicts)
	fmt.Print(report)
	if !locked {
		return fmt.Errorf("corpus does not lock")
	}
	return nil
}

// --- shared loading ---

func loadCorpus(path string) (*Corpus, [32]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("read corpus: %w", err)
	}
	c, err := decodeCorpus(raw)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	_, sum, err := encodeCorpus(c)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return c, sum, nil
}

func loadEmission(path string, corpusSum [32]byte) (*Emission, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read emission: %w", err)
	}
	var em Emission
	if err := ecf.Decode(raw, &em); err != nil {
		return nil, fmt.Errorf("decode emission %s: %w", filepath.Base(path), err)
	}
	if len(em.Results) == 0 && len(em.Skipped) == 0 {
		return nil, fmt.Errorf("emission %s carries no results", filepath.Base(path))
	}
	return &em, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
