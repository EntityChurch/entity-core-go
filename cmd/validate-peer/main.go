// Command validate-peer is the V7 conformance validator.
//
// It runs the validation suite (cmd/internal/validate) against a live peer —
// single-peer or multi-peer convergence — and reports per-category
// PASS/WARN/FAIL/SKIP. The authoritative category set is the const cat* values
// and the RunCategory switch in cmd/internal/validate/suite.go; run one with
// -category <name>. See CLAUDE.md for the full flag and category reference.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

func main() {
	addr := flag.String("addr", "", "remote peer address (host:port)")
	peers := flag.String("peers", "", "peer addresses for convergence testing (comma-separated, e.g., host1:port,host2:port)")
	httpPeers := flag.String("http-peers", "", "HTTP listener URLs of -peers, paired by index (comma-separated, e.g., http://h1:9003/entity,http://h2:9004/entity). Enables the cross-peer-subscription-over-HTTP gate (PROPOSAL-TRANSPORT-FAMILY §7.3 R1).")
	wsPeers := flag.String("ws-peers", "", "WebSocket-live URLs of -peers, paired by index (comma-separated, e.g., ws://h1:9004/ws,ws://h2:9004/ws). Thread F WebSocket-substrate gate (NETWORK §6.5.2b): when set, the three relay categories publish WS profiles for B↔C↔registry so RELAY §3.1.1 terminal-hop delivery rides binary WS messages. Preempts -http-peers per-index.")
	identity := flag.String("identity", "", "use named identity from ~/.entity/identities/ (e.g., framework-admin)")
	jsonOutput := flag.Bool("json", false, "output JSON instead of human-readable text")
	jsonOut := flag.String("json-out", "", "write JSON report to this file AND print the text summary to stdout (replaces the save-then-reparse pattern)")
	category := flag.String("category", "", "run only a specific category (see -list-categories for the full set)")
	listCategories := flag.Bool("list-categories", false, "print every validation category, one per line, and exit")
	reference := flag.String("reference-peer", "", "known-good reference peer (host:port) for origination (A-role) tests; single-peer mode cannot catch outbound-dispatch bugs without it")
	pollURL := flag.String("poll-url", "", "HTTP poll URL prefix (e.g. http://127.0.0.1:9201) — enables the serving_mode category; peer must be started with --http-poll-addr and --serve-namespace system/content/public")
	verbose := flag.Bool("verbose", false, "show wire request/response traces on stderr")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	failuresOnly := flag.Bool("failures-only", false, "show only failed/skipped/warned checks (suppresses passing checks)")
	exclude := flag.String("exclude", "", "comma-separated categories to exclude from output (e.g., local_files,origination)")
	allowSkip := flag.String("allow-skip", "", "comma-separated check names that are allowed to skip without failing the PASS/FAIL gate. Use when a skip is intentional (test requires a setup the current run isn't exercising). Default: every skip is treated as a FAIL.")
	corpus := flag.String("corpus", "", "ECF conformance corpus path (.cbor produced by wire-conformance build-fixture). Required when -category=conformance.")
	hashFormat := flag.String("hash-format", "", "preferred content_hash_format for the hello advertisement (sha256 or sha384). When unset, advertises only sha256 (matches v7.66 default). Set to sha384 when probing a peer started with --hash-type sha384 so negotiation lands on sha384 and locally-authored test entities (delivery tokens, comparison blobs, hash-gate constants) match the peer's substrate format.")
	profile := flag.String("profile", "full", "V7 v7.72 §9.0 conformance profile: `core` (14 core-profile categories, 53-type floor, six CORE-TREE-* vectors, extension-targeted check carve-outs) or `full` (every category — historical behavior). The keystone unblock gate: a core peer should report a clean PASS under --profile core.")
	declaredMaxPayload := flag.Int("declared-max-payload", 0, "peer-declared max payload size in bytes for the resource_bounds category (V7 §4.10(a), v7.75 RESERVED). 0 = use recommended default (16 MiB). Set this when the peer advertises a tighter or wider envelope cap so the probe sends a frame just over the declared value.")
	declaredMaxChainDepth := flag.Int("declared-max-chain-depth", 0, "peer-declared max capability-chain depth for the resource_bounds category (V7 §4.10(b), v7.75 RESERVED). 0 = use recommended default (64).")
	flag.Parse()

	if *listCategories {
		for _, c := range validate.AllCategories() {
			fmt.Println(c)
		}
		return
	}

	switch *profile {
	case "core", "full":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown -profile %q (want core or full)\n", *profile)
		os.Exit(2)
	}

	switch *hashFormat {
	case "", "sha256":
		// keep default
	case "sha384":
		entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown -hash-format %q (want sha256 or sha384)\n", *hashFormat)
		os.Exit(2)
	}

	// Split -allow-skip once so we can hand it to every report we build.
	var allowSkipNames []string
	if *allowSkip != "" {
		for _, n := range strings.Split(*allowSkip, ",") {
			if n = strings.TrimSpace(n); n != "" {
				allowSkipNames = append(allowSkipNames, n)
			}
		}
	}

	if *addr == "" && *peers == "" {
		fmt.Fprintf(os.Stderr, "Usage: validate-peer -addr host:port [-identity name] [-json] [-category name] [-verbose] [-timeout duration]\n")
		fmt.Fprintf(os.Stderr, "       validate-peer -peers host1:port,host2:port [-identity name] [-json] [-verbose] [-timeout duration]\n")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var report *validate.Report
	var err error

	// Pass-through conformance category: drives the corpus into a single
	// live peer via PUT/GET and asserts content-hash agreement. Uses
	// -addr and -corpus; doesn't need -peers.
	if *category == "conformance_passthrough" {
		if *addr == "" {
			fmt.Fprintf(os.Stderr, "Error: -category=conformance_passthrough requires -addr <peer:port>\n")
			os.Exit(2)
		}
		var client *validate.PeerClient
		var clientErr error
		if *identity != "" {
			client, clientErr = validate.NewPeerClientWithIdentity(*addr, *identity)
		} else {
			client, clientErr = validate.NewPeerClient(*addr)
		}
		if clientErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", clientErr)
			os.Exit(1)
		}
		client.SetVerbose(*verbose)
		defer client.Close()
		if connectChecks, ok := validate.RunConnectivity(ctx, client); !ok {
			report = validate.NewReport(*addr)
			report.AddAll(connectChecks)
		} else {
			report, err = validate.RunConformancePassthrough(ctx, client, *corpus)
			if err == nil && report != nil {
				report.AddAll(connectChecks)
			}
		}
	} else if *category == "conformance" {
		if *peers == "" {
			fmt.Fprintf(os.Stderr, "Error: -category=conformance requires -peers <label>:<path>,...\n")
			os.Exit(2)
		}
		emissions, parseErr := parseConformancePeers(*peers)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", parseErr)
			os.Exit(2)
		}
		report, err = validate.RunConformance(ctx, *corpus, emissions)
	} else if *peers != "" {
		// Multi-peer convergence mode.
		peerAddrs := strings.Split(*peers, ",")
		for i := range peerAddrs {
			peerAddrs[i] = strings.TrimSpace(peerAddrs[i])
		}
		var httpURLs []string
		if *httpPeers != "" {
			httpURLs = strings.Split(*httpPeers, ",")
			for i := range httpURLs {
				httpURLs[i] = strings.TrimSpace(httpURLs[i])
			}
			if len(httpURLs) != len(peerAddrs) {
				fmt.Fprintf(os.Stderr, "Error: -http-peers (%d URLs) must have same length as -peers (%d addrs)\n", len(httpURLs), len(peerAddrs))
				os.Exit(2)
			}
		}
		var wsURLs []string
		if *wsPeers != "" {
			wsURLs = strings.Split(*wsPeers, ",")
			for i := range wsURLs {
				wsURLs[i] = strings.TrimSpace(wsURLs[i])
			}
			if len(wsURLs) != len(peerAddrs) {
				fmt.Fprintf(os.Stderr, "Error: -ws-peers (%d URLs) must have same length as -peers (%d addrs)\n", len(wsURLs), len(peerAddrs))
				os.Exit(2)
			}
		}
		suite := validate.NewValidationSuite(peerAddrs[0])
		if *identity != "" {
			suite.SetIdentity(*identity)
		}
		if *verbose {
			suite.SetVerbose(true)
		}
		if httpURLs != nil {
			suite.SetHTTPPeers(httpURLs)
		}
		if wsURLs != nil {
			suite.SetWSPeers(wsURLs)
		}
		suite.SetProfile(*profile)
		suite.SetDeclaredMaxPayload(*declaredMaxPayload)
		suite.SetDeclaredMaxChainDepth(*declaredMaxChainDepth)
		report, err = suite.RunConvergence(ctx, peerAddrs)
	} else {
		// Single-peer validation mode.
		suite := validate.NewValidationSuite(*addr)
		if *identity != "" {
			suite.SetIdentity(*identity)
		}
		if *verbose {
			suite.SetVerbose(true)
		}
		if *reference != "" {
			suite.SetReferencePeer(*reference)
		}
		if *pollURL != "" {
			suite.SetPollURL(*pollURL)
		}
		suite.SetProfile(*profile)
		suite.SetDeclaredMaxPayload(*declaredMaxPayload)
		suite.SetDeclaredMaxChainDepth(*declaredMaxChainDepth)
		if *category != "" {
			report, err = suite.RunCategory(ctx, *category)
		} else {
			report, err = suite.Run(ctx)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply output filters.
	if *exclude != "" {
		excludeCats := make(map[string]bool)
		for _, cat := range strings.Split(*exclude, ",") {
			excludeCats[strings.TrimSpace(cat)] = true
		}
		report.ExcludeCategories(excludeCats)
	}

	report.Finalize()

	// Apply the -allow-skip allowlist BEFORE the result gate runs. Every
	// skipped check whose name isn't on this list counts as a FAIL.
	report.SetAllowedSkips(allowSkipNames)

	// Surface the budget warning to stderr so it's visible regardless of
	// -json (where stdout is consumed by tooling) and -failures-only (where
	// the text body suppresses passes).
	if report.BudgetWarning != "" {
		fmt.Fprintf(os.Stderr, "BUDGET: %s\n", report.BudgetWarning)
	}

	switch {
	case *jsonOut != "":
		// Save JSON to file, print text summary to stdout. One Go code path
		// owns the schema — no inline-python reparse in the shell scripts.
		f, err := os.Create(*jsonOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", *jsonOut, err)
			os.Exit(1)
		}
		if err := report.WriteJSON(f); err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "Error writing JSON to %s: %v\n", *jsonOut, err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing %s: %v\n", *jsonOut, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Saved JSON report: %s\n", *jsonOut)
		report.WriteText(os.Stdout, *failuresOnly)
	case *jsonOutput:
		if err := report.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	default:
		report.WriteText(os.Stdout, *failuresOnly)
	}

	if report.HasFailures() {
		os.Exit(1)
	}
}

// parseConformancePeers parses the conformance category's -peers form:
// `<label>:<path>,<label>:<path>,...`. Labels are short impl names
// (e.g., "go", "rust", "py"), paths point to the emission .cbor files
// each impl's wire-conformance harness produced.
func parseConformancePeers(spec string) ([]validate.ConformancePeerEmission, error) {
	var out []validate.ConformancePeerEmission
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx < 0 {
			return nil, fmt.Errorf("-peers entry %q: expected <label>:<path>", part)
		}
		label := strings.TrimSpace(part[:idx])
		path := strings.TrimSpace(part[idx+1:])
		if label == "" || path == "" {
			return nil, fmt.Errorf("-peers entry %q: empty label or path", part)
		}
		out = append(out, validate.ConformancePeerEmission{Label: label, Path: path})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-peers: no entries parsed from %q", spec)
	}
	return out, nil
}
