package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.entitychurch.org/entity-core-go/cmd/internal/identity"
)

// cmdIdentity dispatches `peer-manager identity <subcmd>` per
// docs/architecture/proposals/active/DESIGN-IDENTITY-CONFIG-AND-PEER-MANAGEMENT.md
// §3.2 (Option C: thin shell over the cmd/internal/identity helper).
func cmdIdentity(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: peer-manager identity <init|show> ...\n")
		os.Exit(2)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "init":
		identityInit(rest)
	case "show":
		identityShow(rest)
	default:
		fmt.Fprintf(os.Stderr, "Unknown identity subcommand: %s\n", sub)
		os.Exit(2)
	}
}

func identityInit(args []string) {
	// Extract NAME (the first non-flag positional) so flag parsing handles
	// flags placed before or after it.
	name, flagArgs := extractFirstPositional(args)
	if name == "" {
		fmt.Fprintf(os.Stderr, "Usage: peer-manager identity init NAME [--simple] [--quorum K-of-N]\n")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("identity init", flag.ExitOnError)
	simple := fs.Bool("simple", false, "Use the simple 1-of-1 quorum + Op==Public_alice collapse (§11.3)")
	quorumSpec := fs.String("quorum", "", "Quorum spec like 2-of-3 (overrides --simple)")
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	opts := identity.BootstrapOptions{Name: name, Simple: *simple}
	if *quorumSpec != "" {
		k, n, err := parseKofN(*quorumSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --quorum: %v\n", err)
			os.Exit(2)
		}
		opts.Simple = false
		opts.QuorumMembers = n
		opts.QuorumThreshold = k
	}

	dir, b, err := identity.BootstrapNewIdentity(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Created identity bundle %q at %s\n", name, dir)
	fmt.Fprintf(os.Stderr, "  Mode:              %s\n", b.Mode)
	fmt.Fprintf(os.Stderr, "  Quorum:            %d of %d\n", b.QuorumThreshold, len(b.QuorumPeerIDs))
	fmt.Fprintf(os.Stderr, "  Public_identity:   %s\n", b.PublicIdentityID)
	fmt.Fprintf(os.Stderr, "  Op(s):             %s\n", strings.Join(b.OpPeerIDs, ", "))
}

func identityShow(args []string) {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: peer-manager identity show NAME\n")
		os.Exit(2)
	}
	b, dir, err := identity.LoadBundle(args[0], "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	fmt.Fprintf(os.Stderr, "Bundle dir: %s\n", dir)
	if err := enc.Encode(b); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}

// extractFirstPositional pulls the first non-flag arg out of args, returning
// it and the remaining args (which the caller passes to flag.Parse). Lets
// `cmd NAME --flag` and `cmd --flag NAME` both work.
func extractFirstPositional(args []string) (string, []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			rest := append([]string{}, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return a, rest
		}
	}
	return "", args
}

// parseKofN parses "K-of-N" e.g., "2-of-3".
func parseKofN(spec string) (k, n int, err error) {
	parts := strings.SplitN(spec, "-of-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected K-of-N (e.g., 2-of-3), got %q", spec)
	}
	k, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid K %q: %v", parts[0], err)
	}
	n, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid N %q: %v", parts[1], err)
	}
	if k < 1 || n < 1 || k > n {
		return 0, 0, fmt.Errorf("require 1 <= K <= N (got K=%d, N=%d)", k, n)
	}
	return k, n, nil
}
