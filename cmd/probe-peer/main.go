// Command probe-peer is a tree explorer.
//
// It connects to a peer, walks system/tree, and prints the entities at the
// given paths. Usage: probe-peer -addr host:port [-identity name] [paths...].
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	addr := flag.String("addr", "", "remote peer address (host:port)")
	identity := flag.String("identity", "", "identity name from ~/.entity/identities/ (default: ephemeral)")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintf(os.Stderr, "Usage: probe-peer -addr host:port [-identity name] [paths...]\n")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var client *validate.PeerClient
	var err error

	if *identity != "" {
		client, err = validate.NewPeerClientWithIdentity(*addr, *identity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create client with identity %q: %v\n", *identity, err)
			os.Exit(1)
		}
		fmt.Printf("Using identity: %s\n", *identity)
	} else {
		client, err = validate.NewPeerClient(*addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create client: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Using ephemeral identity")
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}

	checks := client.PerformHandshake(ctx)
	for _, c := range checks {
		if c.Severity == validate.Fail {
			fmt.Fprintf(os.Stderr, "connect %s: %s\n", c.Name, c.Message)
		}
	}
	if !client.Connected() {
		fmt.Fprintf(os.Stderr, "connect failed\n")
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", *addr)
	fmt.Printf("Remote PeerID: %s\n\n", client.RemotePeerID())

	// Print connection grants.
	printGrants(client.Grants())

	// Default: probe tree listings and handler listings.
	if len(flag.Args()) == 0 {
		probeTreeListings(ctx, client)
		probeHandlerOps(ctx, client)
	} else {
		// Probe specific paths from command line.
		for _, p := range flag.Args() {
			fmt.Printf("=== Listing: %s ===\n", p)
			entries, _, err := client.TreeListing(ctx, p)
			if err != nil {
				fmt.Printf("  ERROR: %v\n\n", err)
				continue
			}
			printEntries(entries)
		}
	}
}

func probeTreeListings(ctx context.Context, client *validate.PeerClient) {
	paths := []string{
		"system/",
		"system/handler/",
		"system/handler/local/",
	}
	for _, p := range paths {
		fmt.Printf("=== Tree Listing: %s ===\n", p)
		entries, _, err := client.TreeListing(ctx, p)
		if err != nil {
			fmt.Printf("  ERROR: %v\n\n", err)
			continue
		}
		printEntries(entries)
	}
}

func probeHandlerOps(ctx context.Context, client *validate.PeerClient) {
	peerID := client.RemotePeerID()

	// Probe local/files — Rust peer uses path-in-URI.
	fmt.Println("=== local/files: list / ===")
	printExecResult(execOp(ctx, client, fmt.Sprintf("entity://%s/local/files/", peerID), "list", nil))

	fmt.Println("=== local/files: list /home/[internal]/ ===")
	printExecResult(execOp(ctx, client, fmt.Sprintf("entity://%s/local/files/home/[internal]", peerID), "list", nil))

	fmt.Println("=== local/files: list /home/[internal]/projects/entity-systems/ ===")
	printExecResult(execOp(ctx, client, fmt.Sprintf("entity://%s/local/files/home/[internal]/projects/entity-systems", peerID), "list", nil))

	// Probe local/processes.
	fmt.Println("=== local/processes: list ===")
	printExecResult(execOp(ctx, client, fmt.Sprintf("entity://%s/local/processes", peerID), "list", nil))
}

// execOp sends an EXECUTE to a handler URI with the given operation and params.
// Returns the response envelope on success.
func execOp(ctx context.Context, client *validate.PeerClient, uri, operation string, params map[string]interface{}) (*execResult, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	paramsRaw, err := ecf.Encode(params)
	if err != nil {
		return nil, fmt.Errorf("encode params: %w", err)
	}
	paramsEntity, err := entity.NewEntity("system/request", cbor.RawMessage(paramsRaw))
	if err != nil {
		return nil, fmt.Errorf("create params entity: %w", err)
	}

	env, _, err := client.SendExecute(ctx, uri, operation, paramsEntity, nil)
	if err != nil {
		return nil, fmt.Errorf("execute: %w", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Decode result entity.
	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		return &execResult{
			Status:   respData.Status,
			RawBytes: respData.Result,
			Included: env.Included,
		}, nil
	}

	// Decode entity data as generic CBOR (preserves CBOR types).
	var decoded interface{}
	if err := ecf.Decode(resultEntity.Data, &decoded); err != nil {
		return &execResult{
			Status:     respData.Status,
			ResultType: resultEntity.Type,
			ResultHash: resultEntity.ContentHash,
			RawBytes:   []byte(resultEntity.Data),
			Included:   env.Included,
		}, nil
	}

	return &execResult{
		Status:     respData.Status,
		ResultType: resultEntity.Type,
		ResultHash: resultEntity.ContentHash,
		Data:       decoded,
		Included:   env.Included,
	}, nil
}

type execResult struct {
	Status     uint
	ResultType string
	ResultHash hash.Hash
	Data       interface{} // decoded CBOR value
	RawBytes   []byte      // fallback when Data decode fails
	Included   map[hash.Hash]entity.Entity
}

func printExecResult(r *execResult, err error) {
	if err != nil {
		fmt.Printf("  ERROR: %v\n\n", err)
		return
	}
	fmt.Printf("  Status: %d\n", r.Status)
	if r.ResultType != "" {
		fmt.Printf("  Type:   %s\n", r.ResultType)
		fmt.Printf("  Hash:   %s\n", r.ResultHash)
	}
	if r.Data != nil {
		fmt.Printf("  Data:\n")
		var b strings.Builder
		entity.FormatCBORValue(&b, "    ", truncateDeep(r.Data, 20))
		fmt.Print(b.String())
	} else if len(r.RawBytes) > 0 {
		fmt.Printf("  Raw:    %s\n", hex.EncodeToString(r.RawBytes))
	}
	if len(r.Included) > 0 {
		fmt.Printf("  Included: %d entities\n", len(r.Included))
		for h, ent := range r.Included {
			fmt.Printf("    %s  type=%s\n", h, ent.Type)
		}
	}
	fmt.Println()
}

// truncateDeep walks a decoded CBOR value and truncates arrays longer than max.
func truncateDeep(v interface{}, max int) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[interface{}]interface{}, len(val))
		for k, v := range val {
			out[k] = truncateDeep(v, max)
		}
		return out
	case []interface{}:
		if len(val) <= max {
			return val
		}
		truncated := make([]interface{}, max+1)
		copy(truncated, val[:max])
		truncated[max] = fmt.Sprintf("...and %d more", len(val)-max)
		return truncated
	default:
		return val
	}
}

func printGrants(grants []types.GrantEntry) {
	fmt.Println("=== Connection Grants ===")
	if len(grants) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	for i, g := range grants {
		fmt.Printf("  grant[%d]:\n", i)
		fmt.Printf("    handlers:   include=%v", g.Handlers.Include)
		if len(g.Handlers.Exclude) > 0 {
			fmt.Printf(" exclude=%v", g.Handlers.Exclude)
		}
		fmt.Println()
		fmt.Printf("    resources:  include=%v", g.Resources.Include)
		if len(g.Resources.Exclude) > 0 {
			fmt.Printf(" exclude=%v", g.Resources.Exclude)
		}
		fmt.Println()
		fmt.Printf("    operations: include=%v", g.Operations.Include)
		if len(g.Operations.Exclude) > 0 {
			fmt.Printf(" exclude=%v", g.Operations.Exclude)
		}
		fmt.Println()
		if g.Peers != nil {
			fmt.Printf("    peers:      include=%v", g.Peers.Include)
			if len(g.Peers.Exclude) > 0 {
				fmt.Printf(" exclude=%v", g.Peers.Exclude)
			}
			fmt.Println()
		}
	}
	fmt.Println()
}

func printEntries(entries map[string]interface{}) {
	if len(entries) == 0 {
		fmt.Printf("  (empty)\n\n")
		return
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %s\n", k)
	}
	fmt.Println()
}
