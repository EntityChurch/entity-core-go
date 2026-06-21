// Command entity-sync sets up cross-peer synchronization.
//
// It wires continuation chains and subscriptions so a source peer's subtree
// mirrors onto a destination peer. Supports one-way and bidirectional sync with
// a TTL; `entity-sync list host:port` shows active sync chains.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	fromAddr := flag.String("from", "", "source peer address (host:port)")
	toAddr := flag.String("to", "", "destination peer address (host:port)")
	srcPrefix := flag.String("source-prefix", "", "tree prefix to watch on source peer")
	dstPrefix := flag.String("dest-prefix", "", "tree prefix for merged entities on destination (defaults to source-prefix)")
	strategy := flag.String("strategy", "source-wins", "merge strategy (source-wins, target-wins, no-overwrite)")
	identity := flag.String("identity", "", "named identity for authentication")
	bidirectional := flag.Bool("bidirectional", false, "set up sync in both directions")
	ttl := flag.Duration("ttl", 24*time.Hour, "delivery token TTL (default: 24h)")
	flag.Parse()

	// Check for list subcommand.
	if len(os.Args) > 1 && os.Args[1] == "list" {
		listAddr := ""
		listIdentity := ""
		if len(os.Args) > 2 {
			listAddr = os.Args[2]
		}
		if *identity != "" {
			listIdentity = *identity
		}
		// Re-parse: entity-sync list <addr> [-identity name]
		for i, arg := range os.Args {
			if arg == "-identity" && i+1 < len(os.Args) {
				listIdentity = os.Args[i+1]
			}
		}
		if listAddr == "" {
			fmt.Fprintf(os.Stderr, "Usage: entity-sync list <host:port> [-identity name]\n")
			os.Exit(2)
		}
		listSync(listAddr, listIdentity)
		return
	}

	if *fromAddr == "" || *toAddr == "" || *srcPrefix == "" {
		fmt.Fprintf(os.Stderr, "Usage: entity-sync -from host:port -to host:port -source-prefix path/ [...]\n")
		fmt.Fprintf(os.Stderr, "       entity-sync list <host:port> [-identity name]\n")
		os.Exit(2)
	}

	// Operator-install model (EXTENSION-CONTINUATION v1.11 §4.2 case 3)
	// requires the same operator identity to be connected to both peers
	// — that identity is the in-chain leaf granter on the cross-peer
	// dispatch_capability. With an ephemeral random keypair per peer
	// (no -identity), the identities diverge and §3.1a rejects at
	// install (writer ≠ in-chain granter). Fail closed with a clear
	// message rather than letting users hit a cryptic 403.
	if *identity == "" {
		fmt.Fprintln(os.Stderr, "Error: -identity NAME is required.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Cross-peer sync uses an operator-install dispatch_capability model")
		fmt.Fprintln(os.Stderr, "(EXTENSION-CONTINUATION v1.11 §4.2 case 3): the same identity must")
		fmt.Fprintln(os.Stderr, "be connected to both peers as the in-chain leaf granter on the")
		fmt.Fprintln(os.Stderr, "dispatch_capability. Provide an identity managed under ~/.entity/")
		fmt.Fprintln(os.Stderr, "identities/ with -identity NAME.")
		os.Exit(2)
	}

	if *dstPrefix == "" {
		*dstPrefix = *srcPrefix
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to both peers.
	src, err := connectPeer(ctx, *fromAddr, *identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to source peer: %v\n", err)
		os.Exit(1)
	}
	defer src.Close()

	dst, err := connectPeer(ctx, *toAddr, *identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to destination peer: %v\n", err)
		os.Exit(1)
	}
	defer dst.Close()

	srcID := string(src.RemotePeerID())
	dstID := string(dst.RemotePeerID())

	fmt.Printf("Source: %s (%s)\n", *fromAddr, srcID)
	fmt.Printf("Dest:   %s (%s)\n", *toAddr, dstID)
	fmt.Printf("Prefix: %s → %s (strategy: %s)\n", *srcPrefix, *dstPrefix, *strategy)
	fmt.Println()

	// Register transport addresses.
	if err := registerTransport(ctx, src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "Error registering transport: %v\n", err)
		os.Exit(1)
	}
	if err := registerTransport(ctx, dst, src); err != nil {
		fmt.Fprintf(os.Stderr, "Error registering transport: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Transport addresses registered.")

	// Set up source → dest sync.
	if err := setupSync(ctx, src, dst, *srcPrefix, *dstPrefix, *strategy, *ttl); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up sync: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sync: %s → %s (%s → %s)\n", srcID[:12], dstID[:12], *srcPrefix, *dstPrefix)

	// Set up reverse direction if bidirectional.
	if *bidirectional {
		if err := setupSync(ctx, dst, src, *dstPrefix, *srcPrefix, *strategy, *ttl); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up reverse sync: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Sync: %s → %s (%s → %s)\n", dstID[:12], srcID[:12], *dstPrefix, *srcPrefix)
	}

	fmt.Println()
	fmt.Printf("Sync wired (token TTL: %s, expires: %s).\n", *ttl, time.Now().Add(*ttl).Format(time.RFC3339))
	fmt.Println("Changes to the source prefix will propagate automatically until the token expires.")
	fmt.Println("Re-run this command to renew.")
}

func listSync(addr, identity string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := connectPeer(ctx, addr, identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("Sync chains on %s (%s):\n\n", addr, client.RemotePeerID())

	// Find sync chains by looking for extract/merge continuation pairs.
	// Walk system/inbox/sync/ recursively looking for "extract" entities.
	entries, _, err := client.TreeListing(ctx, "system/inbox/sync/")
	if err != nil || len(entries) == 0 {
		fmt.Println("  No sync chains found.")
		return
	}

	// Recursively find extract continuations to identify chain prefixes.
	findChains(ctx, client, "system/inbox/sync/", entries)
}

func findChains(ctx context.Context, client *validate.PeerClient, basePath string, entries map[string]interface{}) {
	// Check if this level has extract/merge (leaf of a chain).
	if _, hasExtract := entries["extract"]; hasExtract {
		// This is a chain — the prefix is basePath minus "system/inbox/sync/"
		chainPrefix := strings.TrimPrefix(basePath, "system/inbox/sync/")
		fmt.Printf("  %s\n", chainPrefix)

		extractPath := basePath + "extract"
		mergePath := basePath + "merge"

		extractEnt, _, err := client.TreeGet(ctx, extractPath)
		if err == nil && extractEnt.Type == types.TypeContinuation {
			contData, _ := types.ContinuationDataFromEntity(extractEnt)
			fmt.Printf("    extract → %s (%s)\n", contData.Target, contData.Operation)
			if contData.Resource != nil && len(contData.Resource.Targets) > 0 {
				fmt.Printf("             prefix: %s\n", contData.Resource.Targets[0])
			}
			if contData.DeliverTo != nil {
				fmt.Printf("             delivers to: %s\n", contData.DeliverTo.URI)
			}
		}

		mergeEnt, _, err := client.TreeGet(ctx, mergePath)
		if err == nil && mergeEnt.Type == types.TypeContinuation {
			contData, _ := types.ContinuationDataFromEntity(mergeEnt)
			fmt.Printf("    merge   → %s (%s)\n", contData.Target, contData.Operation)
			if contData.Resource != nil && len(contData.Resource.Targets) > 0 {
				fmt.Printf("             prefix: %s\n", contData.Resource.Targets[0])
			}
		}
		fmt.Println()
		return
	}

	// Recurse into subdirectories.
	for name := range entries {
		subPath := basePath + name + "/"
		subEntries, _, err := client.TreeListing(ctx, subPath)
		if err == nil && len(subEntries) > 0 {
			findChains(ctx, client, subPath, subEntries)
		}
	}
}

func connectPeer(ctx context.Context, addr, identity string) (*validate.PeerClient, error) {
	var client *validate.PeerClient
	var err error
	if identity != "" {
		client, err = validate.NewPeerClientWithIdentity(addr, identity)
	} else {
		client, err = validate.NewPeerClient(addr)
	}
	if err != nil {
		return nil, err
	}
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	client.PerformHandshake(ctx)
	if !client.Connected() {
		return nil, fmt.Errorf("handshake failed")
	}
	return client, nil
}

func registerTransport(ctx context.Context, onPeer, aboutPeer *validate.PeerClient) error {
	pid := string(aboutPeer.RemotePeerID())
	// V7.64 path-encoding alignment: §6.5 TCPProfileData lives at
	// system/peer/transport/{peer_id_hex}/primary. Profile-id "primary"
	// matches the cohort default (E1 ambiguity flagged for arch).
	aboutHash, err := types.ComputePeerIdentityHashFromPeerID(aboutPeer.RemotePeerID())
	if err != nil {
		return fmt.Errorf("derive identity hash for %s: %w", pid, err)
	}
	data, _ := ecf.Encode(types.TCPProfileData{
		PeerID:        pid,
		TransportType: "tcp",
		Endpoint:      types.TransportEndpointURL{URL: "tcp://" + aboutPeer.Addr()},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
	})
	ent, _ := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(data))
	_, err = onPeer.TreePut(ctx, "system/peer/transport/"+types.PeerIdentityHashHex(aboutHash)+"/primary", ent)
	return err
}

func setupSync(ctx context.Context, src, dst *validate.PeerClient, srcPrefix, dstPrefix, strategy string, ttl time.Duration) error {
	srcID := string(src.RemotePeerID())
	dstID := string(dst.RemotePeerID())

	// Use the prefix directly in the inbox path structure.
	inboxExtract := "system/inbox/sync/" + srcPrefix + "extract"
	inboxMerge := "system/inbox/sync/" + srcPrefix + "merge"

	// Dispatch_capability per EXTENSION-CONTINUATION v1.11 §4.2 case 3
	// via validate.InstallCrossPeerContinuation:
	//   cont1 (cross-peer extract on src): chain rooted at src (via
	//     `src` client's connect-grant), leaf granter = operator (a's
	//     and b's shared client identity), grantee = dst peer (the
	//     dispatching host).
	//   cont2 (local merge on dst): chain rooted at dst, leaf granter =
	//     operator (= dst.client identity), grantee = dst peer.
	// Operator-install model: works when `src` and `dst` share an operator
	// identity, which is
	// what `-identity NAME` produces; without it each connectPeer mints a
	// random keypair and the §3.1a in-chain-granter check fails.
	cont1 := types.ContinuationData{
		Target:    "entity://" + srcID + "/system/tree",
		Operation: "extract",
		Resource:  &types.ResourceTarget{Targets: []string{srcPrefix}},
		DeliverTo: &types.DeliverySpec{
			URI:       "entity://" + dstID + "/" + inboxMerge,
			Operation: "receive",
		},
	}
	if err := validate.InstallCrossPeerContinuation(ctx, dst, src, inboxExtract, cont1); err != nil {
		return fmt.Errorf("install continuation 1: %w", err)
	}

	// Continuation 2 on dest: merge locally.
	mergeParams, _ := ecf.Encode(map[string]interface{}{
		"source_envelope": nil,
		"strategy":        strategy,
		"source_prefix":   srcPrefix,
		"target_prefix":   dstPrefix,
	})
	// No ResultTransform: tree:extract delivers its envelope-result
	// directly via DeliverTo; the upstream payload IS the envelope
	// entity (not an EXECUTE_RESPONSE shape with a "result" subfield),
	// so the legacy `Extract: "result"` step would dereference into
	// nothing and leave source_envelope nil → 400. Mirrors the working
	// convergence/psync recipe (cmd/internal/validate/convergence.go).
	cont2 := types.ContinuationData{
		Target:      "system/tree",
		Operation:   "merge",
		Resource:    &types.ResourceTarget{Targets: []string{dstPrefix}},
		Params:      cbor.RawMessage(mergeParams),
		ResultField: "source_envelope",
	}
	if err := validate.InstallCrossPeerContinuation(ctx, dst, dst, inboxMerge, cont2); err != nil {
		return fmt.Errorf("install continuation 2: %w", err)
	}

	// Subscribe on source.
	deliverURI := "entity://" + dstID + "/" + inboxExtract
	tokenEntity, tokenSigEntity, err := src.CreateDeliveryTokenWithTTL(deliverURI, "receive", ttl)
	if err != nil {
		return fmt.Errorf("create delivery token: %w", err)
	}

	subID, _, _, err := src.Subscribe(ctx, srcPrefix+"*", deliverURI, "receive",
		tokenEntity, tokenSigEntity, []string{"created", "updated"}, nil)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	fmt.Printf("  Chain: sync/%s (sub=%s)\n", srcPrefix, subID)
	fmt.Printf("  Extract: %s\n", inboxExtract)
	fmt.Printf("  Merge:   %s\n", inboxMerge)

	return nil
}
