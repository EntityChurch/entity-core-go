// Command probe-signaling is a manual smoke tool for the signaling CLIENT
// (ext/signaling) against a LIVE rendezvous pool — the Rust entity-signaling-node
// today. It is the by-hand live checkpoint behind the signaling validate
// category: two Go peer identities derive a shared key, select the same node
// from the pool by §3.1.1, and meet through it (offer a connect-request, the
// other collects+classifies+finds it, answers with a connect-response echoing
// the nonce, the first collects and finds the answer). One PASS line per mode.
//
// It is a diagnostic, not a conformance gate — the durable gate is
// `validate-peer -category signaling`. This tool needs a running pool and is not
// run in CI.
//
//	go run ./cmd/probe-signaling -pool 127.0.0.1:4050,127.0.0.1:4051
//	go run ./cmd/probe-signaling -pool 127.0.0.1:4050,127.0.0.1:4051 -mode tag -verbose
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/signaling"
)

type node struct {
	dialAddr string
	endpoint string
	peerID   string
}

func main() {
	pool := flag.String("pool", "", "comma-separated node dial addresses (host:port,host:port) — MUST be ≥2 with different advertised endpoints for a real §3.1.1 gate")
	modeFlag := flag.String("mode", "all", "tag|secret|pair|lobby|all")
	verbose := flag.Bool("verbose", false, "print each offer/collect step")
	flag.Parse()

	if *pool == "" {
		fmt.Fprintln(os.Stderr, "usage: probe-signaling -pool host:port,host:port [-mode all] [-verbose]")
		os.Exit(2)
	}
	dialAddrs := strings.Split(*pool, ",")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Two stable identities (A initiates, B responds). Stable keypairs so pair
	// mode's key — and pool re-selection across modes — are consistent.
	kpA, err := crypto.Generate()
	fatalIf(err, "generate keypair A")
	kpB, err := crypto.Generate()
	fatalIf(err, "generate keypair B")
	idA := kpA.PeerID().String()
	idB := kpB.PeerID().String()
	fmt.Printf("A = %s\nB = %s\n\n", idA, idB)

	// Discover the pool: connect to each node, advertise, record its endpoint.
	poolMembers, byEndpoint := discoverPool(ctx, dialAddrs, *verbose)
	if len(poolMembers) == 0 {
		fmt.Fprintln(os.Stderr, "no reachable pool members")
		os.Exit(1)
	}
	fmt.Printf("pool (%d members):\n", len(poolMembers))
	for _, m := range poolMembers {
		fmt.Printf("  %-16s → %s (%s)\n", m.Endpoint, byEndpoint[m.Endpoint].dialAddr, short(byEndpoint[m.Endpoint].peerID))
	}
	if len(poolMembers) < 2 {
		fmt.Println("  NOTE: a 1-member pool cannot validate §3.1.1 — argmax over one member is trivial (§4.2).")
	}
	fmt.Println()

	modes := selectModes(*modeFlag)
	allOK := true
	for _, mode := range modes {
		key, label, err := deriveForMode(mode, idA, idB)
		if err != nil {
			fmt.Printf("[%-6s] FAIL derive: %v\n", mode, err)
			allOK = false
			continue
		}
		sel, ok := signaling.Select(key, poolMembers)
		if !ok {
			fmt.Printf("[%-6s] FAIL select: empty pool\n", mode)
			allOK = false
			continue
		}
		target := byEndpoint[sel.Endpoint]
		if err := meet(ctx, target, kpA, kpB, idA, idB, key, *verbose); err != nil {
			fmt.Printf("[%-6s] FAIL @ %s (%s): %v\n", mode, sel.Endpoint, label, err)
			allOK = false
			continue
		}
		fmt.Printf("[%-6s] PASS — A and B met at %s (key %s, %s)\n", mode, sel.Endpoint, short(hex.EncodeToString(key)), label)
	}

	fmt.Println()
	if !allOK {
		fmt.Println("RESULT: FAIL")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS — the Go signaling client meets itself through the live pool.")
}

// discoverPool connects to each dial address, handshakes, and calls advertise to
// learn the advertised endpoint string that §3.1.1 weights over.
func discoverPool(ctx context.Context, dialAddrs []string, verbose bool) ([]signaling.PoolMember, map[string]node) {
	var members []signaling.PoolMember
	byEndpoint := map[string]node{}
	for _, addr := range dialAddrs {
		addr = strings.TrimSpace(addr)
		c, err := connect(ctx, addr, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "discover %s: %v\n", addr, err)
			continue
		}
		cl := signaling.NewClient(c)
		status, adv, err := cl.Advertise(ctx)
		peerID := string(c.RemotePeerID())
		c.Close()
		if err != nil || status != 200 {
			fmt.Fprintf(os.Stderr, "advertise %s: status %d err %v\n", addr, status, err)
			continue
		}
		if verbose {
			fmt.Printf("  advertise %s → endpoint=%q limits=%+v\n", addr, adv.Endpoint, adv.Limits)
		}
		members = append(members, signaling.PoolMember{Endpoint: adv.Endpoint, Priority: 0})
		byEndpoint[adv.Endpoint] = node{dialAddr: addr, endpoint: adv.Endpoint, peerID: peerID}
	}
	return members, byEndpoint
}

// meet runs the full §4 step-2 rendezvous between A and B at one node.
func meet(ctx context.Context, target node, kpA, kpB crypto.Keypair, idA, idB string, key []byte, verbose bool) error {
	ca, err := connect(ctx, target.dialAddr, &kpA)
	if err != nil {
		return fmt.Errorf("A connect: %w", err)
	}
	defer ca.Close()
	cb, err := connect(ctx, target.dialAddr, &kpB)
	if err != nil {
		return fmt.Errorf("B connect: %w", err)
	}
	defer cb.Close()

	clientA := signaling.NewClient(ca)
	clientB := signaling.NewClient(cb)

	cands := []types.NetworkCandidateData{
		{Type: types.CandidateTypeHost, Substrate: types.CandidateSubstrateTCP, Address: "10.0.0.1:9000"},
	}
	nonce := mustNonce()

	// A → connect-request.
	reqEnt, err := types.ConnectRequestData{Candidates: cands, Initiator: idA, Nonce: nonce}.ToEntity()
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if status, err := clientA.OfferMessage(ctx, key, reqEnt); err != nil || status != 200 {
		return fmt.Errorf("A offer request: status %d err %v", status, err)
	}
	if verbose {
		fmt.Printf("    A offered connect-request (nonce %s)\n", short(hex.EncodeToString(nonce)))
	}

	// B collects and answers EVERY non-own request (not just the first): on a
	// re-run within the 60s TTL a shared-bucket mode still holds stale requests,
	// and answering only the oldest would leave A's current request unanswered
	// while every step reports success (py's §4.5 stale-request finding). A
	// isolates its own answer by nonce echo below.
	_, bMsgs, err := clientB.CollectMessages(ctx, key)
	if err != nil {
		return fmt.Errorf("B collect: %w", err)
	}
	answered := 0
	for _, m := range bMsgs {
		if m.Kind != signaling.KindConnectRequest || m.Request.Initiator == idB {
			continue
		}
		respEnt, err := types.ConnectResponseData{Candidates: cands, Nonce: m.Request.Nonce, Responder: idB}.ToEntity()
		if err != nil {
			return fmt.Errorf("build response: %w", err)
		}
		if status, err := clientB.OfferMessage(ctx, key, respEnt); err != nil || status != 200 {
			return fmt.Errorf("B offer response: status %d err %v", status, err)
		}
		answered++
	}
	if answered == 0 {
		return fmt.Errorf("B collected %d message(s) but found no request to answer", len(bMsgs))
	}
	if verbose {
		fmt.Printf("    B answered %d request(s), including A's (echoed nonce)\n", answered)
	}

	// A collects, finds B's response by nonce echo (skipping its own request).
	_, aMsgs, err := clientA.CollectMessages(ctx, key)
	if err != nil {
		return fmt.Errorf("A collect: %w", err)
	}
	// collect is non-destructive, so A re-reads its own request — its presence
	// is what makes the nonce-echo isolation below meaningful.
	ownPresent := false
	for _, m := range aMsgs {
		if m.Kind == signaling.KindConnectRequest && m.Request.Initiator == idA && string(m.Request.Nonce) == string(nonce) {
			ownPresent = true
			break
		}
	}
	if !ownPresent {
		return fmt.Errorf("A's own request absent from its own collect — should be non-destructive")
	}
	resp, found := signaling.FindResponse(aMsgs, nonce, idA)
	if !found {
		return fmt.Errorf("A collected %d message(s) but found no nonce-matched response from B", len(aMsgs))
	}
	if resp.Responder != idB {
		return fmt.Errorf("responder %q, want B %q", resp.Responder, idB)
	}
	if verbose {
		fmt.Printf("    A found B's response — met.\n")
	}
	return nil
}

func connect(ctx context.Context, addr string, kp *crypto.Keypair) (*validate.PeerClient, error) {
	var c *validate.PeerClient
	var err error
	if kp != nil {
		c, err = validate.NewPeerClientWithKeypair(addr, *kp)
	} else {
		c, err = validate.NewPeerClient(addr)
	}
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		c.Close()
		return nil, err
	}
	c.PerformHandshake(ctx)
	if !c.Connected() {
		c.Close()
		return nil, fmt.Errorf("handshake did not complete")
	}
	return c, nil
}

func deriveForMode(mode, idA, idB string) (key []byte, label string, err error) {
	switch mode {
	case "tag":
		k, e := signaling.TagKey("probe-tag")
		return k, `tag="probe-tag"`, e
	case "secret":
		k, e := signaling.SecretKey("probe-secret-8f3a1c")
		return k, `secret`, e
	case "lobby":
		k, e := signaling.LobbyKey(signaling.LobbyDefault)
		return k, "lobby:default", e
	case "pair":
		k, e := signaling.PairKey(idA, idB)
		return k, "pair(A,B)", e
	default:
		return nil, "", fmt.Errorf("unknown mode %q", mode)
	}
}

func selectModes(m string) []string {
	if m == "all" {
		return []string{"tag", "secret", "lobby", "pair"}
	}
	return []string{m}
}

func mustNonce() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func fatalIf(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}
