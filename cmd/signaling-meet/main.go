// Command signaling-meet plays exactly ONE role of ONE §4 step-2 rendezvous as a
// process — Go's half of the cross-process go↔py meet.
//
// Everything in the `signaling` validation category spawns BOTH peers of the
// exchange in-process, so the two convergence obligations (§2.2 which key, §3.1.1
// which node) are met trivially — both peers are the same code. The 2026-07-30
// cross-impl report closed that statically: the Go and Python clients derive
// byte-identical keys and select the same pool member for the same inputs. What
// is still missing is a LIVE meet between two implementations, and each side has
// to arrive as a separate process to get there.
//
// This is that process, and it speaks the identical CLI + JSON contract as
// Python's tests/interop/signaling_meet.py so a harness in any language can pair
// the two:
//
//	go run ./cmd/signaling-meet \
//	    --node 127.0.0.1:4050 --role responder --mode tag --input chess-42
//
//	{"ok":true,"role":"responder","peer_id":"...","key":"00ea9b…",
//	 "answered":["<nonce-hex>"],"initiators":[...],"candidates":[...]}
//
// The two roles have deliberately different exit contracts, matching Python:
//   - The INITIATOR exits 0 only if it was answered (a real meet) and returns as
//     soon as it is.
//   - The RESPONDER is a server: it answers everything for the whole --timeout and
//     exits 0 if it answered ≥1 request — weaker on purpose. Answering the backlog
//     and leaving would be answer-first in disguise: on a rerun within the TTL it
//     would drain a prior run's stale requests, exit 0, and never answer the peer
//     that started a moment later (Python found this live). So it serves to its
//     deadline, and its status means only "I served and answered ≥1".
//
// The proof of a meet is the PAIR: the initiator exited 0 AND its nonce appears in
// the responder's `answered`. The `key` field is in the output on purpose — if two
// impls fail to meet, the first question is whether they derived the same 33 bytes,
// answerable by diffing two log lines.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// pollInterval matches Python's 0.2s — the node is a plain store with no
// notification, so both roles poll, which is what §4 step 2 assumes.
const pollInterval = 200 * time.Millisecond

// The candidate payloads mirror Python's byte-for-byte so a diff of the two
// impls' output lines up. They are opaque to the node and to the entity layer.
var initiatorCandidates = []types.NATCandidateData{
	{Type: signaling.CandidateHost, Substrate: signaling.SubstrateTCP, Address: "192.168.1.10:9000", Priority: 0},
	{Type: "srflx", Substrate: signaling.SubstrateTCP, Address: "203.0.113.7:41234", Priority: 0},
}
var responderCandidates = []types.NATCandidateData{
	{Type: signaling.CandidateHost, Substrate: signaling.SubstrateTCP, Address: "192.168.1.11:9000", Priority: 0},
}

func deriveKey(mode, value string) ([]byte, error) {
	switch mode {
	case "tag":
		return signaling.TagKey(value)
	case "secret":
		return signaling.SecretKey(value)
	case "lobby":
		return signaling.LobbyKey(value)
	case "pair":
		a, b, found := strings.Cut(value, ",")
		if !found || a == "" || b == "" {
			return nil, errors.New("--input for mode 'pair' must be 'peer-a,peer-b'")
		}
		return signaling.PairKey(a, b)
	}
	return nil, fmt.Errorf("unknown --mode %q", mode)
}

func addrs(cands []types.NATCandidateData) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Address)
	}
	return out
}

// runInitiator offers a connect-request and waits for the response echoing our
// nonce, returning as soon as it arrives.
func runInitiator(ctx context.Context, sig *signaling.Client, key []byte, peerID string, deadline time.Time) map[string]any {
	nonce, err := signaling.GenerateNonce()
	if err != nil {
		return map[string]any{"ok": false, "error": "generate nonce: " + err.Error()}
	}
	reqEnt, err := types.ConnectRequestData{Candidates: initiatorCandidates, Initiator: peerID, Nonce: nonce}.ToEntity()
	if err != nil {
		return map[string]any{"ok": false, "nonce": hex.EncodeToString(nonce), "error": "build connect-request: " + err.Error()}
	}
	if status, err := sig.OfferMessage(ctx, key, reqEnt); err != nil || status != 200 {
		return map[string]any{"ok": false, "nonce": hex.EncodeToString(nonce), "error": fmt.Sprintf("offer connect-request: status %d err %v", status, err)}
	}
	for time.Now().Before(deadline) {
		if _, msgs, err := sig.CollectMessages(ctx, key); err == nil {
			if resp, found := signaling.FindResponse(msgs, nonce, peerID); found {
				return map[string]any{
					"ok":         true,
					"nonce":      hex.EncodeToString(nonce),
					"responder":  resp.Responder,
					"candidates": addrs(resp.Candidates),
				}
			}
		}
		time.Sleep(pollInterval)
	}
	return map[string]any{"ok": false, "nonce": hex.EncodeToString(nonce), "error": "no response echoing our nonce before the deadline"}
}

// runResponder answers every non-own request in the bucket, for the whole
// deadline, skipping nonces it already answered. See the package comment for why
// it must not exit at the first answer.
func runResponder(ctx context.Context, sig *signaling.Client, key []byte, peerID string, deadline time.Time) map[string]any {
	var answeredNonces, initiators, cands []string
	seen := map[string]bool{}
	for time.Now().Before(deadline) {
		if _, msgs, err := sig.CollectMessages(ctx, key); err == nil {
			for _, m := range msgs {
				if m.Kind != signaling.KindConnectRequest || m.Request.Initiator == peerID {
					continue
				}
				nk := string(m.Request.Nonce)
				if seen[nk] {
					continue
				}
				seen[nk] = true
				respEnt, err := types.ConnectResponseData{Candidates: responderCandidates, Nonce: m.Request.Nonce, Responder: peerID}.ToEntity()
				if err != nil {
					return map[string]any{"ok": false, "answered": answeredNonces, "initiators": initiators, "error": "build connect-response: " + err.Error()}
				}
				if status, err := sig.OfferMessage(ctx, key, respEnt); err != nil || status != 200 {
					return map[string]any{"ok": false, "answered": answeredNonces, "initiators": initiators, "error": fmt.Sprintf("offer connect-response: status %d err %v", status, err)}
				}
				answeredNonces = append(answeredNonces, hex.EncodeToString(m.Request.Nonce))
				initiators = append(initiators, m.Request.Initiator)
				cands = append(cands, addrs(m.Request.Candidates)...)
			}
		}
		time.Sleep(pollInterval)
	}
	if len(answeredNonces) > 0 {
		return map[string]any{"ok": true, "answered": answeredNonces, "initiators": initiators, "candidates": cands}
	}
	return map[string]any{"ok": false, "answered": []string{}, "initiators": []string{}, "error": "no request to answer before the deadline"}
}

func meet(node, role, mode, input string, timeout float64) (map[string]any, error) {
	kp, err := crypto.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	client, err := validate.NewPeerClientWithKeypair(node, kp)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	defer client.Close()

	// A generous outer ctx: the role loops enforce the real --timeout deadline.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration((timeout+15)*float64(time.Second)))
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	client.PerformHandshake(ctx)
	if !client.Connected() {
		return nil, errors.New("handshake did not complete")
	}
	peerID := client.LocalPeerID().String()
	sig := signaling.NewClient(client)

	// `pair` needs both peer-ids, and ours is only known once connected — so a
	// driver passes "…,SELF" and we substitute here, exactly as Python does.
	value := strings.ReplaceAll(input, "SELF", peerID)
	key, err := deriveKey(mode, value)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration(timeout * float64(time.Second)))

	var outcome map[string]any
	if role == "initiator" {
		outcome = runInitiator(ctx, sig, key, peerID, deadline)
	} else {
		outcome = runResponder(ctx, sig, key, peerID, deadline)
	}

	result := map[string]any{
		"role":         role,
		"peer_id":      peerID,
		"node_peer_id": client.RemotePeerID().String(),
		"mode":         mode,
		"input":        value,
		"key":          hex.EncodeToString(key),
	}
	for k, v := range outcome {
		result[k] = v
	}
	return result, nil
}

func main() {
	node := flag.String("node", "", "host:port of the connection node")
	role := flag.String("role", "", "initiator|responder")
	mode := flag.String("mode", "", "tag|secret|lobby|pair")
	input := flag.String("input", "", "the mode's input; 'pair' takes 'peer-a,peer-b'; literal SELF -> this peer-id")
	timeout := flag.Float64("timeout", 15.0, "seconds to run")
	flag.Parse()

	fail := func(msg string) {
		out, _ := json.Marshal(map[string]any{"ok": false, "role": *role, "error": msg})
		fmt.Println(string(out))
		os.Exit(1)
	}
	switch {
	case *node == "":
		fail("--node is required")
	case *role != "initiator" && *role != "responder":
		fail("--role must be initiator|responder")
	case *mode != "tag" && *mode != "secret" && *mode != "lobby" && *mode != "pair":
		fail("--mode must be tag|secret|lobby|pair")
	case *input == "":
		fail("--input is required")
	}

	result, err := meet(*node, *role, *mode, *input, *timeout)
	if err != nil {
		fail(err.Error())
	}
	out, _ := json.Marshal(result)
	fmt.Println(string(out))
	if ok, _ := result["ok"].(bool); ok {
		os.Exit(0)
	}
	os.Exit(1)
}
