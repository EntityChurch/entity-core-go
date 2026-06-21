// scan-probe — dispatches system/discovery:scan(mdns) against a target peer
// and prints the snapshot's candidate decoded shape (peer_id + endpoint).
// Throwaway harness for the D8 cohort LAN convergence smoke test.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/discovery/mdns"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9212", "peer addr to dispatch :scan against")
	flag.Parse()

	client, err := validate.NewPeerClient(*addr)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}
	for _, c := range client.PerformHandshake(ctx) {
		if c.Severity == validate.Fail {
			log.Fatalf("handshake fail: %s: %s", c.Name, c.Message)
		}
	}

	req := types.ScanRequestData{Backend: types.DiscoveryBackendMDNS}
	reqEnt, _ := req.ToEntity()
	uri := fmt.Sprintf("entity://%s/system/discovery", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, "scan", reqEnt, nil)
	if err != nil {
		log.Fatalf("dispatch: %v", err)
	}
	resp, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		log.Fatalf("decode exec response: %v", err)
	}
	if resp.Status != 200 {
		log.Fatalf("scan returned status %d", resp.Status)
	}
	var resultEnt entity.Entity
	if err := ecf.Decode(resp.Result, &resultEnt); err != nil {
		log.Fatalf("decode result entity: %v", err)
	}
	sr, err := types.ScanResultDataFromEntity(resultEnt)
	if err != nil {
		log.Fatalf("decode scan-result: %v", err)
	}
	fmt.Printf("Target: %s (peer_id=%s)\n", *addr, client.RemotePeerID())
	fmt.Printf("Snapshot: %d candidates, truncated=%v\n", len(sr.Candidates), sr.Truncated)
	for i, ch := range sr.Candidates {
		candEnt, ok := env.Included[ch]
		if !ok {
			path := fmt.Sprintf("/%s/%s",
				client.RemotePeerID(),
				types.CandidateStoragePath(types.DiscoveryBackendMDNS, ch))
			fetched, _, ferr := client.TreeGet(ctx, path)
			if ferr != nil {
				fmt.Printf("  [%d] %s — fetch error: %v\n", i, ch, ferr)
				continue
			}
			candEnt = fetched
		}
		cd, _ := types.CandidateDataFromEntity(candEnt)
		host, port, txt, _ := mdns.DecodeEndpointHint(cd.EndpointHint)
		fmt.Printf("  [%d] hash=%s\n", i, ch)
		fmt.Printf("       backend=%s peer_id=%q observed_at=%d\n", cd.Backend, cd.PeerID, cd.ObservedAt)
		fmt.Printf("       host=%s port=%d txt=%v\n", host, port, txt)
	}
}
