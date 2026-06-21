// bench-localfiles measures local/files:write / :read latency + throughput
// against a running peer. One-shot benchmark probe for the v1.2 reliability
// pass — runs a fixed matrix of payload sizes per peer and reports per-op
// timing. Not part of the conformance gate; intentionally minimal.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/localfiles"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9002", "peer address")
	label := flag.String("label", "peer", "label printed in the per-op rows")
	prefix := flag.String("prefix", "local/files/bench/", "tree-path prefix (must match a configured root)")
	flag.Parse()

	sizes := []int{
		1 * 1024,
		64 * 1024,
		256 * 1024,
		1 * 1024 * 1024,
		10 * 1024 * 1024,
		50 * 1024 * 1024,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	client, err := validate.NewPeerClient(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	client.PerformHandshake(ctx)
	if !client.Connected() {
		fmt.Fprintf(os.Stderr, "handshake failed\n")
		os.Exit(1)
	}

	uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())

	fmt.Printf("%-8s  %12s  %10s  %12s  %10s  %12s\n", "label", "size", "write_ms", "write_MB/s", "read_ms", "read_MB/s")
	for _, sz := range sizes {
		body := make([]byte, sz)
		_, _ = rand.Read(body) // FastCDC behaves differently on random vs repeated bytes; random is the realistic case
		path := fmt.Sprintf("%s%d-%d.bin", *prefix, sz, time.Now().UnixNano())

		writeMs, readMs := runOnce(ctx, client, uri, path, body)
		mbps := func(ms float64) float64 {
			if ms == 0 {
				return 0
			}
			return (float64(sz) / (1024.0 * 1024.0)) / (ms / 1000.0)
		}
		fmt.Printf("%-8s  %12d  %10.1f  %12.1f  %10.1f  %12.1f\n",
			*label, sz, writeMs, mbps(writeMs), readMs, mbps(readMs))
	}
}

func runOnce(ctx context.Context, client *validate.PeerClient, uri, path string, body []byte) (writeMs, readMs float64) {
	resource := &types.ResourceTarget{Targets: []string{path}}

	// Write
	wr := localfiles.WriteRequestData{Bytes: body, CreateDirs: true}
	raw, _ := ecf.Encode(wr)
	paramsEnt, _ := entity.NewEntity(localfiles.TypeWriteRequest, cbor.RawMessage(raw))

	// Warm the connection with one trivial op to amortize any first-call cost.
	listPath := path[:len(path)-len("0.bin")] // approximate parent dir
	_ = listPath

	// Measure across N runs and take the median for stability.
	const trials = 5
	writeTimes := make([]float64, 0, trials)
	for i := 0; i < trials; i++ {
		t0 := time.Now()
		_, _, err := client.SendExecute(ctx, uri, "write", paramsEnt, resource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write err size=%d trial=%d: %v\n", len(body), i, err)
			return 0, 0
		}
		writeTimes = append(writeTimes, float64(time.Since(t0).Microseconds())/1000.0)
	}
	sort.Float64s(writeTimes)
	writeMs = writeTimes[len(writeTimes)/2]

	// Read
	emptyParams, _ := entity.NewEntity("primitive/map", cbor.RawMessage{0xa0}) // empty CBOR map
	readTimes := make([]float64, 0, trials)
	for i := 0; i < trials; i++ {
		t0 := time.Now()
		_, _, err := client.SendExecute(ctx, uri, "read", emptyParams, resource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read err size=%d trial=%d: %v\n", len(body), i, err)
			return writeMs, 0
		}
		readTimes = append(readTimes, float64(time.Since(t0).Microseconds())/1000.0)
	}
	sort.Float64s(readTimes)
	readMs = readTimes[len(readTimes)/2]

	return writeMs, readMs
}
