package validate

// V7 §6.11 concurrency-correctness conformance gate.
//
// Background: the §7a wire-gate proves the §6.13(a)/(b) seams are reachable
// over the wire. It does NOT exercise §6.11's three concurrency MUSTs:
//
//   - §6.11(a) multiplexed reader / no per-connection serialization
//   - §6.11(b) demux by request_id, no head-of-line blocking
//   - per-impl unit tests for "*ReentrantCrossPeerDoesNotDeadlock" (F-WB28)
//
// Every reference impl unit-tests those — and Go found §6.11
// half-implemented on the accept side, plus all three impls had to do the same
// reentry substrate work. Keystone-generated peers (C#/TS/OCaml) and future
// generated impls (Elixir, OCaml-FFI) inherit the gap until the gate closes it.
//
// This category drives the §6.11 MUSTs over the wire from the (now multiplex-
// capable) PeerClient. It is enumerated in V7 §9.0 as of v7.75 (the §10.2-
// style carve-out used through v7.74 is gone). Its T2.1/T2.2 also exercise
// the §4.9 resilience floor (no silent drop, no crash, recovers when load
// subsides), so the same category covers §6.11 correctness + §4.9 outcomes.
//
// Design principles (mirrored from the arch draft):
//
//   1. A correct §6.11 peer passes unchanged. The validator-side work landed
//      in cmd/internal/validate/client.go (atomic requestSeq + the long-
//      standing bg reader + per-id demux). Peers just get driven harder. A
//      FAIL = a real bug surfaced before ship.
//
//   2. Assert ratios + invariants, not absolute numbers. A slow language
//      passes by being correct, not by being fast. Every assertion is
//      relative ("concurrent ≪ sequential", "p50 stable over windows",
//      "all responses returned") — never "p99 < X ms". Speed is operator
//      concern, not floor.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/conformance"

	"github.com/fxamacker/cbor/v2"
)

const catConcurrency = "concurrency"

// Knob tuning — initial guesses; adjust per category-run feedback. Surfaced
// here so the read of "what does the gate stress" is one open-the-file away.
const (
	// T1.1 — concurrent demux. N parallel tree.gets on distinct paths.
	t11N = 16

	// T1.1 — serialization-ratio ceiling. concurrent wall-clock must be
	// <= this fraction of sequential. 0.7 is generous (false-negatives on
	// slow languages avoided; true serializers — ratio ~1.0 — still caught).
	t11RatioCeiling = 0.7

	// T1.1 — minimum sequential wall-clock for the ratio assertion to fire.
	// Below this, the peer is so fast that wall-clock measurement noise
	// dominates; the assertion would false-FAIL on noise rather than catch
	// real serialization. Completeness + demux + deadlock backstops still
	// fire; only the ratio assertion is suppressed.
	t11MinSeqElapsed = 50 * time.Millisecond

	// T1.1 — deadlock backstop. Concurrent N reqs must complete inside this.
	t11DeadlockCeiling = 30 * time.Second

	// T1.2 — concurrent reentry. M parallel dispatch-outbound calls, each
	// reentering to validator-as-B once. Validator-side hit count asserted
	// to equal M exactly (no missed reentries, no duplicated reentries).
	t12M = 8

	// T1.3 — head-of-line. Solo p50 vs while-slow p50; while-slow must not
	// exceed solo by more than this factor. 4× catches stark serialization
	// while tolerating GC / scheduler jitter typical for sustained loads.
	t13Trials       = 10
	t13Headroom     = 4.0
	t13PayloadBytes = 256 * 1024 // slow request payload size

	// T2.1 — sustained load. C workers × K total reqs (workers pull from a
	// shared counter).
	t21Workers  = 16
	t21TotalReq = 10_000
	// Window size for rolling p50 stability. K must divide evenly into windows.
	t21WindowSize = 1_000
	// Last-window p50 must not exceed first-window p50 by more than this
	// factor (steady-state stability — "doesn't degrade under load").
	t21LatencyRatioCeiling = 4.0

	// T2.2 — connection churn. Number of connect → 1 req → close cycles.
	t22Cycles = 100
)

// runConcurrency entry point — invoked by the suite under --profile core via
// the §9.0 enumeration (v7.75), and unconditionally when -category
// concurrency is explicitly requested. newClient is the suite's own client
// constructor (passed in so churn inherits identity-vs-ephemeral semantics —
// the earlier "load identity: stat ~/.entity/identities" failure against the
// keystone matrix peer was runT22 calling NewPeerClientWithIdentity directly
// instead of going through the suite's newClient → fell over on ephemeral
// invocation, RULINGS-CONCURRENCY-GATE-7b-MATRIX ruling #1).
func runConcurrency(ctx context.Context, client *PeerClient, newClient func() (*PeerClient, error)) []CheckResult {
	r := NewCheckRunner(catConcurrency)

	r.Declare("t1_1_concurrent_demux", "V7 §6.11(a)(b) — multiplexed reader + per-id demux on one connection")
	r.Declare("t1_2_concurrent_reentry", "V7 §6.11 + §7a.2a — concurrent reentrant dispatch (--validate-gated)")
	r.Declare("t1_3_no_head_of_line", "V7 §6.11(a) — fast not gated behind slow on one connection")
	r.Declare("t2_1_sustained_load", "V7 §6.11 robustness — no drops, no latency runaway under sustained C×K load")
	r.Declare("t2_2_connection_churn", "V7 §6.11 robustness — accept loop + per-conn lifecycle across N cycles")

	r.Run("t1_1_concurrent_demux", func() CheckOutcome { return runT11(ctx, client) })
	r.Run("t1_2_concurrent_reentry", func() CheckOutcome { return runT12(ctx, client) })
	r.Run("t1_3_no_head_of_line", func() CheckOutcome { return runT13(ctx, client) })
	r.Run("t2_1_sustained_load", func() CheckOutcome { return runT21(ctx, client) })
	r.Run("t2_2_connection_churn", func() CheckOutcome { return runT22(ctx, newClient) })

	return r.Results()
}

// runT11 — concurrent demux on one connection.
//
// Stage: tree.put N=16 distinct test entities under system/validate/
// concurrency/demux/<i>. Each carries a unique payload → unique content_hash.
// Requires write grants (the gate pairs with --open-access / --debug-grants
// per the §7a opt-in; without write grants the check SKIPs honestly).
//
// Sequential baseline: get all N paths back-to-back, measure wall-clock.
//
// Concurrent: fire N goroutines, each gets one path, asserts the returned
// entity's content_hash equals the expected hash for the requested path.
//
// Asserts (in order):
//   - completeness (FAIL): zero goroutine errors
//   - demux correctness (FAIL): each goroutine got the entity for the path
//     it asked for — cross-talk would show as content_hash mismatch. This
//     is the §6.11(b) core MUST: response demuxed-by-request_id with no
//     cross-talk on a multiplexed connection.
//   - deadlock backstop (FAIL): concurrent < t11DeadlockCeiling.
//   - parallel-speedup (WARN, not FAIL): concurrent < t11RatioCeiling ×
//     sequential. Per RULINGS-CONCURRENCY-GATE-7b-MATRIX ruling
//     #3, this is a *parallelism* signal, not a §6.11 correctness MUST. A
//     cooperative-async / single-OS-thread runtime that demuxes correctly
//     (and passes T1.3 head-of-line) satisfies §6.11 without showing
//     wall-clock speedup. Treating the ratio as FAIL false-flagged TS's
//     event loop as non-conformant. The real serialization signal is T1.3,
//     not this. Ratio kept as informational signal.
func runT11(ctx context.Context, client *PeerClient) CheckOutcome {
	paths, expected, skip := stageDemuxEntities(ctx, client, "demux", t11N)
	if skip != "" {
		return SkipCheck(skip)
	}

	// Sequential baseline.
	seqStart := time.Now()
	for _, p := range paths {
		if _, _, err := client.TreeGet(ctx, p); err != nil {
			return FailCheck(fmt.Sprintf("sequential tree.get %s: %v", p, err))
		}
	}
	seqElapsed := time.Since(seqStart)

	// Concurrent fan-out.
	type result struct {
		path string
		hash string
		err  error
	}
	results := make(chan result, t11N)
	concStart := time.Now()
	for _, p := range paths {
		go func(p string) {
			ent, _, err := client.TreeGet(ctx, p)
			if err != nil {
				results <- result{path: p, err: err}
				return
			}
			results <- result{path: p, hash: ent.ContentHash.String()}
		}(p)
	}
	var errs []string
	var crossTalk []string
	for i := 0; i < t11N; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", r.path, r.err))
				continue
			}
			if r.hash != expected[r.path] {
				crossTalk = append(crossTalk, fmt.Sprintf("%s: got hash %s expected %s", r.path, r.hash, expected[r.path]))
			}
		case <-time.After(t11DeadlockCeiling):
			return FailCheck(fmt.Sprintf("concurrent N=%d tree.get did not complete inside %v — §6.11 deadlock backstop tripped", t11N, t11DeadlockCeiling))
		}
	}
	concElapsed := time.Since(concStart)

	if len(errs) > 0 {
		return FailCheck(fmt.Sprintf("%d/%d concurrent gets errored: %v", len(errs), t11N, errs))
	}
	if len(crossTalk) > 0 {
		return FailCheck(fmt.Sprintf("§6.11(b) demux cross-talk: %d/%d responses carried the wrong entity: %v", len(crossTalk), t11N, crossTalk))
	}

	if seqElapsed < t11MinSeqElapsed {
		return PassCheck(fmt.Sprintf("N=%d concurrent gets all returned + demuxed correctly; sequential baseline %v < %v floor, parallel-speedup signal suppressed (peer too fast for noise-free measurement)", t11N, seqElapsed, t11MinSeqElapsed))
	}

	ratio := float64(concElapsed) / float64(seqElapsed)
	if ratio > t11RatioCeiling {
		// Informational only — see ruling #3 comment on runT11. A
		// cooperative-async runtime sits here and is fully §6.11-conformant
		// (T1.3 head-of-line is the actual serialization correctness gate).
		return WarnCheck(fmt.Sprintf("demux + completeness OK, but no parallel speedup observed: N=%d concurrent took %v vs %v sequential (ratio %.2f > %.2f). Not a §6.11 violation — informational signal for runtimes that don't physically parallelize (single-threaded event loops). The §6.11(a) no-serialization MUST is enforced by t1_3 head-of-line, which a correct cooperative-async peer passes", t11N, concElapsed, seqElapsed, ratio, t11RatioCeiling))
	}
	return PassCheck(fmt.Sprintf("N=%d concurrent gets all returned + demuxed correctly; parallel speedup observed: concurrent %v / sequential %v = ratio %.2f (≤ %.2f informational ceiling)", t11N, concElapsed, seqElapsed, ratio, t11RatioCeiling))
}

// stageDemuxEntities tree-puts n distinct test entities under
// system/validate/concurrency/<bucket>/<i> and returns the paths along with
// each path's expected content_hash (hex). Used by T1.1 (n=16, demux assertion)
// and T2.1 (n=1, hot path). Returns a non-empty skip message when the peer
// refuses the put (no write grant — the gate pairs with --open-access /
// --debug-grants, so this is honest "not opted in", not a substrate failure).
//
// Listing-based path discovery was deliberately dropped: tree.listing is
// single-level by design and handler manifests live at deep-nested paths
// (system/handler/system/tree, etc.), so a top-level listing of system/handler/
// returns 2 namespace stubs, not the 21 manifests the peer registered.
// Hard-coding well-known core handler paths would couple this gate to a
// stable handler set across all generated peers — fragile. Staged entities
// give per-run, deterministic, write-grant-gated paths.
func stageDemuxEntities(ctx context.Context, client *PeerClient, bucket string, n int) (paths []string, expected map[string]string, skip string) {
	paths = make([]string, n)
	expected = make(map[string]string, n)
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("system/validate/concurrency/%s/%d", bucket, i)
		payload := fmt.Sprintf("concurrency-%s-payload-%d-7f3a2c91", bucket, i)
		ent, err := entity.NewEntity("primitive/string", cbor.RawMessage(mustEncode(payload)))
		if err != nil {
			return nil, nil, fmt.Sprintf("build staged entity %d: %v", i, err)
		}
		h, err := client.TreePut(ctx, path, ent)
		if err != nil {
			return nil, nil, fmt.Sprintf("tree.put %s rejected (%v) — peer not running with write grants the concurrency gate requires (pair --validate with --open-access or --debug-grants)", path, err)
		}
		paths[i] = path
		expected[path] = h.String()
	}
	return paths, expected, ""
}

// runT12 — concurrent reentrant dispatch.
//
// Arms validator-side reentry echo once, fires M parallel dispatch-outbound
// EXECUTEs each carrying a unique payload. Each goroutine asserts the
// downstream-echoed payload matches what it sent (per-call demux correctness
// from inside reentry, not just from the outer EXECUTE_RESPONSE). After all
// goroutines return, the validator-side hit count is checked exactly equal
// to M — no missed reentries, no spurious duplicates.
//
// SKIPs when the target peer wasn't started with --validate (no scaffolding).
// This is the cross-impl promotion of each impl's *ReentrantCrossPeerDoesNot
// Deadlock test — the per-connection-mutex / bidirectional-reentry deadlock
// class (the F-WB28 bug that bit all three reference impls).
func runT12(ctx context.Context, client *PeerClient) CheckOutcome {
	if !client.HasConformanceHandlers(ctx) {
		return SkipCheck("target peer not run with --validate (system/validate/dispatch-outbound absent — concurrent-reentry attestation needs the §7a scaffold)")
	}

	st := client.ArmReentryEcho()
	defer client.DisarmReentryEcho()

	type result struct {
		idx int
		err error
	}
	results := make(chan result, t12M)
	for i := 0; i < t12M; i++ {
		go func(i int) {
			value := fmt.Sprintf("concurrent-reentry-%d-7f3a", i)
			err := client.SendDispatchOutboundProbeConcurrent(ctx, value)
			results <- result{idx: i, err: err}
		}(i)
	}

	var errs []string
	for i := 0; i < t12M; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				errs = append(errs, fmt.Sprintf("[%d] %v", r.idx, r.err))
			}
		case <-time.After(t11DeadlockCeiling):
			return FailCheck(fmt.Sprintf("M=%d concurrent dispatch-outbound did not complete inside %v — §6.11 reentry deadlock backstop tripped (F-WB28 class)", t12M, t11DeadlockCeiling))
		}
	}
	if len(errs) > 0 {
		return FailCheck(fmt.Sprintf("%d/%d concurrent reentries errored: %v", len(errs), t12M, errs))
	}

	hits := st.Hits()
	if int(hits) != t12M {
		return FailCheck(fmt.Sprintf("§6.11 reentry hit count drifted from M=%d under concurrency: validator-side echo saw %d inbound EXECUTEs (expected %d — duplicate or missed reentry)", t12M, hits, t12M))
	}
	return PassCheck(fmt.Sprintf("M=%d concurrent reentrant dispatch-outbound calls all round-tripped; validator-as-B served %d inbound echos (exactly-one per dispatch under concurrency)", t12M, hits))
}

// runT13 — head-of-line tolerance.
//
// Strategy: stage one large entity (slow get) + one tiny entity (fast get).
// Measure solo p50 of fast.get over N trials. Then start the slow get in a
// goroutine and, while it's in flight, measure busy p50 of fast.get over
// the same N trials. Assert busy_p50 < t13Headroom × solo_p50.
//
// SKIPs if the peer rejects the staging put (no write grant — this gate runs
// against peers with open / debug grants, but a strict peer may refuse).
//
// Beats single-trial "fast arrived before slow" ordering: that can pass on
// a serializing peer by lucky scheduling. The latency-comparison form makes
// "fast independent of slow's progress" the assertion — exactly the §6.11(a)
// non-serialization property.
func runT13(ctx context.Context, client *PeerClient) CheckOutcome {
	// Stage. Use a content-hash-distinct payload to avoid collision with
	// pre-existing content under the path.
	slowPath := "system/validate/concurrency/slow"
	fastPath := "system/validate/concurrency/fast"

	slowPayload := make([]byte, t13PayloadBytes)
	for i := range slowPayload {
		slowPayload[i] = byte(i % 251)
	}
	slowEnt, err := entity.NewEntity("primitive/bytes", cbor.RawMessage(mustEncode(slowPayload)))
	if err != nil {
		return FailCheck("build slow entity: " + err.Error())
	}
	fastEnt, err := entity.NewEntity("primitive/bytes", cbor.RawMessage(mustEncode([]byte("fast"))))
	if err != nil {
		return FailCheck("build fast entity: " + err.Error())
	}

	if _, err := client.TreePut(ctx, slowPath, slowEnt); err != nil {
		return SkipCheck(fmt.Sprintf("tree.put %s rejected (%v) — peer not running with write grants the head-of-line test requires", slowPath, err))
	}
	if _, err := client.TreePut(ctx, fastPath, fastEnt); err != nil {
		return SkipCheck(fmt.Sprintf("tree.put %s rejected (%v)", fastPath, err))
	}

	measure := func() (time.Duration, error) {
		start := time.Now()
		_, _, err := client.TreeGet(ctx, fastPath)
		return time.Since(start), err
	}

	// Solo p50.
	soloLatencies := make([]time.Duration, 0, t13Trials)
	for i := 0; i < t13Trials; i++ {
		d, err := measure()
		if err != nil {
			return FailCheck(fmt.Sprintf("solo fast.get [%d]: %v", i, err))
		}
		soloLatencies = append(soloLatencies, d)
	}
	soloP50 := p50(soloLatencies)

	// Busy p50: start slow in flight, hammer fast.
	slowDone := make(chan error, 1)
	go func() {
		_, _, err := client.TreeGet(ctx, slowPath)
		slowDone <- err
	}()
	// Tiny yield so slow's wire write goes first.
	time.Sleep(2 * time.Millisecond)

	busyLatencies := make([]time.Duration, 0, t13Trials)
	for i := 0; i < t13Trials; i++ {
		d, err := measure()
		if err != nil {
			<-slowDone // drain
			return FailCheck(fmt.Sprintf("busy fast.get [%d]: %v", i, err))
		}
		busyLatencies = append(busyLatencies, d)
	}
	if err := <-slowDone; err != nil {
		return FailCheck("slow get failed: " + err.Error())
	}
	busyP50 := p50(busyLatencies)

	if soloP50 == 0 {
		return PassCheck(fmt.Sprintf("fast.get solo p50 below measurement resolution; busy p50 = %v (no head-of-line behavior detectable)", busyP50))
	}
	ratio := float64(busyP50) / float64(soloP50)
	if ratio > t13Headroom {
		return FailCheck(fmt.Sprintf("§6.11(a) head-of-line suspected: fast.get latency p50 jumped %.1fx (solo=%v → while-slow=%v, ceiling %.1fx); fast appears gated behind slow on the connection", ratio, soloP50, busyP50, t13Headroom))
	}
	return PassCheck(fmt.Sprintf("fast.get latency p50 stable under contention: solo=%v → while-slow=%v (ratio %.2f ≤ %.1fx)", soloP50, busyP50, ratio, t13Headroom))
}

// runT21 — sustained concurrent load.
//
// C workers pull from a shared atomic counter and issue tree.gets until the
// counter exhausts K total. Latency captured per request. After draining:
//   - completeness: all K returned, zero errors
//   - p50 stability: rolling p50 over t21WindowSize-request windows; the last
//     window's p50 must not exceed the first window's p50 by more than
//     t21LatencyRatioCeiling. Captures "peer degrades under sustained load"
//     without bringing in absolute latency thresholds.
func runT21(ctx context.Context, client *PeerClient) CheckOutcome {
	// Stage one hot entity. Same write-grant requirement as T1.1.
	paths, _, skip := stageDemuxEntities(ctx, client, "sustained", 1)
	if skip != "" {
		return SkipCheck(skip)
	}
	hotPath := paths[0]

	latencies := make([]time.Duration, t21TotalReq)
	errs := make([]error, t21TotalReq)
	var counter atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < t21Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				idx := counter.Add(1) - 1
				if idx >= t21TotalReq {
					return
				}
				start := time.Now()
				_, _, err := client.TreeGet(ctx, hotPath)
				latencies[idx] = time.Since(start)
				errs[idx] = err
			}
		}()
	}
	wg.Wait()

	var dropped int
	for _, e := range errs {
		if e != nil {
			dropped++
		}
	}
	if dropped > 0 {
		return FailCheck(fmt.Sprintf("§6.11 robustness: %d/%d sustained requests dropped (first error: %v)", dropped, t21TotalReq, firstNonNilErr(errs)))
	}

	firstP50 := p50(latencies[:t21WindowSize])
	lastP50 := p50(latencies[t21TotalReq-t21WindowSize:])
	if firstP50 == 0 {
		return PassCheck(fmt.Sprintf("C=%d × K=%d sustained load: zero drops; first-window p50 below measurement resolution; last-window p50 = %v (stable)", t21Workers, t21TotalReq, lastP50))
	}
	ratio := float64(lastP50) / float64(firstP50)
	if ratio > t21LatencyRatioCeiling {
		return FailCheck(fmt.Sprintf("§6.11 robustness: p50 degraded %.1fx over %d sustained requests (first-window=%v, last-window=%v, ceiling %.1fx) — sustained-load runaway", ratio, t21TotalReq, firstP50, lastP50, t21LatencyRatioCeiling))
	}
	return PassCheck(fmt.Sprintf("C=%d × K=%d sustained load: zero drops; p50 stable across windows (first=%v, last=%v, ratio %.2f ≤ %.1fx)", t21Workers, t21TotalReq, firstP50, lastP50, ratio, t21LatencyRatioCeiling))
}

// runT22 — connection churn.
//
// 100 sequential cycles of: dial new client → handshake → 1 tree.get → close.
// Catches per-connection resource leaks the peer doesn't bound (goroutine /
// task / file-descriptor leak per connection — eventually accept() starts
// refusing, latency degrades, or the process OOMs). Pure black-box: leak →
// later cycles fail; no leak → all 100 succeed identically.
func runT22(ctx context.Context, newClient func() (*PeerClient, error)) CheckOutcome {
	if newClient == nil {
		return SkipCheck("connection churn needs the suite's newClient constructor (single-peer mode required)")
	}
	for i := 0; i < t22Cycles; i++ {
		cli, err := newClient()
		if err != nil {
			return FailCheck(fmt.Sprintf("cycle %d: new client: %v", i, err))
		}
		if err := cli.Connect(ctx); err != nil {
			cli.Close()
			return FailCheck(fmt.Sprintf("cycle %d: connect (peer may have stopped accepting — per-connection resource leak?): %v", i, err))
		}
		if _, ok := runConnectivity(ctx, cli); !ok {
			cli.Close()
			return FailCheck(fmt.Sprintf("cycle %d: handshake failed (peer may have degraded under churn)", i))
		}
		// One cheap tree.get on a known core path — the connect handshake
		// alone proves accept() works; this proves the per-conn dispatcher
		// still serves a request on the freshly-accepted socket. The path
		// is the §6.11(b)-required system/handler tree node every peer
		// publishes; no write grants needed.
		if _, _, err := cli.TreeGet(ctx, "system/handler/system/tree"); err != nil {
			cli.Close()
			return FailCheck(fmt.Sprintf("cycle %d: tree.get system/handler/system/tree failed (peer refused or hung): %v", i, err))
		}
		cli.Close()
	}
	return PassCheck(fmt.Sprintf("%d connect → handshake → 1 req → close cycles all succeeded (cycle %d worked as well as cycle 1 — no observable per-connection resource leak)", t22Cycles, t22Cycles))
}

// SendDispatchOutboundProbeConcurrent is the parallel-safe sibling of
// SendDispatchOutboundProbe. Mints its own reentry capability (so concurrent
// invocations don't share mutable state), sends the dispatch-outbound EXECUTE,
// and asserts the downstream echo's value byte-equals what it sent — the
// per-call demux correctness assertion under reentry concurrency. The total
// hit count is asserted at the caller (validator-side aggregate after the
// fan-out completes), not here.
//
// Shape per GUIDE-CONFORMANCE §7a.1 (clarified by RULINGS-CONCURRENCY-GATE-7b-
// MATRIX ruling #2): echo returns the params entity verbatim, where
// params is shaped {value: X}. dispatch-outbound is a generic relay — its
// result field carries the downstream's result entity verbatim, no unwrapping.
// So the round-trip rides as result.value (an entity field, not a bare
// scalar), and the probe MUST assert result.value == sent. A probe that
// expects a bare scalar (the earlier-shipped version of this code) was the
// non-conformant party — surfaced when the keystone matrix ran an Elixir peer
// against it.
func (c *PeerClient) SendDispatchOutboundProbeConcurrent(ctx context.Context, value string) error {
	capEnt, granterEnt, sigEnt, err := c.MintReentryCapability()
	if err != nil {
		return fmt.Errorf("mint reentry capability: %w", err)
	}
	capRaw, err := ecf.Encode(capEnt)
	if err != nil {
		return fmt.Errorf("encode reentry_capability: %w", err)
	}
	granterRaw, err := ecf.Encode(granterEnt)
	if err != nil {
		return fmt.Errorf("encode reentry_granter: %w", err)
	}
	sigRaw, err := ecf.Encode(sigEnt)
	if err != nil {
		return fmt.Errorf("encode reentry_cap_signature: %w", err)
	}

	// Build echo's params shape ({value: X}) and use the encoded form as
	// the outbound value field. A truly generic dispatch-outbound relay
	// won't unwrap or inspect this — it just passes the bytes through as
	// the outbound EXECUTE's params data, which is exactly what echo
	// expects per §7a.1 (params shape = {value: X}, returned verbatim).
	echoParamsRaw, err := ecf.Encode(map[string]interface{}{"value": value})
	if err != nil {
		return fmt.Errorf("encode echo params: %w", err)
	}

	validatorURI := fmt.Sprintf("entity://%s/%s",
		c.identityPeerIDString(), conformance.PatternEcho)
	paramsRaw, err := ecf.Encode(map[string]interface{}{
		"target":                validatorURI,
		"operation":             "echo",
		"value":                 cbor.RawMessage(echoParamsRaw),
		"reentry_capability":    cbor.RawMessage(capRaw),
		"reentry_granter":       cbor.RawMessage(granterRaw),
		"reentry_cap_signature": cbor.RawMessage(sigRaw),
	})
	if err != nil {
		return fmt.Errorf("encode dispatch-outbound params: %w", err)
	}
	paramsEnt, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return fmt.Errorf("build dispatch-outbound params entity: %w", err)
	}
	uri := fmt.Sprintf("entity://%s/%s", c.remotePeerID, conformance.PatternDispatchOutbound)
	env, _, err := c.SendExecute(ctx, uri, "dispatch", paramsEnt, nil)
	if err != nil {
		return fmt.Errorf("send dispatch-outbound: %w", err)
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("decode dispatch-outbound response: %w", err)
	}
	if respData.Status != 200 {
		return fmt.Errorf("dispatch-outbound returned status %d (expected 200)", respData.Status)
	}
	var outerResult entity.Entity
	if err := ecf.Decode(respData.Result, &outerResult); err != nil {
		return fmt.Errorf("decode outer result: %w", err)
	}
	var inner conformance.DispatchOutboundResult
	if err := ecf.Decode(outerResult.Data, &inner); err != nil {
		return fmt.Errorf("decode inner result: %w", err)
	}
	if inner.Status != 200 {
		return fmt.Errorf("downstream echo status %d (expected 200)", inner.Status)
	}

	// Per-call demux assertion. inner.Result is the downstream's result
	// entity verbatim per §7a.1 — for echo that means an entity whose data
	// is the params map ({value: X}). Decode that map, assert .value
	// equals what we sent. A goroutine that received another goroutine's
	// echo (concurrent cross-talk inside reentry) would see a mismatched
	// value here.
	var echoedEnt entity.Entity
	if err := ecf.Decode(inner.Result, &echoedEnt); err != nil {
		return fmt.Errorf("decode echoed result entity: %w", err)
	}
	var echoed struct {
		Value string `cbor:"value"`
	}
	if err := ecf.Decode(echoedEnt.Data, &echoed); err != nil {
		return fmt.Errorf("decode echoed {value: X} map: %w", err)
	}
	if echoed.Value != value {
		return fmt.Errorf("§6.11(b) reentry cross-talk: dispatch sent value %q, downstream result.value replied %q", value, echoed.Value)
	}
	return nil
}

// p50 returns the median of a non-empty duration slice. Mutates a copy, not
// the input.
func p50(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(d))
	copy(cp, d)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

func firstNonNilErr(errs []error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// mustEncode is for inline literal payloads in tests — ECF-encodes the value
// or panics. Use only on call sites where the value is a known-good Go literal
// (test fixtures); never for caller-supplied data.
func mustEncode(v interface{}) []byte {
	b, err := ecf.Encode(v)
	if err != nil {
		panic(fmt.Sprintf("concurrency test fixture ecf.Encode: %v", err))
	}
	return b
}
