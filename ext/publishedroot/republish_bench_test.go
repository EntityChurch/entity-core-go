package publishedroot

import (
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Measurements behind EXTENSION-NETWORK §6.5.6's bounded-convergence MUST.
//
// The spec pins a 30 s maximum convergence delay and says the number is
// derived, not authored — 10 s measured-achievable, 3× headroom — and that
// it is "falsifiable on measured evidence: if a conformant publisher under
// realistic load cannot meet it, that is a finding that fixes this number
// in place." These are that evidence.
//
// The stack under measurement is the one a peer actually wires, in the
// same order (core/peer/peer.go): a notifying location index carrying the
// named sync hooks, with the namespaced index layered on top, and both
// tree/root-tracker and publishedroot/publisher registered as hooks. A
// tree:put therefore cascades write → tracker rebuild → tracked-root
// advance → publisher.OnTreeChange → Publish, exactly as in production.
// Measuring Publish() alone would answer a much easier question.
//
// Run:
//
//	go test ./ext/publishedroot/ -run TestRepublish -v          # the reports
//	go test ./ext/publishedroot/ -bench Republish -benchtime 200x

type republishStack struct {
	cs      store.ContentStore
	nli     store.LocationIndex
	tracker *tree.RootTracker
	pub     *Publisher
	peerID  string
}

func buildRepublishStack(tb testing.TB, prefix string, opts ...PublisherOption) *republishStack {
	tb.Helper()
	cs := store.NewMemoryContentStore()
	inner := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		tb.Fatalf("generate keypair: %v", err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		tb.Fatalf("identity entity: %v", err)
	}
	if _, err := cs.Put(identity); err != nil {
		tb.Fatalf("put identity: %v", err)
	}

	events := make(chan store.TreeChangeEvent, 4096)
	done := make(chan struct{})
	tb.Cleanup(func() { close(done) })
	// Drain: the notifying index drops events when the channel fills, and
	// a dropped event is not a republish that failed to fire — it is a
	// measurement artifact. Draining keeps the async path from
	// contaminating the synchronous one we are timing.
	go func() {
		for {
			select {
			case <-events:
			case <-done:
				return
			}
		}
	}()

	notifying := store.NewNotifyingLocationIndex(inner, events, done)
	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	pub := NewPublisher(cs, tracker, prefix, nil, opts...)
	notifying.AddNamedSyncHook("tree/root-tracker", tracker.OnTreeChange)
	notifying.AddNamedSyncHook("publishedroot/publisher", pub.OnTreeChange)

	nli := store.NewNamespacedIndex(notifying, string(kp.PeerID()))
	// The tracker must read and write through the SAME namespaced index that
	// emits events, or it has no index at all and silently tracks nothing —
	// which looks exactly like a publisher that never fires.
	tracker.SetLocationIndex(nli)
	tracker.Load()
	if err := pub.SetupAuthority(nli, kp, identity, true); err != nil {
		tb.Fatalf("setup authority: %v", err)
	}
	s := &republishStack{cs: cs, nli: nli, tracker: tracker, pub: pub, peerID: string(kp.PeerID())}
	// Settle before returning. enableTracking writes a tracking-config,
	// which cascades into an initial publish that lands ASYNCHRONOUSLY —
	// so a test taking its baseline immediately can attribute that publish
	// to its own writes. That is how the prefix check first reported
	// out-of-prefix writes causing a republish when they had caused none:
	// a baseline read before the system quiesced, which is the same defect
	// class as a check that passes off an unobserved baseline.
	s.settle(tb)
	return s
}

// put authors and binds one entity at a peer-relative path, cascading the
// full hook chain.
func (s *republishStack) put(tb testing.TB, path string, i int) {
	tb.Helper()
	raw, err := cbor.Marshal(map[string]any{"n": i, "body": "republish benchmark payload"})
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	ent, err := entity.NewEntity("test/bench/item/v1", raw)
	if err != nil {
		tb.Fatalf("author: %v", err)
	}
	if _, err := s.cs.Put(ent); err != nil {
		tb.Fatalf("cs.Put: %v", err)
	}
	if err := s.nli.Set(path, ent.ContentHash); err != nil {
		tb.Fatalf("nli.Set %s: %v", path, err)
	}
}

// settle waits until the publisher has gone quiet: the seq stops moving
// across a full debounce window. Any test that measures republish COUNTS
// must start from here, or it charges its own baseline to itself.
func (s *republishStack) settle(tb testing.TB) {
	tb.Helper()
	window := s.pub.debounce
	if window <= 0 {
		window = 5 * time.Millisecond
	}
	deadline := time.Now().Add(5 * time.Second)
	last := s.seq(tb)
	for time.Now().Before(deadline) {
		time.Sleep(2 * window)
		now := s.seq(tb)
		if now == last {
			return
		}
		last = now
	}
	tb.Fatalf("publisher never quiesced (seq still advancing at %d)", last)
}

func (s *republishStack) seq(tb testing.TB) uint64 {
	tb.Helper()
	cur, ok := s.pub.Current()
	if !ok {
		return 0
	}
	var pr types.PublishedRootData
	if err := ecf.Decode(cur.Data, &pr); err != nil {
		tb.Fatalf("decode published-root: %v", err)
	}
	return pr.Seq
}

// publishedRoot returns the root_hash the published root currently commits
// to, which is what a consumer sees — distinct from the seq, which only
// says a republish happened.
func (s *republishStack) publishedRoot(tb testing.TB) (h string, seq uint64) {
	tb.Helper()
	cur, ok := s.pub.Current()
	if !ok {
		return "", 0
	}
	var pr types.PublishedRootData
	if err := ecf.Decode(cur.Data, &pr); err != nil {
		tb.Fatalf("decode published-root: %v", err)
	}
	return pr.RootHash.String(), pr.Seq
}

// awaitConvergence polls until the published root commits to the tracker's
// current tracked root, and returns how long that took. This is §6.5.6's
// actual requirement — "the published root converges to the tracked root
// within a maximum convergence delay" — as opposed to "a republish
// happened", which a seq bump alone would show.
func (s *republishStack) awaitConvergence(tb testing.TB, deadline time.Duration) (time.Duration, bool) {
	tb.Helper()
	start := time.Now()
	tracked, ok := s.tracker.Root(s.pub.prefix)
	if !ok {
		tb.Fatalf("tracker has no root for prefix %q", s.pub.prefix)
	}
	want := tracked.String()
	for time.Since(start) < deadline {
		if got, _ := s.publishedRoot(tb); got == want {
			return time.Since(start), true
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start), false
}

// TestRepublishConvergenceAfterBurst is the §6.5.6 measurement, and it is
// deliberately shaped around the hazard the design creates.
//
// Publishing is asynchronous: OnTreeChange spawns a goroutine, because
// calling Publish inline would deadlock against rootTracker's per-prefix
// mutex. Bursts are compressed by Publish's re-entry guard — a republish
// that arrives while one is in flight returns errPublishInProgress and is
// DROPPED, on the reasoning that "the next cascade will pick up the new
// root once we're done".
//
// That reasoning holds only while writes keep coming. The interesting case
// is a burst that STOPS: if the final write's republish is the one the
// guard dropped, there is no next cascade to pick it up, and the published
// root stays behind the tracked root indefinitely — a convergence delay of
// infinity, not 30 s. So the measurement writes a burst, quiesces, and then
// polls for the published root to catch up.
// TestRepublishConvergenceUndebounced gates the SAME §6.5.6 property with
// debouncing switched off — the configuration in which the newest-wins
// coalescing slot is actually load-bearing.
//
// This exists because of a measured result: with the 25 ms debounce on,
// a regression in the undebounced coalescing does NOT break convergence,
// since the timer rarely collides with an in-flight publish. So the debounced
// test alone cannot gate it, and a regression there would ship silently while
// every test stayed green. Two configurations, two gates.
//
// It once FAILED under CPU starvation (GOMAXPROCS=1 / --cpus<1), and that was
// a real defect, not a flake: the undebounced path spawned one goroutine per
// advance carrying a captured root hash, and under load a late goroutine could
// publish a stale root LAST — leaving the published root behind the tracked
// root indefinitely (seq>writes with converged=false: work done, wrong root
// landed). Fixed by routing every advance through the single newest-wins slot
// (see publisher.go `dirty`); it now converges in ~1 ms regardless of load.
// TestOnTreeChangeRecordsNewestInSlot pins the same invariant deterministically.
func TestRepublishConvergenceUndebounced(t *testing.T) {
	s := buildRepublishStack(t, PrefixForLocalPeer, WithDebounce(0))
	const n = 5000
	for i := 0; i < n; i++ {
		s.put(t, fmt.Sprintf("system/bench/undeb-%06d", i), i)
	}
	d, converged := s.awaitConvergence(t, 30*time.Second)
	_, seq := s.publishedRoot(t)
	t.Logf("undebounced n=%d  convergence=%v converged=%v  seq=%d  republishes/write=%.3f",
		n, d, converged, seq, float64(seq)/float64(n))
	if !converged {
		tracked, _ := s.tracker.Root(s.pub.prefix)
		got, _ := s.publishedRoot(t)
		t.Errorf("§6.5.6 VIOLATED with debouncing off: published root did not converge after the burst stopped.\n"+
			"  tracked root:   %s\n  published root: %s\n"+
			"  The published root is stuck behind the tracked root — a coalesced advance was lost\n"+
			"  (a stale root published last, or a trailing advance never drained).", tracked, got)
	}
}

func TestRepublishConvergenceAfterBurst(t *testing.T) {
	for _, n := range []int{100, 1000, 5000} {
		t.Run(fmt.Sprintf("writes=%d", n), func(t *testing.T) {
			s := buildRepublishStack(t, PrefixForLocalPeer)
			start := time.Now()
			for i := 0; i < n; i++ {
				s.put(t, fmt.Sprintf("system/bench/item-%06d", i), i)
			}
			writeWall := time.Since(start)

			d, converged := s.awaitConvergence(t, 30*time.Second)
			_, seq := s.publishedRoot(t)
			t.Logf("n=%d  write-wall=%v  post-quiesce convergence=%v converged=%v  seq=%d  republishes/write=%.3f",
				n, writeWall, d, converged, seq, float64(seq)/float64(n))
			if !converged {
				tracked, _ := s.tracker.Root(s.pub.prefix)
				got, _ := s.publishedRoot(t)
				t.Errorf("§6.5.6 VIOLATED: published root did not converge within 30 s after the burst stopped.\n"+
					"  tracked root:   %s\n  published root: %s\n"+
					"  The published root is stuck behind the tracked root — a coalesced advance was lost\n"+
					"  (a stale root published last, or a trailing advance never drained).", tracked, got)
			}
		})
	}
}

// TestRepublishAmplification quantifies what §6.5.6 explicitly permits us
// to avoid: "a signature per tree:put is write-amplifying and is not the
// intent ... a cascade SHOULD produce one republish, not one per binding."
//
// Go does no debouncing — OnTreeChange publishes inline on every
// tracked-root advance — so this reports the ratio we actually ship.
func TestRepublishAmplification(t *testing.T) {
	const n = 500
	s := buildRepublishStack(t, PrefixForLocalPeer)
	before := s.seq(t)
	for i := 0; i < n; i++ {
		s.put(t, fmt.Sprintf("system/bench/amp-%06d", i), i)
	}
	// Read the count only AFTER convergence. Sampling seq the instant the
	// loop ends measures how much publishing happened to have finished by
	// then — which with a debounce window is "none", and reads as a
	// spectacular ratio while proving nothing at all.
	if _, ok := s.awaitConvergence(t, 30*time.Second); !ok {
		t.Fatal("did not converge; amplification figure would be meaningless")
	}
	after := s.seq(t)
	republishes := after - before
	t.Logf("writes=%d republishes=%d ratio=%.4f republishes-per-write (debounce=%v)",
		n, republishes, float64(republishes)/float64(n), s.pub.debounce)
	if republishes == 0 {
		t.Error("converged with zero republishes — the counter is not measuring the publish path")
	}
}

// TestRepublishPrefixCostProfile answers the fourth open question: what
// --publish-prefix buys. A narrow prefix bounds both the trie the tracker
// rebuilds and the closure the publisher commits to, so writes landing
// OUTSIDE the tracked prefix should cost nothing in republish terms.
func TestRepublishPrefixCostProfile(t *testing.T) {
	const n = 500
	// Two scenarios against the same narrow prefix. Under debouncing an
	// absolute republish count says little (a burst collapses to a
	// handful either way), so the discriminator is the CONTRAST: writes
	// entirely outside the tracked prefix must cost ZERO republishes,
	// while writes inside it must cost some. Comparing the two is what
	// makes this measure the prefix rather than the clock.
	outOnly := buildRepublishStack(t, "system/content/")
	outBefore := outOnly.seq(t)
	for i := 0; i < n; i++ {
		outOnly.put(t, fmt.Sprintf("system/other/item-%06d", i), i)
	}
	time.Sleep(4 * DefaultDebounce) // give any (incorrect) republish time to land
	outRepublishes := outOnly.seq(t) - outBefore

	inMixed := buildRepublishStack(t, "system/content/")
	inBefore := inMixed.seq(t)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			inMixed.put(t, fmt.Sprintf("system/content/item-%06d", i), i)
		} else {
			inMixed.put(t, fmt.Sprintf("system/other/item-%06d", i), i)
		}
	}
	if _, ok := inMixed.awaitConvergence(t, 30*time.Second); !ok {
		t.Fatal("mixed-prefix stack did not converge")
	}
	inRepublishes := inMixed.seq(t) - inBefore

	t.Logf("prefix=system/content/  out-of-prefix-only: %d republishes for %d writes | half-in-prefix: %d republishes for %d writes",
		outRepublishes, n, inRepublishes, n)
	if outRepublishes != 0 {
		t.Errorf("writes entirely OUTSIDE the tracked prefix triggered %d republishes — the prefix is not bounding the tracker",
			outRepublishes)
	}
	if inRepublishes == 0 {
		t.Error("writes INSIDE the tracked prefix triggered no republish — the check is not measuring the publish path")
	}
}

// BenchmarkRepublishSignOnly isolates the mint+sign+bind cost of one
// Publish. It runs on an UNHOOKED stack deliberately: with the sync hooks
// wired, a publish's own bindings cascade back in and the re-entry guard
// coalesces some iterations into no-ops, so the reported ns/op would be an
// average over work that partly did not happen.
//
// This is the per-republish cost that write amplification multiplies, and
// the floor any debounce would trade against.
func BenchmarkRepublishSignOnly(b *testing.B) {
	cs := store.NewMemoryContentStore()
	li := store.NewMemoryLocationIndex()
	kp, err := crypto.Generate()
	if err != nil {
		b.Fatalf("generate keypair: %v", err)
	}
	identity, err := kp.IdentityEntity()
	if err != nil {
		b.Fatalf("identity entity: %v", err)
	}
	if _, err := cs.Put(identity); err != nil {
		b.Fatalf("put identity: %v", err)
	}
	tracker := tree.NewRootTracker(cs, string(kp.PeerID()), nil)
	pub := NewPublisher(cs, tracker, PrefixForLocalPeer, nil)
	if err := pub.SetupAuthority(store.NewNamespacedIndex(li, string(kp.PeerID())), kp, identity, false); err != nil {
		b.Fatalf("setup authority: %v", err)
	}
	root := fakeRoot(0x7A)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pub.Publish(root); err != nil {
			b.Fatalf("publish: %v", err)
		}
	}
}

// BenchmarkRepublishFullCascade measures the whole path a write takes:
// content put → LI set → tracker rebuild → publisher republish. The gap
// between this and SignOnly is the trie work, which is what grows with
// the published set.
func BenchmarkRepublishFullCascade(b *testing.B) {
	s := buildRepublishStack(b, PrefixForLocalPeer)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.put(b, fmt.Sprintf("system/bench/cascade-%06d", i), i)
	}
}
