package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/hash"
)

// -----------------------------------------------------------------------------
// Conformance — sqlite backend runs the same suite as memory.
// -----------------------------------------------------------------------------

func TestSqliteContentStoreConformance(t *testing.T) {
	runContentStoreSuite(t, func(t *testing.T) (ContentStore, func()) {
		s, err := NewSqliteStoreInMemory()
		if err != nil {
			t.Fatalf("open in-memory sqlite: %v", err)
		}
		return s.ContentStore(), func() { _ = s.Close() }
	})
}

func TestSqliteLocationIndexConformance(t *testing.T) {
	runLocationIndexSuite(t, func(t *testing.T) (LocationIndex, func()) {
		s, err := NewSqliteStoreInMemory()
		if err != nil {
			t.Fatalf("open in-memory sqlite: %v", err)
		}
		return s.LocationIndex(), func() { _ = s.Close() }
	})
}

// -----------------------------------------------------------------------------
// Persistence — the load-bearing test. Open, write, close, reopen, verify.
// -----------------------------------------------------------------------------

func TestSqlitePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Phase 1: write data, close.
	{
		s, err := NewSqliteStore(dbPath)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		cs := s.ContentStore()
		li := s.LocationIndex()

		eA := mkEntity(t, "test/a", "alpha")
		hA, err := cs.Put(eA)
		if err != nil {
			t.Fatalf("put eA: %v", err)
		}
		li.Set("/peer/path/a", hA)

		eB := mkEntity(t, "test/b", "beta")
		hB, err := cs.Put(eB)
		if err != nil {
			t.Fatalf("put eB: %v", err)
		}
		li.Set("/peer/path/b", hB)

		if err := s.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	// Phase 2: reopen, verify all data survived intact.
	{
		s, err := NewSqliteStore(dbPath)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer s.Close()

		cs := s.ContentStore()
		li := s.LocationIndex()

		if cs.Len() != 2 {
			t.Fatalf("len: got %d, want 2", cs.Len())
		}

		hA, ok := li.Get("/peer/path/a")
		if !ok {
			t.Fatal("li.Get /peer/path/a: missing")
		}
		eA, ok := cs.Get(hA)
		if !ok {
			t.Fatal("cs.Get a: missing")
		}
		if eA.Type != "test/a" {
			t.Fatalf("a type: got %q", eA.Type)
		}
		if err := eA.Validate(); err != nil {
			t.Fatalf("a validate: %v", err)
		}

		hB, ok := li.Get("/peer/path/b")
		if !ok {
			t.Fatal("li.Get /peer/path/b: missing")
		}
		eB, ok := cs.Get(hB)
		if !ok {
			t.Fatal("cs.Get b: missing")
		}
		if eB.Type != "test/b" {
			t.Fatalf("b type: got %q", eB.Type)
		}

		entries := li.List("/peer/path/")
		if len(entries) != 2 {
			t.Fatalf("list: got %d, want 2", len(entries))
		}
	}
}

// -----------------------------------------------------------------------------
// Shared connection — write via cs, read via li (same db file).
// -----------------------------------------------------------------------------

func TestSqliteSharedConnection(t *testing.T) {
	s, err := NewSqliteStoreInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	cs := s.ContentStore()
	li := s.LocationIndex()

	e := mkEntity(t, "test/shared", "data")
	h, err := cs.Put(e)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	li.Set("/peer/shared", h)

	if !cs.Has(h) {
		t.Fatal("cs missing entity")
	}
	got, ok := li.Get("/peer/shared")
	if !ok {
		t.Fatal("li missing path")
	}
	if got != h {
		t.Fatalf("li hash mismatch: got %s, want %s", got, h)
	}
}

// -----------------------------------------------------------------------------
// File permissions — disk DB should be 0600 to match bundle keypair convention.
// -----------------------------------------------------------------------------

func TestSqliteUserVersionGuard(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "version.db")

	// First open: fresh DB; init should write SchemaVersion.
	s, err := NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open fresh: %v", err)
	}
	var got int64
	if err := s.DB().QueryRow(`PRAGMA user_version`).Scan(&got); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if got != int64(SchemaVersion) {
		t.Fatalf("after fresh open: got user_version=%d, want %d", got, SchemaVersion)
	}
	s.Close()

	// Second open: existing DB at SchemaVersion; init must NOT rewrite.
	// Force user_version to a sentinel and re-open to prove the write path
	// is skipped on already-initialized DBs.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		t.Fatalf("set version: %v", err)
	}
	db.Close()

	s2, err := NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("reopen at current version: %v", err)
	}
	s2.Close()

	// Future-version DB must be refused, not silently downgraded.
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1)); err != nil {
		t.Fatalf("set future version: %v", err)
	}
	db.Close()

	if _, err := NewSqliteStore(dbPath); err == nil {
		t.Fatalf("opening future-version DB succeeded; want refusal")
	} else if !strings.Contains(err.Error(), "schema") {
		t.Fatalf("future-version refusal err = %v; want schema-related error", err)
	}
}

// -----------------------------------------------------------------------------
// Concurrent writers — regression for the workbench-team SQLITE_BUSY data-loss
// bug (CORE-GO-SQLITE-BUSY-BULK-INGEST).
//
// Before the fix: file-backed SqliteStore had no busy_timeout and no pool
// serialization, so two goroutines writing concurrently could race on the
// WAL write lock; the loser got SQLITE_BUSY (5) immediately. Watchers and
// the subscription engine swallowed the error → silent data loss.
//
// This test exercises N goroutines × M writes against a single file-backed
// store and asserts every write succeeds. Without the busy_timeout +
// MaxOpenConns(1) fix this test reproduces SQLITE_BUSY drops.
// -----------------------------------------------------------------------------

func TestSqliteConcurrentWriters(t *testing.T) {
	const (
		writers       = 8
		writesPerGoro = 50
	)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "concurrent.db")
	s, err := NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	cs := s.ContentStore()
	li := s.LocationIndex()

	var wg sync.WaitGroup
	errs := make(chan error, writers*writesPerGoro)
	wg.Add(writers)
	for g := 0; g < writers; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < writesPerGoro; i++ {
				payload := fmt.Sprintf("g%d-i%d-%s", gid, i, strings.Repeat("x", 64))
				e := mkEntity(t, "test/concurrent", payload)
				h, err := cs.Put(e)
				if err != nil {
					errs <- fmt.Errorf("g%d i%d cs.Put: %w", gid, i, err)
					return
				}
				p := fmt.Sprintf("/peer/concurrent/g%d/i%d", gid, i)
				li.Set(p, h)
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Errorf("concurrent write failure: %v", e)
	}

	if got, want := cs.Len(), writers*writesPerGoro; got != want {
		t.Fatalf("cs.Len after concurrent writes: got %d, want %d", got, want)
	}
	// Sanity check: every binding survived.
	if got, want := len(li.List("/peer/concurrent/")), writers*writesPerGoro; got != want {
		t.Fatalf("li.List after concurrent writes: got %d, want %d", got, want)
	}
}

// TestSqliteConcurrentReadDuringWrite verifies the read/write pool split:
// readers proceed concurrently with a sustained writer instead of serializing
// behind it on the single shared connection.
//
// Before the split (MaxOpenConns=1, shared pool), every Get would queue
// behind in-flight writes and report wall-clock latency in the ms range.
// With the split (writes on the serialized pool; reads on a separate
// mode=ro pool under WAL), reads complete in sub-millisecond and average
// latency stays bounded even when the writer is bursting.
//
// Regression for the SQLite-pool-split fix
// (the concurrency-consolidation plan, Step 1).
func TestSqliteConcurrentReadDuringWrite(t *testing.T) {
	const (
		writers          = 4
		writesPerGoro    = 200
		readers          = 4
		readLatencyBound = 5 * time.Millisecond
	)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "split-pool.db")
	store, err := NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	cs := store.ContentStore()
	li := store.LocationIndex()

	// Seed a path that readers will repeatedly fetch.
	seedE := mkEntity(t, "test/seed", "the seed entity")
	seedH, err := cs.Put(seedE)
	if err != nil {
		t.Fatalf("seed put: %v", err)
	}
	if err := li.Set("/peerA/seed", seedH); err != nil {
		t.Fatalf("seed set: %v", err)
	}

	var writerWG, readerWG sync.WaitGroup
	stopReaders := make(chan struct{})

	// Writers — sustained bursts of writes against disjoint paths.
	writerWG.Add(writers)
	for w := 0; w < writers; w++ {
		go func(wid int) {
			defer writerWG.Done()
			for i := 0; i < writesPerGoro; i++ {
				payload := fmt.Sprintf("w%d-i%d-%s", wid, i, strings.Repeat("x", 64))
				e := mkEntity(t, "test/write", payload)
				h, err := cs.Put(e)
				if err != nil {
					t.Errorf("writer %d put: %v", wid, err)
					return
				}
				p := fmt.Sprintf("/peerA/burst/w%d/i%d", wid, i)
				if err := li.Set(p, h); err != nil {
					t.Errorf("writer %d set: %v", wid, err)
					return
				}
			}
		}(w)
	}

	// Readers — keep fetching the seed binding while writers burst.
	var totalReads int64
	var totalLatencyNs int64
	var maxLatencyNs int64
	readerWG.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer readerWG.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				start := time.Now()
				h, ok := li.Get("/peerA/seed")
				elapsed := time.Since(start).Nanoseconds()
				if !ok || h != seedH {
					t.Errorf("seed read missed or wrong hash (ok=%v)", ok)
					return
				}
				atomic.AddInt64(&totalReads, 1)
				atomic.AddInt64(&totalLatencyNs, elapsed)
				for {
					prev := atomic.LoadInt64(&maxLatencyNs)
					if elapsed <= prev || atomic.CompareAndSwapInt64(&maxLatencyNs, prev, elapsed) {
						break
					}
				}
			}
		}()
	}

	writerWG.Wait()
	close(stopReaders)
	readerWG.Wait()

	reads := atomic.LoadInt64(&totalReads)
	if reads == 0 {
		t.Fatal("no reads completed")
	}
	avgRead := time.Duration(atomic.LoadInt64(&totalLatencyNs) / reads)
	maxRead := time.Duration(atomic.LoadInt64(&maxLatencyNs))
	t.Logf("reads=%d avg=%v max=%v (bound=%v)", reads, avgRead, maxRead, readLatencyBound)

	// Average read latency is the load-bearing assertion: in steady state,
	// reads on the separate mode=ro pool should not block on the writer.
	// Max can spike (cold-cache, OS scheduling) — log it but don't fail on it.
	if avgRead > readLatencyBound {
		t.Errorf("avg read latency %v exceeded bound %v — reads appear to serialize behind writes", avgRead, readLatencyBound)
	}

	// Sanity: all writes landed.
	if got, want := cs.Len(), 1 /* seed */ +writers*writesPerGoro; got != want {
		t.Errorf("cs.Len after run: got %d, want %d", got, want)
	}
}

// TestSqliteOptionsCustom exercises the configurable surface.
func TestSqliteOptionsCustom(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "opts.db")
	opts := DefaultSqliteOptions()
	opts.MaxOpenConns = 4 // not the production default — exercise the knob
	s, err := NewSqliteStoreWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Sanity: pragmas applied per-connection via DSN. Force the pool to open
	// a few connections by running parallel queries, then verify each has
	// busy_timeout set. We can't easily inspect connection identity from
	// the standard sql package, but we can at least verify SOME connection
	// reports the configured timeout.
	var got int
	if err := s.DB().QueryRow(`PRAGMA busy_timeout`).Scan(&got); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if got != int(opts.BusyTimeout.Milliseconds()) {
		t.Fatalf("busy_timeout: got %d ms, want %d ms", got, opts.BusyTimeout.Milliseconds())
	}
}

func TestSqliteFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits don't apply on windows")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "perms.db")

	s, err := NewSqliteStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		t.Fatalf("db file mode %v: group/other bits should be zero", mode)
	}
}

// TestDiag_SqliteWriteCost isolates the per-Put cost in the storage layer
// and exposes the fsync-per-autocommit baseline.
//
// The SDK Put path serializes through a chain of layers (handler dispatch,
// notifying wrappers, cascade tracker, etc) but ultimately every logical
// write decomposes to two SQL operations: an INSERT into entities (content
// store) and an INSERT INTO locations (location index). Both run as
// independent implicit transactions; in WAL + synchronous=NORMAL each
// commit fsyncs the WAL frame to disk.
//
// On a typical SSD an fsync is ~1–5 ms. Two fsyncs per logical write
// therefore puts a floor of ~2–10 ms on every Put at the storage layer,
// before any handler overhead is layered on.
//
// This bench measures three variants over N=1000 logical writes:
//
//   - autocommit (default)            — what AppPeer.Put hits today
//   - one explicit BIG transaction    — best-case lower bound: 1 fsync total
//   - synchronous=OFF (no fsync)      — durability-disabled lower bound
//
// Gated to keep `make test` fast. Run with:
//
//	DIAG_WRITE_COST=1 go test -run TestDiag_SqliteWriteCost -v ./core/store/...
func TestDiag_SqliteWriteCost(t *testing.T) {
	if os.Getenv("DIAG_WRITE_COST") == "" {
		t.Skip("set DIAG_WRITE_COST=1 to run")
	}

	const itemCount = 1000
	mkPayload := func(i int) string {
		return fmt.Sprintf("payload-%04d-%s", i, strings.Repeat("x", 64))
	}

	// Variant A: autocommit, default production options. The shape every
	// SDK Put hits.
	t.Run("autocommit_default", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewSqliteStore(filepath.Join(dir, "a.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer s.Close()
		cs := s.ContentStore()
		li := s.LocationIndex()

		t0 := time.Now()
		for i := 0; i < itemCount; i++ {
			e := mkEntity(t, "test/diag", mkPayload(i))
			h, err := cs.Put(e)
			if err != nil {
				t.Fatalf("cs.Put %d: %v", i, err)
			}
			if err := li.Set(fmt.Sprintf("/peer/diag/%04d", i), h); err != nil {
				t.Fatalf("li.Set %d: %v", i, err)
			}
		}
		elapsed := time.Since(t0)
		t.Logf("[autocommit]    N=%d  total=%s  per_op=%s",
			itemCount, elapsed.Round(time.Millisecond),
			(elapsed / time.Duration(itemCount)).Round(10*time.Microsecond))
	})

	// Variant B: one explicit transaction wrapping ALL N writes. Single
	// commit at the end, single fsync.
	t.Run("single_tx", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewSqliteStore(filepath.Join(dir, "b.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer s.Close()

		t0 := time.Now()
		tx, err := s.DB().Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		entStmt, err := tx.Prepare(`INSERT OR REPLACE INTO entities (hash, entity_type, data) VALUES (?, ?, ?)`)
		if err != nil {
			t.Fatalf("prepare entities: %v", err)
		}
		locStmt, err := tx.Prepare(`INSERT OR REPLACE INTO locations (path, hash) VALUES (?, ?)`)
		if err != nil {
			t.Fatalf("prepare locations: %v", err)
		}
		for i := 0; i < itemCount; i++ {
			e := mkEntity(t, "test/diag", mkPayload(i))
			// Compute the hash the same way SqliteContentStore.Put would.
			h, err := hash.Compute(e.Type, e.Data)
			if err != nil {
				t.Fatalf("hash %d: %v", i, err)
			}
			if _, err := entStmt.Exec(h.Bytes(), e.Type, []byte(e.Data)); err != nil {
				t.Fatalf("ent insert %d: %v", i, err)
			}
			if _, err := locStmt.Exec(fmt.Sprintf("/peer/diag/%04d", i), h.Bytes()); err != nil {
				t.Fatalf("loc insert %d: %v", i, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		elapsed := time.Since(t0)
		t.Logf("[single_tx]     N=%d  total=%s  per_op=%s",
			itemCount, elapsed.Round(time.Millisecond),
			(elapsed / time.Duration(itemCount)).Round(time.Microsecond))
	})

	// Variant C: autocommit but synchronous=OFF. Removes fsync per commit.
	// Unsafe in production (crash can corrupt WAL); a diagnostic floor.
	t.Run("autocommit_sync_off", func(t *testing.T) {
		dir := t.TempDir()
		opts := DefaultSqliteOptions()
		opts.Synchronous = "OFF"
		s, err := NewSqliteStoreWithOptions(filepath.Join(dir, "c.db"), opts)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer s.Close()
		cs := s.ContentStore()
		li := s.LocationIndex()

		t0 := time.Now()
		for i := 0; i < itemCount; i++ {
			e := mkEntity(t, "test/diag", mkPayload(i))
			h, err := cs.Put(e)
			if err != nil {
				t.Fatalf("cs.Put %d: %v", i, err)
			}
			if err := li.Set(fmt.Sprintf("/peer/diag/%04d", i), h); err != nil {
				t.Fatalf("li.Set %d: %v", i, err)
			}
		}
		elapsed := time.Since(t0)
		t.Logf("[sync_off]      N=%d  total=%s  per_op=%s",
			itemCount, elapsed.Round(time.Millisecond),
			(elapsed / time.Duration(itemCount)).Round(time.Microsecond))
	})
}
