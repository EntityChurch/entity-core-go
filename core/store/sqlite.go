package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the on-disk schema version this binary supports. Written
// to PRAGMA user_version on a fresh DB; checked (not overwritten) on an
// existing one. Bump when introducing a backwards-incompatible schema change
// and add a migration path at open time.
//
// Consumers performing pre-flight checks against a SQLite peer database
// should compare the on-disk PRAGMA user_version against this constant
// rather than hard-coding the literal — a binary that supports schema N
// must refuse to open a DB written by a future binary at schema N+1.
const SchemaVersion = 1

// schemaVersion retained as a package-internal alias for the historical
// lowercase name used inside this file.
const schemaVersion = SchemaVersion

// SqliteStore is a factory holding *sql.DB handles shared by
// SqliteContentStore and SqliteLocationIndex.
//
// Concurrency posture (file-backed, default settings):
//   - WAL journal mode for concurrent readers.
//   - busy_timeout 5s, applied per-connection via DSN — writers wait for the
//     WAL write lock instead of failing fast with SQLITE_BUSY.
//   - Split read/write pools. The write pool runs MaxOpenConns=1
//     (serializes writes; mirrors Rust's Arc<Mutex<Connection>>). The read
//     pool runs with mode=ro and MaxOpenConns=ReadPoolSize (default 8), so
//     concurrent reads don't wait behind writes. SQLite WAL allows readers
//     to proceed while a writer holds the WAL header lock, so this split
//     yields real read parallelism.
//
// In-memory stores (NewSqliteStoreInMemory) use a single pool — the
// `:memory:` database is per-connection, so the read and write handles
// must share one connection. The split is file-backed only.
//
// Schema is converged with entity-core-rust/core/store/src/sqlite.rs so a
// peer's persisted state is portable between impls' tooling.
type SqliteStore struct {
	writeDB  *sql.DB
	readDB   *sql.DB
	inMemory bool
}

// SqliteOptions tunes the SQLite store. Use DefaultSqliteOptions() and
// modify fields as needed.
type SqliteOptions struct {
	// BusyTimeout sets PRAGMA busy_timeout per-connection (file-backed only).
	// On lock contention, writers wait up to this long before SQLITE_BUSY.
	// Default: 5 seconds. Zero disables (returns to default-0 instant failure;
	// do not do this in production).
	BusyTimeout time.Duration

	// MaxOpenConns caps the database/sql connection pool. Default: 1
	// (serializes writes, prevents in-process WAL-lock contention). Set to a
	// larger value for read-heavy workloads — but only if you also split the
	// reader/writer pools or accept occasional busy_timeout waits.
	// A value <= 0 leaves sql.DB at its default (unlimited).
	MaxOpenConns int

	// JournalMode (file-backed only). Default: "WAL". Empty defaults to WAL.
	JournalMode string

	// Synchronous (file-backed only). Default: "NORMAL", appropriate for WAL.
	// Empty defaults to NORMAL.
	Synchronous string

	// CacheSizeKB (file-backed only). Sets PRAGMA cache_size to -CacheSizeKB
	// (negative means KB, not pages). Default: 65536 (64 MiB). Zero leaves
	// SQLite's default.
	CacheSizeKB int

	// ReadPoolSize caps the database/sql connection pool for the read-only
	// handle (file-backed only). Default: 8. Concurrent reads are limited
	// to this many in-flight queries; under WAL they don't block on writes.
	// A value <= 0 leaves sql.DB at its default (unlimited).
	ReadPoolSize int
}

// DefaultSqliteOptions returns the recommended production defaults.
func DefaultSqliteOptions() SqliteOptions {
	return SqliteOptions{
		BusyTimeout:  5 * time.Second,
		MaxOpenConns: 1,
		JournalMode:  "WAL",
		Synchronous:  "NORMAL",
		CacheSizeKB:  65536,
		ReadPoolSize: 8,
	}
}

// NewSqliteStore opens (or creates) a SQLite database at path with the
// production-default options. Sets file permissions to 0600 to match the
// bundle keypair convention.
func NewSqliteStore(path string) (*SqliteStore, error) {
	return NewSqliteStoreWithOptions(path, DefaultSqliteOptions())
}

// NewSqliteStoreWithOptions opens a file-backed SQLite store with custom
// tuning. See SqliteOptions for the available knobs.
//
// The store maintains two connection pools: a serialized write pool
// (MaxOpenConns) and a read-only pool (ReadPoolSize) that allows concurrent
// reads to proceed independently of writes. SQLite WAL mode makes this safe.
func NewSqliteStoreWithOptions(path string, opts SqliteOptions) (*SqliteStore, error) {
	writeDSN := buildSqliteDSN(path, opts, false)
	writeDB, err := sql.Open("sqlite", writeDSN)
	if err != nil {
		return nil, fmt.Errorf("sqlite open (write): %w", err)
	}
	if opts.MaxOpenConns > 0 {
		writeDB.SetMaxOpenConns(opts.MaxOpenConns)
		// Keep at least one connection warm so we don't pay reconnection cost
		// on every write under the serialized pool.
		writeDB.SetMaxIdleConns(opts.MaxOpenConns)
	}
	s := &SqliteStore{writeDB: writeDB}
	if err := s.init(opts); err != nil {
		_ = writeDB.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		// Non-fatal — :memory: variants and platforms without chmod still work.
		// The DB itself is initialized; permissions tightening is best-effort.
		_ = err
	}

	// Open the read pool only after schema init has created the file.
	// mode=ro requires the file to exist; opening earlier would race.
	readDSN := buildSqliteReadDSN(path, opts)
	readDB, err := sql.Open("sqlite", readDSN)
	if err != nil {
		_ = writeDB.Close()
		return nil, fmt.Errorf("sqlite open (read): %w", err)
	}
	if opts.ReadPoolSize > 0 {
		readDB.SetMaxOpenConns(opts.ReadPoolSize)
		readDB.SetMaxIdleConns(opts.ReadPoolSize)
	}
	s.readDB = readDB
	return s, nil
}

// NewSqliteStoreInMemory opens an in-memory SQLite database. Useful for tests
// and ephemeral peers. Pinned to a single open connection so all callers see
// the same in-memory database (default sql.DB pooling would create new
// per-connection in-memory databases).
//
// In-memory stores cannot use the read/write pool split — `:memory:` is
// connection-local, so reads and writes share one *sql.DB. This is a
// development/test path; bursty production workloads should use a
// file-backed store.
func NewSqliteStoreInMemory() (*SqliteStore, error) {
	// In-memory has no lock contention with other processes, but we still
	// pin BusyTimeout > 0 in case callers stuff us into a sync.Pool-shaped
	// pattern. cache_size / WAL pragmas don't apply.
	opts := SqliteOptions{
		BusyTimeout:  5 * time.Second,
		MaxOpenConns: 1,
	}
	dsn := buildSqliteDSN(":memory:", opts, true)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open in-memory: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	// Read pool aliases the write handle for in-memory.
	s := &SqliteStore{writeDB: db, readDB: db, inMemory: true}
	if err := s.init(opts); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// buildSqliteDSN builds a modernc.org/sqlite DSN with per-connection pragmas
// baked in. Per-connection because PRAGMA busy_timeout (and synchronous) are
// connection-local — applying them once via db.Exec only affects whichever
// connection happened to handle the call; subsequent pool connections would
// silently default to 0. The driver's ?_pragma= mechanism applies pragmas at
// connection-open time, so every connection in the pool is configured.
//
// See modernc.org/sqlite@v1.50.0/sqlite.go applyQueryParams for the parsing
// path; busy_timeout is sorted to apply first so subsequent statements (which
// may themselves contend) inherit the timeout.
func buildSqliteDSN(path string, opts SqliteOptions, inMemory bool) string {
	params := url.Values{}
	if opts.BusyTimeout > 0 {
		ms := opts.BusyTimeout.Milliseconds()
		params.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", ms))
	}
	if !inMemory {
		journal := opts.JournalMode
		if journal == "" {
			journal = "WAL"
		}
		sync := opts.Synchronous
		if sync == "" {
			sync = "NORMAL"
		}
		params.Add("_pragma", fmt.Sprintf("journal_mode(%s)", journal))
		params.Add("_pragma", fmt.Sprintf("synchronous(%s)", sync))
		params.Add("_pragma", "foreign_keys(1)")
		params.Add("_pragma", "temp_store(memory)")
		if opts.CacheSizeKB > 0 {
			// Negative cache_size argument is in KB rather than pages.
			params.Add("_pragma", fmt.Sprintf("cache_size(-%d)", opts.CacheSizeKB))
		}
	}
	q := params.Encode()
	// modernc.org/sqlite accepts the path verbatim or with a "file:" prefix.
	// We add "file:" only when we need to attach query params, and we keep
	// :memory: as-is since "file::memory:" has different semantics (named
	// shared cache rather than anonymous in-memory).
	switch {
	case inMemory:
		if q == "" {
			return ":memory:"
		}
		return ":memory:?" + q
	case strings.HasPrefix(path, "file:"):
		// Caller already supplied a URI form — append our params.
		if q == "" {
			return path
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + q
	default:
		if q == "" {
			return path
		}
		return "file:" + path + "?" + q
	}
}

// buildSqliteReadDSN builds the DSN for the read-only pool. The writer pool
// owns journal_mode/synchronous/foreign_keys — setting those on a readonly
// connection is either a no-op or an error depending on driver version, so
// we omit them. busy_timeout still applies (a reader can transiently contend
// on the WAL header during a writer's commit). temp_store and cache_size
// affect query execution and are kept.
func buildSqliteReadDSN(path string, opts SqliteOptions) string {
	params := url.Values{}
	if opts.BusyTimeout > 0 {
		ms := opts.BusyTimeout.Milliseconds()
		params.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", ms))
	}
	params.Add("_pragma", "temp_store(memory)")
	if opts.CacheSizeKB > 0 {
		params.Add("_pragma", fmt.Sprintf("cache_size(-%d)", opts.CacheSizeKB))
	}
	params.Set("mode", "ro")
	q := params.Encode()
	if strings.HasPrefix(path, "file:") {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + q
	}
	return "file:" + path + "?" + q
}

func (s *SqliteStore) init(opts SqliteOptions) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS entities (
			hash        BLOB PRIMARY KEY,
			entity_type TEXT NOT NULL,
			data        BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS locations (
			path TEXT PRIMARY KEY,
			hash BLOB NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.writeDB.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite init (%q): %w", stmt, err)
		}
	}

	// PRAGMA user_version is the schema-version contract with future binaries.
	// Read first; only write if the DB is fresh (0). A future binary at
	// schema > SchemaVersion means we can't safely open it. A past binary at
	// schema < SchemaVersion means we have no migration path yet.
	var existing int64
	if err := s.writeDB.QueryRow(`PRAGMA user_version`).Scan(&existing); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	switch {
	case existing == 0:
		if _, err := s.writeDB.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
			return fmt.Errorf("set user_version: %w", err)
		}
	case existing > schemaVersion:
		return fmt.Errorf("sqlite store schema is %d; this binary supports up to %d (refusing to downgrade)", existing, schemaVersion)
	case existing < schemaVersion:
		// Pre-migration era. When migrations land, this is where they run.
		return fmt.Errorf("sqlite store schema is %d; this binary expects %d (migrations not yet implemented)", existing, schemaVersion)
	}
	return nil
}

// ContentStore returns a ContentStore backed by this database.
func (s *SqliteStore) ContentStore() *SqliteContentStore {
	return &SqliteContentStore{writeDB: s.writeDB, readDB: s.readDB}
}

// LocationIndex returns a LocationIndex backed by this database.
func (s *SqliteStore) LocationIndex() *SqliteLocationIndex {
	return &SqliteLocationIndex{writeDB: s.writeDB, readDB: s.readDB}
}

// DB returns the write *sql.DB so co-located extensions can create their
// own tables in the same database. Callers MUST NOT call Close on the
// returned handle — lifecycle is owned by SqliteStore. Extensions doing
// read-heavy work should consider ReadDB() instead.
func (s *SqliteStore) DB() *sql.DB {
	return s.writeDB
}

// ReadDB returns the read-only *sql.DB pool. For file-backed stores this
// is a separate handle from DB() with mode=ro and a larger MaxOpenConns,
// so concurrent reads don't serialize behind writes. For in-memory stores
// this returns the same handle as DB() (`:memory:` is per-connection and
// can't be split). Callers MUST NOT call Close on the returned handle.
func (s *SqliteStore) ReadDB() *sql.DB {
	return s.readDB
}

// Close releases the database. Safe to call multiple times.
func (s *SqliteStore) Close() error {
	if s.writeDB == nil {
		return nil
	}
	// For in-memory, writeDB == readDB; close once.
	var firstErr error
	if s.readDB != nil && s.readDB != s.writeDB {
		if err := s.readDB.Close(); err != nil {
			firstErr = err
		}
	}
	if err := s.writeDB.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	s.writeDB = nil
	s.readDB = nil
	return firstErr
}

// -----------------------------------------------------------------------------
// SqliteContentStore
// -----------------------------------------------------------------------------

// SqliteContentStore is a ContentStore backed by SQLite. Reads route to
// the read-only pool; writes route to the serialized write pool.
type SqliteContentStore struct {
	writeDB *sql.DB
	readDB  *sql.DB
}

// Put stores an entity. The content hash is recomputed from {type, data};
// any mismatch with a non-zero claimed ContentHash returns an error. This
// matches MemoryContentStore semantics per V7 §1.8.
func (s *SqliteContentStore) Put(e entity.Entity) (hash.Hash, error) {
	// Recompute under the claimed Algorithm so SHA-384 entities verify
	// against SHA-384 (v7.67 §2.3 format-code interpretation). A zero
	// ContentHash has Algorithm=0x00 (SHA-256) — the v7.66 default.
	computed, err := hash.ComputeFormat(e.ContentHash.Algorithm, e.Type, e.Data)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("content store put: compute hash: %w", err)
	}
	if !e.ContentHash.IsZero() && e.ContentHash != computed {
		return hash.Hash{}, fmt.Errorf("content store put: hash mismatch: claimed %s, computed %s", e.ContentHash, computed)
	}
	if _, err := s.writeDB.Exec(
		`INSERT OR REPLACE INTO entities (hash, entity_type, data) VALUES (?, ?, ?)`,
		computed.Bytes(), e.Type, []byte(e.Data),
	); err != nil {
		return hash.Hash{}, fmt.Errorf("content store put: %w", err)
	}
	return computed, nil
}

// Get returns the entity at the given hash, or (zero, false).
func (s *SqliteContentStore) Get(h hash.Hash) (entity.Entity, bool) {
	var typ string
	var data []byte
	err := s.readDB.QueryRow(
		`SELECT entity_type, data FROM entities WHERE hash = ?`,
		h.Bytes(),
	).Scan(&typ, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.Entity{}, false
	}
	if err != nil {
		return entity.Entity{}, false
	}
	return entity.Entity{Type: typ, Data: data, ContentHash: h}, true
}

// Has returns true if the store contains the given hash.
func (s *SqliteContentStore) Has(h hash.Hash) bool {
	var one int
	err := s.readDB.QueryRow(
		`SELECT 1 FROM entities WHERE hash = ? LIMIT 1`,
		h.Bytes(),
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return err == nil
}

// Remove deletes the entity at the given hash. Returns true if a row was deleted.
func (s *SqliteContentStore) Remove(h hash.Hash) bool {
	res, err := s.writeDB.Exec(`DELETE FROM entities WHERE hash = ?`, h.Bytes())
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false
	}
	return n > 0
}

// Len returns the number of entities stored.
func (s *SqliteContentStore) Len() int {
	var n int
	if err := s.readDB.QueryRow(`SELECT COUNT(*) FROM entities`).Scan(&n); err != nil {
		return 0
	}
	return n
}

// -----------------------------------------------------------------------------
// SqliteLocationIndex
// -----------------------------------------------------------------------------

// SqliteLocationIndex is a LocationIndex backed by SQLite. Reads route to
// the read-only pool; writes (including CAS-related lookups on the failure
// path) route to the serialized write pool.
type SqliteLocationIndex struct {
	writeDB *sql.DB
	readDB  *sql.DB
}

// Set binds path to h. Idempotent at the SQL level (INSERT OR REPLACE).
// Returns the underlying SQL error on failure (disk full, SQLITE_BUSY beyond
// the configured busy_timeout, corruption, etc). Callers MUST propagate.
func (i *SqliteLocationIndex) Set(path string, h hash.Hash) error {
	if _, err := i.writeDB.Exec(
		`INSERT OR REPLACE INTO locations (path, hash) VALUES (?, ?)`,
		path, h.Bytes(),
	); err != nil {
		return fmt.Errorf("sqlite location set %q: %w", path, err)
	}
	return nil
}

// Get returns the hash bound to path, or (zero, false).
func (i *SqliteLocationIndex) Get(path string) (hash.Hash, bool) {
	return getOn(i.readDB, path)
}

// getOn is the shared Get implementation, parameterized on the pool. Used
// internally by Remove and CAS-failure paths against the write pool so the
// follow-up lookup reflects the committed result of the just-attempted
// write, not a (possibly older) snapshot from the read pool.
func getOn(db *sql.DB, path string) (hash.Hash, bool) {
	var b []byte
	err := db.QueryRow(`SELECT hash FROM locations WHERE path = ?`, path).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return hash.Hash{}, false
	}
	if err != nil {
		return hash.Hash{}, false
	}
	h, err := hash.FromBytes(b)
	if err != nil {
		return hash.Hash{}, false
	}
	return h, true
}

// LenPrefix returns the count of bindings under prefix via SQL COUNT.
// Range-scanned on the path PRIMARY KEY, not a table scan. Empty prefix
// counts every binding in the table.
//
// The prefix range bound mirrors List exactly: nextPrefixBound for the
// half-open upper bound, with the all-0xFF case scanning prefix→end (a
// `path < ""` upper bound would match nothing — the divergence this
// shares-the-helper-with-List change removes).
func (i *SqliteLocationIndex) LenPrefix(prefix string) int {
	var n int
	var err error
	switch {
	case prefix == "":
		err = i.readDB.QueryRow(`SELECT COUNT(*) FROM locations`).Scan(&n)
	default:
		if upper := nextPrefixBound(prefix); upper == "" {
			// Prefix was all 0xFF — count from prefix to end of table.
			err = i.readDB.QueryRow(
				`SELECT COUNT(*) FROM locations WHERE path >= ?`,
				prefix,
			).Scan(&n)
		} else {
			err = i.readDB.QueryRow(
				`SELECT COUNT(*) FROM locations WHERE path >= ? AND path < ?`,
				prefix, upper,
			).Scan(&n)
		}
	}
	if err != nil {
		return 0
	}
	return n
}

// Has returns true if path is bound.
func (i *SqliteLocationIndex) Has(path string) bool {
	var one int
	err := i.readDB.QueryRow(`SELECT 1 FROM locations WHERE path = ? LIMIT 1`, path).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return err == nil
}

// Remove unbinds path. Returns the prior hash and whether a row was removed.
func (i *SqliteLocationIndex) Remove(path string) (hash.Hash, bool) {
	// The prior-hash lookup goes through the write pool so a write that just
	// landed via this connection is visible to the follow-up read.
	prior, ok := getOn(i.writeDB, path)
	if !ok {
		return hash.Hash{}, false
	}
	res, err := i.writeDB.Exec(`DELETE FROM locations WHERE path = ?`, path)
	if err != nil {
		return hash.Hash{}, false
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return hash.Hash{}, false
	}
	return prior, true
}

// CompareAndSwap atomically updates the binding at path from expected to new.
// Returns *CasError on mismatch (Actual populated) or absence (NotFound).
//
// Atomicity is provided by SQL: a conditional UPDATE either matches one row
// (success) or zero rows (mismatch). On mismatch we re-read to populate the
// actual hash, but the failure outcome was already decided atomically.
func (i *SqliteLocationIndex) CompareAndSwap(path string, expected, new hash.Hash) error {
	res, err := i.writeDB.Exec(
		`UPDATE locations SET hash = ? WHERE path = ? AND hash = ?`,
		new.Bytes(), path, expected.Bytes(),
	)
	if err != nil {
		return fmt.Errorf("sqlite cas swap: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite cas swap: %w", err)
	}
	if n == 1 {
		return nil
	}
	// Mismatch or absent — distinguish via lookup on the write pool to see
	// the committed state at the moment the UPDATE ran.
	current, ok := getOn(i.writeDB, path)
	if !ok {
		return &CasError{NotFound: true}
	}
	return &CasError{Actual: current}
}

// CompareAndRemove atomically deletes the binding at path if it equals expected.
func (i *SqliteLocationIndex) CompareAndRemove(path string, expected hash.Hash) error {
	res, err := i.writeDB.Exec(
		`DELETE FROM locations WHERE path = ? AND hash = ?`,
		path, expected.Bytes(),
	)
	if err != nil {
		return fmt.Errorf("sqlite cas remove: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite cas remove: %w", err)
	}
	if n == 1 {
		return nil
	}
	current, ok := getOn(i.writeDB, path)
	if !ok {
		return &CasError{NotFound: true}
	}
	return &CasError{Actual: current}
}

// List returns all path→hash bindings whose path begins with prefix, ordered
// by path. Empty prefix returns everything.
//
// Range scan: compute exclusive upper bound by incrementing the last byte of
// the prefix. If the prefix is all 0xFF bytes (no upper bound representable),
// scan to the end of the table.
func (i *SqliteLocationIndex) List(prefix string) []LocationEntry {
	var rows *sql.Rows
	var err error

	if prefix == "" {
		rows, err = i.readDB.Query(`SELECT path, hash FROM locations ORDER BY path`)
	} else {
		upper := nextPrefixBound(prefix)
		if upper == "" {
			// Prefix was all 0xFF — scan from prefix to end.
			rows, err = i.readDB.Query(
				`SELECT path, hash FROM locations WHERE path >= ? ORDER BY path`,
				prefix,
			)
		} else {
			rows, err = i.readDB.Query(
				`SELECT path, hash FROM locations WHERE path >= ? AND path < ? ORDER BY path`,
				prefix, upper,
			)
		}
	}
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []LocationEntry
	for rows.Next() {
		var path string
		var b []byte
		if err := rows.Scan(&path, &b); err != nil {
			continue
		}
		h, err := hash.FromBytes(b)
		if err != nil {
			continue
		}
		entries = append(entries, LocationEntry{Path: path, Hash: h})
	}
	return entries
}

// nextPrefixBound returns the lexicographically smallest string strictly
// greater than every string starting with prefix, computed by incrementing
// the last byte. Returns "" if no such bound exists (prefix is all 0xFF).
//
// Mirrors the Rust impl in entity-core-rust/core/store/src/sqlite.rs:319-330.
func nextPrefixBound(prefix string) string {
	b := []byte(prefix)
	for len(b) > 0 {
		last := len(b) - 1
		if b[last] < 0xFF {
			b[last]++
			return string(b)
		}
		b = b[:last]
	}
	return ""
}

// Compile-time interface checks.
var (
	_ ContentStore  = (*SqliteContentStore)(nil)
	_ LocationIndex = (*SqliteLocationIndex)(nil)
)
