package store

import (
	"fmt"
	"path"
	"strings"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// QualifyPath builds an absolute path from a namespace (peer ID) and a bare path.
func QualifyPath(ns, path string) string {
	return "/" + ns + "/" + path
}

// SplitNamespace splits an absolute path into namespace (peer ID) and bare path.
// Returns ("", path) if the path is not absolute (no leading "/").
func SplitNamespace(path string) (ns, barePath string) {
	if !strings.HasPrefix(path, "/") {
		return "", path
	}
	rest := path[1:] // strip leading /
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		return rest, "" // just "/{peerID}" with no subpath
	}
	return rest[:idx], rest[idx+1:]
}

// Base58 alphabet used by PeerID encoding (no 0, O, I, l).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// looksLikePeerID returns true if s is a valid Base58-encoded PeerID.
// Minimum 46 characters (current algorithm floor); future algorithms only add bytes.
func looksLikePeerID(s string) bool {
	if len(s) < 46 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune(base58Alphabet, r) {
			return false
		}
	}
	return true
}

// IsAbsolute returns true if path is an absolute path (starts with "/").
func IsAbsolute(path string) bool {
	return strings.HasPrefix(path, "/")
}

// Universal-path {X}-slot reserved words per EXTENSION-NETWORK §6.4 (D-12).
// These are HTTP-poll URL-routing conventions — at the URL layer the `{X}`
// segment in `{tree_url_prefix}/{X}/{rest}` is valid iff it is a peer-ID
// OR one of these reserved words (URL routes via content-store / manifest
// operations on a passive store, not via tree-path resolution).
//
// Crucially, ValidateAbsolutePath continues to REJECT these strings —
// `content`/`manifest` are short lowercase ASCII, never valid Base58 peer-
// IDs, and the §6.4 collision-safety argument depends on the peer-ID-first
// check rejecting them. They are URL-layer conventions, not tree paths.
const (
	URLPathReservedContent  = "content"
	URLPathReservedManifest = "manifest"
)

// IsURLPathXReservedWord reports whether s is a reserved word in the
// http-poll URL `{X}` slot (NETWORK §6.4). Returns true for "content" or
// "manifest". Used by URL construction/parsing sites to distinguish a
// reserved-word redirect from a peer-ID-keyed tree path.
func IsURLPathXReservedWord(s string) bool {
	return s == URLPathReservedContent || s == URLPathReservedManifest
}

// ValidateURLPathXSegment reports whether s is a valid value for the
// `{X}` position of an http-poll URL per NETWORK §6.4: a peer-ID OR
// one of the reserved words `content`/`manifest`. Returns nil on success.
//
// This is the URL-layer validator. Tree-path validation (ValidateAbsolutePath)
// is intentionally stricter — peer-IDs only — and that strictness is what
// makes the reserved words collision-safe.
func ValidateURLPathXSegment(s string) error {
	if s == "" {
		return fmt.Errorf("invalid {X} segment: empty")
	}
	if IsURLPathXReservedWord(s) {
		return nil
	}
	if looksLikePeerID(s) {
		return nil
	}
	return fmt.Errorf("invalid {X} segment %q: not a peer-ID and not a reserved word (content|manifest)", s)
}

// ValidateAbsolutePath checks that path is a well-formed absolute path:
// starts with "/", first segment is a valid peer ID, no empty segments,
// no reserved prefixes, no control characters in any segment (V7 §1.4
// path validation; v7.72 §9.5a CORE-TREE-PATH-FLEX-1). Returns nil on
// success, descriptive error on failure.
func ValidateAbsolutePath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("not absolute: path does not start with /")
	}
	if err := ValidatePathChars(p); err != nil {
		return err
	}
	rest := p[1:]
	if rest == "" {
		return fmt.Errorf("not absolute: empty path after /")
	}
	// Check for empty segments (consecutive slashes).
	if strings.Contains(rest, "//") {
		return fmt.Errorf("invalid path: contains empty segments (consecutive //)")
	}
	idx := strings.IndexByte(rest, '/')
	var firstSeg string
	if idx < 0 {
		firstSeg = rest
	} else {
		firstSeg = rest[:idx]
	}
	if !looksLikePeerID(firstSeg) {
		return fmt.Errorf("not absolute: first segment %q is not a valid peer ID", firstSeg)
	}
	return nil
}

// ValidatePathChars rejects paths that contain ASCII control characters
// (incl. NUL) in any segment, per V7 §1.4 + v7.72 §9.5a CORE-TREE-PATH-
// FLEX-1. Callable on any path form (absolute, peer-relative, raw). Used
// by handlers at the entry boundary to reject malformed caller paths
// before the caller's bytes touch the store or location index.
func ValidatePathChars(p string) error {
	for i := 0; i < len(p); i++ {
		c := p[i]
		// Reject NUL and the C0 control range (0x00-0x1F) plus DEL (0x7F).
		// Slashes and printable ASCII (incl. high-bit Unicode bytes) are
		// fine — Unicode segments are accepted per §1.4.
		if c < 0x20 || c == 0x7F {
			return fmt.Errorf("invalid path: control character 0x%02X at byte offset %d (V7 §1.4: paths MUST NOT contain control characters)", c, i)
		}
	}
	return nil
}

// CleanPath normalizes a path by collapsing redundant slashes, preserving a
// leading "/" (absolute marker), and stripping trailing "/". Paths starting
// with "./" or "../" are rejected (reserved for future directory-relative
// semantics). Handles entity:// URIs by cleaning only the path portion.
func CleanPath(input string) string {
	if input == "" {
		return input
	}
	// Handle entity:// scheme: clean the path portion only.
	if strings.HasPrefix(input, entity.Scheme) {
		cleaned := CleanPath(input[len(entity.Scheme):])
		// Strip leading / from cleaned path to avoid entity:///
		return entity.Scheme + strings.TrimPrefix(cleaned, "/")
	}
	// Reject reserved prefixes (per R1).
	if strings.HasPrefix(input, "./") || strings.HasPrefix(input, "../") {
		return input // pass through unchanged; callers should validate
	}
	// path.Clean collapses //, removes trailing /, preserves leading /.
	// It also resolves . and .. — but we've already rejected leading ./ and ../
	// above. Interior . segments are valid path components (.gitignore, .env).
	cleaned := path.Clean(input)
	return cleaned
}

// LocationEntry is a path→hash binding in the location index.
type LocationEntry struct {
	Path string
	Hash hash.Hash
}

// ContentStore is an immutable content-addressed store: Hash → Entity.
type ContentStore interface {
	Put(e entity.Entity) (hash.Hash, error)
	Get(h hash.Hash) (entity.Entity, bool)
	Has(h hash.Hash) bool
	Remove(h hash.Hash) bool
	Len() int
}

// LocationIndex is a mutable location index: path → Hash.
//
// Set returns an error on storage failure (disk full, SQLITE_BUSY beyond the
// configured timeout, corruption, etc). Callers MUST NOT discard this error —
// V7 §2688 requires storage-write failures to short-circuit envelope processing
// and surface to the protocol layer rather than silently proceeding with
// partial state. In-memory impls (MemoryLocationIndex) always return nil.
//
// CompareAndSwap and CompareAndRemove are atomic conditional mutations: they
// succeed only if the current binding at path equals expected. On mismatch
// they return *CasError carrying the actual binding (or NotFound when no
// binding exists). Atomicity is provided by the implementation — callers
// can rely on no torn read-modify-write window across goroutines.
type LocationIndex interface {
	Set(path string, h hash.Hash) error
	Get(path string) (hash.Hash, bool)
	Has(path string) bool
	Remove(path string) (hash.Hash, bool)
	List(prefix string) []LocationEntry
	// LenPrefix returns the count of bindings under prefix. Empty
	// prefix counts every binding in the index.
	//
	// Contract: implementations MUST NOT materialize entries to
	// compute the count — the result must be a count, not the length
	// of a list. SQL backends use indexed COUNT(*) range queries
	// (O(log N + matches)). Memory backends may walk the map (O(N))
	// since N is bounded by per-process usage; this is acceptable but
	// SHOULD use a maintained counter for the empty-prefix common
	// case if it becomes a hot path. UI status displays call
	// LenPrefix on every refresh tick.
	LenPrefix(prefix string) int
	CompareAndSwap(path string, expected, new hash.Hash) error
	CompareAndRemove(path string, expected hash.Hash) error
}

// CasError carries the failure shape of CompareAndSwap / CompareAndRemove.
// NotFound is true when no binding exists at the path. Otherwise Actual
// holds the current binding that didn't match expected.
type CasError struct {
	NotFound bool
	Actual   hash.Hash
}

func (e *CasError) Error() string {
	if e.NotFound {
		return "cas: path not bound"
	}
	return "cas: hash mismatch (actual " + e.Actual.String() + ")"
}

// ContextualWriter is an optional interface implemented by LocationIndex
// wrappers that can propagate execution context through tree change events.
// Implementations include NotifyingLocationIndex and NamespacedIndex.
// Callers should type-assert to ContextualWriter when they have execution
// context to pass through (e.g., tree handler with HandlerContext).
//
// SetWithContext returns a *CascadeResult describing the sync-phase cascade
// outcome (nil when no hooks are registered) and an error on storage failure.
// A non-nil error means the binding did NOT commit; callers MUST propagate.
// RemoveWithContext adds the cascade result as a third return value.
type ContextualWriter interface {
	SetWithContext(path string, h hash.Hash, ctx *MutationContext) (*CascadeResult, error)
	RemoveWithContext(path string, ctx *MutationContext) (hash.Hash, bool, *CascadeResult)
}
