package store

// ConsumerResult is returned by a named sync hook consumer to signal its
// outcome. A nil return (or Status 200) means success. A non-200 Status is
// an intentional halt signal — the cascade stops and remaining consumers are
// skipped. Per PROPOSAL-CASCADE-SEMANTICS §4.2 / §10.2: non-200 is the
// intentional-halt signal, not a general error channel. Consumer-internal
// errors that should not halt MUST be handled inside the consumer.
type ConsumerResult struct {
	Status  uint
	Code    string
	Message string
}

// NamedSyncHook pairs a consumer name with its callback. Names are stable
// identifiers (e.g., "query-index", "history-recorder", "root-tracker",
// "auto-versioner") used in cascade-halt responses and audit logs. Per
// PROPOSAL-CASCADE-SEMANTICS §4.4: names SHOULD be prefixed with the owning
// extension's handler pattern to avoid collisions.
//
// Pattern, if non-empty, restricts which TreeChangeEvent paths invoke Fn.
// Empty pattern (the default) matches all events — equivalent to the legacy
// no-pattern API. Grammar mirrors Python's `_pattern_matches` (entity-core-py
// storage/emit.py): `*` matches everything; `prefix/*` is a prefix match;
// anything else is an exact match. Skipped hooks do not appear in the
// CascadeResult — they did not participate, so they cannot have halted or
// completed.
type NamedSyncHook struct {
	Name    string
	Pattern string
	Fn      func(TreeChangeEvent) *ConsumerResult
}

// pathMatchesPattern reports whether path satisfies pattern under the
// NamedSyncHook.Pattern grammar. Path is the post-canonicalization event
// path the engine sees — for binding events that means /{peer_id}/rest
// (canonicalization happens in NamespacedIndex).
//
// Grammar — coordinate-space-aware:
//
//	""               match all (legacy AddNamedSyncHook behavior)
//	"*"               match all
//	"/PID/foo/*"     specific peer namespace; prefix glob within it
//	"/PID/foo"       specific peer namespace; exact match
//	"/*/foo/*"       any peer namespace, explicit; prefix glob
//	"/*/foo"         any peer namespace, explicit; exact suffix
//	"foo/*"          peer-relative: any peer namespace + suffix prefix
//	                  (the default for observers — keeps cross-peer visibility)
//	"foo"            peer-relative: any peer namespace + exact suffix
//
// The peer-relative form is deliberately namespace-agnostic so a hook
// watching "system/attestation/*" sees attestation events bound under any
// peer's namespace in the local tree (local + remote-via-sync/revision).
// Scope to one peer explicitly with "/PID/...".
func pathMatchesPattern(pattern, path string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	// Absolute pattern: leading "/".
	if len(pattern) > 0 && pattern[0] == '/' {
		// "/*/..." → any-peer match.
		if len(pattern) >= 3 && pattern[1] == '*' && pattern[2] == '/' {
			// Strip the peer-id segment from path, compare against the
			// suffix of the pattern (after "/*/").
			_, bare := splitNamespaceForMatch(path)
			return matchSuffix(pattern[3:], bare)
		}
		return matchSuffix(pattern[1:], stripLeadingSlash(path))
	}
	// Peer-relative pattern: match against the bare suffix of every event
	// path (which lives under some /{peer_id}/...).
	_, bare := splitNamespaceForMatch(path)
	return matchSuffix(pattern, bare)
}

// matchSuffix applies the exact/prefix-glob grammar to a suffix.
//
//	"a/b/*"  → prefix match on "a/b/"; also matches the bare "a/b"
//	"a/b"    → exact match
func matchSuffix(pattern, suffix string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) >= 2 && pattern[len(pattern)-2:] == "/*" {
		prefix := pattern[:len(pattern)-1] // keep trailing "/"
		if len(suffix) >= len(prefix) && suffix[:len(prefix)] == prefix {
			return true
		}
		bare := pattern[:len(pattern)-2]
		return suffix == bare
	}
	return pattern == suffix
}

// splitNamespaceForMatch is a local copy of SplitNamespace's behavior used
// in pattern matching. Inlined here so the grammar helper doesn't drag in
// the full Path-Model surface — same logic, just trimmed.
func splitNamespaceForMatch(path string) (ns, bare string) {
	if len(path) == 0 || path[0] != '/' {
		return "", path
	}
	rest := path[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i], rest[i+1:]
		}
	}
	return rest, ""
}

func stripLeadingSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}

// CascadeHaltEntry records a consumer that halted the cascade.
type CascadeHaltEntry struct {
	Name  string
	Error ConsumerResult
}

// CascadeResult captures the outcome of a sync-phase emit cascade. It is
// returned from SetWithContext / RemoveWithContext on the NotifyingLocationIndex
// and threaded up through HandlerContext.TreeSet / TreeRemove to the tree
// handler, which maps it to status 200 (complete) or 207 (partial).
type CascadeResult struct {
	BindingCommitted bool
	Completed        []string           // consumer names that ran successfully, in order
	Halted           []CascadeHaltEntry // consumer(s) that returned non-200
	Skipped          []string           // consumer names that were not run
	CascadeDepth     uint64
}

// IsComplete returns true if the cascade ran all consumers without halts.
func (cr *CascadeResult) IsComplete() bool {
	if cr == nil {
		return true
	}
	return len(cr.Halted) == 0 && len(cr.Skipped) == 0
}

// HasHalt returns true if at least one consumer intentionally halted the cascade.
func (cr *CascadeResult) HasHalt() bool {
	if cr == nil {
		return false
	}
	return len(cr.Halted) > 0
}

// IsDepthRefused returns true if the write was refused because cascade depth
// exceeded the system threshold. In this case BindingCommitted is false and
// all consumers were skipped.
func (cr *CascadeResult) IsDepthRefused() bool {
	if cr == nil {
		return false
	}
	return !cr.BindingCommitted && len(cr.Skipped) > 0
}

// DefaultMaxCascadeDepth is the system refusal threshold for nested cascades.
// Writes at or beyond this depth are refused (binding does NOT commit).
// Per SYSTEM-COMPOSITION §3.2.
const DefaultMaxCascadeDepth uint64 = 32
