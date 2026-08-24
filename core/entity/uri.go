package entity

import (
	"fmt"
	"strings"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

const Scheme = "entity://"

// URI represents a parsed entity URI: entity://peer_id/path
type URI struct {
	PeerID string
	Path   string
}

// ParseURI parses an entity URI string.
func ParseURI(s string) (URI, error) {
	if !strings.HasPrefix(s, Scheme) {
		return URI{}, fmt.Errorf("%w: missing scheme prefix", ecerrors.ErrInvalidEntity)
	}
	rest := s[len(Scheme):]
	if rest == "" {
		return URI{}, fmt.Errorf("%w: empty URI body", ecerrors.ErrInvalidEntity)
	}

	idx := strings.Index(rest, "/")
	if idx < 0 {
		// Just peer_id, no path.
		return URI{PeerID: rest}, nil
	}

	return URI{
		PeerID: rest[:idx],
		Path:   rest[idx+1:],
	}, nil
}

// String reconstructs the full entity URI.
func (u URI) String() string {
	if u.Path == "" {
		return Scheme + u.PeerID
	}
	return Scheme + u.PeerID + "/" + u.Path
}

// NormalizePath converts an entity URI to an absolute path, or returns a path as-is.
//
//	NormalizePath("entity://peer_id/path") => "/peer_id/path"
//	NormalizePath("/peer_id/path")         => "/peer_id/path"
//	NormalizePath("system/tree")           => "system/tree"
func NormalizePath(uri string) string {
	if strings.HasPrefix(uri, Scheme) {
		return "/" + uri[len(Scheme):]
	}
	return uri
}

// PathToURI converts an absolute path to an entity URI.
// Strips the leading "/" to avoid triple-slash in the URI.
//
//	PathToURI("/alice_id/system/tree") => "entity://alice_id/system/tree"
func PathToURI(path string) string {
	return Scheme + strings.TrimPrefix(path, "/")
}

// ExtractHandlerPath extracts the handler-relative path from a URI or absolute path.
// For entity URIs, strips scheme and peer_id. For absolute paths, strips /{peer_id}/.
// For peer-relative paths, returns as-is.
//
// The absolute-path case is detected by the V7 §1.4 rule — HasPrefix("/") —
// NOT by whether NormalizePath happened to rewrite the input. Both forms reduce
// to "/{peer_id}/rest" and are stripped identically; only a peer-relative path
// (no leading "/") passes through.
//
// This used to strip only the scheme form, so an absolute path came back with
// its /{peer_id}/ still attached — contradicting the contract above. Callers
// then qualified the result (store.QualifyPath concatenates unconditionally),
// producing "/{peer}//{peer}/rest", and the empty segment panicked
// NamespacedIndex.canonicalize. Reachable from the WIRE: an EXECUTE whose `uri`
// is an absolute path rather than an entity:// URI — a legitimate spelling,
// since paths are absolute — crashed the peer serving it. The panic's own
// comment claims external input is validated before reaching it; this was the
// hole in that claim.
func ExtractHandlerPath(uri string) string {
	normalized := NormalizePath(uri)
	if !strings.HasPrefix(normalized, "/") {
		return normalized // peer-relative — nothing to strip
	}
	// "/{peer_id}/rest" (from either spelling) → "rest".
	rest := normalized[1:]
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return rest // just peer_id, no path
	}
	return rest[idx+1:]
}
