package main

import (
	"strings"
)

// Path represents an absolute location in the universal tree.
// Always "/" or "/{peer_id}/..." format.
type Path string

// Resolve resolves an input path relative to the working directory.
func Resolve(input string, wd Path) Path {
	input = strings.TrimSpace(input)
	if input == "" {
		return wd
	}
	if input == "/" {
		return "/"
	}

	var raw string
	if strings.HasPrefix(input, "/") {
		raw = input
	} else if input == ".." {
		return wd.Parent()
	} else if strings.HasPrefix(input, "../") {
		parent := wd.Parent()
		rest := strings.TrimPrefix(input, "../")
		return Resolve(rest, parent)
	} else {
		w := string(wd)
		if !strings.HasSuffix(w, "/") {
			w += "/"
		}
		raw = w + input
	}

	return Path(normalizePath(raw))
}

// normalizePath cleans a path: resolves "..", removes double slashes,
// ensures leading "/", and preserves trailing "/" for directories.
func normalizePath(raw string) string {
	// Split and resolve.
	parts := strings.Split(raw, "/")
	var resolved []string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		resolved = append(resolved, p)
	}

	if len(resolved) == 0 {
		return "/"
	}

	result := "/" + strings.Join(resolved, "/")

	// Preserve trailing slash if the input had one (indicates directory).
	if strings.HasSuffix(raw, "/") {
		result += "/"
	}
	return result
}

// PeerID returns the first path segment (the peer ID), or empty string if at root.
func (p Path) PeerID() string {
	s := string(p)
	if s == "/" {
		return ""
	}
	s = strings.TrimPrefix(s, "/")
	idx := strings.Index(s, "/")
	if idx < 0 {
		return s
	}
	return s[:idx]
}

// BarePath returns everything after "/{peer_id}/".
// This is what PeerClient methods expect (no leading "/").
func (p Path) BarePath() string {
	s := string(p)
	if s == "/" {
		return ""
	}
	s = strings.TrimPrefix(s, "/")
	idx := strings.Index(s, "/")
	if idx < 0 {
		return ""
	}
	return s[idx+1:]
}

// IsRoot returns true if the path is "/".
func (p Path) IsRoot() bool {
	return p == "/"
}

// Parent returns the parent path (one segment up).
func (p Path) Parent() Path {
	s := string(p)
	if s == "/" {
		return "/"
	}
	// Remove trailing slash.
	s = strings.TrimSuffix(s, "/")
	idx := strings.LastIndex(s, "/")
	if idx <= 0 {
		return "/"
	}
	return Path(s[:idx] + "/")
}

// String returns the path as a string.
func (p Path) String() string {
	return string(p)
}
