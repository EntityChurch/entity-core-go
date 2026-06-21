package localfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.entitychurch.org/entity-core-go/core/store"
)

// RootMapping represents an active filesystem root mapped into the entity tree.
type RootMapping struct {
	Name               string
	Prefix             string // Tree prefix (e.g., "local/files/shared/")
	FSRoot             string // Filesystem root (absolute, cleaned)
	ReadOnly           bool
	Exclude            []string // Glob patterns to exclude (applies to files and dirs)
	Include            []string // Glob patterns to include — empty means all (applies to files only)
	PublishDescriptors bool     // DOMAIN-LOCAL-FILES v1.3 §10.5 V3: publish system/content/descriptor entities on read
}

// AddRoot adds a root mapping and stores the config entity in the tree.
func (h *Handler) AddRoot(name string, cfg RootConfigData, cs store.ContentStore, li store.LocationIndex) error {
	absRoot, err := filepath.Abs(cfg.FilesystemRoot)
	if err != nil {
		return fmt.Errorf("resolve filesystem root: %w", err)
	}

	// Ensure prefix ends with /
	prefix := cfg.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check for overlapping prefixes.
	for _, existing := range h.roots {
		if strings.HasPrefix(prefix, existing.Prefix) || strings.HasPrefix(existing.Prefix, prefix) {
			return fmt.Errorf("prefix %q overlaps with existing root %q (prefix %q)", prefix, existing.Name, existing.Prefix)
		}
	}

	h.roots[name] = &RootMapping{
		Name:               name,
		Prefix:             prefix,
		FSRoot:             absRoot,
		ReadOnly:           cfg.ReadOnly,
		Exclude:            cfg.Exclude,
		Include:            cfg.Include,
		PublishDescriptors: cfg.PublishDescriptors,
	}

	// Store config entity in the tree.
	configEntity, err := cfg.ToEntity()
	if err != nil {
		return fmt.Errorf("create config entity: %w", err)
	}
	eh, err := cs.Put(configEntity)
	if err != nil {
		return fmt.Errorf("store config entity: %w", err)
	}
	if err := li.Set("system/config/local/files/"+name, eh); err != nil {
		return fmt.Errorf("bind config entity: %w", err)
	}

	return nil
}

// findRootMapping returns the root mapping with the longest matching prefix.
func (h *Handler) findRootMapping(treePath string) *RootMapping {
	var best *RootMapping
	for _, root := range h.roots {
		if strings.HasPrefix(treePath, root.Prefix) {
			if best == nil || len(root.Prefix) > len(best.Prefix) {
				best = root
			}
		}
	}
	return best
}

// resolveFSPath resolves a tree path to a filesystem path within the given root.
// Returns (fsPath, relativePath, error). Returns error on path traversal.
func resolveFSPath(root *RootMapping, treePath string) (string, string, error) {
	relativePath := strings.TrimPrefix(treePath, root.Prefix)
	fsPath := filepath.Join(root.FSRoot, relativePath)

	// Path traversal prevention: resolve symlinks and verify containment.
	canonical, err := filepath.EvalSymlinks(root.FSRoot)
	if err != nil {
		// If root doesn't exist yet, use Abs instead.
		canonical, err = filepath.Abs(root.FSRoot)
		if err != nil {
			return "", "", fmt.Errorf("resolve root: %w", err)
		}
	}

	// For the target path, we resolve the parent (file may not exist yet).
	parentDir := filepath.Dir(fsPath)
	canonicalParent, err := filepath.EvalSymlinks(parentDir)
	if err != nil {
		// Parent may not exist either (e.g., create_dirs). Check what we can.
		canonicalParent, err = filepath.Abs(parentDir)
		if err != nil {
			return "", "", fmt.Errorf("resolve path: %w", err)
		}
	}
	resolvedPath := filepath.Join(canonicalParent, filepath.Base(fsPath))

	if !strings.HasPrefix(resolvedPath, canonical) {
		return "", "", fmt.Errorf("path traversal rejected: %q escapes root %q", treePath, root.FSRoot)
	}

	// Leaf-symlink rejection. The EvalSymlinks(parentDir) above defends
	// against parent-component escape; the leaf basename is joined
	// unresolved (the leaf may not exist yet on writes), which leaves a
	// hole if the leaf itself is a symlink pointing outside the root.
	// Lstat the leaf — if it exists and is a symlink, refuse. The leaf
	// not existing is fine (atomic-rename replaces the directory entry
	// rather than following it). Convergent fix with Rust C-1 + Python
	// F-4. A narrow TOCTOU race remains between this check and the
	// subsequent open; kernel-enforced defense via O_NOFOLLOW /
	// openat2(RESOLVE_BENEATH) is RECOMMENDED for production deployments.
	if info, lerr := os.Lstat(resolvedPath); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("path traversal rejected: leaf symlink at %q refused", treePath)
		}
	}

	return fsPath, relativePath, nil
}

// matchesExclude checks if a filename matches any of the exclude glob patterns.
func matchesExclude(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// matchesInclude checks if a filename passes the include glob filter.
// Empty include = no positive filter (everything passes). Non-empty
// include = name must match at least one pattern.
func matchesInclude(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// fileSkipped is the canonical "should this filename be ignored?"
// check, combining exclude + include. Use this for FILES; for
// directories, only matchesExclude applies (include never gates
// recursion).
func fileSkipped(name string, exclude, include []string) bool {
	if matchesExclude(name, exclude) {
		return true
	}
	if !matchesInclude(name, include) {
		return true
	}
	return false
}
