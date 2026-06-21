package handler

import (
	"context"
	"fmt"
	"strings"
	"sync"

	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
)

// Registry maps path patterns to handlers and dispatches requests.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry creates a new handler registry.
func NewRegistry() *Registry {
	return &Registry{
		handlers: make(map[string]Handler),
	}
}

// Register adds a handler at the given pattern.
func (r *Registry) Register(pattern string, handler Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[pattern] = handler
}

// Unregister removes the handler at the given pattern. Returns true if a
// handler was present and removed, false otherwise. Safe to call multiple times.
func (r *Registry) Unregister(pattern string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.handlers[pattern]
	delete(r.handlers, pattern)
	return existed
}

// Resolve finds the handler for the given path using longest prefix match.
// Returns the handler, the matched pattern, and whether a match was found.
func (r *Registry) Resolve(path string) (Handler, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestHandler Handler
	bestPattern := ""
	bestLen := -1

	for pattern, h := range r.handlers {
		if path == pattern || strings.HasPrefix(path, pattern+"/") {
			if len(pattern) > bestLen {
				bestHandler = h
				bestPattern = pattern
				bestLen = len(pattern)
			}
		}
	}

	if bestHandler == nil {
		return nil, "", false
	}
	return bestHandler, bestPattern, true
}

// Dispatch resolves a handler for the request path and invokes it.
func (r *Registry) Dispatch(ctx context.Context, req *Request) (*Response, error) {
	h, pattern, ok := r.Resolve(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: no handler for path %q", ecerrors.ErrNotFound, req.Path)
	}
	if req.Context != nil {
		req.Context.HandlerPattern = pattern
	}
	return h.Handle(ctx, req)
}

// Lookup returns the compiled handler registered at exactly the given pattern.
// Used by the dispatcher to fetch the implementation for a tree-resolved
// handler pattern. Returns (nil, false) if no compiled implementation exists
// at the pattern (an entity-native handler entity in the tree may have no
// corresponding code; that case is dispatched via the compute evaluator).
func (r *Registry) Lookup(pattern string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[pattern]
	return h, ok
}

// Handlers returns a copy of the registered handler map.
func (r *Registry) Handlers() map[string]Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make(map[string]Handler, len(r.handlers))
	for k, v := range r.handlers {
		cp[k] = v
	}
	return cp
}
