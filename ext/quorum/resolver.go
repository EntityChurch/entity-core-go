package quorum

import (
	"context"
	"sync"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// MaxResolverDepth is the default recursion bound for nested resolver
// chains per EXTENSION-QUORUM v1.1 §5.2 (IDENTITY-2). Resolver handlers
// MAY recursively look up downstream identities (e.g., identity-resolved
// mode resolves an identity reference to its current controller, which
// itself may live in another identity). Without a bound, malformed or
// malicious chains can produce unbounded recursion or cycles.
//
// Implementations track resolution depth per CurrentSignerSet invocation
// across the resolver chain; on exceeding MaxResolverDepth implementations
// MUST return ResolverDepthExceededError.
const MaxResolverDepth = 8

// SignerResolver resolves a signer reference (as stored in
// system/quorum.signers) to a concrete peer-identity hash. Pluggable per
// §5.2: implementations register additional resolution modes via
// Handler.RegisterResolver.
//
// The "concrete" mode is built in (§5.1) and bypasses the registry —
// concrete signers' hashes ARE peer-identity hashes; no resolution needed.
//
// Resolvers MUST be deterministic and side-effect-free. The handler is
// invoked at signature-verification time per signer in the quorum's
// signers array. The output is a peer hash that participates in the K-of-N
// count exactly as a concrete signer would.
//
// The asOf parameter (epoch milliseconds) selects historical state per
// v1.1 §5.2. When asOf is 0 the resolver returns the current state;
// otherwise it returns the signer that was live at asOf.
//
// The context carries depth + visited-set state for the recursion bound
// (IDENTITY-2). Resolvers that recurse into CurrentSignerSetCtx MUST pass
// the same context through; the bound spans the resolver chain.
type SignerResolver func(ctx context.Context, signerRef hash.Hash, cs store.ContentStore, li store.LocationIndex, asOf uint64) (hash.Hash, error)

// resolverState carries recursion-bound state across the resolver chain.
// Smuggled via context.Context with an unexported key. Resolvers retrieve
// it via getResolverState; nested CurrentSignerSetCtx calls inherit it.
type resolverState struct {
	depth   int
	visited map[hash.Hash]struct{}
}

type resolverStateKey struct{}

// withResolverState returns a context carrying a fresh resolver state seeded
// with the given quorum_id as visited. Used by CurrentSignerSetCtx when no
// state is already present.
func withResolverState(parent context.Context, quorumID hash.Hash) context.Context {
	st := &resolverState{
		depth:   0,
		visited: map[hash.Hash]struct{}{quorumID: {}},
	}
	return context.WithValue(parent, resolverStateKey{}, st)
}

// getResolverState returns the resolver state from ctx if present.
func getResolverState(ctx context.Context) (*resolverState, bool) {
	st, ok := ctx.Value(resolverStateKey{}).(*resolverState)
	return st, ok
}

// ResolverDepthExceededError is returned when a resolver chain exceeds
// MaxResolverDepth. Per v1.1 §5.2 cross-impl test vector TV-Q-V-IDENTITY-2.
type ResolverDepthExceededError struct {
	QuorumID hash.Hash
	Depth    int
}

func (e *ResolverDepthExceededError) Error() string {
	return "identity_resolver_max_depth_exceeded: depth=" +
		intToString(e.Depth) + " quorum_id=" + e.QuorumID.String()
}

// ResolverCycleError is returned when a resolver chain revisits an
// identity reference. Per v1.1 §5.2 cross-impl test vector
// TV-Q-V-IDENTITY-2-cycle.
type ResolverCycleError struct {
	QuorumID hash.Hash
}

func (e *ResolverCycleError) Error() string {
	return "identity_resolver_cycle: quorum_id=" + e.QuorumID.String()
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// resolverRegistry holds runtime-registered signer resolvers keyed by
// mode name. The "concrete" mode is implicit and not in the registry —
// looking it up returns nil and the resolver call short-circuits.
type resolverRegistry struct {
	mu        sync.RWMutex
	resolvers map[string]SignerResolver
}

func newResolverRegistry() *resolverRegistry {
	return &resolverRegistry{resolvers: make(map[string]SignerResolver)}
}

func (r *resolverRegistry) register(mode string, fn SignerResolver) error {
	if mode == types.SignerResolutionConcrete {
		return &ResolverAlreadyRegisteredError{ModeName: mode}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.resolvers[mode]; exists {
		return &ResolverAlreadyRegisteredError{ModeName: mode}
	}
	r.resolvers[mode] = fn
	return nil
}

func (r *resolverRegistry) lookup(mode string) (SignerResolver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.resolvers[mode]
	return fn, ok
}

// availableModes returns the list of registered mode names plus the implicit
// "concrete" mode. Used in error envelopes per §5.3.1 to help callers
// distinguish "I need to install another extension" (C3) from "the quorum
// entity has bad data" (C4).
func (r *resolverRegistry) availableModes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	modes := []string{types.SignerResolutionConcrete}
	for name := range r.resolvers {
		modes = append(modes, name)
	}
	return modes
}

// ResolverError describes a fail-closed resolver failure per §5.3.1
// (cases C2/C3/C4). The error envelope carries the quorum_id, the requested
// mode_name, and the available modes for diagnostic clarity.
type ResolverError struct {
	QuorumID       hash.Hash
	ModeName       string
	AvailableModes []string
}

func (e *ResolverError) Error() string {
	return "quorum_resolver_unavailable: mode=" + e.ModeName + " quorum_id=" + e.QuorumID.String()
}

// ResolverAlreadyRegisteredError is returned by RegisterResolver when a
// mode_name has already been registered. Per
// PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP §PR-6 (EXTENSION-QUORUM
// §5.2 multi-registration semantics): implementations MUST NOT silently
// replace, override, or stack handlers; duplicate registration fails closed.
// "concrete" is implicit and reserved — registering it returns this error.
type ResolverAlreadyRegisteredError struct {
	ModeName string
}

func (e *ResolverAlreadyRegisteredError) Error() string {
	return "resolver_already_registered: mode=" + e.ModeName
}
