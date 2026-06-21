package quorum

import (
	"context"
	"errors"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// TV-Q-V-IDENTITY-2 (per PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md §3.22):
// resolver chain depth exceeds MaxResolverDepth → returns
// identity_resolver_max_depth_exceeded error.
//
// We construct this by registering a resolver that recurses into
// CurrentSignerSetCtx for a different quorum each step. After 8 levels of
// nesting the bound trips.
func TestTV_Q_V_IDENTITY_2_DepthExceeded(t *testing.T) {
	f := newFixture()
	// Build a chain of N+1 quorums each in identity-resolved mode that
	// resolves to the next one. Depth = N. Setting N > MaxResolverDepth
	// should trip the bound.
	const chainLen = MaxResolverDepth + 2
	signers := []hash.Hash{makeFakeHash(0x01)}
	quorumIDs := make([]hash.Hash, chainLen)
	for i := 0; i < chainLen; i++ {
		// Use a distinct name per quorum so each has a unique content hash.
		q := types.QuorumData{
			Signers:          signers,
			Threshold:        1,
			SignerResolution: types.SignerResolutionIdentityResolved,
			Name:             "depth-test-" + intToString(i),
		}
		ent, err := q.ToEntity()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.cs.Put(ent); err != nil {
			t.Fatal(err)
		}
		f.li.Set(QuorumPath(ent.ContentHash), ent.ContentHash)
		quorumIDs[i] = ent.ContentHash
	}

	// Resolver: when called for a signer matching the i-th quorum's signer,
	// recurse into CurrentSignerSetCtx for the (i+1)-th quorum, returning
	// its first resolved signer. Keyed by source-quorum lookup via signers
	// array reference is brittle; instead we route by signerRef value.
	// Simplest: route signerRef → next quorum_id in the chain by
	// position using a map from "current quorum's known signer" to "next
	// quorum_id".
	//
	// Each quorum has the same `signers = [0x01]`. So the resolver call
	// can't distinguish quorum_i from quorum_j by signerRef alone. We
	// instead test the abstract bound by having the resolver always
	// recurse into the next quorum in the chain — using a pointer to a
	// next-index counter.
	idx := 0
	f.q.RegisterResolver(types.SignerResolutionIdentityResolved,
		func(ctx context.Context, ref hash.Hash, _ store.ContentStore, _ store.LocationIndex, _ uint64) (hash.Hash, error) {
			i := idx
			idx++
			if i+1 >= chainLen {
				// Bottom of chain — return a concrete hash so the recursion
				// would terminate on its own (but it shouldn't; bound trips first).
				return makeFakeHash(0xFF), nil
			}
			next := quorumIDs[i+1]
			signers, _, err := f.q.CurrentSignerSetCtx(ctx, next, 0)
			if err != nil {
				return hash.Hash{}, err
			}
			return signers[0], nil
		})

	_, _, err := f.q.CurrentSignerSet(quorumIDs[0])
	if err == nil {
		t.Fatal("expected ResolverDepthExceededError, got nil")
	}
	var dep *ResolverDepthExceededError
	if !errors.As(err, &dep) {
		t.Fatalf("expected *ResolverDepthExceededError, got %T: %v", err, err)
	}
}

// TV-Q-V-IDENTITY-2-cycle (per PROPOSAL §3.22): resolver chain revisits a
// quorum_id → returns identity_resolver_cycle error.
//
// Setup: quorum A's resolver returns a signer that, when recursed,
// resolves to quorum B; quorum B's resolver returns a signer that
// recursively resolves back to quorum A.
func TestTV_Q_V_IDENTITY_2_Cycle(t *testing.T) {
	f := newFixture()
	signers := []hash.Hash{makeFakeHash(0x01)}
	qA := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)
	qB := f.putQuorum(t, signers, 1, types.SignerResolutionIdentityResolved)

	// Toggle: each call alternates between resolving to qB and resolving
	// to qA. Starting from qA → qB → qA → cycle on revisit.
	visited := []hash.Hash{}
	f.q.RegisterResolver(types.SignerResolutionIdentityResolved,
		func(ctx context.Context, ref hash.Hash, _ store.ContentStore, _ store.LocationIndex, _ uint64) (hash.Hash, error) {
			var next hash.Hash
			if len(visited)%2 == 0 {
				next = qB
			} else {
				next = qA
			}
			visited = append(visited, next)
			ss, _, err := f.q.CurrentSignerSetCtx(ctx, next, 0)
			if err != nil {
				return hash.Hash{}, err
			}
			return ss[0], nil
		})

	_, _, err := f.q.CurrentSignerSet(qA)
	if err == nil {
		t.Fatal("expected ResolverCycleError, got nil")
	}
	var cyc *ResolverCycleError
	if !errors.As(err, &cyc) {
		t.Fatalf("expected *ResolverCycleError, got %T: %v", err, err)
	}
}
