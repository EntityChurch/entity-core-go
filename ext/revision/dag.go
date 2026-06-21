package revision

import (
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
)

// walkHistory performs a BFS traversal of the version DAG starting from head.
// Returns up to limit versions (0 = unlimited) and their hashes in order visited.
// If since is non-zero, stops before visiting that version.
func walkHistory(cs store.ContentStore, head hash.Hash, limit int, since hash.Hash) ([]types.RevisionEntryData, []hash.Hash) {
	var versions []types.RevisionEntryData
	var hashes []hash.Hash
	if head.IsZero() {
		return versions, hashes
	}

	visited := make(map[hash.Hash]bool)
	queue := []hash.Hash{head}

	for len(queue) > 0 {
		if limit > 0 && len(versions) >= limit {
			break
		}

		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		if !since.IsZero() && current == since {
			continue
		}

		ent, ok := cs.Get(current)
		if !ok {
			continue
		}
		v, err := types.RevisionEntryDataFromEntity(ent)
		if err != nil {
			continue
		}

		versions = append(versions, v)
		hashes = append(hashes, current)

		for _, parent := range v.Parents {
			if !visited[parent] {
				queue = append(queue, parent)
			}
		}
	}
	return versions, hashes
}

// findCommonAncestor finds the lowest common ancestor of two version hashes
// using bidirectional BFS. Returns the ancestor hash and true if found.
func findCommonAncestor(cs store.ContentStore, a, b hash.Hash) (hash.Hash, bool) {
	if a == b {
		return a, true
	}
	if a.IsZero() || b.IsZero() {
		return hash.Hash{}, false
	}

	visitedA := make(map[hash.Hash]bool)
	visitedB := make(map[hash.Hash]bool)
	queueA := []hash.Hash{a}
	queueB := []hash.Hash{b}

	visitedA[a] = true
	visitedB[b] = true

	for len(queueA) > 0 || len(queueB) > 0 {
		if len(queueA) > 0 {
			current := queueA[0]
			queueA = queueA[1:]

			if visitedB[current] {
				return current, true
			}

			ent, ok := cs.Get(current)
			if ok {
				v, err := types.RevisionEntryDataFromEntity(ent)
				if err == nil {
					for _, parent := range v.Parents {
						if !visitedA[parent] {
							visitedA[parent] = true
							queueA = append(queueA, parent)
						}
					}
				}
			}
		}

		if len(queueB) > 0 {
			current := queueB[0]
			queueB = queueB[1:]

			if visitedA[current] {
				return current, true
			}

			ent, ok := cs.Get(current)
			if ok {
				v, err := types.RevisionEntryDataFromEntity(ent)
				if err == nil {
					for _, parent := range v.Parents {
						if !visitedB[parent] {
							visitedB[parent] = true
							queueB = append(queueB, parent)
						}
					}
				}
			}
		}
	}

	return hash.Hash{}, false
}

// checkRelationship determines the relationship between local and remote versions.
// Returns one of: "in_sync", "behind", "ahead", "diverged".
func checkRelationship(cs store.ContentStore, local, remote hash.Hash) string {
	if local == remote {
		return "in_sync"
	}
	if local.IsZero() {
		return "behind"
	}
	if remote.IsZero() {
		return "ahead"
	}
	if isAncestor(cs, local, remote) {
		return "behind"
	}
	if isAncestor(cs, remote, local) {
		return "ahead"
	}
	return "diverged"
}

// isAncestor returns true if potentialAncestor is an ancestor of descendant.
func isAncestor(cs store.ContentStore, potentialAncestor, descendant hash.Hash) bool {
	if potentialAncestor == descendant {
		return true
	}
	visited := make(map[hash.Hash]bool)
	queue := []hash.Hash{descendant}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		ent, ok := cs.Get(current)
		if !ok {
			continue
		}
		v, err := types.RevisionEntryDataFromEntity(ent)
		if err != nil {
			continue
		}
		for _, parent := range v.Parents {
			if parent == potentialAncestor {
				return true
			}
			if !visited[parent] {
				queue = append(queue, parent)
			}
		}
	}
	return false
}

// detectOscillation checks whether the proposed merge would re-create an
// existing version in recent ancestry. Per EXTENSION-REVISION v2.1 §4.4.4 +
// PROPOSAL-PRODUCTION-READINESS-AMENDMENTS A.3 / T2.3 (clarified).
//
// Identity comparison is over the full candidate version (root + sorted
// parents), NOT root alone. Same root with different parents is a legitimate
// new version that cross-links lineage from two heads — exactly what a P2P
// merge produces when both peers reach the same content state via different
// merge paths. Root-only matching would abort those cross-link merges and
// leave the DAG with permanently divergent terminals at identical content
// (the F10 part-3 bug; see the F10 part-3 diagnosis and the F10 postmortem).
//
// The previous root-only implementation aborted any merge whose result trie
// matched a recent ancestor's trie. Post-content-convergence this fired on
// every cross-peer merge, leaving alice and bob at different heads forever.
// Comparing full version hashes preserves the original oscillation guard
// (re-creating an existing version IS still an oscillation) without
// over-aborting on legitimate cross-link.
func detectOscillation(cs store.ContentStore, proposedRoot hash.Hash, proposedParents []hash.Hash, localHead hash.Hash, depthLimit int) bool {
	if depthLimit <= 0 {
		depthLimit = 4 // default depth
	}

	// Compute the candidate version hash. The merge handler will construct
	// the same shape (sorted parents) before persisting — we compare against
	// that canonical form so the only way to match is if the candidate is
	// byte-identical to an ancestor entity.
	candidate := types.RevisionEntryData{
		Root:    proposedRoot,
		Parents: tree.SortedParents(proposedParents),
	}
	candidateEnt, err := candidate.ToEntity()
	if err != nil {
		// Encoding failure shouldn't happen for well-formed inputs; err on
		// the side of allowing the merge rather than blocking it.
		return false
	}
	candidateHash := candidateEnt.ContentHash

	visited := make(map[hash.Hash]bool)
	queue := []hash.Hash{localHead}
	depth := 0

	for len(queue) > 0 && depth < depthLimit {
		nextQueue := []hash.Hash{}
		for _, current := range queue {
			if current.IsZero() || visited[current] {
				continue
			}
			visited[current] = true

			// Full-identity match: an ancestor IS the candidate version. This
			// is a true oscillation — we'd be re-creating an existing entry.
			if current == candidateHash {
				return true
			}

			ent, ok := cs.Get(current)
			if !ok {
				continue
			}
			v, err := types.RevisionEntryDataFromEntity(ent)
			if err != nil {
				continue
			}
			nextQueue = append(nextQueue, v.Parents...)
		}
		queue = nextQueue
		depth++
	}

	return false
}
