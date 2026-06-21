package store

import (
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// ChangeType describes the kind of mutation to a location index entry.
type ChangeType int

const (
	ChangeCreated  ChangeType = iota // New path added
	ChangeModified                   // Existing path updated to new hash
	ChangeDeleted                    // Path removed
)

// MutationContext carries execution metadata from the handler that triggered
// a tree mutation. Present when the mutation was made via SetWithContext or
// RemoveWithContext; nil for plain Set/Remove calls (e.g., during peer init).
type MutationContext struct {
	AuthorHash           hash.Hash       // Content hash of the caller's identity entity
	CapabilityHash       hash.Hash       // Content hash of the capability that authorized this specific write
	CallerCapabilityHash hash.Hash       // Content hash of the external caller's capability (may differ from CapabilityHash for handler-authorized writes; zero for autonomous)
	HandlerPattern       string          // Handler that processed the operation (e.g., "system/tree")
	Operation            string          // Operation name (e.g., "put", "merge")
	ChainID              string          // Causal correlation from bounds context (may be empty)
	ParentChainID        string          // Parent chain's chain_id; set when continuation dispatches sub-chain (G-7)
	CascadeDepth         *uint64         // Current cascade depth from bounds (G-3, SYSTEM-COMPOSITION §3.4)
	Clock                cbor.RawMessage // Structured clock state (system/clock/state); set by clock sync hook at position 2 (F6, CLOCK v1.3)
	ClockType            string          // Type name for Clock field (e.g., "system/clock/state"); empty when clock not installed
}

// TreeChangeEvent describes a single mutation to the location index.
// Path is a qualified path (e.g., "{peerID}/data/foo") — the real path as
// stored in the tree. PeerID is a convenience field extracted from the path.
type TreeChangeEvent struct {
	Path         string    // Qualified path (with peer ID prefix)
	PeerID       string    // Peer whose tree was mutated (extracted from Path)
	Hash         hash.Hash // Current hash (zero for deletes)
	PreviousHash hash.Hash // Previous hash (zero for creates)
	ChangeType   ChangeType
	Context      *MutationContext // Execution context; nil when unknown
}
