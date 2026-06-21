package types

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// History extension type constants (EXTENSION-HISTORY.md v1.2).
const (
	TypeHistoryTransition     = "system/history/transition"
	TypeHistoryConfig         = "system/history/config"
	TypeHistoryQueryParams    = "system/history/query-params"
	TypeHistoryQueryResult    = "system/history/query-result"
	TypeHistoryRollbackParams = "system/history/rollback-params"
	TypeHistoryRollbackResult = "system/history/rollback-result"
)

// TransitionData is the data payload for system/history/transition.
// Records a single change to a tree binding with full execution context.
type TransitionData struct {
	Path             string          `cbor:"path"`
	Event            string          `cbor:"event"`                       // "created", "updated", "deleted", "accessed"
	Hash             hash.Hash       `cbor:"hash,omitempty"`              // New entity hash (absent for deleted)
	PreviousHash     hash.Hash       `cbor:"previous_hash,omitempty"`     // Previous entity hash (absent for created)
	Author           hash.Hash       `cbor:"author"`                      // Content hash of caller's identity
	Capability       hash.Hash       `cbor:"capability"`                  // Content hash of the capability that authorized this specific write (§6.8)
	CallerCapability hash.Hash       `cbor:"caller_capability,omitempty"` // Content hash of external caller's capability (may differ from capability for handler-authorized writes; absent for autonomous)
	Handler          string          `cbor:"handler"`                     // Handler pattern (e.g., "system/tree")
	Operation        string          `cbor:"operation"`                   // Operation name (e.g., "put", "merge")
	Timestamp        uint64          `cbor:"timestamp"`                   // Milliseconds since epoch
	Clock            cbor.RawMessage `cbor:"clock,omitempty"`             // Structured clock state (system/clock/state) from execution context; absent when clock extension not present (F7, HISTORY v1.5)
	ChainID          string          `cbor:"chain_id,omitempty"`          // Causal correlation from bounds
	ParentChainID    string          `cbor:"parent_chain_id,omitempty"`   // Parent chain's chain_id from bounds; enables cross-sub-chain audit queries (G-7)
	Previous         hash.Hash       `cbor:"previous,omitempty"`          // Hash of prior transition for this path
}

// ToEntity creates a system/history/transition entity.
func (d TransitionData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryTransition, cbor.RawMessage(raw))
}

// TransitionDataFromEntity decodes a transition entity's data.
func TransitionDataFromEntity(e entity.Entity) (TransitionData, error) {
	var d TransitionData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return TransitionData{}, err
	}
	return d, nil
}

// HistoryConfigData is the data payload for system/history/config.
// Configures history recording for paths matching a pattern.
type HistoryConfigData struct {
	Pattern  string   `cbor:"pattern"`
	Enabled  bool     `cbor:"enabled"`
	Events   []string `cbor:"events,omitempty"`    // Default: ["created", "updated", "deleted"]
	MaxDepth *uint64  `cbor:"max_depth,omitempty"` // Max transitions per path; nil = no limit
}

// ToEntity creates a system/history/config entity.
func (d HistoryConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryConfig, cbor.RawMessage(raw))
}

// HistoryConfigDataFromEntity decodes a history config entity's data.
func HistoryConfigDataFromEntity(e entity.Entity) (HistoryConfigData, error) {
	var d HistoryConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HistoryConfigData{}, err
	}
	return d, nil
}

// HistoryQueryParamsData is the data payload for system/history/query-params.
type HistoryQueryParamsData struct {
	Path   string    `cbor:"path"`
	Limit  *uint64   `cbor:"limit,omitempty"`  // Default: 50
	Since  hash.Hash `cbor:"since,omitempty"`  // Return transitions after this hash (exclusive)
	Before *uint64   `cbor:"before,omitempty"` // Return transitions before this timestamp
	Events []string  `cbor:"events,omitempty"` // Filter by event type
}

// ToEntity creates a system/history/query-params entity.
func (d HistoryQueryParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryQueryParams, cbor.RawMessage(raw))
}

// HistoryQueryParamsDataFromEntity decodes query params entity data.
func HistoryQueryParamsDataFromEntity(e entity.Entity) (HistoryQueryParamsData, error) {
	var d HistoryQueryParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HistoryQueryParamsData{}, err
	}
	return d, nil
}

// HistoryQueryResultData is the data payload for system/history/query-result.
type HistoryQueryResultData struct {
	Path        string           `cbor:"path"`
	Head        hash.Hash        `cbor:"head,omitempty"` // Most recent transition hash
	Transitions []TransitionData `cbor:"transitions"`
	HasMore     bool             `cbor:"has_more"`
}

// ToEntity creates a system/history/query-result entity.
func (d HistoryQueryResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryQueryResult, cbor.RawMessage(raw))
}

// HistoryQueryResultDataFromEntity decodes a query result entity's data.
func HistoryQueryResultDataFromEntity(e entity.Entity) (HistoryQueryResultData, error) {
	var d HistoryQueryResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HistoryQueryResultData{}, err
	}
	return d, nil
}

// HistoryRollbackParamsData is the data payload for system/history/rollback-params.
type HistoryRollbackParamsData struct {
	Path       string    `cbor:"path"`
	TargetHash hash.Hash `cbor:"target_hash"` // Content hash of entity to restore
}

// ToEntity creates a system/history/rollback-params entity.
func (d HistoryRollbackParamsData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryRollbackParams, cbor.RawMessage(raw))
}

// HistoryRollbackParamsDataFromEntity decodes rollback params entity data.
func HistoryRollbackParamsDataFromEntity(e entity.Entity) (HistoryRollbackParamsData, error) {
	var d HistoryRollbackParamsData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HistoryRollbackParamsData{}, err
	}
	return d, nil
}

// HistoryRollbackResultData is the data payload for system/history/rollback-result.
type HistoryRollbackResultData struct {
	Path     string    `cbor:"path"`
	Restored hash.Hash `cbor:"restored"` // Content hash of restored entity
}

// ToEntity creates a system/history/rollback-result entity.
func (d HistoryRollbackResultData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeHistoryRollbackResult, cbor.RawMessage(raw))
}

// HistoryRollbackResultDataFromEntity decodes a rollback result entity's data.
func HistoryRollbackResultDataFromEntity(e entity.Entity) (HistoryRollbackResultData, error) {
	var d HistoryRollbackResultData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return HistoryRollbackResultData{}, err
	}
	return d, nil
}
