package entity

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Envelope packages a root entity with included referenced entities for wire transmission.
type Envelope struct {
	Root     Entity               `cbor:"root"`
	Included map[hash.Hash]Entity `cbor:"included,omitempty"`
}

// NewEnvelope creates an envelope with the given root and included entities.
func NewEnvelope(root Entity, included map[hash.Hash]Entity) Envelope {
	return Envelope{
		Root:     root,
		Included: included,
	}
}

// FindIncluded looks up an entity by its content hash in the included map.
func (e Envelope) FindIncluded(h hash.Hash) (Entity, bool) {
	ent, ok := e.Included[h]
	return ent, ok
}

// FindSignatureFor scans the included entities for a system/signature entity
// whose data.target matches the given hash.
func (e Envelope) FindSignatureFor(target hash.Hash) (Entity, bool) {
	for _, ent := range e.Included {
		if ent.Type != "system/signature" {
			continue
		}
		// Target is a Hash (CBOR byte string on wire).
		var sigData struct {
			Target hash.Hash `cbor:"target"`
		}
		if err := cborDecode(ent.Data, &sigData); err != nil {
			continue
		}
		if sigData.Target == target {
			return ent, true
		}
	}
	return Entity{}, false
}

// ValidateAll validates the root entity and all included entity hashes.
func (e Envelope) ValidateAll() error {
	if err := e.Root.Validate(); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	for h, ent := range e.Included {
		if err := ent.Validate(); err != nil {
			return fmt.Errorf("included[%s]: %w", h, err)
		}
	}
	return nil
}

// Include adds an entity to the included map, creating it if necessary.
func (e *Envelope) Include(ent Entity) {
	if e.Included == nil {
		e.Included = make(map[hash.Hash]Entity)
	}
	e.Included[ent.ContentHash] = ent
}

// ToEntity encodes this envelope as a system/envelope entity.
// The resulting entity has type "system/envelope" with data containing
// the root entity and included entities map, per PROPOSAL-SPEC-AMBIGUITIES-CONSOLIDATED M3.
func (e Envelope) ToEntity() (Entity, error) {
	raw, err := ecf.Encode(e)
	if err != nil {
		return Entity{}, fmt.Errorf("encode envelope: %w", err)
	}
	return NewEntity("system/envelope", cbor.RawMessage(raw))
}
