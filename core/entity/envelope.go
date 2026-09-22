package entity

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/ecf"
	ecerrors "go.entitychurch.org/entity-core-go/core/errors"
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

// ValidateAll validates the root entity and all included entity hashes, and
// binds every included MAP KEY to the entity it addresses.
func (e Envelope) ValidateAll() error {
	if err := e.Root.Validate(); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	// §6.3 (0.8.2.26 DR-3): a received frame MUST NOT carry a CBOR tag at any
	// depth. hash validation cannot see it — a tagged entity self-verifies —
	// and the data field is captured raw for byte fidelity, so the tag is never
	// parsed by the entity decode. One walk over the root's data reaches every
	// nested data field it embeds (an EXECUTE root's data carries the params
	// entity). Wide reading (any depth), matching entity-core-{rust,py}; settles
	// SA-PY-66 toward §6.3 over row (5a)'s narrower "data-field position".
	if err := ecf.ForbidTags(e.Root.Data); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if err := VerifyIncludedKeyBinding(e.Included); err != nil {
		return err
	}
	for h, ent := range e.Included {
		if err := ecf.ForbidTags(ent.Data); err != nil {
			return fmt.Errorf("included[%s]: %w", h, err)
		}
	}
	return nil
}

// VerifyIncludedKeyBinding checks that every entry in an included map is keyed
// by its own content hash. It is the defense against a capability/identity
// FORGERY (core-rust routed 2026-09-13): the map is populated from
// wire-supplied keys, and every authority lookup (author identity, cap chain
// granter, link signer, grantee) resolves an entity BY HASH out of it. Absent
// this binding, an attacker who knows a victim's identity hash — the public
// grantee field of any capability the victim presents — can file THEIR OWN
// system/peer entity under the victim's hash key; the peer then verifies the
// attacker's own signature against the attacker's own key while attributing it
// to the victim. Self-consistency (Validate) alone does not catch it: the
// substitute entity hashes to ITS OWN content, which is self-consistent — it is
// only wrong under the KEY it was filed at.
//
// Each entity is validated for self-consistency (which recomputes the hash over
// {type,data} and compares it to the entity's own content_hash field, since
// content_hash rides the wire and is attacker-controllable), then the map key
// is bound to that verified hash. The two together force key == genuine hash.
func VerifyIncludedKeyBinding(included map[hash.Hash]Entity) error {
	for h, ent := range included {
		if err := ent.Validate(); err != nil {
			return fmt.Errorf("included[%s]: %w", h, err)
		}
		if h != ent.ContentHash {
			return fmt.Errorf("%w: included entry keyed %s but its content hashes to %s (map-key binding — a mis-keyed entity is an identity/capability forgery vector)",
				ecerrors.ErrInvalidEntity, h, ent.ContentHash)
		}
	}
	return nil
}

// Include adds an entity to the included map, creating it if necessary.
//
// The map is keyed by content hash and every authority lookup on the RECEIVER
// resolves an entity BY that key (§3.1, §5.2/§5.5). Resolution integrity
// (§1.8, 0.8.2.23) is therefore a property of the KEYING, and this constructor
// is the one site that keys the map — so it recomputes the key from
// {type, data} rather than trusting the caller-supplied ContentHash field.
// A caller that re-stamps ContentHash from a wire key (the outbound
// authenticate-response re-key idiom in core/peer) cannot file an entity under
// an address that is not its own content: the forgery is closed at the
// constructor, not by a non-local "the source map was already validated"
// argument at each call site. This is mechanism (a) — bind the key — applied
// at the sender's single keying site, mirroring core-rust's constructor.
func (e *Envelope) Include(ent Entity) {
	if e.Included == nil {
		e.Included = make(map[hash.Hash]Entity)
	}
	// Recompute the key from the entity's own bytes, under its declared format.
	// A zero ContentHash carries algorithm 0x00 (ECFv1-SHA-256, the floor), so
	// an unstamped entity still keys correctly.
	if h, err := hash.ComputeFormat(ent.ContentHash.Algorithm, ent.Type, ent.Data); err == nil {
		ent.ContentHash = h
		e.Included[h] = ent
		return
	}
	// Recompute failed (empty/malformed entity or an unknown algorithm byte):
	// the entity is self-inconsistent and a conformant receiver rejects it at
	// ValidateAll, so it can never be resolved for authority. File as given so
	// the failure surfaces there rather than being silently dropped here.
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
