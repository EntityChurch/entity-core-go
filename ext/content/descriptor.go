package content

import (
	"encoding/hex"
	"errors"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
)

// EXTENSION-CONTENT v3.6 §5.3 — Descriptor path convention.
//
// A descriptor entity (§2.4) is bound at a dual-level invariant-pointer
// path keyed by the blob it describes, scoped to the publishing peer:
//
//	/{publisher_peer_id}/system/content/descriptor/{B_hex}/{D_hex}
//
// Where:
//
//	B_hex = hex encoding of the blob's entity hash (the anchor)
//	D_hex = hex encoding of the descriptor's own entity hash (the leaf)
//
// The dual-level keying is normative. The path embeds B_hex; the body
// carries hash(B) in its `content` field. Both MUST agree — the MUST
// integrity check at consume time.

// ErrDescriptorIntegrity is returned when the descriptor's body does not
// reference the blob in the path it was bound at — the §5.3 MUST guard
// against path corruption or accidental misbinding.
var ErrDescriptorIntegrity = errors.New("descriptor integrity check failed: body content hash does not match path anchor")

// ErrDescriptorPresence is returned when neither media_type nor type_ref
// is set on a descriptor (§2.4 presence rule MUST).
var ErrDescriptorPresence = errors.New("descriptor presence rule violated: at least one of media_type or type_ref MUST be present")

// DescriptorRef is a (publisher, descriptor) pair returned from
// LookupDescriptors. The descriptor field is the materialized entity.
type DescriptorRef struct {
	Publisher  crypto.PeerID
	Descriptor entity.Entity
}

// DescriptorPath returns the §5.3 bind path for a descriptor entity.
// Caller supplies the publisher peer ID and the descriptor entity (whose
// `content` field carries the blob anchor B). The descriptor entity must
// already have a content hash (computed via entity.NewEntity).
//
// Returns the absolute path /{publisher}/system/content/descriptor/{B_hex}/{D_hex}.
//
// {B_hex}/{D_hex} use V7 §3.5 invariant-pointer hex (format-byte included,
// 66 chars beginning `00` for ECFv1-SHA-256); §5.3 calls this a "dual-level
// invariant-pointer path convention" and EXTENSION-CONTENT §6.4.2 restates
// the same rule for the sibling namespace path. Cohort parity: Rust + Python
// emit the same 66-char form.
func DescriptorPath(publisher crypto.PeerID, blob hash.Hash, descriptorHash hash.Hash) string {
	bHex := hex.EncodeToString(blob.Bytes())
	dHex := hex.EncodeToString(descriptorHash.Bytes())
	return "/" + string(publisher) + "/system/content/descriptor/" + bHex + "/" + dHex
}

// ValidateDescriptor enforces the §2.4 presence rule and the §5.3
// integrity check. blob is the anchor the descriptor claims to describe.
// Returns nil on a valid descriptor.
func ValidateDescriptor(d types.ContentDescriptorData, blob hash.Hash) error {
	if d.MediaType == nil && d.TypeRef == nil {
		return ErrDescriptorPresence
	}
	if d.Content != blob {
		return ErrDescriptorIntegrity
	}
	return nil
}

// PublishDescriptor binds a descriptor entity at the §5.3 path after
// verifying the §2.4 presence rule and the integrity check. The
// descriptor entity is also persisted in the content store so that
// consumers fetching the leaf path can dereference it.
//
// publisher is the peer publishing the descriptor (typically the local
// peer; the path convention permits any peer to publish for any blob).
func PublishDescriptor(
	publisher crypto.PeerID,
	descriptor entity.Entity,
	contentStore store.ContentStore,
	index store.LocationIndex,
) (string, error) {
	if descriptor.Type != types.TypeContentDescriptor {
		return "", errors.New("PublishDescriptor: entity type is not system/content/descriptor")
	}
	var data types.ContentDescriptorData
	if err := ecf.Decode(descriptor.Data, &data); err != nil {
		return "", err
	}
	if err := ValidateDescriptor(data, data.Content); err != nil {
		return "", err
	}

	dHash, err := contentStore.Put(descriptor)
	if err != nil {
		return "", err
	}
	path := DescriptorPath(publisher, data.Content, dHash)
	if err := index.Set(path, dHash); err != nil {
		return "", err
	}
	return path, nil
}

// LookupDescriptors lists all descriptors bound under the publisher's
// subtree for the given blob anchor, materializes each, and filters out
// leaves whose body fails the §5.3 MUST integrity check. The trust model
// is consumer-side (§5.3 trust model) — this function returns the set of
// integrity-passing descriptors; consumer policy decides which to honor.
func LookupDescriptors(
	publishers []crypto.PeerID,
	blob hash.Hash,
	contentStore store.ContentStore,
	index store.LocationIndex,
) []DescriptorRef {
	var out []DescriptorRef
	bHex := hex.EncodeToString(blob.Bytes())
	for _, p := range publishers {
		prefix := "/" + string(p) + "/system/content/descriptor/" + bHex + "/"
		entries := index.List(prefix)
		for _, e := range entries {
			// Only enumerate leaf bindings (a leaf has a content hash;
			// directory-only entries do not).
			if e.Hash.IsZero() {
				continue
			}
			descriptor, ok := contentStore.Get(e.Hash)
			if !ok {
				continue
			}
			var data types.ContentDescriptorData
			if err := ecf.Decode(descriptor.Data, &data); err != nil {
				continue
			}
			if data.Content != blob {
				continue // integrity check — §5.3 MUST
			}
			out = append(out, DescriptorRef{Publisher: p, Descriptor: descriptor})
		}
	}
	return out
}

// ParseDescriptorPath extracts (B_hex, D_hex) from a §5.3 path. Returns
// ok=false for paths that do not match the convention. Helper for testing
// and for any caller that needs to recover the anchor without re-loading
// the entity.
func ParseDescriptorPath(path string) (bHex, dHex string, ok bool) {
	const marker = "/system/content/descriptor/"
	i := strings.Index(path, marker)
	if i < 0 {
		return "", "", false
	}
	rest := path[i+len(marker):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", "", false
	}
	bHex = rest[:slash]
	dHex = rest[slash+1:]
	if bHex == "" || dHex == "" || strings.ContainsRune(dHex, '/') {
		return "", "", false
	}
	return bHex, dHex, true
}
