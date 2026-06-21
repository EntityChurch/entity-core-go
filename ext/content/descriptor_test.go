package content

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// blob1 and blob2 are two distinct synthetic blob hashes used as anchors
// in descriptor tests. They do not need to refer to real blobs in the
// content store — the §5.3 integrity check is a body↔path identity check
// over the anchor bytes, not a content-store dereference.
func blob1(t *testing.T) hash.Hash {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0x01
	}
	h, err := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, b...))
	if err != nil {
		t.Fatalf("blob1: %v", err)
	}
	return h
}

func blob2(t *testing.T) hash.Hash {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0x02
	}
	h, err := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, b...))
	if err != nil {
		t.Fatalf("blob2: %v", err)
	}
	return h
}

// TestDescriptorPresenceRule — §2.4 MUST. At least one of media_type or
// type_ref must be present. A descriptor with neither set is invalid.
func TestDescriptorPresenceRule(t *testing.T) {
	b := blob1(t)
	d := types.ContentDescriptorData{Content: b}
	if err := ValidateDescriptor(d, b); !errors.Is(err, ErrDescriptorPresence) {
		t.Errorf("ValidateDescriptor with no media_type/type_ref: err = %v, want ErrDescriptorPresence", err)
	}

	mt := "application/json"
	d.MediaType = &mt
	if err := ValidateDescriptor(d, b); err != nil {
		t.Errorf("ValidateDescriptor with media_type: err = %v, want nil", err)
	}

	// type_ref alone also satisfies presence
	d = types.ContentDescriptorData{Content: b}
	ref := b
	d.TypeRef = &ref
	if err := ValidateDescriptor(d, b); err != nil {
		t.Errorf("ValidateDescriptor with type_ref: err = %v, want nil", err)
	}
}

// TestDescriptorIntegrityCheck — §5.3 MUST. descriptor.data.content
// MUST equal the path anchor; mismatch is rejected.
func TestDescriptorIntegrityCheck(t *testing.T) {
	b1 := blob1(t)
	b2 := blob2(t)

	mt := "application/json"
	d := types.ContentDescriptorData{Content: b1, MediaType: &mt}

	if err := ValidateDescriptor(d, b1); err != nil {
		t.Errorf("matching anchor: err = %v, want nil", err)
	}
	if err := ValidateDescriptor(d, b2); !errors.Is(err, ErrDescriptorIntegrity) {
		t.Errorf("mismatched anchor: err = %v, want ErrDescriptorIntegrity", err)
	}
}

// TestDescriptorPath — §5.3 path shape. /{publisher}/system/content/descriptor/{B_hex}/{D_hex}
func TestDescriptorPath(t *testing.T) {
	kp, _ := crypto.Generate()
	b := blob1(t)
	d := blob2(t)

	path := DescriptorPath(kp.PeerID(), b, d)

	wantBHex := hex.EncodeToString(b.Bytes())
	wantDHex := hex.EncodeToString(d.Bytes())
	wantPath := "/" + string(kp.PeerID()) + "/system/content/descriptor/" + wantBHex + "/" + wantDHex
	if path != wantPath {
		t.Errorf("path = %q, want %q", path, wantPath)
	}

	// Round-trip parse
	bHex, dHex, ok := ParseDescriptorPath(path)
	if !ok {
		t.Fatalf("ParseDescriptorPath(%q) = ok=false", path)
	}
	if bHex != wantBHex || dHex != wantDHex {
		t.Errorf("parse: bHex=%q dHex=%q, want bHex=%q dHex=%q", bHex, dHex, wantBHex, wantDHex)
	}
}

// TestPublishDescriptorRoundTrip — publish a descriptor, look it up via
// LookupDescriptors, get back exactly one ref to the same descriptor.
func TestPublishDescriptorRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	b := blob1(t)
	mt := "image/png"
	descData := types.ContentDescriptorData{Content: b, MediaType: &mt}
	descEnt, err := descData.ToEntity()
	if err != nil {
		t.Fatalf("descriptor ToEntity: %v", err)
	}

	path, err := PublishDescriptor(env.peerID, descEnt, env.cs, env.nsLI)
	if err != nil {
		t.Fatalf("PublishDescriptor: %v", err)
	}
	if !strings.Contains(path, "/system/content/descriptor/") {
		t.Errorf("path %q doesn't carry the §5.3 convention marker", path)
	}

	refs := LookupDescriptors([]crypto.PeerID{env.peerID}, b, env.cs, env.nsLI)
	if len(refs) != 1 {
		t.Fatalf("LookupDescriptors: got %d refs, want 1", len(refs))
	}
	if refs[0].Descriptor.ContentHash != descEnt.ContentHash {
		t.Errorf("looked-up descriptor hash differs from published")
	}
}

// TestLookupDescriptorsFiltersTamperedBindings — §5.3 MUST in action. A
// descriptor whose body points at a different blob (path corruption /
// misbinding) is filtered out by the integrity check at lookup time.
func TestLookupDescriptorsFiltersTamperedBindings(t *testing.T) {
	env := newTestEnv(t)
	b1 := blob1(t)
	b2 := blob2(t)

	// Build a descriptor that legitimately describes b2.
	mt := "application/pdf"
	descData := types.ContentDescriptorData{Content: b2, MediaType: &mt}
	descEnt, err := descData.ToEntity()
	if err != nil {
		t.Fatalf("descriptor ToEntity: %v", err)
	}
	descHash, err := env.cs.Put(descEnt)
	if err != nil {
		t.Fatalf("Put descriptor: %v", err)
	}

	// Bind it under b1's anchor — path-corruption / misbinding scenario.
	tamperedPath := DescriptorPath(env.peerID, b1, descHash)
	if err := env.nsLI.Set(tamperedPath, descHash); err != nil {
		t.Fatalf("Set tampered binding: %v", err)
	}

	// Lookup against b1 should filter out the tampered descriptor.
	refs := LookupDescriptors([]crypto.PeerID{env.peerID}, b1, env.cs, env.nsLI)
	if len(refs) != 0 {
		t.Errorf("tampered binding survived lookup: got %d refs, want 0", len(refs))
	}

	// Lookup against b2 finds nothing — descriptor wasn't bound under b2.
	refs = LookupDescriptors([]crypto.PeerID{env.peerID}, b2, env.cs, env.nsLI)
	if len(refs) != 0 {
		t.Errorf("descriptor not bound under b2 yet returned: got %d refs", len(refs))
	}
}
