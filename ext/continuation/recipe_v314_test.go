package continuation

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// TestV314RecipeShape verifies the v3.14 mirror recipe produces a put-request
// shape that decodes cleanly into types.PutRequestData with:
//   - entity: the full entity at notification.hash (deref'd from included)
//   - expected_hash: notification.previous_hash (or nil when absent)
//
// This is the end-to-end shape check ahead of running the cycle test.
func TestV314RecipeShape(t *testing.T) {
	// Build the payload entity (what would have arrived in envelope.included).
	rawData, _ := ecf.Encode(map[string]interface{}{
		"seq":     uint64(0),
		"content": "cycle-write-0",
	})
	payloadEnt, err := entity.NewEntity("test/cycle-doc", cbor.RawMessage(rawData))
	if err != nil {
		t.Fatal(err)
	}
	included := map[hash.Hash]entity.Entity{payloadEnt.ContentHash: payloadEnt}

	// Build a fake "created" event notification (previous_hash absent).
	notifData := types.InboxNotificationData{
		SubscriptionID: "sub-1",
		Event:          "created",
		URI:            "/peer-src/system/validate/cycle/doc",
		Hash:           payloadEnt.ContentHash,
		// PreviousHash zero — omitzero, won't be encoded
	}
	notifEntity, _ := notifData.ToEntity()

	// Apply the recipe transform — same as cycle_test.go's mirror cont.
	tr := &types.ContinuationTransformData{
		Select: map[string]string{
			"entity":        "hash",
			"expected_hash": "previous_hash",
		},
		TransformOps: []types.ContinuationTransformOpData{
			{Op: "deref_included", Field: "entity"},
		},
	}

	final := applyTransform(notifEntity.Data, tr, included)

	// Decode as PutRequestData — what the put handler will do.
	var putReq types.PutRequestData
	if err := ecf.Decode(final, &putReq); err != nil {
		t.Fatalf("PutRequestData decode failed: %v\n  final bytes: %x", err, []byte(final))
	}

	// expected_hash should be nil for a created event (previous_hash absent).
	if putReq.ExpectedHash != nil && !putReq.ExpectedHash.IsZero() {
		t.Fatalf("expected nil/zero ExpectedHash for created event, got %v", putReq.ExpectedHash)
	}

	// entity should decode as the original payload entity.
	if len(putReq.Entity) == 0 {
		t.Fatal("PutRequest.Entity is empty after deref")
	}
	var got entity.Entity
	if err := ecf.Decode(putReq.Entity, &got); err != nil {
		t.Fatalf("entity field decode failed: %v\n  bytes: %x", err, []byte(putReq.Entity))
	}
	if got.ContentHash != payloadEnt.ContentHash {
		t.Fatalf("entity hash mismatch: got %s want %s", got.ContentHash, payloadEnt.ContentHash)
	}
	if got.Type != "test/cycle-doc" {
		t.Fatalf("entity type mismatch: %s", got.Type)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("entity validation failed: %v", err)
	}
}

// Updated event: previous_hash is non-zero, should thread through to
// PutRequest.ExpectedHash.
func TestV314RecipeShape_Updated(t *testing.T) {
	rawOldData, _ := ecf.Encode(map[string]interface{}{"seq": uint64(0)})
	oldEnt, _ := entity.NewEntity("test/cycle-doc", cbor.RawMessage(rawOldData))

	rawNewData, _ := ecf.Encode(map[string]interface{}{"seq": uint64(1)})
	newEnt, _ := entity.NewEntity("test/cycle-doc", cbor.RawMessage(rawNewData))
	included := map[hash.Hash]entity.Entity{newEnt.ContentHash: newEnt}

	notifData := types.InboxNotificationData{
		SubscriptionID: "sub-1",
		Event:          "updated",
		URI:            "/peer-src/system/validate/cycle/doc",
		Hash:           newEnt.ContentHash,
		PreviousHash:   oldEnt.ContentHash,
	}
	notifEntity, _ := notifData.ToEntity()

	tr := &types.ContinuationTransformData{
		Select: map[string]string{
			"entity":        "hash",
			"expected_hash": "previous_hash",
		},
		TransformOps: []types.ContinuationTransformOpData{
			{Op: "deref_included", Field: "entity"},
		},
	}
	final := applyTransform(notifEntity.Data, tr, included)

	var putReq types.PutRequestData
	if err := ecf.Decode(final, &putReq); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if putReq.ExpectedHash == nil {
		t.Fatal("expected non-nil ExpectedHash for updated event")
	}
	if *putReq.ExpectedHash != oldEnt.ContentHash {
		t.Fatalf("ExpectedHash mismatch: got %s want %s", putReq.ExpectedHash, oldEnt.ContentHash)
	}

	var got entity.Entity
	if err := ecf.Decode(putReq.Entity, &got); err != nil {
		t.Fatalf("entity decode failed: %v", err)
	}
	if got.ContentHash != newEnt.ContentHash {
		t.Fatalf("entity hash mismatch: got %s want %s", got.ContentHash, newEnt.ContentHash)
	}
}
