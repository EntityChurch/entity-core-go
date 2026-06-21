package types

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

func TestSubstituteSourceData_RoundTrip_HTTP(t *testing.T) {
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab

	src, err := NewHTTPSource("primary-mirror", peerID, TransportEndpoint{
		TreeURLPrefix:    "https://cdn.example.com/peers/abc",
		ContentURLPrefix: "https://cdn.example.com/content",
		ContentLayout:    ContentLayoutSharded2Flat,
		TreeLeafSuffix:   ".bin",
	}, 10)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypeSubstituteSource {
		t.Errorf("type: got %q want %q", ent.Type, TypeSubstituteSource)
	}

	got, err := SubstituteSourceDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.Name != src.Name ||
		got.SubstituteType != src.SubstituteType ||
		got.SourcePeerID != src.SourcePeerID ||
		got.Priority != src.Priority ||
		got.Enabled != src.Enabled {
		t.Errorf("scalar mismatch:\n  got  %+v\n  want %+v", got, src)
	}

	ep, ok, err := got.HTTPEndpoint()
	if err != nil {
		t.Fatalf("HTTPEndpoint: %v", err)
	}
	if !ok {
		t.Fatal("HTTPEndpoint: expected endpoint present")
	}
	if ep.TreeURLPrefix != "https://cdn.example.com/peers/abc" ||
		ep.ContentURLPrefix != "https://cdn.example.com/content" ||
		ep.ContentLayout != ContentLayoutSharded2Flat ||
		ep.TreeLeafSuffix != ".bin" {
		t.Errorf("endpoint mismatch: %+v", ep)
	}
}

func TestSubstituteSourceData_LegacyFetchTemplate(t *testing.T) {
	// Older-style entry without structured endpoint — Endpoint is empty,
	// FetchTemplate carries the legacy URL template. HTTPEndpoint
	// should return (zero, false, nil) for these.
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab

	src := SubstituteSourceData{
		Name:           "legacy-mirror",
		SubstituteType: SubstituteTypeHTTP,
		SourcePeerID:   peerID,
		FetchTemplate:  "https://legacy.example.com/{hash}",
		Priority:       100,
		Enabled:        true,
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}

	got, err := SubstituteSourceDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.FetchTemplate != src.FetchTemplate {
		t.Errorf("fetch_template lost: got %q want %q", got.FetchTemplate, src.FetchTemplate)
	}

	_, present, err := got.HTTPEndpoint()
	if err != nil {
		t.Fatalf("HTTPEndpoint err: %v", err)
	}
	if present {
		t.Errorf("legacy entry: HTTPEndpoint should report absent, got present")
	}
}

func TestSubstituteSourceData_PathPrefix(t *testing.T) {
	// Sanity: the path prefix constant matches the spec wording (§2.1).
	want := "system/substitute/sources/"
	if SubstituteSourcePathPrefix != want {
		t.Errorf("path prefix: got %q want %q", SubstituteSourcePathPrefix, want)
	}
}

func TestSubstituteTryRequestData_RoundTrip(t *testing.T) {
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab

	src, err := NewHTTPSource("primary-mirror", peerID, TransportEndpoint{
		TreeURLPrefix:    "https://cdn.example.com/peers/abc",
		ContentURLPrefix: "https://cdn.example.com/content",
		ContentLayout:    ContentLayoutSharded2Flat,
	}, 10)
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	entryEnt, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity entry: %v", err)
	}
	target := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	target.Digest[0] = 0xef

	req := SubstituteTryRequestData{
		Entry: entryEnt,
		Hash:  target,
	}
	reqEnt, err := req.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity try-request: %v", err)
	}
	if reqEnt.Type != TypeSubstituteTryRequest {
		t.Errorf("type: got %q want %q", reqEnt.Type, TypeSubstituteTryRequest)
	}

	got, err := SubstituteTryRequestDataFromEntity(reqEnt)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.Hash != target {
		t.Errorf("hash: got %v want %v", got.Hash, target)
	}
	if got.Entry.Type != TypeSubstituteSource {
		t.Errorf("entry type: got %q want %q", got.Entry.Type, TypeSubstituteSource)
	}
	if got.Entry.ContentHash != entryEnt.ContentHash {
		t.Errorf("entry hash: got %v want %v", got.Entry.ContentHash, entryEnt.ContentHash)
	}
	// Verify the carried source decodes cleanly.
	innerSrc, err := SubstituteSourceDataFromEntity(got.Entry)
	if err != nil {
		t.Fatalf("inner source decode: %v", err)
	}
	if innerSrc.Name != "primary-mirror" || innerSrc.SubstituteType != SubstituteTypeHTTP {
		t.Errorf("inner source mismatch: %+v", innerSrc)
	}
}

func TestSubstituteSourceData_Supersedes(t *testing.T) {
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab
	prior := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	prior.Digest[0] = 0xcd

	src := SubstituteSourceData{
		Name:           "rotated-mirror",
		SubstituteType: SubstituteTypeHTTP,
		SourcePeerID:   peerID,
		Priority:       10,
		Enabled:        true,
		Supersedes:     &prior,
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	got, err := SubstituteSourceDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.Supersedes == nil || *got.Supersedes != prior {
		t.Errorf("supersedes mismatch: got %v want %v", got.Supersedes, prior)
	}
}
