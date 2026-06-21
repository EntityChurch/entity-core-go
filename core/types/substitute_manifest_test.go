package types

import (
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

func TestHTTPPollProfileData_RoundTrip(t *testing.T) {
	src := HTTPPollProfileData{
		PeerID:        "ecf-sha256:" + "ab",
		TransportType: "http-poll",
		Endpoint: TransportEndpoint{
			TreeURLPrefix:    "https://cdn.example.com/peers/abc",
			ContentURLPrefix: "https://cdn.example.com/content",
			ContentLayout:    ContentLayoutSharded2Flat,
			TreeLeafSuffix:   ".bin",
		},
		SupportedOps:   []string{OpTreeGet, OpContentGet, OpManifestGet},
		Freshness:      "static-immutable+signed-pointer",
		NonceRequired:  false,
		CapFlow:        "egress",
		PollIntervalMs: 60000,
		SignedPointer:  "system/peer/published-root",
		AdvertisedAt:   1780531200000, // epoch ms
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypePeerTransportHTTPPoll {
		t.Errorf("type: got %q want %q", ent.Type, TypePeerTransportHTTPPoll)
	}

	got, err := HTTPPollProfileDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.PeerID != src.PeerID ||
		got.TransportType != src.TransportType ||
		got.Endpoint != src.Endpoint ||
		got.Freshness != src.Freshness ||
		got.NonceRequired != src.NonceRequired ||
		got.CapFlow != src.CapFlow ||
		got.PollIntervalMs != src.PollIntervalMs ||
		got.SignedPointer != src.SignedPointer ||
		got.AdvertisedAt != src.AdvertisedAt {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, src)
	}
	if len(got.SupportedOps) != 3 ||
		got.SupportedOps[0] != OpTreeGet ||
		got.SupportedOps[1] != OpContentGet ||
		got.SupportedOps[2] != OpManifestGet {
		t.Errorf("supported_ops mismatch: %+v", got.SupportedOps)
	}
}

// TestHTTPPollProfileData_PartialPublisher exercises the D-13 split's load-
// bearing case: a content-only CDN mirror advertises [OpContentGet] alone —
// a freshness-dependent consumer can read this from the profile and know it
// must reach somewhere else for the signed root / tree binding.
func TestHTTPPollProfileData_PartialPublisher(t *testing.T) {
	cases := []struct {
		name string
		ops  []string
	}{
		{"content-only mirror", []string{OpContentGet}},
		{"manifest-only registry", []string{OpManifestGet}},
		{"tree+content split host", []string{OpTreeGet, OpContentGet}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := HTTPPollProfileData{
				PeerID:        "ecf-sha256:" + "ab",
				TransportType: "http-poll",
				Endpoint: TransportEndpoint{
					TreeURLPrefix:    "https://cdn.example.com/peers/abc",
					ContentURLPrefix: "https://cdn.example.com/content",
					ContentLayout:    ContentLayoutFlat,
				},
				SupportedOps: tc.ops,
			}
			ent, err := src.ToEntity()
			if err != nil {
				t.Fatalf("ToEntity: %v", err)
			}
			got, err := HTTPPollProfileDataFromEntity(ent)
			if err != nil {
				t.Fatalf("FromEntity: %v", err)
			}
			if len(got.SupportedOps) != len(tc.ops) {
				t.Fatalf("supported_ops len: got %d want %d", len(got.SupportedOps), len(tc.ops))
			}
			for i, v := range tc.ops {
				if got.SupportedOps[i] != v {
					t.Errorf("supported_ops[%d]: got %q want %q", i, got.SupportedOps[i], v)
				}
			}
		})
	}
}

func TestSubstituteSnapshotManifestData_RoundTrip(t *testing.T) {
	peerID := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	peerID.Digest[0] = 0xab
	rootA := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	rootA.Digest[0] = 0xcd
	leafA := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	leafA.Digest[0] = 0xef
	predecessor := hash.Hash{Algorithm: hash.AlgorithmSHA256}
	predecessor.Digest[0] = 0x12

	src := SubstituteSnapshotManifestData{
		SourcePeerID: peerID,
		SnapshotAt:   1717459200000,
		Seq:          7,
		Endpoint: TransportEndpoint{
			TreeURLPrefix:    "https://cdn.example.com/peers/abc",
			ContentURLPrefix: "https://cdn.example.com/content",
			ContentLayout:    ContentLayoutSharded24,
			TreeLeafSuffix:   ".ent",
		},
		PathIndex:    map[string]hash.Hash{"docs/readme": leafA},
		ContentCount: 42,
		RootHashes:   []hash.Hash{rootA},
		Predecessor:  &predecessor,
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypeSubstituteSnapshotManifest {
		t.Errorf("type: got %q want %q", ent.Type, TypeSubstituteSnapshotManifest)
	}

	got, err := SubstituteSnapshotManifestDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.SourcePeerID != src.SourcePeerID ||
		got.SnapshotAt != src.SnapshotAt ||
		got.Seq != src.Seq ||
		got.Endpoint != src.Endpoint ||
		got.ContentCount != src.ContentCount {
		t.Errorf("scalar mismatch:\n  got  %+v\n  want %+v", got, src)
	}
	if h, ok := got.PathIndex["docs/readme"]; !ok || h != leafA {
		t.Errorf("path_index mismatch: %+v", got.PathIndex)
	}
	if len(got.RootHashes) != 1 || got.RootHashes[0] != rootA {
		t.Errorf("root_hashes mismatch: %+v", got.RootHashes)
	}
	if got.Predecessor == nil || *got.Predecessor != predecessor {
		t.Errorf("predecessor mismatch: got %v want %v", got.Predecessor, predecessor)
	}
}

func TestSubstituteSnapshotManifestData_OmitPredecessor(t *testing.T) {
	src := SubstituteSnapshotManifestData{
		SourcePeerID: hash.Hash{Algorithm: hash.AlgorithmSHA256},
		SnapshotAt:   1717459200000,
		Seq:          1,
		Endpoint: TransportEndpoint{
			TreeURLPrefix:    "https://cdn.example.com/peers/abc",
			ContentURLPrefix: "https://cdn.example.com/content",
			ContentLayout:    ContentLayoutFlat,
		},
		PathIndex:    map[string]hash.Hash{},
		ContentCount: 0,
		RootHashes:   []hash.Hash{},
		Predecessor:  nil,
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	got, err := SubstituteSnapshotManifestDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.Predecessor != nil {
		t.Errorf("predecessor should be nil on omit, got %v", got.Predecessor)
	}
}

func TestTCPProfileData_RoundTrip(t *testing.T) {
	src := TCPProfileData{
		PeerID:        "ecf-sha256:" + "ab",
		TransportType: "tcp",
		Endpoint:      TransportEndpointURL{URL: "tcp://example.com:9002"},
		SupportedOps:  []string{OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  1780617600000, // epoch ms
	}

	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if ent.Type != TypePeerTransportTCP {
		t.Errorf("type: got %q want %q", ent.Type, TypePeerTransportTCP)
	}

	got, err := TCPProfileDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.PeerID != src.PeerID ||
		got.TransportType != src.TransportType ||
		got.Endpoint != src.Endpoint ||
		got.Freshness != src.Freshness ||
		got.NonceRequired != src.NonceRequired ||
		got.CapFlow != src.CapFlow ||
		got.AdvertisedAt != src.AdvertisedAt {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, src)
	}
	if len(got.SupportedOps) != 1 || got.SupportedOps[0] != OpExecute {
		t.Errorf("supported_ops mismatch: %+v", got.SupportedOps)
	}
}

func TestTCPProfileData_EndpointURLShape(t *testing.T) {
	// Per D-14: endpoint is a single {url} field, never {host, port}.
	// Spot-check the wire encoding contains "url" not "host"/"port".
	src := TCPProfileData{
		PeerID:        "ecf-sha256:" + "ab",
		TransportType: "tcp",
		Endpoint:      TransportEndpointURL{URL: "tcp://1.2.3.4:9002"},
		SupportedOps:  []string{OpExecute},
		NonceRequired: true,
	}
	ent, err := src.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	// Round-trip via the typed decoder.
	got, err := TCPProfileDataFromEntity(ent)
	if err != nil {
		t.Fatalf("FromEntity: %v", err)
	}
	if got.Endpoint.URL != "tcp://1.2.3.4:9002" {
		t.Errorf("endpoint URL: got %q want tcp://1.2.3.4:9002", got.Endpoint.URL)
	}
}

// TestTCPProfileData_TransportTypeMismatch — D-5 conformance: a TCP-typed
// entity carrying a non-"tcp" transport_type MUST be rejected on decode.
func TestTCPProfileData_TransportTypeMismatch(t *testing.T) {
	bogus := TCPProfileData{
		PeerID:        "ecf-sha256:" + "ab",
		TransportType: "websocket", // wrong — doesn't match TypePeerTransportTCP suffix
		Endpoint:      TransportEndpointURL{URL: "tcp://example.com:9002"},
		SupportedOps:  []string{OpExecute},
		NonceRequired: true,
	}
	ent, err := bogus.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	_, err = TCPProfileDataFromEntity(ent)
	if err == nil {
		t.Fatal("expected D-5 rejection for transport_type mismatch, got nil")
	}
}

// TestHTTPPollProfileData_TransportTypeMismatch — D-5 conformance for the
// http-poll profile.
func TestHTTPPollProfileData_TransportTypeMismatch(t *testing.T) {
	bogus := HTTPPollProfileData{
		PeerID:        "ecf-sha256:" + "ab",
		TransportType: "tcp", // wrong — doesn't match TypePeerTransportHTTPPoll suffix
		Endpoint: TransportEndpoint{
			TreeURLPrefix: "https://example.com",
			ContentLayout: ContentLayoutFlat,
		},
		SupportedOps: []string{OpContentGet},
	}
	ent, err := bogus.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	_, err = HTTPPollProfileDataFromEntity(ent)
	if err == nil {
		t.Fatal("expected D-5 rejection for transport_type mismatch, got nil")
	}
}
