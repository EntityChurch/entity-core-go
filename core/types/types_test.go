package types

import (
	"reflect"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

const testPeerID = "2KZFtestpeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestHelloRoundtrip(t *testing.T) {
	d := HelloData{
		PeerID:    testPeerID,
		Nonce:     []byte("nonce123456789012345678901234567"),
		Protocols: []string{"entity-core/1.0"},
		Timestamp: 1737900000000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeHello {
		t.Fatalf("expected type %s, got %s", TypeHello, e.Type)
	}

	decoded, err := HelloDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PeerID != d.PeerID {
		t.Fatalf("PeerID: expected %s, got %s", d.PeerID, decoded.PeerID)
	}
	if decoded.Timestamp != d.Timestamp {
		t.Fatalf("Timestamp: expected %d, got %d", d.Timestamp, decoded.Timestamp)
	}
}

func TestAuthenticateRoundtrip(t *testing.T) {
	d := AuthenticateData{
		PeerID:    testPeerID,
		PublicKey: make([]byte, 32),
		KeyType:   "ed25519",
		Nonce:     make([]byte, 32),
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeAuthenticate {
		t.Fatalf("expected type %s, got %s", TypeAuthenticate, e.Type)
	}

	decoded, err := AuthenticateDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.KeyType != "ed25519" {
		t.Fatalf("KeyType: expected ed25519, got %s", decoded.KeyType)
	}
}

func TestExecuteRoundtrip(t *testing.T) {
	d := ExecuteData{
		RequestID: "req-1",
		URI:       "entity://" + testPeerID + "/system/tree",
		Operation: "get",
		Params:    []byte{0xA0}, // empty CBOR map
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeExecute {
		t.Fatalf("expected type %s, got %s", TypeExecute, e.Type)
	}

	decoded, err := ExecuteDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID != "req-1" {
		t.Fatalf("RequestID: expected req-1, got %s", decoded.RequestID)
	}
}

func TestExecuteResponseRoundtrip(t *testing.T) {
	d := ExecuteResponseData{
		RequestID: "req-1",
		Status:    200,
		Result:    []byte{0xA0},
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeExecuteResponse {
		t.Fatalf("expected type %s, got %s", TypeExecuteResponse, e.Type)
	}

	decoded, err := ExecuteResponseDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != 200 {
		t.Fatalf("Status: expected 200, got %d", decoded.Status)
	}
}

func TestErrorRoundtrip(t *testing.T) {
	d := ErrorData{
		Code:    "not_found",
		Message: "entity not found",
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeError {
		t.Fatalf("expected type %s, got %s", TypeError, e.Type)
	}

	decoded, err := ErrorDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Code != "not_found" {
		t.Fatalf("Code: expected not_found, got %s", decoded.Code)
	}
}

func TestIdentityRoundtrip(t *testing.T) {
	d := PeerData{
		PublicKey: make([]byte, 32),
		KeyType:   "ed25519",
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypePeer {
		t.Fatalf("expected type %s, got %s", TypePeer, e.Type)
	}
}

func TestSignatureRoundtrip(t *testing.T) {
	d := SignatureData{
		Target:    hash.Hash{Algorithm: hash.AlgorithmSHA256},
		Signer:    hash.Hash{Algorithm: hash.AlgorithmSHA256},
		Algorithm: "ed25519",
		Signature: make([]byte, 64),
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeSignature {
		t.Fatalf("expected type %s, got %s", TypeSignature, e.Type)
	}

	decoded, err := SignatureDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Algorithm != "ed25519" {
		t.Fatalf("Algorithm: expected ed25519, got %s", decoded.Algorithm)
	}
}

func TestCapabilityTokenRoundtrip(t *testing.T) {
	d := CapabilityTokenData{
		Grants: []GrantEntry{
			{
				Handlers:   CapabilityScope{Include: []string{"system/tree"}},
				Resources:  CapabilityScope{Include: []string{"system/tree/*"}},
				Operations: CapabilityScope{Include: []string{"get"}},
			},
		},
		Granter:   SingleSigGranter(hash.Hash{Algorithm: hash.AlgorithmSHA256}),
		Grantee:   hash.Hash{Algorithm: hash.AlgorithmSHA256},
		CreatedAt: 1737900000000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeCapToken {
		t.Fatalf("expected type %s, got %s", TypeCapToken, e.Type)
	}

	decoded, err := CapabilityTokenDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(decoded.Grants))
	}
	if decoded.CreatedAt != 1737900000000 {
		t.Fatalf("CreatedAt: expected 1737900000000, got %d", decoded.CreatedAt)
	}
}

func TestBoundsRoundtrip(t *testing.T) {
	ttl := uint64(10)
	d := BoundsData{
		TTL:     &ttl,
		ChainID: "chain-1",
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeBounds {
		t.Fatalf("expected type %s, got %s", TypeBounds, e.Type)
	}

	decoded, err := BoundsDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TTL == nil || *decoded.TTL != 10 {
		t.Fatalf("TTL: expected 10, got %v", decoded.TTL)
	}
}

func TestGetRequestRoundtrip(t *testing.T) {
	d := GetRequestData{
		Mode: "entity",
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeTreeGetRequest {
		t.Fatalf("expected type %s, got %s", TypeTreeGetRequest, e.Type)
	}

	decoded, err := GetRequestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != "entity" {
		t.Fatalf("Mode: expected entity, got %s", decoded.Mode)
	}
}

func TestPutRequestRoundtrip(t *testing.T) {
	d := PutRequestData{
		Entity: []byte{0xA0},
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeTreePutRequest {
		t.Fatalf("expected type %s, got %s", TypeTreePutRequest, e.Type)
	}
}

func TestPutRequestExpectedHashRoundtrip(t *testing.T) {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	for i := 0; i < hash.SHA256DigestSize; i++ {
		h.Digest[i] = byte(i)
	}
	d := PutRequestData{
		Entity:       []byte{0xA0},
		ExpectedHash: &h,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := PutRequestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ExpectedHash == nil {
		t.Fatal("ExpectedHash lost in roundtrip")
	}
	if *decoded.ExpectedHash != h {
		t.Fatalf("ExpectedHash mismatch: got %+v want %+v", *decoded.ExpectedHash, h)
	}

	// Absent ExpectedHash must not appear in encoded output (omitempty).
	dNoCAS := PutRequestData{Entity: []byte{0xA0}}
	e2, err := dNoCAS.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	decoded2, err := PutRequestDataFromEntity(e2)
	if err != nil {
		t.Fatal(err)
	}
	if decoded2.ExpectedHash != nil {
		t.Fatalf("ExpectedHash should be nil when absent, got %+v", *decoded2.ExpectedHash)
	}
}

func TestTrackingConfigRoundtrip(t *testing.T) {
	d := TrackingConfigData{
		Prefix:  "/peer/project/",
		Enabled: true,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeTreeTrackingConfig {
		t.Fatalf("expected type %s, got %s", TypeTreeTrackingConfig, e.Type)
	}
	decoded, err := TrackingConfigDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Prefix != d.Prefix || decoded.Enabled != d.Enabled {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", decoded, d)
	}
}

func TestListingRoundtrip(t *testing.T) {
	d := ListingData{
		Path:    "local/",
		Entries: map[string]interface{}{"files": nil, "docs": nil},
		Count:   2,
		Offset:  0,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeTreeListing {
		t.Fatalf("expected type %s, got %s", TypeTreeListing, e.Type)
	}

	decoded, err := ListingDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Count != 2 {
		t.Fatalf("Count: expected 2, got %d", decoded.Count)
	}
	if decoded.NextPage != nil {
		t.Fatalf("NextPage: expected nil on single-page listing, got %v", decoded.NextPage)
	}
}

// TestListingRoundtripWithNextPage verifies V7 §3.9 / 7.57 next_page
// field — present on intermediate pages of a paginated listing, omitted
// (omitempty) on the last/only page. EXTENSION-NETWORK Amendment 5.
func TestListingRoundtripWithNextPage(t *testing.T) {
	h, err := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, []byte("0123456789abcdef0123456789abcdef")...))
	if err != nil {
		t.Fatal(err)
	}
	d := ListingData{
		Path:     "local/",
		Entries:  map[string]interface{}{"files": nil, "docs": nil},
		Count:    100,
		Offset:   0,
		NextPage: &h,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ListingDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NextPage == nil {
		t.Fatal("NextPage: expected hash on paginated head, got nil")
	}
	if *decoded.NextPage != h {
		t.Fatalf("NextPage: roundtrip mismatch")
	}
}

func TestHandlerRoundtrip(t *testing.T) {
	d := HandlerData{
		Interface: "system/handler/system/tree",
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeHandler {
		t.Fatalf("expected type %s, got %s", TypeHandler, e.Type)
	}

	decoded, err := HandlerDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Interface != "system/handler/system/tree" {
		t.Fatalf("Interface: expected system/handler/system/tree, got %s", decoded.Interface)
	}
}

func TestHandlerManifestRoundtrip(t *testing.T) {
	d := HandlerManifestData{
		Pattern: "system/tree",
		Name:    "tree",
		Operations: map[string]HandlerOperationSpec{
			"get": {InputType: "system/tree/get-request"},
			"put": {InputType: "system/tree/put-request"},
		},
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeHandlerManifest {
		t.Fatalf("expected type %s, got %s", TypeHandlerManifest, e.Type)
	}

	decoded, err := HandlerManifestDataFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Pattern != "system/tree" {
		t.Fatalf("Pattern: expected system/tree, got %s", decoded.Pattern)
	}
}

func TestRegistryCoreTypes(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	defs := r.All()

	// RegisterCoreTypes produces the core type set (handler-specific types added separately).
	// PROPOSAL-PATH-AS-RESOURCE-HYGIENE eliminated three wrappers
	// (system/compute/uninstall-request, system/continuation/install-request,
	// system/handler/unregister-request) — counts dropped by 3.
	// PROPOSAL-DELETION-MARKERS A.8 added `system/deletion-marker` — count +1.
	// EXTENSION-CONTINUATION v1.9 G1 added `system/continuation/transform-op`
	// (§2.2, §7.3) — count +1.
	// EXTENSION-DURABILITY v0.1 (exploratory extension; extracted from
	// EXTENSION-INBOX v5.7/v5.8 §10) carries system/durability-
	// request, system/durability-result, system/durability-advertisement —
	// count +3. The types are registered unconditionally on the Go side as
	// reference-implementation surface.
	// EXTENSION-COMPUTE v3.14 (PROPOSAL-COMPUTE-STANDARD-IR-FLOOR) added six
	// types: compute/index, compute/length, compute/numeric-cast (N.1/N.4
	// inline expression types) and system/compute/{map,filter,fold}-args (N.2
	// pinned args types for collection/store builtins) — count +6.
	// EXTENSION-COMPUTE v3.19b §2.3 added system/compute/scope-binding (the
	// kind-tagged scope binding value model, N1/N3) — count +1.
	// EXTENSION-TYPE v1.1 added 24 types: 11 standard constraint types
	// (system/type/constraint/{min,max,min_length,max_length,min_count,
	// max_count,pattern,one_of,not_one_of,format,type_pattern}), 2 constraint
	// dispatch envelopes (validate-request, validate-result), 1 violation, 1
	// field-comparison, 1 field-incompatibility, and 9 analysis-op types
	// (compare-request/result, compatible-request, compatibility-report,
	// converge-request, adopt-request, reconcile-request/result) — count +24.
	// EXTENSION-CONTENT v3.6 §2 added system/content/{blob,chunk,descriptor}
	// — count +3.
	// Storage-substitute substrate (NETWORK §6.5.3 + STORAGE-SUBSTITUTE-HTTP
	// §3-RES.2 + STORAGE-SUBSTITUTE-SOURCES §2.1) added five — shared
	// system/substitute/endpoint block, system/peer/transport/http-poll
	// profile, system/substitute/snapshot-manifest, system/substitute/source,
	// and system/substitute/try-request — count +5.
	// V7 v7.62 capability handler amendment added three input types —
	// system/capability/revoke-request, system/capability/delegate-request,
	// system/capability/policy-entry — count +3.
	// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 (LOCKED) added
	// system/peer/published-root — count +1.
	// EXTENSION-REGISTRY v1.0 added 18: 5 entity types (binding, revocation,
	// resolver-config, local-name-config, resolution-log) + 13 inner / request /
	// result types (resolver-chain-entry, pinned-entry, dispatch-entry,
	// local-name/list-entry, resolve-request, resolve-result, invalidate-cache-
	// request, local-name/{bind,unbind,list,update-transports}-request,
	// local-name/{bind,list}-result).
	// EXTENSION-DISCOVERY v1.0 D1 + D3 adds 7: candidate, decision,
	// identity-claim, scan-result, scan-request, announce-request,
	// announce-stop-request → 171.
	// EXTENSION-RELAY v1.0 R1 adds 8: forward-request, store-entry,
	// advertise, advertise-limits, forward-result, put-result, poll-request,
	// poll-result → 179.
	// EXTENSION-RELAY v1.0 R6/R7 fold (arch faf3fa9) adds 2: §3.5
	// system/peer/inbox-relay + system/peer/inbox-relay-entry → 181 total.
	// EXTENSION-ROUTE v1 storage plane (PROPOSAL-EXTENSION-ROUTE) adds
	// system/route → 182 total.
	// EXTENSION-REGISTRY §6a.9 peer-issued live-registration adds 4
	// (register-request, issuer-policy, revoke-request, renew-request) → 186.
	// EXTENSION-ENCRYPTION v1.0 adds 7: system/encrypted, encryption-pubkey,
	// encryption/handoff, encryption/revocation, encryption/key-backup, plus
	// the two registry-internal sub-shape names encryption/kdf-params and
	// encryption/wrapped-key (Go-only handles for §6.1 / §8.2 anonymous
	// inline shapes — other impls don't need to mirror the names) → 193.
	// EXTENSION-ENCRYPTION v2.5 R3 ENC-KAT-INNER adds system/note → 194.
	if len(defs) != 194 {
		names := make([]string, len(defs))
		for i, d := range defs {
			names[i] = d.Name
		}
		t.Fatalf("expected 194 core type definitions, got %d: %v", len(defs), names)
	}

	seen := make(map[string]bool)
	for _, d := range defs {
		if d.Name == "" {
			t.Fatal("type definition with empty name")
		}
		if seen[d.Name] {
			t.Fatalf("duplicate type definition: %s", d.Name)
		}
		seen[d.Name] = true

		ent, err := d.ToEntity()
		if err != nil {
			t.Fatalf("ToEntity failed for %s: %v", d.Name, err)
		}
		if ent.Type != TypeType {
			t.Fatalf("entity type for %s: expected %s, got %s", d.Name, TypeType, ent.Type)
		}
		if err := ent.Validate(); err != nil {
			t.Fatalf("hash validation failed for %s: %v", d.Name, err)
		}

		expected := "system/type/" + d.Name
		if d.TreePath() != expected {
			t.Fatalf("TreePath for %s: expected %s, got %s", d.Name, expected, d.TreePath())
		}
	}
}

func TestReflectedTypesMatchSpec(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)

	// Simulate handler type registration (normally done by handlers).
	registerConnectTypes(r)
	registerTreeTypes(r)

	// After full registration: 137 core (incl. system/deletion-marker per A.8,
	// system/continuation/transform-op per EXTENSION-CONTINUATION v1.9 G1,
	// durability-request/result/advertisement per EXTENSION-INBOX §10,
	// compute/{index,length,numeric-cast} + system/compute/{map,filter,fold}-args
	// per EXTENSION-COMPUTE v3.14, system/compute/scope-binding per
	// EXTENSION-COMPUTE v3.19b §2.3, EXTENSION-TYPE v1.1's 24 new types, and
	// EXTENSION-CONTENT v3.6 §2's three new types — blob, chunk, descriptor)
	// + 5 handler-specific = 142 baseline. Storage-substitute substrate
	// adds five more (system/substitute/endpoint shared block,
	// system/peer/transport/http-poll, system/substitute/snapshot-manifest,
	// system/substitute/source, system/substitute/try-request) → 147 baseline.
	// V7 v7.62 capability handler amendment adds three more (revoke-request,
	// delegate-request, policy-entry) → 150 total.
	// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 (LOCKED) adds
	// system/peer/published-root → 151 total.
	// EXTENSION-REGISTRY v1.0 adds 18 → 169 total.
	// EXTENSION-DISCOVERY v1.0 D1 + D3 adds 7 → 176.
	// EXTENSION-RELAY v1.0 R1 adds 8 → 184.
	// EXTENSION-RELAY v1.0 R6/R7 fold (arch faf3fa9) adds 2 → 186 total.
	// EXTENSION-ROUTE v1 (PROPOSAL-EXTENSION-ROUTE) adds system/route → 187 total.
	// EXTENSION-REGISTRY §6a.9 peer-issued live-registration adds 4 → 191 total.
	// EXTENSION-ENCRYPTION v1.0 adds 7 → 198 total.
	// EXTENSION-ENCRYPTION v2.5 R3 ENC-KAT-INNER adds system/note → 199 total.
	all := r.All()
	if len(all) != 199 {
		names := make([]string, len(all))
		for i, d := range all {
			names[i] = d.Name
		}
		t.Fatalf("expected 199 total type definitions, got %d: %v", len(all), names)
	}

	// Verify specific types have correct fields.
	tests := []struct {
		name   string
		field  string
		expect FieldSpec
	}{
		{"system/peer", "peer_id", FieldSpec{TypeRef: "system/peer-id"}},
		{"system/peer", "public_key", FieldSpec{TypeRef: "primitive/bytes"}},
		{"system/signature", "target", FieldSpec{TypeRef: "system/hash"}},
		{"system/bounds", "ttl", FieldSpec{TypeRef: "primitive/uint", Optional: true}},
		{"system/bounds", "visited", FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/tree/path"}, Optional: true}},
		{"system/capability/grant", "token", FieldSpec{TypeRef: "system/hash"}},
		{"system/capability/grant-entry", "handlers", FieldSpec{TypeRef: "system/capability/path-scope"}},
		{"system/capability/grant-entry", "resources", FieldSpec{TypeRef: "system/capability/path-scope"}},
		{"system/capability/token", "grants", FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/capability/grant-entry"}}},
		{"system/capability/token", "granter", FieldSpec{UnionOf: []FieldSpec{
			{TypeRef: "system/hash"},
			{TypeRef: TypeMultiGranter},
		}}},
		{"system/capability/token", "delegation_caveats", FieldSpec{TypeRef: "system/capability/delegation-caveats", Optional: true}},
		{"system/capability/token", "resource_limits", FieldSpec{TypeRef: "system/resource-limits", Optional: true}},
		{"system/handler", "interface", FieldSpec{TypeRef: "system/tree/path"}},
		{"system/handler", "expression_path", FieldSpec{TypeRef: "system/tree/path", Optional: true}},
		{"system/handler", "max_scope", FieldSpec{ArrayOf: &FieldSpec{TypeRef: "system/capability/grant-entry"}, Optional: true}},
		{"system/protocol/execute", "params", FieldSpec{TypeRef: "core/entity"}},
		{"system/protocol/execute", "bounds", FieldSpec{TypeRef: "system/bounds", Optional: true}},
		{"system/protocol/execute", "deliver_to", FieldSpec{TypeRef: "system/delivery-spec", Optional: true}},
		{"system/protocol/execute", "author", FieldSpec{TypeRef: "system/hash", Optional: true}},
		{"system/tree/listing", "entries", FieldSpec{MapOf: &FieldSpec{TypeRef: "system/tree/listing-entry"}}},
		// EXTENSION-DURABILITY (exploratory) — the field SHAPE is pinned for
		// cross-impl determinism (§5 / §7); level/reason VALUES are
		// illustrative, not asserted here.
		{"system/durability-request", "level", FieldSpec{TypeRef: "primitive/string"}},
		{"system/durability-request", "must_have", FieldSpec{TypeRef: "primitive/bool", Optional: true}},
		{"system/durability-result", "requested", FieldSpec{TypeRef: "primitive/string"}},
		{"system/durability-result", "applied", FieldSpec{TypeRef: "primitive/string"}},
		{"system/durability-result", "committed", FieldSpec{TypeRef: "primitive/string", Optional: true}},
		{"system/durability-result", "max_available", FieldSpec{TypeRef: "primitive/string", Optional: true}},
		{"system/durability-result", "reason", FieldSpec{TypeRef: "primitive/string", Optional: true}},
		{"system/durability-result", "handle", FieldSpec{TypeRef: "system/tree/path", Optional: true}},
		{"system/protocol/execute", "durability_request", FieldSpec{TypeRef: "system/durability-request", Optional: true}},
		{"system/protocol/execute/response", "durability", FieldSpec{TypeRef: "system/durability-result", Optional: true}},
	}

	for _, tt := range tests {
		def, ok := r.Get(tt.name)
		if !ok {
			t.Fatalf("type %q not registered", tt.name)
		}
		got, ok := def.Fields[tt.field]
		if !ok {
			t.Fatalf("type %q missing field %q (has: %v)", tt.name, tt.field, fieldNames(def.Fields))
			continue
		}
		if !fieldSpecEqual(got, tt.expect) {
			t.Errorf("type %q field %q:\n  got:    %+v\n  expect: %+v", tt.name, tt.field, got, tt.expect)
		}
	}
}

// registerConnectTypes simulates ConnectHandler.RegisterTypes.
func registerConnectTypes(r *TypeRegistry) {
	r.ReflectType(TypeHello, reflect.TypeOf(HelloData{}))
	r.ReflectType(TypeAuthenticate, reflect.TypeOf(AuthenticateData{}))
	r.OverrideField(TypeHello, "peer_id", FieldSpec{TypeRef: "system/peer-id"})
	r.OverrideField(TypeAuthenticate, "peer_id", FieldSpec{TypeRef: "system/peer-id"})
}

// registerTreeTypes simulates tree.Handler.RegisterTypes.
func registerTreeTypes(r *TypeRegistry) {
	r.ReflectType(TypeTreeGetRequest, reflect.TypeOf(GetRequestData{}))
	r.ReflectType(TypeTreePutRequest, reflect.TypeOf(PutRequestData{}))
	r.ReflectType(TypeTreeListing, reflect.TypeOf(ListingData{}))
	r.OverrideField(TypeTreeListing, "entries",
		FieldSpec{MapOf: &FieldSpec{TypeRef: "system/tree/listing-entry"}})
	r.OverrideField(TypeTreeListing, "path",
		FieldSpec{TypeRef: "system/tree/path"})
}

func fieldNames(m map[string]FieldSpec) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

func fieldSpecEqual(a, b FieldSpec) bool {
	if a.TypeRef != b.TypeRef || a.Optional != b.Optional || a.KeyType != b.KeyType {
		return false
	}
	if (a.ArrayOf == nil) != (b.ArrayOf == nil) {
		return false
	}
	if a.ArrayOf != nil && !fieldSpecEqual(*a.ArrayOf, *b.ArrayOf) {
		return false
	}
	if (a.MapOf == nil) != (b.MapOf == nil) {
		return false
	}
	if a.MapOf != nil && !fieldSpecEqual(*a.MapOf, *b.MapOf) {
		return false
	}
	if (a.ByteSize == nil) != (b.ByteSize == nil) {
		return false
	}
	if a.ByteSize != nil && *a.ByteSize != *b.ByteSize {
		return false
	}
	return true
}
