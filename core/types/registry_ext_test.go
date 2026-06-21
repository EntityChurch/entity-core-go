package types

import (
	"bytes"
	"testing"

	"go.entitychurch.org/entity-core-go/core/hash"
)

func rxFakeHash(b byte) hash.Hash {
	var h hash.Hash
	h.Algorithm = hash.AlgorithmSHA256
	h.Digest[0] = b
	return h
}

func TestBindingRoundtrip(t *testing.T) {
	ttl := uint64(60_000)
	pred := rxFakeHash(0x10)
	issuerAtt := rxFakeHash(0x20)
	d := BindingData{
		Name:              "alice",
		Kind:              BindingKindLocalName,
		TargetPeerID:      "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
		Transports:        []hash.Hash{rxFakeHash(0xAA), rxFakeHash(0xBB)},
		IssuedAt:          1_730_000_000_000,
		TTL:               &ttl,
		Supersedes:        &pred,
		IssuerAttestation: &issuerAtt,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if e.Type != TypeRegistryBinding {
		t.Fatalf("type: want %s got %s", TypeRegistryBinding, e.Type)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate hash: %v", err)
	}
	decoded, err := BindingDataFromEntity(e)
	if err != nil {
		t.Fatalf("from entity: %v", err)
	}
	if decoded.Name != "alice" || decoded.Kind != BindingKindLocalName {
		t.Fatalf("name/kind drift: %+v", decoded)
	}
	if decoded.TargetPeerID != d.TargetPeerID {
		t.Fatalf("target_peer_id drift")
	}
	if len(decoded.Transports) != 2 ||
		!bytes.Equal(decoded.Transports[0].Bytes(), d.Transports[0].Bytes()) ||
		!bytes.Equal(decoded.Transports[1].Bytes(), d.Transports[1].Bytes()) {
		t.Fatalf("transports drift")
	}
	if decoded.TTL == nil || *decoded.TTL != ttl {
		t.Fatalf("TTL drift")
	}
	if decoded.Supersedes == nil || !bytes.Equal(decoded.Supersedes.Bytes(), pred.Bytes()) {
		t.Fatalf("supersedes drift")
	}
}

func TestBindingMinimalSelfCertifying(t *testing.T) {
	// Self-certifying: no signature, no transports, no supersedes — minimal
	// shape. Most omitempty fields drop on the wire.
	d := BindingData{
		Name:         "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
		Kind:         BindingKindSelfCertifying,
		TargetPeerID: "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
		IssuedAt:     1_730_000_000_000,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	decoded, err := BindingDataFromEntity(e)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Supersedes != nil || decoded.IssuerAttestation != nil ||
		len(decoded.Transports) != 0 || decoded.TTL != nil {
		t.Fatalf("omitempty fields not dropped: %+v", decoded)
	}
}

func TestRevocationRoundtrip(t *testing.T) {
	reason := "compromised"
	d := RevocationData{
		Revokes:   rxFakeHash(0x77),
		RevokedAt: 1_730_001_000_000,
		Reason:    &reason,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRegistryRevocation {
		t.Fatalf("type drift: %s", e.Type)
	}
	dec, _ := RevocationDataFromEntity(e)
	if !bytes.Equal(dec.Revokes.Bytes(), d.Revokes.Bytes()) {
		t.Fatal("revokes drift")
	}
	if dec.Reason == nil || *dec.Reason != "compromised" {
		t.Fatalf("reason drift: %+v", dec.Reason)
	}
}

func TestResolverConfigRoundtrip(t *testing.T) {
	reason := "production root"
	d := ResolverConfigData{
		ResolverChain: []ResolverChainEntry{
			{
				BackendKind:          BackendKindLocalName,
				BackendID:            "local",
				Priority:             0,
				AcceptedTrustAnchors: []string{TrustAnchorLocalName},
			},
			{
				BackendKind:          BackendKindPeerIssued,
				BackendID:            "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
				Priority:             10,
				AcceptedTrustAnchors: []string{"peer_issued:*"},
			},
		},
		PinnedBindings: []PinnedEntry{
			{
				Name:         "registry",
				TargetPeerID: "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
				Reason:       &reason,
			},
		},
		NameFormatDispatch: []DispatchEntry{
			{Pattern: "*@*.*", BackendKinds: []string{BackendKindDNSTXT}},
			{Pattern: "did:web:*", BackendKinds: []string{BackendKindDIDWeb}},
		},
		LogCacheHits:          true,
		ResolutionLogCapacity: 2048,
	}
	e, err := d.ToEntity()
	if err != nil {
		t.Fatalf("ToEntity: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("hash validate: %v", err)
	}
	dec, err := ResolverConfigDataFromEntity(e)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec.ResolverChain) != 2 || dec.ResolverChain[1].Priority != 10 {
		t.Fatalf("resolver chain drift: %+v", dec.ResolverChain)
	}
	if len(dec.PinnedBindings) != 1 || dec.PinnedBindings[0].Name != "registry" {
		t.Fatalf("pinned drift")
	}
	if len(dec.NameFormatDispatch) != 2 {
		t.Fatalf("dispatch drift: %+v", dec.NameFormatDispatch)
	}
	if !dec.LogCacheHits {
		t.Fatal("log_cache_hits dropped")
	}
	if dec.ResolutionLogCapacity != 2048 {
		t.Fatalf("capacity drift: %d", dec.ResolutionLogCapacity)
	}
}

func TestLocalNameConfigRoundtrip(t *testing.T) {
	d := LocalNameConfigData{
		DefaultPinned:     true,
		AllowSupersede:    true,
		CaseNormalization: CaseNormalizationLower,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRegistryLocalNameConfig {
		t.Fatalf("type drift: %s", e.Type)
	}
	dec, _ := LocalNameConfigDataFromEntity(e)
	if dec.CaseNormalization != "lower" {
		t.Fatalf("case_normalization drift: %s", dec.CaseNormalization)
	}
}

func TestResolutionLogRoundtrip(t *testing.T) {
	bid := "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY"
	reason := "signature_failed"
	binding := rxFakeHash(0xCD)
	d := ResolutionLogData{
		Seq:                 1,
		Name:                "alice",
		BackendID:           &bid,
		Status:              ResolutionStatusResolved,
		Reason:              &reason,
		Binding:             &binding,
		AttemptedAt:         1_730_002_000_000,
		IsFallbackReresolve: true,
	}
	e, _ := d.ToEntity()
	if e.Type != TypeRegistryResolutionLog {
		t.Fatalf("type drift: %s", e.Type)
	}
	dec, _ := ResolutionLogDataFromEntity(e)
	if dec.Seq != 1 || dec.Name != "alice" {
		t.Fatalf("seq/name drift: %+v", dec)
	}
	if dec.BackendID == nil || *dec.BackendID != bid {
		t.Fatalf("backend_id drift")
	}
	if dec.Binding == nil || !bytes.Equal(dec.Binding.Bytes(), binding.Bytes()) {
		t.Fatalf("binding drift")
	}
	if !dec.IsFallbackReresolve {
		t.Fatal("is_fallback_reresolve drift")
	}
}

func TestResolveRequestRoundtrip(t *testing.T) {
	d := ResolveRequestData{Name: "alice"}
	e, _ := d.ToEntity()
	dec, _ := ResolveRequestDataFromEntity(e)
	if dec.Name != "alice" {
		t.Fatalf("name drift")
	}
}

func TestResolveResultRoundtrip(t *testing.T) {
	binding := rxFakeHash(0x11)
	ttl := uint64(60_000)
	d := ResolveResultData{
		Status:      ResolutionStatusResolved,
		Binding:     &binding,
		PeerID:      "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
		Transports:  []hash.Hash{rxFakeHash(0xAA)},
		TrustAnchor: TrustAnchorLocalName,
		TTL:         &ttl,
		BackendID:   "local",
	}
	e, _ := d.ToEntity()
	dec, _ := ResolveResultDataFromEntity(e)
	if dec.Status != ResolutionStatusResolved {
		t.Fatalf("status drift")
	}
	if dec.Binding == nil || *dec.Binding != binding {
		t.Fatalf("binding drift")
	}
	if dec.TrustAnchor != TrustAnchorLocalName {
		t.Fatalf("trust_anchor drift: %s", dec.TrustAnchor)
	}
}

func TestLocalNameBindRoundtrip(t *testing.T) {
	notes := "best friend's peer"
	d := LocalNameBindRequestData{
		Name:         "alice",
		TargetPeerID: "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
		Transports:   []hash.Hash{rxFakeHash(0xAA)},
		Notes:        &notes,
	}
	e, _ := d.ToEntity()
	dec, _ := LocalNameBindRequestDataFromEntity(e)
	if dec.Name != "alice" || dec.TargetPeerID != d.TargetPeerID {
		t.Fatalf("fields drift")
	}
	if dec.Notes == nil || *dec.Notes != notes {
		t.Fatalf("notes drift")
	}
}

func TestLocalNameListResultRoundtrip(t *testing.T) {
	notes := "alpha"
	d := LocalNameListResultData{
		Entries: []LocalNameListEntry{
			{
				Name:         "alice",
				Hash:         rxFakeHash(0x11),
				TargetPeerID: "2K6kyaA9UNaHHXKUV8cq5GLgc7XJDyVxH8EKiFQnMWeGZY",
				Notes:        &notes,
				Pinned:       true,
			},
		},
	}
	e, _ := d.ToEntity()
	dec, _ := LocalNameListResultDataFromEntity(e)
	if len(dec.Entries) != 1 {
		t.Fatalf("entries drift")
	}
	if !dec.Entries[0].Pinned {
		t.Fatalf("pinned drift")
	}
}

func TestStoragePathHelpers(t *testing.T) {
	h := rxFakeHash(0xAB)
	if got := BindingStoragePath(h); got != "system/registry/binding/"+PeerIdentityHashHex(h) {
		t.Fatalf("BindingStoragePath: %s", got)
	}
	if got := RevocationStoragePath(h); got != "system/registry/revocation/"+PeerIdentityHashHex(h) {
		t.Fatalf("RevocationStoragePath: %s", got)
	}
	if got := LocalNamePointerPath("alice"); got != "system/registry/binding/local-name/alice" {
		t.Fatalf("LocalNamePointerPath: %s", got)
	}
	if got := ResolutionLogPath(42); got != "system/registry/resolution-log/42" {
		t.Fatalf("ResolutionLogPath: %s", got)
	}
	if got := ResolutionLogPath(0); got != "system/registry/resolution-log/0" {
		t.Fatalf("ResolutionLogPath(0): %s", got)
	}
}

func TestRegistryTypesRegistered(t *testing.T) {
	r := NewTypeRegistry()
	RegisterCoreTypes(r)
	for _, name := range []string{
		TypeRegistryBinding,
		TypeRegistryRevocation,
		TypeRegistryResolverConfig,
		TypeRegistryLocalNameConfig,
		TypeRegistryResolutionLog,
		TypeRegistryResolveRequest,
		TypeRegistryResolveResult,
		TypeRegistryLocalNameBindRequest,
		TypeRegistryLocalNameBindResult,
		TypeRegistryLocalNameListResult,
		TypeRegistryLocalNameUpdateTransports,
	} {
		if _, ok := r.Get(name); !ok {
			t.Errorf("type %q not registered", name)
		}
	}
	// target_peer_id override must surface as system/peer-id (not the raw
	// primitive/string the reflected struct field renders to).
	def, _ := r.Get(TypeRegistryBinding)
	if fs, ok := def.Fields["target_peer_id"]; !ok || fs.TypeRef != "system/peer-id" {
		t.Errorf("binding.target_peer_id override missing: %+v", fs)
	}
}
