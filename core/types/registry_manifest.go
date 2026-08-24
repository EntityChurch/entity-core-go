package types

import (
	"github.com/fxamacker/cbor/v2"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
)

// EXTENSION-REGISTRY §6a.7 — the signed binding-manifest.
//
// A registry MAY publish one signed entity listing its whole name→hash
// index, so a consumer gets the index in one round trip instead of a
// per-name pointer fetch each time. It is the direct analog of
// SUBSTITUTE §2.4's snapshot-manifest with registry-domain fields, and
// §6a.7 pins the format here precisely so no registry invents its own.
//
// It is an OPTIMIZATION, never an authority upgrade: a missing, stale, or
// signature-invalid manifest MUST fall through to the §6a.3 per-name
// pointer. The one case where the manifest can answer negatively is
// coverage="complete" — see Coverage below.

const (
	// TypeRegistryBindingManifest is the §6a.7 entity type.
	TypeRegistryBindingManifest = "system/registry/binding-manifest"

	// RegistryManifestPath is where a registry serves the current
	// manifest, relative to its tree_url_prefix (§6a.7).
	RegistryManifestPath = "registry/manifest/current"
)

// Coverage values per §6a.7. The distinction is the whole reason the
// field exists: it says whether the absence of a name from `bindings` is
// information or merely silence.
const (
	// CoveragePartial — a name absent from `bindings` says NOTHING. The
	// consumer MUST fall through to the per-name pointer. This is the
	// default, and the safe reading: a registry that indexes a subset
	// cannot be read as denying everything else.
	CoveragePartial = "partial"

	// CoverageComplete — the manifest claims to list every name the
	// registry serves, so absence IS an authoritative not_found. The
	// DNSSEC-NSEC / TUF model: a signed statement that a name does not
	// exist. Only meaningful because the manifest is signed; an
	// unsigned "complete" claim is worth nothing and never reaches this
	// code path.
	CoverageComplete = "complete"
)

// Registry manifest error codes, reused verbatim from SUBSTITUTE §7.2 per
// §6a.7 — same failure, same wire code, so a consumer handling one
// handles the other.
const (
	// RegistryErrManifestSignatureInvalid — the manifest's signature is
	// missing, does not target the manifest hash, or does not verify
	// against the registry's pinned key.
	RegistryErrManifestSignatureInvalid = "manifest_signature_invalid"

	// RegistryErrManifestStaleSeq — the manifest's seq is lower than the
	// highest already seen from this registry (stale-replay defense).
	RegistryErrManifestStaleSeq = "manifest_stale_seq"
)

// RegistryBindingManifestData is the §6a.7 payload.
//
// Bindings maps NFC-normalized name → the content hash of the current
// §3 binding body — the same value the by-name pointer holds, so a
// manifest hit and a pointer hit are interchangeable downstream and the
// signature/TTL/revocation checks that follow are identical either way.
// That is deliberate: the manifest short-circuits the LOOKUP, never the
// verification.
type RegistryBindingManifestData struct {
	// RegistryID is the registry's peer-id (base58, V7 §1.5) — the same
	// identity the pinned key belongs to. Named rather than derived so a
	// consumer can detect a manifest served from the wrong registry
	// before trusting any of it.
	RegistryID string `cbor:"registry_id"`

	SnapshotAt uint64 `cbor:"snapshot_at"`

	// Seq is monotonic per registry and drives the §7.2 freshness gate.
	Seq uint64 `cbor:"seq"`

	// Coverage is CoveragePartial or CoverageComplete. Empty decodes as
	// partial: §6a.7 makes partial the default, and defaulting the other
	// way would turn a malformed manifest into a source of authoritative
	// negative answers.
	Coverage string `cbor:"coverage"`

	Bindings map[string]hash.Hash `cbor:"bindings"`

	// Predecessor optionally chains to the prior manifest's content hash
	// (recommended for audit deployments).
	Predecessor *hash.Hash `cbor:"predecessor,omitempty"`
}

// CoverageOrDefault returns the effective coverage, resolving an
// unset/unknown value to partial.
func (d RegistryBindingManifestData) CoverageOrDefault() string {
	if d.Coverage == CoverageComplete {
		return CoverageComplete
	}
	return CoveragePartial
}

// IsComplete reports whether absence from Bindings is authoritative.
func (d RegistryBindingManifestData) IsComplete() bool {
	return d.CoverageOrDefault() == CoverageComplete
}

// ToEntity creates a system/registry/binding-manifest entity.
func (d RegistryBindingManifestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRegistryBindingManifest, cbor.RawMessage(raw))
}

// RegistryBindingManifestDataFromEntity decodes a binding-manifest entity.
func RegistryBindingManifestDataFromEntity(e entity.Entity) (RegistryBindingManifestData, error) {
	var d RegistryBindingManifestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RegistryBindingManifestData{}, err
	}
	return d, nil
}
