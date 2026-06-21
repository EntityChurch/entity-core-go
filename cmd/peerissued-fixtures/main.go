// Package main emits the REG-PEERISSUED-* cohort byte-equal fixtures —
// the Keystone "static-ECR coral-reef" reproduction bundle for
// PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND v0.4 §6.
//
// Deterministic: every input is seeded (32-byte Ed25519 seeds, fixed
// timestamps, fixed target peer-ids). Cross-impl gate: Rust + Python
// re-deriving with the same seeds + same paths MUST produce byte-equal
// CBOR + the same content_hash for every emitted entity.
//
// Output is a directory bundle:
//
//	<out>/MANIFEST.json                 — top-level index (registry id +
//	                                       per-vector hashes + expected
//	                                       resolve result)
//	<out>/registry/identity.cbor        — the pinned registry identity
//	                                       entity (full bytes)
//	<out>/registry/identity.data.hex    — ECF data field, hex
//	<out>/registry/peer_id.txt          — base58 peer-id (the BackendID)
//	<out>/registry/identity_hash.hex    — content_hash hex (33-byte form)
//	<out>/vectors/<id>/*.cbor           — per-vector binding / signature /
//	                                       revocation entity bytes
//	<out>/vectors/<id>/expected.json    — expected ResolveResultData
//	<out>/vectors/<id>/notes.md         — mode (live/offline), clock,
//	                                       pre-seed state, expected error
//
// Reproduction (Go reference): `go run ./cmd/peerissued-fixtures/ -out
// <out-dir>`. The bundle is also
// self-verified in-process — each vector is re-run through
// `ext/registry/peerissued` and the result asserted to match the
// declared expected.json. A mismatch fails the generator.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
)

// Deterministic seeds. The exact byte patterns don't matter — only that
// every impl agrees. Patterns chosen so a human can spot them in a hex
// dump.
var (
	seedRegistry = [32]byte{
		0xEC, 0xE1, 0x00, 0xE2, 0xC0, 0xCE, 0x07, 0xEC, 0xE1, 0xE2, 0xC0, 0xCE, 0x07,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	seedAttacker = [32]byte{
		0xA1, 0x77, 0xAC, 0x4E, 0xA1, 0x77, 0xAC, 0x4E, 0xA1, 0x77, 0xAC, 0x4E, 0xA1,
		0x77, 0xAC, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
)

// Fixed target peer-id for the resolved binding — opaque base58, the
// backend doesn't dereference it. Same string across all vectors so the
// only thing varying is what's wrong with the binding.
const fixTargetPeerID = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Fixed clock values per vector (milliseconds). RESOLVE-1 / VERIFY-FAIL-1
// / REVOKED-1 / PRECEDE-1 / OFFLINE-NOTFOUND-1 all use NowResolve; EXPIRED-1
// uses NowExpired (past issued_at + ttl).
const (
	ClockIssuedAt  uint64 = 1_000_000
	ClockNowResolve uint64 = 2_000_000
	ClockTTLShort  uint64 = 1_000
	ClockNowExpired uint64 = 1_001_001
	NegativeTTL    uint64 = 30_000
)

// fixedName — the same NFC name across every vector, so the cross-impl
// gate has a single normalized-form pin.
const fixedName = "billslab.com"

type vectorOutcome struct {
	Status      string  `json:"status"`
	Binding     *string `json:"binding,omitempty"`
	PeerID      string  `json:"peer_id,omitempty"`
	TrustAnchor string  `json:"trust_anchor,omitempty"`
	NegTTLMs    *uint64 `json:"neg_ttl_ms,omitempty"`
	BackendID   string  `json:"backend_id,omitempty"`
	// `error` set when Resolve returns a non-nil error (verify-fail,
	// revoked, expired). The string is the Go reference impl's wrapped
	// error message — INFORMATIVE only; other impls produce equivalent
	// errors with their own wording. The gate is "Resolve returns an
	// error" + chain-advance behavior, not the literal text.
	Error string `json:"error,omitempty"`
}

type vectorEntry struct {
	ID                 string         `json:"id"`
	Mode               string         `json:"mode"` // "live" or "offline"
	Description        string         `json:"description"`
	ClockMs            uint64         `json:"clock_ms"`
	Name               string         `json:"name"`
	BindingHash        string         `json:"binding_hash,omitempty"`
	SignatureHash      string         `json:"signature_hash,omitempty"`
	RevocationHash     string         `json:"revocation_hash,omitempty"`
	RevocationSigHash  string         `json:"revocation_signature_hash,omitempty"`
	ExpectedResult     vectorOutcome  `json:"expected_result"`
	Files              []string       `json:"files"`
	OfflinePreseed     map[string]string `json:"offline_preseed,omitempty"` // store-path → entity content_hash
}

type manifest struct {
	BundleVersion       string         `json:"bundle_version"`
	Proposal            string         `json:"proposal"`
	Generated           string         `json:"generated_by"`
	RegistryPeerID      string         `json:"registry_peer_id"`
	RegistryIdentityHash string        `json:"registry_identity_hash"`
	NegativeTTLMs       uint64         `json:"negative_ttl_ms"`
	Vectors             []vectorEntry  `json:"vectors"`
	Notes               []string       `json:"notes"`
}

func main() {
	outDir := flag.String("out", "", "output directory (required)")
	flag.Parse()
	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "missing -out <dir>")
		os.Exit(2)
	}
	if err := run(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	regDir := filepath.Join(outDir, "registry")
	vecDir := filepath.Join(outDir, "vectors")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(vecDir, 0o755); err != nil {
		return err
	}

	// --- Registry identity (the pinned trust root) --------------------
	registryKey := crypto.FromSeed(seedRegistry)
	registryEnt, err := registryKey.IdentityEntity()
	if err != nil {
		return fmt.Errorf("registry identity: %w", err)
	}
	registryPID := string(registryKey.PeerID())

	if err := writeEntity(regDir, "identity", registryEnt); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(regDir, "peer_id.txt"),
		[]byte(registryPID+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(regDir, "identity_hash.hex"),
		[]byte(hex.EncodeToString(registryEnt.ContentHash.Bytes())+"\n"), 0o644); err != nil {
		return err
	}
	// Raw seed shipped alongside so other impls' fixture generators can
	// deterministically rebuild the keypair byte-for-byte.
	if err := os.WriteFile(filepath.Join(regDir, "seed.hex"),
		[]byte(hex.EncodeToString(seedRegistry[:])+"\n"), 0o644); err != nil {
		return err
	}

	attackerKey := crypto.FromSeed(seedAttacker)
	if err := os.WriteFile(filepath.Join(regDir, "attacker_seed.hex"),
		[]byte(hex.EncodeToString(seedAttacker[:])+"\n"), 0o644); err != nil {
		return err
	}

	// --- Per-vector builds ---------------------------------------------
	vectors := []vectorEntry{}

	// RESOLVE-1 — happy path live-fetch.
	{
		body := types.BindingData{
			Name:         fixedName,
			Kind:         types.BindingKindPeerIssued,
			TargetPeerID: fixTargetPeerID,
			IssuedAt:     ClockIssuedAt,
		}
		bind, sig, err := buildBindingPair(registryKey, body)
		if err != nil {
			return err
		}
		dir := filepath.Join(vecDir, "RESOLVE-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeEntity(dir, "binding", bind); err != nil {
			return err
		}
		if err := writeEntity(dir, "signature", sig); err != nil {
			return err
		}
		bh := hex.EncodeToString(bind.ContentHash.Bytes())
		entry := vectorEntry{
			ID:            "REG-PEERISSUED-RESOLVE-1",
			Mode:          "live",
			Description:   "happy path — by-name → binding → verify against pinned key → resolved",
			ClockMs:       ClockNowResolve,
			Name:          fixedName,
			BindingHash:   bh,
			SignatureHash: hex.EncodeToString(sig.ContentHash.Bytes()),
			ExpectedResult: vectorOutcome{
				Status:      types.ResolutionStatusResolved,
				Binding:     strPtr(bh),
				PeerID:      fixTargetPeerID,
				TrustAnchor: types.PeerIssuedTrustAnchor(registryPID),
				BackendID:   registryPID,
			},
			Files: []string{"binding.cbor", "signature.cbor"},
		}
		writeNotes(dir, entry,
			"Mode: live (Reader serves binding + signature; receiver fetches both).",
			"Pre-seed: none — the receiver's local store starts empty.",
			"Wire steps: TreeGet(system/registry/binding/by-name/billslab.com) → binding_hash; ContentGet(binding_hash); TreeGet(system/signature/{binding_hash_hex}) → signature_hash; ContentGet(signature_hash); verify(sig.signature, binding_hash, pinned_pubkey) → ok; revocation lookup misses → not revoked.",
		)
		vectors = append(vectors, entry)
	}

	// VERIFY-FAIL-1 — non-pinned signer.
	{
		body := types.BindingData{
			Name:         fixedName,
			Kind:         types.BindingKindPeerIssued,
			TargetPeerID: "2KAttackerForgedTargetPeerID111111111111111111",
			IssuedAt:     ClockIssuedAt,
		}
		bind, sig, err := buildBindingPair(attackerKey, body)
		if err != nil {
			return err
		}
		dir := filepath.Join(vecDir, "VERIFY-FAIL-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeEntity(dir, "binding", bind); err != nil {
			return err
		}
		if err := writeEntity(dir, "signature", sig); err != nil {
			return err
		}
		entry := vectorEntry{
			ID:            "REG-PEERISSUED-VERIFY-FAIL-1",
			Mode:          "live",
			Description:   "binding signed by non-pinned key → rejected, chain advances (NOT downgraded to pin)",
			ClockMs:       ClockNowResolve,
			Name:          fixedName,
			BindingHash:   hex.EncodeToString(bind.ContentHash.Bytes()),
			SignatureHash: hex.EncodeToString(sig.ContentHash.Bytes()),
			ExpectedResult: vectorOutcome{
				Error: "peerissued: verify: signature signer != pinned registry identity",
			},
			Files: []string{"binding.cbor", "signature.cbor"},
		}
		writeNotes(dir, entry,
			"Mode: live (Reader serves binding + signature; signature signer is the ATTACKER identity, not the pinned registry).",
			"Pre-seed: none.",
			"Gate: Resolve MUST return an error. The meta-resolver chain MUST advance — verify-fail is NEVER downgraded to a pin per §5.",
			"Conformant impls may surface either a `signer != pinned` mismatch or a crypto-verify failure; both satisfy the gate.",
		)
		vectors = append(vectors, entry)
	}

	// REVOKED-1 — valid binding + verifying revocation.
	{
		body := types.BindingData{
			Name:         fixedName,
			Kind:         types.BindingKindPeerIssued,
			TargetPeerID: fixTargetPeerID,
			IssuedAt:     ClockIssuedAt,
		}
		bind, sig, err := buildBindingPair(registryKey, body)
		if err != nil {
			return err
		}
		rev, revSig, err := buildRevocationPair(registryKey, bind.ContentHash, ClockIssuedAt+500_000)
		if err != nil {
			return err
		}
		dir := filepath.Join(vecDir, "REVOKED-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeEntity(dir, "binding", bind); err != nil {
			return err
		}
		if err := writeEntity(dir, "signature", sig); err != nil {
			return err
		}
		if err := writeEntity(dir, "revocation", rev); err != nil {
			return err
		}
		if err := writeEntity(dir, "revocation_signature", revSig); err != nil {
			return err
		}
		entry := vectorEntry{
			ID:               "REG-PEERISSUED-REVOKED-1",
			Mode:             "live",
			Description:      "valid binding + verifying revocation at by-target index → rejected, chain advances",
			ClockMs:          ClockNowResolve,
			Name:             fixedName,
			BindingHash:      hex.EncodeToString(bind.ContentHash.Bytes()),
			SignatureHash:    hex.EncodeToString(sig.ContentHash.Bytes()),
			RevocationHash:   hex.EncodeToString(rev.ContentHash.Bytes()),
			RevocationSigHash: hex.EncodeToString(revSig.ContentHash.Bytes()),
			ExpectedResult: vectorOutcome{
				Error: "peerissued: binding revoked",
			},
			Files: []string{"binding.cbor", "signature.cbor", "revocation.cbor", "revocation_signature.cbor"},
		}
		writeNotes(dir, entry,
			"Mode: live (Reader serves binding + signature + revocation index + revocation signature).",
			"Pre-seed: none.",
			"Wire steps: full RESOLVE-1 wire, plus TreeGet(system/registry/revocation/by-target/{binding_hash_hex}) → revocation_hash; ContentGet(revocation_hash); TreeGet(system/signature/{revocation_hash_hex}) → revocation_signature_hash; ContentGet; verify revocation → ok → revoked.",
			"Gate: Resolve MUST return an error; the meta-resolver chain MUST advance.",
		)
		vectors = append(vectors, entry)
	}

	// EXPIRED-1 — issued_at + ttl <= now.
	{
		ttl := ClockTTLShort
		body := types.BindingData{
			Name:         fixedName,
			Kind:         types.BindingKindPeerIssued,
			TargetPeerID: fixTargetPeerID,
			IssuedAt:     ClockIssuedAt,
			TTL:          &ttl,
		}
		bind, sig, err := buildBindingPair(registryKey, body)
		if err != nil {
			return err
		}
		dir := filepath.Join(vecDir, "EXPIRED-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeEntity(dir, "binding", bind); err != nil {
			return err
		}
		if err := writeEntity(dir, "signature", sig); err != nil {
			return err
		}
		entry := vectorEntry{
			ID:            "REG-PEERISSUED-EXPIRED-1",
			Mode:          "live",
			Description:   "binding's issued_at + ttl is in the past → rejected, chain advances",
			ClockMs:       ClockNowExpired,
			Name:          fixedName,
			BindingHash:   hex.EncodeToString(bind.ContentHash.Bytes()),
			SignatureHash: hex.EncodeToString(sig.ContentHash.Bytes()),
			ExpectedResult: vectorOutcome{
				Error: "peerissued: binding expired",
			},
			Files: []string{"binding.cbor", "signature.cbor"},
		}
		writeNotes(dir, entry,
			"Mode: live.",
			"Pre-seed: none.",
			fmt.Sprintf("Clock arithmetic: issued_at=%d + ttl=%d = %d <= now=%d.",
				ClockIssuedAt, ClockTTLShort, ClockIssuedAt+ClockTTLShort, ClockNowExpired),
			"Gate: Resolve MUST return an error; the meta-resolver chain MUST advance.",
		)
		vectors = append(vectors, entry)
	}

	// PRECEDE-1 — offline cached binding, identical verify as live.
	{
		body := types.BindingData{
			Name:         fixedName,
			Kind:         types.BindingKindPeerIssued,
			TargetPeerID: fixTargetPeerID,
			IssuedAt:     ClockIssuedAt,
		}
		bind, sig, err := buildBindingPair(registryKey, body)
		if err != nil {
			return err
		}
		dir := filepath.Join(vecDir, "PRECEDE-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeEntity(dir, "binding", bind); err != nil {
			return err
		}
		if err := writeEntity(dir, "signature", sig); err != nil {
			return err
		}
		bh := hex.EncodeToString(bind.ContentHash.Bytes())
		entry := vectorEntry{
			ID:            "REG-PEERISSUED-PRECEDE-1",
			Mode:          "offline",
			Description:   "binding pre-cached locally — offline verify identical to live-fetch",
			ClockMs:       ClockNowResolve,
			Name:          fixedName,
			BindingHash:   bh,
			SignatureHash: hex.EncodeToString(sig.ContentHash.Bytes()),
			ExpectedResult: vectorOutcome{
				Status:      types.ResolutionStatusResolved,
				Binding:     strPtr(bh),
				PeerID:      fixTargetPeerID,
				TrustAnchor: types.PeerIssuedTrustAnchor(registryPID),
				BackendID:   registryPID,
			},
			Files: []string{"binding.cbor", "signature.cbor"},
			OfflinePreseed: map[string]string{
				types.PeerIssuedByNamePath(fixedName):       bh,
				types.LocalSignaturePath(bind.ContentHash):  hex.EncodeToString(sig.ContentHash.Bytes()),
			},
		}
		writeNotes(dir, entry,
			"Mode: offline — Reader is empty; the receiver MUST serve the binding + signature from its local store.",
			"Pre-seed (writes the impl MUST make before Resolve):",
			fmt.Sprintf("  ContentStore.Put(binding) — content_hash=%s", bh),
			fmt.Sprintf("  ContentStore.Put(signature) — content_hash=%s", hex.EncodeToString(sig.ContentHash.Bytes())),
			fmt.Sprintf("  LocationIndex.Bind(%q → binding_hash)", types.PeerIssuedByNamePath(fixedName)),
			fmt.Sprintf("  LocationIndex.Bind(%q → signature_hash)", types.LocalSignaturePath(bind.ContentHash)),
			"Gate: Reader.TreeGet for system/registry/binding/by-name/* MUST NOT be called; same for ContentGet on the binding/signature hashes. Resolve outcome MUST match RESOLVE-1's result.",
		)
		vectors = append(vectors, entry)
	}

	// OFFLINE-NOTFOUND-1 — name absent.
	{
		dir := filepath.Join(vecDir, "OFFLINE-NOTFOUND-1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		negTTL := NegativeTTL
		entry := vectorEntry{
			ID:          "REG-PEERISSUED-OFFLINE-NOTFOUND-1",
			Mode:        "offline",
			Description: "name absent from by-name index → not_found + neg_ttl, chain advances",
			ClockMs:     ClockNowResolve,
			Name:        "nope.example",
			ExpectedResult: vectorOutcome{
				Status:    types.ResolutionStatusNotFound,
				NegTTLMs:  &negTTL,
				BackendID: registryPID,
			},
			Files: []string{},
		}
		writeNotes(dir, entry,
			"Mode: offline (empty Reader, empty local store).",
			"Pre-seed: none.",
			"Gate: Resolve MUST return nil error with Status=not_found, BackendID=<registry_peer_id>, NegTTL=30_000ms. The meta-resolver MUST advance the chain (not_found is a backend-scoped negative; chain_exhausted is the meta-resolver's aggregate).",
		)
		vectors = append(vectors, entry)
	}

	// --- Manifest -------------------------------------------------------
	m := manifest{
		BundleVersion:        "1.0",
		Proposal:             "PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND v0.4 §6",
		Generated:            "go.entitychurch.org/entity-core-go/cmd/peerissued-fixtures",
		RegistryPeerID:       registryPID,
		RegistryIdentityHash: hex.EncodeToString(registryEnt.ContentHash.Bytes()),
		NegativeTTLMs:        NegativeTTL,
		Vectors:              vectors,
		Notes: []string{
			"Byte-equal across cohort: every .cbor file is the full encoded entity; every .data.hex file is the ECF-encoded data field (the hash-input bytes). Both content_hash values are sha256 over data + type wrapper per V7 §1.5.",
			"Reproduce: every impl's fixture generator, given the same seeds (registry/seed.hex, registry/attacker_seed.hex), MUST emit byte-identical .cbor + .data.hex + content_hash for every vector.",
			"Verification: this generator self-verifies — each vector is re-run through ext/registry/peerissued in-process and the live result asserted to match expected_result. A mismatch aborts generation.",
			"Live vs offline: 'live' vectors require a Reader that serves the declared (path → hash) and (hash → entity) entries; 'offline' vectors require the impl to pre-seed its local store per the offline_preseed map and then call Resolve with an empty Reader.",
			"Keystone consumption: drive each impl's Resolve via its meta-resolver, pinning <registry_peer_id> as a peer-issued backend, with the Reader (live vectors) backed by the .cbor bytes here or the local store (offline vectors) pre-seeded per notes.md.",
		},
	}
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "MANIFEST.json"),
		append(manifestBytes, '\n'), 0o644); err != nil {
		return err
	}

	// Top-level README.
	if err := writeReadme(outDir, m); err != nil {
		return err
	}

	// Self-verify by replaying each vector through the real backend.
	if err := verifyAll(registryKey, registryEnt, registryPID, attackerKey, m); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}

	fmt.Printf("✔ wrote %d vectors to %s\n", len(vectors), outDir)
	fmt.Printf("  registry peer-id: %s\n", registryPID)
	fmt.Printf("  registry hash:    %s\n", hex.EncodeToString(registryEnt.ContentHash.Bytes()))
	return nil
}

// buildBindingPair encodes a BindingData + its detached signature signed
// by `signer`. Mirrors the same shape the runtime backend verifies
// against — signature.target = binding.content_hash, signature.signer =
// signer's identity content_hash, signature.algorithm = signer's
// identity type (informative; verify uses key_type).
func buildBindingPair(signer crypto.Keypair, body types.BindingData) (entity.Entity, entity.Entity, error) {
	bindEnt, err := body.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("binding encode: %w", err)
	}
	sigBytes := signer.Sign(bindEnt.ContentHash.Bytes())
	signerEnt, err := signer.IdentityEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("signer identity: %w", err)
	}
	sigData := types.SignatureData{
		Target:    bindEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("signature encode: %w", err)
	}
	return bindEnt, sigEnt, nil
}

// buildRevocationPair builds a RevocationData targeting `bindingHash`,
// then its detached signature signed by `signer`. The runtime backend's
// verifyRevocation re-uses verifyBinding so the signature shape is
// identical to a binding's.
func buildRevocationPair(signer crypto.Keypair, bindingHash hash.Hash, revokedAt uint64) (entity.Entity, entity.Entity, error) {
	revData := types.RevocationData{Revokes: bindingHash, RevokedAt: revokedAt}
	revEnt, err := revData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("revocation encode: %w", err)
	}
	sigBytes := signer.Sign(revEnt.ContentHash.Bytes())
	signerEnt, err := signer.IdentityEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("signer identity: %w", err)
	}
	sigData := types.SignatureData{
		Target:    revEnt.ContentHash,
		Signer:    signerEnt.ContentHash,
		Algorithm: signerEnt.Type,
		Signature: sigBytes,
	}
	sigEnt, err := sigData.ToEntity()
	if err != nil {
		return entity.Entity{}, entity.Entity{}, fmt.Errorf("revocation signature encode: %w", err)
	}
	return revEnt, sigEnt, nil
}

// writeEntity drops three files per entity: <name>.cbor (full entity
// encoded — for transports that ship the wrapper), <name>.data.hex
// (the raw ECF data bytes, the actual hash input), <name>.hash (the
// 33-byte content_hash as hex). The .data.hex form is what cross-impl
// byte-equality is asserted on.
func writeEntity(dir, name string, e entity.Entity) error {
	// .cbor file = canonical {data, type} 2-key map per ECF — the
	// hash-input bytes (also what a content-fetch returns over the
	// wire as the entity body). Cross-impl byte-equal gate.
	full, err := ecf.EncodeHashable(e.Type, e.Data)
	if err != nil {
		return fmt.Errorf("%s encode: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".cbor"), full, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".data.hex"),
		[]byte(hex.EncodeToString(e.Data)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".hash"),
		[]byte(hex.EncodeToString(e.ContentHash.Bytes())+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func writeNotes(dir string, entry vectorEntry, lines ...string) {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# %s\n\n", entry.ID)
	fmt.Fprintf(b, "**Description**: %s\n\n", entry.Description)
	fmt.Fprintf(b, "**Mode**: `%s`\n", entry.Mode)
	fmt.Fprintf(b, "**Clock (ms)**: `%d`\n", entry.ClockMs)
	fmt.Fprintf(b, "**Resolved name**: `%s`\n\n", entry.Name)
	if entry.BindingHash != "" {
		fmt.Fprintf(b, "**Binding hash**: `%s`\n", entry.BindingHash)
	}
	if entry.SignatureHash != "" {
		fmt.Fprintf(b, "**Signature hash**: `%s`\n", entry.SignatureHash)
	}
	if entry.RevocationHash != "" {
		fmt.Fprintf(b, "**Revocation hash**: `%s`\n", entry.RevocationHash)
		fmt.Fprintf(b, "**Revocation signature hash**: `%s`\n", entry.RevocationSigHash)
	}
	fmt.Fprintln(b)
	fmt.Fprintln(b, "## Reproduction notes")
	fmt.Fprintln(b)
	for _, l := range lines {
		fmt.Fprintf(b, "- %s\n", l)
	}
	expected, _ := json.MarshalIndent(entry.ExpectedResult, "", "  ")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "## Expected ResolveResultData")
	fmt.Fprintln(b)
	fmt.Fprintf(b, "```json\n%s\n```\n", string(expected))
	_ = os.WriteFile(filepath.Join(dir, "notes.md"), []byte(b.String()), 0o644)

	// Companion expected.json for programmatic consumers.
	_ = os.WriteFile(filepath.Join(dir, "expected.json"),
		append(expected, '\n'), 0o644)
}

func strPtr(s string) *string { return &s }

// --- Self-verification ---------------------------------------------------

// verifyAll re-runs every emitted vector through the real backend in-process
// — proves the fixture matches what the runtime actually produces. A
// divergence here is a generator bug, not a Keystone problem.
func verifyAll(registryKey crypto.Keypair, registryEnt entity.Entity, registryPID string, attackerKey crypto.Keypair, m manifest) error {
	for _, v := range m.Vectors {
		switch v.ID {
		case "REG-PEERISSUED-RESOLVE-1":
			if err := verifyResolve(registryKey, registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		case "REG-PEERISSUED-VERIFY-FAIL-1":
			if err := verifyVerifyFail(attackerKey, registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		case "REG-PEERISSUED-REVOKED-1":
			if err := verifyRevoked(registryKey, registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		case "REG-PEERISSUED-EXPIRED-1":
			if err := verifyExpired(registryKey, registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		case "REG-PEERISSUED-PRECEDE-1":
			if err := verifyPrecede(registryKey, registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		case "REG-PEERISSUED-OFFLINE-NOTFOUND-1":
			if err := verifyOfflineNotFound(registryEnt, registryPID, v); err != nil {
				return fmt.Errorf("%s: %w", v.ID, err)
			}
		default:
			return fmt.Errorf("unknown vector %s", v.ID)
		}
	}
	return nil
}

func verifyResolve(registryKey crypto.Keypair, registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader()
	body := types.BindingData{Name: fixedName, Kind: types.BindingKindPeerIssued,
		TargetPeerID: fixTargetPeerID, IssuedAt: ClockIssuedAt}
	bind, sig, _ := buildBindingPair(registryKey, body)
	reader.tree[types.PeerIssuedByNamePath(fixedName)] = bind.ContentHash
	reader.tree[types.LocalSignaturePath(bind.ContentHash)] = sig.ContentHash
	reader.content[bind.ContentHash] = bind
	reader.content[sig.ContentHash] = sig
	be, err := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithClock(func() uint64 { return v.ClockMs }))
	if err != nil {
		return err
	}
	r, err := be.Resolve(newHctx(), fixedName)
	if err != nil {
		return fmt.Errorf("unexpected error: %w", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		return fmt.Errorf("status: got %q want %q", r.Status, types.ResolutionStatusResolved)
	}
	if r.PeerID != fixTargetPeerID {
		return fmt.Errorf("peer_id: got %s want %s", r.PeerID, fixTargetPeerID)
	}
	want := types.PeerIssuedTrustAnchor(registryPID)
	if r.TrustAnchor != want {
		return fmt.Errorf("trust_anchor: got %s want %s", r.TrustAnchor, want)
	}
	if r.BackendID != registryPID {
		return fmt.Errorf("backend_id: got %s want %s", r.BackendID, registryPID)
	}
	return nil
}

func verifyVerifyFail(attackerKey crypto.Keypair, registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader()
	body := types.BindingData{Name: fixedName, Kind: types.BindingKindPeerIssued,
		TargetPeerID: "2KAttackerForgedTargetPeerID111111111111111111", IssuedAt: ClockIssuedAt}
	bind, sig, _ := buildBindingPair(attackerKey, body)
	reader.tree[types.PeerIssuedByNamePath(fixedName)] = bind.ContentHash
	reader.tree[types.LocalSignaturePath(bind.ContentHash)] = sig.ContentHash
	reader.content[bind.ContentHash] = bind
	reader.content[sig.ContentHash] = sig
	be, _ := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithClock(func() uint64 { return v.ClockMs }))
	_, err := be.Resolve(newHctx(), fixedName)
	if err == nil {
		return errors.New("expected verify-fail error, got nil")
	}
	return nil
}

func verifyRevoked(registryKey crypto.Keypair, registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader()
	body := types.BindingData{Name: fixedName, Kind: types.BindingKindPeerIssued,
		TargetPeerID: fixTargetPeerID, IssuedAt: ClockIssuedAt}
	bind, sig, _ := buildBindingPair(registryKey, body)
	rev, revSig, _ := buildRevocationPair(registryKey, bind.ContentHash, ClockIssuedAt+500_000)
	reader.tree[types.PeerIssuedByNamePath(fixedName)] = bind.ContentHash
	reader.tree[types.LocalSignaturePath(bind.ContentHash)] = sig.ContentHash
	reader.tree[types.PeerIssuedRevocationByTargetPath(bind.ContentHash)] = rev.ContentHash
	reader.tree[types.LocalSignaturePath(rev.ContentHash)] = revSig.ContentHash
	reader.content[bind.ContentHash] = bind
	reader.content[sig.ContentHash] = sig
	reader.content[rev.ContentHash] = rev
	reader.content[revSig.ContentHash] = revSig
	be, _ := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithClock(func() uint64 { return v.ClockMs }))
	_, err := be.Resolve(newHctx(), fixedName)
	if err == nil {
		return errors.New("expected revoked error, got nil")
	}
	if !strings.Contains(err.Error(), "revoked") {
		return fmt.Errorf("expected revoked-shaped error, got %q", err)
	}
	return nil
}

func verifyExpired(registryKey crypto.Keypair, registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader()
	ttl := ClockTTLShort
	body := types.BindingData{Name: fixedName, Kind: types.BindingKindPeerIssued,
		TargetPeerID: fixTargetPeerID, IssuedAt: ClockIssuedAt, TTL: &ttl}
	bind, sig, _ := buildBindingPair(registryKey, body)
	reader.tree[types.PeerIssuedByNamePath(fixedName)] = bind.ContentHash
	reader.tree[types.LocalSignaturePath(bind.ContentHash)] = sig.ContentHash
	reader.content[bind.ContentHash] = bind
	reader.content[sig.ContentHash] = sig
	be, _ := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithClock(func() uint64 { return v.ClockMs }))
	_, err := be.Resolve(newHctx(), fixedName)
	if err == nil {
		return errors.New("expected expired error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		return fmt.Errorf("expected expired-shaped error, got %q", err)
	}
	return nil
}

func verifyPrecede(registryKey crypto.Keypair, registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader() // empty — must not be touched for binding/signature
	body := types.BindingData{Name: fixedName, Kind: types.BindingKindPeerIssued,
		TargetPeerID: fixTargetPeerID, IssuedAt: ClockIssuedAt}
	bind, sig, _ := buildBindingPair(registryKey, body)
	hctx := newHctx()
	if _, err := hctx.Store.Put(bind); err != nil {
		return err
	}
	if _, err := hctx.Store.Put(sig); err != nil {
		return err
	}
	if _, err := hctx.TreeSet(types.PeerIssuedByNamePath(fixedName), bind.ContentHash, "preseed"); err != nil {
		return err
	}
	if _, err := hctx.TreeSet(types.LocalSignaturePath(bind.ContentHash), sig.ContentHash, "preseed"); err != nil {
		return err
	}
	be, _ := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithClock(func() uint64 { return v.ClockMs }))
	r, err := be.Resolve(hctx, fixedName)
	if err != nil {
		return fmt.Errorf("offline resolve failed: %w", err)
	}
	if r.Status != types.ResolutionStatusResolved {
		return fmt.Errorf("offline status: got %s want resolved", r.Status)
	}
	// The revocation by-target lookup MAY hit the reader (one TreeGet
	// that misses → not_found). Binding / signature lookups MUST NOT.
	for _, c := range reader.calls {
		if strings.HasPrefix(c, "tree:"+types.PeerIssuedByNamePath(fixedName)) {
			return fmt.Errorf("offline path hit wire for binding by-name: %s", c)
		}
		if strings.HasPrefix(c, "content:") {
			return fmt.Errorf("offline path hit wire for content: %s", c)
		}
	}
	return nil
}

func verifyOfflineNotFound(registryEnt entity.Entity, registryPID string, v vectorEntry) error {
	reader := newMemReader()
	be, _ := peerissued.New(registryEnt, registryPID, reader,
		peerissued.WithNegativeTTLMillis(NegativeTTL))
	r, err := be.Resolve(newHctx(), v.Name)
	if err != nil {
		return fmt.Errorf("not_found should NOT error: %w", err)
	}
	if r.Status != types.ResolutionStatusNotFound {
		return fmt.Errorf("status: got %s want not_found", r.Status)
	}
	if r.NegTTL == nil || *r.NegTTL != NegativeTTL {
		return fmt.Errorf("neg_ttl: got %v want %d", r.NegTTL, NegativeTTL)
	}
	if r.BackendID != registryPID {
		return fmt.Errorf("backend_id: got %s want %s", r.BackendID, registryPID)
	}
	return nil
}

// --- In-process helpers --------------------------------------------------

type memReader struct {
	tree    map[string]hash.Hash
	content map[hash.Hash]entity.Entity
	calls   []string
}

func newMemReader() *memReader {
	return &memReader{tree: map[string]hash.Hash{}, content: map[hash.Hash]entity.Entity{}}
}

func (r *memReader) TreeGet(_ context.Context, path string) (hash.Hash, error) {
	r.calls = append(r.calls, "tree:"+path)
	if h, ok := r.tree[path]; ok {
		return h, nil
	}
	return hash.Hash{}, peerissued.ErrNotFound
}

func (r *memReader) ContentGet(_ context.Context, h hash.Hash) (entity.Entity, error) {
	r.calls = append(r.calls, "content:"+hex.EncodeToString(h.Bytes()))
	if ent, ok := r.content[h]; ok {
		return ent, nil
	}
	return entity.Entity{}, peerissued.ErrNotFound
}

func newHctx() *handler.HandlerContext {
	cs := store.NewMemoryContentStore()
	kp := crypto.FromSeed([32]byte{0xFF, 0xEE})
	pid := kp.PeerID()
	li := store.NewNamespacedIndex(store.NewMemoryLocationIndex(), string(pid))
	return &handler.HandlerContext{
		Store:         cs,
		LocationIndex: li,
		LocalPeerID:   pid,
	}
}

// writeReadme drops the top-level reproduction guide.
func writeReadme(outDir string, m manifest) error {
	b := &strings.Builder{}
	fmt.Fprintln(b, "# REG-PEERISSUED-* cohort fixtures")
	fmt.Fprintln(b)
	fmt.Fprintf(b, "**Proposal**: %s\n\n", m.Proposal)
	fmt.Fprintf(b, "**Bundle version**: %s\n", m.BundleVersion)
	fmt.Fprintf(b, "**Generator**: `%s` (Go reference)\n\n", m.Generated)
	fmt.Fprintln(b, "## Pinned registry identity")
	fmt.Fprintln(b)
	fmt.Fprintf(b, "- **base58 peer-id**: `%s`\n", m.RegistryPeerID)
	fmt.Fprintf(b, "- **identity content_hash**: `%s`\n", m.RegistryIdentityHash)
	fmt.Fprintln(b, "- **seed (Ed25519, 32-byte)**: `registry/seed.hex`")
	fmt.Fprintln(b, "- **attacker seed (used by VERIFY-FAIL-1 only)**: `registry/attacker_seed.hex`")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "## Vectors")
	fmt.Fprintln(b)
	for _, v := range m.Vectors {
		fmt.Fprintf(b, "### %s (`%s`)\n\n", v.ID, v.Mode)
		fmt.Fprintf(b, "%s\n\n", v.Description)
		if v.BindingHash != "" {
			fmt.Fprintf(b, "- binding: `%s`\n", v.BindingHash)
		}
		if v.SignatureHash != "" {
			fmt.Fprintf(b, "- signature: `%s`\n", v.SignatureHash)
		}
		if v.RevocationHash != "" {
			fmt.Fprintf(b, "- revocation: `%s`\n", v.RevocationHash)
			fmt.Fprintf(b, "- revocation signature: `%s`\n", v.RevocationSigHash)
		}
		fmt.Fprintf(b, "- clock (ms): `%d`\n", v.ClockMs)
		fmt.Fprintf(b, "- files: `vectors/%s/`\n\n", strings.TrimPrefix(v.ID, "REG-PEERISSUED-"))
	}
	fmt.Fprintln(b, "## How a cross-impl runner consumes this bundle")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "1. Load `registry/identity.cbor` as the pinned trust root (no fetching — the receiver MUST pin this identity ahead of time).")
	fmt.Fprintln(b, "2. For each `live` vector: stand up a Reader that serves the declared (path → hash) and (hash → entity) entries from the vector's `*.cbor` files. Call your `Resolve(name)`. Assert outcome matches `expected.json`.")
	fmt.Fprintln(b, "3. For each `offline` vector: pre-seed your local store per `notes.md` (the `offline_preseed` map in MANIFEST.json), then call `Resolve(name)` with an EMPTY Reader. The binding + signature lookups MUST be satisfied from local state; only the revocation by-target lookup MAY hit the wire.")
	fmt.Fprintln(b, "4. Byte-equal gate: the `.data.hex` files are the ECF-encoded data bytes that go into `content_hash` (V7 §1.5). Two impls re-deriving from the seeds + the same `BindingData` / `SignatureData` / `RevocationData` MUST emit the same `.data.hex` (and therefore the same `.hash`).")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "## Notes (from MANIFEST.json)")
	fmt.Fprintln(b)
	for _, n := range m.Notes {
		fmt.Fprintf(b, "- %s\n", n)
	}
	return os.WriteFile(filepath.Join(outDir, "README.md"), []byte(b.String()), 0o644)
}
