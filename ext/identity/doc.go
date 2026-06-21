// Package identity implements EXTENSION-IDENTITY v3.3 — the convention
// layer over EXTENSION-ATTESTATION (system/attestation) and
// EXTENSION-QUORUM (system/quorum) that establishes recognizable,
// recoverable, rotatable presence in the signed-graph substrate.
//
// Identity v3.3 contributes:
//
//   - Two identity-owned types: system/identity/peer-config (per-agent
//     local state) and system/identity/identity-binding (helper inner
//     type carried inside peer-config.bindings).
//   - Four properties.kind values for identity-context system/attestation
//     entities: "identity-cert", "identity-rotation-handoff",
//     "identity-rotation-recovery", "identity-retirement". Plus
//     identity-specific authority rules over the universal "revocation"
//     kind owned by EXTENSION-ATTESTATION.
//   - Standard cert function values: "controller", "agent", "identifier";
//     app-defined functions allowed (per §4.2 row 5).
//   - Publication modes for identity-cert attestations: "internal",
//     "public", "per-relationship", "embedded". Mode is fixed at
//     create-time per §4.2 — eliminates the in-flight rotation race that a
//     runtime shape lookup would create.
//   - Topology dispatch (which kind/function/handle-bearing combination
//     requires K-of-N from quorum vs. single-sig from controller vs.
//     dual-sig for handoff).
//   - Cert-chain walking (walk via attesting back to a quorum;
//     terminate predicate identity_is_quorum_link).
//   - Identity-specific authority-revocation rules (only the quorum at
//     the chain root may revoke its certs).
//   - Storage path conventions per properties.mode (internal/public/
//     per-relationship/embedded).
//   - Registration of "identity-resolved" signer-resolution mode against
//     EXTENSION-QUORUM's pluggable resolver hook (§5.2).
//   - Seven handler operations: configure, create_quorum,
//     create_attestation, supersede_attestation, revoke_attestation,
//     publish_attestation, process_attestation.
//
// Three-parallel-mechanisms invariant (§2.2): identity attestations are
// validated by identity_verify_cert which composes EXTENSION-ATTESTATION
// helpers + EXTENSION-QUORUM K-of-N. They are NEVER routed through V7's
// verify_capability_chain. The three classes (V7 capability tokens,
// system/attestation entities, system/quorum entities) share signature-
// counting at a low level but maintain type-level distinction.
//
// Mechanics that would otherwise live here are delegated to primitives:
// signature verification, supersedes-chain walks, liveness checks,
// revocation lookups, and K-of-N validation are all primitive calls.
// Identity contributes ~60 lines of orchestration + dispatch + identity-
// specific predicates per §3.6.
package identity
