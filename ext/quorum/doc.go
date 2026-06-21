// Package quorum implements EXTENSION-QUORUM v1.0 — the K-of-N node
// primitive in the system's signed-graph substrate.
//
// The quorum primitive defines:
//
//   - One entity type: system/quorum (the K-of-N signing roster — special
//     node type whose "signature" is K signatures from N constituent peers).
//   - Two helpers: VerifyKOfNSignatures (the K-of-N validator callable on
//     any entity per §4.1), CurrentSignerSet (walks the live quorum-update
//     chain to determine the effective signer set per §4.2, with cache
//     contract per §4.2.1).
//   - Quorum identification: IsQuorumID (path-based lookup at
//     system/quorum/{hex(hash)} per §4.3).
//   - Two attestation conventions: properties.kind = "quorum-update" and
//     "quorum-publish". Both are system/attestation entities (per
//     EXTENSION-ATTESTATION) discriminated by kind — NOT separate entity
//     types.
//   - Pluggable signer-resolution interface: "concrete" mode built in;
//     other modes registered at runtime by other extensions
//     (EXTENSION-IDENTITY v3.3 registers "identity-resolved" against this
//     hook on its configure operation).
//   - Four handler operations: system/quorum:create, :update, :publish,
//     :verify.
//
// Quorum operations are NOT identity-specific. Any consumer extension that
// needs to manage a quorum (identity, group, cluster, transaction,
// governance, multi-sig committee) calls EXTENSION-QUORUM's operations
// directly. The K-of-N authorization rule is uniform; only the caller varies.
//
// Three-parallel-mechanisms invariant (§10): system/quorum entities are
// validated by VerifyKOfNSignatures plus consumer-specific topology rules.
// They are NEVER routed through V7's verify_capability_chain (cap-token
// validation) and are NEVER processed as system/attestation entities (whose
// validators live in ext/attestation). The three classes share signature-
// counting at a low level but maintain type-level distinction.
package quorum
