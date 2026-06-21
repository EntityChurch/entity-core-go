// Package attestation implements EXTENSION-ATTESTATION v1.0 — the substrate
// primitive for the system's signed graph.
//
// The attestation primitive defines:
//
//   - One entity type: system/attestation (the edge type in the signed graph).
//   - Two signature-validation helpers: VerifyAttestationSignature (default
//     single-sig per §4.1), VerifySpecificSigner (used by consumers for
//     dual-sig and other multi-sig topologies per §4.2).
//   - One composite liveness check: IsAttestationLive (expiration +
//     supersession + self-revocation, with as_of for time-traveling
//     validation per §4.3).
//   - Six graph operations (parameterized by consumer-supplied predicates
//     where interpretation matters): WalkAttestingChain (with
//     DefaultFindAuthorizing per §5.1), WalkSupersedesChain, FindLiveHead,
//     FindAttestationsTargeting, FindAttestationsBy, FindRevocationsFor,
//     FindAttestationsWithSupersedes, FindAttestationsWithKind.
//   - Four handler operations: system/attestation:create, :supersede, :revoke,
//     :verify.
//   - One universal kind: "revocation". All other kinds belong to consumer
//     extensions.
//   - Index invariants on attesting, attested, properties.kind, supersedes
//     fields per §5.7 / §9.1.
//
// Consumer extensions (identity, quorum, future VC / reputation / cluster /
// transaction / governance / audit) layer semantics on top by registering
// their own properties.kind values, signature topology rules, storage paths,
// and lifecycle semantics. The primitive itself does not interpret kinds
// other than "revocation" and does not mandate storage paths.
//
// Three-parallel-mechanisms invariant (§2.1): system/attestation entities
// are validated by the helpers in this package plus consumer-specific rules.
// They are NEVER routed through V7's verify_capability_chain machinery
// (cap-token validation) and are NEVER processed as system/quorum entities
// (whose validator lives in ext/quorum). The three classes share
// signature-counting at a low level but maintain type-level distinction.
package attestation
