// Package role implements the system/role handler per EXTENSION-ROLE v1.5.
//
// Roles are named bundles of capability grant entries that the role handler
// issues as capability tokens when a peer is assigned to a role within a
// context. The role extension is a management abstraction over the
// capability system (V7 §5) — capabilities remain the enforcement mechanism;
// roles add organizational structure on top.
//
// # Operations
//
//   - define     — write or mutate a role definition (RL2 at write-time + re-derive cascade)
//   - assign     — bind a peer to a role within a context (RL2 + grant derivation)
//   - unassign   — remove an assignment and revoke role-derived tokens (IA12)
//   - exclude    — deny a peer all role-derived access in a context (layer-1 sweep, R7)
//   - unexclude  — remove an exclusion entity (does NOT auto-restore tokens)
//   - re-derive  — re-issue role-derived tokens for all assignees after a definition change (IA9)
//   - delegate   — member-to-member delegation rooted at the delegator's runtime peer (IA22)
//
// # Tree paths
//
//	system/role/{context}/{role_name}                      — role definition
//	system/role/{context}/assignment/{peer_id}/{role_name} — assignment
//	system/role/{context}/excluded/{peer_id}               — exclusion
//	system/capability/grants/role-derived/{context}/{peer_id}/{token_hash}
//	                                                       — role-derived caps (R4)
//
// # Invariants
//
//   - Role definitions, assignments, and exclusions are load-bearing
//     (§1.3): direct tree:put to system/role/{context}/{role_name},
//     assignment/*, or excluded/* is rejected at content validation.
//     Runtime derivation flows through the role handler so RL2 (§4.3,
//     §5.1) and re-derive cascade (§5.5) can be enforced.
//
//   - Bootstrap is the only other write path — L0-only per §4.5 IA13.
//
//   - Layer-1 token revocation (§6.1) makes exclusion fleet-wide via the
//     OnTreeChange sweep (§6.5 IA8): a non-issuing runtime peer that
//     receives an exclusion entity sweeps its own role-derived subtree.
//
// Spec: ../entity-core-architecture/docs/architecture/v7.0-core-revision/
// core-protocol-domain/specs/extensions/EXTENSION-ROLE.md (v1.5).
package role
