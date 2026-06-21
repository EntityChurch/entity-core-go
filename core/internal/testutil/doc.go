// Package testutil provides shared test helpers for entity-core-go packages.
//
// Helpers include factory functions for creating test entities, hashes,
// keypairs, and other fixtures. This package is internal and cannot be
// imported by external consumers.
//
// Example helpers:
//   - MakeEntity(typ, data) — create an entity with computed hash
//   - MakeHash(data) — compute a content hash
//   - MakeKeypair() — generate a test Ed25519 keypair
package testutil
