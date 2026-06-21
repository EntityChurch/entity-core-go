// Package store defines the two-layer storage interfaces and a memory
// implementation.
//
// ContentStore is the immutable content-addressed store: Hash → Entity.
// LocationIndex is the mutable location index: URI → Hash.
//
// The memory implementation provides an in-process store suitable for
// testing and single-peer scenarios.
//
// Dependencies: hash, entity
package store
