// Package entity defines the core data structures of the entity system:
// Entity, Envelope, URI, and ValidatedEntity.
//
// An Entity is a typed data unit with a type string and data as cbor.RawMessage.
// The data field preserves byte fidelity for hash verification — it is never
// decoded and re-encoded during storage or forwarding.
//
// An Envelope packages a root entity with included referenced entities for
// wire transmission.
//
// A URI addresses entities in the tree: entity://peer_id/path
//
// Dependencies: hash, ecf
package entity
