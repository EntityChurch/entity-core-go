// Package capability implements the authorization system: capability tokens,
// grants, delegation chains, and two-level scope checking.
//
// A capability token grants permission for specific operations on resources
// matching URI patterns. Tokens can be delegated with attenuation — child
// tokens must be a subset of the parent's permissions.
//
// Scope checking is two-level:
//  1. Handler scope: capability covers the handler's registered path
//  2. Path scope: capability covers the specific entity being accessed
//
// Dependencies: hash, entity, crypto
package capability
