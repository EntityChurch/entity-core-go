// Package protocol implements the EXECUTE dispatch, handshake flow, and
// request authentication.
//
// The handshake flow:
//  1. HELLO exchange (peer_id, nonce, protocols)
//  2. IDENTIFY exchange (public_key, signature of nonce)
//  3. Capability grant exchange
//  4. EXECUTE messages with capability references
//
// Dependencies: handler, wire, crypto, types
package protocol
