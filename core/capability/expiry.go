package capability

// Expired reports whether a capability carrying the given expires_at is expired
// at time now (both in ms since the Unix epoch).
//
// CAP-6 (0.8.1, ENTITY-CORE-PROTOCOL §5.6): expiry is an EXCLUSIVE upper bound —
// a capability is expired when now >= expires_at, i.e. the validity window is the
// half-open interval [not_before, expires_at). A nil expires_at never expires.
//
// This is the SINGLE enforcement point for the boundary. Every "is this capability
// currently expired" gate — request/path permission checks, chain-link validation,
// grant validity, and the ext consumers (compute installation grants, subscription
// delivery tokens, network delivery-token liveness) — routes through here rather
// than inlining the comparison. The inline form was `< now` (inclusive at the
// boundary) until CAP-6; that made a token minted with ttl_ms:0 (expires_at ==
// created_at, per §5.6 rule 2) valid for exactly one instant and racing. Do not
// re-inline: the comparison has been wrong before, and one place is where it stays
// pinned by TestExpiredExclusiveBoundary.
func Expired(expiresAt *uint64, now uint64) bool {
	return expiresAt != nil && *expiresAt <= now
}
