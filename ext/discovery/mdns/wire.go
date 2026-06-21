// Package mdns implements the v1 DISCOVERY backend per EXTENSION-DISCOVERY
// §3 + §3.2 wire pin. This file pins the §3.2 DNS-SD wire-interop
// constants as the cross-impl-convergence anchor (the **silent** failure
// mode the cohort flagged — Go + Rust + Py never see each other on the
// LAN if these differ, with no error to catch).
package mdns

// ServiceType is the DNS-SD service-name convention per RFC 6763 §7.
// PINNED NORMATIVE per EXTENSION-DISCOVERY §3.2 — Go + Rust + Py MUST
// emit this exact full string on the wire or LAN-discovery silently fails.
//
// `ServiceType` is the canonical full name (service + domain). The
// grandcat/zeroconf API takes service + domain as separate arguments —
// `ServiceTypeLabel` is the service-half and `ServiceDomain` is the
// domain-half. The cohort spec pin is the concatenation; the split is a
// Go-side adapter for the library API.
const (
	ServiceType      = "_entity-core._udp.local."
	ServiceTypeLabel = "_entity-core._udp"
	ServiceDomain    = "local."
)

// MUST-present TXT keys per §3.2. Every Go-advertised announcement
// emits all three; consumers that fail to find one MUST treat the
// candidate as forward-incompatible (not a degraded-mode admission).
//
// The keys are alphabetically ordered here for ease of cross-impl audit;
// runtime TXT-key emission order is determined by the mDNS library, but
// the spec §3.2 doesn't require ordering — `version`, `peer_id_hint`,
// `profile_ref` MUST be PRESENT, not in any particular slot.
const (
	TXTKeyVersion      = "version"
	TXTKeyPeerIDHint   = "peer_id_hint"
	TXTKeyProfileRef   = "profile_ref"
	TXTKeyProto        = "proto"        // OPTIONAL — comma-list of advertised transports
	TXTKeyDisplayName  = "display_name" // OPTIONAL — UTF-8 user-facing label hint
)

// CurrentVersion is the DISCOVERY major version pinned in TXTKeyVersion.
// Bumps only on a breaking wire change (none planned for v1.x).
const CurrentVersion = "1"

// Backend kind identifier — matches types.DiscoveryBackendMDNS for the
// substrate's backend-lookup table.
const BackendKind = "mdns"
