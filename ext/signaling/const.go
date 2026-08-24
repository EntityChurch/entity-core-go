// Package signaling implements the entity-core-go CLIENT of the rendezvous /
// NAT-introduction surface (PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH §2.2/§3,
// PROPOSAL-CONNECTION-NODE). Go leads the client build; the server/node role
// lives in the sibling subpackage ext/signaling/node (the §4/§5 rendezvous node),
// added so Go self-hosts the rendezvous for the cross-impl punch gate rather than
// depending on the Rust entity-signaling-node — a second server is exactly the
// convergence signal §5 asks for. This package stays client-only.
//
// The package is client obligations only — key derivation (§2.2), pool
// selection (§3.1.1), the §3 coordination messages and their dial ordering,
// §4.4 blob framing + §4.5 bucket-read rules, and a thin Offer/Collect/Advertise
// client over a Transport. It depends only on core (core ← ext ← cmd).
//
// SOURCE OF TRUTH: the arch signaling corpus is not yet committed upstream. Every
// shape here traces to the rust→cohort build brief
// (entity-core-rust/docs/status/HANDOFF-2026-07-30-signaling-go-py-client-brief.md);
// re-diff against the committed spec once it lands.
package signaling

const (
	// HandlerPattern is the wrapped signaling handler's address pattern (§5.1).
	HandlerPattern = "system/signaling"

	// OpOffer deposits a blob at a rendezvous key (§5.1).
	OpOffer = "offer"
	// OpCollect reads a rendezvous key's bucket non-destructively (§5.1).
	OpCollect = "collect"
	// OpAdvertise returns the node's endpoint/limits/lobby (§5.1).
	OpAdvertise = "advertise"
)

const (
	// rendezvousKeyType is the `type` half of the §2.2 hash input. Pinned
	// because the substrate content-hash primitive hashes ECF {data, type} and
	// has no bare-byte form.
	rendezvousKeyType = "system/signaling/rendezvous-key"

	// domain is the §2.2 domain-separation prefix. Versioned so a future
	// derivation change is a new domain, not a silent reinterpretation.
	domain = "entity:rdv:v1"

	// sep = ASCII US (0x1F). It appears AFTER the domain string and AFTER the
	// mode tag — not only before the input (§4.1).
	sep = 0x1F

	// The exact ASCII mode tags (§2.2). Wire-visible through the derived key.
	modePair   = "pair"
	modeTag    = "tag"
	modeSecret = "secret"
	modeLobby  = "lobby"

	// LobbyDefault is the §2.2 Finding-B named default for `lobby` mode, used
	// unless the node's advertise published an override. "Per deployment"
	// without an actual named default is a silent-never-meet bug.
	LobbyDefault = "lobby:default"
)
