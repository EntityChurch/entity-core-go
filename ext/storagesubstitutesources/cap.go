// Capability gate per RULING-NAMED-CAPABILITY-MAPPING +
// PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS D-2.
//
// The named cap `system/capability/content-substitute-consult` referenced
// in SUBSTITUTE-SOURCES §2.5 reduces to a grant on (handler-pattern,
// operation-id) = (system/substitute/sources, consult), checked by V7
// §5.2 check_permission. Per-cap narrowing — source_peer_id,
// substitute_types — lives in the grant's `constraints` map (byte-equal
// under delegation, V7 §5.6).
//
// Per D-2 the **resource axis = the triggering CONTENT EXECUTE's
// `resource_target`** (the target namespace the consumer is reading
// into). A static chain-namespace resource (which Go's initial cap-fix
// used) is BANNED by D-2 — it didn't compose with delegation across
// peers. The orchestrator is invoked from the CONTENT miss-resolver, so
// hctx.Resource is the inbound content:get's resource_target — exactly
// what the spec pins.
//
// Fail closed: absent a matching grant the gate denies. "Any token
// present" is NOT a grant match.

package storagesubstitutesources

import (
	"fmt"

	"go.entitychurch.org/entity-core-go/core/capability"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

// HandlerPatternSources is the handler pattern the consult gate checks
// against per the ruling §4 mapping. Stable cohort identifier.
const HandlerPatternSources = "system/substitute/sources"

// OperationConsult is the operation id the consult gate checks against
// per the ruling §4 mapping. Stable cohort identifier.
const OperationConsult = "consult"

// ConsultGateDenied is the descriptive error returned when a consult
// check fails. The orchestrator maps it to OutcomeDisabled so the
// chain aborts at the gate (no leakage of which axis denied).
type ConsultGateDenied struct {
	Reason string
}

func (e *ConsultGateDenied) Error() string {
	return "consult denied: " + e.Reason
}

// checkConsultGrant applies the ruling's check_permission to the consult
// gate per D-2's pinned resource axis. Returns nil when the caller's
// grant permits consultation against the claimed source for the
// triggering CONTENT request's namespace; *ConsultGateDenied otherwise.
//
// Fail-closed default: an empty CallerCapability denies. The pinned
// shape is:
//
//	handler   = HandlerPatternSources
//	operation = OperationConsult
//	resource  = hctx.Resource (D-2: triggering CONTENT resource_target)
//	peers     = (default — chain root is the local peer)
//
// Constraint narrowing: when the grant carries a `source_peer_id`
// constraint, the claimed source MUST equal it byte-for-byte.
func (o *Orchestrator) checkConsultGrant(hctx *handler.HandlerContext, claimedSourcePeerID hash.Hash) error {
	if hctx.CallerCapability.ContentHash.IsZero() {
		return &ConsultGateDenied{Reason: "no caller capability (fail closed)"}
	}
	capData, err := types.CapabilityTokenDataFromEntity(hctx.CallerCapability)
	if err != nil {
		return &ConsultGateDenied{Reason: "invalid caller capability: " + err.Error()}
	}

	// D-2: resource axis is the inbound CONTENT EXECUTE's resource_target
	// (the namespace the consumer is reading into). Without one the
	// triggering content:get is malformed — fail closed.
	if hctx.Resource == nil || len(hctx.Resource.Targets) == 0 {
		return &ConsultGateDenied{Reason: "no resource_target on inbound content:get (D-2)"}
	}

	execute := types.ExecuteData{
		Operation: OperationConsult,
		Resource:  hctx.Resource,
	}

	// Per VerifyChain Site 3 the chain root equals the local peer — use
	// LocalPeerID for both canonicalization axes (PR-8 self-issued case).
	grant, ok := capability.FindMatchingGrant(execute, capData,
		HandlerPatternSources, hctx.LocalPeerID, hctx.LocalPeerID)
	if !ok {
		return &ConsultGateDenied{Reason: fmt.Sprintf(
			"no matching grant for (%s, %s, resource=%v)",
			HandlerPatternSources, OperationConsult, hctx.Resource.Targets)}
	}

	if err := enforceConsultConstraints(grant.Constraints, claimedSourcePeerID); err != nil {
		return err
	}
	return nil
}

// consultConstraints decodes the ruling §4 narrowing fields off a grant.
// Unknown keys are tolerated for forward compatibility; recognized keys
// (`source_peer_id`) are enforced byte-equal per V7 §5.6.
type consultConstraints struct {
	SourcePeerID *hash.Hash `cbor:"source_peer_id,omitempty"`
}

// enforceConsultConstraints walks the recognized narrowing fields off the
// grant's constraints map. Currently enforces `source_peer_id` — if
// present, the claimed source MUST equal it. Other keys (substitute_types
// etc.) are placeholders for future narrowing and pass through.
func enforceConsultConstraints(raw cbor.RawMessage, claimedSourcePeerID hash.Hash) error {
	if len(raw) == 0 {
		return nil
	}
	var c consultConstraints
	if err := cbor.Unmarshal(raw, &c); err != nil {
		return &ConsultGateDenied{Reason: "constraints decode failed: " + err.Error()}
	}
	if c.SourcePeerID != nil && *c.SourcePeerID != claimedSourcePeerID {
		return &ConsultGateDenied{Reason: "source_peer_id constraint mismatch"}
	}
	return nil
}
