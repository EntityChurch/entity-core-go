// Package storagesubstitutesources implements the chain-consultation
// orchestrator per EXTENSION-SUBSTITUTE v1.0 §3 (was §2.2 of the source
// PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-SOURCES; landed and
// consolidated). It walks the ordered chain of substitute-source entries
// for a given source_peer_id and dispatches each to its convention-
// extension handler (system/substitute/<type>:try) per the §4 trust
// contract.
//
// The orchestrator is invoked by the CONTENT miss-hook (companion in
// ext/content) when a local content:get misses. It returns one of four
// outcomes:
//
//   - Bytes — a substitute returned a hash-verified entity; the
//     orchestrator hands it back so the caller can ingest.
//   - NotFound — chain exhausted (or skipped per cap / wildcard rules);
//     the miss is terminal.
//   - CapDenied — a substitute handler returned 403; the chain aborts
//     per §3-RES.10 / §5.1.
//   - Disabled — caller lacks the consult cap, or no claimedSourcePeerID
//     was provided (v1 doesn't support wildcard consultation).
//
// source_peer_id is local context per Ruling 4 — it does NOT travel on
// the wire as a `system/content:get-request` field. Callers in this
// package pass it as an explicit Consult parameter; the CONTENT miss-hook
// supplies it from the dispatcher context.
//
// **Substitute-source signature validation.** Per §2.4, every entry MUST
// carry refs.signature signed by source_peer_id over the entry's content
// hash. The v1.0 first slice exposes a SignatureVerifier hook
// (function field) that defaults to permit-all so the orchestrator is
// testable in isolation; production deployments MUST wire a real
// verifier before exposing this on a live peer. The wiring is left to
// the PeerBuilder integration arc (Phase 1 §3 of the catch-up plan).
//
// Manifest processing (signature verify + freshness gate) is OUT OF
// SCOPE for v1.0 across all three impls per Ruling 5.
package storagesubstitutesources

import (
	"context"
	"sort"
	"time"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

// Outcome distinguishes the four possible results of Consult per §2.2.
type Outcome int

const (
	// OutcomeBytes — a substitute handler returned a hash-verified entity.
	// Bytes carries the entity; the caller ingests it.
	OutcomeBytes Outcome = iota
	// OutcomeNotFound — chain exhausted (or skipped because no entries
	// matched the claimed source). The local miss is terminal.
	OutcomeNotFound
	// OutcomeCapDenied — a convention handler returned 403; the chain
	// aborts per §3-RES.10 / §5.1.
	OutcomeCapDenied
	// OutcomeDisabled — consult-cap absent, or claimedSourcePeerID is
	// zero (no wildcard consultation in v1).
	OutcomeDisabled
)

// ConsultResult is what Consult returns to the caller.
type ConsultResult struct {
	Outcome Outcome
	// Bytes is the verified entity when Outcome == OutcomeBytes.
	Bytes entity.Entity
	// AttemptedCount is how many chain entries were dispatched to
	// (informational; surfaced via the §3-RES.7 substitute_chain_attempted
	// meta the CONTENT miss-hook writes onto the get response).
	AttemptedCount int
	// LastError carries the most recent advance-causing error message
	// (informational; helps debugging). Empty when no errors occurred.
	LastError string
}

// SignatureVerifier validates that a substitute-source entry's signature
// is present and signs the entry's content hash with source_peer_id's
// identity key. Returns nil on valid; non-nil error means the entry MUST
// be rejected (per §2.4 trust contract).
//
// hctx is supplied so verifier implementations can resolve the signature
// entity (at InvariantSignaturePath) and the signer's public key (from
// the system/peer entity) via the peer's content store + location index.
// The real Ed25519 verifier is in verify.go.
//
// A default permit-all verifier is used when none is wired; PRODUCTION
// DEPLOYMENTS MUST WIRE A REAL VERIFIER before exposing this orchestrator.
type SignatureVerifier func(hctx *handler.HandlerContext, entry entity.Entity, srcData types.SubstituteSourceData) error

// permitAllVerifier is the default — used in tests and for the v1.0
// first slice. Production wires a real verifier via WithSignatureVerifier.
func permitAllVerifier(_ *handler.HandlerContext, _ entity.Entity, _ types.SubstituteSourceData) error {
	return nil
}

// Now returns the current time; injectable for tests.
type nowFunc func() time.Time

// Orchestrator implements Consult.
type Orchestrator struct {
	verifySignature SignatureVerifier
	now             nowFunc
}

// Option is a functional knob for New.
type Option func(*Orchestrator)

// WithSignatureVerifier wires the §2.4-required signature check. REQUIRED
// for production; tests and the v1.0 first slice may leave it default
// (permit-all) until the wiring lands in the PeerBuilder integration arc.
func WithSignatureVerifier(v SignatureVerifier) Option {
	return func(o *Orchestrator) { o.verifySignature = v }
}

// WithNow overrides the time source for expires_at checks. Tests only.
func WithNow(fn func() time.Time) Option {
	return func(o *Orchestrator) { o.now = nowFunc(fn) }
}

// New constructs an Orchestrator. Without WithSignatureVerifier the
// default is permit-all — see package doc.
func New(opts ...Option) *Orchestrator {
	o := &Orchestrator{
		verifySignature: permitAllVerifier,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Consult walks the substitute chain for target on behalf of
// claimedSourcePeerID per §2.2. The hctx must carry the caller's cap
// chain (for the cheap pre-flight consult-cap check) + LocationIndex (to
// list substitute entries) + Store (to load entry entities) + Execute
// (to dispatch to convention handlers).
//
// Returns OutcomeDisabled when the consult-cap is absent or
// claimedSourcePeerID is the zero hash (no wildcard in v1).
// Returns OutcomeBytes on the first successful hash-verified fetch.
// Returns OutcomeCapDenied on the first 403 from a convention handler.
// Returns OutcomeNotFound on chain exhaustion.
func (o *Orchestrator) Consult(
	ctx context.Context,
	hctx *handler.HandlerContext,
	target hash.Hash,
	claimedSourcePeerID hash.Hash,
) ConsultResult {
	// §3-RES.2 — bare-hash queries (no claimed source) never consult chain.
	if claimedSourcePeerID.IsZero() {
		return ConsultResult{Outcome: OutcomeDisabled}
	}

	// Cap gate per RULING-NAMED-CAPABILITY-MAPPING §4 —
	// check_permission against (HandlerPatternSources, OperationConsult,
	// ConsultResource) on the caller's grant; fail closed (absent grant
	// denies). source_peer_id constraint narrows by claimed source.
	if err := o.checkConsultGrant(hctx, claimedSourcePeerID); err != nil {
		return ConsultResult{Outcome: OutcomeDisabled, LastError: err.Error()}
	}

	// Enumerate substitute-source entries.
	entries, skips := o.listEntries(hctx, claimedSourcePeerID)
	if len(entries) == 0 {
		res := ConsultResult{Outcome: OutcomeNotFound}
		// Surface the first skip reason so a peer (or validate-peer)
		// debugging "I see entries in the tree but the chain says
		// NotFound" gets a hint — especially "signature_invalid" under
		// the strict-default §2.4 verifier.
		if len(skips) > 0 {
			res.LastError = skips[0]
		}
		return res
	}

	// Dispatch each, in priority order.
	res := ConsultResult{}
	for _, e := range entries {
		res.AttemptedCount++

		handlerURI := substituteHandlerURI(e.data.SubstituteType)
		tryReq := types.SubstituteTryRequestData{
			Entry: e.entity,
			Hash:  target,
		}
		params, err := tryReq.ToEntity()
		if err != nil {
			res.LastError = "encode_try_request: " + err.Error()
			continue
		}

		resp, err := hctx.Execute(ctx, handlerURI, types.OpSubstituteTry, params)
		if err != nil {
			res.LastError = "execute: " + err.Error()
			continue
		}

		switch resp.Status {
		case 200:
			// Re-verify hash even though the handler already did — the
			// orchestrator is the trust anchor per §2.2 ("verify_hash(bytes,
			// hash)" before ingest). Defense-in-depth against a buggy or
			// malicious convention handler.
			if !verifyEntityHash(resp.Result, target) {
				res.LastError = "post_dispatch_hash_mismatch"
				continue
			}
			res.Outcome = OutcomeBytes
			res.Bytes = resp.Result
			return res

		case 403:
			// Cap-denied at the convention handler aborts the whole chain
			// per §3-RES.10 / §5.1 (caller lacks authority for the outbound
			// fetch; trying other entries won't fix that).
			res.Outcome = OutcomeCapDenied
			res.LastError = "convention_handler_403"
			return res

		default:
			// 404, 502, transient — advance to next entry.
			res.LastError = "convention_handler_status_" + statusString(resp.Status)
			continue
		}
	}

	// Chain exhausted with no successful fetch.
	res.Outcome = OutcomeNotFound
	return res
}

// sourceEntry is an enumerated substitute-source entry ready for
// dispatch. We carry the decoded data + the original entity (the entity
// is what gets passed as try-request.Entry).
type sourceEntry struct {
	entity entity.Entity
	data   types.SubstituteSourceData
}

// listEntries scans the location index for substitute-source entries
// under SubstituteSourcePathPrefix, filters per §2.2's predicate (enabled
// + source matches + not expired + signature valid), and sorts by
// priority ascending (lower number = consulted first).
//
// Returns the surviving entries + a slice of skip reasons in scan order.
// Skip reasons are surfaced to ConsultResult.LastError (best-effort
// diagnostic) so cohort/validate-peer interop sees WHY an entry was
// rejected instead of an opaque NotFound. Especially load-bearing for
// signature-verification skips under the strict-default §2.4 posture.
func (o *Orchestrator) listEntries(hctx *handler.HandlerContext, claimed hash.Hash) ([]sourceEntry, []string) {
	if hctx.LocationIndex == nil || hctx.Store == nil {
		return nil, nil
	}
	now := uint64(o.now().Unix())

	var out []sourceEntry
	var skips []string
	for _, entry := range hctx.LocationIndex.List(types.SubstituteSourcePathPrefix) {
		ent, ok := hctx.Store.Get(entry.Hash)
		if !ok {
			continue
		}
		if ent.Type != types.TypeSubstituteSource {
			continue
		}
		data, err := types.SubstituteSourceDataFromEntity(ent)
		if err != nil {
			skips = append(skips, "decode_failed: "+err.Error())
			continue
		}
		if !data.Enabled {
			skips = append(skips, "skip "+data.Name+": disabled")
			continue
		}
		if data.SourcePeerID != claimed {
			// Common case — entry for a different source peer. Don't
			// pollute diagnostics with these; the chain is per-source by
			// design.
			continue
		}
		if data.ExpiresAt != 0 && data.ExpiresAt <= now {
			skips = append(skips, "skip "+data.Name+": expired")
			continue
		}
		// §2.4 signature MUST. Skip if verifier rejects, but record
		// the reason so the orchestrator's result surfaces it.
		if err := o.verifySignature(hctx, ent, data); err != nil {
			skips = append(skips, "skip "+data.Name+": signature_invalid: "+err.Error())
			continue
		}
		out = append(out, sourceEntry{entity: ent, data: data})
	}

	// Priority ascending; ties resolved by SubstituteHash for determinism.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].data.Priority != out[j].data.Priority {
			return out[i].data.Priority < out[j].data.Priority
		}
		return out[i].entity.ContentHash.String() < out[j].entity.ContentHash.String()
	})
	return out, skips
}

// verifyEntityHash recomputes hash(ent.Type, ent.Data) and compares to
// expected. The orchestrator does this independently of any per-handler
// check so a buggy convention handler can't sneak a wrong entity past
// the chain.
func verifyEntityHash(ent entity.Entity, expected hash.Hash) bool {
	// Recompute under the expected Algorithm — the format is intrinsic
	// to the expected hash (v7.67 §2.3 format-code interpretation).
	computed, err := hash.ComputeFormat(expected.Algorithm, ent.Type, ent.Data)
	if err != nil {
		return false
	}
	return computed == expected
}

// substituteHandlerURI builds the dispatch URI for a given substitute_type.
// Per §2.3: `system/substitute/<type>` — the orchestrator hands this to
// Execute, which routes to whichever handler registered at the pattern.
func substituteHandlerURI(substituteType string) string {
	return "system/substitute/" + substituteType
}

func statusString(s uint) string {
	// Avoid a strconv import for a small detail; the orchestrator's
	// LastError is informational, not parsed.
	switch {
	case s >= 100 && s < 600:
		return fmtUint(s)
	default:
		return "unknown"
	}
}

func fmtUint(s uint) string {
	if s == 0 {
		return "0"
	}
	var digits [4]byte
	i := len(digits)
	for s > 0 && i > 0 {
		i--
		digits[i] = byte('0' + s%10)
		s /= 10
	}
	return string(digits[i:])
}

