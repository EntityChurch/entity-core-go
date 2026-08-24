// Category: substitute. Probes EXTENSION-SUBSTITUTE's §7 HTTP convention —
// the `system/substitute/http:try` operation — which is the one part of this
// extension a conformance client can reach.
//
// WHY THIS CATEGORY DID NOT EXIST UNTIL 2026-08-13, AND WHY THAT WAS NOT AN
// OVERSIGHT. `EXTENSION-SUBSTITUTE` is built in go, rust and python and had
// **zero** behavioural checks in any of the 108 validator files. The obvious
// reading — "somebody forgot" — is wrong, and the real reason is worth stating
// because it changes what this file can and cannot assert.
//
// **The chain-consultation algorithm (§3) is not wire-reachable in ANY of the
// three implementations, by a cohort-convergent deliberate deferral.** The
// chain fires only from a caller that supplies `claimed_source_peer_id`, which
// per the storage-substitute cross-impl Ruling 4 is LOCAL DISPATCHER CONTEXT
// and explicitly NOT a wire field on `system/content:get-request`. Read live
// 2026-08-13:
//
//   - **rust `1152d35`** — `extensions/content/src/handler.rs:164` binds
//     `let claimed_source: Option<Hash> = None;` at the miss-hook call site,
//     under a comment saying so: *"CONTENT-level get-requests do NOT trigger
//     substitute consult by themselves … Plumbing a local context channel here
//     lands when that driver materializes."*
//   - **py `d6cfbda`** — `entity_handlers/content/handler.py:201` : *"the chain
//     helper `consult_substitute_chain(...)` is exposed for SDK / dispatcher
//     use; this handler does NOT auto-invoke it. Phase 2 … is where
//     consumer-side wiring lives."*
//   - **go** (this repo) — `ext/storagesubstitutesources/adapter.go:46` reads
//     the claimed source from a context key, and **`WithClaimedSource` has
//     exactly one caller in the entire repository: its own integration test.**
//     No production path populates it, so `Resolve` returns an empty
//     `MissResult` on every live request and the chain is never entered.
//
// The three are behaviourally identical. **Go's is the one that was not
// written down** — rust and py state the deferral in-source at the call site,
// while Go's reads as installed-and-working wiring whose trigger silently
// never fires. That is the defect worth naming: not the deferral, which is
// cohort-convergent and defensible, but that ours was legible only by grepping
// for callers of a context helper. Recorded in
// docs/validation/spec-issues/2026-08-13-e.
//
// The consequence for THIS file: the §3 chain vectors (`TV-SS-CORE-*`,
// `TV-SS-COMP-*`, `TV-SS-BARE-*`, `TV-SS-DISP-*`) are not drivable here and
// are stated as a declared exclusion (see exclusions.go) rather than faked
// with a proxy. What IS drivable is the §7 convention handler, which every
// peer registers as an ordinary handler and which a client may dispatch to
// directly — and it is worth driving on its own merits: **it is the component
// that performs an outbound network fetch**, so its refusals are the security
// boundary of the whole extension.
//
// NO EXTERNAL NETWORK IS REQUIRED. Every check below asserts a refusal that
// happens at or before the URL-scheme gate (steps 1-6 of handleTry), plus one
// unreachable-origin case pointed at a closed localhost port. Nothing here
// reaches the public internet, which is what makes it runnable in the gate.
package validate

import (
	"context"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/storagesubstitutehttp"
)

const catSubstitute = "substitute"

func substituteURI(peerID string) string {
	return "entity://" + peerID + "/" + storagesubstitutehttp.HandlerPattern
}

// substituteTarget is the content hash a try-request asks the convention to
// fetch. Any well-formed hash works — every check below refuses before the
// fetch, or fails to connect — so it is derived from a fixed entity rather
// than randomised, keeping failure messages reproducible.
func substituteTarget() (hash.Hash, error) {
	return mustCreateEntity("primitive/string", "substitute-probe-target").ContentHash, nil
}

// substituteTryRequest builds the §2.3 try-request wire entity around a
// source entry, which is the shape the orchestrator would send.
func substituteTryRequest(entry entity.Entity, target hash.Hash) (entity.Entity, error) {
	return types.SubstituteTryRequestData{Entry: entry, Hash: target}.ToEntity()
}

// substituteSource builds a §2.1 source entity carrying the given endpoint.
// The signature is NOT staged: §4's signature MUST is enforced by the CHAIN
// at consultation time, not by the convention handler, and every check here
// dispatches to the convention handler directly. Asserting a signature
// refusal here would be measuring the wrong component.
func substituteSource(ep types.TransportEndpoint, substType string) (entity.Entity, error) {
	src, err := types.NewHTTPSource("probe-mirror", hash.Hash{}, ep, 0)
	if err != nil {
		return entity.Entity{}, err
	}
	src.SubstituteType = substType
	return src.ToEntity()
}

func runSubstitute(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catSubstitute)
	uri := substituteURI(string(client.RemotePeerID()))

	r.Declare("surface_registered", "EXTENSION-SUBSTITUTE §6/§7 — the http convention handler is registered at system/substitute/http and answers `try`. §6's whole dispatch model is that a convention is found by ORDINARY handler dispatch, so an unreachable handler means the convention model is not wired, not merely that a fetch failed")
	r.Declare("https_required_at_consume", "EXTENSION-SUBSTITUTE §7 / TV-CDN-TLS-1 — an `http://` endpoint MUST be refused at consume time. This is the extension's security floor: the convention performs an OUTBOUND FETCH and then ingests what comes back, so a plaintext scheme silently downgrades every substituted byte to a tamper-able channel. Hash-verification catches tampering after the fact; it does not make plaintext acceptable, and a peer that fetches first and verifies later has already leaked which hashes it wants")
	r.Declare("wrong_substitute_type_refused", "EXTENSION-SUBSTITUTE §6 — a convention handler handed an entry whose `substitute_type` names a DIFFERENT convention. §6 pins the ORCHESTRATOR's routing (`handler_uri = system/substitute/ + entry.substitute_type`) and says nothing about handler-side validation, so this is UNPINNED and cannot be a FAIL. It is measured because the two live answers differ materially: go refuses 400, py performs the outbound fetch. Refusing is the safe direction — a handler that serves any entry handed to it will fetch over HTTP for an entry its publisher addressed to a more restricted convention. Routed to arch to pin; WARN until then")
	r.Declare("wrong_entry_type_refused", "EXTENSION-SUBSTITUTE §2.3 — try-request.entry MUST be a system/substitute/source. A handler that accepts an arbitrary entity here is fetching on the say-so of an unvalidated payload")
	r.Declare("no_endpoint_refused", "EXTENSION-SUBSTITUTE §2.2 — an entry with no endpoint block MUST be refused rather than guessed at (legacy fetch_template is out of scope for v1)")
	r.Declare("content_url_prefix_required_no_derivation", "EXTENSION-SUBSTITUTE §2.2 [pinned ruling] — `content_url_prefix` is REQUIRED and there is NO derivation default: an endpoint carrying only `tree_url_prefix` MUST be refused, NOT resolved to `{tree_url_prefix}/content`. \"An impl that treats it as optional-with-derivation is non-conformant.\" What it protects is deployment scenario S4 (tree on one host, dedup'd content on a shared bucket): a deriving consumer fetches from an origin the publisher never committed to, which either 404s or exists and serves a different peer's bytes")
	r.Declare("unreachable_origin_is_transient", "EXTENSION-SUBSTITUTE §3.2 / TV-CDN-PUB-1 — an origin that cannot be reached is a TRANSIENT failure (5xx), not a terminal `not_found`. The distinction is what §3.2 branches the whole chain on: terminal exhausts to 404, transient answers 503 chain_pending and a retry MAY help. A handler that reports an unreachable origin as not_found makes a temporarily-down mirror indistinguishable from a permanently-absent object")
	r.Declare("unknown_operation_rejected", "EXTENSION-SUBSTITUTE §6 — the convention handler exposes `try` and MUST refuse operations it does not implement")

	// --- surface reachability ---------------------------------------------

	target, terr := substituteTarget()
	probeStatus, probeCode, probeErr := issuerDispatch(ctx, client, uri, types.OpSubstituteTry,
		mustCreateEntity(types.TypeSubstituteTryRequest, map[string]any{}))

	// Unlike registry_issuer's issuer surface, this one is NOT default-off:
	// every peer in the cohort registers the http convention unconditionally.
	// So an absent handler is a real finding, reported as a category skip with
	// the reason rather than as eight identical failures.
	if probeErr == nil && isHandlerMissing(probeStatus, probeCode) {
		return skipCategory(catSubstitute, fmt.Sprintf(
			"peer has no %s handler (probe answered %d/%q) — EXTENSION-SUBSTITUTE §6's convention-dispatch model requires the convention to be reachable by ordinary handler dispatch. Nothing in this category is measured",
			storagesubstitutehttp.HandlerPattern, probeStatus, probeCode))
	}

	r.Run("surface_registered", func() CheckOutcome {
		if probeErr != nil {
			return FailCheck("dispatch to " + storagesubstitutehttp.HandlerPattern + ": " + probeErr.Error())
		}
		if terr != nil {
			return FailCheck("build probe target hash: " + terr.Error())
		}
		return PassCheck(fmt.Sprintf("http convention handler reachable (malformed probe answered %d/%q)",
			probeStatus, probeCode))
	})

	surfaceLive := probeErr == nil && terr == nil
	gate := func(fn func() CheckOutcome) func() CheckOutcome {
		return func() CheckOutcome {
			if !surfaceLive {
				return FailCheck("http convention handler not reachable — see surface_registered")
			}
			return fn()
		}
	}

	// try dispatches one try-request built from `ep` + `substType` and
	// returns the status and code.
	try := func(ep types.TransportEndpoint, substType string) (uint, string, error) {
		entryEnt, err := substituteSource(ep, substType)
		if err != nil {
			return 0, "", fmt.Errorf("build source entry: %w", err)
		}
		params, err := substituteTryRequest(entryEnt, target)
		if err != nil {
			return 0, "", fmt.Errorf("build try-request: %w", err)
		}
		return issuerDispatch(ctx, client, uri, types.OpSubstituteTry, params)
	}

	// --- TV-CDN-TLS-1 — the security floor --------------------------------

	r.Run("https_required_at_consume", gate(func() CheckOutcome {
		status, code, err := try(types.TransportEndpoint{
			ContentURLPrefix: "http://127.0.0.1:1/content",
			ContentLayout:    types.ContentLayoutFlat,
		}, types.SubstituteTypeHTTP)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		// A 2xx is the catastrophic outcome and is named separately: it means
		// the peer performed a plaintext outbound fetch on a caller's say-so.
		if status < 400 {
			return FailCheck(fmt.Sprintf("an http:// endpoint answered %d — the peer performed (or would perform) "+
				"a PLAINTEXT outbound fetch. TV-CDN-TLS-1 requires refusal at consume", status))
		}
		if status != 403 {
			return FailCheck(fmt.Sprintf("http:// endpoint refused %d/%q, want 403 — the refusal is an "+
				"authorization decision about the scheme, not a malformed-input one, and a 400 here would "+
				"invite a caller to 'fix' the request rather than the scheme", status, code))
		}
		return PassCheck("http:// endpoint refused 403/" + code + " before any fetch")
	}))

	// --- §6 dispatch integrity --------------------------------------------

	r.Run("wrong_substitute_type_refused", gate(func() CheckOutcome {
		status, code, err := try(types.TransportEndpoint{
			ContentURLPrefix: "https://example.invalid/content",
			ContentLayout:    types.ContentLayoutFlat,
		}, types.SubstituteTypePeerToPeer)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		// WARN, not FAIL. §6 pins the orchestrator's type→handler routing and
		// is silent on whether the handler re-validates, so a peer that does
		// not is not violating anything written down. Failing a peer against
		// a rule the spec does not carry is a too-strict probe, and the
		// correct move is to flag the divergence in writing and route it —
		// not to gate a cycle on our own reading.
		if status != 400 {
			return WarnCheck(fmt.Sprintf("an entry with substitute_type=%q handed to the http convention "+
				"answered %d/%q rather than refusing — the peer treated an entry addressed to another "+
				"convention as its own and proceeded to the outbound fetch. §6 does not pin handler-side "+
				"validation, so this is a DIVERGENCE, not a violation; routed to arch "+
				"(spec-issues/2026-08-13-e). go refuses 400, py fetches",
				types.SubstituteTypePeerToPeer, status, code))
		}
		return PassCheck("mismatched substitute_type refused 400/" + code)
	}))

	r.Run("wrong_entry_type_refused", gate(func() CheckOutcome {
		notASource := mustCreateEntity("primitive/string", "not a substitute source")
		params, err := substituteTryRequest(notASource, target)
		if err != nil {
			return FailCheck("build try-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, types.OpSubstituteTry, params)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("try-request.entry carrying a non-source entity answered %d/%q, "+
				"want 400 (§2.3)", status, code))
		}
		return PassCheck("non-source entry refused 400/" + code)
	}))

	r.Run("no_endpoint_refused", gate(func() CheckOutcome {
		// A source with substitute_type=http and NO endpoint block at all.
		src := types.SubstituteSourceData{
			Name:           "probe-no-endpoint",
			SubstituteType: types.SubstituteTypeHTTP,
			Priority:       0,
			Enabled:        true,
		}
		entryEnt, err := src.ToEntity()
		if err != nil {
			return FailCheck("build endpoint-less source: " + err.Error())
		}
		params, err := substituteTryRequest(entryEnt, target)
		if err != nil {
			return FailCheck("build try-request: " + err.Error())
		}
		status, code, err := issuerDispatch(ctx, client, uri, types.OpSubstituteTry, params)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("an entry with no endpoint block answered %d/%q, want 400 (§2.2)",
				status, code))
		}
		return PassCheck("endpoint-less entry refused 400/" + code)
	}))

	// --- §6.4 / D-14 default prefix resolution ----------------------------

	r.Run("content_url_prefix_required_no_derivation", gate(func() CheckOutcome {
		// The tree prefix is https:// on a REACHABLE-looking host so that a
		// deriving peer does NOT get rescued by the scheme gate or a
		// connection refusal — it has to answer for the derivation itself.
		// A conformant peer refuses at prefix-resolution (400); a deriving
		// one proceeds to fetch and answers with a network/5xx outcome.
		//
		// THIS CHECK WAS WRITTEN THE WRONG WAY ROUND on 2026-08-13 and
		// asserted the derivation as required — FAILing core-py for the
		// conformant behaviour and passing go for the non-conformant one.
		// Corrected by reading §2.2 before filing the report. Left recorded
		// here because a probe that fails the right peer is worse than no
		// probe: it spends a sibling's cycle defending correct code.
		status, code, err := try(types.TransportEndpoint{
			TreeURLPrefix: "https://127.0.0.1:1/tree",
			ContentLayout: types.ContentLayoutFlat,
		}, types.SubstituteTypeHTTP)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		if status != 400 {
			return FailCheck(fmt.Sprintf("an endpoint carrying only tree_url_prefix answered %d/%q, want 400 "+
				"— §2.2 pins `content_url_prefix` as REQUIRED with no derivation default, and names "+
				"optional-with-derivation NON-CONFORMANT by construction. A %d here means the peer resolved a "+
				"prefix the publisher never committed to and went on to fetch from it", status, code, status))
		}
		return PassCheck("endpoint without content_url_prefix refused 400/" + code + " (no derivation)")
	}))

	// --- §3.2 transient vs terminal ---------------------------------------

	r.Run("unreachable_origin_is_transient", gate(func() CheckOutcome {
		// Port 1 on loopback: nothing listens, the connection is refused
		// immediately, no external network involved and no timeout to wait
		// out. https:// so the scheme gate passes and the FETCH is what fails.
		status, code, err := try(types.TransportEndpoint{
			ContentURLPrefix: "https://127.0.0.1:1/content",
			ContentLayout:    types.ContentLayoutFlat,
		}, types.SubstituteTypeHTTP)
		if err != nil {
			return FailCheck("try: " + err.Error())
		}
		switch {
		case status == 404:
			return FailCheck("an unreachable origin answered 404 not_found — §3.2 branches the chain on exactly " +
				"this distinction: terminal exhausts to 404, transient answers 503 chain_pending. Reporting a " +
				"down mirror as terminal makes it indistinguishable from a permanently absent object, and the " +
				"chain gives up on content that is merely temporarily unavailable")
		case status >= 500:
			return PassCheck(fmt.Sprintf("unreachable origin reported as transient %d/%q", status, code))
		default:
			return FailCheck(fmt.Sprintf("unreachable origin answered %d/%q, want a 5xx transient (§3.2)", status, code))
		}
	}))

	r.Run("unknown_operation_rejected", gate(func() CheckOutcome {
		status, code, err := issuerDispatch(ctx, client, uri, "fetch-everything",
			mustCreateEntity(types.TypeSubstituteTryRequest, map[string]any{}))
		if err != nil {
			return FailCheck("dispatch: " + err.Error())
		}
		if status < 400 {
			return FailCheck(fmt.Sprintf("an unimplemented operation answered %d — silently accepting an "+
				"unknown operation on a handler that performs outbound fetches is how a future op gets "+
				"honoured before it is written", status))
		}
		return PassCheck(fmt.Sprintf("unknown operation refused %d/%q", status, code))
	}))

	return r.Results()
}
