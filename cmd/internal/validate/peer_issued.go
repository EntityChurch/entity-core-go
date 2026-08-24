// Category: peer_issued. Probes the EXTENSION-REGISTRY peer-issued backend
// per PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND v0.4 §6 — six vectors:
//
//	REG-PEERISSUED-RESOLVE-1          — by-name → binding → verify → resolved (live)
//	REG-PEERISSUED-VERIFY-FAIL-1      — non-pinned signer → rejected, chain advances
//	REG-PEERISSUED-REVOKED-1          — verifying revocation → excluded
//	REG-PEERISSUED-EXPIRED-1          — issued_at + ttl ≤ now → excluded
//	REG-PEERISSUED-PRECEDE-1          — offline binding identical-verify to live
//	REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name absent → not_found + neg_ttl
//
// These run against a LIVE target peer, driven by a fixture registry the
// validator serves (see peer_issued_fixture.go). To arm them:
//
//	go run ./cmd/peerissued-fixtures -wire -out <dir>
//	<start target> --peer-issued-registry <registry_pid>@http://127.0.0.1:<port>
//	go run ./cmd/validate-peer -addr <target> -peer-issued-bundle <dir> \
//	    -peer-issued-addr 127.0.0.1:<port>
//
// scripts/validate-complete.sh does all three. Without -peer-issued-bundle
// the vectors SKIP, and the skip message says exactly what is missing.
//
// # What the wire can and cannot see
//
// The meta-resolver advances past a backend that errors (§2.2) and drops the
// reason on the floor, so VERIFY-FAIL-1, REVOKED-1 and EXPIRED-1 all surface
// the SAME observable status as a peer with no peer-issued backend at all:
// `chain_exhausted`. Asserting status alone would therefore pass against a
// peer that never consulted the backend — the check would be measuring
// nothing, which is the failure mode this whole category exists to avoid.
//
// So each vector asserts TWO things: the resolve outcome, and the FETCH
// PATTERN recorded by the fixture origin. The fetch pattern is what proves
// the backend ran, reached the binding, and rejected it at the right step.
//
// # Rejection is asserted, not inferred
//
// A `chain_exhausted` for VERIFY-FAIL-1 is only meaningful because RESOLVE-1
// — same registry, same wire, same peer, differing only in who signed the
// binding — resolves. The two together are the discrimination; either alone
// is not. Same for EXPIRED-1 (differs only by carrying a lapsed TTL) and
// REVOKED-1 (differs only by a revocation at the by-target index).

package validate

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/types"
)

const catPeerIssued = "peer_issued"

// peerIssuedSkipReason is emitted when the category runs unarmed. It names
// the exact invocation rather than gesturing at "fixture wiring" — an
// un-actionable skip message is how a skip becomes permanent.
const peerIssuedSkipReason = "peer-issued wire vectors need a fixture registry: generate the bundle " +
	"(`go run ./cmd/peerissued-fixtures -wire -out <dir>`), start the target with " +
	"`--peer-issued-registry <registry_pid>@http://127.0.0.1:<port>` (the registry peer-id is a " +
	"deterministic constant printed in the bundle's MANIFEST.json), then re-run validate-peer with " +
	"`-peer-issued-bundle <dir> -peer-issued-addr 127.0.0.1:<port>`. " +
	"scripts/validate-complete.sh does all three. The Backend is additionally unit-tested in " +
	"ext/registry/peerissued (in-process, all six paths) — but in-process coverage is not wire coverage. " +
	"NOTE for non-Go targets: --peer-issued-registry is Go-only today (Rust + Python impl pending), so a " +
	"sibling peer cannot be pinned and this category is UNBUILT rather than failing — a routing item for " +
	"the sibling's work queue, not a conformance debt to close from here."

func runPeerIssued(ctx context.Context, client *PeerClient, bundleDir, fixtureAddr string) []CheckResult {
	r := NewCheckRunner(catPeerIssued)

	r.Declare("v1_resolve_happy_path",
		"REG-PEERISSUED-RESOLVE-1 — by-name → binding → verify against the pinned registry key → resolved (live-fetch over http-poll)")
	r.Declare("v2_verify_fail_non_pinned_signer",
		"REG-PEERISSUED-VERIFY-FAIL-1 — §2.1 step 3 MUST: a binding whose signature is not by the pinned registry identity is rejected and the chain advances (NOT downgraded to a pin)")
	r.Declare("v3_revoked",
		"REG-PEERISSUED-REVOKED-1 — §2.1 step 4 MUST: a verifying revocation at the by-target index excludes the binding, chain advances")
	r.Declare("v4_expired",
		"REG-PEERISSUED-EXPIRED-1 — §2.1 step 5 MUST: issued_at + ttl ≤ now excludes the binding, chain advances")
	r.Declare("v5_precede_offline_identical_verify",
		"REG-PEERISSUED-PRECEDE-1 — §2.2: a locally-cached (preceded) binding resolves identically to live-fetch, WITHOUT touching the wire")
	r.Declare("v6_offline_not_found",
		"REG-PEERISSUED-OFFLINE-NOTFOUND-1 — §2.1 step 1: a name absent from the registry's by-name index yields the backend's negative result; the backend is consulted (wire probe observed) and the chain advances")

	if bundleDir == "" {
		for _, name := range peerIssuedCheckNames {
			r.Run(name, func() CheckOutcome { return SkipCheck(peerIssuedSkipReason) })
		}
		return r.Results()
	}

	fx, err := loadPeerIssuedFixture(bundleDir, fixtureAddr)
	if err != nil {
		// A bundle was supplied and could not be served. That is a FAIL, not
		// a skip: the operator armed the category and the harness broke.
		fail := FailCheck("load peer-issued fixture bundle: " + err.Error())
		for _, name := range peerIssuedCheckNames {
			r.Run(name, func() CheckOutcome { return fail })
		}
		return r.Results()
	}
	defer fx.close()

	// Registering a backend is not the same as consulting one. The §4
	// meta-resolver only walks backends named in
	// `system/registry/resolver-config`.resolver_chain — with no config
	// installed the chain is EMPTY, every resolve returns chain_exhausted,
	// and the pinned registry is never dialed. That is a configuration
	// step, not a peer defect: the resolver chain is operator policy per
	// §4, and the other REGISTRY checks install their own config the same
	// way. So arm the chain here, before any vector runs.
	//
	// This is also why the four rejection vectors assert the fetch pattern
	// and not just the status: an un-armed chain produces exactly the
	// `chain_exhausted` those vectors "expect", and would have made four of
	// six pass while measuring nothing at all.
	if out := installPeerIssuedResolverChain(ctx, client, fx); out != nil {
		for _, name := range peerIssuedCheckNames {
			r.Run(name, func() CheckOutcome { return *out })
		}
		return r.Results()
	}

	// Start cold. The backend runs `cacheOnResolve`, so a target that has
	// already run this category holds every vector's binding in its own
	// tree — and a resolve served from that cache never touches the wire,
	// which is precisely what v1 and v5 pass 1 assert it must do. Left
	// alone, the category passes on a fresh peer and fails on the second
	// run against the same one, for a reason whose message points at the
	// peer rather than at the leftovers. Clear the cache instead of
	// documenting the trap.
	clearPeerIssuedCache(ctx, client, fx)

	r.Run("v1_resolve_happy_path", func() CheckOutcome { return runPeerIssuedResolve(ctx, client, fx) })
	r.Run("v2_verify_fail_non_pinned_signer", func() CheckOutcome { return runPeerIssuedVerifyFail(ctx, client, fx) })
	r.Run("v3_revoked", func() CheckOutcome { return runPeerIssuedRevoked(ctx, client, fx) })
	r.Run("v4_expired", func() CheckOutcome { return runPeerIssuedExpired(ctx, client, fx) })
	r.Run("v5_precede_offline_identical_verify", func() CheckOutcome { return runPeerIssuedPrecede(ctx, client, fx) })
	r.Run("v6_offline_not_found", func() CheckOutcome { return runPeerIssuedOfflineNotFound(ctx, client, fx) })

	return r.Results()
}

var peerIssuedCheckNames = []string{
	"v1_resolve_happy_path",
	"v2_verify_fail_non_pinned_signer",
	"v3_revoked",
	"v4_expired",
	"v5_precede_offline_identical_verify",
	"v6_offline_not_found",
}

// installPeerIssuedResolverChain writes a resolver-config naming the fixture
// registry as the sole peer-issued chain entry, keyed by its peer-id so the
// §4 (kind, id) lookup routes to exactly this backend. Returns nil on
// success, or the FAIL outcome every vector should carry.
//
// No local-name entry is included on purpose: the vectors' names must be
// answered by the peer-issued backend or not at all. A second backend in the
// chain could resolve a name the peer-issued backend rejected, turning a
// correct rejection into an apparent pass.
func installPeerIssuedResolverChain(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) *CheckOutcome {
	cfg := types.ResolverConfigData{
		ResolverChain: []types.ResolverChainEntry{{
			BackendKind: types.BackendKindPeerIssued,
			BackendID:   fx.manifest.RegistryPeerID,
			Priority:    0,
		}},
	}
	cfgEnt, err := cfg.ToEntity()
	if err != nil {
		out := FailCheck("encode resolver-config: " + err.Error())
		return &out
	}
	if _, err := client.TreePut(ctx, types.ResolverConfigStoragePath, cfgEnt); err != nil {
		out := FailCheck(fmt.Sprintf(
			"install resolver-config at %s: %v — without a resolver_chain entry for backend_kind=%q id=%s the "+
				"meta-resolver never consults the pinned registry and every vector below would be measuring an "+
				"empty chain",
			types.ResolverConfigStoragePath, err, types.BackendKindPeerIssued, fx.manifest.RegistryPeerID))
		return &out
	}
	return nil
}

// clearPeerIssuedCache unbinds the three paths the backend's cacheOnResolve
// writes for every vector, so each run's live vectors start cold:
//
//	system/registry/binding/by-name/{name}   — the entry point
//	system/signature/{hex33(binding_hash)}   — the cached signature
//	system/registry/binding/{hex33(bh)}      — the cached body
//
// Errors and 404s are ignored on purpose: "already absent" is the desired
// state, and a peer that declines the removal will be caught by the vector
// itself (a warm cache makes v1's by-name fetch assertion fail loudly). This
// is cleanup, not a check — it must not manufacture its own verdict.
func clearPeerIssuedCache(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) {
	for i := range fx.manifest.Vectors {
		v := &fx.manifest.Vectors[i]
		if v.Name != "" {
			_, _ = client.TreeRemove(ctx, types.PeerIssuedByNamePath(v.Name))
		}
		if v.BindingHash == "" {
			continue
		}
		bh, err := parseHash33(v.BindingHash)
		if err != nil {
			continue
		}
		_, _ = client.TreeRemove(ctx, types.LocalSignaturePath(bh))
		_, _ = client.TreeRemove(ctx, types.BindingStoragePath(bh))
	}
}

// peerIssuedResolveVector resolves a vector's name against the target and
// returns the result plus the fixture paths fetched during that resolve.
func peerIssuedResolveVector(ctx context.Context, client *PeerClient, fx *peerIssuedFixture, v *peerIssuedVector) (types.ResolveResultData, uint, []string, error) {
	mark := fx.mark()
	res, status, err := regResolve(ctx, client, v.Name)
	fetched, _ := fx.requestsSince(mark)
	return res, status, fetched, err
}

// requireVector fetches a vector from the manifest, FAILing (not skipping)
// when the bundle lacks it — a bundle missing a vector is a broken bundle,
// and reporting five of six as green would overstate coverage.
func requireVector(fx *peerIssuedFixture, short string) (*peerIssuedVector, *CheckOutcome) {
	v := fx.manifest.vectorByShortID(short)
	if v == nil {
		out := FailCheck(fmt.Sprintf(
			"bundle has no vector %s — regenerate with `go run ./cmd/peerissued-fixtures -wire -out <dir>`", short))
		return nil, &out
	}
	return v, nil
}

// --- v1: RESOLVE-1 ---------------------------------------------------------

func runPeerIssuedResolve(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "RESOLVE-1")
	if bad != nil {
		return *bad
	}

	res, status, fetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d, want 200", status))
	}

	// The peer must actually have gone to the wire for this — otherwise a
	// stale cache or a coincidence could produce the same result.
	byNamePath := fx.treeLeafPath(types.PeerIssuedByNamePath(v.Name))
	if !sawPath(fetched, byNamePath) {
		return FailCheck(fmt.Sprintf(
			"target resolved without fetching the by-name pointer %s from the pinned registry. "+
				"Fixture saw %d request(s): %v — the peer-issued backend was not consulted",
			byNamePath, len(fetched), fetched))
	}

	if res.Status != types.ResolutionStatusResolved {
		return FailCheck(fmt.Sprintf(
			"status %q, want %q. The registry served the by-name pointer (fixture recorded %d fetch(es): %v) "+
				"but the peer did not surface a resolved binding — §2.1 steps 2-6 rejected a binding that "+
				"verifies against the pinned key",
			res.Status, types.ResolutionStatusResolved, len(fetched), fetched))
	}

	// Every surfaced field is checked against the bundle's declaration —
	// this is the vector's expected_result, the same object the cohort
	// impls assert.
	if res.Binding == nil {
		return FailCheck("resolved but binding is nil — §2.1 step 6 MUST surface the binding hash")
	}
	wantBinding, err := parseHash33(v.Expected.Binding)
	if err != nil {
		return FailCheck("bundle expected.binding: " + err.Error())
	}
	if *res.Binding != wantBinding {
		return FailCheck(fmt.Sprintf("binding %s, want %s", res.Binding.String(), wantBinding.String()))
	}
	if res.PeerID != v.Expected.PeerID {
		return FailCheck(fmt.Sprintf("peer_id %q, want %q", res.PeerID, v.Expected.PeerID))
	}
	if res.TrustAnchor != v.Expected.TrustAnchor {
		return FailCheck(fmt.Sprintf(
			"trust_anchor %q, want %q — §2.4 requires the backend-qualified `peer_issued:{registry_peer_id}` form",
			res.TrustAnchor, v.Expected.TrustAnchor))
	}
	if res.BackendID != v.Expected.BackendID {
		return FailCheck(fmt.Sprintf("backend_id %q, want %q", res.BackendID, v.Expected.BackendID))
	}

	return PassCheck(fmt.Sprintf(
		"resolved %s → %s via trust_anchor %s; %d wire fetch(es) against the pinned registry",
		v.Name, res.PeerID, res.TrustAnchor, len(fetched)))
}

// --- v2: VERIFY-FAIL-1 -----------------------------------------------------

func runPeerIssuedVerifyFail(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "VERIFY-FAIL-1")
	if bad != nil {
		return *bad
	}

	res, status, fetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d, want 200 (the resolve itself succeeds; the BINDING is what gets rejected)", status))
	}

	// The backend must have reached the binding — otherwise "rejected" is
	// indistinguishable from "never looked", and this check would pass on a
	// peer with no peer-issued backend at all.
	byNamePath := fx.treeLeafPath(types.PeerIssuedByNamePath(v.Name))
	if !sawPath(fetched, byNamePath) {
		return FailCheck(fmt.Sprintf(
			"the peer never fetched the by-name pointer %s — the backend was not consulted, so this vector "+
				"proves nothing about signature verification. Fixture saw: %v", byNamePath, fetched))
	}
	bindingHash, err := parseHash33(v.BindingHash)
	if err != nil {
		return FailCheck("bundle binding_hash: " + err.Error())
	}
	if !sawPath(fetched, contentPath(bindingHash)) {
		return FailCheck(fmt.Sprintf(
			"the peer fetched the by-name pointer but never fetched the binding body %s — it cannot have "+
				"verified a signature over a binding it did not read. Fixture saw: %v",
			contentPath(bindingHash), fetched))
	}

	// §2.1 step 3 MUST: reject, and do NOT downgrade to a pin.
	if res.Status == types.ResolutionStatusResolved {
		anchor := res.TrustAnchor
		return FailCheck(fmt.Sprintf(
			"binding signed by a NON-PINNED key resolved anyway (status=resolved, trust_anchor=%q, peer_id=%q). "+
				"§2.1 step 3 MUST reject a binding whose signature does not verify against the pinned registry "+
				"identity — this is the forgery path: any peer able to serve the registry's by-name index could "+
				"bind any name",
			anchor, res.PeerID))
	}

	return PassCheck(fmt.Sprintf(
		"non-pinned signer rejected → status %q; backend confirmed on the wire (by-name + binding body fetched, %d request(s))",
		res.Status, len(fetched)))
}

// --- v3: REVOKED-1 ---------------------------------------------------------

func runPeerIssuedRevoked(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "REVOKED-1")
	if bad != nil {
		return *bad
	}

	res, status, fetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d, want 200", status))
	}

	bindingHash, err := parseHash33(v.BindingHash)
	if err != nil {
		return FailCheck("bundle binding_hash: " + err.Error())
	}
	// The distinguishing fetch: the by-target revocation index. A peer that
	// skips this lookup will resolve the binding happily — the revocation is
	// the ONLY thing wrong with it.
	revIdxPath := fx.treeLeafPath(types.PeerIssuedRevocationByTargetPath(bindingHash))
	if !sawPath(fetched, revIdxPath) {
		return FailCheck(fmt.Sprintf(
			"the peer never probed the revocation by-target index %s. §2.1 step 4 MUST check for a revocation "+
				"before surfacing a binding; this binding is otherwise valid, so skipping the check means serving "+
				"a revoked name. Fixture saw: %v", revIdxPath, fetched))
	}

	if res.Status == types.ResolutionStatusResolved {
		return FailCheck(fmt.Sprintf(
			"REVOKED binding resolved anyway (status=resolved, peer_id=%q). The registry served a revocation at "+
				"%s that verifies against the same pinned identity — §2.1 step 4 MUST exclude the binding and "+
				"advance the chain", res.PeerID, types.PeerIssuedRevocationByTargetPath(bindingHash)))
	}

	return PassCheck(fmt.Sprintf(
		"revoked binding excluded → status %q; by-target revocation index probed on the wire (%d request(s))",
		res.Status, len(fetched)))
}

// --- v4: EXPIRED-1 ---------------------------------------------------------

// The expiry vector needs NO clock injection. Its binding carries
// issued_at=1_000_000 ms + ttl=1_000 ms — an expiry at 1970-01-01T00:16:41Z,
// which is in the past under any wall clock a peer will ever run with. Only
// this vector carries a TTL at all (the backend skips the expiry check when
// TTL is nil), so the other five are equally clock-independent. The static
// bundle drives a live wall-clock peer as-is.
func runPeerIssuedExpired(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "EXPIRED-1")
	if bad != nil {
		return *bad
	}

	res, status, fetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d, want 200", status))
	}

	bindingHash, err := parseHash33(v.BindingHash)
	if err != nil {
		return FailCheck("bundle binding_hash: " + err.Error())
	}
	if !sawPath(fetched, contentPath(bindingHash)) {
		return FailCheck(fmt.Sprintf(
			"the peer never fetched the binding body %s — it cannot have evaluated issued_at + ttl against its "+
				"clock. Fixture saw: %v", contentPath(bindingHash), fetched))
	}

	if res.Status == types.ResolutionStatusResolved {
		ttl := "nil"
		if res.TTL != nil {
			ttl = fmt.Sprintf("%d", *res.TTL)
		}
		return FailCheck(fmt.Sprintf(
			"EXPIRED binding resolved anyway (status=resolved, peer_id=%q, surfaced ttl=%s). The binding declares "+
				"issued_at=1000000ms + ttl=1000ms — an expiry in 1970, lapsed under any wall clock. §2.1 step 5 "+
				"MUST exclude it", res.PeerID, ttl))
	}

	return PassCheck(fmt.Sprintf(
		"expired binding excluded → status %q; binding body fetched and evaluated against the peer's wall clock (%d request(s))",
		res.Status, len(fetched)))
}

// --- v5: PRECEDE-1 ---------------------------------------------------------

// PRECEDE-1 is the one vector whose wire form differs from its in-process
// form, and deliberately so. In-process the binding is pre-seeded into the
// local store per the bundle's `offline_preseed` map. Over the wire the
// validator cannot reach into the target's store — but it does not need to:
// the backend runs `cacheOnResolve`, and the paths it caches to are exactly
// the offline_preseed paths. So the first resolve establishes the precede
// and the second exercises it.
//
// The assertion is the one that matters and the one the in-process test also
// makes: the second resolve must produce an IDENTICAL result while touching
// the wire for neither the by-name pointer nor any content. That is only
// observable because the fixture origin is ours and counts its requests.
func runPeerIssuedPrecede(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "PRECEDE-1")
	if bad != nil {
		return *bad
	}

	// Pass 1 — live fetch, which warms the cache into the precede layout.
	first, status, firstFetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve pass 1 " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve pass 1 status %d, want 200", status))
	}
	if first.Status != types.ResolutionStatusResolved {
		return FailCheck(fmt.Sprintf(
			"pass 1 (live) status %q, want resolved — PRECEDE-1 needs a successful live resolve to establish the "+
				"precede before the offline path can be compared to it. %d wire fetch(es): %v",
			first.Status, len(firstFetched), firstFetched))
	}
	byNamePath := fx.treeLeafPath(types.PeerIssuedByNamePath(v.Name))
	if !sawPath(firstFetched, byNamePath) {
		return FailCheck(fmt.Sprintf(
			"pass 1 resolved without fetching %s — there was no live fetch, so pass 2 cannot demonstrate anything "+
				"about the precede path. Fixture saw: %v", byNamePath, firstFetched))
	}

	// Pass 2 — must be served from the precede, off the wire entirely.
	second, status2, secondFetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve pass 2 " + v.Name + ": " + err.Error())
	}
	if status2 != 200 {
		return FailCheck(fmt.Sprintf("resolve pass 2 status %d, want 200", status2))
	}

	// Identical verify — the §2.2 contract is that the offline path is not a
	// weaker path. Same binding, same peer-id, same trust anchor.
	if second.Status != first.Status {
		return FailCheck(fmt.Sprintf("pass 2 status %q != pass 1 status %q — the precede path is not identical to live-fetch",
			second.Status, first.Status))
	}
	if (first.Binding == nil) != (second.Binding == nil) ||
		(first.Binding != nil && *first.Binding != *second.Binding) {
		return FailCheck("pass 2 surfaced a different binding hash than pass 1 — the precede path is not identical to live-fetch")
	}
	if second.PeerID != first.PeerID {
		return FailCheck(fmt.Sprintf("pass 2 peer_id %q != pass 1 %q", second.PeerID, first.PeerID))
	}
	if second.TrustAnchor != first.TrustAnchor {
		return FailCheck(fmt.Sprintf(
			"pass 2 trust_anchor %q != pass 1 %q — a precede that resolves under a WEAKER anchor is the §2.2 "+
				"downgrade the identical-verify requirement exists to forbid",
			second.TrustAnchor, first.TrustAnchor))
	}

	// The offline assertion: no by-name pointer fetch, no content fetch.
	// A revocation by-target probe is permitted — the in-process vector
	// permits it too (the local store has no revocation, so the check falls
	// through to the wire and misses).
	if sawPath(secondFetched, byNamePath) {
		return FailCheck(fmt.Sprintf(
			"pass 2 went to the wire for the by-name pointer %s — the binding was cached by pass 1 at the §2.2 "+
				"precede path, so this resolve should not have needed it. Fixture saw: %v",
			byNamePath, secondFetched))
	}
	if anyPathContains(secondFetched, "/content/") {
		return FailCheck(fmt.Sprintf(
			"pass 2 fetched content from the registry — the precede path must verify against the LOCAL copy of "+
				"the binding and its signature. Fixture saw: %v", secondFetched))
	}

	return PassCheck(fmt.Sprintf(
		"precede path identical to live-fetch (binding, peer_id and trust_anchor %s all match) and served without "+
			"touching the wire: pass 1 made %d fetch(es), pass 2 made %d",
		second.TrustAnchor, len(firstFetched), len(secondFetched)))
}

// --- v6: OFFLINE-NOTFOUND-1 ------------------------------------------------

// Over the wire this vector cannot assert the backend's `neg_ttl` directly:
// the meta-resolver's chain loop treats a backend not_found as "advance"
// (§2.2) and does not carry the negative TTL into the surfaced result. The
// bundle's expected_result records the BACKEND-level outcome, which is what
// the in-process vector asserts.
//
// What the wire CAN prove, and what this check asserts, is the pair that
// actually matters: the name does not resolve, AND the backend was genuinely
// consulted — the fixture recorded the by-name probe and answered it 404.
// Without the second half, "not found" is what you get from a peer with no
// peer-issued backend configured, and the check would be vacuous.
func runPeerIssuedOfflineNotFound(ctx context.Context, client *PeerClient, fx *peerIssuedFixture) CheckOutcome {
	v, bad := requireVector(fx, "OFFLINE-NOTFOUND-1")
	if bad != nil {
		return *bad
	}

	res, status, fetched, err := peerIssuedResolveVector(ctx, client, fx, v)
	if err != nil {
		return FailCheck("resolve " + v.Name + ": " + err.Error())
	}
	if status != 200 {
		return FailCheck(fmt.Sprintf("resolve status %d, want 200", status))
	}

	byNamePath := fx.treeLeafPath(types.PeerIssuedByNamePath(v.Name))
	if !sawPath(fetched, byNamePath) {
		return FailCheck(fmt.Sprintf(
			"the peer never probed %s against the pinned registry. A name that does not resolve is meaningless "+
				"unless the backend actually looked for it — without the probe this check would pass identically "+
				"against a peer with no peer-issued backend at all. Fixture saw: %v", byNamePath, fetched))
	}

	if res.Status == types.ResolutionStatusResolved {
		return FailCheck(fmt.Sprintf(
			"name %q resolved to %q, but the registry has no binding for it (the fixture 404s the by-name pointer). "+
				"§2.1 step 1 requires the backend to return its negative result", v.Name, res.PeerID))
	}
	if res.Status != types.ResolutionStatusNotFound && res.Status != types.ResolutionStatusChainExhausted {
		return FailCheck(fmt.Sprintf(
			"status %q — want %q (backend-level negative surfaced) or %q (the chain ran to the end, which is what "+
				"the meta-resolver reports when every backend declines)",
			res.Status, types.ResolutionStatusNotFound, types.ResolutionStatusChainExhausted))
	}

	// When the peer DOES surface the backend-level negative, hold it to the
	// bundle's declared neg_ttl / backend_id. When it reports chain_exhausted
	// the fields are legitimately absent — the chain loop drops them.
	detail := fmt.Sprintf("status %q", res.Status)
	if res.Status == types.ResolutionStatusNotFound {
		if v.Expected.NegTTLMs != nil {
			if res.NegTTL == nil {
				return FailCheck(fmt.Sprintf(
					"status not_found but neg_ttl absent — §2.1 step 1 pairs the negative with a negative TTL (bundle declares %d ms)",
					*v.Expected.NegTTLMs))
			}
			if *res.NegTTL != *v.Expected.NegTTLMs {
				return FailCheck(fmt.Sprintf("neg_ttl %d ms, want %d ms", *res.NegTTL, *v.Expected.NegTTLMs))
			}
			detail += fmt.Sprintf(" with neg_ttl=%d ms", *res.NegTTL)
		}
		if v.Expected.BackendID != "" && res.BackendID != v.Expected.BackendID {
			return FailCheck(fmt.Sprintf("backend_id %q, want %q", res.BackendID, v.Expected.BackendID))
		}
	}

	return PassCheck(fmt.Sprintf(
		"absent name declined → %s; the backend was consulted (fixture answered the by-name probe for %q with 404, %d request(s))",
		detail, strings.TrimPrefix(byNamePath, "/"), len(fetched)))
}
