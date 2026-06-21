package validate

import (
	"context"
	"fmt"
	"strings"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/entity"
)

// alignAuthoringFormatWithPeer shifts the process-global default that
// entity.NewEntity uses to match the format the peer negotiated at hello.
// Validate-peer is itself an authoring actor — it builds delivery tokens,
// comparison blobs, test entities, etc. — and the peer verifies / dedups /
// path-derives those against its own active format. Aligning the two closes
// a class of false-negative test failures that surface on SHA-384 peers as
// "test-side built X with SHA-256, peer hashed it with SHA-384."
//
// Process-global side effect is acceptable here: one validate-peer process
// talks to one cohort of peers at a time, and (under §5.2's still-open
// arch question) the recipes already pair same-format peers. If --peers
// ever spans mixed formats, this needs to be re-thought; flag and re-visit.
func alignAuthoringFormatWithPeer(c *PeerClient) {
	entity.SetDefaultHashAlgorithm(c.ActiveHashFormat())
}

// ValidationSuite orchestrates all validation categories against a remote peer.
type ValidationSuite struct {
	addr          string
	referenceAddr string // if set, run origination-side tests with this addr as peer B
	identityName  string // if set, use named identity from ~/.entity/identities/
	verbose       bool   // if set, trace wire exchanges to stderr
	pollURL       string // if set, run serving_mode tests against this HTTP poll URL
	profile       string // V7 v7.72 §9.0 conformance profile: "core" or "full"; default "full" (back-compat)
	httpPeers     []string // if set in convergence mode, HTTP listener URLs paired by index with peer addresses; enables the R1 cross-peer-subscription-over-HTTP gate
	wsPeers       []string // if set in convergence mode, WebSocket-live URLs paired by index with peer addresses; Thread F substrate gate for §6.5.2b. When wsPeers[i] is set it preempts httpPeers[i] in transportProfileForPeer (lex-sort puts ws after http after tcp).

	// V7 §4.10 (v7.75 RESERVED) — peer-declared resource bounds; the
	// resource_bounds category probes a value just over each. Zero means
	// "use the recommended default" (16 MiB / 64).
	declaredMaxPayload    int
	declaredMaxChainDepth int
}

// NewValidationSuite creates a suite targeting the given peer address.
func NewValidationSuite(addr string) *ValidationSuite {
	return &ValidationSuite{addr: addr}
}

// SetIdentity configures the suite to use a named identity from
// ~/.entity/identities/ instead of an ephemeral keypair.
func (s *ValidationSuite) SetIdentity(name string) {
	s.identityName = name
}

// SetVerbose enables wire trace output on stderr.
func (s *ValidationSuite) SetVerbose(v bool) {
	s.verbose = v
}

// SetReferencePeer configures the suite to run origination-side (A-role) tests
// using the given address as peer B. When set, the `origination` category is
// enabled in Run/RunCategory. Single-peer validate-peer cannot catch bugs that
// only manifest when the target peer dispatches an outbound EXECUTE (params
// entity-wrapping, continuation resource-target handling, etc.) — a reference
// peer is required to play the role of B. Typical usage pairs the target peer
// against a known-good Go reference:
//
//	go run ./cmd/peer-manager start --name ref --type go
//	validate-peer -addr python:port -reference-peer $(peer-manager addrs ref) ...
func (s *ValidationSuite) SetReferencePeer(addr string) {
	s.referenceAddr = addr
}

// SetHTTPPeers configures the suite with HTTP listener URLs for each
// peer in convergence mode (paired by index with the -peers list).
// Enables the cross-peer-subscription-over-HTTP gate (PROPOSAL-
// TRANSPORT-FAMILY §7.3 R1).
func (s *ValidationSuite) SetHTTPPeers(urls []string) {
	s.httpPeers = urls
}

// SetWSPeers configures the suite with WebSocket-live URLs for each
// peer in convergence mode (paired by index with the -peers list).
// Drives the Thread F WebSocket substrate gate (§6.5.2b) — when set,
// the three relay categories publish WS transport profiles for B↔C↔
// registry instead of TCP/HTTP, so RELAY §3.1.1 terminal-hop delivery
// rides binary WS messages end-to-end.
func (s *ValidationSuite) SetWSPeers(urls []string) {
	s.wsPeers = urls
}

// SetProfile selects the V7 v7.72 §9.0 conformance profile the suite
// scores against. "core" runs the 14-category core-profile set, scores
// type_system against the §9.5 53-type floor, runs the §9.5a
// CORE-TREE-* vectors, and applies per-check carve-outs for extension-
// targeted oracle checks. "full" (default) keeps historical behavior.
// Empty string is treated as "full". Unknown profile is treated as
// "full" with a stderr warning at the call site (CLI).
func (s *ValidationSuite) SetProfile(profile string) {
	s.profile = profile
}

// Profile returns the active conformance profile ("core" or "full").
// Defaults to "full" when unset.
func (s *ValidationSuite) Profile() string {
	if s.profile == ProfileCore {
		return ProfileCore
	}
	return ProfileFull
}

// SetDeclaredMaxPayload sets the peer-declared max payload size (bytes)
// the resource_bounds category probes against. Zero means use the
// recommended default (16 MiB). V7 §4.10(a) (v7.75 RESERVED).
func (s *ValidationSuite) SetDeclaredMaxPayload(n int) {
	s.declaredMaxPayload = n
}

// SetDeclaredMaxChainDepth sets the peer-declared cap-chain max depth the
// resource_bounds category probes against. Zero means use the recommended
// default (64). V7 §4.10(b) (v7.75 RESERVED).
func (s *ValidationSuite) SetDeclaredMaxChainDepth(n int) {
	s.declaredMaxChainDepth = n
}

func (s *ValidationSuite) effectiveDeclaredMaxPayload() int {
	if s.declaredMaxPayload > 0 {
		return s.declaredMaxPayload
	}
	return defaultDeclaredMaxPayload
}

func (s *ValidationSuite) effectiveDeclaredMaxChainDepth() int {
	if s.declaredMaxChainDepth > 0 {
		return s.declaredMaxChainDepth
	}
	return defaultDeclaredMaxChainDepth
}

// SetPollURL configures the suite to run serving_mode tests against the
// peer's HTTP poll listener. The URL is the prefix BEFORE the /content
// or /tree route (e.g. "http://127.0.0.1:9201" for Posture 1, or
// "http://127.0.0.1:9100/poll" for Posture 2). When empty, the
// serving_mode category SKIPs — the peer has not exposed its serving-mode
// face to the validator.
func (s *ValidationSuite) SetPollURL(url string) {
	s.pollURL = url
}

// newClient creates a PeerClient using the suite's identity setting.
func (s *ValidationSuite) newClient() (*PeerClient, error) {
	if s.identityName != "" {
		return NewPeerClientWithIdentity(s.addr, s.identityName)
	}
	return NewPeerClient(s.addr)
}

// Run executes all validation categories in order.
// If connectivity fails, remaining categories are skipped.
// If connection grants don't cover types/handlers, those categories are skipped.
func (s *ValidationSuite) Run(ctx context.Context) (*Report, error) {
	report := NewReport(s.addr)

	client, err := s.newClient()
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	defer client.Close()
	client.SetVerbose(s.verbose)
	client.SetProfile(s.Profile())

	// runCat wraps a category's run/skip choice with a budget guard. When the
	// run-wide -timeout has already expired, every subsequent client write
	// returns "i/o timeout" instantly and each category records a wall of
	// timeout FAILs that drowns out the real signal (the prior slow category).
	// Instead, once ctx is done, record a single skipCategory per remaining
	// category citing budget_exhausted so the report says what actually
	// happened. Called per category in the order they appear below.
	//
	// Profile guard (V7 v7.72 §9.0): under --profile core, categories outside
	// the core-profile set skip with a diagnostic. Distinct from the budget
	// guard so the report names *why* a category was skipped.
	runCat := func(cat string, runFn func() []CheckResult) {
		if s.Profile() == ProfileCore && !inCoreProfile(cat) {
			// §10.2 carve-out: origination isn't in §9.0's category set,
			// but under --profile core with -reference-peer, run the
			// minimal-origination slice (the gate runOriginationCore
			// installs in suite.go below). The core-profile category set
			// is the publication contract; the minimal-origination probe
			// is a layered conditional check defined by PROPOSAL-V7-V7.74
			// §10.2 — distinct from "extension-only category, skip
			// always". Without -reference-peer the probe still skips
			// (same behavior as full-profile + no -reference-peer).
			//
			// (Concurrency is now enumerated in §9.0 per v7.75 — no
			// carve-out needed; falls through the normal core-profile
			// path. Kept as a comment marker since the §6.11/§4.9
			// outcomes the category exercises remain the rationale for
			// the §9.0 fold.)
			if cat == catOrigination && s.referenceAddr != "" {
				// fall through to runFn
			} else {
				report.AddAll(skipCategory(cat, "outside --profile core (V7 v7.72 §9.0 — extension-only category)"))
				return
			}
		}
		if err := ctx.Err(); err != nil {
			report.AddAll(skipCategory(cat, fmt.Sprintf("budget_exhausted: prior categories consumed the -timeout window (%v); re-run with a longer -timeout to surface this category", err)))
			return
		}
		report.AddAll(runFn())
	}

	// Category 1: Connectivity + connect handshake.
	connectivityChecks, connected := runConnectivity(ctx, client)
	report.AddAll(connectivityChecks)

	if !connected {
		report.AddAll(skipCategory(catEncoding, "connect failed"))
		report.AddAll(skipCategory(catTypeSystem, "connect failed"))
		report.AddAll(skipCategory(catHandlers, "connect failed"))
		return report, nil
	}

	report.PeerID = string(client.RemotePeerID())
	alignAuthoringFormatWithPeer(client)

	// Category 2: Encoding checks (only needs connection data).
	runCat(catEncoding, func() []CheckResult { return runEncoding(client) })

	// Category 3: Type system comparison — requires system/type/* grant.
	runCat(catTypeSystem, func() []CheckResult {
		if client.GrantsAllow("system/type/system/peer") {
			return runTypeSystem(ctx, client)
		}
		return skipCategory(catTypeSystem, "connection grants do not cover system/type/*")
	})

	// Category 4: Handler manifest comparison — requires system/handler/* grant.
	runCat(catHandlers, func() []CheckResult {
		if client.GrantsAllow("system/handler/system/tree") {
			return runHandlers(ctx, client)
		}
		return skipCategory(catHandlers, "connection grants do not cover system/handler/*")
	})

	// Category 4b: Capability handler behavioral conformance (V7 §6.2).
	// Skip if the peer doesn't advertise the capability:request grant
	// in its accepted-grants set (the spec marks the handler SHOULD;
	// absence + dropped grant is conformant per the §5 ruling).
	runCat(catCapability, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/capability", "", "request") {
			return runCapability(ctx, client)
		}
		return skipCategory(catCapability, "connection grants do not advertise system/capability:request — V7 §6.2 marks the handler SHOULD; peers that drop the grant are conformant")
	})

	// Category 5: Tree operations (snapshot, diff, merge, extract).
	runCat(catTreeOps, func() []CheckResult {
		if client.GrantsAllow("system/validate/test-1") {
			return runTreeOperations(ctx, client)
		}
		return skipCategory(catTreeOps, "connection grants do not cover system/validate/*")
	})

	// Category 6: Subscription extension (subscribe, notify, unsubscribe).
	runCat(catSubscriptions, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/subscription", "system/validate/sub-test/*", "subscribe") {
			return runSubscriptions(ctx, client)
		}
		return skipCategory(catSubscriptions, "connection grants do not cover subscribe operation")
	})

	// Category 7: Continuation extension (forward, resume, abandon).
	runCat(catContinuations, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/inbox", "system/inbox/*", "receive") {
			return runContinuations(ctx, client)
		}
		return skipCategory(catContinuations, "connection grants do not cover inbox operations")
	})

	// Category 8: Revision extension (commit, log, branch, merge, etc.).
	// Gate probes the shared runner family (revisionTestFamily), not a literal
	// instance, so gating matches the randomized paths the runner writes.
	runCat(catRevision, func() []CheckResult {
		if client.GrantsAllow(revisionTestFamily + "gate/probe") {
			return runRevision(ctx, client)
		}
		return skipCategory(catRevision, "connection grants do not cover revision operations")
	})

	// Category 8b: Auto-version (EXTENSION-REVISION §6.1 per-write CRDT contract).
	runCat(catAutoVersion, func() []CheckResult {
		if client.GrantsAllow(autoVersionTestFamily + "gate/probe") {
			return runAutoVersion(ctx, client)
		}
		return skipCategory(catAutoVersion, "connection grants do not cover auto-version validation paths")
	})

	// Category 9: Clock extension (now, compare, tick).
	runCat(catClock, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/clock", "system/clock/*", "now") {
			return runClock(ctx, client)
		}
		return skipCategory(catClock, "connection grants do not cover clock operations")
	})

	// Category 10: History extension (recording, query, rollback).
	runCat(catHistory, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/history", "system/history", "query") {
			return runHistory(ctx, client)
		}
		return skipCategory(catHistory, "connection grants do not cover history operations")
	})

	// Category 11: Security — capability enforcement checks.
	runCat(catSecurity, func() []CheckResult { return runSecurity(ctx, client) })

	// Category 11b: Multi-sig root capabilities (PROPOSAL-MULTISIG-CORE-PRIMITIVE).
	// Negative-only over the wire — peer should reject malformed/unauthorized
	// multi-sig caps. Positive paths covered by core/capability/multisig_test.go.
	runCat(catMultiSig, func() []CheckResult { return runMultiSig(ctx, client) })

	// Category 12: Query extension (find, count, indexes).
	runCat(catQuery, func() []CheckResult {
		if grantsAllow(client.Grants(), "system/query", "system/validate/query/*", "find") {
			return runQuery(ctx, client)
		}
		return skipCategory(catQuery, "connection grants do not cover query operations")
	})

	// Category 11: Local files — domain handler operations.
	runCat(catLocalFiles, func() []CheckResult {
		if grantsAllow(client.Grants(), "local/files", "local/files/*", "read") {
			return runLocalFiles(ctx, client)
		}
		return skipCategory(catLocalFiles, "connection grants do not cover local/files operations")
	})

	// Category 14: Compute extension (eval, install, reactive mode).
	runCat(catCompute, func() []CheckResult {
		if client.GrantsAllow("system/validate/compute-test") {
			return runCompute(ctx, client)
		}
		return skipCategory(catCompute, "connection grants do not cover compute test paths")
	})

	// Category 15: Entity-native handler dispatch (V7 §6.6, COMPUTE §3, §4).
	runCat(catEntityNative, func() []CheckResult {
		if client.GrantsAllow("app/validate/entity-native") {
			return runEntityNative(ctx, client)
		}
		return skipCategory(catEntityNative, "connection grants do not cover entity-native test paths")
	})

	// Category 13: Origination (A-role) — requires a reference peer.
	// Under --profile core, run the §10.2 minimal slice instead of the
	// full A-role sub-suite (async delivery, cross-peer subscription,
	// chain sync, prefix sync, file sync are extension legs and stay
	// out of core per PROPOSAL-V7-V7.74-CORE-EXTENSIBILITY-BOUNDARY §10.2).
	runCat(catOrigination, func() []CheckResult {
		if s.referenceAddr == "" {
			return skipCategory(catOrigination, "no -reference-peer provided (single-peer mode cannot catch origination-side bugs)")
		}
		if client.Profile() == ProfileCore {
			return runOriginationCore(ctx, client, s.referenceAddr, s.identityName)
		}
		return runOrigination(ctx, client, s.referenceAddr, s.identityName)
	})

	// Category 13b: §6.11 concurrency-correctness + §4.9 resilience
	// conformance (enumerated in V7 §9.0 as of v7.75; the §10.2-style
	// carve-out used through v7.74 is gone). Covers §6.11(a) multiplexed
	// reader, §6.11(b) demux by request_id, no-head-of-line, plus §4.9
	// outcomes via T2.1 sustained load + T2.2 connection churn (no
	// silent drop, no crash, recovers when load subsides).
	runCat(catConcurrency, func() []CheckResult {
		return runConcurrency(ctx, client, s.newClient)
	})

	// Category 13c: V7 §4.10 resource bounds + admission control
	// (enumerated in §9.0 as of v7.75 — arch fold `414b892`
	// moved §4.10(a)+(b) from RESERVED → §9.1 floor MUSTs once the
	// `resource_bounds` gate landed 3-way GREEN; see the V7.75
	// resource-bounds cohort-close notes).
	runCat(catResourceBounds, func() []CheckResult {
		return runResourceBounds(ctx, s.addr, s.newClient, s.effectiveDeclaredMaxPayload(), s.effectiveDeclaredMaxChainDepth())
	})

	// Category 16: EXTENSION-ATTESTATION (substrate primitive).
	runCat(catAttestation, func() []CheckResult { return runAttestation(ctx, client) })

	// Category 17: EXTENSION-QUORUM (K-of-N node primitive).
	runCat(catQuorum, func() []CheckResult { return runQuorum(ctx, client) })

	// Category 18: EXTENSION-IDENTITY (convention layer).
	runCat(catIdentity, func() []CheckResult { return runIdentity(ctx, client) })

	// Category 19: EXTENSION-ROLE (named grant bundles + context-scoped
	// peer authorization). Structural conformance — manifest + types.
	runCat(catRole, func() []CheckResult { return runRole(ctx, client) })

	// Category 20: EXTENSION-ROLE behavioral test vectors (drives the
	// v1.6 lifecycle through the wire — define/assign/exclude/sweep,
	// linkage entity, hex path encoding).
	runCat(catBehavioralRole, func() []CheckResult { return runBehavioralRole(ctx, client) })

	// Category 21: behavioral v3.3 test vectors (drives TVs through
	// the wire — TV-A4a/b/c/d transitive supersession etc.).
	runCat(catBehavioralV33, func() []CheckResult { return runBehavioralV33(ctx, client) })

	// Category 22: EXTENSION-DURABILITY (v0.1 exploratory/optional —
	// extracted from EXTENSION-INBOX §10). Probes against
	// `system/tree` get, which the connection grant covers; durability is
	// reconciled before handler dispatch (§5) so the handler choice is
	// immaterial. Absence of the extension is conformant; the category
	// validates behavior for peers that implement the reference design.
	runCat(catDurability, func() []CheckResult { return runDurability(ctx, client) })

	// Category 23: EXTENSION-TYPE v1.1 — validate, standard constraints,
	// §5.5 ECF byte-equality gate, §4.5 fail-closed format vocabulary,
	// §12.1 PCRE rejection. Connection grants cover system/type/* via
	// open-access; named-peer flows depend on the peer's grant config.
	runCat(catType, func() []CheckResult { return runType(ctx, client) })

	// Category 24: EXTENSION-CONTENT v3.6 — handler manifest, blob /
	// chunk / descriptor types, §6.2/§6.3 path_required MUSTs, FastCDC
	// gear-table + boundary + edit-stability vectors, §3.7 ECF
	// byte-equality, §4.3 inline-include boundary, §2.4 presence rule,
	// §5.3 descriptor integrity check.
	runCat(catContent, func() []CheckResult { return runContent(ctx, client) })

	// Category 25: EXTENSION-NETWORK Chunk E HTTP serving-mode — the
	// /content/{hex} and /tree/{abs-path} face per Amendment 4 §6.5.3.
	// Skip when -poll-url is absent (the peer hasn't exposed its
	// serving-mode listener to the validator).
	runCat(catServingMode, func() []CheckResult {
		if s.pollURL != "" {
			return runServingMode(ctx, client, s.pollURL)
		}
		return skipCategory(catServingMode, "no -poll-url provided (peer's HTTP serving-mode face not exposed to validator); start the peer with --http-poll-addr and --serve-namespace system/content/public, then pass -poll-url http://host:port")
	})

	// Category 26: V7 §1.4 universal address space — peer-relative ↔
	// absolute round-trip, foreign-namespace publishing, listing
	// traversal across peer-id top-level segments. Distinct from
	// `serving_mode` (HTTP read surface) and `tree_operations` (handler
	// semantics): this pins the **addressing model** itself.
	runCat(catUniversalAddressSpace, func() []CheckResult { return runUniversalAddressSpace(ctx, client) })

	// Category 27: PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3
	// mechanical track — G1 mixed-transport coexistence + R3a granter
	// idempotency across reconnect. R1 cross-peer-HTTP-subscription
	// lives in the convergence flow (requires -http-peers).
	runCat(catTransportFamily, func() []CheckResult {
		return runTransportFamily(ctx, transportFamilyRunner{
			primary:   client,
			reconnect: s.connectedClient(ctx, client),
		})
	})

	// Category 28: PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.2 (R6)
	// — per-peer session entity at /{target}/system/peer/(granted-)session/
	// {validator}. Visible proof that the granter's cap-holding state
	// lives in the entity tree (R6's central commit), not in connection
	// memory.
	runCat(catSession, func() []CheckResult { return runSession(ctx, client) })

	// Category 29: V7 v7.65 peer entity canonicalization conformance vectors
	// (PROPOSAL-V7-PEER-ENTITY-CANONICALIZATION-AND-V1-CONTRACT §13).
	// Seven vectors: PEER-CANON-1/2, PEER-PATTERN-1/2, PEER-MUT-1/2,
	// COMPOSITION-1. Cross-impl 7/7 PASS is the v7.65 lock signal.
	// Sub-vectors gate internally on policy/* grants.
	runCat(catPeerCanonicalization, func() []CheckResult { return runPeerCanonicalization(ctx, client) })

	// Category 30: V7 v7.66 format-agility validation + cleanup conformance
	// vectors (PROPOSAL-V7-V7.66-FORMAT-AGILITY-VALIDATION-AND-CLEANUP §7,
	// with v7.67 §2 errata rename folded in). Ten vectors: KEY-TYPE-
	// STRING-1, KEY-TYPE-PREFIX-1, LEGACY-MINT-1, AGILITY-DECODE-1,
	// AGILITY-ENTITY-1, AGILITY-CANONICAL-1, AGILITY-PATTERN-1, AGILITY-
	// UNKNOWN-1, FORMAT-CODE-INTERPRETATION-1 (renamed from PREFIX-
	// DISPATCH-1), CAP-FREEZE-1. Cross-impl 10/10 PASS is the v7.66 lock
	// signal.
	runCat(catFormatAgility, func() []CheckResult { return runFormatAgility(ctx, client) })

	// Category 31: V7 v7.67 Phase-1 crypto-agility conformance vectors
	// (PROPOSAL-V7-V7.67-CRYPTO-AGILITY-SEED-TABLES §13.7). Four Phase-1
	// vectors: KEY-TYPE-ED448-1, HASH-FORMAT-SHA-384-1, VARINT-MULTIBYTE-1,
	// VARINT-RESERVED-FF-1. Phase-1 cross-impl PASS plus v7.66/v7.65 no-
	// regression is the gate to start Phase 2 (cross-key matrix).
	runCat(catCryptoAgility, func() []CheckResult { return runCryptoAgility(ctx, client) })

	// Category 32: V7 v7.69 §4.5/§4.5a hello-negotiation conformance.
	// NEGOTIATE-FORMAT-1 (hash_formats = single-active-value + advertised
	// floor + disjoint reject = 400 incompatible_hash_format) and
	// NEGOTIATE-KEYTYPE-1 (key_types = accept-set + advertised floor +
	// disjoint reject = 400 unsupported_key_type). This is the v7.69
	// landing gate that closes the M3 seam.
	runCat(catNegotiation, func() []CheckResult { return runNegotiation(ctx, client) })

	// Category 33: V7 v7.71 §A4-AUTHZ authorization-denial status+code matrix.
	// Seven vectors per PROPOSAL-V7-V7.71-AUTHORIZATION-ERROR-CODE-CONTRACT
	// §3.3: AUTHZ-DELEGATE-GRANT-1, AUTHZ-DENY-DEFAULT-1, AUTHZ-SCOPE-
	// EXCEEDS-1, AUTHZ-GRANTEE-1, AUTHZ-REVOKED-1, AUTHZ-NO-CATCHALL-1,
	// AUTHZ-EXPIRED-1. Pins the §3.3 normative MUST that authz-path DENY
	// MUST surface a defined authorization code (never a catch-all default
	// like `verification_failed`). Overlap-dedup: AUTHZ-SCOPE-EXCEEDS-1
	// generalizes the existing capability::request_rejects_scope_widening
	// vector at the §6.2 dispatch layer.
	runCat(catAuthz, func() []CheckResult { return runAuthz(ctx, client) })

	// Category 34: PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 published-root.
	// Six vectors covering ECF round-trip + signature carriage + seq
	// monotonicity + MANIFEST_GET + outbound dial + §1.1 host-bytes-distrust.
	// v4 + v5 require -poll-url to reach the peer's MANIFEST_GET surface;
	// the rest are pure-Go probes that ride alongside.
	runCat(catPublishedRoot, func() []CheckResult { return runPublishedRoot(ctx, s.pollURL) })

	// Category 35: EXTENSION-REGISTRY v1.0 — 14 vectors covering meta-resolver
	// precedence (pin / dispatch / chain / exhaustion / revocation), petname
	// backend ops (bind / unbind / list / supersedes), and entity wire shapes
	// (binding / revocation / resolver-config / resolution-log). Requires
	// registry-resolve + registry-petname-bind + registry-petname-unbind +
	// registry-petname-list caps; under --open-access the validator picks
	// them up via the wildcard grant.
	runCat(catRegistry, func() []CheckResult { return runRegistry(ctx, client) })

	// Category 36: EXTENSION-DISCOVERY v1.0 — 10 vectors covering the
	// substrate (`:scan` / `:announce-stop` round-trips, §3.1 truncation
	// non-silent), the entity types (candidate / decision / identity-claim
	// / scan-result flat envelope), the §2.2 successor-candidate pattern,
	// and the §3.2 DNS-SD wire pin (the silent-divergence anchor). v5-v7
	// require the system/discovery handler reachable; under --open-access
	// the validator picks up the wildcard grant.
	runCat(catDiscovery, func() []CheckResult { return runDiscovery(ctx, client) })

	// Category 37: EXTENSION-RELAY v1.0 — 13 vectors covering Mode F +
	// Mode S surfaces (post-Go-pre-impl-review at arch 54e5373 + 15b30d0).
	// Pure-Go vectors gate the entity-type wire shapes + the cohort byte-
	// equality pin on `envelope_inner` (data field, NOT refs block) + the
	// V7 §5.2 invariant-pointer signature carriage on advertise. Live
	// vectors gate the handler ops: advertise / put / poll cursor advance /
	// put_by_mismatch / empty-namespace-returns-empty / ttl_exhausted /
	// no_route / expired_on_arrival. Forward dispatch (terminal unwrap +
	// fallback) is exercised by the unit tests in ext/relay; live cross-
	// peer dispatch needs an OutboundDispatcher wired (R5+).
	runCat(catRelay, func() []CheckResult { return runRelay(ctx, client) })

	// Category 38: Tier-1 publish→fetch end-to-end over http-poll
	// (`docs/RELEASE-READINESS.md` Thread B + arch three-tier reframe).
	// Self-contained in-process flow: publisher mints + serves a small
	// blog tree via PollHandler on httptest; consumer drives MANIFEST_GET
	// → signature verify → TREE_GET → CONTENT_GET → ingest byte-equality.
	// No -poll-url / -reference-peer needed — the PollHandler the
	// publisher mounts IS the static origin (wire-equivalent to nginx /
	// R2 / S3 serving the same routes).
	runCat(catPublishFetchHTTPPoll, func() []CheckResult { return runPublishFetchHTTPPoll(ctx) })

	// Category 39: PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §6 — six vectors
	// covering the peer-issued backend's resolve / verify / revocation /
	// expiry / precede / offline-not-found paths. v1 vectors all SKIP with
	// explicit reasoning — the Backend itself is unit-tested in
	// ext/registry/peerissued (8 vectors); wire-level vectors against an
	// external peer need fixture orchestration (start the target with
	// --peer-issued-registry pinning a registry identity the validator
	// also controls). Wire vectors land in the Keystone leg per
	// HANDOFF-PEER-ISSUED-REGISTRY-BACKEND-IMPL §7.
	runCat(catPeerIssued, func() []CheckResult { return runPeerIssued() })

	// Category 40: EXTENSION-ENCRYPTION v1.0 — 10 vectors covering self/peer/
	// group encrypt-decrypt round-trips, the F2-1 group key-commitment
	// rejection of equivocation (ENC-GROUP-COMMIT-1), AAD tamper detection
	// (ENC-AAD-1), the §8.6 256-member ceiling (ENC-RESOURCE-BOUNDS-1), and
	// the §16 cert-lifecycle round-trip at Tier A (publish pubkey + signature
	// + handoff + revocation over the wire). Cohort byte-pin KATs at v1
	// baseline Argon2id (§16.5 BLOCK-0 lock) run as ext/encryption package
	// tests, not here, to keep validate-peer wall-clock tight.
	runCat(catEncryption, func() []CheckResult { return runEncryption(ctx, client) })

	return report, nil
}

// connectedClient returns a factory that produces a freshly-connected,
// fully-handshaken PeerClient against the suite's target, reusing the primary
// client's keypair. Used by the transport_family R3a reconnect check, whose
// premise is "reconnect with the SAME identity yields the same cap hash" —
// so the reconnect MUST present the same peer ID. newClient() would mint a
// fresh ephemeral keypair when no -identity is set, making every "reconnect" a
// different grantee: the peer then correctly mints a new cap (different hash)
// and the check spuriously reports an R3a violation against a conformant peer.
// Threading the primary's keypair keeps the identity stable in both the
// -identity and ephemeral cases. (The session redial already does this via
// NewPeerClientWithKeypair — this aligns transport_family with it.)
func (s *ValidationSuite) connectedClient(ctx context.Context, primary *PeerClient) func() (*PeerClient, error) {
	return func() (*PeerClient, error) {
		c, err := NewPeerClientWithKeypair(s.addr, primary.Keypair())
		if err != nil {
			return nil, err
		}
		c.SetVerbose(s.verbose)
		if err := c.Connect(ctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("reconnect: %w", err)
		}
		handshakeChecks := c.PerformHandshake(ctx)
		if !c.Connected() {
			c.Close()
			// Surface the first failing check name so the test message
			// is actionable rather than a blank "reconnect failed".
			for _, ck := range handshakeChecks {
				if ck.Severity == Fail {
					return nil, fmt.Errorf("reconnect handshake failed: %s: %s", ck.Name, ck.Message)
				}
			}
			return nil, fmt.Errorf("reconnect handshake failed (no specific check; client.Connected()=false)")
		}
		return c, nil
	}
}

// RunCategory executes a single validation category.
func (s *ValidationSuite) RunCategory(ctx context.Context, category string) (*Report, error) {
	report := NewReport(s.addr)

	client, err := s.newClient()
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	defer client.Close()
	client.SetVerbose(s.verbose)
	client.SetProfile(s.Profile())

	// Profile guard (V7 v7.72 §9.0): refuse to run a single category that
	// isn't in --profile core. Distinct from per-category skips inside the
	// runner — this is the entry-point gate. §10.2 carve-out: origination
	// is admissible under --profile core when -reference-peer is set
	// (the minimal-origination slice runs; see runCat closure above).
	// (Concurrency enumerated in §9.0 as of v7.75; the prior carve-out is
	// gone — the §9.0 publication contract now covers it directly.)
	if s.Profile() == ProfileCore && category != catConnectivity && !inCoreProfile(category) {
		if !(category == catOrigination && s.referenceAddr != "") {
			report.AddAll(skipCategory(category, "outside --profile core (V7 v7.72 §9.0 — extension-only category)"))
			return report, nil
		}
	}

	// Always need connectivity first.
	connectivityChecks, connected := runConnectivity(ctx, client)

	if category == catConnectivity {
		report.AddAll(connectivityChecks)
		return report, nil
	}

	if !connected {
		report.AddAll(connectivityChecks)
		report.AddAll(skipCategory(category, "connect failed"))
		return report, nil
	}

	report.PeerID = string(client.RemotePeerID())
	alignAuthoringFormatWithPeer(client)

	switch category {
	case catEncoding:
		report.AddAll(runEncoding(client))
	case catTypeSystem:
		if client.GrantsAllow("system/type/system/peer") {
			report.AddAll(runTypeSystem(ctx, client))
		} else {
			report.AddAll(skipCategory(catTypeSystem, "connection grants do not cover system/type/*"))
		}
	case catHandlers:
		if client.GrantsAllow("system/handler/system/tree") {
			report.AddAll(runHandlers(ctx, client))
		} else {
			report.AddAll(skipCategory(catHandlers, "connection grants do not cover system/handler/*"))
		}
	case catCapability:
		if grantsAllow(client.Grants(), "system/capability", "", "request") {
			report.AddAll(runCapability(ctx, client))
		} else {
			report.AddAll(skipCategory(catCapability, "connection grants do not advertise system/capability:request"))
		}
	case catTreeOps:
		if client.GrantsAllow("system/validate/test-1") {
			report.AddAll(runTreeOperations(ctx, client))
		} else {
			report.AddAll(skipCategory(catTreeOps, "connection grants do not cover system/validate/*"))
		}
	case catSubscriptions:
		if grantsAllow(client.Grants(), "system/subscription", "system/validate/sub-test/*", "subscribe") {
			report.AddAll(runSubscriptions(ctx, client))
		} else {
			report.AddAll(skipCategory(catSubscriptions, "connection grants do not cover subscribe operation"))
		}
	case catContinuations:
		if grantsAllow(client.Grants(), "system/inbox", "system/inbox/*", "receive") {
			report.AddAll(runContinuations(ctx, client))
		} else {
			report.AddAll(skipCategory(catContinuations, "connection grants do not cover inbox operations"))
		}
	case catRevision:
		if client.GrantsAllow("system/validate/revision-main-0/") {
			report.AddAll(runRevision(ctx, client))
		} else {
			report.AddAll(skipCategory(catRevision, "connection grants do not cover revision operations"))
		}
	case catAutoVersion:
		if client.GrantsAllow("system/validate/auto-version-0/") {
			report.AddAll(runAutoVersion(ctx, client))
		} else {
			report.AddAll(skipCategory(catAutoVersion, "connection grants do not cover auto-version validation paths"))
		}
	case catClock:
		if grantsAllow(client.Grants(), "system/clock", "system/clock/*", "now") {
			report.AddAll(runClock(ctx, client))
		} else {
			report.AddAll(skipCategory(catClock, "connection grants do not cover clock operations"))
		}
	case catHistory:
		if grantsAllow(client.Grants(), "system/history", "system/history", "query") {
			report.AddAll(runHistory(ctx, client))
		} else {
			report.AddAll(skipCategory(catHistory, "connection grants do not cover history operations"))
		}
	case catSecurity:
		report.AddAll(runSecurity(ctx, client))
	case catMultiSig:
		report.AddAll(runMultiSig(ctx, client))
	case catLocalFiles:
		if grantsAllow(client.Grants(), "local/files", "local/files/*", "read") {
			report.AddAll(runLocalFiles(ctx, client))
		} else {
			report.AddAll(skipCategory(catLocalFiles, "connection grants do not cover local/files operations"))
		}
	case catQuery:
		if grantsAllow(client.Grants(), "system/query", "system/validate/query/*", "find") {
			report.AddAll(runQuery(ctx, client))
		} else {
			report.AddAll(skipCategory(catQuery, "connection grants do not cover query operations"))
		}
	case catCompute:
		if client.GrantsAllow("system/validate/compute-test") {
			report.AddAll(runCompute(ctx, client))
		} else {
			report.AddAll(skipCategory(catCompute, "connection grants do not cover compute test paths"))
		}
	case catEntityNative:
		if client.GrantsAllow("app/validate/entity-native") {
			report.AddAll(runEntityNative(ctx, client))
		} else {
			report.AddAll(skipCategory(catEntityNative, "connection grants do not cover entity-native test paths"))
		}
	case catOrigination:
		if s.referenceAddr == "" {
			return nil, fmt.Errorf("origination category requires -reference-peer to be set")
		}
		if client.Profile() == ProfileCore {
			report.AddAll(runOriginationCore(ctx, client, s.referenceAddr, s.identityName))
		} else {
			report.AddAll(runOrigination(ctx, client, s.referenceAddr, s.identityName))
		}
	case catConcurrency:
		report.AddAll(runConcurrency(ctx, client, s.newClient))
	case catResourceBounds:
		report.AddAll(runResourceBounds(ctx, s.addr, s.newClient, s.effectiveDeclaredMaxPayload(), s.effectiveDeclaredMaxChainDepth()))
	case catAttestation:
		report.AddAll(runAttestation(ctx, client))
	case catQuorum:
		report.AddAll(runQuorum(ctx, client))
	case catIdentity:
		report.AddAll(runIdentity(ctx, client))
	case catRole:
		report.AddAll(runRole(ctx, client))
	case catBehavioralRole:
		report.AddAll(runBehavioralRole(ctx, client))
	case catBehavioralV33:
		report.AddAll(runBehavioralV33(ctx, client))
	case catDurability:
		report.AddAll(runDurability(ctx, client))
	case catType:
		report.AddAll(runType(ctx, client))
	case catContent:
		report.AddAll(runContent(ctx, client))
	case catServingMode:
		if s.pollURL == "" {
			return nil, fmt.Errorf("serving_mode category requires -poll-url http://host:port (peer must be started with --http-poll-addr and --serve-namespace system/content/public)")
		}
		report.AddAll(runServingMode(ctx, client, s.pollURL))
	case catUniversalAddressSpace:
		report.AddAll(runUniversalAddressSpace(ctx, client))
	case catTransportFamily:
		report.AddAll(runTransportFamily(ctx, transportFamilyRunner{
			primary:   client,
			reconnect: s.connectedClient(ctx, client),
		}))
	case catSession:
		report.AddAll(runSession(ctx, client))
	case catPeerIDForm:
		report.AddAll(runPeerIDForm(ctx, client))
	case catPolicyDualForm:
		report.AddAll(runPolicyDualForm(ctx, client))
	case catPeerCanonicalization:
		report.AddAll(runPeerCanonicalization(ctx, client))
	case catFormatAgility:
		report.AddAll(runFormatAgility(ctx, client))
	case catCryptoAgility:
		report.AddAll(runCryptoAgility(ctx, client))
	case catNegotiation:
		report.AddAll(runNegotiation(ctx, client))
	case catAuthz:
		report.AddAll(runAuthz(ctx, client))
	case catPublishedRoot:
		report.AddAll(runPublishedRoot(ctx, s.pollURL))
	case catRegistry:
		report.AddAll(runRegistry(ctx, client))
	case catDiscovery:
		report.AddAll(runDiscovery(ctx, client))
	case catRelay:
		report.AddAll(runRelay(ctx, client))
	case catPublishFetchHTTPPoll:
		report.AddAll(runPublishFetchHTTPPoll(ctx))
	case catPeerIssued:
		report.AddAll(runPeerIssued())
	case catEncryption:
		report.AddAll(runEncryption(ctx, client))
	case catConvergentMirror:
		// convergent_mirror is a multi-peer category — invocation through
		// the single-peer path is a usage error. The category runs from
		// RunConvergence (use -peers host1:port,host2:port).
		return nil, fmt.Errorf("convergent_mirror is a multi-peer category — pass -peers host1:port,host2:port (not -addr)")
	default:
		return nil, fmt.Errorf("unknown category: %q (valid: %s)", category, strings.Join(AllCategories(), ", "))
	}

	return report, nil
}

// RunConvergence executes multi-peer convergence tests across the given peer addresses.
func (s *ValidationSuite) RunConvergence(ctx context.Context, peerAddrs []string) (*Report, error) {
	if len(peerAddrs) < 2 {
		return nil, fmt.Errorf("convergence testing requires at least 2 peer addresses, got %d", len(peerAddrs))
	}

	report := NewReport("multi-peer")

	// EXTENSION-CONTINUATION §4.2 case 3 models ONE installer principal that
	// holds one keypair and wields it across every peer connection in the
	// dispatch chain (root cap from B granted to installer; installer
	// re-attenuates as leaf granter; installs on A). The harness simulates a
	// single principal driving multiple peer connections, so every PeerClient
	// in this run shares ONE keypair — the installer's identity is byte-equal
	// across A, B, C... Each PeerClient still authenticates and gets its own
	// connection-bound caps from its peer, but the underlying signer/grantee
	// identity is the same one principal.
	//
	// Previously this loop minted a fresh ephemeral keypair per peer addr,
	// which fragmented the validator into N distinct identities and made the
	// §3.1a in-chain check fail on rexec_setup (writer = A-side identity, leaf
	// granter = B-side identity, byte-distinct → 403 embedded_cap_unauthorized).
	// That bug was introduced when the legacy self-rooted continuations test
	// was migrated to the proper §4.2 case 3 B-rooted pattern (commit 43f07dc)
	// without updating the harness to match the spec's single-principal model.
	var sharedKP crypto.Keypair
	if s.identityName != "" {
		kp, err := crypto.LoadIdentity(s.identityName)
		if err != nil {
			return nil, fmt.Errorf("load identity %q: %w", s.identityName, err)
		}
		sharedKP = kp
	} else {
		kp, err := crypto.Generate()
		if err != nil {
			return nil, fmt.Errorf("generate shared validator keypair: %w", err)
		}
		sharedKP = kp
	}

	// Connect to all peers.
	labels := []string{"A", "B", "C", "D", "E", "F"}
	var clients []*PeerClient
	for i, addr := range peerAddrs {
		label := labels[i%len(labels)]
		client, err := NewPeerClientWithKeypair(addr, sharedKP)
		if err != nil {
			return nil, fmt.Errorf("create client for peer %s (%s): %w", label, addr, err)
		}
		client.SetVerbose(s.verbose)

		connectChecks, connected := runConnectivity(ctx, client)
		report.AddAll(connectChecks)
		if !connected {
			client.Close()
			report.AddAll(skipCategory(catConvergence, fmt.Sprintf("peer %s (%s) connect failed", label, addr)))
			// Close already-connected clients.
			for _, c := range clients {
				c.Close()
			}
			return report, nil
		}

		report.Peers = append(report.Peers, PeerInfo{
			Label:  label,
			Addr:   addr,
			PeerID: string(client.RemotePeerID()),
		})
		clients = append(clients, client)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	// Cross-peer TCP subscription — focused TCP-only dispatch gate.
	// Runs FIRST (before runConvergence) so peer B's outbound
	// connection pool is empty when the dispatch fires; otherwise a
	// cached HTTP connection from the convergence flow gets reused
	// and the TCP path is never exercised. See RUST-TCP-URL-DIALER-
	// BUG — Rust's outbound TCP dialer doesn't strip
	// the tcp:// scheme, which used to surface as cascading failures
	// across 30+ convergence tests; this gate surfaces it as one
	// named failure with a pointed diagnostic.
	report.AddAll(runCrossPeerTCPSubscription(ctx, clients))

	// Run convergence tests.
	report.AddAll(runConvergence(ctx, clients))

	// PROPOSAL-CONVERGENT-MIRRORING §5 conformance gate: exercises the
	// v3.14 include_payload + V7 v7.50 CAS-create + deref_included
	// recipe end-to-end on a two-peer A→B mirror and asserts
	// convergence-to-latest + bounded amplification.
	report.AddAll(runConvergentMirror(ctx, clients))

	// EXTENSION-RELAY v1.0 three-peer behavioral gate: terminal-hop forward
	// (A → B(relay) → C), §6.2.1 offline-stranger fallback (A → B with C
	// unreachable, then C polls), and §3.5 forged-redirection defense (bad-
	// sig inbox-relay decl MUST NOT be honored). Requires 3 peers; SKIPs
	// gracefully with -peers a,b only. Validates the PeerDispatcher +
	// TreeInboxRelayResolver wiring that flipped on at entity-peer:main.go
	// post-SetupStore.
	report.AddAll(runRelayMultiPeer(ctx, clients, s.httpPeers, s.wsPeers))

	// EXTENSION-RELAY source-routed multi-hop gate per PROPOSAL-RELAY-
	// SOURCE-ROUTED-MULTIHOP-AND-ROUTING-BOUNDARY §2 (arch DRAFT 2026-06-
	// 15). Proves the `route: [peer_id]` field threads a wire forward-
	// request through two real relay hops: A → B(route=[C,D]) → C(route=
	// [D]) → D. Validates the per-hop pop + ttl decrement + §9 inner
	// opacity under source-routing, the receive-side ttl=0 gate (proposal
	// §4 SRCROUTE-TTL-EXHAUST-1), §6.2.1 fallback under a routed
	// unreachable intermediate (SRCROUTE-UNREACHABLE-FALLBACK-1), and
	// the v1 default-resolver no_route/502 (RESOLVER-DEFAULT-1). Requires
	// 3 peers; SKIPs with -peers a,b only.
	report.AddAll(runRelaySourceRoute(ctx, clients))

	// EXTENSION-ROUTE v1 storage-plane behavioral gate per PROPOSAL-
	// EXTENSION-ROUTE.md (arch DRAFT — storage plane only;
	// producers deferred by design). Proves system/route entities are
	// readable by RELAY when a forward-request lacks both Route and
	// NextHop: the §3 documented match (exact > `*` default, lowest
	// metric wins, expiry-skip, no-match → no_route/502) drives the
	// table-backed resolver added by PROPOSAL-RELAY-SOURCE-ROUTED-
	// MULTIHOP §3. Routes are hand-populated by the validator per the
	// proposal's deferral framing (peer / DISCOVERY / GOSSIP own
	// production in deployment). Requires 3 peers.
	report.AddAll(runRoute(ctx, clients))

	// EXTENSION-RELAY v1.0 offline-delivery pre-release behavioral gate:
	// proves the POSITIVE inbox-relay decl resolver path (mp4 was the
	// negative), the full receive-side two-hop fetch + decode + verify
	// (mp3 only confirmed the entry count), and the §9 byte-identity-to-
	// direct discipline across the §6.2.1 fallback storage path. See
	// `EXPLORATION-RELAY-RECEIVE-SIDE-OPACITY-AND-CROSS-PROTOCOL`
	// pre-release test case #2 (inbox-relay fallback / offline delivery).
	// Requires 3 peers; SKIPs gracefully with -peers a,b only.
	report.AddAll(runRelayOfflineDelivery(ctx, clients))

	// EXTENSION-RELAY §3.5 REGISTRY-served decl chain (pre-release Test
	// #2b per RELAY-PRE-RELEASE-TESTS-STATUS §1, Option A).
	// Requires clients[1] (B) to have been started with
	// `--inbox-relay-registry <clients[0]'s peer-name>` — peer-manager
	// translates the name to a peer-id and forwards to entity-peer's
	// --inbox-relay-registry flag.
	report.AddAll(runRelayOfflineDeliveryRegistry(ctx, clients, s.httpPeers, s.wsPeers))

	// EXTENSION-RELAY §3.1 multi-principal sub-piece of pre-release Test #3
	// (Phase-2 multi-hop deferred; see
	// RELAY-PRE-RELEASE-ARCH-HANDOFF Item 1). Drives the
	// connection-author / wire-author divergence through §6.2.1 fallback
	// + tree-fetch receive-side.
	report.AddAll(runRelayMultiPrincipal(ctx, clients))

	// PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3 R1: cross-peer
	// subscription dispatched over HTTP. Only runs when -http-peers is
	// provided (each peer needs to be reachable over HTTP). The check
	// publishes A's HTTP profile in B's tree, subscribes on B targeting
	// A's inbox, triggers on B, and polls A's inbox for delivery. Pre-
	// R1 (single-profile dispatcher) this could not work because the
	// dispatcher only walked TCP profiles.
	report.AddAll(runCrossPeerHTTPSubscription(ctx, clients, s.httpPeers))

	return report, nil
}

// skipCategory returns a single SKIP result for an entire category.
func skipCategory(category, reason string) []CheckResult {
	return []CheckResult{
		skip(category, "skipped", "", fmt.Sprintf("category skipped: %s", reason)),
	}
}
