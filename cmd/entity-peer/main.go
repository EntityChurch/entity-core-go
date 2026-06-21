// Command entity-peer runs an Entity Core V7 peer server.
//
// It wires the core protocol library with every ext handler and serves EXECUTE
// traffic over TCP, with optional HTTP-live, WebSocket, and HTTP-poll serving
// listeners. This is the reference peer the conformance suite and the
// cross-implementation interop drives run against. See CLAUDE.md for the flag
// reference; flags like --files, --http-poll-addr, and --publish-root gate
// specific validate-peer categories.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"strconv"

	"go.entitychurch.org/entity-core-go/cmd/internal/config"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/tree"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/attestation"
	extcapability "go.entitychurch.org/entity-core-go/ext/capability"
	"go.entitychurch.org/entity-core-go/ext/clock"
	"go.entitychurch.org/entity-core-go/ext/compute"
	"go.entitychurch.org/entity-core-go/ext/conformance"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/continuation"
	"go.entitychurch.org/entity-core-go/ext/discovery"
	discoverymdns "go.entitychurch.org/entity-core-go/ext/discovery/mdns"
	"go.entitychurch.org/entity-core-go/ext/relay"
	relaypeer "go.entitychurch.org/entity-core-go/ext/relay/peerwiring"
	"go.entitychurch.org/entity-core-go/ext/handlers"
	"go.entitychurch.org/entity-core-go/ext/history"
	"go.entitychurch.org/entity-core-go/ext/identity"
	"go.entitychurch.org/entity-core-go/ext/inbox"
	"go.entitychurch.org/entity-core-go/ext/localfiles"
	"go.entitychurch.org/entity-core-go/ext/publishedroot"
	"go.entitychurch.org/entity-core-go/ext/query"
	"go.entitychurch.org/entity-core-go/ext/registry"
	"go.entitychurch.org/entity-core-go/ext/registry/localname"
	"go.entitychurch.org/entity-core-go/ext/registry/peerissued"
	"go.entitychurch.org/entity-core-go/ext/quorum"
	"go.entitychurch.org/entity-core-go/ext/revision"
	"go.entitychurch.org/entity-core-go/ext/httplive"
	"go.entitychurch.org/entity-core-go/ext/role"
	storagesubstitutehttp "go.entitychurch.org/entity-core-go/ext/storagesubstitutehttp"
	storagesubstitutesources "go.entitychurch.org/entity-core-go/ext/storagesubstitutesources"
	"go.entitychurch.org/entity-core-go/ext/subscription"
	typeext "go.entitychurch.org/entity-core-go/ext/type"
	constrainth "go.entitychurch.org/entity-core-go/ext/type/constraint"

	"github.com/fxamacker/cbor/v2"
)

func main() {
	name := flag.String("name", "", "peer name from ~/.entity/peers/{name}/ (persistent identity + grants)")
	addr := flag.String("addr", "", "TCP listen address (overrides config.toml)")
	debug := flag.Bool("debug", false, "enable debug protocol logging")
	openAccess := flag.Bool("open-access", false, "[DEPRECATED in v7.74; removed in v7.75] grant full access to connecting peers (degenerate seed policy default → *). Migrate to --seed-policy / WithSeedPolicy.")
	readyFile := flag.String("ready-file", "", "write JSON {addr, peer_id} to this file when ready")
	filesRoot := flag.String("files", "", "expose filesystem directory (format: name:/path:tree/prefix/)")
	publishDescriptors := flag.Bool("publish-descriptors", false, "DOMAIN-LOCAL-FILES v1.3 §10.5 V3: when set, the --files root is configured with publish_descriptors=true so file reads write `system/content/descriptor/{hash}` entities into the local tree. Arms local_files.v3_descriptor_publish_exercised.")
	historyFlag := flag.String("history", "", "enable history recording (format: pattern[:max_depth], e.g. \"*:1000\" or \"project/*\")")
	storage := flag.String("storage", "memory", "storage backend: memory (default) or sqlite")
	storagePath := flag.String("storage-path", "", "sqlite database path (default ~/.entity/peers/{name}/peer.db when --name is set)")
	substituteAllowHTTP := flag.Bool("substitute-allow-http", false, "allow http:// (not just https://) URLs in the storage-substitute chain (insecure; testing only)")
	httpAddr := flag.String("http-addr", "", "additional HTTP-live listen address (e.g. :9003); empty disables. POST EXECUTE → EXECUTE-RESPONSE per NETWORK §5 (Chunk D)")
	httpPath := flag.String("http-path", "/entity", "URL path the HTTP-live listener accepts POSTs at (when --http-addr set)")
	wsAddr := flag.String("ws-addr", "", "additional WebSocket-live listen address (e.g. :9004); empty disables. Each binary WS message carries one length-prefixed ECF envelope per NETWORK §6.5.2b + §6.5.2c L864.")
	wsPath := flag.String("ws-path", "/ws", "URL path the WebSocket listener accepts upgrades at (when --ws-addr set)")
	// Chunk E serving-mode flags. impl plan §3.
	httpPollAddr := flag.String("http-poll-addr", "", "Chunk E: isolated HTTP poll listener address (e.g. :9201); GET /content/{hex(H)}. Mutually exclusive with --http-poll-mount-on-live.")
	httpPollMountOnLive := flag.Bool("http-poll-mount-on-live", false, "Chunk E: mount poll routes on the live HTTP listener (Posture 2). Requires --http-addr. Mutually exclusive with --http-poll-addr.")
	httpPollPrefix := flag.String("http-poll-prefix", "/poll", "Chunk E: URL prefix for poll routes when mounted on live listener (default /poll); ignored on isolated port.")
	serveNamespace := flag.String("serve-namespace", "", "Chunk E: content-namespace scope (e.g. system/content/public). Serves H iff bound at NAMESPACE/{hex(H)} in tree. Mutually exclusive with --serve-scope-whole-store / --serve-closure-root.")
	serveWholeStore := flag.Bool("serve-scope-whole-store", false, "Chunk E: DEBUG OPT-IN — serve every H in local content-store. Operator owns T2/T3 consequence (ruling §1.3). Logs startup warning.")
	serveClosureRoot := flag.Bool("serve-closure-root", false, "EXTENSION-NETWORK §6.5.6 Amendment 10: scope served set to the transitive trie-node closure reachable from the local peer's current system/peer/published-root. Pairs with --publish-root so a consumer's signed-root hash-chain walk does not 404 on a CHAMP interior node. Mutually exclusive with --serve-namespace / --serve-scope-whole-store.")
	keyType := flag.String("key-type", "ed25519", "ephemeral keypair algorithm: ed25519 (default) | ed448. Ignored when --name selects a persistent identity (algorithm comes from the on-disk PEM header).")
	hashType := flag.String("hash-type", "sha256", "content_hash_format used for entities this peer authors: sha256 (default, 0x00) | sha384 (0x01). Received entities verify under their claimed algorithm regardless (v7.67 §2.3 format-code interpretation).")
	validate := flag.Bool("validate", false, "enable GUIDE-CONFORMANCE §7a test handlers (system/validate/echo + system/validate/dispatch-outbound) for validate-peer probing. OFF by default — these handlers expose §6.13(a)/§6.13(b) for black-box wire attestation and MUST NOT be on in production (dispatch-outbound originates outbound).")
	publishRoot := flag.Bool("publish-root", false, "PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4 (LOCKED): on every tree-root change, mint a signed system/peer/published-root pointer at system/peer/published-root/{peer_id_hex}, bind its signature at the invariant-pointer, and serve it as MANIFEST_GET's body via the http-poll listener. Requires a serving-mode posture (--http-poll-addr or --http-poll-mount-on-live) to be reachable on the wire; produces the entity unconditionally so other consumers can read it from the local tree.")
	discoveryAnnounce := flag.String("discovery-announce", "", "EXTENSION-DISCOVERY §3: announce self on the mDNS backend (`_entity-core._udp.local.`). Value is the transport profile_ref to advertise (the {profile-id} under system/peer/transport/{peer}/...). Empty disables. Requires --addr (TCP profile) or --http-addr (HTTP-live profile) to provide a reachable port.")
	inboxRelayRegistry := flag.String("inbox-relay-registry", "", "EXTENSION-RELAY §3.5 REGISTRY-served inbox-relay decl chain: comma-separated peer-ids to consult (in order) before the local-tree fallback. Each registry peer must have a published transport profile in this peer's tree so the remote tree:get can dial. Empty disables (local-tree only).")
	peerIssuedRegistry := flag.String("peer-issued-registry", "", "PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2 — pin one or more peer-issued registries (comma-separated, each `peer_id@tree_url_prefix`). The peer-id MUST be identity-multihash form (ed25519) so the receiver can derive the registry's pinned key. URL prefix is the http-poll TreeURLPrefix the registry serves at; allow http:// requires --substitute-allow-http. Empty disables (no peer-issued backend registered). The substrate IS opt-in / default-off per handoff §1.1 — a common peer's footprint is unchanged.")
	issuerPolicyMode := flag.String("issuer-policy-mode", "", "EXTENSION-REGISTRY §6a.9 — run this peer as a peer-issued live registry. Value selects the issuer-policy mode: `open` (any layer-1-valid request is signed; first-come-first-serve), `allowlist` (requires --issuer-policy-allowlist), `manual` (requests queue as pending_review). Empty disables — the register-request handler is not wired and publishers must use the curated `registry-issue-binding` CLI. `domain-control` is rejected (deferred per §6a.10).")
	issuerPolicyAllowlist := flag.String("issuer-policy-allowlist", "", "EXTENSION-REGISTRY §6a.9.1 — comma-separated target_peer_ids permitted to register when --issuer-policy-mode=allowlist. Ignored in other modes.")
	issuerPolicyNameConstraints := flag.String("issuer-policy-name-constraints", "", "EXTENSION-REGISTRY §6a.9.1 — POSIX glob narrowing which names this registry will issue (e.g. \"*.lab\"). Empty = no constraint.")
	issuerPolicyDefaultTTL := flag.Duration("issuer-policy-default-ttl", 0, "EXTENSION-REGISTRY §6a.9.1 — TTL the registry signs when register-request omits requested_ttl. Zero = no expiry.")
	flag.Parse()

	// Wire --hash-type into the process-global authoring default before
	// any entity construction happens (peer startup mints identity / clock
	// state under whatever default is set here).
	switch *hashType {
	case "sha256":
		entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA256)
	case "sha384":
		entity.SetDefaultHashAlgorithm(hash.AlgorithmSHA384)
	default:
		log.Fatalf("--hash-type: unsupported algorithm %q (supported: sha256, sha384)", *hashType)
	}

	// Validate Chunk E flag combinations per impl plan §3 before
	// constructing the peer.
	pollEnabled, pollErr := validateChunkEFlags(*httpAddr, *httpPollAddr, *httpPollMountOnLive, *serveNamespace, *serveWholeStore, *serveClosureRoot)
	if pollErr != nil {
		log.Fatalf("serving-mode flags: %v", pollErr)
	}

	var opts []peer.Option
	var staticResolver protocol.GrantResolver

	if *name != "" {
		namedOpts, listenAddr, sr := loadNamedPeer(*name)
		opts = append(opts, namedOpts...)
		staticResolver = sr
		// Use config.toml listen_addr as default, --addr overrides.
		if *addr == "" {
			*addr = listenAddr
		}
	}

	// Ephemeral mode: generate keypair if no --name given. --key-type picks
	// the algorithm (v7.67 §3 crypto-agility).
	if *name == "" {
		ktByte, ok := crypto.KeyTypeByte(*keyType)
		if !ok {
			log.Fatalf("--key-type: unsupported algorithm %q (supported: ed25519, ed448)", *keyType)
		}
		kp, err := crypto.GenerateForKeyType(ktByte)
		if err != nil {
			log.Fatalf("generate keypair (%s): %v", *keyType, err)
		}
		opts = append(opts, peer.WithIdentity(kp))
	}

	if *addr == "" {
		*addr = ":9002"
	}

	var cs store.ContentStore
	var li store.LocationIndex
	var sqliteStore *store.SqliteStore

	switch *storage {
	case "", "memory":
		cs = store.NewMemoryContentStore()
		li = store.NewMemoryLocationIndex()
	case "sqlite":
		path := *storagePath
		if path == "" {
			if *name == "" {
				log.Fatalf("--storage=sqlite requires --storage-path or --name")
			}
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("home dir: %v", err)
			}
			peerDir := home + "/.entity/peers/" + *name
			if err := os.MkdirAll(peerDir, 0700); err != nil {
				log.Fatalf("mkdir %s: %v", peerDir, err)
			}
			path = peerDir + "/peer.db"
		}
		s, err := store.NewSqliteStore(path)
		if err != nil {
			log.Fatalf("open sqlite at %s: %v", path, err)
		}
		sqliteStore = s
		cs = s.ContentStore()
		li = s.LocationIndex()
		log.Printf("Storage: sqlite at %s", path)
	default:
		log.Fatalf("unknown --storage %q (supported: memory, sqlite)", *storage)
	}

	var debugLog *log.Logger
	if *debug {
		debugLog = log.New(os.Stderr, "[debug] ", log.Ltime|log.Lmicroseconds)
	}

	opts = append(opts,
		peer.WithListenAddr(*addr),
		peer.WithStore(cs),
		peer.WithLocationIndex(li),
	)

	if debugLog != nil {
		opts = append(opts, peer.WithDebugLog(debugLog))
	}
	if *openAccess {
		opts = append(opts, peer.WithConnectionGrants(peer.OpenAccessGrants()))
		log.Printf("WARNING: --open-access is DEPRECATED in v7.74 (V7 Phase 2 §6.9a / §3.7) and will be REMOVED in v7.75. Migrate to a declared seed policy (peer.WithSeedPolicy / peer.WithSeedPolicyFromFile). The flag is the degenerate seed policy default → *.")
	}

	// Wire query extension: index maintainer + sync hook + handler.
	queryMaintainer := query.NewIndexMaintainer(cs)
	queryHandler := query.NewHandler(
		queryMaintainer.TypeIndex(),
		queryMaintainer.ReverseHashIndex(),
		queryMaintainer.PathLinkIndex(),
		cs,
	)

	// Wire system extensions: clock + inbox + continuation + subscription + query.
	clockH := clock.NewHandler()

	engine := subscription.NewEngine(cs, li, debugLog)
	engineCtx, cancelEngine := context.WithCancel(context.Background())

	// Wire history extension: recorder (sync hook) + handler.
	// Recorder needs localPeerID which isn't available yet — it will be set
	// after peer construction. We create a placeholder and wire it below.
	historyRecorder := history.NewRecorder(cs, "", debugLog)
	historyHandler := history.NewHandler(cs, historyRecorder)

	// Wire trie-root tracker (EXTENSION-TREE v3.8 §3.4.1a). Same lifecycle as
	// the history recorder: construct now, wire peer ID + location index after
	// peer construction, then Load() to scan tracking-configs and perform an
	// initial build for each enabled prefix.
	rootTracker := tree.NewRootTracker(cs, "", debugLog)

	// Wire auto-version emit consumer (EXTENSION-REVISION §6.1, position 7).
	// Hook order matters: must fire AFTER rootTracker (reads the settled tracked
	// root) and strictly BEFORE any async TreeEventSink (subscription at
	// position 8 observes settled head+version).
	autoVersioner := revision.NewAutoVersioner(cs, rootTracker, debugLog)

	// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4: when --publish-root is set,
	// mint a signed system/peer/published-root on every root-tracker write.
	// The publisher is constructed pre-peer.New so its OnTreeChange hook can
	// register via WithNamedSyncHook; the location-index + keypair land
	// post-construction via SetupAuthority. Without authority the hook
	// no-ops.
	var publisher *publishedroot.Publisher
	if *publishRoot {
		publisher = publishedroot.NewPublisher(cs, rootTracker, publishedroot.PrefixForLocalPeer, debugLog)
	}

	// Wire compute extension: engine (reactive mode) + handler.
	computeEngine := compute.NewEngine(cs, li, debugLog)
	computeH := compute.NewHandler(computeEngine)

	// Wire handlers handler — the system/handler register/unregister
	// extension. Authority (peer keypair + identity for grant signing)
	// is wired in via SetupAuthority after peer construction.
	handlersH := handlers.NewHandler()

	// Wire capability handler — V7 §6.2 request/delegate/revoke. Closes
	// the advertised-but-unregistered gap caught by Godot G1 / arch
	// ruling RULING-CAPABILITY-HANDLER-ADVERTISEMENT. Authority
	// wired post-construction via SetupAuthority (same pattern as
	// handlersH).
	capabilityH := extcapability.NewHandler()

	// Storage-substitute chain — orchestrator threads into content's miss-
	// resolver (STORAGE-SUBSTITUTE-SOURCES); a per-source-type handler is
	// registered separately (here: system/substitute/http for http-poll).
	// On a content miss, the orchestrator walks system/substitute-source
	// entries for the claimed source peer (set via WithClaimedSource on
	// ctx) and dispatches try-requests; successful fetches land via
	// content:ingest.
	//
	// Strict §2.4 posture: Ed25519SignatureVerifier rejects entries
	// lacking a valid signature by source_peer_id at the V7 §3.5 invariant
	// signature path. Skip reasons surface via ConsultResult.LastError so
	// validate-peer + cohort interop see "signature_invalid: …" instead
	// of an opaque NotFound. The operator-prompt-to-consume-anyway flow
	// (use-without-verification trust override) is flagged as an
	// architectural question on the cross-impl handoff — not wired here.
	//
	// Cap gate: tightened per RULING-NAMED-CAPABILITY-MAPPING
	// to (handler=system/substitute/sources, op=consult) + fail closed.
	substituteOrchestrator := storagesubstitutesources.New(
		storagesubstitutesources.WithSignatureVerifier(
			storagesubstitutesources.NewSignatureVerifier(),
		),
	)

	// Wire the identity stack per EXTENSION-IDENTITY v3.3 substrate split:
	// EXTENSION-ATTESTATION (signed-graph substrate) + EXTENSION-QUORUM
	// (K-of-N node primitive) + EXTENSION-IDENTITY (convention layer).
	//
	// Each handler exposes a sync hook:
	//   - attestation/index-maintainer: maintains attesting/attested/kind/
	//     supersedes indexes per §5.7 / §9.1 invariants I1-I5.
	//   - quorum/cache-invalidator: invalidates the current_signer_set
	//     cache when validated quorum-update / quorum-publish attestations
	//     arrive per §4.2.1 (TV-QF12-QF15).
	//   - identity/process-attestation: runs IdentityVerifyCert against
	//     identity-context attestations entering the local tree at
	//     system/identity/{internal,public,relationships/*}/cert/...;
	//     fail-closed unbinds the path on validation failure per §6.8.
	//
	// Identity's first configure goes through identity.Startup (L0 path,
	// peer-owner authority) before any cross-peer calls. Until then,
	// identity ops requiring peer-config return 503 authority_not_ready.
	attH := attestation.NewHandler()
	quorumH := quorum.NewHandler()
	identityH := identity.NewHandler()
	roleH := role.NewHandler()

	// EXTENSION-REGISTRY v1.0 — meta-resolver + local-name backend. The
	// meta-resolver dispatches `:resolve` per §4.1 (pin → dispatch filter
	// → chain → fail-closed); the local-name backend implements the four §6.5
	// ops + Resolve. localnameH.SetupStore + registryH.RegisterBackend run
	// post-peer-construction.
	localnameH := localname.NewHandler()
	registryH := registry.NewHandler()
	registryH.SetLogger(registry.NewLogger(0, nil))

	// EXTENSION-REGISTRY §6a.9 — peer-issued live-registration handler.
	// Default-off: when --issuer-policy-mode is empty, the Issuer is not
	// wired and the registry runs curated-only (§6a.8 — operator signs by
	// hand via registry-issue-binding). When the flag is set, the handler
	// is registered now (pre-Build) and its keypair is installed
	// post-Build via SetupAuthority — same lifecycle as handlers /
	// capability / role.
	var peerIssuedIssuer *peerissued.Issuer
	var peerIssuedSeedEntries []peer.SeedPolicyEntry
	if *issuerPolicyMode != "" {
		policy, err := buildIssuerPolicy(*issuerPolicyMode, *issuerPolicyAllowlist, *issuerPolicyNameConstraints, *issuerPolicyDefaultTTL)
		if err != nil {
			log.Fatalf("--issuer-policy-mode: %v", err)
		}
		peerIssuedIssuer = peerissued.NewIssuerForSetup(peerissued.WithFallbackPolicy(policy))

		// §6a.9 closing paragraph: "register-request is the external surface,
		// gated by registry-request-binding (open → granted broadly;
		// allowlist → narrow)." Translate the policy mode into seed-policy
		// entries so the handler is actually reachable from outside.
		grants := peerissued.RequestBindingSeedGrants()
		switch policy.Mode {
		case types.IssuerPolicyModeOpen, types.IssuerPolicyModeManual:
			entry := peer.SeedPolicyDefault(grants)
			entry.Notes = "§6a.9 issuer-policy=" + policy.Mode + " — broad register-request grant"
			peerIssuedSeedEntries = append(peerIssuedSeedEntries, entry)
		case types.IssuerPolicyModeAllowlist:
			for _, pidStr := range policy.Allowlist {
				entry := peer.SeedPolicyForPeerID(crypto.PeerID(pidStr), grants)
				entry.Notes = "§6a.9 issuer-policy=allowlist — narrow register-request grant"
				peerIssuedSeedEntries = append(peerIssuedSeedEntries, entry)
			}
		}
	}

	// EXTENSION-DISCOVERY v1.0 — substrate + mDNS v1 backend. SetupStore
	// (the OOB binder over store + location-index) + backend wiring run
	// post-peer-construction so the binder sees the real store. The v1
	// floor (§4.1) "local peer can scan + announce on its own network"
	// is satisfied by the v7.74 §6.9a self-owner seed-policy entry
	// (which grants `*` over the local namespace) — no extra default
	// grant is needed beyond that.
	discoveryH := discovery.NewHandler()

	// EXTENSION-RELAY v1.0 — substrate (Mode F + Mode S). SetupStore
	// (with the local Base58 peer-id) runs post-peer-construction. The
	// OutboundDispatcher seam is left at its default (noop returning
	// ErrDestinationUnreachable) — this is the conservative Mode-S-only
	// posture per §10.1 ("a deployment MAY enable any subset of modes");
	// every :forward goes straight to §6.2.1 fallback until a real
	// dispatcher is wired. The §5.5 self-poll default grant is per-peer
	// install via relay.SelfPollSeedGrants(peerID); the v7.74 §6.9a
	// self-owner seed-policy entry already grants the LOCAL peer `*` on
	// the local namespace, so the local peer's own :poll works out-of-
	// box; broader inter-peer self-poll grants are operator-deployed.
	relayH := relay.NewHandler()

	opts = append(opts,
		peer.WithRootTracker(rootTracker),
		peer.WithContextField(store.ContextFieldRegistration{
			Name:     "clock",
			TypeName: types.TypeClockState,
			Owner:    "system/clock",
		}),
		peer.WithNamedSyncHook("query/index-maintainer", queryMaintainer.OnTreeChange),
		peer.WithNamedSyncHook("clock/advancement", clockH.OnTreeChange),
		peer.WithNamedSyncHook("history/recorder", historyRecorder.OnTreeChange),
		peer.WithNamedSyncHook("tree/root-tracker", rootTracker.OnTreeChange),
		peer.WithNamedSyncHook("revision/auto-version", autoVersioner.OnTreeChange),
		peer.WithNamedSyncHook("compute/reactive", computeEngine.OnTreeChange),
		peer.WithNamedSyncHook("subscription/notification", engine.OnTreeChange),
		peer.WithNamedSyncHook("attestation/index-maintainer", attH.OnTreeChange),
		peer.WithNamedSyncHook("quorum/cache-invalidator", quorumH.OnTreeChange),
		peer.WithNamedSyncHook("identity/process-attestation", identityH.OnTreeChange),
		peer.WithNamedSyncHook("role/exclusion-sweep", roleH.OnTreeChange),
		peer.WithHandler("system/query", queryHandler),
		peer.WithHandler("system/history", historyHandler),
		peer.WithHandler("system/clock", clockH),
		peer.WithHandler("system/inbox", func() *inbox.Handler {
			h := inbox.NewHandler()
			if debugLog != nil {
				h.SetDebugLog(debugLog)
			}
			return h
		}()),
		peer.WithHandler("system/continuation", continuation.NewHandler()),
		peer.WithHandler("system/subscription", subscription.NewHandler(engine)),
		peer.WithHandler("system/revision", func() *revision.Handler {
			h := revision.NewHandler()
			// Wire AV reference so version-transcription ops (merge,
			// fast-forward, checkout, cherry-pick, revert) acquire the
			// per-prefix mutex during binding-apply, preventing the
			// phantom-deletion-marker race per F10 part 7.
			h.SetAutoVersioner(autoVersioner)
			return h
		}()),
		peer.WithHandler("system/compute", computeH),
		peer.WithHandler("system/content", content.NewHandler(
			content.WithMissResolver(substituteOrchestrator),
		)),
		peer.WithHandler(storagesubstitutehttp.HandlerPattern,
			storagesubstitutehttp.NewHandler(
				storagesubstitutehttp.WithAllowHTTP(*substituteAllowHTTP),
			)),
		peer.WithHandler("system/handler", handlersH),
		peer.WithHandler("system/capability", capabilityH),
		peer.WithHandler("system/attestation", attH),
		peer.WithHandler("system/quorum", quorumH),
		peer.WithHandler("system/identity", identityH),
		peer.WithHandler("system/role", roleH),
		// EXTENSION-REGISTRY v1.0 — meta-resolver + local-name backend.
		peer.WithHandler(registry.HandlerPattern, registryH),
		peer.WithHandler(localname.HandlerPattern, localnameH),
		// EXTENSION-DISCOVERY v1.0 — substrate (mDNS backend registered
		// post-construction).
		peer.WithHandler(discovery.HandlerPattern, discoveryH),
		// EXTENSION-REGISTRY §6a.9 — peer-issued live-registration handler.
		// Default-off; only registered when --issuer-policy-mode is set.
		// SetupAuthority(p.Keypair()) wires the signing key post-build.
	)
	if peerIssuedIssuer != nil {
		opts = append(opts, peer.WithHandler(peerissued.IssuerHandlerPattern, peerIssuedIssuer))
		if len(peerIssuedSeedEntries) > 0 {
			opts = append(opts, peer.WithSeedPolicy(peerIssuedSeedEntries))
		}
	}
	opts = append(opts,
		// EXTENSION-RELAY v1.0 — substrate (Mode F + Mode S). SetupStore
		// called post-construction; noop OutboundDispatcher (default) so
		// every :forward exercises §6.2.1 fallback.
		peer.WithHandler(relay.HandlerPattern, relayH),
		// EXTENSION-TYPE v1.1 — type handler + standard constraint handler.
		peer.WithHandler("system/type", typeext.NewHandler()),
		peer.WithHandler("system/type/constraint", constrainth.NewHandler()),
		peer.WithCloseFunc(cancelEngine),
	)

	// Publisher hook fires AFTER rootTracker (RT writes the new trie root,
	// then the publisher signs+binds the system/peer/published-root pointing
	// at that root). Order is position-7-or-later in the sync-hook cascade.
	if publisher != nil {
		opts = append(opts, peer.WithNamedSyncHook("publishedroot/publisher", publisher.OnTreeChange))
	}

	// GUIDE-CONFORMANCE §7a conformance test handlers — runtime opt-in.
	// OFF by default; --validate flips them on so validate-peer can
	// black-box probe §6.13(a) resolve→dispatch + §6.13(b)/§6.11 outbound
	// seam over the wire. dispatch-outbound originates outbound EXECUTE,
	// which MUST NOT be a standing dialer in production — hence
	// off-by-default. A default peer 404s system/validate/echo so an
	// absence-is-honest SKIP fires on the validator side.
	if *validate {
		opts = append(opts,
			peer.WithHandler(conformance.PatternEcho, conformance.NewEchoHandler()),
			peer.WithHandler(conformance.PatternDispatchOutbound, conformance.NewDispatchOutboundHandler()),
		)
		log.Printf("Conformance handlers enabled (--validate): %s + %s (§7a opt-in)",
			conformance.PatternEcho, conformance.PatternDispatchOutbound)
	}
	if sqliteStore != nil {
		opts = append(opts, peer.WithCloseFunc(func() {
			if err := sqliteStore.Close(); err != nil {
				log.Printf("WARNING: sqlite close: %v", err)
			}
		}))
	}

	// Wire local files handler unconditionally so persisted root configs
	// can rehydrate via filesH.Load() on restart per GUIDE-RESTART-AND-
	// PERSISTENCE §3 (A.6). The --files flag adds an additional explicit
	// root after Load runs.
	filesH := localfiles.NewHandler(debugLog)
	filesEvents := make(chan store.TreeChangeEvent, 256)
	opts = append(opts,
		peer.WithHandler("local/files", filesH),
		peer.WithTreeEventSink(filesEvents),
		peer.WithCloseFunc(func() { _ = filesH.Close() }),
	)

	p, err := peer.New(opts...)
	if err != nil {
		log.Fatalf("create peer: %v", err)
	}

	// Wire clock advancement after peer construction (needs store, identity).
	clockH.SetupAdvancement(
		p.Store(), p.LocationIndex(), string(p.PeerID()), p.Identity().ContentHash, debugLog)

	// Wire compute engine after peer construction (needs peer ID + notifying index).
	computeEngine.SetLocalPeerID(string(p.PeerID()))
	computeEngine.SetLocationIndex(p.LocationIndex())
	computeEngine.RebuildDependencyIndex()

	// Wire entity-native handler dispatch (V7 §3.7, §6.6).
	// When dispatch resolves a handler with expression_path, it evaluates the
	// compute expression instead of calling compiled code.
	p.Dispatcher().EvaluateExpression = computeH.EvaluateAtPath

	// Wire handlers handler authority (V7 §6.2 / spec-gap-handler-grant-authority §S1).
	// register signs each emitted grant with the peer's keypair so dispatch-time
	// validation per V7 §6.8 can verify granter chain to local peer.
	handlersH.SetupAuthority(p.Keypair(), p.Identity())
	capabilityH.SetupAuthority(p.Keypair(), p.Identity())

	// Wire the identity stack (attestation + quorum + identity) per
	// EXTENSION-IDENTITY v3.3.
	attH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID())
	quorumH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID())
	quorumH.SetupAttestation(attH)

	// Identity handler: authority for cap issuance + substrate dependencies.
	// SetupSubstrate also registers the identity-resolved signer-resolution
	// mode against the quorum handler's resolver hook per §6.1.
	identityH.SetupAuthority(p.Keypair(), p.Identity())
	identityH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID())
	if err := identityH.SetupSubstrate(attH, quorumH); err != nil {
		log.Fatalf("identity SetupSubstrate failed: %v", err)
	}

	// Wire role handler authority + store. Required before any role op
	// (assign / re-derive / delegate / define) can issue role-derived
	// caps. Per EXTENSION-ROLE v1.5 §4 / §5.1.
	roleH.SetupAuthority(p.Keypair(), p.Identity())
	roleH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID())

	// EXTENSION-REGISTRY: wire the local-name backend's store + connect it
	// to the meta-resolver as the `local-name` chain entry. The meta-resolver
	// looks up backends by (kind, id); we register as id="" so a
	// resolver-config entry with BackendID empty or "local" matches.
	localnameH.SetupStore(p.Store(), p.LocationIndex(), p.PeerID(), nil)
	registryH.RegisterBackend(localnameH)

	// PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2.1 — register one
	// peerissued.Backend per --peer-issued-registry spec. The Backend is
	// trust logic; the http-poll Reader is one transport binding (the v1
	// demo wire, SUBSTITUTE §7 Mode S). A future RemoteExecute reader
	// (live socket) would slot in here unchanged. Default-off: when the
	// flag is empty, nothing is registered and the chain has no
	// peer-issued entry to consult.
	if *peerIssuedRegistry != "" {
		if err := wirePeerIssuedRegistries(*peerIssuedRegistry, *substituteAllowHTTP, registryH); err != nil {
			log.Fatalf("--peer-issued-registry: %v", err)
		}
	}

	// EXTENSION-REGISTRY §6a.9 — install the registry's signing keypair on
	// the Issuer registered above. The Issuer's keypair is THIS peer's
	// keypair; the running registry IS the peer, so a register-request
	// landing here is signed by the same key the receiver-side backend
	// verifies against.
	if peerIssuedIssuer != nil {
		if err := peerIssuedIssuer.SetupAuthority(p.Keypair()); err != nil {
			log.Fatalf("peerissued.SetupAuthority: %v", err)
		}
		log.Printf("EXTENSION-REGISTRY §6a.9: peer-issued live registration ACTIVE (mode=%s)", *issuerPolicyMode)
	}

	// EXTENSION-DISCOVERY: wire the OOB binder over the peer's store +
	// location-index, then register the mDNS v1 backend. The mDNS
	// ProfileResolver reads the announce port off the runtime TCP /
	// HTTP-live addrs (parsed from the listen-addr flags so we don't
	// need to round-trip through the type-registry to resolve a port).
	// If --discovery-announce is set, we call :announce against the
	// resolved profile_ref once the peer is ready (after the
	// initial-handshake wiring below). Failure here is non-fatal — the
	// mDNS layer logs the issue; user can still :scan via dispatch.
	discoveryH.SetupStore(discovery.NewPeerBinder(p.Store(), p.LocationIndex()))
	relayH.SetupStore(string(p.PeerID()))
	// EXTENSION-RELAY §3.1.1 production wiring: install the OutboundDispatcher
	// over the peer's connection pool + the §3.5 InboxRelayResolver backed
	// by the local tree (V7 §5.2 signature-verifying — forged-redirection
	// defense). With these installed:
	//   - terminal-hop :forward dispatches the inner EXECUTE to the destination
	//     over the established outbound transport (RemoteExecute);
	//   - intermediate-hop :forward forwards system/relay:forward to next_hop
	//     with the inner entity riding the included set;
	//   - §6.2.1 fallback still fires when the destination has no live session
	//     and no resolvable transport profile (ErrDestinationUnreachable).
	relayH.SetDispatcher(relaypeer.New(p))
	// §3.5 resolver: when --inbox-relay-registry names one or more registry
	// peers, consult them in order (remote tree:get) BEFORE falling back to
	// the local-tree resolver. Empty list → local-tree only (the previous
	// behavior). The remote resolver applies the same V7 §5.2 sig-verify
	// + forged-redirection defense as the local-tree resolver.
	registries := splitCSV(*inboxRelayRegistry)
	if len(registries) == 0 {
		relayH.SetInboxRelayResolver(relaypeer.NewTreeInboxRelayResolver(p))
	} else {
		relayH.SetInboxRelayResolver(relaypeer.Chain(
			relaypeer.NewRemoteTreeInboxRelayResolver(p, registries...),
			relaypeer.NewTreeInboxRelayResolver(p),
		))
	}
	mdnsResolver := makeMDNSProfileResolver(*addr, *httpAddr)
	mdnsBackend := discoverymdns.New(string(p.PeerID()), mdnsResolver)
	discoveryH.RegisterBackend(mdnsBackend)

	// Wire AUTHENTICATE-time role-aware grant resolver (EXTENSION-ROLE
	// §4.7 / RA-6 — recognize-on-attestation policy mode). The resolver
	// composes:
	//   1. static-grants resolver (per-peer-ID overrides from grants.toml,
	//      already installed via WithGrantResolver if a grants.toml was
	//      loaded — pulled out via SetGrantResolver(nil) below to chain),
	//   2. role-policy resolver (consults system/role/initial-grant-policy
	//      and synthesizes default_role grants for recognized peers).
	//
	// Order: static FIRST so explicit per-peer overrides win over policy.
	// Unconfigured peers (no static override) fall through to policy
	// dispatch (deny / allow / recognize-on-attestation).
	policyDeps := role.PolicyResolverDeps{
		Store:          p.Store(),
		Locations:      p.LocationIndex(),
		AttestationIdx: attH.Index(),
	}
	if debugLog != nil {
		policyDeps.DebugLog = func(format string, args ...any) { debugLog.Printf(format, args...) }
	}
	policyResolver := role.NewPolicyGrantResolver(policyDeps)
	if staticResolver != nil {
		// Compose static (already wired pre-construction) + policy.
		// NewPolicyGrantResolver returns role.GrantResolverFunc which is
		// a structural match for protocol.GrantResolver.
		staticAdapter := role.GrantResolverFunc(staticResolver)
		composed := role.ChainGrantResolvers(staticAdapter, policyResolver)
		p.SetGrantResolver(protocol.GrantResolver(composed))
	} else {
		p.SetGrantResolver(protocol.GrantResolver(policyResolver))
	}

	// Wire identity binding checker (EXTENSION-IDENTITY §12.3 / IA23).
	// PolicyAllowAnyAttestedAgent accepts caps whose grantee is the attested
	// peer of any live identity-cert (function=agent or function=controller).
	// V7-only peers without any identity-certs still work because configure
	// must run before the binding-check has anything to check; until then,
	// dispatched ops requiring binding lookup fail closed.
	bindingChecker := identity.NewBindingChecker(
		p.Store(), p.LocationIndex(), attH, identity.PolicyAllowAnyAttestedAgent)
	p.Dispatcher().IdentityBindingChecker = bindingChecker

	// Wire dispatcher's local identity hash so it can verify handler grants
	// (spec-gap-handler-grant-authority §S2).
	p.Dispatcher().LocalIdentityHash = p.Identity().ContentHash

	// Wire subscription engine after peer construction.
	engine.SetLocationIndex(p.LocationIndex())
	engine.Load()
	engine.Deliver = subscription.MakeDeliveryFunc(
		p.Keypair(), p.Identity(), p.Store(), p.LocationIndex(), p.Dispatcher(),
	)

	// Start the subscription engine delivery loop (async network delivery).
	engine.StartDelivery(engineCtx)

	// Wire history recorder after peer construction (needs peer ID + location index).
	historyRecorder.SetLocalPeerID(string(p.PeerID()), p.Identity().ContentHash)
	historyRecorder.SetLocationIndex(p.LocationIndex())
	if *historyFlag != "" {
		pattern, maxDepth, err := parseHistoryFlag(*historyFlag)
		if err != nil {
			log.Fatalf("parse --history flag: %v", err)
		}
		cfg := types.HistoryConfigData{
			Pattern: pattern,
			Enabled: true,
		}
		if maxDepth > 0 {
			cfg.MaxDepth = &maxDepth
		}
		cfgEntity, err := cfg.ToEntity()
		if err != nil {
			log.Fatalf("create history config entity: %v", err)
		}
		cfgHash, err := p.Store().Put(cfgEntity)
		if err != nil {
			log.Fatalf("store history config entity: %v", err)
		}
		p.LocationIndex().Set("system/history/config/cli", cfgHash)
		log.Printf("History: enabled for pattern %q", pattern)
	}
	historyRecorder.Load()

	// Wire root tracker after peer construction.
	rootTracker.SetLocalPeerID(string(p.PeerID()), p.Identity().ContentHash)
	rootTracker.SetLocationIndex(p.LocationIndex())
	rootTracker.Load()

	// Wire auto-versioner after peer construction. Must follow rootTracker.Load
	// so that cached tracked roots are available to early firings.
	autoVersioner.SetLocalPeerID(string(p.PeerID()), p.Identity().ContentHash)
	autoVersioner.SetLocationIndex(p.LocationIndex())
	autoVersioner.Load()

	// Rebuild extension in-memory indexes from persisted tree state.
	// Required for persistent storage backends (sqlite): OnTreeChange only
	// fires for runtime mutations, and seed-time Set is idempotent-suppressed
	// when the binding is unchanged, so indexes seeded only via OnTreeChange
	// would otherwise start empty after cold restart. Harmless on memory
	// backends where the tree is empty at start anyway.
	// See DESIGN-SQLITE-PERSISTENCE.md §4.3.
	attH.Load()
	queryMaintainer.Rebuild(p.LocationIndex())

	// Wire published-root publisher authority AFTER rootTracker has its
	// location-index set + has loaded existing configs. SetupAuthority
	// installs a system/tree/tracking-config for the publisher's prefix so
	// the RootTracker starts maintaining a root; the tree-change cascade
	// from that write reaches the publisher's hook → initial publish. The
	// MANIFEST_GET route then serves the bound entity.
	if publisher != nil {
		if err := publisher.SetupAuthority(p.LocationIndex(), p.Keypair(), p.Identity(), true); err != nil {
			log.Fatalf("publishedroot SetupAuthority failed: %v", err)
		}
	}

	// Wire local files handler after peer construction (needs store, location index).
	// StartReverseWrite is unconditional — both restart-rehydrated roots
	// (via Load) and explicit --files roots share the same reverse-write
	// pump that bridges tree mutations back to the filesystem.
	filesH.StartReverseWrite(engineCtx, filesEvents, p.Store(), p.LocationIndex(), string(p.PeerID()))
	// Rehydrate any persisted root configs (system/config/local/files/*)
	// and restart their fsnotify watchers. No-op on a fresh peer; idempotent
	// on re-runs. GUIDE-RESTART-AND-PERSISTENCE §3 / A.6.
	if err := filesH.Load(engineCtx, p.Store(), p.LocationIndex(), p.Identity().ContentHash); err != nil {
		log.Printf("WARNING: local-files Load failed: %v", err)
	}
	if *filesRoot != "" {
		rootName, rootPath, rootPrefix, err := parseFilesFlag(*filesRoot)
		if err != nil {
			log.Fatalf("parse --files flag: %v", err)
		}
		cfg := localfiles.RootConfigData{
			Prefix:             rootPrefix,
			FilesystemRoot:     rootPath,
			PublishDescriptors: *publishDescriptors,
		}
		if err := filesH.AddRoot(rootName, cfg, p.Store(), p.LocationIndex()); err != nil {
			log.Fatalf("add files root: %v", err)
		}
		if err := filesH.StartWatching(engineCtx, rootName, p.Store(), p.LocationIndex(), p.Identity().ContentHash); err != nil {
			log.Printf("WARNING: failed to start file watcher: %v", err)
		} else {
			log.Printf("File watcher started for %s", rootName)
		}
		log.Printf("Local files: %s → %s (tree prefix: %s)", rootName, rootPath, rootPrefix)
	}

	log.Printf("Peer ID: %s", p.PeerID())
	log.Printf("Listening on %s", *addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, shutting down...", sig)
		cancel()
		p.Close()
	}()

	ready := make(chan struct{})
	go func() {
		<-ready
		log.Printf("Ready to accept connections")
		if *readyFile != "" {
			info := fmt.Sprintf(`{"addr":"%s","peer_id":"%s"}`, p.Addr(), p.PeerID())
			if err := os.WriteFile(*readyFile, []byte(info), 0644); err != nil {
				log.Printf("WARNING: failed to write ready file: %v", err)
			}
		}
		// EXTENSION-NETWORK §6.5.1: self-publish reachable transport
		// profiles at system/peer/transport/{own_identity_hex}/ so the
		// transport_family.r3_profile_enum_membership probe (and remote
		// dispatchers per Amendment 8) can read this peer's profile
		// surface without the validator stuffing a synthetic fixture.
		// Profile id "primary" carries the TCP listener; "primary-http"
		// carries the http-live listener when --http-addr is configured.
		publishSelfTransportProfiles(p, *httpAddr)
		// EXTENSION-DISCOVERY: kick off mDNS announce now that the
		// listeners are up. Non-fatal — multicast may be unavailable on
		// the host network; user can still :scan / :announce explicitly.
		if *discoveryAnnounce != "" {
			if err := mdnsBackend.Announce(ctx, *discoveryAnnounce); err != nil {
				log.Printf("WARNING: discovery announce on %q failed: %v", *discoveryAnnounce, err)
			} else {
				log.Printf("Discovery: announced profile %q via mDNS (%s)",
					*discoveryAnnounce, discoverymdns.ServiceType)
			}
		}
	}()

	// Chunk D + E: optional HTTP listeners alongside TCP.
	//
	// Two postures (impl plan §2):
	//   1. Isolated port — live (POST) and poll (GET) on separate
	//      listeners. Clean abstraction; CDN-friendly.
	//   2. Same listener — POST live + GET poll route-demux'd on one
	//      port via ComposedHandler (G2 bless).
	//
	// pollEnabled was validated above; pollScope below is non-nil iff
	// Chunk E serving-mode is on.
	var pollScope httplive.ScopePredicate
	if pollEnabled {
		pollScope = makeChunkEScopePredicate(p, *serveNamespace, *serveWholeStore, *serveClosureRoot)
		switch {
		case *serveClosureRoot:
			log.Printf("Serving mode: closure-of-signed-root (NETWORK §6.5.6 Amendment 10) — content gated by transitive trie-node closure of system/peer/published-root")
		case *serveWholeStore:
			log.Printf("Serving mode: whole-store (debug)")
		case *serveNamespace != "":
			log.Printf("Serving mode: namespace %q", *serveNamespace)
		}
		if *serveWholeStore {
			log.Printf("WARNING: --serve-scope-whole-store enabled. " +
				"Any hash held in this peer's content-store is publicly fetchable. " +
				"Operator is responsible for T2/T3 mitigation per arch ruling §1.3.")
		}
		if *serveClosureRoot && !*publishRoot {
			log.Printf("WARNING: --serve-closure-root set without --publish-root. " +
				"The closure scope derives from the local published-root head; without " +
				"--publish-root no head exists and the served set is empty until one is published.")
		}
	}

	if *httpAddr != "" {
		httpSrv := httplive.NewServer(p.Dispatcher())

		if *httpPollMountOnLive {
			// Posture 2 — POST live + GET poll on the same listener.
			pollH := httplive.NewPollHandler(*httpPollPrefix, p.Store(), p.LocationIndex(), pollScope, p.PeerID())
			if publisher != nil {
				pollH.ManifestProvider = func() *entity.Entity {
					e, ok := publisher.Current()
					if !ok {
						return nil
					}
					return e
				}
			}
			composed := &httplive.ComposedHandler{
				LiveServer: httpSrv,
				LivePath:   *httpPath,
				Poll:       pollH,
			}
			log.Printf("HTTP-live listener on %s (POST %s | GET %s/...)",
				*httpAddr, *httpPath, *httpPollPrefix)
			go runHTTPListener(ctx, *httpAddr, composed, "http-live+poll")
		} else {
			log.Printf("HTTP-live listener on %s%s (POST EXECUTE)", *httpAddr, *httpPath)
			go func() {
				if err := httpSrv.ListenAndServe(ctx, *httpAddr, *httpPath); err != nil && ctx.Err() == nil {
					log.Printf("WARNING: http-live listener: %v", err)
				}
			}()
		}
	}

	if *wsAddr != "" {
		log.Printf("WebSocket-live listener on %s%s (NETWORK §6.5.2b)", *wsAddr, *wsPath)
		go func() {
			if err := p.ListenWebSocketReady(ctx, *wsAddr, *wsPath, nil); err != nil && ctx.Err() == nil {
				log.Printf("WARNING: ws-live listener: %v", err)
			}
		}()
	}

	if *httpPollAddr != "" {
		// Posture 1 — isolated port for serving-mode GET routes.
		pollH := httplive.NewPollHandler("", p.Store(), p.LocationIndex(), pollScope, p.PeerID())
		if publisher != nil {
			pollH.ManifestProvider = func() *entity.Entity {
				e, ok := publisher.Current()
				if !ok {
					return nil
				}
				return e
			}
		}
		log.Printf("HTTP-poll listener on %s (Amendment 5 routes: /content/{hex}, /manifest, /{peer_id}/{path}.bin|.list, /peers.list)", *httpPollAddr)
		go runHTTPListener(ctx, *httpPollAddr, pollH, "http-poll")
	}

	if err := p.ListenReady(ctx, ready); err != nil && ctx.Err() == nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("Shut down complete")
}

// loadNamedPeer loads persistent identity and grants from ~/.entity/peers/{name}/.
// Returns the per-peer static grant resolver separately (rather than baked into
// opts via WithGrantResolver) so the caller can chain it with the role-extension's
// policy resolver post-construction; see the SetGrantResolver wiring in main().
func loadNamedPeer(name string) (opts []peer.Option, listenAddr string, staticResolver protocol.GrantResolver) {
	// Load keypair.
	kp, err := crypto.LoadPeerKeypair(name)
	if err != nil {
		log.Fatalf("load peer keypair %q: %v", name, err)
	}
	opts = append(opts, peer.WithIdentity(kp))
	log.Printf("Loaded identity for peer %q: %s", name, kp.PeerID())

	// Load config.toml (optional — only for listen_addr).
	cfg, err := config.LoadPeerConfig(name)
	if err != nil {
		log.Printf("No config.toml for peer %q (using defaults): %v", name, err)
	} else {
		listenAddr = cfg.Peer.ListenAddr
	}

	// Load grants.toml (optional — enables identity-aware access control).
	gf, err := config.LoadGrants(name)
	if err != nil {
		log.Printf("No grants.toml for peer %q (using default grants): %v", name, err)
	} else {
		staticResolver = gf.BuildGrantResolver()
		log.Printf("Grant groups: %s", gf.Summary())
	}

	return opts, listenAddr, staticResolver
}

// parseFilesFlag parses the --files flag value in "name:/path:tree/prefix/" format.
func parseFilesFlag(value string) (name, fsPath, prefix string, err error) {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("expected format name:/path:tree/prefix/, got %q", value)
	}
	return parts[0], parts[1], parts[2], nil
}

// validateChunkEFlags enforces the impl plan §3 flag combination rules.
// Returns (pollEnabled, error). Serving-mode is OFF when both
// --http-poll-addr and --http-poll-mount-on-live are unset.
func validateChunkEFlags(httpAddr, httpPollAddr string, httpPollMountOnLive bool, serveNamespace string, serveWholeStore, serveClosureRoot bool) (bool, error) {
	pollAddrSet := httpPollAddr != ""
	mountSet := httpPollMountOnLive
	scopeSet := (serveNamespace != "") || serveWholeStore || serveClosureRoot

	// (1) Serving disabled unless one of poll-addr / mount-on-live.
	if !pollAddrSet && !mountSet {
		if scopeSet {
			return false, fmt.Errorf("--serve-namespace / --serve-scope-whole-store / --serve-closure-root set without --http-poll-addr or --http-poll-mount-on-live")
		}
		return false, nil
	}
	// (2) Mutually exclusive listener selection.
	if pollAddrSet && mountSet {
		return false, fmt.Errorf("--http-poll-addr and --http-poll-mount-on-live are mutually exclusive (pick one posture per impl plan §2)")
	}
	// (3) mount-on-live requires --http-addr.
	if mountSet && httpAddr == "" {
		return false, fmt.Errorf("--http-poll-mount-on-live requires --http-addr (live listener) to be set")
	}
	// (4) Exactly one scope source.
	scopeCount := 0
	if serveNamespace != "" {
		scopeCount++
	}
	if serveWholeStore {
		scopeCount++
	}
	if serveClosureRoot {
		scopeCount++
	}
	if scopeCount > 1 {
		return false, fmt.Errorf("--serve-namespace, --serve-scope-whole-store, and --serve-closure-root are mutually exclusive")
	}
	if scopeCount == 0 {
		return false, fmt.Errorf("serving-mode requires a scope: --serve-namespace NAMESPACE, --serve-scope-whole-store, or --serve-closure-root")
	}
	return true, nil
}

// makeChunkEScopePredicate constructs the appropriate ScopePredicate
// for the configured flags. Caller guarantees validateChunkEFlags
// has returned pollEnabled=true.
func makeChunkEScopePredicate(p *peer.Peer, namespace string, wholeStore, closureRoot bool) httplive.ScopePredicate {
	if wholeStore {
		return httplive.WholeStoreScope{}
	}
	if closureRoot {
		return &httplive.ClosureScope{
			Store:       p.Store(),
			Index:       p.LocationIndex(),
			LocalPeerID: string(p.PeerID()),
		}
	}
	return httplive.NamespaceScope{
		Index:     p.LocationIndex(),
		Namespace: namespace,
	}
}

// runHTTPListener spins up an http.Server on addr serving handler.
// Shuts down cleanly on ctx cancellation. Used for both Posture 1
// isolated poll listener and Posture 2 composed listener.
func runHTTPListener(ctx context.Context, addr string, handler http.Handler, label string) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			log.Printf("WARNING: %s listener: %v", label, err)
		}
	}
}

// makeMDNSProfileResolver builds a discoverymdns.ProfileResolver that
// maps profile_ref strings to (port, transport-protocol-names) for the
// mDNS announce. v1 supports two well-known refs derived from runtime
// flags: "tcp" → the --addr listener; "http-poll" → the --http-addr
// listener (when present). Unknown refs error.
//
// This keeps the announce path independent of EXTENSION-NETWORK profile
// resolution at peer-startup time; once the peer's persistence has its
// own system/peer/transport/{peer}/{profile-id} bindings, a future
// resolver can read those directly.
func makeMDNSProfileResolver(tcpAddr, httpAddr string) discoverymdns.ProfileResolver {
	return func(profileRef string) (int, []string, error) {
		switch profileRef {
		case "tcp":
			port, err := portFromAddr(tcpAddr)
			if err != nil {
				return 0, nil, fmt.Errorf("mdns profile tcp: %w", err)
			}
			return port, []string{"tcp"}, nil
		case "http-poll":
			if httpAddr == "" {
				return 0, nil, fmt.Errorf("mdns profile http-poll: --http-addr not configured")
			}
			port, err := portFromAddr(httpAddr)
			if err != nil {
				return 0, nil, fmt.Errorf("mdns profile http-poll: %w", err)
			}
			return port, []string{"http-poll"}, nil
		default:
			return 0, nil, fmt.Errorf("mdns: unknown profile_ref %q (v1 backend supports: tcp, http-poll)", profileRef)
		}
	}
}

// portFromAddr extracts the port from a "host:port" or ":port" listen-
// address string.
func portFromAddr(addr string) (int, error) {
	if addr == "" {
		return 0, fmt.Errorf("empty addr")
	}
	idx := strings.LastIndexByte(addr, ':')
	if idx < 0 {
		return 0, fmt.Errorf("addr %q missing ':port'", addr)
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0, fmt.Errorf("addr %q port parse: %w", addr, err)
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("addr %q port out of range: %d", addr, p)
	}
	return p, nil
}

// parseHistoryFlag parses the --history flag value in "pattern[:max_depth]" format.
func parseHistoryFlag(value string) (pattern string, maxDepth uint64, err error) {
	parts := strings.SplitN(value, ":", 2)
	pattern = parts[0]
	if pattern == "" {
		return "", 0, fmt.Errorf("empty history pattern")
	}
	if pattern == "**" {
		pattern = "*"
	}
	if len(parts) == 2 {
		maxDepth, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return "", 0, fmt.Errorf("invalid max_depth %q: %w", parts[1], err)
		}
	}
	return pattern, maxDepth, nil
}

// publishSelfTransportProfiles writes the local peer's reachable transport
// profile entries into its own tree under
// system/peer/transport/{own_identity_hex}/{profile-id}. The TCP profile
// publishes whenever the peer is listening (always true in the binary's
// runtime path); the HTTP profile publishes when --http-addr is configured.
//
// Best-effort: errors are logged at WARNING and do not abort startup. The
// transport_family.r3_profile_enum_membership probe + remote dispatchers
// per EXTENSION-NETWORK Amendment 8 read these entries; cohort parity is
// what the arch Bucket A action requested.
func publishSelfTransportProfiles(p *peer.Peer, httpAddr string) {
	ownHash, err := types.ComputePeerIdentityHashFromPeerID(p.PeerID())
	if err != nil {
		log.Printf("WARNING: self-publish transport profile: identity hash: %v", err)
		return
	}
	prefix := "system/peer/transport/" + types.PeerIdentityHashHex(ownHash) + "/"

	if a := p.Addr(); a != nil {
		ent := selfTCPProfileEntity(string(p.PeerID()), a.String())
		if err := putAt(p, prefix+"primary", ent); err != nil {
			log.Printf("WARNING: self-publish TCP profile: %v", err)
		}
	}
	if httpAddr != "" {
		ent := selfHTTPProfileEntity(string(p.PeerID()), httpAddr)
		if err := putAt(p, prefix+"primary-http", ent); err != nil {
			log.Printf("WARNING: self-publish HTTP profile: %v", err)
		}
	}
}

func selfTCPProfileEntity(peerID, addr string) entity.Entity {
	data := types.TCPProfileData{
		PeerID:        peerID,
		TransportType: "tcp",
		Endpoint:      types.TransportEndpointURL{URL: "tcp://" + addr},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportTCP, cbor.RawMessage(raw))
	return ent
}

func selfHTTPProfileEntity(peerID, addr string) entity.Entity {
	data := types.HTTPProfileData{
		PeerID:        peerID,
		TransportType: "http",
		Endpoint:      types.TransportEndpointURL{URL: "http://" + addr + "/entity"},
		SupportedOps:  []string{types.OpExecute},
		Freshness:     "live",
		NonceRequired: true,
		CapFlow:       "both",
		AdvertisedAt:  uint64(time.Now().UnixMilli()),
	}
	raw, _ := ecf.Encode(data)
	ent, _ := entity.NewEntity(types.TypePeerTransportHTTP, cbor.RawMessage(raw))
	return ent
}

func putAt(p *peer.Peer, path string, ent entity.Entity) error {
	h, err := p.Store().Put(ent)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := p.LocationIndex().Set(path, h); err != nil {
		return fmt.Errorf("location-index Set %s: %w", path, err)
	}
	return nil
}

// wirePeerIssuedRegistries parses the --peer-issued-registry CSV spec
// ("<peer_id>@<tree_url_prefix>[,...]"), builds a peerissued.Backend per
// entry, and registers each with the meta-resolver. Each entry needs:
//   - an identity-multihash peer-id (ed25519); SHA-256-form peer-ids need
//     the public key out-of-band and are rejected for v1.
//   - an http-poll TreeURLPrefix the registry serves at.
//
// The http-poll Reader is the v1 demo wire (SUBSTITUTE §7 Mode S). Per
// handoff §1.1 the backend itself is transport-agnostic — swapping in a
// live-socket Reader is one line and the trust logic does not change.
func wirePeerIssuedRegistries(spec string, allowHTTP bool, registryH *registry.Handler) error {
	for _, entry := range splitCSV(spec) {
		at := strings.IndexByte(entry, '@')
		if at <= 0 || at == len(entry)-1 {
			return fmt.Errorf("entry %q: want `<peer_id>@<tree_url_prefix>`", entry)
		}
		pidStr := strings.TrimSpace(entry[:at])
		urlPrefix := strings.TrimSpace(entry[at+1:])

		pub, keyType, ok := crypto.DerivePeerFromPeerID(crypto.PeerID(pidStr))
		if !ok {
			return fmt.Errorf("peer %q: peer-id is not identity-multihash form (SHA-256 form requires out-of-band public key; not supported in v1)", pidStr)
		}
		registryPeer, err := types.PeerData{
			PublicKey: pub,
			KeyType:   crypto.KeyTypeString(keyType),
		}.ToEntity()
		if err != nil {
			return fmt.Errorf("peer %q: build identity entity: %w", pidStr, err)
		}

		// httplive.Outbound dial profile — minimal TransportEndpoint with
		// the TreeURLPrefix. ContentURLPrefix defaults to `<tree>/content`
		// at the call site (EffectiveContentURLPrefix).
		profile := types.HTTPPollProfileData{
			PeerID:        pidStr,
			TransportType: "http-poll",
			Endpoint: types.TransportEndpoint{
				TreeURLPrefix: urlPrefix,
				ContentLayout: types.ContentLayoutFlat,
			},
			SupportedOps: []string{types.OpTreeGet, types.OpContentGet},
		}
		outOpts := []httplive.OutboundOption{
			httplive.WithPinnedIdentity(registryPeer),
		}
		if allowHTTP {
			outOpts = append(outOpts, httplive.WithOutboundAllowHTTP(true))
		}
		out := httplive.NewOutbound(profile, outOpts...)
		reader := peerissued.NewHTTPPollReader(out, pidStr)

		backend, err := peerissued.New(registryPeer, pidStr, reader)
		if err != nil {
			return fmt.Errorf("peer %q: build backend: %w", pidStr, err)
		}
		registryH.RegisterBackend(backend)
		log.Printf("peer-issued registry %s pinned at %s", pidStr, urlPrefix)
	}
	return nil
}

// buildIssuerPolicy translates the --issuer-policy-* CLI flags into a
// types.IssuerPolicyData per EXTENSION-REGISTRY §6a.9.1. The resulting
// policy is installed as the Issuer's in-memory fallback; an explicit
// `system/registry/issuer-policy` entity in the store still wins at
// dispatch time so an operator can re-tune without a restart.
func buildIssuerPolicy(mode, allowlistCSV, nameConstraints string, defaultTTL time.Duration) (types.IssuerPolicyData, error) {
	switch mode {
	case types.IssuerPolicyModeOpen, types.IssuerPolicyModeAllowlist, types.IssuerPolicyModeManual:
		// supported
	case types.IssuerPolicyModeDomainControl:
		return types.IssuerPolicyData{}, fmt.Errorf("mode %q is deferred per §6a.10 (web-native domain-proof co-design)", mode)
	default:
		return types.IssuerPolicyData{}, fmt.Errorf("unsupported mode %q (want one of: open, allowlist, manual)", mode)
	}

	p := types.IssuerPolicyData{Mode: mode}

	if mode == types.IssuerPolicyModeAllowlist {
		entries := splitCSV(allowlistCSV)
		if len(entries) == 0 {
			return types.IssuerPolicyData{}, fmt.Errorf("mode=allowlist requires --issuer-policy-allowlist")
		}
		p.Allowlist = entries
	}

	if nameConstraints != "" {
		nc := nameConstraints
		p.NameConstraints = &nc
	}

	if defaultTTL > 0 {
		ms := uint64(defaultTTL.Milliseconds())
		p.DefaultTTL = &ms
	}

	return p, nil
}

// splitCSV splits a comma-separated value, trimming whitespace and skipping
// empty fields. Returns nil for an empty input.
func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
