package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/peer"
	"go.entitychurch.org/entity-core-go/core/types"
)

// writeAdminSeedPolicy loads the named identity, resolves its identity-entity
// hash, and writes a seed-policy file in the KEYSTONE CANONICAL format
// (protocol-generator/shared/seed-policy/seed-policy.schema.json — the
// operator-admin.json shape): {"version":1,"entries":[{"grantee":"<hex>",
// "grants":[...]}]}. The single entry grants THAT identity (keyed by its 66-char
// hex, never `default`) the open-access grant set; unknown peers match no entry
// and fall to the intrinsic §4.4 discovery floor, staying gated by the
// initial-grant policy — the restrictive posture a gating check needs, with the
// one exception that the admin can stage its own setup. Returns the file path.
func writeAdminSeedPolicy(identityName string) (string, error) {
	kp, err := crypto.LoadIdentity(identityName)
	if err != nil {
		return "", fmt.Errorf("load identity %q: %w", identityName, err)
	}
	id, err := kp.IdentityEntity()
	if err != nil {
		return "", fmt.Errorf("identity entity for %q: %w", identityName, err)
	}
	doc := struct {
		Version int `json:"version"`
		Entries []struct {
			Comment string             `json:"_comment,omitempty"`
			Grantee string             `json:"grantee"`
			Grants  []types.GrantEntry `json:"grants"`
		} `json:"entries"`
	}{Version: 1}
	doc.Entries = append(doc.Entries, struct {
		Comment string             `json:"_comment,omitempty"`
		Grantee string             `json:"grantee"`
		Grants  []types.GrantEntry `json:"grants"`
	}{
		Comment: "admin-seeded-restrictive: broad write for " + identityName + " only; unknown peers gated by the initial-grant policy",
		Grantee: hex.EncodeToString(id.ContentHash.Bytes()),
		Grants:  peer.OpenAccessGrants(),
	})
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal seed policy: %w", err)
	}
	// Write into $HOME/.entity — the ONE directory podmanRunBase bind-mounts into
	// every container peer (as homeEntity). os.TempDir() is host-only and is NOT
	// visible inside the rust/python containers, so a policy written there loaded
	// on go (native) but silently vanished on the siblings — the peer came up
	// unseeded and non-restrictive, defeating the gating posture. The seed-policies/
	// subdir keeps it out of the peers/ + store/ tree; the name is deterministic
	// per identity (not timestamped) so it neither accumulates nor races between
	// the adm1/adm2 pair, which seed an identical policy.
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	dir := filepath.Join(home, ".entity", "seed-policies")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create seed-policy dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, fmt.Sprintf("entity-seed-policy-%s.json", identityName))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("write seed policy %s: %w", path, err)
	}
	return path, nil
}

// containerSeedPolicyPath maps a host seed-policy path (under $HOME/.entity, per
// writeAdminSeedPolicy) to where it appears INSIDE a container peer, whose
// homeEntity mount target ("/root/.entity", "/home/entity/.entity") stands in for
// the host's $HOME/.entity. Go peers run native and use the host path directly;
// only the rust/python container starts need this translation.
func containerSeedPolicyPath(hostPath, homeEntity string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return hostPath
	}
	hostEntity := filepath.Join(home, ".entity")
	rel, err := filepath.Rel(hostEntity, hostPath)
	if err != nil {
		return hostPath
	}
	return filepath.Join(homeEntity, rel)
}

// The sibling-surface verification pin — ONE pin for every present-tense
// "honored by …" / "absent from …" claim in this file.
//
// WHY THIS EXISTS (G-7, filed by our own discipline audit 2026-08-12 d, closed
// 2026-08-12 e). `AGENTS.md` names this exact file as where build-state
// staleness accumulates: *"every `Honored by …` / `… impl pending` string is a
// build-state assertion about a repo we do not control … treat a stale one as a
// defect, not a typo — it is the documentation of a skip."* The audit measured
// **20 such claims pinned across 18 different sibling commits, not one of them
// current.** The citation format was working — a reader could tell they were
// dated — and that was precisely the problem: twenty independent dates rot
// independently, and no single reading of the tree can refresh them.
//
// So the pin is consolidated. Re-verification is now ONE edit, and the rule that
// comes with it is not optional:
//
//	MOVING THESE CONSTANTS ASSERTS THAT EVERY CLAIM BELOW WAS RE-READ IN BOTH
//	SIBLING WORKTREES AT THESE COMMITS. Not spot-checked. Not inferred from a
//	report, a handoff, or `git log`. Opened, and read.
//
// That is a stronger obligation than twenty separate dates imposed, because it
// cannot be discharged partially — which is the point. The audit's stated fear
// was "spot-checking two and re-dating twenty"; with one constant that is a
// single visible lie rather than nineteen invisible ones.
//
// Two claim kinds live below and they are NOT the same:
//
//   - **Present-tense surface claims** — "rust ships X", "absent from py". These
//     decay the moment a sibling commits and carry `siblingSurfaceVerifiedAt()`.
//   - **Historical landing pins** — "flag X landed at rust 3e9c9fc". A fact about
//     the past; it does not decay and MUST NOT be re-dated. Marked `[historical]`
//     so a re-verification pass does not waste a read on it.
//
// Runtime/behavioral claims are a third kind and are pinned separately at the
// claim, with the date they were MEASURED — reading a CLI cannot establish them.
const (
	// rust HEAD, read live: `git log -1` in ../entity-core-rust.
	siblingPinRust = "dfd4d45"
	// py HEAD, read live: `git log -1` in ../entity-core-py.
	siblingPinPython = "ad0ef98"
	siblingPinDate   = "2026-08-12 (e)"
)

// siblingSurfaceVerifiedAt renders the pin for a flag's help text, so `-h`
// output carries it and a reader never has to trust an undated claim.
func siblingSurfaceVerifiedAt() string {
	return fmt.Sprintf(" [sibling CLI surface read live %s: rust %s, py %s]",
		siblingPinDate, siblingPinRust, siblingPinPython)
}

func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	name := fs.String("name", "", "peer name (required)")
	peerType := fs.String("type", "go", "peer type: go, rust, python")
	addr := fs.String("addr", "127.0.0.1:0", "listen address (default: random port)")
	openAccess := fs.Bool("open-access", true, "grant open access to connecting peers")
	adminIdentity := fs.String("admin-identity", "", "seed a restrictive peer where ONLY this named identity (from ~/.entity/identities/) gets broad write access — unknown peers stay gated by the initial-grant policy. Implies --open-access=false. This is the admin-seeded-restrictive posture the recognize-on-attest / anonymous-deny gating checks need: the validator (run with the same -identity) can stage its setup, but K/M/N are gated so the gate is observable.")
	debug := fs.Bool("debug", false, "enable debug logging")
	storage := fs.String("storage", "", "storage backend: memory (default), sqlite (go + rust)")
	files := fs.String("files", "", "expose filesystem directory (format: name:/path:tree/prefix/) — supported by all three impls' --files flag")
	history := fs.String("history", "*", "history recording pattern (default: \"*\" records all; use \"\" to disable)")
	clockTickMs := fs.Uint64("clock-tick-ms", 0, "EXTENSION-CLOCK §2.5 tick_interval: emit a periodic clock tick every N ms (Go peers only; 0 = disabled, the spec default). Forwarded as --clock-tick-ms to entity-peer.")
	relayStoreRetentionMs := fs.Uint64("relay-store-retention-ms", 0, "EXTENSION-RELAY §8.1 (v1.3) Mode-S store retention ceiling in ms (Go relay only; 0 = no ceiling). When set, the relay clamps a long/null store-entry expires_at to now+ceiling and publishes it as limits.max_retention_ms in its advertise. Forwarded as --relay-store-retention-ms to entity-peer.")
	relayMaxStorageBytes := fs.Uint64("relay-max-storage-bytes", 0, "EXTENSION-RELAY §8.2 (v1.3) Mode-S relay-wide store bound in bytes (Go relay only; 0 = unbounded). A :put over the bound is refused with storage_full/507; published as limits.max_storage_bytes in the advertise. Forwarded as --relay-max-storage-bytes to entity-peer.")
	remote := fs.String("remote", "", "register a remote peer by name (must already be running)")
	httpAddr := fs.String("http-addr", "", "additional HTTP-live listener address (e.g. 127.0.0.1:0 for random; empty disables). Chunk D / Amendment 3. Honored by all three: Go -http-addr, Rust --http-listen (`http_listen` in cmd/entity-peer/src/main.rs), Python --http-addr (packages/entity-cli/src/entity_cli/main.py argparse). peer-manager already forwards to both siblings below — the prior \"CLI wiring pending\" note contradicted the forwarding code in this same file."+siblingSurfaceVerifiedAt())
	httpPath := fs.String("http-path", "/entity", "URL path the HTTP-live listener accepts POSTs at (when --http-addr set)")
	wsAddr := fs.String("ws-addr", "", "additional WebSocket-live listener address (e.g. 127.0.0.1:9501; --ws-addr does not yet accept :0 because the port is needed to construct the ws:// URL). Thread F (NETWORK §6.5.2b). Go + Rust only: Rust ships --ws-listen ungated at the CLI (`ws_listen` in cmd/entity-peer/src/main.rs) and peer-manager forwards it below; there is no --ws-path on the Rust side, so Go's configurable path is a Go-side extension. Python has NO WebSocket listener flag — enumerated its full 49-flag argparse surface, not grepped for one name."+siblingSurfaceVerifiedAt())
	wsPath := fs.String("ws-path", "/ws", "URL path the WebSocket listener accepts upgrades at (when --ws-addr set)")
	// Chunk E serving-mode flags. All three ship them; see the
	// siblingPin* block for the verification pin. Rust: http_poll_addr,
	// http_poll_mount_on_live, http_poll_prefix, serve_namespace,
	// serve_closure_root in cmd/entity-peer/src/main.rs — but NOT
	// serve_scope_whole_store (see the warning at the rust branch below).
	// Python: all six, in the entity-cli argparse. [historical] the flags
	// landed at rust 58d9188. The "Go-only initially" note this replaces
	// described the state during E impl and outlived it.
	httpPollAddr := fs.String("http-poll-addr", "", "Chunk E: isolated HTTP poll listener (e.g. 127.0.0.1:9201); GET /content/{hex(H)}. Mutually exclusive with --http-poll-mount-on-live.")
	httpPollMountOnLive := fs.Bool("http-poll-mount-on-live", false, "Chunk E: mount poll routes on the live HTTP listener (Posture 2). Requires --http-addr.")
	httpPollPrefix := fs.String("http-poll-prefix", "/poll", "Chunk E: URL prefix when mounting poll on live listener (default /poll); ignored on isolated port.")
	serveNamespace := fs.String("serve-namespace", "", "Chunk E: content-namespace scope (e.g. system/content/public). Tree binding at NAMESPACE/{hex(H)} = in-scope.")
	serveWholeStore := fs.Bool("serve-scope-whole-store", false, "Chunk E: DEBUG OPT-IN — serve every H in local content-store (ruling §1.3 T2/T3 caveat).")
	keyType := fs.String("key-type", "ed25519", "peer keypair algorithm: ed25519 (default) | ed448 (v7.67 §3). Applies when minting a new identity for this peer. Honored by all three: Go --key-type, Python --key-type, Rust `key_type` on `peer init` (cmd/entity-peer/src/main.rs, PeerAction::Init) — and peer-manager HAS been forwarding it to rust init all along (see startRustPeer below). This note read \"forwarded to Rust once its CLI lands\" until 2026-08-12 (e), which was the SECOND claim in this file to contradict the forwarding code sitting a few hundred lines beneath it. A false negative about a sibling reads as their gap and is ours."+siblingSurfaceVerifiedAt())
	hashType := fs.String("hash-type", "sha256", "content_hash_format / home format the peer authors content + substrate under: sha256 (default, 0x00) | sha384 (0x01). V7 v7.70 §1.2. Honored by all three: Go --hash-type, Rust `hash_type` (cmd/entity-peer/src/main.rs, on both `peer start` and `peer issue-binding`), Python --hash-type. NOTE: sha384 is accepted by all three CLIs. The two spec pins that blocked it are GONE as of 2026-08-10 (verified in spec text 2026-08-11): EXTENSION-NETWORK §6.5.3.1 has no 33-byte pin left, and EXTENSION-SIGNALING §6.3 carries an explicit \"Corrected 2026-08-10\" dropping the fixed-33 requirement on inner_content_hash — it is authored content and follows the signing peer's home format. §3.1's 33-byte rendezvous_key is deliberate and NOT the defect: it is pinned to the SHA-256 floor because a rendezvous key is a reproduced lookup token, not authored content. GO NOW RUNS SHA-384 END TO END, MEASURED 2026-08-12 (e): `HASH_TYPE=sha384 ./scripts/validate-complete.sh` → 1571 · 0F · 0S · 0W / 633 / 55 / 19, exit 0 on all four passes. This sentence read \"UNMEASURED SINCE THAT CORRECTION — re-measure before relying on it\" for two days, and the honest part of that warning was warranted: the first run found 1 F plus two more defects hidden behind it, all of them §4.5a item 1a identity-format violations in our own code. Fixed; see WORK-STATUS G-9. See docs/validation/spec-issues/2026-08-10-the-33-byte-hash-*."+siblingSurfaceVerifiedAt())
	inboxRelayRegistry := fs.String("inbox-relay-registry", "", "EXTENSION-RELAY §3.5 REGISTRY-served inbox-relay decl chain (Go-only initially): comma-separated peer-names of registries to consult (in order). The names are translated to peer-ids from state. Forwarded as --inbox-relay-registry to entity-peer.")
	validate := fs.Bool("validate", false, "GUIDE-CONFORMANCE §7a: enable system/validate/echo + system/validate/dispatch-outbound test handlers (unblocks concurrency.t1_2_concurrent_reentry). MUST NOT be on in production. Honored by all three: Go -validate, Rust `validate` (cmd/entity-peer/src/main.rs), Python --validate (entity-cli argparse; handlers in packages/entity-handlers/src/entity_handlers/conformance.py). This was the one 'honored by all three' claim in this file carrying NO pin at all — unfalsifiable rather than merely stale."+siblingSurfaceVerifiedAt())
	signalingNode := fs.Bool("signaling-node", false, "EXTENSION-SIGNALING §4/§5: serve the system/signaling rendezvous node (offer/collect/advertise) for the punch gate. Honored by all three: Go -signaling-node, Rust `signaling_node` (cmd/entity-peer/src/main.rs), Python --signaling-node. Off by default everywhere — a peer is a signaling CLIENT by default and only a deployed introducer serves. The flag registers the handler but grants nobody access, so it needs an admission posture: Go/Python get the default --open-access, Rust gets --debug-grants (passed unconditionally; rust has no --open-access, `debug_grants` is its equivalent)."+siblingSurfaceVerifiedAt())
	publishRoot := fs.Bool("publish-root", false, "PROPOSAL-PEER-MANIFEST §4: mint signed system/peer/published-root on every tree-root change + serve via http-poll. Pair with --http-poll-addr to expose the manifest on the wire. Honored by all three, and all three republish on a root change. THAT SECOND HALF IS A RUNTIME CLAIM, so it carries its own measurement pin and not the CLI-surface one: `serving_mode.seed_republished` PASSes three ways on real seq advances — **re-measured 2026-08-12 (e) against live rust `dfd4d45` and py `ad0ef98` peers**, both started `--publish-root --http-poll-addr --serve-closure-root`. Reading a CLI cannot establish it, so it is re-run rather than re-dated. The 2026-08-07 measurement of Rust + Python frozen at seq=0 (docs/validation/reports/2026-08-07-f-...md) is superseded: both built it after that report. NOTE the wording above describes what these impls DO, not what the spec requires — no landed spec obliges a publisher to ever republish, so a peer that mints once and freezes is conformant today. That gap is PROPOSAL-PUBLISHED-ROOT-PREFIX-AND-REPUBLISH §5 (DRAFT); until it folds, a non-republishing peer is not a sibling bug.")
	serveClosureRoot := fs.Bool("serve-closure-root", false, "EXTENSION-NETWORK §6.5.6 Amendment 10: scope served set to the transitive trie-node closure reachable from system/peer/published-root. Pair with --publish-root so a consumer's signed-root hash-chain walk does not 404 on a CHAMP interior node. Mutually exclusive with --serve-namespace / --serve-scope-whole-store. Honored by all three: Go, Rust `serve_closure_root` (declared in cmd/entity-peer/src/main.rs — this note cited commands/peer.rs, which is where it is CONSUMED, not declared; already forwarded below), Python --serve-closure-root (takes a PATH — peer-manager passes \"published\")."+siblingSurfaceVerifiedAt())
	peerIssuedRegistry := fs.String("peer-issued-registry", "", "PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2: pin one or more peer-issued registries (comma-separated `peer_id@tree_url_prefix`). Pair with validate-peer -peer-issued-bundle, which serves the fixture registry at that URL. An http:// prefix implies --substitute-allow-http (fixture registries are loopback-only). Honored by all three, same peer_id@url spec, installing a trust root + a §4 chain entry carrying hints.endpoint. Rust's flag is `peer_issued_registry: Vec<String>` — repeatable rather than comma-separated, so peer-manager splits on comma and emits one occurrence per pin. Its live remote-read seam is present: `HttpPollRegistryReader` implementing `entity_registry::peer_issued::RegistryTreeReader`, core/peer/src/poll_read.rs. [historical] that seam landed at rust 5c58195; before it, rust registered a backend but resolved against its LOCAL STORE only, and the category SKIPped rather than fail an unbuilt surface."+siblingSurfaceVerifiedAt())
	publishPrefix := fs.String("publish-prefix", "", "EXTENSION-TREE §3.3a: the subtree --publish-root commits to, and the `prefix` the published root declares (e.g. system/content/ to publish only shareable content, or / for the universal tree). Empty keeps the peer's own default. This is how a peer publishes a SUBSET of its tree — the common deployment — rather than everything under system/. Go-only: absent from both sibling CLIs — established by enumerating rust's full `PeerAction::Start` arg set and py's full 49-flag argparse surface, not by grepping for one name — so it is dropped with a warning for those types rather than passed and rejected."+siblingSurfaceVerifiedAt())
	publishDescriptors := fs.Bool("publish-descriptors", false, "DOMAIN-LOCAL-FILES v1.3 §10.5 V3: configure the --files root with publish_descriptors=true so file reads write `system/content/descriptor/{hash}` entities into the tree. Arms local_files.v3_descriptor_publish_exercised. Honored by all three: Go, Rust `publish_descriptors` (cmd/entity-peer/src/main.rs), Python --publish-descriptors. And the check it arms is a RUNTIME claim, so it is measured rather than inferred from the flag: `local_files.v3_descriptor_publish_exercised` PASSes against live rust `dfd4d45` and py `ad0ef98` peers, 2026-08-12 (e)."+siblingSurfaceVerifiedAt())
	keepalive := fs.String("keepalive", "", "EXTENSION-NETWORK §2.3 keepalive override as interval_ms,timeout_ms,max_missed (e.g. 1500,800,2) so the §5.4 escalation is observable in seconds — pair with validate-peer -keepalive-envelope-ms for the liveness harness. A field may be empty to keep its spec default. Honored by all three, same three flag names: Go -keepalive-{interval,timeout,max-missed}-ms, Python --keepalive-{interval,timeout,max-missed}-ms, Rust `keepalive_{interval_ms,timeout_ms,max_missed}` (cmd/entity-peer/src/main.rs)."+siblingSurfaceVerifiedAt())
	discoveryAnnounce := fs.String("discovery-announce", "", "EXTENSION-DISCOVERY §3 — announce this peer on the mDNS backend at startup. Value is the transport profile_ref to advertise; the v1 mDNS backend serves `tcp` and `http-poll`. Requires the matching listener (--addr is always set by peer-manager; `http-poll` additionally needs --http-addr). Empty disables. Go + Python: py ships --discovery-announce AND --discovery-profile in the entity-cli argparse; rust exposes NO CLI flag for it (absent from `PeerAction::Start`, enumerated in full), though it has the announce capability and the `:announce` operation. So it is dropped with a warning for rust only. This note read \"Go-only: neither sibling exposes a CLI flag for it\" until 2026-08-12 (e) — wrong about py. The OPERATION itself is covered cross-impl by discovery.v7a_announce_lifecycle, which needs no flag.")
	issuerPolicyMode := fs.String("issuer-policy-mode", "", "EXTENSION-REGISTRY §6a.9 — run this peer as a peer-issued LIVE registry, accepting `register-request` / `revoke-request` / `renew-request`. Value is the issuer-policy mode: `open`, `allowlist` (needs --issuer-policy-allowlist), or `manual` (requests queue as 202 pending_review). Empty disables. ARMING DIVERGES ACROSS THE COHORT, but ONLY at the CLI: Go gates handler *registration* on this flag (cmd/entity-peer --issuer-policy-mode), while Python AND Rust both register the handler unconditionally and leave it inert until an issuer-policy is written (rust: RegisterRequestHandler in core/peer/src/lib.rs, ops bootstrapped at system/registry/peer-issued; python: packages/entity-handlers/.../registry.py). All three implement §6a.9.2 `set-issuer-policy`, so the validator arms either sibling over the wire and `registry_issuer` needs no flag from us — measured 2026-08-12 (e): python 19/19, rust 17/19 (the two failures are the arch-ruled register-result gap, not arming). This note previously said rust \"exposes no CLI arming flag\" AND that set-issuer-policy was python-only that \"go and rust do not implement\" — the first is true and irrelevant, the second was false twice over. Forwarded to Go peers only; dropped with a warning otherwise, and the warning now says why nothing is lost."+siblingSurfaceVerifiedAt())
	issuerPolicyAllowlist := fs.String("issuer-policy-allowlist", "", "EXTENSION-REGISTRY §6a.9.1 — comma-separated target_peer_ids permitted to register when --issuer-policy-mode=allowlist. Ignored in other modes. Go-only, see --issuer-policy-mode.")
	issuerPolicyNameConstraints := fs.String("issuer-policy-name-constraints", "", "EXTENSION-REGISTRY §6a.9.1 — POSIX glob narrowing which names this registry will issue (e.g. \"*.lab\"); a non-matching name is rejected 403 not_entitled. Empty = no constraint. Go-only, see --issuer-policy-mode.")
	issuerPolicyDefaultTTL := fs.String("issuer-policy-default-ttl", "", "EXTENSION-REGISTRY §6a.9.1 — Go duration (e.g. 1h) the registry signs when register-request omits requested_ttl. REQUIRED for a live registry (a null default_ttl mints unresolvable bindings). Go-only, see --issuer-policy-mode.")
	issuerPolicyMaxTTL := fs.String("issuer-policy-max-ttl", "", "EXTENSION-REGISTRY §6a.9 (v1.11) — Go duration issuer-side TTL ceiling; a resolved binding ttl above it is CLAMPED (not refused). REQUIRED for a live registry. Go-only, see --issuer-policy-mode.")
	reflectionEndpoints := fs.String("reflection-endpoint", "", "EXTENSION-SIGNALING §4.5.1 (v1.1): comma-separated RFC 7064 STUN URI(s) this node advertises as its OWN §9.3 reflection listener(s), in `advertise`'s top-level reflection_endpoints. Pair with --signaling-node. Go-only for now: the field is unbuilt in rust and py as of 2026-08-15 (source-read, docs/validation/reports/2026-08-15-reflection-endpoints-*.md) — arch routed it P0 to entity-core-rust. Dropped with a warning for those peer types rather than passed and rejected.")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintf(os.Stderr, "Error: --name is required\n")
		os.Exit(1)
	}

	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
		os.Exit(1)
	}

	if entry, exists := state.Peers[*name]; exists && isAlive(entry.PID) {
		fmt.Fprintf(os.Stderr, "Peer %q already running (pid %d, addr %s)\n", *name, entry.PID, entry.Addr)
		os.Exit(1)
	}

	// Set up log file.
	logDir := filepath.Join(stateDir(), "logs")
	os.MkdirAll(logDir, 0755)
	logFile := filepath.Join(logDir, *name+".log")
	lf, err := os.Create(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating log file: %v\n", err)
		os.Exit(1)
	}

	var entry *PeerEntry

	pollFlags := chunkEFlags{
		pollAddr:            *httpPollAddr,
		mountOnLive:         *httpPollMountOnLive,
		pollPrefix:          *httpPollPrefix,
		serveNamespace:      *serveNamespace,
		serveWholeStore:     *serveWholeStore,
		serveClosureRoot:    *serveClosureRoot,
		validate:            *validate,
		signalingNode:       *signalingNode,
		publishRoot:         *publishRoot,
		publishDescriptors:  *publishDescriptors,
		publishPrefix:       *publishPrefix,
		peerIssuedRegistry:  *peerIssuedRegistry,
		substituteAllowHTTP: *peerIssuedRegistry != "" && strings.Contains(*peerIssuedRegistry, "http://"),

		discoveryAnnounce:           *discoveryAnnounce,
		issuerPolicyMode:            *issuerPolicyMode,
		issuerPolicyAllowlist:       *issuerPolicyAllowlist,
		issuerPolicyNameConstraints: *issuerPolicyNameConstraints,
		issuerPolicyDefaultTTL:      *issuerPolicyDefaultTTL,
		issuerPolicyMaxTTL:          *issuerPolicyMaxTTL,
		reflectionEndpoints:         *reflectionEndpoints,
	}

	// Resolve --inbox-relay-registry peer-names → peer-ids from state.
	// Comma-separated; unknown names hard-fail (registry must already be
	// running before the relay peer that consults it starts).
	var registryPeerIDs string
	if *inboxRelayRegistry != "" {
		var ids []string
		for _, regName := range strings.Split(*inboxRelayRegistry, ",") {
			regName = strings.TrimSpace(regName)
			if regName == "" {
				continue
			}
			reg, ok := state.Peers[regName]
			if !ok || !isAlive(reg.PID) {
				fmt.Fprintf(os.Stderr, "Error: --inbox-relay-registry %q: peer not running (start it first)\n", regName)
				os.Exit(1)
			}
			ids = append(ids, reg.PeerID)
		}
		registryPeerIDs = strings.Join(ids, ",")
	}

	// Parse --keepalive up front so a malformed triple fails before any
	// process is spawned.
	ka, err := parseKeepalive(*keepalive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: --keepalive: %v\n", err)
		os.Exit(1)
	}

	// --admin-identity establishes the restrictive posture: a per-identity seed
	// grant for the admin only, and open-access OFF so unknown peers are gated.
	// --admin-identity establishes the restrictive posture on ALL THREE impls now
	// that the siblings read the keystone canonical seed-policy container:
	//   - go    reads --seed-policy-file (entity-peer/main.go)
	//   - rust  reads --seed-policy (peer.rs with_seed_policy_from_file; refuses
	//           the flag alongside --debug-grants, so startRustPeer drops the
	//           unconditional --debug-grants when a policy is set)
	//   - python reads --seed-policy (entity-cli/main.py); its --debug flag ALSO
	//           re-enables open-access (main.py: open_access = args.debug or …),
	//           so startPythonPeer suppresses --debug in this posture — otherwise
	//           the very gate we want to observe would be hidden.
	// The single emitted file lives under $HOME/.entity so every container sees it.
	seedPolicyFile := ""
	if *adminIdentity != "" {
		if *peerType != "go" && *peerType != "rust" && *peerType != "python" {
			fmt.Fprintf(os.Stderr, "Unknown peer type: %s (supported: go, rust, python)\n", *peerType)
			os.Exit(1)
		}
		p, err := writeAdminSeedPolicy(*adminIdentity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: --admin-identity: %v\n", err)
			os.Exit(1)
		}
		seedPolicyFile = p
		*openAccess = false
	}

	switch *peerType {
	case "go":
		entry = startGoPeer(*name, *addr, *debug, *openAccess, *files, *history, *storage, *httpAddr, *httpPath, *wsAddr, *wsPath, *keyType, *hashType, registryPeerIDs, *clockTickMs, *relayStoreRetentionMs, *relayMaxStorageBytes, ka, pollFlags, logFile, seedPolicyFile, lf)
	case "rust":
		// [historical] Rust 474bb11 (Chunk D), 58d9188 (Chunk E flags), 0616727 (v7.70 home-format).
		// Rust ships --ws-listen for NETWORK §6.5.2b; cohort flag string is
		// --ws-addr at the peer-manager boundary, translated below.
		entry = startRustPeer(*name, *addr, *debug, *storage, *history, *files, *httpAddr, *httpPath, *wsAddr, *keyType, *hashType, *relayStoreRetentionMs, *relayMaxStorageBytes, ka, pollFlags, logFile, seedPolicyFile, lf)
	case "python":
		// [historical] Python aligned with Chunk D and 74b3335 (Chunk E flags); Python
		// ships --key-type from f231406 and --hash-type from ff6d1e2 (v7.70).
		if *wsAddr != "" {
			fmt.Fprintf(os.Stderr, "Note: --ws-addr has no Python equivalent; ignored for Python peer %q\n", *name)
		}
		entry = startPythonPeer(*name, *addr, *debug, *openAccess, *history, *files, *httpAddr, *httpPath, *keyType, *hashType, *relayStoreRetentionMs, *relayMaxStorageBytes, ka, pollFlags, logFile, seedPolicyFile, lf)
	default:
		fmt.Fprintf(os.Stderr, "Unknown peer type: %s (supported: go, rust, python)\n", *peerType)
		os.Exit(1)
	}

	entry.Type = *peerType
	if *storage != "" {
		entry.Storage = *storage
	} else {
		entry.Storage = "memory"
	}

	state.Peers[*name] = entry
	if err := saveState(state); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Started peer %q: addr=%s peer_id=%s storage=%s pid=%d\n", *name, entry.Addr, entry.PeerID, entry.Storage, entry.PID)

	if *remote != "" {
		wireRemote(state, *name, *remote)
	}
}

// --- Chunk E flag bundle ---

// chunkEFlags carries the serving-mode flags through to per-impl
// start functions without bloating signatures. Each impl forwards
// what it supports today; unsupported flags warn and are dropped.
type chunkEFlags struct {
	pollAddr         string
	mountOnLive      bool
	pollPrefix       string
	serveNamespace   string
	serveWholeStore  bool
	serveClosureRoot bool
	// Beyond Chunk E, but plumbed alongside since the orchestrator path
	// (validate-peers-green.sh) brings them up as a bundle.
	validate           bool
	signalingNode      bool
	publishRoot        bool
	publishDescriptors bool
	// publishPrefix is the EXTENSION-TREE §3.3a subtree --publish-root commits
	// to. Empty means "use the peer's own default".
	publishPrefix string
	// peerIssuedRegistry is the PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2
	// pin spec, `peer_id@url_prefix`. Forwarded verbatim; the peer-id is a
	// registry identity, not a peer-manager-managed peer, so unlike
	// --inbox-relay-registry there is no name→id translation to do.
	peerIssuedRegistry  string
	substituteAllowHTTP bool

	// discoveryAnnounce is the EXTENSION-DISCOVERY §3 startup announce —
	// the transport profile_ref to advertise on mDNS.
	discoveryAnnounce string

	// issuerPolicy* arm the EXTENSION-REGISTRY §6a.9 LIVE-registration
	// surface — the write side of peer-issued (`register-request` /
	// `revoke-request` / `renew-request`), as distinct from
	// peerIssuedRegistry above, which pins a registry to READ from.
	//
	// Go arms this at construction: the handler is not registered at all
	// unless issuerPolicyMode is set, which is why the surface had zero
	// validator coverage until this passthrough existed — the suite could
	// not start it (GUIDE-CONFORMANCE §5.2b).
	// reflectionEndpoints is the EXTENSION-SIGNALING §4.5.1 (v1.1) comma-separated
	// RFC 7064 STUN URI list this node advertises as its own §9.3 reflection
	// listener(s). Go-only for now — unbuilt in rust/py, so forwarded to Go peers
	// and dropped-with-warning for the siblings, the same shape as publishPrefix.
	reflectionEndpoints string

	issuerPolicyMode            string
	issuerPolicyAllowlist       string
	issuerPolicyNameConstraints string
	issuerPolicyDefaultTTL      string
	issuerPolicyMaxTTL          string
}

// enabled reports whether serving-mode was requested.
func (f chunkEFlags) enabled() bool {
	return f.pollAddr != "" || f.mountOnLive
}

// keepaliveSpec is a parsed --keepalive triple. An empty field means that
// parameter keeps its §2.3 spec default; the impls agree on partial overrides.
type keepaliveSpec struct {
	intervalMS string
	timeoutMS  string
	maxMissed  string
}

// parseKeepalive parses the --keepalive triple (interval_ms,timeout_ms,
// max_missed). Empty input → zero spec.
func parseKeepalive(spec string) (keepaliveSpec, error) {
	var ka keepaliveSpec
	if spec == "" {
		return ka, nil
	}
	parts := strings.Split(spec, ",")
	if len(parts) != 3 {
		return ka, fmt.Errorf("want interval_ms,timeout_ms,max_missed (got %q)", spec)
	}
	fields := []*string{&ka.intervalMS, &ka.timeoutMS, &ka.maxMissed}
	names := []string{"interval_ms", "timeout_ms", "max_missed"}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := strconv.ParseUint(p, 10, 64); err != nil {
			return keepaliveSpec{}, fmt.Errorf("%s: %q is not a non-negative integer", names[i], p)
		}
		*fields[i] = p
	}
	return ka, nil
}

func (ka keepaliveSpec) empty() bool {
	return ka.intervalMS == "" && ka.timeoutMS == "" && ka.maxMissed == ""
}

// args renders the override flags in the given dash dialect. The flag names are
// identical across impls; only the dash count differs — Go's stdlib flag takes
// "-keepalive-interval-ms", Python's argparse takes "--keepalive-interval-ms".
func (ka keepaliveSpec) args(dash string) []string {
	var out []string
	for _, f := range []struct{ name, val string }{
		{"keepalive-interval-ms", ka.intervalMS},
		{"keepalive-timeout-ms", ka.timeoutMS},
		{"keepalive-max-missed", ka.maxMissed},
	} {
		if f.val != "" {
			out = append(out, dash+f.name, f.val)
		}
	}
	return out
}

// --- Go peer ---

func startGoPeer(name, addr string, debug, openAccess bool, files, history, storage, httpAddr, httpPath, wsAddr, wsPath, keyType, hashType, inboxRelayRegistry string, clockTickMs, relayStoreRetentionMs, relayMaxStorageBytes uint64, keepalive keepaliveSpec, poll chunkEFlags, logFile, seedPolicyFile string, lf *os.File) *PeerEntry {
	readyFile := filepath.Join(os.TempDir(), fmt.Sprintf("entity-peer-%s-%d.ready", name, time.Now().UnixNano()))

	// Pass -name so the Go peer loads (or creates) its keypair at
	// ~/.entity/peers/{name}/keypair, matching Rust's convention. This
	// gives the peer a stable identity across restarts and lets external
	// tools (e.g., validate-peer multi-sig convergence tests) load the
	// same keypair to produce signatures attributable to this peer.
	// keyType selects the algorithm at mint time; the PEM header tracks it.
	cmdArgs := []string{"-addr", addr, "-ready-file", readyFile}
	if name != "" {
		if err := ensurePeerKeypair(name, keyType); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create peer keypair %q: %v (falling back to ephemeral identity)\n", name, err)
			// Ephemeral fallback still honors --key-type so the spawned
			// peer matches the requested algorithm.
			if keyType != "" && keyType != "ed25519" {
				cmdArgs = append(cmdArgs, "-key-type", keyType)
			}
		} else {
			cmdArgs = append(cmdArgs, "-name", name)
		}
	} else if keyType != "" && keyType != "ed25519" {
		cmdArgs = append(cmdArgs, "-key-type", keyType)
	}
	if openAccess {
		cmdArgs = append(cmdArgs, "-open-access")
	}
	if seedPolicyFile != "" {
		cmdArgs = append(cmdArgs, "-seed-policy-file", seedPolicyFile)
	}
	if debug {
		cmdArgs = append(cmdArgs, "-debug")
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "-files", files)
	}
	if history != "" {
		cmdArgs = append(cmdArgs, "-history", history)
	}
	if relayStoreRetentionMs > 0 {
		cmdArgs = append(cmdArgs, "-relay-store-retention-ms", strconv.FormatUint(relayStoreRetentionMs, 10))
	}
	if relayMaxStorageBytes > 0 {
		cmdArgs = append(cmdArgs, "-relay-max-storage-bytes", strconv.FormatUint(relayMaxStorageBytes, 10))
	}
	if clockTickMs > 0 {
		cmdArgs = append(cmdArgs, "-clock-tick-ms", strconv.FormatUint(clockTickMs, 10))
	}
	if hashType != "" && hashType != "sha256" {
		cmdArgs = append(cmdArgs, "--hash-type", hashType)
	}
	if storage != "" {
		cmdArgs = append(cmdArgs, "-storage", storage)
	}
	if httpAddr != "" {
		cmdArgs = append(cmdArgs, "-http-addr", httpAddr, "-http-path", httpPath)
	}
	if wsAddr != "" {
		cmdArgs = append(cmdArgs, "-ws-addr", wsAddr, "-ws-path", wsPath)
	}
	if poll.pollAddr != "" {
		cmdArgs = append(cmdArgs, "-http-poll-addr", poll.pollAddr)
	}
	if poll.mountOnLive {
		cmdArgs = append(cmdArgs, "-http-poll-mount-on-live")
	}
	if poll.pollPrefix != "" && poll.pollPrefix != "/poll" {
		cmdArgs = append(cmdArgs, "-http-poll-prefix", poll.pollPrefix)
	}
	if poll.serveNamespace != "" {
		cmdArgs = append(cmdArgs, "-serve-namespace", poll.serveNamespace)
	}
	if poll.serveWholeStore {
		cmdArgs = append(cmdArgs, "-serve-scope-whole-store")
	}
	if poll.serveClosureRoot {
		cmdArgs = append(cmdArgs, "-serve-closure-root")
	}
	if poll.validate {
		cmdArgs = append(cmdArgs, "-validate")
	}
	if poll.signalingNode {
		cmdArgs = append(cmdArgs, "-signaling-node")
	}
	if poll.reflectionEndpoints != "" {
		cmdArgs = append(cmdArgs, "-reflection-endpoint", poll.reflectionEndpoints)
	}
	if poll.publishRoot {
		cmdArgs = append(cmdArgs, "-publish-root")
	}
	if poll.publishPrefix != "" {
		cmdArgs = append(cmdArgs, "-publish-prefix", poll.publishPrefix)
	}
	if poll.publishDescriptors {
		cmdArgs = append(cmdArgs, "-publish-descriptors")
	}
	if poll.discoveryAnnounce != "" {
		cmdArgs = append(cmdArgs, "-discovery-announce", poll.discoveryAnnounce)
	}
	if poll.issuerPolicyMode != "" {
		cmdArgs = append(cmdArgs, "-issuer-policy-mode", poll.issuerPolicyMode)
		if poll.issuerPolicyAllowlist != "" {
			cmdArgs = append(cmdArgs, "-issuer-policy-allowlist", poll.issuerPolicyAllowlist)
		}
		if poll.issuerPolicyNameConstraints != "" {
			cmdArgs = append(cmdArgs, "-issuer-policy-name-constraints", poll.issuerPolicyNameConstraints)
		}
		if poll.issuerPolicyDefaultTTL != "" {
			cmdArgs = append(cmdArgs, "-issuer-policy-default-ttl", poll.issuerPolicyDefaultTTL)
		}
		if poll.issuerPolicyMaxTTL != "" {
			cmdArgs = append(cmdArgs, "-issuer-policy-max-ttl", poll.issuerPolicyMaxTTL)
		}
	}
	if poll.peerIssuedRegistry != "" {
		cmdArgs = append(cmdArgs, "-peer-issued-registry", poll.peerIssuedRegistry)
		if poll.substituteAllowHTTP {
			cmdArgs = append(cmdArgs, "-substitute-allow-http")
		}
	}
	if inboxRelayRegistry != "" {
		cmdArgs = append(cmdArgs, "-inbox-relay-registry", inboxRelayRegistry)
	}
	cmdArgs = append(cmdArgs, keepalive.args("-")...)

	peerBin := findGoBinary()

	cmd := exec.Command(peerBin, cmdArgs...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = detachProcessGroup()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Go peer: %v\n", err)
		os.Exit(1)
	}

	// Wait for ready file.
	var readyData struct {
		Addr   string `json:"addr"`
		PeerID string `json:"peer_id"`
	}

	timeout := time.After(10 * time.Second)
poll:
	for {
		select {
		case <-timeout:
			cmd.Process.Kill()
			fmt.Fprintf(os.Stderr, "Timeout waiting for Go peer %q to become ready\n", name)
			os.Exit(1)
		default:
			data, err := os.ReadFile(readyFile)
			if err == nil {
				if err := json.Unmarshal(data, &readyData); err == nil && readyData.Addr != "" {
					break poll
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	os.Remove(readyFile)

	return &PeerEntry{
		PID:       cmd.Process.Pid,
		Addr:      readyData.Addr,
		WSAddr:    wsAddr,
		PeerID:    readyData.PeerID,
		Name:      name,
		ReadyFile: readyFile,
		LogFile:   logFile,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Owner:     currentOwner(),
	}
}

func findGoBinary() string {
	binDir := filepath.Join(stateDir(), "bin")
	os.MkdirAll(binDir, 0755)
	binPath := filepath.Join(binDir, "entity-peer")

	fmt.Fprintf(os.Stderr, "Building entity-peer...\n")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/entity-peer")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: go build failed: %v\n", err)
		os.Exit(1)
	}
	return binPath
}

// --- Rust peer ---

func startRustPeer(name, addr string, debug bool, storage, history, files, httpAddr, httpPath, wsAddr, keyType, hashType string, relayStoreRetentionMs, relayMaxStorageBytes uint64, keepalive keepaliveSpec, poll chunkEFlags, logFile, seedPolicyFile string, lf *os.File) *PeerEntry {
	requirePodman()
	rustDir := findRustDir()
	rustImage := envOr("ENTITY_RUST_IMAGE", defaultRustImage)
	ensureImage(rustDir, rustImage)

	// Containers run with --network host and there's no ready-file mechanism,
	// so pin a concrete port up front.
	addr = resolveAddr(addr)

	spec := containerSpec{
		name:       name,
		image:      rustImage,
		homeEntity: rustHomeEntity, // rust runtime image runs as root
		userns:     false,          // container root maps to host user; bind-mount is writable without keep-id
		filesArg:   files,
		addr:       addr,
		logFile:    logFile,
		lf:         lf,
	}

	// Ensure the peer identity exists (init if needed). [historical] Rust 7b48eda ships
	// `peer init --key-type {ed25519|ed448}`; `peer start` auto-detects from
	// the algorithm-tagged PEM header. Run it as a one-shot container so the
	// keypair lands in the bind-mounted ~/.entity/peers.
	initArgs := []string{"peer", "init", name}
	if keyType != "" {
		initArgs = append(initArgs, "--key-type", keyType)
	}
	initRun := spec.podmanRunBase(rustImage)
	initRun = append(initRun, initArgs...)
	initCheck := exec.Command("podman", initRun...)
	initCheck.Stderr = lf
	initCheck.Stdout = lf
	initCheck.Run() // Ignore error — may already exist.

	// Build command: entity peer -v start <name> -l <addr> [--debug-grants | --seed-policy <file>]
	cmdArgs := []string{"peer", "-v"}
	if debug {
		cmdArgs = append(cmdArgs, "--trace-entities")
	}
	cmdArgs = append(cmdArgs, "start", name, "-l", addr)
	// Admission posture. --debug-grants is the default open floor; the
	// admin-seeded-restrictive posture replaces it with a --seed-policy file
	// (keystone canonical container, read by rust's with_seed_policy_from_file).
	// Rust REFUSES the two together at the clap level (open grants would hide the
	// exact gate the policy declares), so it is one XOR the other — never both.
	if seedPolicyFile != "" {
		cmdArgs = append(cmdArgs, "--seed-policy", containerSeedPolicyPath(seedPolicyFile, spec.homeEntity))
	} else {
		cmdArgs = append(cmdArgs, "--debug-grants")
	}
	if storage != "" {
		cmdArgs = append(cmdArgs, "--storage", storage)
	}
	if history != "" {
		cmdArgs = append(cmdArgs, "--history", history)
	}
	if hashType != "" && hashType != "sha256" {
		// Rust --hash-type sets the peer's home (content) format. Read in the
		// live tree at 0480712 (cmd/entity-peer/src/commands/peer.rs,
		// 2026-08-10); the pin this comment used to carry (0616727) resolves
		// in no sibling repo, so the capability was right and the provenance
		// was fiction.

		cmdArgs = append(cmdArgs, "--hash-type", hashType)
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "--files", files)
	}
	if httpAddr != "" {
		// [historical] Rust 474bb11: --http-listen / --http-path. Same semantics as
		// Go's -http-addr / -http-path.
		cmdArgs = append(cmdArgs, "--http-listen", httpAddr, "--http-path", httpPath)
	}
	if wsAddr != "" {
		// Rust ships --ws-listen (NETWORK §6.5.2b). No --ws-path on the
		// Rust side — the path is fixed by Rust's WebSocketListener and
		// the published profile derives the URL from socket_addr; Go's
		// configurable --ws-path is a Go-side extension. For interop we
		// just pass --ws-listen.
		cmdArgs = append(cmdArgs, "--ws-listen", wsAddr)
	}
	// EXTENSION-RELAY §8.1/§8.2 (v1.3) store bounds. Rust matched the Go flag
	// strings deliberately (rust 411bee4 §3), so the forward is mechanical —
	// double-dash `--flag value` form. Arming a rust relay lets validate-complete.sh
	// PASS 4 (relay_store_bounds) score it instead of a trivial go-only skip.
	if relayStoreRetentionMs > 0 {
		cmdArgs = append(cmdArgs, "--relay-store-retention-ms", strconv.FormatUint(relayStoreRetentionMs, 10))
	}
	if relayMaxStorageBytes > 0 {
		cmdArgs = append(cmdArgs, "--relay-max-storage-bytes", strconv.FormatUint(relayMaxStorageBytes, 10))
	}
	// Chunk E flags ([historical] Rust 58d9188 — same flag names as cohort convergence).
	if poll.pollAddr != "" {
		cmdArgs = append(cmdArgs, "--http-poll-addr", poll.pollAddr)
	}
	if poll.mountOnLive {
		cmdArgs = append(cmdArgs, "--http-poll-mount-on-live")
	}
	if poll.pollPrefix != "" && poll.pollPrefix != "/poll" {
		cmdArgs = append(cmdArgs, "--http-poll-prefix", poll.pollPrefix)
	}
	if poll.serveNamespace != "" {
		cmdArgs = append(cmdArgs, "--serve-namespace", poll.serveNamespace)
	}
	if poll.serveWholeStore {
		// Rust handoff notes v1 ships namespace-only; warn.
		// Rust ships serve_namespace AND serve_closure_root but NOT
		// serve_scope_whole_store — enumerated across PeerAction::Start, not
		// grepped for one name. This warning said "v1 ships namespace-only",
		// which stopped being true when 3e9c9fc [historical] added the closure
		// scope; the DROP is still correct, the reason given for it was not.
		fmt.Fprintf(os.Stderr, "Warning: --serve-scope-whole-store ignored for type=rust (rust has serve-namespace + serve-closure-root; no whole-store opt-in)\n")
	}
	if poll.serveClosureRoot {
		// R1 ([historical] Rust 3e9c9fc): --serve-closure-root CLI flag landed
		// (publishes over the whole peer subtree when paired with --publish-root).
		cmdArgs = append(cmdArgs, "--serve-closure-root")
	}
	if poll.validate {
		cmdArgs = append(cmdArgs, "--validate")
	}
	if poll.publishRoot {
		cmdArgs = append(cmdArgs, "--publish-root")
	}
	if poll.signalingNode {
		// Rust 2026-08-08: the §4/§5 node role installs through the same
		// public PeerBuilder::handler seam entity-signaling-node uses, so any
		// peer can serve it. Rust's own flag doc requires pairing it with an
		// admission posture — the handler is registered but grants nobody
		// access, and without one every verb is 403 at the §4.4 floor. The
		// default --debug-grants above supplies that pairing; the
		// admin-seeded-restrictive posture (--seed-policy, no --debug-grants) is
		// for gating validation, not for serving a signaling node, and the two
		// are not combined.
		cmdArgs = append(cmdArgs, "--signaling-node")
	}
	if poll.publishDescriptors {
		// R5 ([historical] Rust 3e9c9fc): --publish-descriptors CLI flag landed.
		cmdArgs = append(cmdArgs, "--publish-descriptors")
	}
	if poll.peerIssuedRegistry != "" {
		// [historical] Rust 5c58195: the live remote-read seam landed (RegistryTreeReader +
		// HttpPollRegistryReader over a poll_read module), so the pin now
		// reaches the wire instead of resolving against the local store. Until
		// then this passthrough did not exist and the category SKIPped.
		//
		// Rust's flag is REPEATABLE (`Vec<String>`), not comma-separated like
		// Go's single string — pinning several registries means several
		// occurrences, tried in flag order. Split here rather than handing
		// clap a comma-joined value it would take as one malformed spec.
		for _, spec := range strings.Split(poll.peerIssuedRegistry, ",") {
			if spec = strings.TrimSpace(spec); spec != "" {
				cmdArgs = append(cmdArgs, "--peer-issued-registry", spec)
			}
		}
	}
	if poll.publishPrefix != "" {
		// Absent from both sibling CLIs — established by enumerating rust's full
		// PeerAction::Start arg set and python's full argparse surface, at the
		// siblingPin* commits. Passing it would be rejected at startup, so
		// drop it and SAY SO — a silently dropped scope flag would publish the
		// peer's default subtree while the operator believed it had narrowed.
		fmt.Fprintf(os.Stderr, "Warning: --publish-prefix ignored for this peer type (Go-only; the peer publishes its own default subtree)\n")
	}
	if poll.reflectionEndpoints != "" {
		// EXTENSION-SIGNALING §4.5.1 reflection_endpoints is unbuilt in this
		// sibling as of 2026-08-15 (source-read; arch routed it P0 to rust). A
		// node that cannot advertise its reflector is not a bug — the field is
		// OPTIONAL and absent means host-candidates-only — so drop it and SAY SO
		// rather than pass a flag the sibling CLI would reject at startup.
		fmt.Fprintf(os.Stderr, "Warning: --reflection-endpoint ignored for this peer type (Go-only; the sibling has no §4.5.1 reflection_endpoints surface yet)\n")
	}
	if poll.discoveryAnnounce != "" {
		// Dropped for RUST only, and now for a verified reason rather than a
		// carried one: rust's `PeerAction::Start` has no discovery flag at all
		// (enumerated in full, not grepped). Python HAS the flag and is now
		// forwarded — see startPythonPeer. Until 2026-08-12 (e) this branch was
		// duplicated verbatim into the python path on a stale "Go-only" belief,
		// which is the concrete cost of the G-7 defect class: the claim did not
		// merely read wrong, it silently disabled a sibling capability the
		// operator had asked for, and this warning made the skip look
		// deliberate.
		fmt.Fprintf(os.Stderr, "Warning: --discovery-announce ignored for type=rust (no CLI flag in PeerAction::Start; the `:announce` operation itself is cross-impl and covered by discovery.v7a_announce_lifecycle)\n")
	}
	if poll.issuerPolicyMode != "" {
		// The §6a.9 handler exists in all three (rust
		// extensions/registry/src/registration.rs, python
		// packages/entity-handlers/.../registry.py; both re-read at the
		// siblingPin* commits) — what differs is only how it is ARMED, and
		// dropping this flag costs NOTHING for either sibling.
		//
		// TWO CORRECTIONS, 2026-08-12 (e). This comment said python "arms over
		// the wire via a `set-issuer-policy` operation that go and rust do not
		// implement." Both halves were wrong: rust registers the op (it is in
		// the `registry-peer-issued` bootstrap op list beside the three write
		// verbs, core/peer/src/lib.rs) and go implements it too — the
		// registry_issuer category's three set_issuer_policy_* checks PASS
		// against all three. And rust registers its RegisterRequestHandler
		// UNCONDITIONALLY, inert until an issuer-policy is written, exactly like
		// python.
		//
		// So the arming divergence is narrower than this said: it is a CLI
		// convenience only. The category writes system/registry/issuer-policy
		// itself, so `registry_issuer` is fully reachable against both siblings
		// with no flag at all — measured 2026-08-12 (e): python 19/19,
		// rust 17/19 (the two manual-mode rows, which is the arch-ruled
		// register-result gap, not an arming gap).
		fmt.Fprintf(os.Stderr, "Warning: --issuer-policy-mode ignored for this peer type (Go's CLI arming mechanism only; rust and python register the handler unconditionally and are armed over the wire by the validator's own set-issuer-policy call, so no coverage is lost)\n")
	}
	// §2.3 keepalive overrides ([historical] Rust 99ff398 — same flag names as Go and
	// Python in clap's double-dash dialect; omitted fields keep spec defaults).
	cmdArgs = append(cmdArgs, keepalive.args("--")...)

	spec.args = cmdArgs
	entry := runContainerPeer(spec)
	entry.WSAddr = wsAddr
	return entry
}

// findRustDir locates the Rust sibling repo (the directory whose `make build`
// produces the entity-core-rust image). Env override: ENTITY_RUST_DIR.
func findRustDir() string {
	projectDir := os.Getenv("ENTITY_RUST_DIR")
	if projectDir == "" {
		if abs, err := filepath.Abs("../entity-core-rust"); err == nil {
			if _, err := os.Stat(filepath.Join(abs, "Makefile")); err == nil {
				projectDir = abs
			}
		}
	}
	if projectDir == "" {
		fmt.Fprintf(os.Stderr, "Error: Rust project not found.\n")
		fmt.Fprintf(os.Stderr, "  Set ENTITY_RUST_DIR or ensure ../entity-core-rust/ exists\n")
		os.Exit(1)
	}
	return projectDir
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// discoverPeerID connects to a freshly-started peer and returns its peer_id via
// the hello handshake. Impl-agnostic — works for rust/python containers (which
// have no ready-file) the same as for Go. Uses the validate package's
// PeerClient (the same handshake the conformance suite uses) rather than a
// shell-out, which is both more reliable and avoids a redundant `go run`.
func discoverPeerID(addr string) string {
	client, err := validate.NewPeerClient(addr)
	if err != nil {
		return "(connect to discover)"
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return "(connect to discover)"
	}
	// PerformHandshake's side effect populates remotePeerID from the peer's
	// hello reply; the returned conformance checks are not needed here.
	client.PerformHandshake(ctx)
	if id := string(client.RemotePeerID()); id != "" {
		return id
	}
	return "(connect to discover)"
}

// --- Python peer ---

func startPythonPeer(name, addr string, debug, openAccess bool, history, files, httpAddr, httpPath, keyType, hashType string, relayStoreRetentionMs, relayMaxStorageBytes uint64, keepalive keepaliveSpec, poll chunkEFlags, logFile, seedPolicyFile string, lf *os.File) *PeerEntry {
	// Identity provisioning. [historical] Python 91f8f77 ships the algorithm-tagged PEM
	// loader, so the prior Ed448 skip can drop.
	if err := ensureIdentity(name, keyType); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create identity %q: %v (falling back to 'default')\n", name, err)
		name = "default"
	}

	requirePodman()
	pyDir := findPythonProject()
	pyImage := envOr("ENTITY_PYTHON_IMAGE", defaultPythonImage)
	ensureImage(pyDir, pyImage)

	// Containers run with --network host and there's no ready-file mechanism,
	// so pin a concrete port up front.
	addr = resolveAddr(addr)

	// Command: entity-core start --listen ADDR --identity NAME [--debug] [--open-access] [--key-type]
	// The entrypoint is `entity-core`, so args start at the subcommand.
	cmdArgs := []string{"start", "--listen", addr, "--identity", name}
	if keyType != "" && keyType != "ed25519" {
		// [historical] Python ships --key-type from f231406 (v7.67 Phase 2 backend).
		// Forward only when non-default so older Python builds without the
		// flag still work for ed25519 identities.
		cmdArgs = append(cmdArgs, "--key-type", keyType)
	}
	// Python's --debug ALSO turns on open-access (main.py: open_access =
	// bool(args.debug) or …), so under the admin-seeded-restrictive posture it
	// would silently re-open the very gate the seed policy declares. Suppress it
	// there — the trace output is not worth defeating the posture. (Rust keeps its
	// --trace-entities under the same posture because rust does NOT conflate the
	// two; only python does.)
	if debug && seedPolicyFile == "" {
		cmdArgs = append(cmdArgs, "--debug")
	}
	if seedPolicyFile != "" {
		// Admin-seeded-restrictive: the keystone canonical container, read by
		// python's with_seed_policy_from_file. The admin identity gets write;
		// unknown peers stay gated. Mutually exclusive with --open-access (set
		// false by the dispatcher) and --debug (suppressed above).
		cmdArgs = append(cmdArgs, "--seed-policy", containerSeedPolicyPath(seedPolicyFile, pythonHomeEntity))
	} else if openAccess {
		// Python's open-access flag — cross-impl-aligned with Go's --open-access
		// and Rust's --debug-grants. Without this, the Python peer narrows
		// authorization on system/inbox/* reads/extracts/merges, producing
		// 403s that look like a Python defect but are actually a config gap.
		cmdArgs = append(cmdArgs, "--open-access")
	}
	if history != "" {
		// Python --history takes just the pattern, no :max_depth suffix.
		pattern := history
		if idx := strings.LastIndexByte(pattern, ':'); idx >= 0 {
			// Check if the part after : is all digits (max_depth) — strip it.
			suffix := pattern[idx+1:]
			allDigits := true
			for _, c := range suffix {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && len(suffix) > 0 {
				pattern = pattern[:idx]
			}
		}
		cmdArgs = append(cmdArgs, "--history", pattern)
	}
	if hashType != "" && hashType != "sha256" {
		// Python ships --hash-type (packages/entity-cli/.../main.py). Read in
		// the live tree at e60c822, 2026-08-10; the pin this comment used to
		// carry (ff6d1e2) resolves in no sibling repo.

		cmdArgs = append(cmdArgs, "--hash-type", hashType)
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "--files", files)
	}
	if httpAddr != "" {
		// Python aligned with --http-addr / --http-path (Amendment 3).
		cmdArgs = append(cmdArgs, "--http-addr", httpAddr, "--http-path", httpPath)
	}
	// EXTENSION-RELAY §8.1/§8.2 (v1.3) store bounds. Python matched the Go flag
	// strings deliberately (py ROUTING-2026-09-01-b §2.1), so the forward is
	// mechanical — double-dash `--flag value` form. Arming a python relay lets
	// validate-complete.sh PASS 4 (relay_store_bounds) score it.
	if relayStoreRetentionMs > 0 {
		cmdArgs = append(cmdArgs, "--relay-store-retention-ms", strconv.FormatUint(relayStoreRetentionMs, 10))
	}
	if relayMaxStorageBytes > 0 {
		cmdArgs = append(cmdArgs, "--relay-max-storage-bytes", strconv.FormatUint(relayMaxStorageBytes, 10))
	}
	// Chunk E flags ([historical] Python 74b3335 — same flag names as cohort convergence).
	if poll.pollAddr != "" {
		cmdArgs = append(cmdArgs, "--http-poll-addr", poll.pollAddr)
	}
	if poll.mountOnLive {
		cmdArgs = append(cmdArgs, "--http-poll-mount-on-live")
	}
	if poll.pollPrefix != "" && poll.pollPrefix != "/poll" {
		cmdArgs = append(cmdArgs, "--http-poll-prefix", poll.pollPrefix)
	}
	if poll.serveNamespace != "" {
		cmdArgs = append(cmdArgs, "--serve-namespace", poll.serveNamespace)
	}
	if poll.serveWholeStore {
		cmdArgs = append(cmdArgs, "--serve-scope-whole-store")
	}
	if poll.validate {
		cmdArgs = append(cmdArgs, "--validate")
	}
	if poll.publishRoot {
		cmdArgs = append(cmdArgs, "--publish-root")
	}
	if poll.serveClosureRoot {
		// Python's --serve-closure-root takes a PATH; "published" binds to
		// the current system/peer/published-root head (main.py:898).
		cmdArgs = append(cmdArgs, "--serve-closure-root", "published")
	}
	if poll.signalingNode {
		// Python 2026-08-08: §4/§5 node role landed (keyed mailbox, §5's six
		// pins, §8.2 rate limiting per source and per key), off by default —
		// same posture as Go and Rust: client by default, only a deployed
		// introducer serves. Without this passthrough the 7 signaling vectors
		// skipped against a peer that passes them when driven directly.
		cmdArgs = append(cmdArgs, "--signaling-node")
	}
	if poll.publishDescriptors {
		// Python's --publish-descriptors landed (entity_cli/main.py). This was
		// warn-and-dropped for two handoffs on a "CLI surface pending" note
		// that had gone stale — the warning outlived the gap it described,
		// which is its own kind of silent skip.
		cmdArgs = append(cmdArgs, "--publish-descriptors")
	}
	if poll.peerIssuedRegistry != "" {
		// Python 2026-08-08: --peer-issued-registry takes the same
		// `peer_id@url` spec as Go and installs BOTH halves (trust root + §4
		// resolver-chain entry). No allow-http gate on their side. Containers
		// run --network host, so a 127.0.0.1 fixture URL resolves to the same
		// loopback the validator serves on.
		cmdArgs = append(cmdArgs, "--peer-issued-registry", poll.peerIssuedRegistry)
	}
	if poll.publishPrefix != "" {
		// Absent from both sibling CLIs — established by enumerating rust's full
		// PeerAction::Start arg set and python's full argparse surface, at the
		// siblingPin* commits. Passing it would be rejected at startup, so
		// drop it and SAY SO — a silently dropped scope flag would publish the
		// peer's default subtree while the operator believed it had narrowed.
		fmt.Fprintf(os.Stderr, "Warning: --publish-prefix ignored for this peer type (Go-only; the peer publishes its own default subtree)\n")
	}
	if poll.reflectionEndpoints != "" {
		// EXTENSION-SIGNALING §4.5.1 reflection_endpoints is unbuilt in this
		// sibling as of 2026-08-15 (source-read; arch routed it P0 to rust). A
		// node that cannot advertise its reflector is not a bug — the field is
		// OPTIONAL and absent means host-candidates-only — so drop it and SAY SO
		// rather than pass a flag the sibling CLI would reject at startup.
		fmt.Fprintf(os.Stderr, "Warning: --reflection-endpoint ignored for this peer type (Go-only; the sibling has no §4.5.1 reflection_endpoints surface yet)\n")
	}
	if poll.discoveryAnnounce != "" {
		// FORWARDED as of 2026-08-12 (e). Python has had this flag; we were
		// dropping it on a stale "Go-only" belief copied from the rust branch.
		//
		// The SHAPES DIVERGE and the translation is the substance: Go's
		// -discovery-announce takes the profile_ref as its VALUE, while python
		// splits it in two — --discovery-announce is a `store_true` and the ref
		// goes in --discovery-profile (default "tcp"). One Go flag becomes two
		// python flags, so this is a translation, not a rename.
		cmdArgs = append(cmdArgs, "--discovery-announce",
			"--discovery-profile", poll.discoveryAnnounce)
	}
	if poll.issuerPolicyMode != "" {
		// The §6a.9 handler exists in all three (rust
		// extensions/registry/src/registration.rs, python
		// packages/entity-handlers/.../registry.py; both re-read at the
		// siblingPin* commits) — what differs is only how it is ARMED, and
		// dropping this flag costs NOTHING for either sibling.
		//
		// TWO CORRECTIONS, 2026-08-12 (e). This comment said python "arms over
		// the wire via a `set-issuer-policy` operation that go and rust do not
		// implement." Both halves were wrong: rust registers the op (it is in
		// the `registry-peer-issued` bootstrap op list beside the three write
		// verbs, core/peer/src/lib.rs) and go implements it too — the
		// registry_issuer category's three set_issuer_policy_* checks PASS
		// against all three. And rust registers its RegisterRequestHandler
		// UNCONDITIONALLY, inert until an issuer-policy is written, exactly like
		// python.
		//
		// So the arming divergence is narrower than this said: it is a CLI
		// convenience only. The category writes system/registry/issuer-policy
		// itself, so `registry_issuer` is fully reachable against both siblings
		// with no flag at all — measured 2026-08-12 (e): python 19/19,
		// rust 17/19 (the two manual-mode rows, which is the arch-ruled
		// register-result gap, not an arming gap).
		fmt.Fprintf(os.Stderr, "Warning: --issuer-policy-mode ignored for this peer type (Go's CLI arming mechanism only; rust and python register the handler unconditionally and are armed over the wire by the validator's own set-issuer-policy call, so no coverage is lost)\n")
	}
	// §2.3 keepalive overrides ([historical] Python 0a0eb48 — same flag names as the Go
	// peer in argparse's double-dash dialect; omitted fields keep spec defaults).
	cmdArgs = append(cmdArgs, keepalive.args("--")...)

	return runContainerPeer(containerSpec{
		name:       name,
		image:      pyImage,
		homeEntity: pythonHomeEntity, // python runtime image runs as USER entity
		userns:     true,             // map host uid 1000 → container `entity` (1000) so the bind-mount is writable
		filesArg:   files,
		args:       cmdArgs,
		addr:       addr,
		logFile:    logFile,
		lf:         lf,
	})
}

// findPythonProject locates the Python entity-core project directory.
func findPythonProject() string {
	projectDir := os.Getenv("ENTITY_PYTHON_DIR")
	if projectDir == "" {
		candidates := []string{
			"../entity-core-py",
		}
		for _, c := range candidates {
			if abs, err := filepath.Abs(c); err == nil {
				if _, err := os.Stat(filepath.Join(abs, "pyproject.toml")); err == nil {
					projectDir = abs
					break
				}
			}
		}
	}
	if projectDir == "" {
		fmt.Fprintf(os.Stderr, "Error: Python project not found.\n")
		fmt.Fprintf(os.Stderr, "  Set ENTITY_PYTHON_DIR or ensure ../entity-core-py/ exists\n")
		os.Exit(1)
	}
	return projectDir
}

// wireRemote writes Peer A's transport address to Peer B's tree so B can reach A.
func wireRemote(state *State, localName, remoteName string) {
	remoteEntry, ok := state.Peers[remoteName]
	if !ok || !isAlive(remoteEntry.PID) {
		fmt.Fprintf(os.Stderr, "Warning: remote peer %q not found or not running, skipping remote wiring\n", remoteName)
		return
	}

	localEntry := state.Peers[localName]

	fmt.Printf("Remote: %s knows about %s (addr=%s, peer_id=%s)\n", localName, remoteName, remoteEntry.Addr, remoteEntry.PeerID)
	fmt.Printf("  To wire: PUT system/peer/transport/%s on %s\n", remoteEntry.PeerID, localEntry.Addr)
}
