package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/cmd/internal/validate"
)

func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	name := fs.String("name", "", "peer name (required)")
	peerType := fs.String("type", "go", "peer type: go, rust, python")
	addr := fs.String("addr", "127.0.0.1:0", "listen address (default: random port)")
	openAccess := fs.Bool("open-access", true, "grant open access to connecting peers")
	debug := fs.Bool("debug", false, "enable debug logging")
	storage := fs.String("storage", "", "storage backend: memory (default), sqlite (go + rust)")
	files := fs.String("files", "", "expose filesystem directory (format: name:/path:tree/prefix/) — supported by all three impls' --files flag")
	history := fs.String("history", "*", "history recording pattern (default: \"*\" records all; use \"\" to disable)")
	remote := fs.String("remote", "", "register a remote peer by name (must already be running)")
	httpAddr := fs.String("http-addr", "", "additional HTTP-live listener address (e.g. 127.0.0.1:0 for random; empty disables). Chunk D / Amendment 3. Go supports; Rust + Python CLI wiring pending.")
	httpPath := fs.String("http-path", "/entity", "URL path the HTTP-live listener accepts POSTs at (when --http-addr set)")
	wsAddr := fs.String("ws-addr", "", "additional WebSocket-live listener address (e.g. 127.0.0.1:9501; --ws-addr does not yet accept :0 because the port is needed to construct the ws:// URL). Thread F (NETWORK §6.5.2b). Go-only initially; Rust wiring is feature-gated and Python has no WS listener.")
	wsPath := fs.String("ws-path", "/ws", "URL path the WebSocket listener accepts upgrades at (when --ws-addr set)")
	// Chunk E serving-mode flags (Go-only initially; Rust + Python add equivalents during E impl).
	httpPollAddr := fs.String("http-poll-addr", "", "Chunk E: isolated HTTP poll listener (e.g. 127.0.0.1:9201); GET /content/{hex(H)}. Mutually exclusive with --http-poll-mount-on-live.")
	httpPollMountOnLive := fs.Bool("http-poll-mount-on-live", false, "Chunk E: mount poll routes on the live HTTP listener (Posture 2). Requires --http-addr.")
	httpPollPrefix := fs.String("http-poll-prefix", "/poll", "Chunk E: URL prefix when mounting poll on live listener (default /poll); ignored on isolated port.")
	serveNamespace := fs.String("serve-namespace", "", "Chunk E: content-namespace scope (e.g. system/content/public). Tree binding at NAMESPACE/{hex(H)} = in-scope.")
	serveWholeStore := fs.Bool("serve-scope-whole-store", false, "Chunk E: DEBUG OPT-IN — serve every H in local content-store (ruling §1.3 T2/T3 caveat).")
	keyType := fs.String("key-type", "ed25519", "peer keypair algorithm: ed25519 (default) | ed448 (v7.67 §3). Applies when minting a new identity for this peer; honored by Go (--key-type), Python (--key-type), and forwarded to Rust once its CLI lands.")
	hashType := fs.String("hash-type", "sha256", "content_hash_format / home format the peer authors content + substrate under: sha256 (default, 0x00) | sha384 (0x01). V7 v7.70 §1.2. Honored by Go (--hash-type), Rust (--hash-type, post-v7.70 0616727), Python (--hash-type).")
	inboxRelayRegistry := fs.String("inbox-relay-registry", "", "EXTENSION-RELAY §3.5 REGISTRY-served inbox-relay decl chain (Go-only initially): comma-separated peer-names of registries to consult (in order). The names are translated to peer-ids from state. Forwarded as --inbox-relay-registry to entity-peer.")
	validate := fs.Bool("validate", false, "GUIDE-CONFORMANCE §7a: enable system/validate/echo + system/validate/dispatch-outbound test handlers (unblocks concurrency.t1_2_concurrent_reentry). MUST NOT be on in production. Honored by all three impls.")
	publishRoot := fs.Bool("publish-root", false, "PROPOSAL-PEER-MANIFEST §4: mint signed system/peer/published-root on every tree-root change + serve via http-poll. Pair with --http-poll-addr to expose the manifest on the wire. Honored by all three impls.")
	serveClosureRoot := fs.Bool("serve-closure-root", false, "EXTENSION-NETWORK §6.5.6 Amendment 10: scope served set to the transitive trie-node closure reachable from system/peer/published-root. Pair with --publish-root so a consumer's signed-root hash-chain walk does not 404 on a CHAMP interior node. Mutually exclusive with --serve-namespace / --serve-scope-whole-store. Honored by Go + Python (Rust impl pending).")
	publishDescriptors := fs.Bool("publish-descriptors", false, "DOMAIN-LOCAL-FILES v1.3 §10.5 V3: configure the --files root with publish_descriptors=true so file reads write `system/content/descriptor/{hash}` entities into the tree. Arms local_files.v3_descriptor_publish_exercised. Honored by Go; Rust + Python impl pending.")
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
		pollAddr:           *httpPollAddr,
		mountOnLive:        *httpPollMountOnLive,
		pollPrefix:         *httpPollPrefix,
		serveNamespace:     *serveNamespace,
		serveWholeStore:    *serveWholeStore,
		serveClosureRoot:   *serveClosureRoot,
		validate:           *validate,
		publishRoot:        *publishRoot,
		publishDescriptors: *publishDescriptors,
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

	switch *peerType {
	case "go":
		entry = startGoPeer(*name, *addr, *debug, *openAccess, *files, *history, *storage, *httpAddr, *httpPath, *wsAddr, *wsPath, *keyType, *hashType, registryPeerIDs, pollFlags, logFile, lf)
	case "rust":
		// Rust 474bb11 (Chunk D), 58d9188 (Chunk E flags), 0616727 (v7.70 home-format).
		// Rust ships --ws-listen for NETWORK §6.5.2b; cohort flag string is
		// --ws-addr at the peer-manager boundary, translated below.
		entry = startRustPeer(*name, *addr, *debug, *storage, *history, *files, *httpAddr, *httpPath, *wsAddr, *keyType, *hashType, pollFlags, logFile, lf)
	case "python":
		// Python aligned with Chunk D and 74b3335 (Chunk E flags); Python
		// ships --key-type from f231406 and --hash-type from ff6d1e2 (v7.70).
		if *wsAddr != "" {
			fmt.Fprintf(os.Stderr, "Note: --ws-addr has no Python equivalent; ignored for Python peer %q\n", *name)
		}
		entry = startPythonPeer(*name, *addr, *debug, *openAccess, *history, *files, *httpAddr, *httpPath, *keyType, *hashType, pollFlags, logFile, lf)
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
	publishRoot        bool
	publishDescriptors bool
}

// enabled reports whether serving-mode was requested.
func (f chunkEFlags) enabled() bool {
	return f.pollAddr != "" || f.mountOnLive
}

// --- Go peer ---

func startGoPeer(name, addr string, debug, openAccess bool, files, history, storage, httpAddr, httpPath, wsAddr, wsPath, keyType, hashType, inboxRelayRegistry string, poll chunkEFlags, logFile string, lf *os.File) *PeerEntry {
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
	if debug {
		cmdArgs = append(cmdArgs, "-debug")
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "-files", files)
	}
	if history != "" {
		cmdArgs = append(cmdArgs, "-history", history)
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
	if poll.publishRoot {
		cmdArgs = append(cmdArgs, "-publish-root")
	}
	if poll.publishDescriptors {
		cmdArgs = append(cmdArgs, "-publish-descriptors")
	}
	if inboxRelayRegistry != "" {
		cmdArgs = append(cmdArgs, "-inbox-relay-registry", inboxRelayRegistry)
	}

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

func startRustPeer(name, addr string, debug bool, storage, history, files, httpAddr, httpPath, wsAddr, keyType, hashType string, poll chunkEFlags, logFile string, lf *os.File) *PeerEntry {
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
		homeEntity: "/root/.entity", // rust runtime image runs as root
		userns:     false,           // container root maps to host user; bind-mount is writable without keep-id
		filesArg:   files,
		addr:       addr,
		logFile:    logFile,
		lf:         lf,
	}

	// Ensure the peer identity exists (init if needed). Rust 7b48eda ships
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

	// Build command: entity peer -v start <name> -l <addr> --debug-grants
	cmdArgs := []string{"peer", "-v"}
	if debug {
		cmdArgs = append(cmdArgs, "--trace-entities")
	}
	cmdArgs = append(cmdArgs, "start", name, "-l", addr, "--debug-grants")
	if storage != "" {
		cmdArgs = append(cmdArgs, "--storage", storage)
	}
	if history != "" {
		cmdArgs = append(cmdArgs, "--history", history)
	}
	if hashType != "" && hashType != "sha256" {
		// Rust 0616727: --hash-type sets the peer's home (content) format.
		cmdArgs = append(cmdArgs, "--hash-type", hashType)
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "--files", files)
	}
	if httpAddr != "" {
		// Rust 474bb11: --http-listen / --http-path. Same semantics as
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
	// Chunk E flags (Rust 58d9188 — same flag names as cohort convergence).
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
		fmt.Fprintf(os.Stderr, "Warning: --serve-scope-whole-store ignored for type=rust (v1 ships namespace-only per Rust 33b3984)\n")
	}
	if poll.serveClosureRoot {
		// R1 (Rust 3e9c9fc): --serve-closure-root CLI flag landed
		// (publishes over the whole peer subtree when paired with --publish-root).
		cmdArgs = append(cmdArgs, "--serve-closure-root")
	}
	if poll.validate {
		cmdArgs = append(cmdArgs, "--validate")
	}
	if poll.publishRoot {
		cmdArgs = append(cmdArgs, "--publish-root")
	}
	if poll.publishDescriptors {
		// R5 (Rust 3e9c9fc): --publish-descriptors CLI flag landed.
		cmdArgs = append(cmdArgs, "--publish-descriptors")
	}

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

func startPythonPeer(name, addr string, debug, openAccess bool, history, files, httpAddr, httpPath, keyType, hashType string, poll chunkEFlags, logFile string, lf *os.File) *PeerEntry {
	// Identity provisioning. Python 91f8f77 ships the algorithm-tagged PEM
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
		// Python ships --key-type from f231406 (v7.67 Phase 2 backend).
		// Forward only when non-default so older Python builds without the
		// flag still work for ed25519 identities.
		cmdArgs = append(cmdArgs, "--key-type", keyType)
	}
	if debug {
		cmdArgs = append(cmdArgs, "--debug")
	}
	if openAccess {
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
		// Python ff6d1e2 (v7.70 deletion-marker fix) ships --hash-type.
		cmdArgs = append(cmdArgs, "--hash-type", hashType)
	}
	if files != "" {
		cmdArgs = append(cmdArgs, "--files", files)
	}
	if httpAddr != "" {
		// Python aligned with --http-addr / --http-path (Amendment 3).
		cmdArgs = append(cmdArgs, "--http-addr", httpAddr, "--http-path", httpPath)
	}
	// Chunk E flags (Python 74b3335 — same flag names as cohort convergence).
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
	if poll.publishDescriptors {
		// Python local-files takes publish_descriptors via the per-root
		// config; CLI surface pending. Warn-and-drop until Python ships it.
		fmt.Fprintf(os.Stderr, "Warning: --publish-descriptors ignored for type=python (CLI flag pending)\n")
	}

	return runContainerPeer(containerSpec{
		name:       name,
		image:      pyImage,
		homeEntity: "/home/entity/.entity", // python runtime image runs as USER entity
		userns:     true,                    // map host uid 1000 → container `entity` (1000) so the bind-mount is writable
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
