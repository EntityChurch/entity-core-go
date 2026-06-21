package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Rust and Python adopted the make + podman build convention (their
// `w-build-unify` merges): a bare box has only `make` + `podman` — no host
// cargo/uv. The release artifacts live inside runtime images, not at
// target/debug/entity or behind `uv run`. So peer-manager launches non-Go
// peers by running their images instead of host binaries.
//
//	rust:   image `entity-core-rust`, ENTRYPOINT ["entity"],      runs as root (HOME=/root)
//	python: image `entity-core-py`,   ENTRYPOINT ["entity-core"], runs as USER entity (uid 1000, HOME=/home/entity)
//
// Containers use --network host (the peer binds a host-reachable port with no
// -p translation), bind-mount $HOME/.entity into the container home (identity +
// keypairs persist and are shared with host tooling like validate-peer), and
// --security-opt label=disable (no SELinux relabel of the shared ~/.entity, and
// no per-container category conflict when rust + python + go peers run at once).
const (
	defaultRustImage   = "entity-core-rust"
	defaultPythonImage = "entity-core-py"
)

// envOr returns the environment variable value or a fallback default.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// containerName derives a stable, collision-resistant podman container name
// for a managed peer.
func containerName(peerName string) string {
	return "entity-pm-" + peerName
}

// requirePodman exits with a clear message if podman is not on PATH.
func requirePodman() {
	if _, err := exec.LookPath("podman"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: podman not found on PATH.\n")
		fmt.Fprintf(os.Stderr, "  Rust and Python peers run as containers (make + podman convention).\n")
		fmt.Fprintf(os.Stderr, "  Install podman, or run those peers some other way.\n")
		os.Exit(1)
	}
}

// ensureImage (re)builds the peer image via `make build` in the sibling repo so
// the container reflects the latest source — the make+podman analogue of the
// old `cargo build` / `uv run`-from-source behavior. Idempotent: podman
// layer-caches, so an unchanged tree rebuilds in seconds. Set
// ENTITY_PM_SKIP_BUILD=1 to skip and use a pre-built image (e.g. in CI, or when
// iterating on the Go side against an already-built sibling image).
func ensureImage(repoDir, image string) {
	if os.Getenv("ENTITY_PM_SKIP_BUILD") != "" {
		return
	}
	if _, err := exec.LookPath("make"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: make not found on PATH (needed to build the %s image from %s).\n", image, repoDir)
		fmt.Fprintf(os.Stderr, "  Pre-build the image and set ENTITY_PM_SKIP_BUILD=1 to skip this step.\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Building %s image (make build in %s)...\n", image, repoDir)
	build := exec.Command("make", "build")
	build.Dir = repoDir
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: `make build` failed in %s: %v\n", repoDir, err)
		os.Exit(1)
	}
}

// resolveAddr turns a :0 / random-port request into a concrete host:port.
// Containers run with --network host and there is no ready-file mechanism for
// rust/python, so the port must be chosen up front.
func resolveAddr(addr string) string {
	if addr == "127.0.0.1:0" || addr == ":0" || addr == "0.0.0.0:0" {
		port, err := findFreePort()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding free port: %v\n", err)
			os.Exit(1)
		}
		host := "127.0.0.1"
		if addr == "0.0.0.0:0" {
			host = "0.0.0.0"
		}
		return fmt.Sprintf("%s:%d", host, port)
	}
	return addr
}

// filesHostPath extracts the host filesystem path from a --files argument
// (format name:/fs/path:tree/prefix/) so it can be bind-mounted into the
// container at the same path. Returns "" if the argument has no path field.
func filesHostPath(filesArg string) string {
	parts := strings.SplitN(filesArg, ":", 3)
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}
	return ""
}

// containerSpec describes how to launch a containerized peer.
type containerSpec struct {
	name       string   // managed peer name
	image      string   // podman image (entity-core-rust / entity-core-py)
	homeEntity string   // in-container mount target for $HOME/.entity (/root/.entity or /home/entity/.entity)
	userns     bool     // add --userns=keep-id (python: maps host uid 1000 → container `entity` uid 1000)
	filesArg   string   // --files value whose host path is bind-mounted (empty = none)
	args       []string // entrypoint arguments (appended after the image)
	addr       string   // concrete host:port the peer binds (for readiness polling)
	logFile    string
	lf         *os.File
}

// podmanRunBase builds the shared `podman run` prefix (before the image) for a
// spec: resource caps, --network host, the ~/.entity bind-mount, optional
// userns, optional --files bind-mount, and label=disable.
func (s containerSpec) podmanRunBase(extra ...string) []string {
	home, _ := os.UserHomeDir()
	args := []string{"run", "--rm", "--network", "host", "--security-opt", "label=disable"}
	args = append(args, podmanRunCaps()...)
	if s.userns {
		args = append(args, "--userns=keep-id")
	}
	args = append(args, "-v", fmt.Sprintf("%s:%s", filepath.Join(home, ".entity"), s.homeEntity))
	if fsPath := filesHostPath(s.filesArg); fsPath != "" {
		args = append(args, "-v", fmt.Sprintf("%s:%s", fsPath, fsPath))
	}
	return append(args, extra...)
}

// podmanRunCaps returns the per-container resource ceilings applied to every
// peer `podman run` — so a runaway peer (memory leak, fork bomb) is OOM-killed
// at the cap instead of taking the host down. This is the runtime arm of the
// RESOURCE-CAPS.md standard: it honors the same CAP_* env vars (the env layer of
// the precedence chain) but its committed defaults are sized for a *running
// peer* — an in-memory store + network listener, far lighter than a build — not
// the Makefile's build/test defaults. Override per-run with CAP_MEM=… etc.
//
// CAP_SWAP defaults to CAP_MEM (no swap → clean OOM, no host thrash). A peer is
// a `podman run`, which accepts the full flag set (unlike `podman build`).
func podmanRunCaps() []string {
	mem := envOr("CAP_MEM", "2g")
	return []string{
		"--memory=" + mem,
		"--memory-swap=" + envOr("CAP_SWAP", mem),
		"--pids-limit=" + envOr("CAP_PIDS", "1024"),
		"--cpus=" + envOr("CAP_CPUS", "2"),
	}
}

// runContainerPeer launches the peer as an attached, backgrounded `podman run`.
// Attached (not -d) so container stdout/stderr flow straight into the peer log
// file exactly as the old host-process model did, and so the podman client is a
// real host PID that the existing isAlive/list machinery tracks. Teardown is
// container-aware (see stopContainerPeer) because the peers ignore SIGTERM and
// SIGKILLing the attached client would orphan the container.
func runContainerPeer(spec containerSpec) *PeerEntry {
	requirePodman()
	cname := containerName(spec.name)

	// Remove any stale container with this name (a prior crash/SIGKILL can
	// leave one behind; `podman run --name` then fails with "name in use").
	exec.Command("podman", "rm", "-f", cname).Run()

	runArgs := spec.podmanRunBase("--name", cname, spec.image)
	runArgs = append(runArgs, spec.args...)

	cmd := exec.Command("podman", runArgs...)
	cmd.Stdout = spec.lf
	cmd.Stderr = spec.lf
	cmd.SysProcAttr = detachProcessGroup()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting %s container: %v\n", spec.image, err)
		os.Exit(1)
	}

	if !waitForPort(spec.addr, 20*time.Second) {
		exec.Command("podman", "rm", "-f", cname).Run()
		fmt.Fprintf(os.Stderr, "Timeout waiting for %s peer %q at %s\n", spec.image, spec.name, spec.addr)
		fmt.Fprintf(os.Stderr, "  Check logs: %s\n", spec.logFile)
		os.Exit(1)
	}

	peerID := discoverPeerID(spec.addr)

	return &PeerEntry{
		PID:       cmd.Process.Pid,
		Addr:      spec.addr,
		PeerID:    peerID,
		Name:      spec.name,
		Container: cname,
		LogFile:   spec.logFile,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
