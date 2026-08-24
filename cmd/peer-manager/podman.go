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
// the container reflects the latest source — the make+podman analogue of the old
// `cargo build` / `uv run`-from-source behavior.
//
// It is SOURCE-PROVENANCE AWARE, because trusting podman's layer cache alone is
// not safe: a `make build` can report success and hand back a stale image whose
// cache did not invalidate on a source change (observed 2026-07-30 — peer-manager
// served a 36 h-old entity-core-rust image after real fixes had landed, so a
// cross-impl validation run silently tested old code). That is the same
// "green-but-meaningless" failure class the RT-6 fix exposed, one layer down in
// the tooling. To make staleness IMPOSSIBLE-to-miss rather than merely unlikely:
//
//   - After a build off a CLEAN, committed tree at commit C, the image is tagged
//     `<image>:src-<C>`. That tag is the provenance record — no side state.
//   - If `<image>:src-<HEAD>` already exists (clean tree), the exact source is
//     already built: skip the build entirely (fast AND verified).
//   - If an image exists but NOT for HEAD — the sibling moved on, or the tree is
//     dirty, or ENTITY_PM_NO_CACHE is set — a plain `make build` might hand back
//     the stale cache, so the rebuild is forced with `--no-cache` (injected via
//     the Makefiles' `PODMAN_BUILD_CAPS`, which preserves each recipe's own
//     `--target`).
//   - As defense in depth, if the sibling stamps a git-commit LABEL on the image
//     (the sibling half of this fix), a post-build mismatch against HEAD warns.
//
// Env: ENTITY_PM_SKIP_BUILD=1 skips the build (pre-built image / CI);
// ENTITY_PM_NO_CACHE=1 forces a clean rebuild.
func ensureImage(repoDir, image string) {
	if os.Getenv("ENTITY_PM_SKIP_BUILD") != "" {
		return
	}

	sha, dirty := gitStamp(repoDir)
	srcTag := ""
	if sha != "" {
		srcTag = image + ":src-" + sha
	}
	forceEnv := os.Getenv("ENTITY_PM_NO_CACHE") != ""

	plan := planImageBuild(sha, dirty, forceEnv,
		srcTag != "" && podmanImageExists(srcTag),
		podmanImageExists(image))

	if plan.skip {
		// Point :latest at the source-verified build in case it drifted.
		_ = podmanTag(srcTag, image)
		fmt.Fprintf(os.Stderr, "peer-manager: %s image is current (%s) — skipping build.\n", image, plan.reason)
		return
	}

	if _, err := exec.LookPath("make"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: make not found on PATH (needed to build the %s image from %s).\n", image, repoDir)
		fmt.Fprintf(os.Stderr, "  Pre-build the image and set ENTITY_PM_SKIP_BUILD=1 to skip this step.\n")
		os.Exit(1)
	}
	if sha == "" {
		fmt.Fprintf(os.Stderr, "peer-manager: WARNING — cannot read %s git HEAD; building without source-provenance tracking, so a stale image could go undetected. Ensure `git` works in %s, or set ENTITY_PM_NO_CACHE=1 to force a clean build.\n", image, repoDir)
	}

	verb := "Building"
	if plan.noCache {
		verb = "Rebuilding (no cache)"
	}
	fmt.Fprintf(os.Stderr, "peer-manager: %s %s image via `make build` in %s (%s)...\n", verb, image, repoDir, plan.reason)

	if err := runMakeBuild(repoDir, plan.noCache); err != nil {
		fmt.Fprintf(os.Stderr, "Error: `make build` failed in %s: %v\n", repoDir, err)
		os.Exit(1)
	}

	// Record provenance so the next run off this commit hits the fast path.
	if sha != "" && !dirty {
		if err := podmanTag(image, srcTag); err != nil {
			fmt.Fprintf(os.Stderr, "peer-manager: note — could not tag %s (%v); provenance not recorded for this build.\n", srcTag, err)
		}
	}

	// Defense in depth: if the sibling stamped a git-commit label, cross-check it.
	if lbl := podmanImageLabel(image, "org.entity.git.commit", "org.opencontainers.image.revision"); lbl != "" && sha != "" {
		if !strings.HasPrefix(lbl, sha) && !strings.HasPrefix(sha, lbl) {
			fmt.Fprintf(os.Stderr, "peer-manager: WARNING — %s image revision label %q does not match %s HEAD %s; the image may not reflect the current source.\n", image, lbl, repoDir, sha)
		}
	}
}

// buildPlan is the decision ensureImage makes before touching podman.
type buildPlan struct {
	skip    bool   // the exact source is already built — do nothing
	noCache bool   // podman's layer cache is untrustworthy — force a clean build
	reason  string // human-readable, for the log line
}

// planImageBuild decides how to (re)build an image from the source provenance
// signals alone — pure, so it is unit-testable without podman. srcTagExists is
// whether `<image>:src-<sha>` is present (clean-tree provenance for HEAD);
// latestExists is whether any `<image>` is present at all.
func planImageBuild(sha string, dirty, forceEnv, srcTagExists, latestExists bool) buildPlan {
	if forceEnv {
		return buildPlan{noCache: true, reason: "ENTITY_PM_NO_CACHE set"}
	}
	if sha == "" {
		// No git provenance — preserve the old build-and-trust-the-cache behavior
		// (a warning is emitted separately). Cannot force safely on every run.
		return buildPlan{reason: "no git provenance"}
	}
	if dirty {
		return buildPlan{noCache: true, reason: "working tree dirty at " + sha}
	}
	if srcTagExists {
		return buildPlan{skip: true, reason: "already built from " + sha}
	}
	if latestExists {
		// An image exists but not for this commit: a plain `make build` may serve
		// the stale cache, so bust it. This is the silent-stale case.
		return buildPlan{noCache: true, reason: "existing image predates " + sha}
	}
	// No image at all — a fresh build from a cold cache cannot be stale.
	return buildPlan{reason: "first build at " + sha}
}

// runMakeBuild runs `make build` in the sibling repo. When noCache is set it
// injects `--no-cache` through PODMAN_BUILD_CAPS (a command-line make-var
// assignment overrides the Makefile's `:=`, and preserves the recipe's own
// `-t $(IMAGE)` / `--target`), carrying the build memory caps forward from
// CAP_MEM/CAP_SWAP when set so a forced rebuild is not OOM-prone on a small box.
func runMakeBuild(repoDir string, noCache bool) error {
	args := []string{"build"}
	if noCache {
		caps := "--no-cache"
		if m := os.Getenv("CAP_MEM"); m != "" {
			caps += " --memory=" + m + " --memory-swap=" + envOr("CAP_SWAP", m)
		}
		args = append(args, "PODMAN_BUILD_CAPS="+caps)
	}
	build := exec.Command("make", args...)
	build.Dir = repoDir
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	return build.Run()
}

// gitStamp returns the sibling repo's short HEAD and whether its tree is dirty.
// sha is "" (and dirty false) when git is unavailable or repoDir is not a repo —
// the caller then falls back to the old build-and-trust behavior with a warning.
func gitStamp(repoDir string) (sha string, dirty bool) {
	out, err := exec.Command("git", "-C", repoDir, "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return "", false
	}
	sha = strings.TrimSpace(string(out))
	if sha == "" {
		return "", false
	}
	st, err := exec.Command("git", "-C", repoDir, "status", "--porcelain").Output()
	if err != nil {
		return sha, false
	}
	return sha, strings.TrimSpace(string(st)) != ""
}

func podmanImageExists(ref string) bool {
	return exec.Command("podman", "image", "exists", ref).Run() == nil
}

func podmanTag(src, dst string) error {
	return exec.Command("podman", "tag", src, dst).Run()
}

// podmanImageLabel returns the first non-empty value among the given label keys
// on the image, or "" if none are set (e.g. the sibling has not stamped one yet).
func podmanImageLabel(image string, keys ...string) string {
	for _, k := range keys {
		out, err := exec.Command("podman", "inspect", "--format", fmt.Sprintf("{{index .Config.Labels %q}}", k), image).Output()
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(out)); v != "" && v != "<no value>" {
			return v
		}
	}
	return ""
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
