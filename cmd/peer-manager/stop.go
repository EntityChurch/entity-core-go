package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func cmdStop(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: peer-manager stop <name> | --all\n")
		os.Exit(2)
	}

	state, err := loadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading state: %v\n", err)
		os.Exit(1)
	}

	if args[0] == "--all" {
		for name := range state.Peers {
			stopPeer(state, name)
		}
	} else {
		stopPeer(state, args[0])
	}

	if err := saveState(state); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
		os.Exit(1)
	}
}

func stopPeer(state *State, name string) {
	entry, ok := state.Peers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "Peer %q not found\n", name)
		return
	}

	// Containerized peers (rust/python) are torn down through podman: the peers
	// ignore SIGTERM, so SIGKILLing the attached `podman run` client would
	// orphan the container. `podman stop` cleanly stops the container (which the
	// --rm then removes and the attached client follows out).
	if entry.Container != "" {
		stopContainerPeer(state, name, entry)
		return
	}

	if !isAlive(entry.PID) {
		fmt.Printf("Peer %q (pid %d) already dead, cleaning up\n", name, entry.PID)
		delete(state.Peers, name)
		return
	}

	// Send SIGTERM.
	proc, err := os.FindProcess(entry.PID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot find process %d: %v\n", entry.PID, err)
		delete(state.Peers, name)
		return
	}

	fmt.Printf("Stopping peer %q (pid %d)...\n", name, entry.PID)
	proc.Signal(syscall.SIGTERM)

	// Managed peers are detached (peer-manager start exits after launching
	// them), so they are NOT children of this `stop` invocation. proc.Wait()
	// returns immediately with "no child processes" for a non-child — relying
	// on it made the SIGKILL escalation dead code and leaked any peer that
	// ignored SIGTERM (dropped from state but left running, holding its port).
	// Poll isAlive (signal-0 existence check, works for non-children) instead.
	if waitGone(entry.PID, 5*time.Second) {
		fmt.Printf("Peer %q stopped\n", name)
	} else {
		fmt.Printf("Peer %q didn't stop in 5s, sending SIGKILL\n", name)
		proc.Kill()
		if !waitGone(entry.PID, 3*time.Second) {
			fmt.Fprintf(os.Stderr, "Warning: peer %q (pid %d) still alive after SIGKILL — manual cleanup may be needed\n", name, entry.PID)
		}
	}

	delete(state.Peers, name)
}

// stopContainerPeer tears down a containerized peer via podman. `podman stop`
// sends the container's StopSignal (SIGTERM) then SIGKILLs after the timeout;
// the peers ignore SIGTERM, so a short --time keeps teardown brisk. The
// container ran with --rm, so it's removed on stop; rm -f mops up if it somehow
// lingered. The attached `podman run` client exits once the container is gone.
func stopContainerPeer(state *State, name string, entry *PeerEntry) {
	fmt.Printf("Stopping peer %q (container %s)...\n", name, entry.Container)
	stop := exec.Command("podman", "stop", "--time", "3", entry.Container)
	stop.Stdout = os.Stderr
	stop.Stderr = os.Stderr
	if err := stop.Run(); err != nil {
		// Already gone, or stop failed — force-remove as cleanup.
		exec.Command("podman", "rm", "-f", entry.Container).Run()
	}

	if entry.PID > 0 {
		waitGone(entry.PID, 5*time.Second)
	}

	fmt.Printf("Peer %q stopped\n", name)
	delete(state.Peers, name)
}

// waitGone polls until the process is no longer alive or the timeout elapses.
// Returns true if the process is gone. Works for non-child processes (uses
// the signal-0 existence check via isAlive), unlike proc.Wait().
func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !isAlive(pid)
}
