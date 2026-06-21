package main

import "syscall"

// detachProcessGroup returns SysProcAttr that puts the child in its own process group,
// so SIGINT to the parent doesn't kill the child peers.
func detachProcessGroup() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
