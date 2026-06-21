//go:build linux

package localfiles

import (
	"os"
	"syscall"
)

func extraStatFields(info os.FileInfo) (dev, ino uint64, ctimeNs int64) {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	dev = uint64(sys.Dev)
	ino = uint64(sys.Ino)
	ctimeNs = sys.Ctim.Sec*1_000_000_000 + sys.Ctim.Nsec
	return
}
