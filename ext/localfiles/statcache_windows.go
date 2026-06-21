//go:build windows

package localfiles

import "os"

// On Windows the L7 cache degrades to mtime+size+mode (sufficient for
// the common case per Git's index model on FAT/NTFS). dev/ino/ctime
// extraction is POSIX-shaped via syscall.Stat_t which doesn't exist on
// Windows; this stub returns zeros so the predicate works on the
// available fields.
func extraStatFields(_ os.FileInfo) (dev, ino uint64, ctimeNs int64) {
	return 0, 0, 0
}
