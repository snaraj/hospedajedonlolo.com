//go:build !linux

package server

import (
	"io/fs"
	"syscall"
)

// mediaFileHasMultipleLinks applies the same hard-link refusal on the
// developer's machine when the platform exposes a link count.
func mediaFileHasMultipleLinks(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink != 1
}
