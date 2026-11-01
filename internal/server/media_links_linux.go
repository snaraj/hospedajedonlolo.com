//go:build linux

package server

import (
	"io/fs"
	"syscall"
)

// mediaFileHasMultipleLinks refuses hard links: publication copies every file,
// so a second link means something other than the publishing flow put it there.
func mediaFileHasMultipleLinks(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}
