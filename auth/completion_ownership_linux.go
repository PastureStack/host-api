//go:build linux

package auth

import (
	"os"
	"syscall"
)

func completionOwnedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func completionTrustedAncestor(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	return info.Mode().Perm()&0022 == 0 || (stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)
}
