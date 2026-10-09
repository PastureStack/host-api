//go:build linux

package auth

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func completionOwnedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func completionTrustedAncestor(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && completionTrustedOwnership(stat.Uid, info.Mode().Perm()&0022 != 0, info.Mode()&os.ModeSticky != 0)
}

func completionTrustedOwnership(uid uint32, writable, sticky bool) bool {
	return (uid == 0 || uid == uint32(os.Geteuid())) && (!writable || (uid == 0 && sticky))
}

// Create through verified directory descriptors: pathname prechecks followed
// by MkdirAll can follow a substituted symlink before they reject the path.
func createCompletionSpoolDirectory(dir string) error {
	flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	for _, component := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("unsafe completion spool component")
		}
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if !completionTrustedOwnership(stat.Uid, stat.Mode&0022 != 0, stat.Mode&unix.S_ISVTX != 0) {
			return errors.New("unsafe completion spool ancestor")
		}
		next, err := openCompletionSpoolChild(fd, component, unix.Mkdirat)
		if err != nil {
			return err
		}
		_ = unix.Close(fd)
		fd = next
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != uint32(os.Geteuid()) || !completionTrustedOwnership(stat.Uid, stat.Mode&0022 != 0, stat.Mode&unix.S_ISVTX != 0) {
		return errors.New("unsafe completion spool directory")
	}
	// O_PATH does not require directory read permission, preserving searchable
	// ancestors and owner-only mode repair. procfs resolves this held descriptor,
	// not the configurable pathname, on kernels predating fchmodat2.
	return unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), 0700)
}

func openCompletionSpoolChild(parent int, name string, mkdir func(int, string, uint32) error) (int, error) {
	flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(parent, name, flags, 0)
	if err == unix.ENOENT {
		if err = mkdir(parent, name, 0700); err != nil && err != unix.EEXIST {
			return -1, err
		}
		// Even a concurrently created child must be reopened without following
		// links; its ownership is checked before any descendant is created.
		return unix.Openat(parent, name, flags, 0)
	}
	return fd, err
}
