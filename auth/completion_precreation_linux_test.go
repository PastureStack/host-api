//go:build linux

package auth

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCompletionSpoolRejectsAncestorSymlinkBeforeCreation(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "outside")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := openCompletionSpool(filepath.Join(alias, "new", "completion-spool")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected ancestor produced filesystem side effects")
	}
}

func TestCompletionSpoolRejectsWritableParentBeforeCreation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	if _, err := openCompletionSpool(filepath.Join(parent, "new", "completion-spool")); err == nil {
		t.Fatal("unsafe writable parent accepted")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected writable parent produced filesystem side effects")
	}
}

func TestCompletionSpoolRejectsForeignOwnedParentBeforeCreation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required only to construct the foreign-owner fixture")
	}
	parent := t.TempDir()
	if err := os.Chown(parent, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	defer os.Chown(parent, 0, 0)
	if _, err := openCompletionSpool(filepath.Join(parent, "new", "completion-spool")); err == nil {
		t.Fatal("foreign-owned parent accepted")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected foreign-owned parent produced filesystem side effects")
	}
}

func TestCompletionSpoolCreatesPrivateNestedCustomDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state", "completion-spool")
	if _, err := openCompletionSpool(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("legitimate private custom directory failed")
	}
	if _, err := openCompletionSpool(dir); err != nil {
		t.Fatal("existing private directory could not be reused")
	}
}

func TestCompletionSpoolConcurrentChildSymlinkIsNotFollowed(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	called := 0
	child, err := openCompletionSpoolChild(fd, "child", func(dirfd int, name string, mode uint32) error {
		called++
		if dirfd != fd || name != "child" || mode != 0700 {
			t.Fatal("unexpected creation boundary")
		}
		// Deterministic interleaving: the child appears after the failed open,
		// before mkdir reports EEXIST. No sleeps or probabilistic race loop.
		if err := unix.Symlinkat(outside, dirfd, name); err != nil {
			t.Fatal(err)
		}
		return unix.EEXIST
	})
	if child >= 0 {
		unix.Close(child)
	}
	if err == nil || called != 1 {
		t.Fatal("concurrently planted symlink was followed")
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("concurrent alias modified destination")
	}
}

func TestCompletionSpoolSearchableAncestorAndOwnerModeRepair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run additionally as an unprivileged UID to verify DAC permissions")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0711); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	dir := filepath.Join(parent, "completion-spool")
	if err := os.Mkdir(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if _, err := openCompletionSpool(dir); err != nil {
		t.Fatalf("legitimate search-only ancestor or owner mode repair failed: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("owner mode repair did not persist")
	}
	info, err = os.Lstat(parent)
	if err != nil || info.Mode().Perm() != 0711 {
		t.Fatal("search-only ancestor mode was changed")
	}
}
