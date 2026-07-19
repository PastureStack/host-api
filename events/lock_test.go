package events

import "testing"

func TestKeyedLockExcludesSameKeyAndAllowsReuse(t *testing.T) {
	lock := keyedLock{held: make(map[string]struct{})}
	unlock := lock.tryLock("container-1")
	if unlock == nil {
		t.Fatal("first lock attempt failed")
	}
	if lock.tryLock("container-1") != nil {
		t.Fatal("same key was acquired twice")
	}
	other := lock.tryLock("container-2")
	if other == nil {
		t.Fatal("independent key was blocked")
	}
	other()
	unlock()
	unlock()
	if next := lock.tryLock("container-1"); next == nil {
		t.Fatal("released key was not reusable")
	} else {
		next()
	}
}
