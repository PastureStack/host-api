package events

import "sync"

type keyedLock struct {
	mutex sync.Mutex
	held  map[string]struct{}
}

var eventLocks = keyedLock{held: make(map[string]struct{})}

func (lock *keyedLock) tryLock(key string) func() {
	lock.mutex.Lock()
	defer lock.mutex.Unlock()
	if _, exists := lock.held[key]; exists {
		return nil
	}
	lock.held[key] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			lock.mutex.Lock()
			delete(lock.held, key)
			lock.mutex.Unlock()
		})
	}
}
