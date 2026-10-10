// ttl_store.go — the in-memory StateStore.
// Sessions are keyed by session_id and expire after a period without a
// request. The number of sessions is capped so a flood of session IDs cannot
// exhaust memory: at the cap, expired sessions are swept and then the least
// recently seen session is evicted.
package state

import (
	"sync"
	"time"
)

// TTLStore is the in-memory StateStore. It is safe for concurrent use.
type TTLStore struct {
	mu       sync.Mutex
	sessions map[string]*entry
	ttl      time.Duration
	max      int
	now      func() time.Time
	evicted  int

	stopCh   chan struct{}
	stopOnce sync.Once
}

type entry struct {
	s       *Session
	expires time.Time
}

// NewTTLStore returns a store whose sessions expire ttl after their last
// request, holding at most maxSessions at once, and starts the background
// sweep. Call Stop on shutdown.
func NewTTLStore(ttl time.Duration, maxSessions int) *TTLStore {
	t := newTTLStore(ttl, maxSessions, time.Now)
	go t.sweepLoop()
	return t
}

// newTTLStore builds a store without the sweep goroutine, with an injectable
// clock, for tests.
func newTTLStore(ttl time.Duration, maxSessions int, now func() time.Time) *TTLStore {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if maxSessions <= 0 {
		maxSessions = 10000
	}
	return &TTLStore{
		sessions: make(map[string]*entry),
		ttl:      ttl,
		max:      maxSessions,
		now:      now,
		stopCh:   make(chan struct{}),
	}
}

// Get returns a copy of the session's state, or nil if it is unknown or
// expired. It does not renew the expiry; only Update does.
func (t *TTLStore) Get(sessionID string) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.sessions[sessionID]
	if !ok || !t.now().Before(e.expires) {
		return nil
	}
	return e.s.Clone()
}

// Update applies fn to the session, creating it if needed, and renews its
// expiry. An expired session is replaced by a fresh one rather than revived.
func (t *TTLStore) Update(sessionID string, fn func(*Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.sessions[sessionID]
	if ok && !now.Before(e.expires) {
		delete(t.sessions, sessionID)
		ok = false
	}
	if !ok {
		if len(t.sessions) >= t.max {
			t.makeRoomLocked(now)
		}
		e = &entry{s: &Session{ID: sessionID, Created: now}}
		t.sessions[sessionID] = e
	}
	fn(e.s)
	e.s.LastSeen = now
	e.expires = now.Add(t.ttl)
}

// Len returns the number of sessions held, including expired ones not yet swept.
func (t *TTLStore) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// Evicted returns how many live sessions were evicted to stay under the cap.
func (t *TTLStore) Evicted() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

// Stop ends the background sweep. Safe to call more than once.
func (t *TTLStore) Stop() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}

func (t *TTLStore) makeRoomLocked(now time.Time) {
	t.sweepLocked(now)
	if len(t.sessions) < t.max {
		return
	}
	var oldestID string
	var oldest time.Time
	for id, e := range t.sessions {
		if oldestID == "" || e.expires.Before(oldest) {
			oldestID, oldest = id, e.expires
		}
	}
	delete(t.sessions, oldestID)
	t.evicted++
}

func (t *TTLStore) sweepLocked(now time.Time) {
	for id, e := range t.sessions {
		if !now.Before(e.expires) {
			delete(t.sessions, id)
		}
	}
}

func (t *TTLStore) sweepLoop() {
	interval := t.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.mu.Lock()
			t.sweepLocked(t.now())
			t.mu.Unlock()
		}
	}
}
