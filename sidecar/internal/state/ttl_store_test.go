package state

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock for the store.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore(ttl time.Duration, max int) (*TTLStore, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return newTTLStore(ttl, max, c.now), c
}

func TestTTLStore_UpdateCreatesAndGetReturnsACopy(t *testing.T) {
	s, _ := newTestStore(time.Minute, 10)
	if s.Get("a") != nil {
		t.Fatal("unknown session should be nil")
	}
	s.Update("a", func(sess *Session) { sess.Requests++ })
	got := s.Get("a")
	if got == nil || got.ID != "a" || got.Requests != 1 {
		t.Fatalf("Get = %+v, want session a with 1 request", got)
	}
	got.Requests = 99
	if s.Get("a").Requests != 1 {
		t.Error("mutating the returned copy changed the stored session")
	}
}

func TestTTLStore_SessionsExpireAfterIdleTTL(t *testing.T) {
	s, clock := newTestStore(time.Minute, 10)
	s.Update("a", func(sess *Session) { sess.Requests++ })

	clock.advance(59 * time.Second)
	s.Update("a", func(sess *Session) { sess.Requests++ }) // renews the expiry
	clock.advance(59 * time.Second)
	if got := s.Get("a"); got == nil || got.Requests != 2 {
		t.Fatalf("session should still be live with 2 requests, got %+v", got)
	}

	clock.advance(2 * time.Second)
	if s.Get("a") != nil {
		t.Error("session should have expired a minute after its last request")
	}
	s.Update("a", func(sess *Session) { sess.Requests++ })
	if got := s.Get("a"); got.Requests != 1 {
		t.Errorf("an expired session should restart empty, got %d requests", got.Requests)
	}
}

func TestTTLStore_CapEvictsTheLeastRecentlySeen(t *testing.T) {
	s, clock := newTestStore(time.Hour, 3)
	for _, id := range []string{"a", "b", "c"} {
		s.Update(id, func(*Session) {})
		clock.advance(time.Second)
	}
	s.Update("a", func(*Session) {}) // a is now the most recent
	clock.advance(time.Second)
	s.Update("d", func(*Session) {}) // over the cap: b is least recently seen

	if s.Len() != 3 || s.Evicted() != 1 {
		t.Fatalf("len=%d evicted=%d, want 3 and 1", s.Len(), s.Evicted())
	}
	if s.Get("b") != nil {
		t.Error("b should have been evicted")
	}
	for _, id := range []string{"a", "c", "d"} {
		if s.Get(id) == nil {
			t.Errorf("%s should still be held", id)
		}
	}
}

func TestTTLStore_CapSweepsExpiredBeforeEvictingLive(t *testing.T) {
	s, clock := newTestStore(time.Minute, 2)
	s.Update("old", func(*Session) {})
	clock.advance(2 * time.Minute) // old has expired
	s.Update("b", func(*Session) {})
	s.Update("c", func(*Session) {})
	if s.Evicted() != 0 {
		t.Errorf("evicted %d live sessions; the expired one should have made room", s.Evicted())
	}
	if s.Get("b") == nil || s.Get("c") == nil {
		t.Error("both live sessions should be held")
	}
}

func TestTTLStore_ConcurrentUpdatesAreNotLost(t *testing.T) {
	s, _ := newTestStore(time.Hour, 100)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.Update("shared", func(sess *Session) { sess.Requests++ })
				s.Update(fmt.Sprintf("own-%d", w), func(sess *Session) { sess.Requests++ })
				_ = s.Get("shared")
			}
		}(w)
	}
	wg.Wait()
	if got := s.Get("shared").Requests; got != 8*500 {
		t.Errorf("shared session counted %d requests, want %d", got, 8*500)
	}
}

func TestNewTTLStore_StopIsIdempotent(t *testing.T) {
	s := NewTTLStore(time.Minute, 10)
	s.Stop()
	s.Stop()
}
