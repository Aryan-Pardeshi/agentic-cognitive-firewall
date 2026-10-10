package state

import "testing"

func TestNoopStore_GetReturnsNil(t *testing.T) {
	store := &NoopStore{}
	for _, key := range []string{"session-1", "session-2", "", "abc-123"} {
		if store.Get(key) != nil {
			t.Errorf("NoopStore.Get(%q) should return nil", key)
		}
	}
}

func TestNoopStore_UpdateIsANoOp(t *testing.T) {
	store := &NoopStore{}
	called := false
	store.Update("session-1", func(*Session) { called = true })
	if called {
		t.Error("NoopStore.Update should not run the update function")
	}
	if store.Get("session-1") != nil {
		t.Error("NoopStore is stateless — Get after Update should still return nil")
	}
}
