// noop.go — the stateless StateStore.
// Get always returns nil. Update is a no-op.
package state

// NoopStore keeps no state: every request is evaluated on its own.
type NoopStore struct{}

// Get always returns nil.
func (n *NoopStore) Get(_ string) *Session { return nil }

// Update does nothing.
func (n *NoopStore) Update(_ string, _ func(*Session)) {}
