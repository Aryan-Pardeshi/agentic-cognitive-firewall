// Package state defines the StateStore interface and its implementations.
// v1 used noop.go (stateless). v2 injects ttl_store.go at startup.
// The pipeline calls the interface only.
package state

// StateStore holds per-session state across hook calls.
type StateStore interface {
	// Get returns a copy of the session's state, or nil if the session is
	// unknown or has expired.
	Get(sessionID string) *Session
	// Update applies fn to the session's state, creating the session if it does
	// not exist, and renews its expiry. fn runs under the store's lock, so it
	// must be quick and must not call back into the store.
	Update(sessionID string, fn func(*Session))
}
