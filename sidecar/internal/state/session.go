package state

import "time"

// Session is what the sidecar remembers about one agent session between hook
// calls. The sidecar owns it: a client names a session by ID but cannot write
// its contents, and the validate stage discards any state a client sends.
type Session struct {
	ID       string
	Created  time.Time
	LastSeen time.Time
	// Requests and Blocked count the decided requests in the session.
	Requests int
	Blocked  int
	// Task is the scope declared through on_task, or nil if none was declared.
	Task *TaskScope
}

// Clone returns a copy that shares nothing mutable with s, so a caller can
// read it without holding the store's lock.
func (s *Session) Clone() *Session {
	c := *s
	c.Task = s.Task.clone()
	return &c
}

// View is the part of the session policies can read, as input.state. Values
// are JSON-shaped so the policy engine sees the same types as for a payload.
func (s *Session) View() map[string]any {
	v := map[string]any{
		"requests": s.Requests,
		"blocked":  s.Blocked,
	}
	if s.Task != nil {
		v["task"] = s.Task.view()
	}
	return v
}
