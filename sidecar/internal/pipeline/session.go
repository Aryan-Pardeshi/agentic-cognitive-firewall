// session.go — the session stage.
// Runs after validate. For a request that names a session, it loads the
// session's state into rc.State so policies can read it as input.state, and
// after the decision it records the request in the session. A request with no
// session_id is evaluated on its own, exactly as before sessions existed.
package pipeline

import (
	"regexp"

	"github.com/acf-sdk/sidecar/internal/state"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// sessionIDPattern bounds session IDs to a short, printable set, so an ID can
// be logged and keyed safely. The SDK generates 32 hex characters.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// SessionStage hydrates and records per-session state.
type SessionStage struct {
	store state.StateStore
}

// NewSessionStage returns a SessionStage backed by store.
func NewSessionStage(store state.StateStore) *SessionStage {
	return &SessionStage{store: store}
}

func (s *SessionStage) Name() string { return "session" }

// Run loads the session's state into rc.State. It hard-blocks a malformed
// session ID rather than treating the request as sessionless, because a
// sessionless request would skip the session's restrictions.
func (s *SessionStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	if rc.SessionID == "" {
		return false
	}
	if !sessionIDPattern.MatchString(rc.SessionID) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_session_id"})
		return true
	}
	if sess := s.store.Get(rc.SessionID); sess != nil {
		rc.State = sess.View()
	}
	return false
}

// Record updates the session after a decision. The pipeline calls it once per
// request that reached policy evaluation.
func (s *SessionStage) Record(rc *riskcontext.RiskContext, d byte) {
	if rc.SessionID == "" || !sessionIDPattern.MatchString(rc.SessionID) {
		return
	}
	s.store.Update(rc.SessionID, func(sess *state.Session) {
		sess.Requests++
		if d == decision.Block {
			sess.Blocked++
		}
	})
}
