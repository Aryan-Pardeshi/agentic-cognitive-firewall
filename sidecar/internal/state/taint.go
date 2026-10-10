package state

// Caps on the values a session tracks for argument tainting, so content stuffed
// with addresses cannot grow a session without bound.
const (
	MaxUntrustedTokens = 4096
	MaxTrustedTokens   = 2048
	maxSourcesPerToken = 4
)

// TaintSource says where the agent read an untrusted value.
type TaintSource struct {
	// Hook is "on_context" or "on_tool_result".
	Hook string
	// Tool names the tool for on_tool_result, and is empty otherwise.
	Tool string
}

// AddUntrusted records that the agent read the value with this token key in
// untrusted content. A value already tracked gains the new source, up to a
// few per value. Once the session tracks MaxUntrustedTokens values, new ones
// are not stored and TaintOverflow is set, so policy can fail closed on
// values the session can no longer vouch for.
func (s *Session) AddUntrusted(key string, src TaintSource) {
	if s.Untrusted == nil {
		s.Untrusted = map[string][]TaintSource{}
	}
	srcs, known := s.Untrusted[key]
	if !known && len(s.Untrusted) >= MaxUntrustedTokens {
		s.TaintOverflow = true
		return
	}
	for _, have := range srcs {
		if have == src {
			return
		}
	}
	if len(srcs) < maxSourcesPerToken {
		s.Untrusted[key] = append(srcs, src)
	}
}

// AddTrusted records a value the user or developer vouches for. Past
// MaxTrustedTokens a value is simply not trusted, which can only make policy
// stricter.
func (s *Session) AddTrusted(key string) {
	if s.Trusted == nil {
		s.Trusted = map[string]bool{}
	}
	if len(s.Trusted) < MaxTrustedTokens {
		s.Trusted[key] = true
	}
}
