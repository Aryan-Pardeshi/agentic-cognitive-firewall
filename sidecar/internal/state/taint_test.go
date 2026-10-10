package state

import (
	"fmt"
	"testing"
)

func TestAddUntrusted_TracksSourcesPerValue(t *testing.T) {
	s := &Session{}
	page := TaintSource{Hook: "on_tool_result", Tool: "web_fetch"}
	doc := TaintSource{Hook: "on_context"}
	s.AddUntrusted("email:a@x.io", page)
	s.AddUntrusted("email:a@x.io", page) // duplicate source ignored
	s.AddUntrusted("email:a@x.io", doc)
	if got := s.Untrusted["email:a@x.io"]; len(got) != 2 {
		t.Errorf("sources = %v, want web_fetch and on_context once each", got)
	}
	for i := 0; i < 10; i++ {
		s.AddUntrusted("email:a@x.io", TaintSource{Hook: "on_tool_result", Tool: fmt.Sprintf("t%d", i)})
	}
	if got := len(s.Untrusted["email:a@x.io"]); got != maxSourcesPerToken {
		t.Errorf("kept %d sources, want the cap of %d", got, maxSourcesPerToken)
	}
}

func TestAddUntrusted_OverflowFlagsInsteadOfGrowing(t *testing.T) {
	s := &Session{}
	src := TaintSource{Hook: "on_context"}
	for i := 0; i < MaxUntrustedTokens; i++ {
		s.AddUntrusted(fmt.Sprintf("number:%d", 10000000+i), src)
	}
	if s.TaintOverflow {
		t.Fatal("overflow set before the cap was exceeded")
	}
	s.AddUntrusted("email:one-too-many@x.io", src)
	if !s.TaintOverflow || len(s.Untrusted) != MaxUntrustedTokens {
		t.Errorf("overflow=%v len=%d, want overflow at the cap", s.TaintOverflow, len(s.Untrusted))
	}
	// A value already tracked can still gain a source after overflow.
	s.AddUntrusted("number:10000000", TaintSource{Hook: "on_tool_result", Tool: "web_fetch"})
	if len(s.Untrusted["number:10000000"]) != 2 {
		t.Error("a known value should still record new sources after overflow")
	}
}

func TestAddTrusted_StopsAtTheCap(t *testing.T) {
	s := &Session{}
	for i := 0; i < MaxTrustedTokens+10; i++ {
		s.AddTrusted(fmt.Sprintf("number:%d", 10000000+i))
	}
	if len(s.Trusted) != MaxTrustedTokens {
		t.Errorf("trusted = %d, want the cap of %d", len(s.Trusted), MaxTrustedTokens)
	}
}

func TestClone_CopiesTaintState(t *testing.T) {
	s := &Session{}
	s.AddUntrusted("email:a@x.io", TaintSource{Hook: "on_context"})
	s.AddTrusted("email:b@x.io")
	c := s.Clone()
	c.Untrusted["email:a@x.io"][0].Hook = "changed"
	c.Trusted["email:c@x.io"] = true
	if s.Untrusted["email:a@x.io"][0].Hook != "on_context" || s.Trusted["email:c@x.io"] {
		t.Error("Clone shares taint state with the original")
	}
}
