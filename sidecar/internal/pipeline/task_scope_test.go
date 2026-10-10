package pipeline

import (
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/state"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// newSessionEnv is the pipeline main.go builds: the shipped config, patterns
// and policies, with the session stage and its recorder.
func newSessionEnv(tb testing.TB) *Pipeline {
	tb.Helper()
	env := newBenchEnv(tb)
	store := state.NewTTLStore(time.Minute, 100)
	tb.Cleanup(store.Stop)
	stage := NewSessionStage(store)
	stages := []Stage{env.stages[0], stage, env.stages[1], env.stages[2], env.stages[3]}
	return NewWithEvaluator(env.cfg, stages, env.eng).OnDecision(stage)
}

func declare(pl *Pipeline, session string, scope map[string]any) Result {
	return pl.Run(&riskcontext.RiskContext{
		HookType: "on_task", Provenance: "developer", SessionID: session, Payload: scope,
	})
}

func call(pl *Pipeline, session, tool string, params map[string]any) byte {
	return pl.Run(&riskcontext.RiskContext{
		HookType: "on_tool_call", Provenance: "agent", SessionID: session,
		Payload: map[string]any{"name": tool, "params": params},
	}).Decision
}

func tools(names ...string) []any {
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

// The shipped policy_config.yaml allows search, calculator, get_weather and
// read_file.

func TestTaskScope_NarrowsToolsForTheSession(t *testing.T) {
	pl := newSessionEnv(t)
	if d := call(pl, "s1", "calculator", nil); d != decision.Allow {
		t.Fatalf("before any scope, calculator = %d, want ALLOW", d)
	}
	if r := declare(pl, "s1", map[string]any{"allowed_tools": tools("search")}); r.Decision != decision.Allow {
		t.Fatalf("declaring [search] = %d (blocked at %q), want ALLOW", r.Decision, r.BlockedAt)
	}
	if d := call(pl, "s1", "calculator", nil); d != decision.Block {
		t.Errorf("calculator outside the scope = %d, want BLOCK", d)
	}
	if d := call(pl, "s1", "search", map[string]any{"query": "weather"}); d != decision.Allow {
		t.Errorf("search inside the scope = %d, want ALLOW", d)
	}
	if d := call(pl, "s2", "calculator", nil); d != decision.Allow {
		t.Errorf("another session's calculator = %d, want ALLOW; scopes must not leak", d)
	}
}

func TestTaskScope_CannotWidenGlobalPolicy(t *testing.T) {
	pl := newSessionEnv(t)
	r := declare(pl, "s1", map[string]any{"allowed_tools": tools("search", "send_money")})
	if r.Decision != decision.Block {
		t.Fatalf("widening scope = %d, want BLOCK", r.Decision)
	}
	if d := call(pl, "s1", "send_money", nil); d != decision.Block {
		t.Errorf("send_money after a rejected scope = %d, want BLOCK", d)
	}
	if d := call(pl, "s1", "calculator", nil); d != decision.Allow {
		t.Errorf("a rejected scope must not be stored; calculator = %d, want ALLOW", d)
	}
}

func TestTaskScope_DeclarationRules(t *testing.T) {
	pl := newSessionEnv(t)
	cases := []struct {
		name    string
		session string
		scope   map[string]any
	}{
		{"no session", "", map[string]any{"allowed_tools": tools("search")}},
		{"malformed", "s1", map[string]any{"tools": tools("search")}},
	}
	for _, c := range cases {
		if r := declare(pl, c.session, c.scope); r.Decision != decision.Block || r.BlockedAt != "session" {
			t.Errorf("%s: decision=%d blocked_at=%q, want BLOCK at session", c.name, r.Decision, r.BlockedAt)
		}
	}

	if r := declare(pl, "s2", map[string]any{"allowed_tools": tools("search")}); r.Decision != decision.Allow {
		t.Fatalf("first declaration = %d, want ALLOW", r.Decision)
	}
	r := declare(pl, "s2", map[string]any{"allowed_tools": tools("search", "calculator")})
	if r.Decision != decision.Block || r.BlockedAt != "session" {
		t.Errorf("second declaration: decision=%d blocked_at=%q, want BLOCK at session", r.Decision, r.BlockedAt)
	}
	if d := call(pl, "s2", "calculator", nil); d != decision.Block {
		t.Errorf("the second declaration must not replace the first; calculator = %d", d)
	}
}

func TestTaskScope_ArgumentConstraints(t *testing.T) {
	pl := newSessionEnv(t)
	scope := map[string]any{
		"allowed_tools": tools("search", "get_weather"),
		"tool_constraints": map[string]any{
			"search":      map[string]any{"query": map[string]any{"pattern": "^[a-z ]+$"}},
			"get_weather": map[string]any{"city": map[string]any{"allowed": tools("paris")}, "days": map[string]any{"max": 3.0}},
		},
	}
	if r := declare(pl, "s1", scope); r.Decision != decision.Allow {
		t.Fatalf("declare = %d, want ALLOW", r.Decision)
	}
	cases := []struct {
		tool   string
		params map[string]any
		want   byte
	}{
		{"search", map[string]any{"query": "weather today"}, decision.Allow},
		{"search", map[string]any{"query": "Weather"}, decision.Block},
		{"search", map[string]any{}, decision.Allow},
		{"get_weather", map[string]any{"city": "paris", "days": 2.0}, decision.Allow},
		{"get_weather", map[string]any{"city": "lyon", "days": 2.0}, decision.Block},
		{"get_weather", map[string]any{"city": "paris", "days": 7.0}, decision.Block},
	}
	for _, c := range cases {
		if d := call(pl, "s1", c.tool, c.params); d != c.want {
			t.Errorf("%s %v = %d, want %d", c.tool, c.params, d, c.want)
		}
	}
}
