package pipeline

import (
	"encoding/json"
	"testing"

	"github.com/acf-sdk/sidecar/internal/benchdata"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func toolResult(pl *Pipeline, tool string, result any) Result {
	return pl.Run(&riskcontext.RiskContext{
		HookType: "on_tool_result", Provenance: "tool_output",
		Payload: map[string]any{"tool": tool, "result": result},
	})
}

// The shipped policy_config.yaml lists no trusted tools, so every tool's
// output is screened.

func TestToolResult_ScreensInjectedOutput(t *testing.T) {
	pl := newSessionEnv(t)
	if r := toolResult(pl, "web_fetch", benchdata.BenignText(1024)); r.Decision != decision.Allow {
		t.Errorf("benign output = %d, want ALLOW", r.Decision)
	}
	r := toolResult(pl, "web_fetch", benchdata.InjectedText(1024))
	if r.Decision == decision.Allow {
		t.Fatalf("injected output was ALLOWed")
	}
	if r.Decision == decision.Sanitise {
		var body map[string]string
		if err := json.Unmarshal(r.SanitisedPayload, &body); err != nil {
			t.Fatalf("sanitised payload is not JSON: %v", err)
		}
		if body["sanitised"] == "" || body["sanitised"] == benchdata.InjectedText(1024) {
			t.Errorf("sanitised payload did not remove the injection: %.80q", body["sanitised"])
		}
	}
}

func TestToolResult_MalformedPayloadIsHardBlocked(t *testing.T) {
	pl := newSessionEnv(t)
	for _, bad := range []any{map[string]any{"result": "x"}, "just text"} {
		r := pl.Run(&riskcontext.RiskContext{HookType: "on_tool_result", Provenance: "tool_output", Payload: bad})
		if r.Decision != decision.Block || r.BlockedAt != "validate" {
			t.Errorf("payload %v: decision=%d blocked_at=%q, want BLOCK at validate", bad, r.Decision, r.BlockedAt)
		}
	}
	if r := toolResult(pl, "web_fetch", map[string]any{"structured": true}); r.Decision != decision.Block {
		t.Errorf("non-text result = %d, want BLOCK", r.Decision)
	}
}
