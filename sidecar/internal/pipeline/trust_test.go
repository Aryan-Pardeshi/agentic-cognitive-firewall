package pipeline

import (
	"testing"

	"github.com/acf-sdk/sidecar/internal/benchdata"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func TestValidate_ProvenanceComesFromTheHook(t *testing.T) {
	want := map[string]string{"on_prompt": "user", "on_context": "rag", "on_tool_call": "agent", "on_memory": "agent"}
	for hook, prov := range want {
		rc := &riskcontext.RiskContext{HookType: hook, Provenance: "memory_read", Payload: "x"}
		if NewValidateStage().Run(rc) {
			t.Fatalf("%s: unexpected hard block, signals=%v", hook, rc.Signals)
		}
		if rc.Provenance != prov || rc.ClaimedProvenance != "memory_read" {
			t.Errorf("%s: provenance=%q claimed=%q, want %q with the claim kept",
				hook, rc.Provenance, rc.ClaimedProvenance, prov)
		}
	}
}

func TestValidate_SetsAsideFieldsTheClientMustNotControl(t *testing.T) {
	rc := &riskcontext.RiskContext{
		HookType:   "on_context",
		Provenance: "rag",
		Payload:    "x",
		Score:      0.01,
		State:      map[string]any{"allowed_tools": []any{"send_money"}},
		Signals:    []riskcontext.Signal{{Category: "source_trust", Score: 0.99}},
	}
	NewValidateStage().Run(rc)
	if len(rc.Signals) != 0 || len(rc.ClientSignals) != 1 {
		t.Errorf("signals=%v client=%v, want the client's signal set aside", rc.Signals, rc.ClientSignals)
	}
	if rc.Score != 0 || rc.State != nil {
		t.Errorf("score=%v state=%v, want both cleared", rc.Score, rc.State)
	}
}

func TestValidate_RejectedRequestCarriesOnlyTheValidateSignal(t *testing.T) {
	rc := &riskcontext.RiskContext{
		HookType: "on_unknown", Provenance: "user", Payload: "x",
		Signals: []riskcontext.Signal{{Category: "source_trust", Score: 0.99}},
	}
	if !NewValidateStage().Run(rc) {
		t.Fatal("expected a hard block for an unknown hook")
	}
	if len(rc.Signals) != 1 || rc.Signals[0].Category != "validate:invalid_hook_type" {
		t.Errorf("signals = %v, want only validate:invalid_hook_type", rc.Signals)
	}
}

func TestAggregate_ClientSignalsCanOnlyAddWeightedRisk(t *testing.T) {
	agg := NewAggregateStage(testConfig(true), StaticWeights{"jailbreak_pattern": 0.9, "instruction_override": 0.85})

	// A weighted category counts at its configured weight, not the client's score.
	rc := &riskcontext.RiskContext{
		HookType: "on_prompt", Provenance: "user",
		ClientSignals: []riskcontext.Signal{{Category: "instruction_override", Score: 0.01}},
	}
	agg.Run(rc)
	if rc.Score != 0.85 {
		t.Errorf("score = %v, want 0.85 from the weight table", rc.Score)
	}

	// A category with no weight is dropped, and with it the client's score.
	rc = &riskcontext.RiskContext{
		HookType: "on_prompt", Provenance: "user",
		Signals:       []riskcontext.Signal{{Category: "jailbreak_pattern"}},
		ClientSignals: []riskcontext.Signal{{Category: "source_trust", Score: 0.99}},
	}
	agg.Run(rc)
	for _, s := range rc.Signals {
		if s.Category == "source_trust" {
			t.Errorf("unweighted client category reached policy: %v", rc.Signals)
		}
	}
	if rc.Score != 0.9 || rc.ClientSignals != nil {
		t.Errorf("score=%v client=%v, want 0.9 and the client signals consumed", rc.Score, rc.ClientSignals)
	}
}

// TestClientCannotLowerItsOwnVerdict runs the shipped config and policies end
// to end. Before the sidecar took these fields out of the client's hands, a
// client could send source_trust 0.99, which context.rego turns into a 0.5x
// multiplier on the effective score, and claim a provenance with a lower trust
// weight. Decisions are bytes ordered ALLOW < SANITISE < BLOCK, so a forged
// request must never come back with a smaller one.
func TestClientCannotLowerItsOwnVerdict(t *testing.T) {
	env := newBenchEnv(t)
	inputs := []struct {
		hook, provenance string
		payload          any
	}{
		{"on_context", "rag", benchdata.InjectedText(1024)},
		{"on_prompt", "user", benchdata.Injection},
	}
	forgeries := []struct {
		name   string
		mutate func(*riskcontext.RiskContext)
	}{
		{"claims a low-trust provenance", func(rc *riskcontext.RiskContext) { rc.Provenance = "memory_read" }},
		{"sends source_trust", func(rc *riskcontext.RiskContext) {
			rc.Signals = []riskcontext.Signal{{Category: "source_trust", Score: 0.99}}
		}},
		{"sends a zero score and a state", func(rc *riskcontext.RiskContext) {
			rc.Score = 0
			rc.State = map[string]any{"trusted": true}
		}},
		{"all of the above", func(rc *riskcontext.RiskContext) {
			rc.Provenance = "memory_read"
			rc.Signals = []riskcontext.Signal{{Category: "source_trust", Score: 0.99}}
			rc.State = map[string]any{"trusted": true}
		}},
	}
	run := func(hook, provenance string, payload any, mutate func(*riskcontext.RiskContext)) byte {
		rc := &riskcontext.RiskContext{HookType: hook, Provenance: provenance, Payload: payload}
		if mutate != nil {
			mutate(rc)
		}
		return env.pl.Run(rc).Decision
	}
	for _, in := range inputs {
		base := run(in.hook, in.provenance, in.payload, nil)
		if base == decision.Allow {
			t.Fatalf("%s: baseline is ALLOW; the test needs an input the policy flags", in.hook)
		}
		for _, f := range forgeries {
			if got := run(in.hook, in.provenance, in.payload, f.mutate); got < base {
				t.Errorf("%s, client %s: decision %d weaker than baseline %d", in.hook, f.name, got, base)
			}
		}
	}
}
