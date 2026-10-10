package hooks

import (
	"reflect"
	"testing"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func TestBuiltinHooksAreRegistered(t *testing.T) {
	want := map[string][2]string{
		"on_prompt":    {"acf.policy.prompt", "user"},
		"on_context":   {"acf.policy.context", "rag"},
		"on_tool_call": {"acf.policy.tool", "agent"},
		"on_memory":    {"acf.policy.memory", "agent"},
	}
	for name, w := range want {
		h, ok := Lookup(name)
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		if h.Policy != w[0] || h.Provenance != w[1] {
			t.Errorf("%s = (%q, %q), want (%q, %q)", name, h.Policy, h.Provenance, w[0], w[1])
		}
	}
	if _, ok := Lookup("on_unknown"); ok {
		t.Error("an unregistered hook was found")
	}
}

func TestAllIsSortedAndMatchesNames(t *testing.T) {
	names := Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("names not sorted: %v", names)
		}
	}
	all := All()
	if len(all) != len(names) {
		t.Fatalf("All has %d hooks, Names has %d", len(all), len(names))
	}
}

func TestRegisterRejectsDuplicatesAndEmptyFields(t *testing.T) {
	for _, h := range []Hook{
		{Name: "on_prompt", Policy: "acf.policy.prompt", Provenance: "user"},
		{Name: "", Policy: "acf.policy.x", Provenance: "x"},
		{Name: "on_x", Policy: "", Provenance: "x"},
		{Name: "on_x", Policy: "acf.policy.x", Provenance: ""},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) did not panic", h)
				}
			}()
			Register(h)
		}()
	}
}

func TestInputBuildersMatchThePreviousEngineFields(t *testing.T) {
	cases := []struct {
		hook    string
		payload any
		want    map[string]any
	}{
		{"on_tool_call", map[string]any{"name": "search", "params": map[string]any{}},
			map[string]any{"tool_name": "search", "tool_metadata": map[string]any{}}},
		{"on_tool_call", map[string]any{"name": "fetch", "metadata": map[string]any{"destination": "x.com"}},
			map[string]any{"tool_name": "fetch", "tool_metadata": map[string]any{"destination": "x.com"}}},
		{"on_context", map[string]any{"content": "abcd", "source_trust": 0.2},
			map[string]any{"payload_size_bytes": 4, "source_trust": 0.2}},
		{"on_memory", map[string]any{"op": "write", "value": "abc", "hmac_valid": true},
			map[string]any{"memory_op": "write", "payload_size_bytes": 3,
				"integrity": map[string]any{"hmac_valid": true}}},
		{"on_context", "a plain string chunk", map[string]any{}},
	}
	for _, c := range cases {
		h, _ := Lookup(c.hook)
		got := map[string]any{}
		if h.Input != nil {
			h.Input(&riskcontext.RiskContext{HookType: c.hook, Payload: c.payload}, got)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %v: input = %v, want %v", c.hook, c.payload, got, c.want)
		}
	}
}
