package state

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestParseTaskScope_AcceptsAFullDeclaration(t *testing.T) {
	scope, err := ParseTaskScope(map[string]any{
		"allowed_tools":  []any{"send_money", "get_balance"},
		"trusted_values": []any{"GB29NWBK60161331926819"},
		"tool_constraints": map[string]any{
			"send_money": map[string]any{
				"recipient": map[string]any{"allowed": []any{"GB29NWBK60161331926819"}},
				"amount":    map[string]any{"max": 100.0},
				"memo":      map[string]any{"pattern": "^[A-Za-z ]{0,40}$"},
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseTaskScope: %v", err)
	}
	if !reflect.DeepEqual(scope.AllowedTools, []string{"send_money", "get_balance"}) {
		t.Errorf("allowed tools = %v", scope.AllowedTools)
	}
	rules := scope.ToolConstraints["send_money"]
	if got := sortedKeys(rules); !reflect.DeepEqual(got, []string{"amount", "memo", "recipient"}) {
		t.Errorf("constrained params = %v", got)
	}
	if *rules["amount"].Max != 100 || rules["memo"].Pattern == "" || len(rules["recipient"].Allowed) != 1 {
		t.Errorf("rules parsed wrongly: %+v", rules)
	}
}

func TestParseTaskScope_RejectsMalformedDeclarations(t *testing.T) {
	cases := map[string]any{
		"not an object":            []any{"x"},
		"missing allowed_tools":    map[string]any{},
		"unknown field":            map[string]any{"allowed_tools": []any{"a"}, "admin": true},
		"tools not strings":        map[string]any{"allowed_tools": []any{1}},
		"empty tool name":          map[string]any{"allowed_tools": []any{""}},
		"constraint on a tool not allowed": map[string]any{
			"allowed_tools":    []any{"a"},
			"tool_constraints": map[string]any{"b": map[string]any{"p": map[string]any{"max": 1.0}}},
		},
		"bad regex": map[string]any{
			"allowed_tools":    []any{"a"},
			"tool_constraints": map[string]any{"a": map[string]any{"p": map[string]any{"pattern": "("}}},
		},
		"unknown rule key": map[string]any{
			"allowed_tools":    []any{"a"},
			"tool_constraints": map[string]any{"a": map[string]any{"p": map[string]any{"min": 1.0}}},
		},
		"empty rule": map[string]any{
			"allowed_tools":    []any{"a"},
			"tool_constraints": map[string]any{"a": map[string]any{"p": map[string]any{}}},
		},
		"max not a number": map[string]any{
			"allowed_tools":    []any{"a"},
			"tool_constraints": map[string]any{"a": map[string]any{"p": map[string]any{"max": "10"}}},
		},
		"oversized value": map[string]any{"allowed_tools": []any{strings.Repeat("x", 1025)}},
	}
	for name, payload := range cases {
		if _, err := ParseTaskScope(payload); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
}

func TestSession_CloneAndViewCarryTheTask(t *testing.T) {
	max := 5.0
	s := &Session{ID: "s", Task: &TaskScope{
		AllowedTools:    []string{"a"},
		TrustedValues:   []string{"v"},
		ToolConstraints: map[string]map[string]ParamRule{"a": {"p": {Allowed: []any{"x"}, Max: &max}}},
	}}
	c := s.Clone()
	c.Task.AllowedTools[0] = "changed"
	*c.Task.ToolConstraints["a"]["p"].Max = 99
	if s.Task.AllowedTools[0] != "a" || *s.Task.ToolConstraints["a"]["p"].Max != 5 {
		t.Error("Clone shares the task scope with the original")
	}

	view := s.View()["task"].(map[string]any)
	if !reflect.DeepEqual(view["allowed_tools"], []any{"a"}) {
		t.Errorf("view allowed_tools = %v", view["allowed_tools"])
	}
	rule := view["tool_constraints"].(map[string]any)["a"].(map[string]any)["p"].(map[string]any)
	if rule["max"] != 5.0 || !reflect.DeepEqual(rule["allowed"], []any{"x"}) {
		t.Errorf("view rule = %v", rule)
	}
	if _, ok := (&Session{}).View()["task"]; ok {
		t.Error("a session with no task should not expose one")
	}
}
