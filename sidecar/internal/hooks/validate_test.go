package hooks

import "testing"

func TestToolResultValidator(t *testing.T) {
	h, _ := Lookup("on_tool_result")
	good := map[string]any{"tool": "web_fetch", "result": "page text"}
	if err := h.Validate(good); err != nil {
		t.Errorf("valid payload rejected: %v", err)
	}
	for name, bad := range map[string]any{
		"not an object":     "text",
		"missing tool":      map[string]any{"result": "x"},
		"empty tool":        map[string]any{"tool": "", "result": "x"},
		"tool not a string": map[string]any{"tool": 1, "result": "x"},
		"missing result":    map[string]any{"tool": "t"},
		"result not text":   map[string]any{"tool": "t", "result": map[string]any{"a": 1}},
	} {
		if err := h.Validate(bad); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
}

func TestOnlyHooksThatNeedItHaveAValidator(t *testing.T) {
	for _, name := range []string{"on_prompt", "on_context", "on_tool_call", "on_memory", "on_task"} {
		if h, _ := Lookup(name); h.Validate != nil {
			t.Errorf("%s has a validator; its payload checks live elsewhere", name)
		}
	}
}
