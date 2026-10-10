package state

import (
	"errors"
	"fmt"
	"regexp"
)

// Limits on a declared scope, so a declaration cannot be used to make the
// sidecar hold or evaluate unbounded data.
const (
	maxAllowedTools  = 256
	maxTrustedValues = 1024
	maxValueLen      = 1024
	maxRuleValues    = 256
)

// TaskScope is what a session declares it needs, via the on_task hook. Policies
// enforce it for the rest of the session: tool calls outside AllowedTools are
// blocked, and ToolConstraints bound individual arguments. TrustedValues are
// values the developer vouches for, such as user-supplied recipients.
type TaskScope struct {
	AllowedTools    []string
	TrustedValues   []string
	ToolConstraints map[string]map[string]ParamRule
}

// ParamRule bounds one argument of one tool. Every rule set must hold. An
// argument the call does not pass is not checked.
type ParamRule struct {
	// Allowed lists the permitted values. An empty, non-nil list permits none.
	Allowed []any
	// Pattern is a regular expression the value must match (RE2, as in Rego).
	Pattern string
	// Max is the largest permitted numeric value.
	Max *float64
}

// ParseTaskScope validates an on_task payload and returns the scope it
// declares. It rejects unknown keys, wrong types, a constrained tool that is
// not allowed, and a pattern that does not compile, so a policy never has to
// guess what a malformed declaration meant.
func ParseTaskScope(payload any) (*TaskScope, error) {
	m, ok := payload.(map[string]any)
	if !ok {
		return nil, errors.New("task scope must be an object")
	}
	for k := range m {
		switch k {
		case "allowed_tools", "trusted_values", "tool_constraints":
		default:
			return nil, fmt.Errorf("unknown task scope field %q", k)
		}
	}

	tools, err := stringList(m["allowed_tools"], "allowed_tools", maxAllowedTools, true)
	if err != nil {
		return nil, err
	}
	trusted, err := stringList(m["trusted_values"], "trusted_values", maxTrustedValues, false)
	if err != nil {
		return nil, err
	}
	scope := &TaskScope{AllowedTools: tools, TrustedValues: trusted}

	raw, present := m["tool_constraints"]
	if !present || raw == nil {
		return scope, nil
	}
	byTool, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("tool_constraints must be an object")
	}
	allowed := map[string]bool{}
	for _, t := range tools {
		allowed[t] = true
	}
	scope.ToolConstraints = map[string]map[string]ParamRule{}
	for tool, rawParams := range byTool {
		if !allowed[tool] {
			return nil, fmt.Errorf("tool_constraints names %q, which is not in allowed_tools", tool)
		}
		params, ok := rawParams.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tool_constraints.%s must be an object", tool)
		}
		rules := map[string]ParamRule{}
		for param, rawRule := range params {
			rule, err := parseRule(rawRule)
			if err != nil {
				return nil, fmt.Errorf("tool_constraints.%s.%s: %w", tool, param, err)
			}
			rules[param] = rule
		}
		scope.ToolConstraints[tool] = rules
	}
	return scope, nil
}

func stringList(raw any, field string, max int, required bool) ([]string, error) {
	if raw == nil {
		if required {
			return nil, fmt.Errorf("%s is required", field)
		}
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of strings", field)
	}
	if len(items) > max {
		return nil, fmt.Errorf("%s has %d entries, more than %d", field, len(items), max)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok || s == "" || len(s) > maxValueLen {
			return nil, fmt.Errorf("%s entries must be non-empty strings of at most %d bytes", field, maxValueLen)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseRule(raw any) (ParamRule, error) {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return ParamRule{}, errors.New("a rule must be an object with allowed, pattern or max")
	}
	var r ParamRule
	for k, v := range m {
		switch k {
		case "allowed":
			list, ok := v.([]any)
			if !ok || len(list) > maxRuleValues {
				return r, fmt.Errorf("allowed must be a list of at most %d values", maxRuleValues)
			}
			r.Allowed = append([]any{}, list...)
		case "pattern":
			s, ok := v.(string)
			if !ok || len(s) > maxValueLen {
				return r, errors.New("pattern must be a string")
			}
			if _, err := regexp.Compile(s); err != nil {
				return r, fmt.Errorf("pattern does not compile: %w", err)
			}
			r.Pattern = s
		case "max":
			f, ok := v.(float64)
			if !ok {
				return r, errors.New("max must be a number")
			}
			r.Max = &f
		default:
			return r, fmt.Errorf("unknown rule key %q", k)
		}
	}
	return r, nil
}

// clone returns a deep copy of the scope.
func (t *TaskScope) clone() *TaskScope {
	if t == nil {
		return nil
	}
	c := &TaskScope{
		AllowedTools:  append([]string(nil), t.AllowedTools...),
		TrustedValues: append([]string(nil), t.TrustedValues...),
	}
	if t.ToolConstraints != nil {
		c.ToolConstraints = map[string]map[string]ParamRule{}
		for tool, rules := range t.ToolConstraints {
			cr := map[string]ParamRule{}
			for p, r := range rules {
				cp := ParamRule{Pattern: r.Pattern}
				if r.Allowed != nil {
					cp.Allowed = append([]any{}, r.Allowed...)
				}
				if r.Max != nil {
					m := *r.Max
					cp.Max = &m
				}
				cr[p] = cp
			}
			c.ToolConstraints[tool] = cr
		}
	}
	return c
}

// view renders the scope as JSON-shaped values for the policy input.
func (t *TaskScope) view() map[string]any {
	constraints := map[string]any{}
	for tool, rules := range t.ToolConstraints {
		params := map[string]any{}
		for p, r := range rules {
			rule := map[string]any{}
			if r.Allowed != nil {
				rule["allowed"] = append([]any{}, r.Allowed...)
			}
			if r.Pattern != "" {
				rule["pattern"] = r.Pattern
			}
			if r.Max != nil {
				rule["max"] = *r.Max
			}
			params[p] = rule
		}
		constraints[tool] = params
	}
	return map[string]any{
		"allowed_tools":    toAny(t.AllowedTools),
		"trusted_values":   toAny(t.TrustedValues),
		"tool_constraints": constraints,
	}
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
