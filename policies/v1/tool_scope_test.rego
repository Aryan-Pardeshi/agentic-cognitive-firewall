# ACF-SDK — Tool Call Task Scope Tests
# Validates: session allowed_tools and per-argument constraints, read from
# input.state.task, on top of the global allowlist.

package acf.policy.tool_scope_test

import future.keywords.if
import data.acf.policy.tool

_call(name, params, task) := {
    "tool_name": name,
    "tool_params": params,
    "tool_metadata": {},
    "score": 0.0,
    "signals": [],
    "provenance": "agent", "session_id": "s1", "hook_type": "on_tool_call",
    "state": {"requests": 1, "blocked": 0, "task": task},
}

_scope := {
    "allowed_tools": ["search", "get_weather"],
    "trusted_values": [],
    "tool_constraints": {
        "search": {"query": {"pattern": "^[a-z ]+$"}},
        "get_weather": {"city": {"allowed": ["paris", "london"]}, "days": {"max": 3}},
    },
}

_allowlist := ["search", "get_weather", "calculator"]

test_tool_in_scope_allowed if {
    tool.decision == "ALLOW" with input as _call("search", {"query": "weather today"}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_tool_globally_allowed_but_out_of_scope_blocked if {
    tool.decision == "BLOCK" with input as _call("calculator", {}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_no_task_leaves_global_allowlist_in_charge if {
    tool.decision == "ALLOW" with input as object.remove(_call("calculator", {}, _scope), ["state"])
        with data.config.tool_allowlist as _allowlist
}

test_scope_cannot_widen_global_allowlist if {
    wide := object.union(_scope, {"allowed_tools": ["search", "get_weather", "send_money"]})
    tool.decision == "BLOCK" with input as _call("send_money", {}, wide)
        with data.config.tool_allowlist as _allowlist
}

test_pattern_violation_blocked if {
    tool.decision == "BLOCK" with input as _call("search", {"query": "Weather; DROP"}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_pattern_on_non_string_blocked if {
    tool.decision == "BLOCK" with input as _call("search", {"query": 42}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_allowed_values_enforced if {
    tool.decision == "ALLOW" with input as _call("get_weather", {"city": "paris", "days": 2}, _scope)
        with data.config.tool_allowlist as _allowlist
    tool.decision == "BLOCK" with input as _call("get_weather", {"city": "lyon", "days": 2}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_max_enforced if {
    tool.decision == "ALLOW" with input as _call("get_weather", {"city": "paris", "days": 3}, _scope)
        with data.config.tool_allowlist as _allowlist
    tool.decision == "BLOCK" with input as _call("get_weather", {"city": "paris", "days": 7}, _scope)
        with data.config.tool_allowlist as _allowlist
    tool.decision == "BLOCK" with input as _call("get_weather", {"city": "paris", "days": "2"}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_unpassed_constrained_argument_is_not_checked if {
    tool.decision == "ALLOW" with input as _call("get_weather", {"city": "paris"}, _scope)
        with data.config.tool_allowlist as _allowlist
}

test_empty_allowed_list_permits_nothing if {
    strict := {"allowed_tools": ["search"], "tool_constraints": {"search": {"query": {"allowed": []}}}}
    tool.decision == "BLOCK" with input as _call("search", {"query": "anything"}, strict)
        with data.config.tool_allowlist as _allowlist
}
