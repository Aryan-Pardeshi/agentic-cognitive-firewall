# ACF — Task Scope Policy Tests
# Validates: a task scope can only narrow the global tool allowlist.

package acf.policy.task_test

import future.keywords.if
import data.acf.policy.task

_task_input(tools) := {
    "task": {"allowed_tools": tools},
    "score": 0.0,
    "signals": [],
    "provenance": "developer", "session_id": "s1", "hook_type": "on_task",
}

test_scope_within_global_allowlist_allowed if {
    result := task.decision with input as _task_input(["search"])
        with data.config.tool_allowlist as ["search", "calculator"]
    result == "ALLOW"
}

test_scope_widening_global_allowlist_blocked if {
    result := task.decision with input as _task_input(["search", "send_money"])
        with data.config.tool_allowlist as ["search", "calculator"]
    result == "BLOCK"
}

test_any_scope_allowed_when_no_global_allowlist if {
    result := task.decision with input as _task_input(["send_money"])
        with data.config as {}
    result == "ALLOW"
}

test_empty_global_allowlist_permits_only_an_empty_scope if {
    task.decision == "BLOCK" with input as _task_input(["search"])
        with data.config.tool_allowlist as []
    task.decision == "ALLOW" with input as _task_input([])
        with data.config.tool_allowlist as []
}

test_sidecar_rejection_signal_blocks if {
    result := task.decision with input as object.union(_task_input(["search"]),
            {"signals": [{"category": "task:invalid_scope", "score": 1.0}]})
        with data.config.tool_allowlist as ["search"]
    result == "BLOCK"
}
