# ACF — Tool Call Argument Taint Tests
# Validates: a consequential tool is blocked when a sensitive argument carries
# a value read in untrusted content, per input.state.taint.

package acf.policy.tool_taint_test

import future.keywords.if
import data.acf.policy.tool

_call(name, params, findings) := {
    "tool_name": name,
    "tool_params": params,
    "tool_metadata": {},
    "score": 0.0,
    "signals": [],
    "provenance": "agent", "session_id": "s1", "hook_type": "on_tool_call",
    "state": {"requests": 3, "blocked": 0, "taint": findings},
}

_finding(param, sources) := {
    "param": param, "kind": "email", "value": "attacker@evil.example", "sources": sources,
}

_page := {"hook": "on_tool_result", "tool": "web_fetch"}
_payments := {"hook": "on_tool_result", "tool": "payments_api"}
_doc := {"hook": "on_context", "tool": ""}

_cfg := {
    "tool_allowlist": ["send_email", "send_money", "search"],
    "consequential_tools": ["send_email", "send_money"],
    "trusted_tools": ["payments_api"],
    "sensitive_params": {"send_money": ["recipient"]},
}

test_tainted_argument_to_consequential_tool_blocked if {
    tool.decision == "BLOCK" with input as _call("send_email", {"to": "attacker@evil.example"},
            [_finding("to", [_page])])
        with data.config as _cfg
}

test_untainted_consequential_call_allowed if {
    tool.decision == "ALLOW" with input as _call("send_email", {"to": "amy@corp.example"}, [])
        with data.config as _cfg
}

test_tainted_argument_to_non_consequential_tool_allowed if {
    tool.decision == "ALLOW" with input as _call("search", {"query": "attacker@evil.example"},
            [_finding("query", [_page])])
        with data.config as _cfg
}

test_value_only_from_trusted_tool_does_not_taint if {
    tool.decision == "ALLOW" with input as _call("send_money", {"recipient": "x"},
            [_finding("recipient", [_payments])])
        with data.config as _cfg
}

test_any_untrusted_source_is_enough if {
    tool.decision == "BLOCK" with input as _call("send_money", {"recipient": "x"},
            [_finding("recipient", [_payments, _page])])
        with data.config as _cfg
}

test_retrieved_document_is_untrusted if {
    tool.decision == "BLOCK" with input as _call("send_email", {"to": "x"},
            [_finding("to", [_doc])])
        with data.config as _cfg
}

test_overflow_fails_closed if {
    tool.decision == "BLOCK" with input as _call("send_email", {"to": "x"},
            [_finding("to", [{"hook": "overflow", "tool": ""}])])
        with data.config as _cfg
}

test_sensitive_params_limit_the_check if {
    tool.decision == "ALLOW" with input as _call("send_money", {"memo": "x"},
            [_finding("memo", [_page])])
        with data.config as _cfg
    tool.decision == "BLOCK" with input as _call("send_money", {"recipient": "x"},
            [_finding("recipient", [_page])])
        with data.config as _cfg
}

test_omitted_consequential_tools_makes_every_tool_consequential if {
    strict := object.remove(_cfg, ["consequential_tools"])
    tool.decision == "BLOCK" with input as _call("search", {"query": "x"},
            [_finding("query", [_page])])
        with data.config as strict
}

test_empty_consequential_tools_switches_tainting_off if {
    off := object.union(_cfg, {"consequential_tools": []})
    tool.decision == "ALLOW" with input as _call("send_email", {"to": "x"},
            [_finding("to", [_page])])
        with data.config as off
}
