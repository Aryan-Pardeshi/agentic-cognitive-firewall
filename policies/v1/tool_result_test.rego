# ACF — Tool Result Policy Tests
# Validates: score thresholds for untrusted tool output, and that output from
# a configured trusted tool is not screened.

package acf.policy.tool_result_test

import future.keywords.if
import future.keywords.in
import data.acf.policy.tool_result

_result(tool, score) := {
    "tool_name": tool,
    "score": score,
    "signals": [],
    "provenance": "tool_output", "session_id": "", "hook_type": "on_tool_result",
}

test_low_score_output_allowed if {
    tool_result.decision == "ALLOW" with input as _result("web_fetch", 0.1)
        with data.config.trusted_tools as []
}

test_medium_score_output_sanitised if {
    tool_result.decision == "SANITISE" with input as _result("web_fetch", 0.6)
        with data.config.trusted_tools as []
    "tool_result" in tool_result.sanitise_targets with input as _result("web_fetch", 0.6)
        with data.config.trusted_tools as []
}

test_high_score_output_blocked if {
    tool_result.decision == "BLOCK" with input as _result("web_fetch", 0.9)
        with data.config.trusted_tools as []
}

test_trusted_tool_output_not_screened if {
    tool_result.decision == "ALLOW" with input as _result("payments_api", 0.9)
        with data.config.trusted_tools as ["payments_api"]
}

test_trust_is_per_tool if {
    tool_result.decision == "BLOCK" with input as _result("web_fetch", 0.9)
        with data.config.trusted_tools as ["payments_api"]
}

test_no_trusted_tools_configured_screens_everything if {
    tool_result.decision == "BLOCK" with input as _result("payments_api", 0.9)
        with data.config as {}
}
