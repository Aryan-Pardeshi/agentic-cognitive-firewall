# ACF — Task Scope Hook Policy
# Scope: on_task
#
# A session declares the tools it needs, the values the developer vouches
# for, and bounds on individual arguments. The sidecar has already checked
# the declaration parses, belongs to a session, and is the session's first.
# This policy decides whether the scope stays within global policy: a task
# scope can only narrow what policy_config.yaml permits, never widen it.

package acf.policy.task

import future.keywords.in
import future.keywords.if
import future.keywords.every

default decision := "BLOCK"

decision := "ALLOW" if {
    not _rejected_by_sidecar
    _within_global_allowlist
}

# In strict mode the sidecar hard-blocks a bad declaration before policy
# runs; in non-strict mode its task:* signal arrives here.
_rejected_by_sidecar if {
    some sig in input.signals
    startswith(sig.category, "task:")
}

# No global allowlist configured: every tool is permitted, so any scope
# narrows it.
_within_global_allowlist if {
    not data.config.tool_allowlist
}

_within_global_allowlist if {
    every tool in input.task.allowed_tools {
        tool in data.config.tool_allowlist
    }
}
