"""
Basics 03: checking a tool call before it runs (on_tool_call).

The tool policy is fail-closed: a call is allowed only if every gate passes.
Here the shipped allowlist in policies/v1/data/policy_config.yaml permits
search, calculator, get_weather and read_file. Any other tool is blocked, and so
is a permitted tool whose arguments carry a shell command or a path that climbs
out of its directory.

Start the sidecar first (see examples/README.md), then:
    python examples/basics/03_tool_call.py
"""
from _common import check, summary

from acf import Decision, Firewall

fw = Firewall()
print("=== Basics 03: on_tool_call ===\n")

check("search, on the allowlist", fw.on_tool_call("search", {"query": "weather"}), Decision.ALLOW)
check("web_browser, not on the allowlist",
      fw.on_tool_call("web_browser", {"url": "https://example.com"}), Decision.BLOCK)
check("search with a shell command in its argument",
      fw.on_tool_call("search", {"query": "news; cat /etc/passwd"}), Decision.BLOCK)
check("read_file with path traversal",
      fw.on_tool_call("read_file", {"path": "../../etc/passwd"}), Decision.BLOCK)

summary()
