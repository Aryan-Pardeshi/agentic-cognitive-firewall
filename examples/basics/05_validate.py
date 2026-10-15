"""
Basics 05: malformed requests are blocked before any policy runs.

The Validate stage checks every request before the rest of the pipeline. An
unknown or missing hook, a missing provenance claim, or an empty payload is a
hard block in the default strict mode: no Rego rule is consulted. The public
SDK methods always send well-formed requests, so this example sends raw ones
through the transport to show the check.

Start the sidecar first (see examples/README.md), then:
    python examples/basics/05_validate.py
"""
import json

from _common import check, summary

from acf import Decision, Firewall

fw = Firewall()


def send_raw(**fields) -> Decision:
    """Send a hand-built request and return the sidecar's decision."""
    request = {"score": 0.0, "signals": [], "provenance": "user", "session_id": "",
               "state": None, "hook_type": "on_prompt", "payload": "hello", **fields}
    raw = json.dumps(request, separators=(",", ":")).encode("utf-8")
    return Decision.from_byte(fw._transport.send(raw)["decision"])


print("=== Basics 05: validation before policy ===\n")
check("unknown hook", send_raw(hook_type="on_unknown_hook"), Decision.BLOCK)
check("missing hook", send_raw(hook_type=""), Decision.BLOCK)
check("missing provenance claim", send_raw(provenance=""), Decision.BLOCK)
check("empty payload", send_raw(payload=None), Decision.BLOCK)
check("well-formed request, for contrast", send_raw(payload="What is the weather today?"), Decision.ALLOW)
summary()
