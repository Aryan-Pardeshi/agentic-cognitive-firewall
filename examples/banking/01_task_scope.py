"""
Banking 01: task scope.

A session declares what one task needs: the tools it may call and bounds on
their arguments. The sidecar then blocks anything outside that scope, whatever
the agent was told to do. A scope can only narrow the application's allowlist
in policy.yaml, so a scope naming any other tool is rejected outright.

Run run_sidecar.py first, then:  python examples/banking/01_task_scope.py
"""
from bank import USER_IBAN, show

from acf import Decision, Firewall, FirewallError

fw = Firewall()
print("=== Banking 01: task scope ===\n")

# The task "send 50 to my own account" needs reading nothing and paying once,
# at most 100.
with fw.session(
    allowed_tools=["send_money"],
    tool_constraints={"send_money": {"amount": {"max": 100}}},
) as s:
    s.on_prompt(f"Please send 50 to my savings account {USER_IBAN}.")
    checks = [
        ("send_money 50 to the user's account", s.on_tool_call(
            "send_money", {"recipient": USER_IBAN, "amount": 50}), Decision.ALLOW),
        ("send_money 5000: breaks the amount bound", s.on_tool_call(
            "send_money", {"recipient": USER_IBAN, "amount": 5000}), Decision.BLOCK),
        ("update_password: allowed by the app, not by this task", s.on_tool_call(
            "update_password", {"password": "hunter2"}), Decision.BLOCK),
    ]
    ok = True
    for label, result, expected in checks:
        show(label, result)
        ok &= result == expected

# A scope may only narrow policy.yaml's tool_allowlist.
print()
try:
    fw.session(allowed_tools=["send_money", "delete_account"])
    print("  scope naming delete_account                               -> accepted (unexpected)")
    ok = False
except FirewallError as exc:
    print(f"  scope naming delete_account                                -> rejected: {exc}")

print("\nPASS" if ok else "\nFAIL")
