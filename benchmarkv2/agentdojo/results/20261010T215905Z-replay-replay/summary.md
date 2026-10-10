# AgentDojo with ACF in the agent loop

Mode `replay`, agent model `none (replay)`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`.
ACF commit `a71e9cff32130f16d9a143c7539e45740d7b3ecb`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

Replay: no model. A worst-case agent replays the ground-truth calls and obeys any injected instruction it can read, so every attack reaches ACF. Utility here is a lower bound: a case counts as useful only if the suite's check passes and none of the user's own tool results was blocked or sanitised.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 100.0% | 39.9% | 98.0% | 0/2374 | 0 | 0 | 0 | 0 |
| gate-global | 100.0% | 39.9% | 98.0% | 0/2374 | 0 | 0 | 0 | 0 |
| gate-task | 100.0% | 94.1% | 15.8% | 0/2374 | 0 | 511 | 0 | 0 |
| detect | 100.0% | 39.9% | 98.0% | 0/2374 | 0 | 0 | 0 | 0 |
| full-global | 100.0% | 39.9% | 98.0% | 0/2374 | 0 | 0 | 0 | 0 |
| full-task | 100.0% | 94.1% | 15.8% | 0/2374 | 0 | 511 | 0 | 0 |
| full-global-taint | 86.6% | 70.6% | 53.5% | 97/2374 | 0 | 280 | 0 | 0 |
| full-task-taint | 86.6% | 86.9% | 12.2% | 97/2374 | 0 | 533 | 0 | 0 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 100.0% | 87.5% | 99.3% | 0/330 |
| none | slack | 100.0% | 98.1% | 100.0% | 0/588 |
| none | travel | 100.0% | 6.7% | 98.3% | 0/868 |
| none | workspace | 100.0% | 2.5% | 96.2% | 0/588 |
| gate-global | banking | 100.0% | 87.5% | 99.3% | 0/330 |
| gate-global | slack | 100.0% | 98.1% | 100.0% | 0/588 |
| gate-global | travel | 100.0% | 6.7% | 98.3% | 0/868 |
| gate-global | workspace | 100.0% | 2.5% | 96.2% | 0/588 |
| gate-task | banking | 100.0% | 99.3% | 31.9% | 0/330 |
| gate-task | slack | 100.0% | 98.1% | 20.0% | 0/588 |
| gate-task | travel | 100.0% | 94.2% | 5.8% | 0/868 |
| gate-task | workspace | 100.0% | 89.2% | 9.2% | 0/588 |
| detect | banking | 100.0% | 87.5% | 99.3% | 0/330 |
| detect | slack | 100.0% | 98.1% | 100.0% | 0/588 |
| detect | travel | 100.0% | 6.7% | 98.3% | 0/868 |
| detect | workspace | 100.0% | 2.5% | 96.2% | 0/588 |
| full-global | banking | 100.0% | 87.5% | 99.3% | 0/330 |
| full-global | slack | 100.0% | 98.1% | 100.0% | 0/588 |
| full-global | travel | 100.0% | 6.7% | 98.3% | 0/868 |
| full-global | workspace | 100.0% | 2.5% | 96.2% | 0/588 |
| full-task | banking | 100.0% | 99.3% | 31.9% | 0/330 |
| full-task | slack | 100.0% | 98.1% | 20.0% | 0/588 |
| full-task | travel | 100.0% | 94.2% | 5.8% | 0/868 |
| full-task | workspace | 100.0% | 89.2% | 9.2% | 0/588 |
| full-global-taint | banking | 87.5% | 81.2% | 99.3% | 11/330 |
| full-global-taint | slack | 76.2% | 74.3% | 80.0% | 30/588 |
| full-global-taint | travel | 100.0% | 53.3% | 49.2% | 0/868 |
| full-global-taint | workspace | 85.0% | 71.2% | 16.7% | 56/588 |
| full-task-taint | banking | 87.5% | 93.1% | 31.9% | 11/330 |
| full-task-taint | slack | 76.2% | 74.3% | 20.0% | 30/588 |
| full-task-taint | travel | 100.0% | 95.8% | 4.2% | 0/868 |
| full-task-taint | workspace | 85.0% | 84.2% | 0.8% | 56/588 |

## Not replayed

Injection tasks with no ground-truth tool calls (the attack is in the agent's text answer, or upstream gives no reference calls) cannot be replayed. Agent mode covers them.

- travel: injection_task_6
- workspace: injection_task_6, injection_task_7, injection_task_8, injection_task_9, injection_task_10, injection_task_11, injection_task_12, injection_task_13

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
