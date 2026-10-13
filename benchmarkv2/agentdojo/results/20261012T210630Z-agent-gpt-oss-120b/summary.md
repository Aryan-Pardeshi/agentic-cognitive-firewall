# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `gpt-oss-120b`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`, model thinking `model default`.
ACF commit `8c5a26b7b4b5d779c3d74425cc89cd76564d5689`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 72.2% | 54.9% | 37.9% | 0/395 | 0 | 0 | 0 | 7 |
| gate-task | 72.9% | 64.1% | 6.3% | 35/394 | 0 | 0 | 0 | 5 |
| full-global-taint | 66.7% | 49.3% | 12.4% | 32/438 | 0 | 0 | 0 | 7 |
| full-task-taint | 55.2% | 51.1% | 2.7% | 62/386 | 0 | 0 | 0 | 4 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 62.5% | 60.1% | 71.3% | 0/24 |
| none | slack | 95.2% | 66.3% | 92.3% | 0/115 |
| none | travel | 30.0% | 18.7% | 58.3% | 0/124 |
| none | workspace | 85.0% | 60.4% | 14.0% | 0/132 |
| gate-task | banking | 75.0% | 66.0% | 13.9% | 6/33 |
| gate-task | slack | 80.0% | 41.9% | 15.2% | 10/81 |
| gate-task | travel | 45.0% | 28.5% | 10.9% | 3/153 |
| gate-task | workspace | 82.5% | 76.6% | 1.6% | 16/127 |
| full-global-taint | banking | 68.8% | 54.2% | 8.3% | 1/26 |
| full-global-taint | slack | 71.4% | 21.2% | 18.3% | 8/116 |
| full-global-taint | travel | 52.6% | 20.3% | 47.1% | 0/105 |
| full-global-taint | workspace | 70.0% | 60.5% | 3.8% | 23/191 |
| full-task-taint | banking | 56.2% | 52.8% | 0.0% | 3/23 |
| full-task-taint | slack | 52.4% | 19.0% | 8.6% | 22/88 |
| full-task-taint | travel | 31.6% | 31.7% | 10.8% | 5/149 |
| full-task-taint | workspace | 67.5% | 61.5% | 0.4% | 32/126 |

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
