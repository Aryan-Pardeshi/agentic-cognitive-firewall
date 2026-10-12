# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `gemma4`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`.
ACF commit `50eef1de105df19f5a22486065fe851af90b062c`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 83.5% | 70.4% | 19.6% | 0/427 | 0 | 0 | 0 | 0 |
| gate-task | 80.4% | 71.4% | 3.9% | 87/428 | 0 | 0 | 0 | 0 |
| full-global-taint | 71.1% | 65.5% | 5.4% | 52/471 | 0 | 0 | 0 | 0 |
| full-task-taint | 67.0% | 64.1% | 1.6% | 146/451 | 0 | 0 | 0 | 0 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 87.5% | 71.5% | 52.8% | 0/41 |
| none | slack | 95.2% | 67.6% | 66.7% | 0/117 |
| none | travel | 75.0% | 65.0% | 7.9% | 0/126 |
| none | workspace | 80.0% | 72.0% | 5.2% | 0/143 |
| gate-task | banking | 81.2% | 70.1% | 13.2% | 7/40 |
| gate-task | slack | 81.0% | 63.8% | 13.3% | 14/100 |
| gate-task | travel | 80.0% | 67.9% | 1.4% | 13/125 |
| gate-task | workspace | 80.0% | 74.1% | 0.4% | 53/163 |
| full-global-taint | banking | 75.0% | 66.7% | 9.0% | 4/38 |
| full-global-taint | slack | 66.7% | 38.1% | 16.2% | 12/125 |
| full-global-taint | travel | 70.0% | 65.7% | 7.9% | 0/124 |
| full-global-taint | workspace | 72.5% | 70.4% | 1.8% | 36/184 |
| full-task-taint | banking | 75.0% | 61.1% | 0.0% | 15/46 |
| full-task-taint | slack | 47.6% | 34.3% | 10.5% | 36/112 |
| full-task-taint | travel | 70.0% | 67.1% | 1.4% | 22/140 |
| full-task-taint | workspace | 72.5% | 69.6% | 0.4% | 73/153 |

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
