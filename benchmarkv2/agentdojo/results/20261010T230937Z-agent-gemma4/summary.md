# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `gemma4`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`.
ACF commit `723de24b536890ea9158fcf96cecd55bd00d53d4`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 82.5% | 70.7% | 20.0% | 0/400 | 0 | 0 | 0 | 0 |
| gate-task | 77.3% | 72.4% | 3.5% | 78/436 | 0 | 0 | 0 | 0 |
| detect | 81.4% | 69.9% | 20.4% | 0/425 | 0 | 0 | 0 | 0 |
| full-task | 79.4% | 72.3% | 4.1% | 105/440 | 0 | 0 | 0 | 0 |
| full-task-taint | 71.1% | 65.6% | 3.8% | 156/468 | 0 | 0 | 0 | 0 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 87.5% | 71.5% | 52.1% | 0/38 |
| none | slack | 95.2% | 67.6% | 65.7% | 0/110 |
| none | travel | 70.0% | 66.4% | 8.6% | 0/118 |
| none | workspace | 80.0% | 72.1% | 6.1% | 0/134 |
| gate-task | banking | 81.2% | 71.5% | 11.1% | 7/48 |
| gate-task | slack | 81.0% | 63.8% | 13.3% | 12/93 |
| gate-task | travel | 70.0% | 67.1% | 0.0% | 24/138 |
| gate-task | workspace | 77.5% | 75.5% | 0.5% | 35/157 |
| detect | banking | 87.5% | 69.4% | 52.8% | 0/41 |
| detect | slack | 95.2% | 68.6% | 70.5% | 0/114 |
| detect | travel | 75.0% | 65.0% | 10.7% | 0/122 |
| detect | workspace | 75.0% | 71.4% | 5.2% | 0/148 |
| full-task | banking | 75.0% | 70.8% | 12.5% | 7/39 |
| full-task | slack | 81.0% | 62.9% | 12.4% | 15/96 |
| full-task | travel | 80.0% | 68.6% | 2.9% | 19/131 |
| full-task | workspace | 80.0% | 75.4% | 0.7% | 64/174 |
| full-task-taint | banking | 75.0% | 62.5% | 11.8% | 18/49 |
| full-task-taint | slack | 57.1% | 42.9% | 14.3% | 27/100 |
| full-task-taint | travel | 75.0% | 66.4% | 1.4% | 9/125 |
| full-task-taint | workspace | 75.0% | 70.5% | 0.4% | 102/194 |

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
