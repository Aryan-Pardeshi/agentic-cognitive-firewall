# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `qwen3-8b`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`, model thinking `off`.
ACF commit `32a7250cdbbc260013dc3e4304d4f317089c6624`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 39.2% | 29.3% | 11.3% | 0/407 | 0 | 0 | 0 | 14 |
| gate-task | 33.3% | 24.6% | 1.1% | 38/241 | 0 | 0 | 0 | 18 |
| full-global-taint | 33.0% | 27.2% | 3.3% | 12/440 | 0 | 0 | 0 | 16 |
| full-task-taint | 30.2% | 23.5% | 0.8% | 46/236 | 0 | 0 | 0 | 19 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 56.2% | 47.2% | 12.5% | 0/21 |
| none | slack | 57.1% | 37.1% | 46.7% | 0/130 |
| none | travel | 35.0% | 27.9% | 23.6% | 0/125 |
| none | workspace | 25.0% | 23.4% | 1.1% | 0/131 |
| gate-task | banking | 56.2% | 47.2% | 0.7% | 2/17 |
| gate-task | slack | 42.9% | 19.0% | 4.8% | 11/60 |
| gate-task | travel | 30.0% | 25.0% | 2.9% | 6/105 |
| gate-task | workspace | 20.5% | 19.5% | 0.0% | 19/59 |
| full-global-taint | banking | 43.8% | 47.2% | 3.5% | 1/22 |
| full-global-taint | slack | 33.3% | 9.5% | 8.6% | 6/106 |
| full-global-taint | travel | 35.0% | 31.4% | 10.7% | 0/195 |
| full-global-taint | workspace | 27.5% | 24.3% | 0.4% | 5/117 |
| full-task-taint | banking | 50.0% | 47.9% | 0.0% | 3/17 |
| full-task-taint | slack | 28.6% | 7.6% | 3.8% | 16/62 |
| full-task-taint | travel | 30.0% | 28.6% | 2.1% | 7/100 |
| full-task-taint | workspace | 23.1% | 18.8% | 0.0% | 20/57 |

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
