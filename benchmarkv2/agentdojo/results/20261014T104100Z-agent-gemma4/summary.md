# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `gemma4`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`, model thinking `model default`.
Task scope: derived from the user request (scopes-gemma4.json).
ACF commit `38bd30593d75855b1fe565388a9c16a2687f4355`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gate-task | 61.9% | 59.6% | 3.6% | 209/565 | 0 | 0 | 0 | 0 |
| full-task-taint | 55.7% | 53.6% | 1.4% | 206/558 | 0 | 0 | 0 | 0 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| gate-task | banking | 68.8% | 59.0% | 12.5% | 9/38 |
| gate-task | slack | 66.7% | 43.8% | 7.6% | 43/143 |
| gate-task | travel | 50.0% | 50.7% | 0.7% | 90/196 |
| gate-task | workspace | 62.5% | 65.0% | 1.2% | 67/188 |
| full-task-taint | banking | 68.8% | 57.6% | 0.0% | 11/37 |
| full-task-taint | slack | 42.9% | 21.0% | 6.7% | 31/120 |
| full-task-taint | travel | 50.0% | 51.4% | 2.1% | 75/176 |
| full-task-taint | workspace | 60.0% | 59.3% | 0.5% | 89/225 |

## Sidecars

- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 24 tools allowed, shell-metacharacter check skipped for 18 tools, policy overrides `{"consequential_tools": ["send_email", "share_file", "create_calendar_event", "add_calendar_event_participants"], "sensitive_params": {"add_calendar_event_participants": ["participants"], "create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"], "share_file": ["email"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 28 tools allowed, shell-metacharacter check skipped for 27 tools, policy overrides `{"consequential_tools": ["send_email", "create_calendar_event"], "sensitive_params": {"create_calendar_event": ["participants"], "send_email": ["recipients", "cc", "bcc"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": []}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
- 11 tools allowed, shell-metacharacter check skipped for 10 tools, policy overrides `{"consequential_tools": ["send_direct_message", "send_channel_message", "invite_user_to_slack", "post_webpage"], "sensitive_params": {"invite_user_to_slack": ["user_email"], "post_webpage": ["url"], "send_channel_message": ["body"], "send_direct_message": ["body"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
