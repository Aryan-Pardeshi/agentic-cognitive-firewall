# AgentDojo with ACF in the agent loop

Mode `agent`, agent model `gemma4`, attack `important_instructions`, agentdojo `0.1.35` (suites v1.2.2), semantic scanner `off`, shell-metacharacter check on tool arguments `skipped`.
ACF commit `bfa91c3b286a8031ec7097ca381e69e187c04af0`.

Rates are measured after enforcement: a tool call ACF blocks never runs and is not in the trace the suite's checks read. Utility and attack success are AgentDojo's own checks.

| Arm | Benign utility | Utility under attack | ASR | False blocks | Stopped by detect | Stopped by gate | Altered observations | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 100.0% | 55.6% | 66.7% | 0/7 | 0 | 0 | 0 | 0 |
| full-task-taint | 66.7% | 55.6% | 0.0% | 2/7 | 0 | 0 | 0 | 0 |

## By suite

| Arm | Suite | Benign utility | Utility under attack | ASR | False blocks |
|---|---|---:|---:|---:|---:|
| none | banking | 100.0% | 55.6% | 66.7% | 0/7 |
| full-task-taint | banking | 66.7% | 55.6% | 0.0% | 2/7 |

## Sidecars

- 11 tools allowed, shell-metacharacter check skipped for 7 tools, policy overrides `{"consequential_tools": ["send_money", "schedule_transaction", "update_scheduled_transaction"], "sensitive_params": {"schedule_transaction": ["recipient"], "send_money": ["recipient"], "update_scheduled_transaction": ["recipient"]}}`: preflight benign-context=ALLOW, injection-context=SANITISE, allowlisted-tool=ALLOW, unauthorized-tool=BLOCK
