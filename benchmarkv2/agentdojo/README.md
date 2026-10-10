# AgentDojo with ACF in the agent loop

AgentDojo scores both sides of a defence on the same tasks:

- **benign utility**: the agent finishes the user's task with no attack present
- **utility under attack**: it still finishes the task while under attack
- **attack success rate (ASR)**: the injected task succeeds

It is the benchmark Progent, CaMeL and FIDES report on, so it is where ACF can
be compared with other system-level defences. Its injection tasks also misuse
tools the user's task needs (`send_money`, `send_email`), which a tool-name
allowlist cannot stop. It backs §eval-agentdojo.

The runner is written against **agentdojo 0.1.35**, suites **v1.2.2**: 97 user
tasks and 949 attacked cases across `workspace`, `travel`, `banking` and
`slack`.

## Two modes

| | `--mode replay` (default) | `--mode agent` |
|---|---|---|
| Model | none | a real one, through an OpenAI-compatible endpoint |
| Agent | a worst-case agent: replays the reference tool calls, and obeys any injected instruction it can read | AgentDojo's default tool-calling pipeline |
| Question | When an attack reaches ACF, is it stopped, and by which enforcement point? What legitimate work is blocked? | How much safer is a real agent with ACF, and what does it cost in task success? |
| Cost | about 5 minutes, deterministic | one model run per case and arm |

**Replay** is the model-independent result. For each case the agent makes the
user task's ground-truth calls in order. The first time the injected
instruction is readable in a tool result, after ACF has screened it, the agent
makes the injection task's ground-truth calls, then carries on. A call ACF
blocks does not run. Attack success is then ACF's residual risk with no help
from the model; a real model can only do better on security.

**Agent** runs the upstream pipeline with ACF added at three points: the user's
prompt (`on_prompt`), each tool call before it runs (`on_tool_call`), and each
tool result before the model reads it (`on_tool_result`). A blocked call
returns an error to the model.

Both modes score with the suite's own utility and security checks, after
enforcement. Calls ACF blocked are left out of the trace those checks read.

## Arms

Every ACF arm runs each case in its own session.

| Arm | Tool results screened | Tool calls checked | Argument tainting |
|---|---|---|---|
| `none` | no | no | no |
| `gate-global` | no | allowlist = every tool in the suite | no |
| `gate-task` | no | session scope = the task's own tools | no |
| `detect` | yes | no | no |
| `full-global` | yes | suite allowlist | no |
| `full-task` | yes | task scope | no |
| `full-global-taint` | yes | suite allowlist | yes |
| `full-task-taint` | yes | task scope | yes |

- **Task scope** is declared through the SDK, `firewall.session(allowed_tools=...)`,
  so the sidecar enforces it. The tools are the ones the task's reference
  solution uses. That is least privilege, and it assumes the task's tools are
  known in advance; say so when reporting it.
- **Argument tainting** blocks a consequential tool call whose argument repeats
  a value the agent read in a tool result. Which tools and arguments count is
  the developer's policy, in [`domain_policies.json`](domain_policies.json):
  one entry per suite, written from the tool signatures. Arms without tainting
  set `consequential_tools: []`.

## Deployment settings

Two things differ from the shipped configuration, in every ACF arm, and both
are recorded in `summary.json`:

- `tool_allowlist` is the suite's tools.
- The shell-metacharacter check on tool arguments is skipped
  (`tool_param_scan_skip`). It reads every string argument, and none of these
  tools runs a shell, so it misfires on prose: with it on, 114 legitimate Slack
  calls are blocked for a `;` or `&` in a message. `--shipped-param-scan` keeps
  it on, to measure that.

## Setup

```sh
python -m venv benchmarkv2/agentdojo/.venv
benchmarkv2/agentdojo/.venv/Scripts/python -m pip install "agentdojo==0.1.35" pytest   # bin/ on Linux and macOS
```

`manifest.json` pins the version and the runner refuses any other. Go is needed
to build the sidecar. Agent mode reads `OPENAI_API_KEY`; with `--base-url` any
value works for a local server.

## Running

Use the venv's Python for everything below.

```sh
# Sidecar only: build, start, preflight. No AgentDojo needed.
python benchmarkv2/agentdojo/run_agentdojo.py --dry-run --build-sidecar

# Replay, all suites and arms.
python benchmarkv2/agentdojo/run_agentdojo.py --mode replay

# Agent mode pilot: one suite, three user tasks, two arms.
python benchmarkv2/agentdojo/run_agentdojo.py --mode agent --model gemma4 \
    --base-url http://localhost:8000/v1 --suites banking --limit 3 --arms none,full-task-taint

# Agent mode, full run.
python benchmarkv2/agentdojo/run_agentdojo.py --mode agent --model gpt-4o-2024-05-13

# Finish an interrupted run.
python benchmarkv2/agentdojo/run_agentdojo.py --mode agent --model gemma4 --base-url ... \
    --resume benchmarkv2/agentdojo/results/<run directory>
```

Other flags: `--attack` (default `important_instructions`, the attack Progent
and CaMeL report; `tool_knowledge` is the one FIDES uses), `--user-tasks`,
`--injection-tasks`, `--no-benign`, `--workers`, `--semantic`,
`--benchmark-version`.

The model server must support OpenAI tool calling. The injected text addresses
the model by name; a model AgentDojo does not know is addressed as "Local
model", as upstream does for its own local providers.

## Outputs

`results/<UTC timestamp>-<mode>-<model>/`:

- `records.jsonl`: one line per (suite, user task, injection task, arm), written
  as each case finishes, with every ACF verdict
- `summary.json`: scores per arm and suite, sidecar settings and preflights,
  provenance (commit, file and binary hashes, versions)
- `summary.md`: the tables
- `work/`: the generated sidecar configs and logs. Each log line has the
  signals behind a decision.

## Reading the replay numbers

- **ASR** under `none` is just under 100%, not 100%: a few injection tasks fail
  their own check when their reference calls are replayed after the user's.
- **Utility is a lower bound.** A case counts only if the suite's check passes
  and none of the user's own tool results was blocked or sanitised. The
  reference answer is not credible if the agent could not read its inputs.
- **Utility under attack is low under `none`** because the injected calls ran
  and changed the environment, which most utility checks reject.
- **False blocks** counts the user's own calls that ACF blocked, over all of
  the user's calls.
- **Stopped by detect / gate** attributes each failed attack: the instruction
  was hidden from the agent, or the agent tried and a call was blocked.
- **Not replayed**: 9 injection tasks have no reference tool calls (the attack
  is in the agent's answer, or upstream gives none), so replay covers 609 of
  the 949 attacked cases. Agent mode covers all of them.

## Limits

- Replay's agent follows reference solutions, so it never takes a different
  legitimate route or recovers from a blocked call. Task scope therefore shows
  no false blocks in replay by construction. Agent mode measures that cost.
- A tool call ACF returns SANITISE for runs with its original arguments.
- The task scope comes from the benchmark's reference solutions.

## Tests

```sh
python -m pytest benchmarkv2/agentdojo benchmarkv2/common
```

`test_run_agentdojo.py` covers the guard, scoring and the report and needs no
AgentDojo. `test_agentdojo_adapter.py` covers the plan, replay and the agent
pipeline with a scripted model, and is skipped where AgentDojo is not installed.
