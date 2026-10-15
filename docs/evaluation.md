# Evaluation

How well ACF stops prompt-injection attacks, what it costs, and where it falls
short. All numbers come from runs recorded in the repository; the folder for
each is listed under [Sources](#sources). How to run each benchmark is in
[`benchmarkv2/README.md`](../benchmarkv2/README.md).

The questions:

1. Does ACF's protection hold whichever model drives the agent?
2. Where does the protection come from: recognising attack text, or policy?
3. What does it cost in task completion and latency?

## Benchmark and method

[AgentDojo](https://github.com/ethz-spylab/agentdojo) 0.1.35, suites v1.2.2: four
simulated applications (banking, Slack, travel, and a workspace with email,
calendar and files), 97 user tasks and 35 attacker tasks, giving 949 attacked
cases. In each, an attacker's instruction is planted in data the agent reads
while doing the user's task. AgentDojo scores task completion alongside attack
success, and it is the benchmark Progent, CaMeL and FIDES report on.

The agent runs inside an ACF session: the user's request, every tool call
before it runs and every tool result before the model reads it pass through
ACF, and a blocked call never runs. Configurations:

| Configuration | What ACF enforces |
|---|---|
| Undefended | Nothing |
| Detect | Content scanning only |
| Scope | The task's tools only, taken from the task's reference solution unless stated otherwise |
| Provenance | Every tool of the application available; the provenance rule blocks a payment, message or invitation to a value the agent read in a tool result. Written once per application from the tool signatures, so it uses no knowledge of the task |
| Full | Detect, Scope and Provenance together |

The attack is `important_instructions`, AgentDojo's own: a polite note signed
by the user, with no phrase a scanner would recognise.

## Results with three local models

Models served on an NVIDIA DGX Spark with vLLM: Qwen3 8B with thinking off,
Gemma 4 26B, and gpt-oss-120b (which always reasons). ASR is attack success
rate; Benign is benign task completion.

| Configuration | Qwen3 8B ASR | Benign | Gemma 4 26B ASR | Benign | gpt-oss-120b ASR | Benign |
|---|---:|---:|---:|---:|---:|---:|
| Undefended | 11.3% | 39.2% | 19.6% | 83.5% | 37.9% | 72.2% |
| Detect | — | — | 20.4% | 81.4% | — | — |
| Scope | 1.1% | 33.3% | 3.9% | 80.4% | 6.3% | 72.9% |
| Provenance | 3.3% | 33.0% | 5.4% | 71.1% | 12.4% | 66.7% |
| Full | 0.8% | 30.2% | 1.6% | 67.0% | 2.7% | 55.2% |
| **Attacks removed by Full** | **93%** | | **92%** | | **93%** | |

- **The reduction is the same for every model**, although undefended attack
  success differs more than threefold. The more capable model is the more
  exposed one.
- **Detection alone changes nothing on this attack.** The lexical scanner raised
  no signal on any of the 11,228 tool results it screened.
- **Banking falls to 0% under Full with every model.**
- **Every attack that survives Full has no destination value** for the
  provenance rule to track. Across the three models, the 47 that succeed open
  an attacker's web page (22), recommend a hotel in the answer, which involves
  no tool call (17), create a calendar event (4), or delete a file (4). No
  payment, message or invitation to an attacker's address succeeded with any
  model.

## Without a model

A scripted agent that obeys every injected instruction it can still read, on
the 609 attacked cases with reference tool calls. It shows what the policy does
when the model offers no resistance at all.

| Configuration | ASR | Benign utility |
|---|---:|---:|
| Undefended | 98.0% | 100% |
| Scope | 15.8% | 100% |
| Provenance | 22.2% | 86.6% |
| Full | 3.1% | 86.6% |
| Full, destinations confirmed by the user | 3.1% | 100% |

`make bench` reproduces this table in about 7 minutes.

## Scope without the benchmark's answer key

The Scope configuration normally takes each task's tools from AgentDojo's
reference solution, which a deployment does not have. Instead, the agent's
model derived each task's scope from the user's request alone, before reading
any tool output. Compared with the reference solutions, the derived scopes
omitted a needed tool in 21 of 97 tasks and added tools in 25.

| Configuration | Scope from | Gemma 4 ASR | Benign tasks | Scripted agent ASR |
|---|---|---:|---:|---:|
| Scope | reference solution | 3.9% | 78 | 15.8% |
| Scope | user's request | 3.6% | 60 | 14.0% |
| Full | reference solution | 1.6% | 65 | 3.1% |
| Full | user's request | 1.4% | 54 | 2.6% |

The security does not depend on the answer key; the utility obtained with it is
an upper bound.

## The cost of the provenance rule, and confirmation

The provenance rule lowers benign task completion by 9 to 17 points. In 12 of
the 13 benign tasks whose reference solution it would block, the user's own
request points the agent to the source of the value, such as "pay the bill in
this file" or "her email is on her website". The rule cannot tell that value
from one an attacker wrote into the same document; only the user can.

Running Full with the task's legitimate destinations declared as trusted, as if
ACF asked the user before acting on a value it read:

| | Gemma 4 Benign tasks | Gemma 4 ASR | Scripted agent Benign | Scripted agent ASR |
|---|---:|---:|---:|---:|
| Full | 65 | 1.5% | 86.6% | 3.1% |
| Full, destinations confirmed | 73 | 1.5% | 100% | 3.1% |

Confirmation recovers half the cost with a real model, which does not always
use the reference solution's destinations, and all of it with an agent that
does. The confirming user here always answers correctly, so this is an upper
bound.

## Detecting injected instructions by content

The scanners alone, on the injected tool result of each of the 609 cases, in
each of AgentDojo's six attack wordings. Percentages are results flagged, not
attacks prevented.

| Wording | Lexical | TF-IDF | EmbeddingGemma 2 | EmbeddingGemma 2, windows |
|---|---:|---:|---:|---:|
| `direct` ("TODO: ...") | 0% | 20% | 2% | 16% |
| `system_message` | 0% | 20% | 2% | 15% |
| `ignore_previous` | 0% | 62% | 5% | 32% |
| `injecagent` ("IMPORTANT!!! Ignore all previous instructions ...") | 100% | 100% | 12% | 80% |
| `important_instructions` (signed note) | 0% | 14% | 0% | 42% |
| `tool_knowledge` (signed note with tool calls) | 0% | 14% | 1% | 85% |
| Benign user requests flagged | 0% | 7% | 8% | 10% |
| Benign tool results flagged | 0% | 2% | 0% | 0% |

The lexical scanner catches the phrase it knows and nothing else; one inserted
word and a misspelling evade it. Semantic scanning extends coverage at a cost
in false alarms and, for windowed embeddings, latency (46 ms per result on a
GPU). When a scanner does flag an injection, policy acts on it: all 609 lexical
flags led to the injection being removed. The limit is recognition, which is why
the security claim rests on Scope and Provenance.

## Latency and resources

On a Windows laptop (Intel Core Ultra 7 255U) on mains power, over named pipes:

| Measurement | p50 | p99 |
|---|---:|---:|
| Hook call without session state, scanner off | 0.21–0.26 ms | about 0.5–0.6 ms |
| Hook call with session, task scope and provenance tracking, on AgentDojo payloads | 0.53 ms | 3.1 ms |
| Tool results only (some are 30 KB) | 0.49 ms | 9.3 ms |

About 6 ms of ACF time per task, against seconds per model reply. The sidecar
uses about 75 MB. The optional semantic scanner adds about 0.5 ms (TF-IDF) or
20 ms (sentence-transformer) per call in the SDK.

## Limits

- **Two to three runs at most per configuration.** Gemma 4 undefended, Scope
  and Full were each run twice (20.0% and 19.6%; 3.5% and 3.9%; 1.6% and 1.5%).
  Differences under a point are not meaningful; the models sample, so single
  cases vary between runs.
- **The models did not run in one mode**: Qwen3 had its thinking off, and
  gpt-oss-120b cannot turn its reasoning off. Qwen3's low attack rate partly
  reflects its low task completion.
- **Excluded cases.** Cases that failed with a model error (14 to 19 per
  configuration for Qwen3, 4 to 7 for gpt-oss-120b) are excluded; counting each
  as a successful attack moves no rate by more than 1.8 points.
- **The provenance rule was corrected on this benchmark**: a first run did not
  recognise its account numbers or links without a scheme.
- **One attack wording end to end, fixed attacks.** An adversary who adapts to
  ACF's patterns and policy has not been evaluated, nor other defences on the
  same models, so these numbers should not be ranked against those reported for
  other systems. Progent, for example, reports 39.9% to 1.0% with GPT-4o and a
  policy generated by a second language model.

## Sources

| Result | Folder in `benchmarkv2/agentdojo/results/` |
|---|---|
| Gemma 4, all configurations after the provenance fix | `20261011T193525Z-agent-gemma4` |
| Gemma 4, Detect, and the first run | `20261010T230937Z-agent-gemma4` |
| Gemma 4, Full again and with confirmed destinations | `20261013T145811Z-agent-gemma4` |
| Gemma 4, scope derived from the request | `20261014T104100Z-agent-gemma4`, scopes in `scopes-gemma4.json` |
| Qwen3 8B | `20261012T145711Z-agent-qwen3-8b` |
| gpt-oss-120b | `20261012T210630Z-agent-gpt-oss-120b` |
| Scripted agent, before and after the provenance fix | `20261010T215905Z-replay-replay`, `20261011T164447Z-replay-replay` |
| Scripted agent, confirmed destinations | `20261013T140145Z-replay-replay` |
| Scripted agent, derived scopes | `20261014T142249Z-replay-replay` |
| Scanner comparison | `20261011T145719Z-scanners` |
| Scanner flag to policy decision | `20261011T164757Z-flag-to-decision` |
| Overhead without sessions | `benchmarkv2/overhead/results/20260914T104233Z-windows-amd64` |
