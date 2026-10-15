# ACF-SDK — Agentic Cognitive Firewall

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://github.com/c2siorg/acf-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/c2siorg/acf-sdk/actions/workflows/ci.yml)

ACF-SDK is a security layer for LLM agents. It checks everything an agent takes
in and every action it is about to take — the user's prompt, retrieved
documents, tool output, tool calls and memory — against policies you write as
code, and returns **ALLOW**, **SANITISE** or **BLOCK**. Decisions are made in a
separate sidecar process the agent cannot reach into, so they do not depend on
the agent's code or on which model runs it.

**New here?** The [plain-language overview](docs/overview.md) explains what the
SDK and sidecar do before any of the detail below.

---

## Why this exists

An LLM agent does not have one front door. It reads the user's message, pulls
documents from a vector store, calls tools and reads their output, and reads and
writes memory. Any of these can carry instructions an attacker planted, and the
indirect ones — a poisoned web page, an email, a tool response — reach the model
long after a front-door filter has looked at the prompt. Because agents act
through tools, a successful injection is not just a wrong answer: it can send
email, move money or delete files.

The model itself is not a reliable last line of defence. Frontier models resist
many known attacks, but smaller and self-hosted models often do not, and even
robust models fail against attacks tailored to them. ACF-SDK takes the position
that enforcement should hold regardless of the model:

- **Check every channel**, not just the prompt: each point where content enters
  the agent or an action leaves it is an enforcement point.
- **Decide outside the agent.** The policy decision point is an isolated Go
  sidecar. The agent process only holds a thin client.
- **Write policy as code.** Rules are Rego (Open Policy Agent), versioned and
  hot-reloaded; detection data (patterns, weights) is kept separate from
  decision logic.
- **Use what the application knows.** A deployment can declare what a task is
  allowed to do — which tools, which argument values, which sources it trusts —
  and the sidecar enforces that for the whole agent session. This is what stops
  an attacker using a tool the task legitimately needs, such as sending an email
  to an address an injected page planted.

---

## How it works

![ACF-SDK architecture](docs/architecture.png)

Two zones separated by an operating-system process boundary:

- **PEP (policy enforcement point)** — a thin SDK inside the agent process. It
  wraps each check as a signed request and sends it to the sidecar.
- **PDP (policy decision point)** — a Go sidecar. All detection and policy
  evaluation happens here.

They talk over a Unix domain socket (`/tmp/acf.sock`) on Linux and macOS, or a
named pipe (`\\.\pipe\acf`) on Windows. Every request is signed with
HMAC-SHA256 and carries a fresh nonce; a bad signature or replayed nonce is
dropped before the payload is parsed.

### Enforcement points (hooks)

| Hook | Called | Stops |
|---|---|---|
| `on_prompt` | When user input arrives | Direct prompt injection |
| `on_context` | Before retrieved chunks enter the model's context | Indirect injection in documents |
| `on_tool_result` | Before the agent reads a tool's output | Indirect injection in tool output, told apart by the producing tool |
| `on_tool_call` | Before a tool runs | Disallowed tools, dangerous parameters, and the attacker's values in a legitimate tool's arguments |
| `on_memory` | Before a memory read or write | Memory poisoning |
| `on_task` | When a session starts (sent for you) | Declares the session's task scope |

### Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | Pass the input or action through unchanged |
| `SANITISE` | Use the cleaned version the sidecar returns |
| `BLOCK` | Do not proceed |

### The pipeline

```
verify → validate → session → normalise → scan → aggregate → OPA policy → execute → record
```

| Stage | What it does |
|---|---|
| Verify | Checks the HMAC and nonce before the payload is parsed (in the transport) |
| Validate | Schema checks; assigns provenance per hook and sets aside fields the client must not control |
| Session | Loads the session's state (task scope, trusted and untrusted values) and finds argument values read from untrusted content |
| Normalise | Decodes URL and Base64, NFKC-normalises Unicode, strips zero-width characters, collapses whitespace, undoes leetspeak |
| Scan | Aho-Corasick pattern scan, allowlist and parameter checks |
| Aggregate | Combines signals into a 0.0–1.0 risk score, weighted by provenance |
| OPA policy | Rego decides per hook, using the score, signals and session state. The only stage that decides |
| Execute | Applies the transformation a SANITISE asks for |
| Record | Updates the session: values in an admitted tool result become untrusted, values in the prompt trusted |

The stages before the policy only gather evidence. In the default strict mode, a
hard block at any stage short-circuits to BLOCK.

### Sessions and the application policy layer

Calls made through `firewall.session()` are evaluated as one agent run. On top
of the per-request checks, a session can:

- **declare a task scope** — the tools the task needs and bounds on their
  arguments; anything outside it is blocked, and a scope can only narrow global
  policy, never widen it;
- **taint values from untrusted content** — email addresses, URLs, IBANs and
  account numbers the agent read in documents or tool output; a consequential
  tool (`send_email`, `send_money`, ...) whose argument repeats one is blocked
  unless the user or developer vouched for the value;
- **trust specific tools' output** — so an internal payment API's response can
  flow into a payment while the same IBAN read on a web page cannot.

See [docs/application-policy-layer.md](docs/application-policy-layer.md).

### Writing an application policy

The Rego rules are the same for every deployment. An application supplies the
data they read, in `policies/v1/data/policy_config.yaml`, and declares each
task's scope in code:

| Who | What | Where |
|---|---|---|
| ACF | The rules | `policies/v1/*.rego` (not edited) |
| Developer, once per application | The tools the application may use, which of them are consequential, which argument decides where money or data goes, and which tools' output it controls | `policy_config.yaml`: `tool_allowlist`, `consequential_tools`, `sensitive_params`, `trusted_tools` |
| Application, once per task | The task's tools, bounds on their arguments, and values the user confirmed | `fw.session(allowed_tools=..., tool_constraints=..., trusted_values=...)` |
| Application, at each boundary | The hook calls | `on_prompt`, `on_tool_call`, `on_tool_result`, ... or a framework adapter |

[`examples/banking/`](examples/banking/) is a complete worked example: a
banking agent's policy file, and scripts showing task scope, tool-result
screening, the provenance rule with user confirmation, and an agent loop.

---

## Quick start

### Prerequisites

- Go 1.25+ (to build the sidecar)
- Python 3.10+ (the SDK has no required dependencies)

### 1. Create a shared key

```bash
export ACF_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

The sidecar and the SDK must use the same key.

### 2. Build and run the sidecar

```bash
make build            # or: cd sidecar && go build -o ../bin/acf-sidecar ./cmd/sidecar
./bin/acf-sidecar
# sidecar: OPA engine ready (policy_dir=.../policies/v1)
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on /tmp/acf.sock
```

It reads `config/sidecar.yaml` (override with `ACF_CONFIG`) and the policies in
`policies/v1/`. Set `ACF_SOCKET_PATH` to listen somewhere else.

### 3. Install the SDK and make some calls

```bash
pip install -e sdk/python
```

```python
from acf import Firewall, Decision, SanitiseResult

fw = Firewall()   # reads ACF_HMAC_KEY and ACF_SOCKET_PATH

fw.on_prompt("What is the capital of France?")             # Decision.ALLOW
fw.on_prompt("Ignore previous instructions and ...")       # Decision.BLOCK

for chunk in fw.on_context(retrieved_docs):                # one result per chunk
    if chunk.decision is Decision.SANITISE:
        use(chunk.sanitised_text)

result = fw.on_tool_call("search", {"query": "weather"})
```

### 4. Use a session with a task scope

```python
with fw.session(
    allowed_tools=["get_balance", "send_money", "web_fetch"],
    trusted_values=["GB29NWBK60161331926819"],   # a payee the user saved
    tool_constraints={"send_money": {"amount": {"max": 100}}},
) as s:
    s.on_prompt(user_message)
    page = s.on_tool_result("web_fetch", html)   # screened before the agent reads it
    if isinstance(page, SanitiseResult):
        html = page.sanitised_text
    decision = s.on_tool_call("send_money", {"recipient": iban, "amount": 20})
```

`session()` raises `FirewallError` if the sidecar rejects the scope.

### Optional: semantic scanning

The lexical scan in the sidecar catches known phrasings. For paraphrases, the
SDK can add an embedding-based scanner (TF-IDF or a sentence-transformer):

```bash
pip install -e 'sdk/python[scanners]'
```

```python
fw = Firewall(enable_semantic_scan=True, semantic_backend="sentence-transformer")
```

### Docker

```bash
docker compose up -d                                  # sidecar
docker compose --profile observability up -d          # plus an OpenTelemetry collector
cd demo && docker compose up --build                  # nine attack scenarios, no API keys
```

---

## What's in this repo

| Path | What it is |
|---|---|
| [`sidecar/`](sidecar/) | The Go policy decision point: IPC transport and crypto, the pipeline stages, the OPA engine, the session store, value tainting, and the hook registry |
| [`sdk/python/`](sdk/python/) | The Python SDK: `Firewall`, `Session`, the optional semantic scanner, and framework adapters |
| [`sdk/typescript/`](sdk/typescript/) | The TypeScript SDK for Node: `Firewall`, `Session`, `guardTool`, and a LangGraph.js node; same wire protocol as Python |
| [`policies/v1/`](policies/v1/) | Rego policies, one per hook, with their unit tests, plus `data/` (thresholds, allowlists, trust settings, signal weights, the pattern library) |
| [`config/`](config/) | Sidecar configuration (`sidecar.yaml`, with an annotated example) |
| [`tests/integration/`](tests/integration/) | End-to-end tests against the real sidecar binary: an 80-case adversarial corpus, gap probes, forgery probes and session flows |
| [`examples/`](examples/) | Runnable scripts: one hook at a time, a banking agent with its own policy, framework adapters, and the TypeScript SDK |
| [`demo/`](demo/) | A Docker demo of nine attack scenarios, three of them in a session under the banking policy |
| [`benchmarks/`](benchmarks/) | Replays public benchmark payloads through ACF with no model (detector catch rates) |
| [`benchmarkv2/`](benchmarkv2/) | Evaluations for the paper: runtime overhead, InjecAgent with a live agent, AgentDojo (model-free replay and live agent), and an Agent Security Bench scaffold |
| [`docs/`](docs/) | Architecture, design notes, threat analysis and the paper sources |
| [`scripts/`](scripts/) | Utilities, such as measuring the semantic scanner's detection rate |

### Framework integrations

| Integration | Status |
|---|---|
| LangChain — `acf.adapters.langchain.guard_tools` | Wraps tools so each call and result passes through ACF; with a `Session`, task scope and the provenance rule apply. Also works for LangGraph agents |
| LangGraph — `acf.adapters.langgraph.FirewallNode` | Any hook as a graph node; accepts a `Session` |
| Agent Kernel — `acf.adapters.agent_kernel.ACFInputGuardrail` | Input guardrail; accepts a `Session` |
| TypeScript — `sdk/typescript` | `guardTool` for any async tool function, and `firewallNode` for LangGraph.js |

---

## Testing

```bash
make test               # Go unit tests, including the Rego policy tests
make sdk-test-python    # Python SDK tests
make sdk-test-ts        # TypeScript SDK tests (against a fake sidecar)
make examples           # every example against a freshly built sidecar
make integration        # end-to-end tests against a freshly built sidecar
make test-all           # all of the above, plus the benchmark tests
make opa-test           # Rego tests with the opa binary, if you have it
```

CI runs on every push and pull request to `main`:

| Job | What it runs |
|---|---|
| Go tests | Sidecar unit tests and Rego policy tests, `go vet` |
| Integration tests | The real sidecar binary against the adversarial corpus, probes and session flows, on Ubuntu and Windows |
| Python tests | The Python SDK, and the framework adapters against real LangChain |
| TypeScript tests | The TypeScript SDK against a fake sidecar that verifies every frame |
| Examples | Every example in `examples/` against a freshly built sidecar, under the shipped and the banking policy |
| AgentDojo benchmark | The benchmark's tests and a two-task replay with no model |

---

## Evaluation

| What | Where | Result so far |
|---|---|---|
| AgentDojo, live agent (default benchmark) | [`benchmarkv2/agentdojo/`](benchmarkv2/agentdojo/) | Three local models (Qwen3 8B, Gemma 4 26B, gpt-oss-120b), 949 attacked cases each. Undefended attack success is 11.3%, 19.6% and 37.9%; with scope and the provenance rule it is 0.8%, 1.6% and 2.7%, removing 92–93% of successful attacks for every model. The cost is 9–17 points of benign task completion, about half recovered when the user confirms destinations. A scope the model derives from the request, instead of the benchmark's reference solution, keeps the same security at a further utility cost |
| AgentDojo, no model | [`benchmarkv2/agentdojo/`](benchmarkv2/agentdojo/) | A worst-case agent that obeys every injected instruction it can read, on the 609 attacked cases with reference calls. Attack success falls from 98.0% to 15.8% with a per-task tool scope, 22.2% with the provenance rule alone, and 3.1% with both. Lexical detection never fires on this attack |
| Runtime overhead | [`benchmarkv2/overhead/`](benchmarkv2/overhead/), [`benchmarkv2/agentdojo/latency_agentdojo.py`](benchmarkv2/agentdojo/latency_agentdojo.py) | On a Windows laptop over named pipes: a plain hook call costs about 0.21–0.26 ms at p50 with the semantic scanner off, about 0.8 ms with TF-IDF and about 20 ms with a sentence-transformer. With a session, task scope and provenance tracking, on AgentDojo's payloads: 0.53 ms at p50 and 3.1 ms at p99, about 75 MB for the sidecar |
| InjecAgent, live agent | [`benchmarkv2/injecagent/`](benchmarkv2/injecagent/) | Runs with any OpenAI-compatible model. The models tried so far resist InjecAgent on their own, so it measures model robustness more than ACF |
| Agent Security Bench | [`benchmarkv2/asb/`](benchmarkv2/asb/) | Harness scaffolded; upstream adapter to write |
| Detector catch rates | [`benchmarks/`](benchmarks/) | Model-free replay of public datasets |

AgentDojo is the default benchmark: `make bench-setup` once, then `make bench`
for the model-free replay (about 7 minutes) or `make bench-agent MODEL=... BASE_URL=...`
for a live agent. How each benchmark is run is in
[`benchmarkv2/README.md`](benchmarkv2/README.md).

---

## Security model and limits

- **The enforcement point is in-process.** ACF protects an honest agent from
  injected content and from forged or misconfigured fields. It cannot stop a
  fully compromised agent process from simply not calling the hooks; that would
  need tools to be reachable only through the sidecar.
- **Detection is best-effort; policy is the guarantee.** Pattern and semantic
  detection miss paraphrased and novel attacks. Task scope and argument tainting
  do not depend on recognising an attack, which is why they carry the stronger
  claims.
- **Tainting covers the value types it extracts**: email addresses, URLs and
  their hosts (with or without a scheme), IBANs and account numbers in IBAN
  form, and long numbers. A name or a paraphrased instruction is not tracked,
  and an attack whose goal has no destination value, such as opening a web
  page, is outside the provenance rule.
- **Memory reads rely on a client-supplied integrity flag**, which the SDKs do
  not send yet, so reads are blocked (fail closed). A proper fix needs a
  sidecar-signed stamp and a wire protocol change.
- **The semantic scanner runs in the agent process**, so its signals can only
  add risk; the sidecar never lets them lower it.

[docs/mitre-atlas-analysis.md](docs/mitre-atlas-analysis.md) maps coverage and
gaps against MITRE ATLAS.

---

## Status and roadmap

| | Goal | Status |
|---|---|---|
| Phase 1 | Wire protocol, HMAC and nonce crypto | Done |
| Phase 2 | Pipeline stages | Done |
| Phase 3 | OPA integration and Rego policies | Done |
| Phase 4 | Integration test suite; OpenTelemetry observability | Test suite done; OpenTelemetry not started (a per-request timing log exists) |
| v2 | Sessions, `on_tool_result`, task scope, argument tainting | Done |
| v2 | TypeScript SDK with sessions and tool-result screening | Done (no semantic scanner) |
| v2 | `on_outbound`, `on_subagent`, accumulation policies, signed memory integrity | Planned |

---

## Documentation

- [Overview](docs/overview.md) — plain-language introduction
- [Architecture](docs/architecture.md) — full design, wire protocol, pipeline
- [Application policy layer](docs/application-policy-layer.md) — sessions, task scope, tool output, tainting
- [Pipeline](docs/pipeline.md) — stage-by-stage detail
- [Semantic scanner](docs/semantic-scanner.md) — the optional embedding-based detector
- [Crypto](docs/crypto.md) — HMAC signing and nonce replay protection
- [MITRE ATLAS analysis](docs/mitre-atlas-analysis.md) — threat mapping and residual risk
- [Phase 1](docs/phase1.md) · [Phase 2](docs/phase2.md) · [Phase 3](docs/phase3.md) — implementation notes per phase
- [Policies](policies/v1/README.md) — the Rego policies and their coverage
- [Philosophy](PHILOSOPHY.md) — design principles
- [Implementation log](docs/implementation_log.md) — decisions, trade-offs and corrections over time

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
