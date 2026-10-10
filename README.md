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
validate → session → normalise → scan → aggregate → OPA policy → executor
```

| Stage | What it does |
|---|---|
| Validate | Schema checks; assigns provenance per hook and sets aside fields the client must not control |
| Session | Loads the session's state (task scope, values read so far) for policy to use |
| Normalise | Decodes URL and Base64, NFKC-normalises Unicode, strips zero-width characters, undoes leetspeak |
| Scan | Aho-Corasick pattern scan, allowlist and parameter checks |
| Aggregate | Combines signals into a 0.0–1.0 risk score, weighted by provenance |
| OPA policy | Rego decides per hook, using the score, signals and session state |
| Executor | Applies the transformation a SANITISE asks for |

A hard block at any stage short-circuits to BLOCK.

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
cd demo && docker compose up --build                  # six attack scenarios, no API keys
```

---

## What's in this repo

| Path | What it is |
|---|---|
| [`sidecar/`](sidecar/) | The Go policy decision point: IPC transport and crypto, the pipeline stages, the OPA engine, the session store, value tainting, and the hook registry |
| [`sdk/python/`](sdk/python/) | The Python SDK: `Firewall`, `Session`, the optional semantic scanner, and framework adapters |
| [`sdk/typescript/`](sdk/typescript/) | An early TypeScript SDK, not yet at parity with Python |
| [`policies/v1/`](policies/v1/) | Rego policies, one per hook, with their unit tests, plus `data/` (thresholds, allowlists, trust settings, signal weights, the pattern library) |
| [`config/`](config/) | Sidecar configuration (`sidecar.yaml`, with an annotated example) |
| [`tests/integration/`](tests/integration/) | End-to-end tests against the real sidecar binary: an 80-case adversarial corpus, gap probes, forgery probes and session flows |
| [`examples/`](examples/) | Runnable scripts showing which rule fires for each kind of input |
| [`demo/`](demo/) | A Docker demo of six attack scenarios |
| [`benchmarks/`](benchmarks/) | Replays public benchmark payloads through ACF with no model (detector catch rates) |
| [`benchmarkv2/`](benchmarkv2/) | Evaluations for the paper: runtime overhead, InjecAgent with a live agent, and AgentDojo and Agent Security Bench harnesses (scaffolds) |
| [`docs/`](docs/) | Architecture, design notes, threat analysis and the paper sources |
| [`scripts/`](scripts/) | Utilities, such as measuring the semantic scanner's detection rate |

### Framework integrations

| Integration | Status |
|---|---|
| LangGraph — `acf.adapters.langgraph.FirewallNode` | Any hook as a graph node; accepts a `Session` for task scope |
| Agent Kernel — `acf.adapters.agent_kernel.ACFInputGuardrail` | Input guardrail |
| LangChain — `acf.adapters.langchain` | Placeholder |
| TypeScript — `sdk/typescript` | Early: client and a LangGraph adapter |

---

## Testing

```bash
make test               # Go unit tests, including the Rego policy tests
make sdk-test-python    # Python SDK tests
make integration        # end-to-end tests against a freshly built sidecar
make opa-test           # Rego tests with the opa binary, if you have it
```

CI runs the Go and Python tests on Ubuntu and the integration suite on Ubuntu
and Windows.

---

## Evaluation

| What | Where | Result so far |
|---|---|---|
| Runtime overhead | [`benchmarkv2/overhead/`](benchmarkv2/overhead/) | On a Windows laptop over named pipes: an SDK hook call costs about 0.25–0.3 ms at p50 with the semantic scanner off, about 0.8 ms with TF-IDF and about 20 ms with a sentence-transformer. Inside the sidecar a request takes about 0.2 ms, two-thirds of it policy evaluation. Large payloads cost more: a 64 KB chunk takes about 6 ms, mostly normalisation |
| InjecAgent, live agent | [`benchmarkv2/injecagent/`](benchmarkv2/injecagent/) | Runs with any OpenAI-compatible model. The models tried so far resist InjecAgent on their own, so it measures model robustness more than ACF |
| AgentDojo, Agent Security Bench | [`benchmarkv2/agentdojo/`](benchmarkv2/agentdojo/), [`benchmarkv2/asb/`](benchmarkv2/asb/) | Harnesses scaffolded; upstream adapters to write |
| Detector catch rates | [`benchmarks/`](benchmarks/) | Model-free replay of public datasets |

How each benchmark is run is in [`benchmarkv2/README.md`](benchmarkv2/README.md).

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
- **Tainting covers the value types it extracts**: email addresses, URLs, IBANs
  and long numbers. A name or a paraphrased instruction is not tracked.
- **Memory reads still trust a client-supplied integrity flag.** A proper fix
  needs a sidecar-signed stamp and a wire protocol change.

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
| v2 | Sessions, `on_tool_result`, task scope, argument tainting | Done on `feat/application-policy-layer` |
| v2 | `on_outbound`, `on_subagent`, accumulation policies, TypeScript parity, signed memory integrity | Planned |

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
