# ACF-SDK — Project context for Claude Code

## What this project is
A framework-agnostic security firewall for LLM agents. It checks what an agent
takes in and the actions it takes, at every enforcement point, against Rego
policies, and returns ALLOW / SANITISE / BLOCK.

Two zones separated by a hard trust boundary (OS process boundary):
- **PEP** (Policy Enforcement Point) — thin SDK inside the agent process.
- **PDP** (Policy Decision Point) — isolated Go sidecar; all detection and policy evaluation happens here.

## Language decisions
- Sidecar: Go 1.25 (see `sidecar/go.mod`) — embeds the OPA Go SDK, single binary
- SDK: Python 3.10+ — zero required dependencies (stdlib only); `[scanners]` extra for semantic scanning
- SDK: TypeScript/Node 18+ — early, same wire protocol, not at parity
- Policies: Rego (OPA) + YAML/JSON data

## IPC — wire protocol
Unix domain socket at `/tmp/acf.sock` (Linux/macOS) or named pipe `\\.\pipe\acf` (Windows); override with `ACF_SOCKET_PATH`. Length-prefixed binary framing, one connection per request.

**Request frame (54-byte header + payload):**
| Field | Size | Value |
|---|---|---|
| Magic byte | 1B | `0xAC` — fast-reject misaddressed connections |
| Version | 1B | Current: `1` |
| Payload length | 4B | Length of JSON payload |
| Nonce | 16B | Random per-request — replay protection |
| HMAC | 32B | HMAC-SHA256 over (version + length + nonce + payload) |
| Payload | variable | JSON-serialised RiskContext |

**Response frame:**
| Field | Size | Value |
|---|---|---|
| Decision | 1B | `0x00` ALLOW · `0x01` SANITISE · `0x02` BLOCK |
| Sanitised length | 4B | 0 if not SANITISE |
| Sanitised payload | variable | Present only on SANITISE |

Invalid HMAC or reused nonce → connection dropped before the JSON is parsed. Changing the frame layout is a wire version bump.

## Hooks
```python
fw.on_prompt(user_msg)            # user input — direct injection
fw.on_context(chunks)             # retrieved docs — indirect injection
fw.on_tool_result(tool, output)   # tool output before the agent reads it
fw.on_tool_call(name, params)     # before a tool runs — tool abuse, tainted arguments
fw.on_memory(key, value, op)      # memory read/write — poisoning
fw.session(allowed_tools=..., trusted_values=..., tool_constraints=...)  # sends on_task
```
The `Firewall`'s own methods are sessionless; a `Session` carries a session ID on every call.
Planned: `on_outbound` · `on_subagent` · `on_startup`.

## Seam 1 — Hook registry (critical discipline)
Each hook is one entry in `sidecar/internal/hooks/builtin.go`: name, Rego package, provenance, OPA input builder, optional payload validator. Adding a hook = a registry entry + its Rego file (+ SDK method). The transport, pipeline stages and policy engine do NOT change. Never hard-code a hook name in the engine or validate stage.

## Sidecar pipeline stages (in order)
`validate → session → normalise → scan → aggregate → OPA policy engine → executor`, then recorders (`Pipeline.OnDecision`) update session state.

| Stage | What it does |
|---|---|
| **Validate** | Hook lookup, required fields, hook payload validator; assigns provenance per hook; sets client signals/score/state aside |
| **Session** | Rejects malformed session IDs; loads session state into `rc.State`; validates `on_task`; computes argument taint findings |
| **Normalise** | Recursive URL/Base64 decode, NFKC, zero-width strip, whitespace collapse, leetspeak clean → canonical text |
| **Scan** | Aho-Corasick lexical scan, allowlist and dangerous-parameter checks |
| **Aggregate** | Merges weighted client signals back, scores 0.0–1.0, applies provenance trust weight |
| **OPA engine** | Evaluates the Rego package registered for the hook → decision + sanitise_targets |
| **Executor** | Performs the transforms OPA declares (redact, split marker) |

HMAC and nonce checks happen in the transport, before the pipeline. Strict mode short-circuits to BLOCK on a hard block signal.

## Seam 2 — Risk context object (critical discipline)
Single payload through the whole pipeline. The wire schema is fixed:
```json
{"score": 0.0, "signals": [], "provenance": "", "session_id": "", "hook_type": "", "payload": {}, "state": null}
```
Internal-only fields (`json:"-"`): `CanonicalText`, `ClaimedProvenance`, `ClientSignals`.

## Server-side trust (critical discipline)
The client is not trusted for anything that sets trust:
- **provenance** is assigned per hook by the registry; the client's claim is kept for audit only
- **client signals** survive only for categories with a weight, scored by that weight — they may add risk, never lower it
- **score** and **state** sent by the client are discarded; `input.state` only ever holds what the sidecar stored
`TestClientFieldForgeryProbe` and `TestProvenanceForgeryProbe` (integration) guard this. Keep it that way.

## State store and sessions
- Interface `sidecar/internal/state/store.go` (`Get`/`Update` on `*Session`); `noop.go` (stateless), `ttl_store.go` (idle TTL, session cap, LRU eviction) — wired in `main.go`.
- A session holds request counters, the declared `TaskScope`, and taint sets (untrusted values with sources, trusted values) with caps; overflow fails closed.
- Policies see `input.state`: `{requests, blocked, task?, taint?}`.
- Details: `docs/application-policy-layer.md`.

## Policy files
```
policies/v1/
├── prompt.rego          instruction override · role escalation · thresholds
├── context.rego         source trust · embedded instruction · structural anomaly
├── tool.rego            allowlist · destination · detection · task scope · argument constraints · argument taint
├── memory.rego          HMAC verify · write scan · provenance
├── tool_result.rego     score thresholds · trusted_tools
├── task.rego            a task scope may only narrow the global allowlist
├── *_test.rego          one test file per policy
└── data/
    ├── policy_config.yaml         thresholds · allowlists · trusted_tools · consequential_tools · sensitive_params · signal_weights
    └── jailbreak_patterns.json    versioned pattern library
```
Policy logic (Rego) and data (YAML/JSON) stay separate. Hot-reloaded every 5s.

**Signal weight contract:** every `Category: "..."` literal in non-test sidecar code needs an entry in `signal_weights` (`TestPolicyConfig_EveryEmittableSignalHasAWeight`), and so does every SDK scanner category (Python contract test). A category with no weight scores 0.0.

## Testing
```bash
cd sidecar && go test ./...       # unit tests + Rego tests (TestRegoPolicyTests)
cd sdk/python && python -m pytest
cd tests/integration && go test ./... -timeout 300s   # builds and drives the real sidecar
python -m pytest benchmarkv2 benchmarks/test_run_benchmark.py
```
- Changing `policies/v1/data/policy_config.yaml`, `config/sidecar.yaml`, `jailbreak_patterns.json`, `sdk/python/acf/firewall.py` or `attack_library.py` requires re-pinning `benchmarks/manifest.json` (hash of the committed LF content; baseline = last commit touching a pinned file).
- New corpus cases in `tests/integration/adversarial_payloads.json`: take `expected` from the sidecar's actual verdict, and keep the file's existing formatting.

## Windows development notes
- The virus scanner blocks freshly built binaries in `%TEMP%`: build sidecars to a repo-local path (e.g. `benchmarkv2/overhead/.bin/`). Go unit tests run fine; the integration suite is unreliable locally — rely on CI.
- `TestLoadResolvesRelativePolicyDirViaConfigSymlink` fails locally (needs a symlink privilege); not a regression.
- Go's runtime clock is coarse on Windows (~0.5 ms steps); use `sidecar/internal/clock` for per-request timing.
- Files check out with CRLF; `gofmt -l` flags them for that alone. Check formatting on LF content.

## Build phases
| Phase | Goal | Status |
|---|---|---|
| 1 | Wire protocol + crypto | Done |
| 2 | Pipeline stages | Done |
| 3 | OPA integration + Rego policies | Done |
| 4 | Integration test suite + OTel observability | Suite done; OTel not started (`internal/telemetry` has the timing log only) |
| v2 | Sessions, on_tool_result, task scope, argument tainting | Done (`feat/application-policy-layer`) |
| v2 | on_outbound, on_subagent, accumulation policies, TS parity, signed memory integrity | Planned |

Work one phase at a time unless the maintainer explicitly decides otherwise.

## Enforcement latency
Measured (`benchmarkv2/overhead/`, Windows laptop, named pipes): SDK hook call ≈ 0.25–0.3 ms p50 with the semantic scanner off; sidecar internal ≈ 0.2 ms, about two-thirds OPA. Telemetry must never block the request path.

## Folder structure
```
acf-sdk/
├── sidecar/
│   ├── cmd/sidecar/main.go
│   ├── internal/transport/   listener · frame · UDS/pipe connectors
│   ├── internal/pipeline/    pipeline · validate · session · normalise · scan · aggregate
│   ├── internal/policy/      engine · executor · sanitise
│   ├── internal/hooks/       hook registry
│   ├── internal/state/       store · noop · ttl_store · session · task · taint
│   ├── internal/taint/       value extraction for argument tainting
│   ├── internal/crypto/      hmac · nonce
│   ├── internal/config/      config + pattern loading
│   ├── internal/telemetry/   timing log (OTel planned)
│   ├── internal/clock/       high-resolution clock
│   ├── internal/benchdata/   benchmark workloads (test-only)
│   └── pkg/riskcontext/, pkg/decision/
├── sdk/python/acf/           firewall · session · transport · frame · models · scanners/ · adapters/
├── sdk/typescript/src/       firewall · adapters/ (early)
├── policies/v1/              *.rego · *_test.rego · data/      policies/tests/  adversarial Rego tests
├── tests/integration/        harness · adversarial_payloads.json · probes · session flows
├── benchmarks/               v1 model-free replay runner
├── benchmarkv2/              overhead · injecagent · agentdojo · asb · common
├── examples/ · demo/ · config/ · scripts/
└── docs/                     architecture · application-policy-layer · pipeline · crypto · paper/
```

## Reference documents
- `docs/architecture.md` — full design with diagrams
- `docs/application-policy-layer.md` — sessions, task scope, tool output screening, argument tainting, limits
- `docs/architecture.png` · `docs/hook-registry.png` · `docs/risk_context_object.png` — diagrams
- `benchmarkv2/README.md` — how to run each evaluation
- `.archived/` — earlier folder listing and policy decision matrix
