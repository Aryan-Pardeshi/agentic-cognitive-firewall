# ACF — v1 Rego Policy Templates

Default policy templates for each hook, mapped to the [ACF Policy Taxonomy Matrix](../../docs/acf_policy_matrix.pdf).

## Structure

```
policies/v1/
├── prompt.rego             on_prompt hook policies
├── context.rego            on_context hook policies
├── tool.rego               on_tool_call: allowlist, destination, detection, task scope,
│                           argument constraints, argument taint, threshold
├── memory.rego             on_memory hook policies
├── tool_result.rego        on_tool_result: score thresholds, trusted_tools
├── task.rego               on_task: a session's scope may only narrow the global allowlist
├── *_test.rego             unit tests, one file per policy; tool_scope_test.rego and
│                           tool_taint_test.rego cover tool.rego's session gates
└── data/
    ├── policy_config.yaml       thresholds, allowlists, trusted_tools, consequential_tools,
    │                            sensitive_params, signal weights
    └── jailbreak_patterns.json  lexical pattern library
```

The Rego tests here and in `policies/tests/` run under `go test` through
`TestRegoPolicyTests` in `sidecar/internal/policy`, as well as with
`make opa-test`.

Sessions, task scope, tool output screening and argument tainting are
described in [docs/application-policy-layer.md](../../docs/application-policy-layer.md).
The coverage matrix below is for the original four hooks.

## Taxonomy Matrix Coverage

| Policy Type | on_prompt | on_context | on_tool_call | on_memory |
|---|---|---|---|---|
| **Detection** | instruction_override `BLOCK` · role_escalation `BLOCK` · jailbreak_pattern `BLOCK` · obfuscation_escalation `BLOCK` · policy_integrity `HALT` | embedded_instruction `SANITISE` · structural_anomaly `BLOCK` | parameter_injection `BLOCK` · shell_metacharacter `BLOCK` · path_traversal `BLOCK` | write_time_content_scan `SANITISE` |
| **Permission** | — | — | tool_allowlist `BLOCK` · network_destination `BLOCK` | — |
| **Integrity** | — | — | — | write_time_hmac_stamp `STAMP` · read_time_hmac_verify `BLOCK` |
| **Trust** | — | source_trust_weighting `MULTIPLIER` | — | write_provenance_tag `TAG` · read_time_trust_weight `MARKER` |
| **Containment** | injection_threshold `graduated` | context_risk_threshold `graduated` · rag_chunk_size_limit `SPLIT` | tool_call_threshold `graduated` | memory_entry_size_limit `BLOCK` |
| **Accumulation** | v2 | v2 | v2 | v2 |

## Input Schema

Every policy expects the same `RiskContext` object from the sidecar pipeline:

```json
{
  "score": 0.45,
  "signals": [
    {"category": "instruction_override", "score": 0.9}
  ],
  "provenance": "sdk",
  "session_id": "abc-123",
  "hook_type": "on_prompt",
  "payload_size_bytes": 1024,
  "tool_name": "web_search",
  "tool_metadata": {"destination": "api.example.com"},
  "memory_op": "write",
  "integrity": {"hmac_valid": true}
}
```

Fields are hook-dependent — `tool_name` only appears in `on_tool_call`, `memory_op` only in `on_memory`, etc.

## Output Schema

Policies return structured JSON for the pipeline to act on:

```json
{
  "decision": "ALLOW | SANITISE | BLOCK",
  "sanitise_targets": ["prompt_text", "context_chunk", "tool_params", "memory_value", "split_chunk"],
  "metadata": {"action": "stamp_hmac", "provenance": "sdk", "trust_level": "verified"}
}
```

The pipeline reads `decision` for routing and `sanitise_targets` / `metadata` for transformation. **OPA decides what; the pipeline decides how.** Mutation logic never enters the policy layer.

## Running Tests

```bash
# Requires OPA CLI (https://www.openpolicyagent.org/docs/latest/#running-opa)
cd policies/v1
opa test . -v
```

## Design Decisions

1. **Default-deny for tool calls.** `on_tool_call` defaults to `BLOCK` — tools must be explicitly allowed. All other hooks default to `ALLOW`.

2. **Graduated containment.** Containment policies use three thresholds: `< 0.4` → ALLOW, `0.4–0.8` → SANITISE, `≥ 0.8` → BLOCK. These map to the risk context score after aggregation.

3. **Trust as a multiplier.** Trust policies don't make decisions directly. They adjust the effective score via a multiplier (2x for low-trust, 0.5x for high-trust), which feeds into containment thresholds.

4. **Metadata for non-decision actions.** HMAC stamping, provenance tagging, and trust marking are not decisions — they're instructions to the pipeline. Returned via the `metadata` field.

5. **Configurable via `data.config`.** Allowlists, size limits, and thresholds are loaded from OPA's data layer, not hardcoded in policy. This lets operators customise without editing Rego.

## References

- [ACF v0.2 Architecture](../../docs/acf_abstract_architecture_v0_2.pdf) — Seam 1 (hook registry), pipeline stages
- [ACF Policy Taxonomy Matrix](../../docs/acf_policy_matrix.pdf) — canonical policy classification
- [Vakhula et al., 2025](../../docs/Policy_as_code_research_paper.pdf) — Policy-as-Code for RBAC/ABAC in cloud-native systems
