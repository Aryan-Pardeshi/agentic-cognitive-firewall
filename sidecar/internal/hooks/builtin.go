// builtin.go — the hooks the sidecar ships with.
package hooks

import "github.com/acf-sdk/sidecar/pkg/riskcontext"

// The provenance labels match what the SDK's hook methods have always sent, so
// assigning them in the sidecar changes no trust weight for SDK traffic.
func init() {
	Register(Hook{Name: "on_prompt", Policy: "acf.policy.prompt", Provenance: "user"})
	Register(Hook{Name: "on_context", Policy: "acf.policy.context", Provenance: "rag", Input: contextInput})
	Register(Hook{Name: "on_tool_call", Policy: "acf.policy.tool", Provenance: "agent", Input: toolCallInput})
	Register(Hook{Name: "on_memory", Policy: "acf.policy.memory", Provenance: "agent", Input: memoryInput})
}

func payloadMap(rc *riskcontext.RiskContext) (map[string]any, bool) {
	m, ok := rc.Payload.(map[string]any)
	return m, ok
}

func toolCallInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	input["tool_name"] = m["name"]
	if meta, ok := m["metadata"]; ok {
		input["tool_metadata"] = meta
	} else {
		input["tool_metadata"] = map[string]any{}
	}
}

func contextInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	if s, ok := m["content"].(string); ok {
		input["payload_size_bytes"] = len([]byte(s))
	}
	if trust, ok := m["source_trust"]; ok {
		input["source_trust"] = trust
	}
}

func memoryInput(rc *riskcontext.RiskContext, input map[string]any) {
	m, ok := payloadMap(rc)
	if !ok {
		return
	}
	input["memory_op"] = m["op"]
	if v, ok := m["value"].(string); ok {
		input["payload_size_bytes"] = len([]byte(v))
	}
	input["integrity"] = map[string]any{
		"hmac_valid": m["hmac_valid"],
	}
}
