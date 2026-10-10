// Package hooks is the registry of hook types the sidecar accepts.
//
// A hook is one enforcement point in the agent loop. Each entry names the Rego
// package that decides it and adds the hook-specific fields to the OPA input.
// Adding a hook is one Register call plus its Rego file: validation, the
// policy engine and the transport look hooks up here and do not change.
package hooks

import (
	"fmt"
	"sort"
	"sync"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Hook describes one enforcement point.
type Hook struct {
	// Name is the hook_type value on the wire, e.g. "on_tool_call".
	Name string
	// Policy is the Rego package that decides this hook, e.g. "acf.policy.tool".
	Policy string
	// Input adds hook-specific fields to the OPA input document, read from
	// rc.Payload. Nil when the hook needs only the common fields.
	Input func(rc *riskcontext.RiskContext, input map[string]any)
}

var (
	mu       sync.RWMutex
	registry = map[string]Hook{}
)

// Register adds h to the registry. An empty name or policy, or a name already
// registered, is a programming error and panics at startup.
func Register(h Hook) {
	if h.Name == "" || h.Policy == "" {
		panic(fmt.Sprintf("hooks: Register needs a name and a policy, got %+v", h))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[h.Name]; dup {
		panic(fmt.Sprintf("hooks: %q is already registered", h.Name))
	}
	registry[h.Name] = h
}

// Lookup returns the hook registered under name.
func Lookup(name string) (Hook, bool) {
	mu.RLock()
	defer mu.RUnlock()
	h, ok := registry[name]
	return h, ok
}

// All returns every registered hook, sorted by name so policy compilation and
// error messages are deterministic.
func All() []Hook {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Hook, 0, len(registry))
	for _, h := range registry {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns the registered hook names, sorted.
func Names() []string {
	all := All()
	names := make([]string, len(all))
	for i, h := range all {
		names[i] = h.Name
	}
	return names
}
