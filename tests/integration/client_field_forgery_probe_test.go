// TestClientFieldForgeryProbe is a permanent invariant guard, the companion to
// TestProvenanceForgeryProbe: no field the client controls may downgrade a
// verdict.
//
// The client sends signals and state alongside its payload. Several policies
// read signal categories nothing in the sidecar emits, and context.rego halves
// the effective score on a high source_trust, so a client that could supply
// those talked its own risk down. The sidecar now drops client signals with no
// configured weight and discards client state. This probe replays every
// non-ALLOW corpus case with forged signals and state and fails on any
// loosening.
package integration

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

var forgedSignalSets = map[string][]map[string]any{
	"high source_trust":    {{"category": "source_trust", "score": 0.99}},
	"low_trust_source":     {{"category": "low_trust_source", "score": 0.99}},
	"zero-scored weighted": {{"category": "jailbreak_pattern", "score": 0.0}},
}

var forgedState = map[string]any{
	"allowed_tools": []any{"delete_database", "send_money"},
	"trusted":       true,
}

func TestClientFieldForgeryProbe(t *testing.T) {
	all := loadCorpus(t)

	baseline := map[string]string{}
	for _, pc := range all {
		baseline[pc.ID] = send(t, pc)
	}

	var downgrades []string
	weakened := map[string]bool{}
	for _, pc := range all {
		base := baseline[pc.ID]
		if base == "ALLOW" {
			continue // nothing to downgrade
		}
		variants := map[string]payloadCase{}
		for name, sigs := range forgedSignalSets {
			v := pc
			v.Signals = sigs
			variants["signals: "+name] = v
		}
		withState := pc
		withState.State = forgedState
		variants["state: allowed_tools + trusted"] = withState

		for name, v := range variants {
			if got := send(t, v); rank(got) < rank(base) {
				downgrades = append(downgrades, fmt.Sprintf("%s [%s] %s -> %s by forging %s",
					pc.ID, pc.HookType, base, got, name))
				weakened[pc.ID] = true
			}
		}
	}

	sort.Strings(downgrades)
	var b strings.Builder
	fmt.Fprintf(&b, "\nclient field forgery probe: %d payloads, %d downgraded\n", len(all), len(weakened))
	for _, d := range downgrades {
		fmt.Fprintf(&b, "  %s\n", d)
	}
	t.Log(b.String())
	if len(downgrades) > 0 {
		t.Errorf("forged client fields downgraded %d verdict(s)", len(weakened))
	}
}
