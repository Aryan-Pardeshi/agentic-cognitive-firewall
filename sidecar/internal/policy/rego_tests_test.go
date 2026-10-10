package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"
)

// TestRegoPolicyTests runs the Rego unit tests in policies/v1 and
// policies/tests with OPA's own test runner, the same tests `make opa-test`
// runs with the opa binary. Running them here puts them under `go test`, so
// CI covers them without an opa install. The two directories load together
// because policies/tests exercises the packages defined in policies/v1.
func TestRegoPolicyTests(t *testing.T) {
	root := filepath.Join(policyDir(t), "..", "..")
	results, err := tester.Run(context.Background(),
		filepath.Join(root, "policies", "v1"),
		filepath.Join(root, "policies", "tests"))
	if err != nil {
		t.Fatalf("running Rego tests: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("found no Rego tests")
	}
	passed := 0
	for _, r := range results {
		if r.Pass() {
			passed++
			continue
		}
		if r.Error != nil {
			t.Errorf("%s.%s: %v", r.Package, r.Name, r.Error)
		} else {
			t.Errorf("%s.%s failed", r.Package, r.Name)
		}
	}
	t.Logf("%d of %d Rego tests passed", passed, len(results))
}
