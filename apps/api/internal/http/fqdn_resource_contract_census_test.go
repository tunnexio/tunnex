package http

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFQDNResourceConsumerContractCensus names the consumers deliberately. A
// new policy destination is not automatically safe for JIT, templates, agents,
// CLI, or access-test surfaces: each must either support it end-to-end or remain
// explicitly unavailable. Lane 1 makes ordinary policy rules real and leaves
// resolver compilation/consumer expansion to their owning lanes.
func TestFQDNResourceConsumerContractCensus(t *testing.T) {
	type consumer struct {
		path        string
		oldKinds    []string
		unavailable bool
	}
	consumers := map[string]consumer{
		"jit":         {"../agentaccess/service.go", []string{"resource", "group", "site", "k8s_service"}, true},
		"template":    {"../agenttemplates/service.go", []string{"resource", "group", "site", "k8s_service"}, true},
		"agent":       {"../../../node/internal/reconcile/reconcile.go", nil, true},
		"cli":         {"../../../cli", nil, false},
		"test-access": {"agent_access_integration_test.go", []string{"resource"}, true},
	}
	for name, c := range consumers {
		path := filepath.Clean(c.path)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s consumer census target missing: %v", name, err)
		}
		if info.IsDir() {
			continue // CLI is generated from OpenAPI; generated drift is checked below.
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range c.oldKinds {
			if !strings.Contains(string(b), kind) {
				t.Fatalf("%s silently lost existing destination kind %q", name, kind)
			}
		}
		if c.unavailable && strings.Contains(string(b), `"fqdn_resource"`) {
			t.Fatalf("%s appears to accept fqdn_resource without this lane owning its resolver/compilation contract", name)
		}
	}
	generated, err := os.ReadFile("../../../../packages/shared/src/api.d.ts")
	if err != nil || !strings.Contains(string(generated), "dst_fqdn_resource_id") {
		t.Fatalf("generated CLI/web contract drifted from the FQDN destination field: %v", err)
	}
}
