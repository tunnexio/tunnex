//go:build linux

package egress

import (
	"strings"
	"testing"
)

// K8N-3, found on GKE: the request reached the API server and no reply came back, because the API
// server of a managed cluster has no return route to a device address. Flows forwarded to it leave
// through the node's address; Service flows are untouched.
func TestK8sAPIFlowsAreMasqueradedAndServiceFlowsAreNot(t *testing.T) {
	m := &Manager{}
	if got := m.k8sAPIMasqueradeRules([]string{"wg0"}); got != "" {
		t.Fatalf("no API address is forwarded, yet a rule was rendered: %q", got)
	}
	vips := []string{"100.65.0.4", "not-an-address", "fd00::4"}
	m.k8sAPIVIPs.Store(&vips)
	got := m.k8sAPIMasqueradeRules([]string{"wg0"})
	if strings.Count(got, "masquerade") != 1 {
		t.Fatalf("want exactly one rule, for the one valid IPv4 address: %q", got)
	}
	for _, want := range []string{"ct original ip daddr 100.65.0.4", "oifname", "wg0", "masquerade"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rule %q lacks %q", got, want)
		}
	}
	// Scoped by the flow's original destination: a Service address never appears.
	if strings.Contains(got, "100.65.0.3") || strings.Contains(got, "ip saddr") {
		t.Fatalf("rule is not limited to the API address: %q", got)
	}
}
