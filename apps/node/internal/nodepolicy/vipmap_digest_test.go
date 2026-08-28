package nodepolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Twin of policyspec's golden: the node must report the same digest the
// control plane computed, without making it a policy/desync input.
func TestVIPMapDigestCanonicalReportOnlyContract(t *testing.T) {
	base := []nodepolicy.VIPMapping{
		{ServiceID: "svc-a", VIP: "100.64.0.5", Namespace: "prod", Service: "api", Protocol: "udp", PortLow: 53, PortHigh: 53, ServiceCIDR: "10.96.0.0/12", DNSName: "api.prod.svc.c.example"},
		{ServiceID: "svc-b", VIP: "100.64.0.6", Namespace: "prod", Service: "web", Protocol: "tcp", PortLow: 443, PortHigh: 443, ServiceCIDR: "10.96.0.0/12", DNSName: "web.prod.svc.c.example"},
	}
	const want = "af1f1bff66247839a690d66050a2b14a7d8cb58624400aff5914f0a6bb48602a"
	if got := nodepolicy.VIPMapDigest(base); got != want {
		t.Fatalf("VIPMapDigest = %q, want %q", got, want)
	}
	if got := nodepolicy.VIPMapDigest([]nodepolicy.VIPMapping{base[1], base[0]}); got != want {
		t.Fatalf("mapping order changed digest: got %q, want %q", got, want)
	}

	changes := map[string]func(*nodepolicy.VIPMapping){
		"service_id":   func(m *nodepolicy.VIPMapping) { m.ServiceID = "svc-other" },
		"vip":          func(m *nodepolicy.VIPMapping) { m.VIP = "100.64.0.99" },
		"namespace":    func(m *nodepolicy.VIPMapping) { m.Namespace = "other" },
		"service":      func(m *nodepolicy.VIPMapping) { m.Service = "other" },
		"service_cidr": func(m *nodepolicy.VIPMapping) { m.ServiceCIDR = "10.97.0.0/16" },
		"dns_name":     func(m *nodepolicy.VIPMapping) { m.DNSName = "other.prod.svc.c.example" },
		"protocol":     func(m *nodepolicy.VIPMapping) { m.Protocol = "tcp" },
		"port_low":     func(m *nodepolicy.VIPMapping) { m.PortLow = 54 },
		"port_high":    func(m *nodepolicy.VIPMapping) { m.PortHigh = 54 },
	}
	for field, change := range changes {
		t.Run(field, func(t *testing.T) {
			changed := append([]nodepolicy.VIPMapping(nil), base...)
			change(&changed[0])
			if got := nodepolicy.VIPMapDigest(changed); got == want {
				t.Fatalf("changing included %s did not change digest", field)
			}
		})
	}

	compiled := &nodepolicy.Compiled{Version: 7, NodeID: "node-a", Mode: "enforcing", VIPMappings: base}
	changedCompiled := *compiled
	changedCompiled.VIPMappings = append([]nodepolicy.VIPMapping(nil), base...)
	changedCompiled.VIPMappings[0].ServiceID = "svc-other"
	if nodepolicy.CanonicalHash(compiled) != nodepolicy.CanonicalHash(&changedCompiled) {
		t.Fatal("service_id changed CanonicalHash; VIP reporting must remain desync-blind")
	}

	var legacy nodepolicy.Compiled
	if err := json.Unmarshal([]byte(`{"vip_mappings":[{"vip":"100.64.0.5","namespace":"prod","service":"api","protocol":"udp","port_low":53,"port_high":53}]}`), &legacy); err != nil {
		t.Fatalf("decode legacy artifact: %v", err)
	}
	if len(legacy.VIPMappings) != 1 || legacy.VIPMappings[0].ServiceID != "" {
		t.Fatalf("legacy mapping must remain accepted without service_id, got %+v", legacy.VIPMappings)
	}
	if got := nodepolicy.VIPMapDigest(legacy.VIPMappings); got != "" {
		t.Fatalf("legacy mapping must not be reportable, got digest %q", got)
	}
}
