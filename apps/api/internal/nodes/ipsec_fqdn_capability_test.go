package nodes

import (
	"encoding/json"
	"testing"
)

func TestIPsecFQDNPolicyCapabilityRequiresExactTypedVersion(t *testing.T) {
	for _, c := range []struct{ config, fqdn, want int }{{1, 1, 1}, {0, 1, 0}, {1, 0, 0}, {1, 2, 0}, {2, 1, 0}, {1, -1, 0}} {
		if got := ipsecFQDNPolicyCapability(c.config, c.fqdn); got != c.want {
			t.Fatalf("capability %+v got%d", c, got)
		}
	}
	for _, wire := range []string{`{"ipsec_fqdn_policy_version":"1"}`, `{"ipsec_fqdn_policy_version":true}`} {
		var p AppliedPolicy
		if json.Unmarshal([]byte(wire), &p) == nil {
			t.Fatal("nonnumeric version accepted")
		}
	}
	var caps NodeCapabilities
	if err := json.Unmarshal([]byte(`{"ipsec_config_version":1,"ipsec_gcp_classic_version":1,"ipsec_gcp_ha_version":1,"ipsec_fqdn_policy_version":1}`), &caps); err != nil || caps.IPsecFQDNPolicyVersion != 1 || caps.IPsecGCPClassicVersion != 1 || caps.IPsecGCPHAVersion != 1 {
		t.Fatal("typed common capability lost GCP capabilities", err)
	}
}
