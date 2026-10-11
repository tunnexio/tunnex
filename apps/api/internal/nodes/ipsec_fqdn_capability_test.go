package nodes

import (
	"encoding/json"
	"testing"
)

func TestIPsecFQDNPolicyCapabilityRequiresExactTypedVersion(t *testing.T) {
	for _, c := range []struct{ config, fqdn, want int }{{1, 1, 1}, {0, 1, 0}, {1, 0, 0}, {1, 2, 2}, {1, 3, 0}, {1, -1, 0}, {2, 1, 0}} {
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
	if err := json.Unmarshal([]byte(`{"ipsec_config_version":1,"ipsec_fqdn_policy_version":1}`), &caps); err != nil || caps.IPsecFQDNPolicyVersion != 1 {
		t.Fatal("typed capability lost", err)
	}
}
