package control

import "testing"

func TestDesktopFQDNCapabilityColdClientRefuses(t *testing.T) {
	var absent *Client
	if absent.ipsecDesktopFQDNCapability() != 0 || (&Client{}).ipsecDesktopFQDNCapability() != 0 {
		t.Fatal("unqualified runtime advertised desktop FQDN")
	}
}
