package control

import (
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestIPsecFQDNCapabilityNeverDefaultsToAuthority(t *testing.T) {
	var nilClient *Client
	for _, c := range []*Client{nilClient, {}, {}} {
		if c != nil {
			c.AttachIPsecController(&ipsec.RuntimeController{})
		}
		if c.ipsecFQDNPolicyCapability() != 0 {
			t.Fatal("cold/unqualified feature advertised")
		}
	}
}
