package policy

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func i(n int) *int { return &n }

// Finding #3: a tcp/udp resource must set ports both-or-neither. A HALF-SET range
// (only low or only high) is rejected AT THE API — otherwise it is stored, compiled,
// and then silently SKIPPED by the gateway's fail-closed renderAllow, breaking a grant
// the API reported as created. This validation and renderAllow's skip are the two halves
// of one invariant.
func TestValidateResourcePortsBothOrNeither(t *testing.T) {
	ok := []policyspec.ResourceInput{
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "tcp"},                                  // neither
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: i(80), PortHigh: i(80)}, // both
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "any"},                                  // any, no ports
	}
	for _, in := range ok {
		if err := validateResource(in); err != nil {
			t.Fatalf("valid resource rejected: %+v -> %v", in, err)
		}
	}
	bad := []policyspec.ResourceInput{
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: i(80)},   // only low
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "tcp", PortHigh: i(443)}, // only high
		{Name: "r", CIDR: "10.0.5.0/24", Protocol: "udp", PortLow: i(53)},   // only low (udp)
	}
	for _, in := range bad {
		if err := validateResource(in); err == nil {
			t.Fatalf("half-set port range must be rejected at the API: %+v", in)
		}
	}
}
