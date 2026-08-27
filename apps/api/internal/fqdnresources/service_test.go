package fqdnresources

import "testing"

func intPtr(v int) *int { return &v }

func TestValidRejectsHalfPortRanges(t *testing.T) {
	for _, in := range []Input{
		{Name: "api", FQDN: "api.example.test", Protocol: "tcp", PortLow: intPtr(443)},
		{Name: "api", FQDN: "api.example.test", Protocol: "udp", PortHigh: intPtr(53)},
	} {
		if err := valid(&in); err == nil {
			t.Fatalf("half port range %+v was accepted", in)
		}
	}
	if err := valid(&Input{Name: "api", FQDN: "api.example.test", Protocol: "tcp", PortLow: intPtr(443), PortHigh: intPtr(443)}); err != nil {
		t.Fatalf("complete TCP port range rejected: %v", err)
	}
}
