package ipsec

import (
	"strings"
	"testing"
	"time"
)

func TestGuardRemoteInitiationQualifiedIngress(t *testing.T) {
	i := guardFixture()
	c := &i.Connections[0]
	c.Grants[0].Source, c.Grants[0].Destination = c.Grants[0].Destination, c.Grants[0].Source
	c.ReplyIngressIndices = []int{10, 11}
	m, err := RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"meta iif 11 meta oif 2 ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 tcp dport 443 ct direction original meta iif @reply_lease_",
		"meta iif 2 meta oif 10 ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/24 tcp sport 443 ct direction reply ct state established meta oif @lease_",
	} {
		if !strings.Contains(m.NFT, want) {
			t.Fatalf("missing authorized reverse path: %s", want)
		}
	}
	for _, line := range strings.Split(m.NFT, "\n") {
		if strings.Contains(line, "counter accept") && strings.Contains(line, "meta oif 11") {
			t.Fatalf("backup egress widened: %s", line)
		}
	}
	for _, state := range []string{"unhealthy", "withdrawn", "expired", "revoked"} {
		j := guardFixture()
		j.Connections[0] = *c
		switch state {
		case "unhealthy":
			j.Connections[0].ReplyIngressIndices = []int{10}
		case "withdrawn":
			j.Connections[0].PermittedInterfaceIndices = nil
		case "expired":
			j.Connections[0].PermitFor = time.Millisecond
		case "revoked":
			j.Connections[0].Grants = nil
		}
		got, e := RenderGuard(j)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(got.NFT, "\n") {
			if strings.Contains(line, "counter accept") && strings.Contains(line, "meta iif 11") {
				t.Fatalf("%s retained remote ingress: %s", state, line)
			}
		}
	}
}
