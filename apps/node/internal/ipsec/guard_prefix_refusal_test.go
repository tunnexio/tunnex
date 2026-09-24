package ipsec

import (
	"strings"
	"testing"
)

func TestGuardPrefixOnlyStartupRefusal(t *testing.T) {
	in := guardFixture()
	c := &in.Connections[0]
	c.PrefixOnly = true
	c.Tunnels = [2]Ownership{}
	c.PermitFor = 0
	c.PermittedInterfaceIndices = nil
	c.LocalIngressIndices = nil
	c.Grants = nil
	got, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.NFT, "counter accept") || strings.Contains(got.NFT, "meta iif 0") || strings.Contains(got.NFT, "meta oif 0") {
		t.Fatal("startup guard borrowed invalid ownership or permits")
	}
	if strings.Count(got.NFT, "ip daddr 10.20.0.0/24 counter drop") < 3 || strings.Count(got.NFT, "ip saddr 10.20.0.0/24 counter drop") < 3 {
		t.Fatal("permanent refusal missing")
	}
	c.Tunnels[0] = guardFixture().Connections[0].Tunnels[0]
	if _, err = RenderGuard(in); err != ErrGuardIntent {
		t.Fatal("prefix mode accepted stale interface")
	}
	c.Tunnels = [2]Ownership{}
	c.Grants = guardFixture().Connections[0].Grants
	if _, err = RenderGuard(in); err != ErrGuardIntent {
		t.Fatal("prefix mode accepted policy authority")
	}
}
