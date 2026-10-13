package ipsec_test

import (
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func bgpConfigFixture() ipsec.StaticConfig {
	c := staticConfigFixture()
	c.Mode = "ipv4-bgp"
	c.BGP = &ipsec.BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	return c
}
func TestBGPConfigValidation(t *testing.T) {
	c := bgpConfigFixture()
	if err := ipsec.ValidateAWSConfig(c); err != nil {
		t.Fatal(err)
	}
	if ipsec.ValidateAWSStaticConfig(c) == nil {
		t.Fatal("BGP entered static validator")
	}
	for _, a := range []uint32{64512, 65534, 4200000000, 4294967294} {
		c.BGP.LocalASN = a
		if err := ipsec.ValidateAWSConfig(c); err != nil {
			t.Fatalf("private ASN %d: %v", a, err)
		}
	}
	cases := []struct {
		name   string
		change func(*ipsec.StaticConfig)
	}{
		{"missing", func(c *ipsec.StaticConfig) { c.BGP = nil }},
		{"public local", func(c *ipsec.StaticConfig) { c.BGP.LocalASN = 7224 }},
		{"reserved local", func(c *ipsec.StaticConfig) { c.BGP.LocalASN = 65535 }},
		{"public remote", func(c *ipsec.StaticConfig) { c.BGP.RemoteASN = 23456 }},
		{"same ASN", func(c *ipsec.StaticConfig) { c.BGP.RemoteASN = c.BGP.LocalASN }},
		{"zero limit", func(c *ipsec.StaticConfig) { c.BGP.MaximumPrefixes = 0 }},
		{"large limit", func(c *ipsec.StaticConfig) { c.BGP.MaximumPrefixes = 65 }},
		{"zero router", func(c *ipsec.StaticConfig) { c.BGP.RouterID = "0.1.1.1" }},
		{"multicast router", func(c *ipsec.StaticConfig) { c.BGP.RouterID = "224.1.1.1" }},
		{"noncanonical router", func(c *ipsec.StaticConfig) { c.BGP.RouterID = "010.10.0.1" }},
		{"IPv6 router", func(c *ipsec.StaticConfig) { c.BGP.RouterID = "::1" }},
		{"default import", func(c *ipsec.StaticConfig) { c.RemotePrefixes = []string{"0.0.0.0/0"} }},
		{"static mixed", func(c *ipsec.StaticConfig) { c.Mode = "ipv4-static" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := bgpConfigFixture()
			tt.change(&c)
			if ipsec.ValidateAWSConfig(c) == nil {
				t.Fatal("invalid BGP intent accepted")
			}
		})
	}
}
