package ipsec_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func staticConfigFixture() ipsec.StaticConfig {
	return ipsec.StaticConfig{Mode: "ipv4-static", CustomerOutsideAddress: "9.9.9.9", LocalPrefixes: []string{"10.10.0.0/16"}, RemotePrefixes: []string{"10.20.0.0/16"}, Tunnels: []ipsec.StaticTunnel{
		{OutsideAddress: "8.8.8.8", InsideCIDR: "169.254.10.0/30", CustomerInsideAddress: "169.254.10.2", CloudInsideAddress: "169.254.10.1", PSK: "Synthetic.fixture.PSK_123"},
		{OutsideAddress: "1.1.1.1", InsideCIDR: "169.254.10.4/30", CustomerInsideAddress: "169.254.10.5", CloudInsideAddress: "169.254.10.6", PSK: "Other.fixture.PSK_456"},
	}}
}
func TestAWSStaticConfigValidAndUnmodified(t *testing.T) {
	c := staticConfigFixture()
	before, _ := json.Marshal(c)
	if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("preflight mutated input")
	}
	if strings.Contains(string(after), "PSK_") {
		t.Fatal("config JSON exposed credentials")
	}
	// Either host order is accepted: assignment is explicit, never inferred.
	c.Tunnels[0].CustomerInsideAddress, c.Tunnels[0].CloudInsideAddress = c.Tunnels[0].CloudInsideAddress, c.Tunnels[0].CustomerInsideAddress
	if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
		t.Fatal(err)
	}
	if c.Tunnels[0].PSK != "Synthetic.fixture.PSK_123" || c.Tunnels[1].PSK != "Other.fixture.PSK_456" {
		t.Fatal("preflight altered credentials")
	}
	c.LocalPrefixes = append(c.LocalPrefixes, "10.11.0.0/16")
	if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
		t.Fatalf("adjacent prefixes rejected: %v", err)
	}
}
func TestAWSStaticConfigRejectsInvalidShape(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ipsec.StaticConfig)
	}{
		{"unsupported mode", func(c *ipsec.StaticConfig) { c.Mode = "bgp" }},
		{"missing local", func(c *ipsec.StaticConfig) { c.LocalPrefixes = nil }},
		{"missing remote", func(c *ipsec.StaticConfig) { c.RemotePrefixes = nil }},
		{"too many prefixes", func(c *ipsec.StaticConfig) {
			c.LocalPrefixes = nil
			for i := 0; i < 65; i++ {
				c.LocalPrefixes = append(c.LocalPrefixes, fmt.Sprintf("10.30.%d.0/24", i))
			}
		}},
		{"noncanonical", func(c *ipsec.StaticConfig) { c.LocalPrefixes[0] = "10.10.0.1/16" }},
		{"invalid prefix", func(c *ipsec.StaticConfig) { c.LocalPrefixes[0] = "secret-command-marker" }},
		{"IPv6", func(c *ipsec.StaticConfig) { c.RemotePrefixes[0] = "fd00::/64" }},
		{"mapped IPv4", func(c *ipsec.StaticConfig) { c.RemotePrefixes[0] = "::ffff:10.20.0.0/112" }},
		{"duplicate local", func(c *ipsec.StaticConfig) { c.LocalPrefixes = append(c.LocalPrefixes, c.LocalPrefixes[0]) }},
		{"nested local", func(c *ipsec.StaticConfig) { c.LocalPrefixes = append(c.LocalPrefixes, "10.10.1.0/24") }},
		{"cross overlap", func(c *ipsec.StaticConfig) { c.RemotePrefixes[0] = "10.10.1.0/24" }},
		{"one tunnel", func(c *ipsec.StaticConfig) { c.Tunnels = c.Tunnels[:1] }},
		{"three tunnels", func(c *ipsec.StaticConfig) { c.Tunnels = append(c.Tunnels, c.Tunnels[0]) }},
		{"same outside", func(c *ipsec.StaticConfig) { c.Tunnels[1].OutsideAddress = c.Tunnels[0].OutsideAddress }},
		{"same inside prefix", func(c *ipsec.StaticConfig) { c.Tunnels[1] = c.Tunnels[0]; c.Tunnels[1].OutsideAddress = "1.1.1.1" }},
		{"inside host prefix", func(c *ipsec.StaticConfig) { c.Tunnels[0].InsideCIDR = "169.254.10.1/30" }},
		{"inside network address", func(c *ipsec.StaticConfig) { c.Tunnels[0].CustomerInsideAddress = "169.254.10.0" }},
		{"inside broadcast address", func(c *ipsec.StaticConfig) { c.Tunnels[0].CloudInsideAddress = "169.254.10.3" }},
		{"outside inside prefix", func(c *ipsec.StaticConfig) { c.Tunnels[0].CustomerInsideAddress = "169.254.20.1" }},
		{"same inside address", func(c *ipsec.StaticConfig) { c.Tunnels[0].CloudInsideAddress = c.Tunnels[0].CustomerInsideAddress }},
		{"inside routes overlap", func(c *ipsec.StaticConfig) { c.LocalPrefixes[0] = "169.254.10.0/24" }},
		{"blank PSK", func(c *ipsec.StaticConfig) { c.Tunnels[0].PSK = "" }},
		{"control PSK", func(c *ipsec.StaticConfig) { c.Tunnels[1].PSK = "secret-marker\ncommand" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := staticConfigFixture()
			tc.change(&c)
			err := ipsec.ValidateAWSStaticConfig(c)
			if err == nil {
				t.Fatal("invalid accepted")
			}
			var validation *ipsec.ConfigValidationError
			if !errors.As(err, &validation) || validation.Code == "" {
				t.Fatalf("untyped error=%v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "command") || strings.Contains(err.Error(), "10.10") {
				t.Fatal("error reflected input")
			}
		})
	}
}

func TestAWSStaticConfigProviderBounds(t *testing.T) {
	for _, prefix := range []string{"169.254.0.0/30", "169.254.1.0/30", "169.254.2.0/30", "169.254.3.0/30", "169.254.4.0/30", "169.254.5.0/30", "169.254.169.252/30", "169.254.10.0/29", "10.0.0.0/30"} {
		t.Run("inside_"+prefix, func(t *testing.T) {
			c := staticConfigFixture()
			c.Tunnels[0].InsideCIDR = prefix
			p := netip.MustParsePrefix(prefix)
			c.Tunnels[0].CustomerInsideAddress = p.Addr().Next().String()
			c.Tunnels[0].CloudInsideAddress = p.Addr().Next().Next().String()
			if ipsec.ValidateAWSStaticConfig(c) == nil {
				t.Fatal("unsupported inside CIDR accepted")
			}
		})
	}
	for _, psk := range []string{"1234567", strings.Repeat("a", 65), "012345678", "has-hyphen", "has space", "unicodeé", "synthetic\x00marker"} {
		c := staticConfigFixture()
		c.Tunnels[0].PSK = psk
		if ipsec.ValidateAWSStaticConfig(c) == nil {
			t.Fatal("invalid provider PSK accepted")
		}
	}
	for _, psk := range []string{"Abc12._x", strings.Repeat("Z", 64)} {
		c := staticConfigFixture()
		c.Tunnels[0].PSK = psk
		if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
			t.Fatal(err)
		}
	}
	c := staticConfigFixture()
	c.LocalPrefixes = []string{"11.10.0.0/16"}
	if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
		t.Fatalf("ordinary global LAN rejected: %v", err)
	}
	c.LocalPrefixes = nil
	for i := 0; i < 64; i++ {
		c.LocalPrefixes = append(c.LocalPrefixes, fmt.Sprintf("10.30.%d.0/24", i))
	}
	if err := ipsec.ValidateAWSStaticConfig(c); err != nil {
		t.Fatalf("64-prefix boundary refused: %v", err)
	}
	c.LocalPrefixes = []string{"8.8.8.0/24"}
	if ipsec.ValidateAWSStaticConfig(c) == nil {
		t.Fatal("outside endpoint route accepted")
	}
}
func TestAWSStaticConfigSpecialUse(t *testing.T) {
	special := []string{"0.1.2.3", "10.1.2.3", "100.64.0.1", "127.1.2.3", "169.254.1.1", "172.16.1.1", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::ffff:8.8.8.8", "2001:db8::1", "8.8.8.8:500"}
	for _, address := range special {
		t.Run(address, func(t *testing.T) {
			c := staticConfigFixture()
			c.Tunnels[0].OutsideAddress = address
			if ipsec.ValidateAWSStaticConfig(c) == nil {
				t.Fatal("special outside accepted")
			}
		})
	}
	for _, prefix := range []string{"0.0.0.0/0", "100.64.0.0/10", "192.0.0.0/8", "198.16.0.0/14", "224.0.0.0/4", "240.0.0.0/4"} {
		c := staticConfigFixture()
		c.LocalPrefixes = []string{prefix}
		if ipsec.ValidateAWSStaticConfig(c) == nil {
			t.Fatal("route overlapping special allocation accepted")
		}
	}
}

func TestAWSStaticConfigCustomerOutside(t *testing.T) {
	for _, address := range []string{"", "10.0.0.1", "0.0.0.0", "::ffff:9.9.9.9", "8.8.8.8", "1.1.1.1", "9.9.9.9:500"} {
		c := staticConfigFixture()
		c.CustomerOutsideAddress = address
		if validationErr := ipsec.ValidateAWSStaticConfig(c); validationErr == nil {
			t.Fatal("invalid customer outside accepted")
		}
	}
	c := staticConfigFixture()
	c.RemotePrefixes = []string{"9.9.9.0/24"}
	if ipsec.ValidateAWSStaticConfig(c) == nil {
		t.Fatal("customer outside captured by route")
	}
}
