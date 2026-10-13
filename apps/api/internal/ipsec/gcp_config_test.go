package ipsec

import "testing"

func gcpHAConfig() StaticConfig {
	return StaticConfig{ProfileID: GCPHAProfile, Mode: "ipv4-bgp", CustomerOutsideAddress: "9.9.9.9", LocalPrefixes: []string{"10.0.0.0/24"}, RemotePrefixes: []string{"10.1.0.0/24"}, BGP: &BGPConfig{LocalASN: 65001, RemoteASN: 65002, RouterID: "10.0.0.1", MaximumPrefixes: 8}, Tunnels: []StaticTunnel{{OutsideAddress: "8.8.8.8", InsideCIDR: "169.254.1.0/30", CustomerInsideAddress: "169.254.1.1", CloudInsideAddress: "169.254.1.2", PSK: "0-valid-GCP!"}, {OutsideAddress: "8.8.4.4", InsideCIDR: "169.254.2.0/30", CustomerInsideAddress: "169.254.2.1", CloudInsideAddress: "169.254.2.2", PSK: "0-valid-GCP!"}}}
}
func TestGCPHAAdmissionDoesNotInheritAWSReservations(t *testing.T) {
	c := gcpHAConfig()
	if err := ValidateProviderConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAWSConfig(c); err == nil {
		t.Fatal("AWS accepted GCP reservations")
	}
}
func TestGCPProfilesRefuseUnsafeIntent(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*StaticConfig)
	}{
		{"AWS remote ASN", func(c *StaticConfig) { c.BGP.RemoteASN = 7224 }},
		{"default route", func(c *StaticConfig) { c.RemotePrefixes = []string{"0.0.0.0/0"} }},
		{"overlapping routes", func(c *StaticConfig) { c.RemotePrefixes = c.LocalPrefixes }},
		{"single HA tunnel", func(c *StaticConfig) { c.Tunnels = c.Tunnels[:1] }},
		{"duplicate endpoint", func(c *StaticConfig) { c.Tunnels[1].OutsideAddress = c.Tunnels[0].OutsideAddress }},
		{"duplicate inside", func(c *StaticConfig) { c.Tunnels[1].InsideCIDR = c.Tunnels[0].InsideCIDR }},
		{"invalid inside host", func(c *StaticConfig) { c.Tunnels[0].CustomerInsideAddress = "169.254.1.0" }},
		{"invalid secret", func(c *StaticConfig) { c.Tunnels[0].PSK = "short" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := gcpHAConfig()
			tc.mutate(&c)
			if ValidateProviderConfig(c) == nil {
				t.Fatal("unsafe intent accepted")
			}
		})
	}
}
func TestGCPClassicAdmissionIsExplicitSingleTunnel(t *testing.T) {
	c := gcpHAConfig()
	c.ProfileID = GCPClassicProfile
	c.Mode = "ipv4-static"
	c.BGP = nil
	c.Tunnels = c.Tunnels[:1]
	c.Tunnels[0].InsideCIDR = ""
	c.Tunnels[0].CustomerInsideAddress = ""
	c.Tunnels[0].CloudInsideAddress = ""
	if err := ValidateProviderConfig(c); err != nil {
		t.Fatal(err)
	}
	c.BGP = &BGPConfig{}
	if ValidateProviderConfig(c) == nil {
		t.Fatal("Classic BGP accepted")
	}
}
