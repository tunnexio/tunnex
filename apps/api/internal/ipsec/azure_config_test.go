package ipsec

import (
	"github.com/google/uuid"
	"testing"
)

func azureFixture(profile string) StaticConfig {
	c := gcpHAConfig()
	c.Azure = &AzureContract{GatewaySKU: "VpnGw1AZ", VPNType: "RouteBased", IKEVersion: 2, CustomPolicy: "aes256-sha256-dh14-pfs2048"}
	c.ProfileID = profile
	c.BGP.RemoteASN = 65515
	for i := range c.Tunnels {
		if i == 0 {
			c.Tunnels[i].InsideCIDR = "169.254.21.0/30"
			c.Tunnels[i].CustomerInsideAddress = "169.254.21.1"
			c.Tunnels[i].CloudInsideAddress = "169.254.21.2"
		} else {
			c.Tunnels[i].InsideCIDR = "169.254.22.0/30"
			c.Tunnels[i].CustomerInsideAddress = "169.254.22.1"
			c.Tunnels[i].CloudInsideAddress = "169.254.22.2"
		}
	}
	if azureBGP(profile) {
		for i := range c.Tunnels {
			c.Tunnels[i].InsideCIDR = "169.254.20.1/32"
			c.Tunnels[i].CustomerInsideAddress = "169.254.20.1"
		}
	}
	if azureStandby(profile) {
		c.Tunnels = c.Tunnels[:1]
	}
	if !azureBGP(profile) {
		c.Mode = "ipv4-static"
		c.BGP = nil
	}
	return c
}
func TestAzureFourProviderContracts(t *testing.T) {
	for _, p := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(p, func(t *testing.T) {
			c := azureFixture(p)
			if err := ValidateProviderConfig(c); err != nil {
				t.Fatal(err)
			}
			c.Tunnels = append(c.Tunnels, c.Tunnels[0])
			if ValidateProviderConfig(c) == nil {
				t.Fatal("wrong topology accepted")
			}
		})
	}
}
func TestAzureAdmissionRejectsInvalidCloudPeerAndReservedASN(t *testing.T) {
	for _, mutate := range []func(*StaticConfig){func(c *StaticConfig) { c.BGP.LocalASN = 65515 },
		func(c *StaticConfig) { c.Azure.GatewaySKU = "Basic" }, func(c *StaticConfig) { c.Azure.VPNType = "PolicyBased" }, func(c *StaticConfig) { c.Azure.CustomPolicy = "default" }, func(c *StaticConfig) { c.Azure.NATEnabled = true }, func(c *StaticConfig) { c.Azure = nil },
		func(c *StaticConfig) { c.Tunnels[1].PSK = "differentKey" }, func(c *StaticConfig) {
			c.Tunnels[1].InsideCIDR = "169.254.20.2/32"
			c.Tunnels[1].CustomerInsideAddress = "169.254.20.2"
		}, func(c *StaticConfig) { c.BGP.LocalASN = 8075 }, func(c *StaticConfig) { c.BGP.RemoteASN = 23456 }, func(c *StaticConfig) { c.BGP.RemoteASN = c.BGP.LocalASN }, func(c *StaticConfig) {
			c.Tunnels[0].InsideCIDR = "169.254.20.0/30"
			c.Tunnels[0].CustomerInsideAddress = "169.254.20.1"
			c.Tunnels[0].CloudInsideAddress = "169.254.20.2"
		}, func(c *StaticConfig) { c.LocalPrefixes = []string{"0.0.0.0/0"} }, func(c *StaticConfig) { c.Tunnels[0].PSK = "key\nsecret" }, func(c *StaticConfig) { c.ProfileID = "azure-policy-based" }} {
		c := azureFixture(AzureActiveActiveBGPProfile)
		mutate(&c)
		if ValidateProviderConfig(c) == nil {
			t.Fatal("unsafe Azure intent accepted")
		}
	}
	c := azureFixture(AzureActiveActiveBGPProfile)
	c.BGP.LocalASN = 12345
	c.BGP.RemoteASN = 4200000123
	if err := ValidateProviderConfig(c); err != nil {
		t.Fatal("valid Azure public/32bit ASN rejected", err)
	}
}
func TestAzureStandbyManifestAndStatusContract(t *testing.T) {
	c := azureFixture(AzureActiveStandbyBGPProfile)
	tun := [2]RuntimeTunnel{{ID: uuid.New(), Slot: 1}}
	m := runtimeManifest(Connection{}, c, tun)
	if !azureManifestCompatible(m, true) || m.BGPVersion == nil || *m.BGPVersion != 3 || m.TunnelCount == nil || *m.TunnelCount != 1 {
		t.Fatal("standby manifest incompatible")
	}
	r := RuntimeStatusReport{TransportVersion: m.TransportVersion, TunnelCount: m.TunnelCount, Tunnels: [2]RuntimeTunnelStatus{{ID: tun[0].ID, Slot: 1, Status: "up"}}, BGP: &RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]RuntimeBGPPeerStatus{{Slot: 1, State: "established"}}, Routes: []RuntimeBGPRoute{}}}
	if !validBGPStatus(m, r) {
		t.Fatal("standby status rejected")
	}
	r.BGP.Routes = []RuntimeBGPRoute{{Prefix: c.RemotePrefixes[0], Slot: 2}}
	if validBGPStatus(m, r) {
		t.Fatal("inactive slot route accepted")
	}
	r.BGP.Routes = []RuntimeBGPRoute{}
	r.BGP.Peers[1] = RuntimeBGPPeerStatus{Slot: 2, State: "idle"}
	if validBGPStatus(m, r) {
		t.Fatal("fabricated inactive peer accepted")
	}
}
