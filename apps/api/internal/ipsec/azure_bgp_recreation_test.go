package ipsec

import (
	"encoding/json"
	"testing"
)

func TestAzureRecreationDomains(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want bool
	}{{[]string{"10.231.0.0/16"}, []string{"10.231.0.0/16", "10.235.77.0/24"}, true}, {[]string{"10.231.0.0/16", "10.235.77.0/24"}, []string{"10.231.0.0/16"}, true}, {[]string{"10.231.0.0/16"}, []string{"10.231.0.0/16", "10.231.1.0/24"}, false}, {[]string{"10.231.0.0/16"}, []string{"10.235.77.0/24"}, false}, {[]string{"10.231.1.1/24"}, []string{"10.231.1.1/24"}, false}} {
		if azureRecreationDomains(c.a, c.b) != c.want {
			t.Fatal(c)
		}
	}
}
func TestAzureRecreationManifestContract(t *testing.T) {
	v := 3
	a := RuntimeManifest{ProfileID: AzureActiveActiveBGPProfile, BGPVersion: &v, BGP: &BGPConfig{LocalASN: 64512, RemoteASN: 65515, RouterID: "10.1.1.1", MaximumPrefixes: 8}, LocalPrefixes: []string{"10.233.10.0/24"}, RemotePrefixes: []string{"10.231.0.0/16"}}
	for i := range a.Tunnels {
		a.Tunnels[i] = RuntimeTunnel{Slot: i + 1, OutsideAddress: "1.1.1.1", InsideCIDR: "169.254.10.1/32", CustomerInsideAddress: "169.254.10.1", CloudInsideAddress: "169.254.21.2"}
	}
	clone := func() RuntimeManifest {
		raw, _ := json.Marshal(a)
		var b RuntimeManifest
		json.Unmarshal(raw, &b)
		return b
	}
	b := clone()
	b.BGP.MaximumPrefixes = 1
	b.RemotePrefixes = append(b.RemotePrefixes, "10.235.77.0/24")
	if !azureRecreationManifestContract(a, b) {
		t.Fatal("expansion")
	}
	for _, change := range []func(*RuntimeManifest){func(b *RuntimeManifest) { b.BGP.LocalASN++ }, func(b *RuntimeManifest) { b.BGP.RemoteASN++ }, func(b *RuntimeManifest) { b.BGP.RouterID = "10.1.1.2" }, func(b *RuntimeManifest) { b.Tunnels[0].OutsideAddress = "1.1.1.2" }, func(b *RuntimeManifest) { b.Tunnels[1].CloudInsideAddress = "169.254.22.3" }, func(b *RuntimeManifest) { b.Tunnels[0].Slot = 2 }, func(b *RuntimeManifest) { b.ProfileID = AzureActiveStandbyBGPProfile }} {
		b := clone()
		change(&b)
		if azureRecreationManifestContract(a, b) {
			t.Fatal("changed contract accepted")
		}
	}
}

func TestAzureRecreationCapabilityAndVersion(t *testing.T) {
	good := `{"ipsec_config_version":1,"ipsec_retained_guard_version":1,"ipsec_azure_version":1,"ipsec_bgp_version":1,"ipsec_azure_bgp_recreation_version":1}`
	if !azureBGPRecreationCapability([]byte(good)) {
		t.Fatal("qualified")
	}
	for _, raw := range []string{`{}`, `{"ipsec_azure_bgp_recreation_version":1}`, `{"ipsec_config_version":1,"ipsec_retained_guard_version":1,"ipsec_azure_version":1,"ipsec_bgp_version":1,"ipsec_azure_bgp_recreation_version":"1"}`} {
		if azureBGPRecreationCapability([]byte(raw)) {
			t.Fatal("unsupported capability")
		}
	}
	l := runtimeLocked{retainedGuardEligible: true, azureBGPRecreationEligible: true}
	m := RuntimeManifest{ProfileID: AzureActiveActiveBGPProfile, RetainedGuardPredecessors: []RuntimeRetainedGuardPredecessor{{}}}
	if l.recreationEligible(m) {
		t.Fatal("missing explicit version")
	}
	v := 1
	m.AzureBGPRecreationVersion = &v
	if !l.recreationEligible(m) {
		t.Fatal("explicit version")
	}
	v = 2
	if l.recreationEligible(m) {
		t.Fatal("future version")
	}
	v = 1
	m.RetainedGuardPredecessors = nil
	if l.recreationEligible(m) {
		t.Fatal("unsolicited version")
	}
}
