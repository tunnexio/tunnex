package ipsec

import (
	"encoding/json"
	"net/netip"
)

// Only exact shared or disjoint canonical prefixes can change between owners.
func azureRecreationDomains(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, set := range [][]string{a, b} {
		seen := map[string]bool{}
		for _, raw := range set {
			p, e := netip.ParsePrefix(raw)
			if e != nil || !p.Addr().Is4() || p.String() != raw || p != p.Masked() || seen[raw] {
				return false
			}
			seen[raw] = true
		}
	}
	shared := false
	for _, x := range a {
		p, e := netip.ParsePrefix(x)
		if e != nil || p.String() != x || p != p.Masked() {
			return false
		}
		for _, y := range b {
			q, e := netip.ParsePrefix(y)
			if e != nil || q.String() != y || q != q.Masked() {
				return false
			}
			if p == q {
				shared = true
			} else if p.Overlaps(q) {
				return false
			}
		}
	}
	return shared
}
func azureRecreationManifestContract(a, b RuntimeManifest) bool {
	if a.ProfileID != AzureActiveActiveBGPProfile || !azureManifestCompatible(a, true) || !azureManifestCompatible(b, true) || b.ProfileID != a.ProfileID || a.BGP == nil || b.BGP == nil || a.BGPVersion == nil || b.BGPVersion == nil || *a.BGPVersion != 3 || *b.BGPVersion != 3 || a.CustomerOutsideAddress != b.CustomerOutsideAddress || !equalPrefixDomains(a.LocalPrefixes, b.LocalPrefixes) || !azureRecreationDomains(a.RemotePrefixes, b.RemotePrefixes) {
		return false
	}
	if a.BGP.LocalASN != b.BGP.LocalASN || a.BGP.RemoteASN != b.BGP.RemoteASN || a.BGP.RouterID != b.BGP.RouterID {
		return false
	}
	for i, x := range a.Tunnels {
		y := b.Tunnels[i]
		if x.Slot != i+1 || y.Slot != i+1 || x.OutsideAddress != y.OutsideAddress || x.InsideCIDR != y.InsideCIDR || x.CustomerInsideAddress != y.CustomerInsideAddress || x.CloudInsideAddress != y.CloudInsideAddress {
			return false
		}
	}
	return true
}
func azureRecreationConfigManifest(c StaticConfig) RuntimeManifest {
	v := 3
	m := RuntimeManifest{ProfileID: c.ProfileID, BGP: c.BGP, BGPVersion: &v, CustomerOutsideAddress: c.CustomerOutsideAddress, LocalPrefixes: c.LocalPrefixes, RemotePrefixes: c.RemotePrefixes}
	for i, t := range c.Tunnels {
		if i >= 2 {
			break
		}
		m.Tunnels[i] = RuntimeTunnel{Slot: i + 1, OutsideAddress: t.OutsideAddress, InsideCIDR: t.InsideCIDR, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress}
	}
	return m
}
func azureBGPRecreationCapability(raw []byte) bool {
	var f map[string]json.RawMessage
	return retainedGuardCapability(raw) && json.Unmarshal(raw, &f) == nil && string(f["ipsec_azure_version"]) == "1" && string(f["ipsec_bgp_version"]) == "1" && string(f["ipsec_azure_bgp_recreation_version"]) == "1"
}
func (l runtimeLocked) recreationEligible(m RuntimeManifest) bool {
	if len(m.RetainedGuardPredecessors) == 0 {
		return m.AzureBGPRecreationVersion == nil && m.AzureProfileRecreationVersion == nil
	}
	if m.AzureProfileRecreationVersion != nil {
		return isAzureProfile(m.ProfileID) && *m.AzureProfileRecreationVersion == 1 && m.AzureBGPRecreationVersion == nil && l.retainedGuardEligible && l.azureProfileRecreationEligible
	}
	if m.ProfileID == AzureActiveActiveBGPProfile {
		return m.AzureBGPRecreationVersion != nil && *m.AzureBGPRecreationVersion == 1 && l.retainedGuardEligible && l.azureBGPRecreationEligible
	}
	return m.AzureBGPRecreationVersion == nil && l.retainedGuardEligible
}
