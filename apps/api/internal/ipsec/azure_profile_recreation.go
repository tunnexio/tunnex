package ipsec

import "encoding/json"

// Profile transitions preserve each predecessor's own immutable transport tuple.
// SKU is deliberately not reconstructed: it was not retained in old manifests.
func azureProfileRecreationContract(a, b RuntimeManifest) bool {
	if !azureManifestCompatible(a, true) || !azureManifestCompatible(b, true) || a.CustomerOutsideAddress != b.CustomerOutsideAddress || !equalPrefixDomains(a.LocalPrefixes, b.LocalPrefixes) || !azureRecreationDomains(a.RemotePrefixes, b.RemotePrefixes) {
		return false
	}
	n := activeTunnelCount(a.ProfileID)
	if k := activeTunnelCount(b.ProfileID); k < n {
		n = k
	}
	for i := 0; i < n; i++ {
		x, y := a.Tunnels[i], b.Tunnels[i]
		if x.Slot != i+1 || y.Slot != i+1 || x.OutsideAddress != y.OutsideAddress {
			return false
		}
		if azureBGP(a.ProfileID) == azureBGP(b.ProfileID) && (x.InsideCIDR != y.InsideCIDR || x.CustomerInsideAddress != y.CustomerInsideAddress || x.CloudInsideAddress != y.CloudInsideAddress) {
			return false
		}
	}
	if a.BGP != nil && b.BGP != nil && (a.BGP.LocalASN != b.BGP.LocalASN || a.BGP.RemoteASN != b.BGP.RemoteASN || a.BGP.RouterID != b.BGP.RouterID) {
		return false
	}
	return true
}
func azureProfileConfigManifest(c StaticConfig) RuntimeManifest {
	var tunnels [2]RuntimeTunnel
	for i, t := range c.Tunnels {
		if i >= 2 {
			break
		}
		tunnels[i] = RuntimeTunnel{Slot: i + 1, OutsideAddress: t.OutsideAddress, InsideCIDR: t.InsideCIDR, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress}
	}
	return runtimeManifest(Connection{}, c, tunnels)
}
func azureProfileRecreationCapability(raw []byte) bool {
	var f map[string]json.RawMessage
	return retainedGuardCapability(raw) && json.Unmarshal(raw, &f) == nil && string(f["ipsec_azure_version"]) == "1" && string(f["ipsec_bgp_version"]) == "1" && string(f["ipsec_azure_profile_recreation_version"]) == "1"
}
