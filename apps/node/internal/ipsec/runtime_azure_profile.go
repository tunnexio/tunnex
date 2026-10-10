package ipsec

import "net/netip"

const AzureActiveActiveBGPProfile = "azure-active-active-bgp-ipv4-v1"
const AzureActiveActiveStaticProfile = "azure-active-active-static-ipv4-v1"
const AzureActiveStandbyBGPProfile = "azure-active-standby-bgp-ipv4-v1"
const AzureActiveStandbyStaticProfile = "azure-active-standby-static-ipv4-v1"

func IsAzureRuntimeProfile(p string) bool {
	return p == AzureActiveActiveBGPProfile || p == AzureActiveActiveStaticProfile || p == AzureActiveStandbyBGPProfile || p == AzureActiveStandbyStaticProfile
}
func IsAzureBGPProfile(p string) bool {
	return p == AzureActiveActiveBGPProfile || p == AzureActiveStandbyBGPProfile
}
func IsSingleTunnelProfile(p string) bool {
	return p == GCPClassicStaticProfile || p == AzureActiveStandbyBGPProfile || p == AzureActiveStandbyStaticProfile
}

// Azure's APIPA peers are explicitly configured, never inferred from public IPs.
// One Azure connection shares the on-premises /32 update source across both
// instances; each cloud APIPA /32 is routed over its independently owned XFRM
// interface. Azure's cloud address stays in its documented custom APIPA range.
func validAzurePeer(a netip.Addr) bool {
	return a.Is4() && (netip.MustParsePrefix("169.254.21.0/24").Contains(a) || netip.MustParsePrefix("169.254.22.0/24").Contains(a))
}
func azureReservedASN(a uint32) bool {
	return a == 8074 || a == 8075 || a == 12076 || a == 65515 || a >= 65517 && a <= 65520
}
func validAzureBGPConfig(b BGPConfig) bool {
	return validBGPConfig(b) && !azureReservedASN(b.LocalASN) && (b.RemoteASN == 65515 || !azureReservedASN(b.RemoteASN)) && b.RemoteASN != 7224
}

// Capability proves the native controller prerequisites, not Azure connectivity.
func (c *RuntimeController) AzureCapability() int {
	if c == nil {
		return 0
	}
	return c.BGPCapability()
}
