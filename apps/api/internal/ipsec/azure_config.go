package ipsec

import "net/netip"

const (
	AzureActiveActiveBGPProfile     = "azure-active-active-bgp-ipv4-v1"
	AzureActiveActiveStaticProfile  = "azure-active-active-static-ipv4-v1"
	AzureActiveStandbyBGPProfile    = "azure-active-standby-bgp-ipv4-v1"
	AzureActiveStandbyStaticProfile = "azure-active-standby-static-ipv4-v1"
)

func isAzureProfile(p string) bool {
	return p == AzureActiveActiveBGPProfile || p == AzureActiveActiveStaticProfile || p == AzureActiveStandbyBGPProfile || p == AzureActiveStandbyStaticProfile
}
func azureStandby(p string) bool {
	return p == AzureActiveStandbyBGPProfile || p == AzureActiveStandbyStaticProfile
}
func azureBGP(p string) bool {
	return p == AzureActiveActiveBGPProfile || p == AzureActiveStandbyBGPProfile
}

type AzureContract struct {
	GatewaySKU                     string `json:"gateway_sku"`
	VPNType                        string `json:"vpn_type"`
	IKEVersion                     int    `json:"ike_version"`
	CustomPolicy                   string `json:"custom_policy"`
	UsePolicyBasedTrafficSelectors bool   `json:"use_policy_based_traffic_selectors"`
	NATEnabled                     bool   `json:"nat_enabled"`
}

func validAzureContract(a *AzureContract) bool {
	if a == nil || a.VPNType != "RouteBased" || a.IKEVersion != 2 || a.CustomPolicy != "aes256-sha256-dh14-pfs2048" || a.UsePolicyBasedTrafficSelectors || a.NATEnabled {
		return false
	}
	switch a.GatewaySKU {
	case "VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ":
		return true
	}
	return false
}

// ValidateAzureConfig admits only route-based IKEv2 with a custom Azure policy
// matching AES256/SHA256/DHGroup14 and AES256/SHA256/PFS2048. Basic,
// policy-based, NAT and non-APIPA BGP contracts are outside this bounded profile.
// Static inside addresses are Tunnex interface allocations, not Azure assignments.
// https://learn.microsoft.com/en-us/azure/vpn-gateway/configure-bgp
// https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-ipsecikepolicy-rm-powershell
func ValidateAzureConfig(c StaticConfig) error {
	if !isAzureProfile(c.ProfileID) {
		return configError("profile_unsupported", "profile_id", 0)
	}
	if !validAzureContract(c.Azure) {
		return configError("azure_contract_unsupported", "azure", 0)
	}
	bgp := azureBGP(c.ProfileID)
	if bgp && c.Mode != "ipv4-bgp" || !bgp && (c.Mode != "ipv4-static" || c.BGP != nil) {
		return configError("mode_unsupported", "mode", 0)
	}
	routes, err := validateRoutedIPv4Pair(c.LocalPrefixes, c.RemotePrefixes)
	if err != nil {
		return err
	}
	if len(c.Tunnels) != activeTunnelCount(c.ProfileID) {
		return configError("tunnel_count", "tunnels", 0)
	}
	customer, err := gcpOutside(c.CustomerOutsideAddress, "customer_outside_address", 0, routes)
	if err != nil {
		return err
	}
	var previousOutside netip.Addr
	var previousInside netip.Prefix
	for i, t := range c.Tunnels {
		slot := i + 1
		outside, err := gcpOutside(t.OutsideAddress, "outside_address", slot, routes)
		if err != nil {
			return err
		}
		if outside == customer || outside == previousOutside {
			return configError("outside_duplicate", "outside_address", slot)
		}
		previousOutside = outside
		if !validPSK(t.PSK) || len(t.PSK) < 8 || len(t.PSK) > 64 {
			return configError("credential_invalid", "psk", slot)
		}

		if i > 0 && t.PSK != c.Tunnels[0].PSK {
			return configError("azure_connection_psk_mismatch", "psk", slot)
		}
		p, ok := canonicalIPv4Prefix(t.InsideCIDR)
		a, aOK := canonicalIPv4Address(t.CustomerInsideAddress)
		b, bOK := canonicalIPv4Address(t.CloudInsideAddress)
		if !ok || !awsInsideRange.Contains(p.Addr()) {
			return configError("inside_contract_unsupported", "inside_cidr", slot)
		}
		if bgp {
			if p.Bits() != 32 || !aOK || p.Addr() != a {
				return configError("inside_contract_unsupported", "customer_inside_address", slot)
			}
			if !bOK || a == b || !(netip.MustParsePrefix("169.254.21.0/24").Contains(b) || netip.MustParsePrefix("169.254.22.0/24").Contains(b)) {
				return configError("azure_apipa_invalid", "cloud_inside_address", slot)
			}
			if i > 0 && (t.CustomerInsideAddress != c.Tunnels[0].CustomerInsideAddress || t.InsideCIDR != c.Tunnels[0].InsideCIDR || t.CloudInsideAddress == c.Tunnels[0].CloudInsideAddress) {
				return configError("azure_connection_peer_mismatch", "customer_inside_address", slot)
			}
		} else {
			if p.Bits() != 30 {
				return configError("inside_contract_unsupported", "inside_cidr", slot)
			}
			if previousInside.IsValid() && p.Overlaps(previousInside) {
				return configError("inside_prefix_overlap", "inside_cidr", slot)
			}
			first, second := p.Addr().Next(), p.Addr().Next().Next()
			if !aOK || (a != first && a != second) {
				return configError("inside_host_invalid", "customer_inside_address", slot)
			}
			if !bOK || (b != first && b != second) || a == b {
				return configError("inside_host_invalid", "cloud_inside_address", slot)
			}
		}
		previousInside = p

	}
	if bgp {
		return validateAzureBGP(c.BGP)
	}
	return nil
}
func azureASN(a uint32, local bool) bool {
	if a == 0 || a == 23456 || a == 4294967295 || a >= 64496 && a <= 64511 || a >= 65535 && a <= 65551 {
		return false
	}
	if local || a != 65515 {
		switch a {
		case 8074, 8075, 12076, 65515, 65517, 65518, 65519, 65520:
			return false
		}
	}
	return true
}
func validateAzureBGP(b *BGPConfig) error {
	if b == nil {
		return configError("bgp_required", "bgp", 0)
	}
	if !azureASN(b.LocalASN, true) {
		return configError("asn_invalid", "bgp.local_asn", 0)
	}
	if !azureASN(b.RemoteASN, false) || b.LocalASN == b.RemoteASN {
		return configError("asn_invalid", "bgp.remote_asn", 0)
	}
	copy := *b
	copy.LocalASN = 65000
	copy.RemoteASN = 65001
	return validateBGPParameters(&copy)
}
func azureManifestCompatible(m RuntimeManifest, eligible bool) bool {
	if !isAzureProfile(m.ProfileID) || !eligible {
		return false
	}
	if azureStandby(m.ProfileID) {
		if m.TransportVersion == nil || *m.TransportVersion != 1 || m.TunnelCount == nil || *m.TunnelCount != 1 || m.Tunnels[1] != (RuntimeTunnel{}) {
			return false
		}
	} else if m.TransportVersion != nil || m.TunnelCount != nil {
		return false
	}
	if azureBGP(m.ProfileID) {
		return m.BGPVersion != nil && *m.BGPVersion == 3 && validateAzureBGP(m.BGP) == nil && m.RecoveryVersion == nil && !m.Tunnels[0].Selected && !m.Tunnels[1].Selected
	}
	return m.BGP == nil && m.BGPVersion == nil && (!azureStandby(m.ProfileID) || m.RecoveryVersion == nil)
}
