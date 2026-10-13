package ipsec

import "net/netip"

const GCPHAProfile = "gcp-ha-bgp-ipv4-v1"
const GCPClassicProfile = "gcp-classic-static-ipv4-v1"

// ValidateProviderConfig retains implicit AWS profiles for existing callers.
// Validation never attests cloud provisioning or grants packet authority.
func ValidateProviderConfig(c StaticConfig) error {
	if isAzureProfile(c.ProfileID) {
		return ValidateAzureConfig(c)
	}
	if c.Azure != nil {
		return configError("azure_not_applicable", "azure", 0)
	}
	if c.ProfileID == GCPHAProfile || c.ProfileID == GCPClassicProfile {
		return ValidateGCPConfig(c)
	}
	if c.ProfileID != "" && c.ProfileID != "aws-static-ipv4-v1" && c.ProfileID != "aws-bgp-ipv4-v1" {
		return configError("profile_unsupported", "profile_id", 0)
	}
	if c.ProfileID == "aws-static-ipv4-v1" && c.Mode != "ipv4-static" || c.ProfileID == "aws-bgp-ipv4-v1" && c.Mode != "ipv4-bgp" {
		return configError("mode_unsupported", "mode", 0)
	}
	return ValidateAWSConfig(c)
}

// ValidateGCPConfig covers the bounded IPv4 HA dual-interface BGP and Classic
// route-based static profiles. Google interface0/1 maps to stable slots1/2.
// Inside IPs and ASNs come from Cloud Router; AWS reservations are not inherited.
// Sources: Cloud Router configuring-bgp and Cloud VPN choosing-networks-routing.
func ValidateGCPConfig(c StaticConfig) error {
	ha := c.ProfileID == GCPHAProfile
	if !ha && c.ProfileID != GCPClassicProfile {
		return configError("profile_unsupported", "profile_id", 0)
	}
	count := 1
	if ha {
		count = 2
	}
	if ha && c.Mode != "ipv4-bgp" || !ha && (c.Mode != "ipv4-static" || c.BGP != nil) {
		return configError("mode_unsupported", "mode", 0)
	}
	routes, err := validateRoutedIPv4Pair(c.LocalPrefixes, c.RemotePrefixes)
	if err != nil {
		return err
	}
	if len(c.Tunnels) != count {
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
		// Reuse the envelope's structural safety boundary; provider limits are explicit.
		if !validPSK(t.PSK) || len(t.PSK) < 8 || len(t.PSK) > 64 {
			return configError("credential_invalid", "psk", slot)
		}
		if !ha {
			if t.InsideCIDR != "" || t.CustomerInsideAddress != "" || t.CloudInsideAddress != "" {
				return configError("inside_not_applicable", "inside_cidr", slot)
			}
			continue
		}
		p, ok := canonicalIPv4Prefix(t.InsideCIDR)
		if !ok || p.Bits() != 30 || !netip.MustParsePrefix("169.254.0.0/16").Contains(p.Addr()) {
			return configError("inside_prefix_invalid", "inside_cidr", slot)
		}
		if previousInside.IsValid() && p.Overlaps(previousInside) {
			return configError("inside_prefix_overlap", "inside_cidr", slot)
		}
		previousInside = p
		a, aOK := canonicalIPv4Address(t.CustomerInsideAddress)
		b, bOK := canonicalIPv4Address(t.CloudInsideAddress)
		first, second := p.Addr().Next(), p.Addr().Next().Next()
		if !aOK || (a != first && a != second) {
			return configError("inside_host_invalid", "customer_inside_address", slot)
		}
		if !bOK || (b != first && b != second) || a == b {
			return configError("inside_host_invalid", "cloud_inside_address", slot)
		}
	}
	if ha {
		if c.BGP == nil {
			return configError("bgp_required", "bgp", 0)
		}
		if !privateBGPASN(c.BGP.RemoteASN) {
			return configError("asn_invalid", "bgp.remote_asn", 0)
		}
		if err := validateBGPParameters(c.BGP); err != nil {
			return err
		}
	}
	return nil
}
func gcpOutside(raw, field string, slot int, routes []netip.Prefix) (netip.Addr, error) {
	a, ok := canonicalIPv4Address(raw)
	if !ok {
		return netip.Addr{}, configError("outside_invalid", field, slot)
	}
	for _, special := range staticSpecialIPv4 {
		if special.Contains(a) {
			return netip.Addr{}, configError("outside_special_use", field, slot)
		}
	}
	for _, route := range routes {
		if route.Contains(a) {
			return netip.Addr{}, configError("outside_route_overlap", field, slot)
		}
	}
	return a, nil
}

func isBGPProfile(profile string) bool {
	return profile == "aws-bgp-ipv4-v1" || profile == GCPHAProfile || azureBGP(profile)
}

func activeTunnelCount(profile string) int {
	if profile == GCPClassicProfile || azureStandby(profile) {
		return 1
	}
	return 2
}
func classicManifestCompatible(m RuntimeManifest, eligible bool) bool {
	return eligible && m.ProfileID == GCPClassicProfile && m.TransportVersion != nil && *m.TransportVersion == 1 && m.TunnelCount != nil && *m.TunnelCount == 1 && m.BGP == nil && m.BGPVersion == nil && m.RecoveryVersion == nil && m.Tunnels[1] == (RuntimeTunnel{}) && m.Tunnels[0].Slot == 1 && m.Tunnels[0].Selected && m.Tunnels[0].InsideCIDR == "" && m.Tunnels[0].CustomerInsideAddress == "" && m.Tunnels[0].CloudInsideAddress == ""
}
