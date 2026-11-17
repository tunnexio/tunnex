package ipsec

// DesktopProfileSupported gates ephemeral desktop authority independently of
// LAN selectors. Static support is opt-in evidence from upgraded gateways;
// BGP retains the existing v1 contract. Other providers remain unqualified.
func DesktopProfileSupported(in RuntimePolicyInput) bool {
	if in.DesktopTransitVersion != 1 {
		return false
	}
	switch in.Config.ProfileID {
	case "aws-bgp-ipv4-v1":
		return in.Config.BGP != nil
	case "aws-static-ipv4-v1":
		return in.Config.BGP == nil && in.DesktopStaticVersion == 2
	default:
		return false
	}
}

// The transport marker is immutable intent, independent of mutable grants.
// Legacy narrow deliveries keep their digest and LAN authority; only a fresh
// qualified delivery may authorize route-based selectors for desktop sources.
func runtimeDesktopStaticCompatible(m RuntimeManifest, capable bool) bool {
	if m.DesktopStaticVersion == nil {
		return true
	}
	return capable && *m.DesktopStaticVersion == 1 && m.ProfileID == "aws-static-ipv4-v1" && m.BGP == nil && m.BGPVersion == nil && m.TransportVersion == nil && m.TunnelCount == nil && m.RecoveryVersion != nil && *m.RecoveryVersion == 1
}
