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
		return in.Config.BGP == nil && in.DesktopStaticVersion == 1
	default:
		return false
	}
}
