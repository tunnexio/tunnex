package ipsec

// runtimeBGPCompatible protects apply/material/lease authorization. Cleanup
// intentionally uses exact immutable lineage without requiring current capability.
func runtimeBGPCompatible(m RuntimeManifest, eligible bool) bool {
	if m.ProfileID != "aws-bgp-ipv4-v1" {
		return m.ProfileID == "aws-static-ipv4-v1" && m.BGP == nil && m.BGPVersion == nil
	}
	if !eligible || m.BGP == nil || m.BGPVersion == nil || *m.BGPVersion != 1 || m.RecoveryVersion != nil {
		return false
	}
	for _, t := range m.Tunnels {
		if t.Selected {
			return false
		}
	}
	return validateBGPParameters(m.BGP) == nil
}
