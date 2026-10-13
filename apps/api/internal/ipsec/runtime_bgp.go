package ipsec

// runtimeBGPCompatible protects apply/material/lease authorization. Cleanup
// intentionally uses exact immutable lineage without requiring current capability.
func runtimeBGPCompatible(m RuntimeManifest, eligible bool) bool {
	if isAzureProfile(m.ProfileID) {
		return azureManifestCompatible(m, eligible || !azureBGP(m.ProfileID))
	}
	if m.ProfileID == GCPClassicProfile {
		return classicManifestCompatible(m, true)
	}
	if m.TransportVersion != nil || m.TunnelCount != nil {
		return false
	}
	if !isBGPProfile(m.ProfileID) {
		return m.ProfileID == "aws-static-ipv4-v1" && m.BGP == nil && m.BGPVersion == nil
	}
	version := 1
	if m.ProfileID == GCPHAProfile {
		version = 2
	}
	if !eligible || m.BGP == nil || m.BGPVersion == nil || *m.BGPVersion != version || m.RecoveryVersion != nil {
		return false
	}
	for _, t := range m.Tunnels {
		if t.Selected {
			return false
		}
	}
	return validateBGPParameters(m.BGP) == nil && (m.ProfileID != GCPHAProfile || privateBGPASN(m.BGP.RemoteASN))
}
