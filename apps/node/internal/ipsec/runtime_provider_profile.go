package ipsec

// GCPHABGPProfile reuses the common two-session IPv4 engine. Its versioned
// delivery is refused by legacy nodes. A single peer host is not host HA.
const GCPHABGPProfile = "gcp-ha-bgp-ipv4-v1"
const GCPClassicStaticProfile = "gcp-classic-static-ipv4-v1"

// Empty metadata is the unchanged legacy AWS journal representation. Classic
// is intentionally refused until a versioned one-tunnel lifecycle exists.
func validRuntimeProviderProfile(profile string) bool {
	return profile == "" || profile == GCPHABGPProfile
}
func runtimeProfileMTU(profile string) uint32 {
	if profile == GCPHABGPProfile {
		return 1382
	}
	if profile == "" {
		return AWSIPv4TunnelMTU
	}
	return 0
}

// Google documents1460 outer/1390 CBC-SHA256 inner IPv4, minus8 for NAT-T.
// Always budget NAT-T; observed smaller underlays lower the common ceiling.
// https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/mtu-considerations
func runtimeProfileInnerMTU(profile string, outer uint32) (uint32, bool) {
	if !validRuntimeProviderProfile(profile) {
		return 0, false
	}
	if profile == GCPHABGPProfile && outer > 1460 {
		outer = 1460
	}
	value, ok := awsIPv4InnerMTU(outer)
	if !ok {
		return 0, false
	}
	if ceiling := runtimeProfileMTU(profile); value > ceiling {
		value = ceiling
	}
	return value, true
}
func validGCPBGPConfig(b BGPConfig) bool {
	private := func(a uint32) bool { return a >= 64512 && a <= 65534 || a >= 4200000000 && a <= 4294967294 }
	return validBGPConfig(b) && private(b.RemoteASN)
}

// Google IKEv2 lifetimes36000/10800; initiate rekey ahead of expiry.
// https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/supported-ike-ciphers
func runtimeChildLifetime(profile string) string {
	if profile == GCPHABGPProfile {
		return "10800s"
	}
	return "3600s"
}
func runtimeChildRekey(profile string) string {
	if profile == GCPHABGPProfile {
		return "9000s"
	}
	return "3000s"
}
func runtimeIKERekey(profile string) string {
	if profile == GCPHABGPProfile {
		return "32400s"
	}
	return "28800s"
}

// GCPHACapability reuses native host qualification. Per-connection GCP evidence
// and authority are mandatory independently; this is never a tunnel UP status.
func (c *RuntimeController) GCPHACapability() int {
	if c == nil {
		return 0
	}
	return c.BGPCapability()
}
