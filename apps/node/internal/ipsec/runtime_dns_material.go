package ipsec

import (
	"net/netip"

	"github.com/google/uuid"
)

// RuntimeDNSResolverGrant is authenticated resolver-only transport authority.
// UDP/TCP destination port 53 and /32 endpoints are implicit; callers cannot
// supply generic HostOrigin or arbitrary protocol/port authority.
type RuntimeDNSResolverGrant struct {
	ContextConfigID       uuid.UUID `json:"context_config_id"`
	ContextConfigVersion  int64     `json:"context_config_version"`
	ProfileID             uuid.UUID `json:"profile_id"`
	ConnectionID          uuid.UUID `json:"connection_id"`
	ConfigurationRevision int64     `json:"configuration_revision"`
	SourceAddress         string    `json:"source_address"`
	ResolverAddress       string    `json:"resolver_address"`
}

// DNSResolverBinding is comparable so it retains the renderer's exact
// duplicate checks. It travels only in fresh memory-only grants, not journals.
type DNSResolverBinding struct {
	ContextConfigID       uuid.UUID
	ContextConfigVersion  int64
	ProfileID             uuid.UUID
	ConnectionID          uuid.UUID
	ConfigurationRevision int64
}

func (b DNSResolverBinding) valid() bool {
	return b.ContextConfigID != uuid.Nil && b.ContextConfigVersion > 0 && b.ProfileID != uuid.Nil && b.ConnectionID != uuid.Nil && b.ConfigurationRevision > 0
}

func runtimeDNSGrants(material RuntimeMaterial, local, remote []netip.Prefix) ([]GuardGrant, error) {
	if len(material.Policy.DNSResolverGrants) > 64 || len(material.Policy.Grants)+2*len(material.Policy.DNSResolverGrants) > 128 {
		return nil, ErrRuntimeController
	}
	out := []GuardGrant{}
	seen := map[RuntimeDNSResolverGrant]bool{}
	for _, d := range material.Policy.DNSResolverGrants {
		b := DNSResolverBinding{d.ContextConfigID, d.ContextConfigVersion, d.ProfileID, d.ConnectionID, d.ConfigurationRevision}
		src, se := netip.ParseAddr(d.SourceAddress)
		dst, de := netip.ParseAddr(d.ResolverAddress)
		if !b.valid() || seen[d] || b.ConnectionID != material.Manifest.ConnectionID || b.ConfigurationRevision != material.Manifest.ConfigurationRevision || se != nil || de != nil || !src.Is4() || !dst.Is4() || src.String() != d.SourceAddress || dst.String() != d.ResolverAddress || src.IsLoopback() || dst.IsLoopback() || src.IsLinkLocalUnicast() || dst.IsLinkLocalUnicast() || src.IsUnspecified() || dst.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() {
			return nil, ErrRuntimeController
		}
		source, destination := netip.PrefixFrom(src, 32), netip.PrefixFrom(dst, 32)
		if !withinPrefixes(source, local) || !withinPrefixes(destination, remote) {
			return nil, ErrRuntimeController
		}
		seen[d] = true
		for _, protocol := range []GuardProtocol{GuardUDP, GuardTCP} {
			out = append(out, GuardGrant{Source: source, Destination: destination, Protocol: protocol, PortLow: 53, PortHigh: 53, HostOrigin: true, DNSResolver: b})
		}
	}
	return out, nil
}
