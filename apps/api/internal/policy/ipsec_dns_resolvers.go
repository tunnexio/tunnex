package policy

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"net/netip"
	"sort"
)

type IPsecDNSProfile struct {
	Profile            policyspec.DNSResolverProfile
	LocalPrefixes      []string
	TransportAvailable bool
}

func DecodeIPsecDNSProfile(row sqlc.ListIPsecDNSResolverProfilesRow) (IPsecDNSProfile, error) {
	var out IPsecDNSProfile
	out.TransportAvailable = row.TransportAvailable
	if err := json.Unmarshal(row.Profile, &out.Profile); err != nil {
		return out, err
	}
	if err := json.Unmarshal(row.LocalPrefixes, &out.LocalPrefixes); err != nil {
		return out, err
	}
	p := out.Profile
	if _, err := uuid.Parse(p.ContextConfigID); err != nil {
		return out, err
	}
	if _, err := uuid.Parse(p.ProfileID); err != nil {
		return out, err
	}
	if p.ContextConfigVersion < 1 || len(p.ZoneSuffixes) == 0 {
		return out, fmt.Errorf("invalid DNS profile identity")
	}
	if len(p.StaticRecords) > 0 {
		if len(p.StaticRecords) > 128 || len(p.Endpoints) > 3 || p.IPsecPath != (policyspec.DNSResolverIPsecPath{}) {
			return out, fmt.Errorf("invalid static DNS profile")
		}
		seen := map[string]bool{}
		for _, endpoint := range p.Endpoints {
			ip, err := netip.ParseAddr(endpoint.Address)
			if err != nil || !fqdn.PublicResolverIPv4(ip) || ip.String() != endpoint.Address || endpoint.Port != 53 || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") || seen[endpoint.Address] {
				return out, fmt.Errorf("invalid static DNS target resolver")
			}
			seen[endpoint.Address] = true
		}
		return out, nil
	}
	if _, err := uuid.Parse(p.IPsecPath.ConnectionID); err != nil {
		return out, err
	}
	source, err := netip.ParseAddr(p.IPsecPath.SourceAddress)
	if err != nil || !source.Is4() || p.ContextConfigVersion < 1 || p.IPsecPath.ConfigurationRevision < 1 || len(p.ZoneSuffixes) == 0 || len(p.Endpoints) == 0 {
		return out, fmt.Errorf("invalid configured IPsec DNS profile")
	}
	for _, e := range p.Endpoints {
		address, err := netip.ParseAddr(e.Address)
		if err != nil || !address.Is4() || e.Port != 53 || (e.Transport != "udp" && e.Transport != "tcp") {
			return out, fmt.Errorf("invalid configured IPsec DNS endpoint")
		}
	}
	return out, nil
}
func DNSProfileForAllowedTraffic(declared IPsecDNSProfile, allows []policyspec.AllowEntry, gatewayDNSAddresses ...string) policyspec.DNSResolverProfile {
	p := declared.Profile
	p.AllowedSources = []string{}
	endpoints := p.Endpoints
	// A gateway-local DNS permission authorizes the proxy itself for either
	// transport. Upstream IPsec host authority remains separately path-bound.
	if len(gatewayDNSAddresses) > 0 {
		gatewayProfile := declared
		gatewayProfile.Profile.Endpoints = nil
		for _, address := range gatewayDNSAddresses {
			if parsed, err := netip.ParseAddr(address); err == nil && parsed.Is4() {
				gatewayProfile.Profile.Endpoints = append(gatewayProfile.Profile.Endpoints, policyspec.DNSResolverEndpoint{Address: parsed.String(), Port: 53, Transport: "udp"})
			}
		}
		gatewayProfile.Profile.StaticRecords = nil
		if len(gatewayProfile.Profile.Endpoints) > 0 {
			p.AllowedSources = DNSProfileForAllowedTraffic(gatewayProfile, allows).AllowedSources
		}
	}
	gatewaySources := append([]string(nil), p.AllowedSources...)
	if len(p.StaticRecords) > 0 {
		endpoints = nil
		for _, address := range gatewayDNSAddresses {
			if parsed, err := netip.ParseAddr(address); err == nil {
				endpoints = append(endpoints, policyspec.DNSResolverEndpoint{Address: parsed.String(), Port: 53, Transport: "udp"})
			}
		}
		if len(endpoints) == 0 {
			return p
		}
	}
	candidates := map[string]bool{}
	for _, allow := range allows {
		source, ok := runtimePolicyPrefix(allow.SrcIP)
		// Proxy clients stay on the WireGuard side; only the separately bound upstream source crosses IPsec.
		if ok && !allow.FQDNManaged {
			candidates[source.String()] = true
		}
	}
	for source := range candidates {
		authorized := true
		for _, endpoint := range endpoints {
			address, _ := netip.ParseAddr(endpoint.Address)
			for _, protocol := range []policyspec.Protocol{"udp", "tcp"} {
				found := false
				for _, allow := range allows {
					candidate, ok := runtimePolicyPrefix(allow.SrcIP)
					if !ok || candidate.String() != source || allow.FQDNManaged {
						continue
					}
					dst, ok := runtimePolicyPrefix(allow.DstCIDR)
					if !ok || !dst.Contains(address) {
						continue
					}
					if allow.Protocol == "any" || (allow.Protocol == protocol && (allow.PortLow == 0 || (allow.PortLow <= 53 && allow.PortHigh >= 53))) {
						found = true
						break
					}
				}
				if !found {
					authorized = false
					break
				}
			}
			if !authorized {
				break
			}
		}
		if authorized {
			p.AllowedSources = append(p.AllowedSources, source)
		}
	}
	seen := map[string]bool{}
	for _, source := range append(p.AllowedSources, gatewaySources...) {
		seen[source] = true
	}
	p.AllowedSources = p.AllowedSources[:0]
	for source := range seen {
		p.AllowedSources = append(p.AllowedSources, source)
	}
	sort.Strings(p.AllowedSources)
	return p
}

func attachRuntimeDNSProfiles(policy *ipsec.RuntimePolicy, profiles []IPsecDNSProfile, input ipsec.RuntimePolicyInput, allow []policyspec.AllowEntry) error {
	for _, declared := range profiles {
		p := declared.Profile
		if p.IPsecPath.ConnectionID != input.ConnectionID.String() || !declared.TransportAvailable {
			continue
		}
		policy.DNSResolverProfiles = append(policy.DNSResolverProfiles, DNSProfileForAllowedTraffic(declared, allow))
		seen := map[string]bool{}
		for _, endpoint := range p.Endpoints {
			if seen[endpoint.Address] {
				continue
			}
			seen[endpoint.Address] = true
			policy.DNSResolverGrants = append(policy.DNSResolverGrants, ipsec.RuntimeDNSResolverGrant{ContextConfigID: p.ContextConfigID, ContextConfigVersion: p.ContextConfigVersion, ProfileID: p.ProfileID, ConnectionID: p.IPsecPath.ConnectionID, ConfigurationRevision: p.IPsecPath.ConfigurationRevision, SourceAddress: p.IPsecPath.SourceAddress, ResolverAddress: endpoint.Address})
		}
	}
	if len(policy.Grants)+len(policy.FQDNGrants)+len(policy.DesktopGrants)+2*len(policy.DNSResolverGrants) > 128 {
		return ipsec.ErrConnectionIneligible
	}
	sort.Slice(policy.DNSResolverGrants, func(a, b int) bool {
		x, _ := json.Marshal(policy.DNSResolverGrants[a])
		y, _ := json.Marshal(policy.DNSResolverGrants[b])
		return string(x) < string(y)
	})
	sort.Slice(policy.DNSResolverProfiles, func(a, b int) bool {
		return policy.DNSResolverProfiles[a].ProfileID < policy.DNSResolverProfiles[b].ProfileID
	})
	return nil
}
