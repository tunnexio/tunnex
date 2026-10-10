package policy

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
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
func DNSProfileForAllowedTraffic(declared IPsecDNSProfile, allows []policyspec.AllowEntry) policyspec.DNSResolverProfile {
	p := declared.Profile
	p.AllowedSources = []string{}
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
		for _, endpoint := range p.Endpoints {
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
	if len(policy.Grants)+2*len(policy.DNSResolverGrants) > 128 {
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
