package fqdnresources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
)

func recordsJSON(records []ResolverStaticRecord) []byte {
	if records == nil {
		records = []ResolverStaticRecord{}
	}
	data, _ := json.Marshal(records)
	return data
}
func listenerJSON(listener *ResolverLANListener) any {
	if listener == nil {
		return nil
	}
	data, _ := json.Marshal(listener)
	return data
}

func validateStaticRecords(records []ResolverStaticRecord, suffixes []string) error {
	bad := func(message string) error { return apierr.BadRequest("invalid_static_dns_record", message) }
	if len(records) > 128 {
		return bad("a profile may contain at most 128 static records")
	}
	addressCounts := map[string]int{}
	names, aliases, seen, rrTTL := map[string]bool{}, map[string]string{}, map[string]bool{}, map[string]int{}
	for i := range records {
		r := &records[i]
		name, err := fqdn.Normalize(strings.TrimSpace(r.Name))
		if err != nil {
			return bad("record names must be exact hostnames without wildcards")
		}
		owned := false
		for _, suffix := range suffixes {
			if name == suffix || strings.HasSuffix(name, "."+suffix) {
				owned = true
			}
		}
		if !owned {
			return bad("record names must belong to a DNS zone in this profile")
		}
		r.Name, r.Type, r.Value = name, strings.ToUpper(strings.TrimSpace(r.Type)), strings.TrimSpace(r.Value)
		if r.TTL == 0 {
			r.TTL = 300
		}
		if r.TTL < 30 || r.TTL > 86400 {
			return bad("record TTL must be between 30 and 86400 seconds")
		}
		switch r.Type {
		case "A", "AAAA":
			address, err := netip.ParseAddr(r.Value)
			if err != nil || !address.IsPrivate() || address.Is4In6() || (r.Type == "A" && !address.Is4()) || (r.Type == "AAAA" && !address.Is6()) {
				return bad("A records require private IPv4 addresses; AAAA records require private IPv6 addresses")
			}
			r.Value = address.String()
			names[name] = true
			addressCounts[name]++
			if addressCounts[name] > 32 {
				return bad("each hostname may contain at most 32 A and AAAA addresses")
			}
		case "CNAME":
			target, err := fqdn.Normalize(r.Value)
			if err != nil {
				return bad("CNAME targets must be hostnames, not IP addresses")
			}
			if _, exists := aliases[name]; exists {
				return bad("a hostname may have only one CNAME record")
			}
			r.Value, aliases[name] = target, target
		default:
			return bad("static records support A, AAAA, and CNAME only")
		}
		key := name + "|" + r.Type + "|" + r.Value
		if seen[key] {
			return bad("duplicate DNS records are not allowed")
		}
		seen[key] = true
		rrset := name + "|" + r.Type
		if ttl, exists := rrTTL[rrset]; exists && ttl != r.TTL {
			return bad("records in one DNS record set must use the same TTL")
		}
		rrTTL[rrset] = r.TTL
	}
	for name := range aliases {
		if names[name] {
			return bad("a CNAME cannot coexist with A or AAAA records at the same hostname")
		}
		visited := map[string]bool{}
		for current := name; current != ""; current = aliases[current] {
			if visited[current] {
				return bad("CNAME chains must not contain cycles")
			}
			visited[current] = true
			if len(visited) > 9 {
				return bad("CNAME chains may contain at most 8 aliases")
			}
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	return nil
}

var dnsInterfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func validateLANListener(listener *ResolverLANListener) error {
	if listener == nil {
		return nil
	}
	bad := func() error {
		return apierr.BadRequest("invalid_dns_lan_listener", "LAN DNS requires a private IPv4 address, a valid network interface, and 1 to 32 private IPv4 source CIDRs")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(listener.Address))
	if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.Is4In6() || !dnsInterfaceName.MatchString(listener.Interface) || len(listener.AllowedSources) == 0 || len(listener.AllowedSources) > 32 {
		return bad()
	}
	listener.Address = addr.String()
	seen := map[string]bool{}
	for i, raw := range listener.AllowedSources {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() || prefix.Addr().BitLen() != addr.BitLen() {
			return bad()
		}
		// A private starting address alone is insufficient: reject a prefix that also spans public space.
		private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
		bounded := false
		for _, bound := range private {
			if bound.Addr().BitLen() == prefix.Addr().BitLen() && bound.Bits() <= prefix.Bits() && bound.Contains(prefix.Addr()) {
				bounded = true
			}
		}
		if !bounded || seen[prefix.String()] {
			return bad()
		}
		seen[prefix.String()] = true
		listener.AllowedSources[i] = prefix.String()
	}
	sort.Strings(listener.AllowedSources)
	if len(listener.DefaultUpstreams) > 3 {
		return apierr.BadRequest("invalid_dns_default_upstreams", "Other-domain DNS requires at most 3 distinct public IPv4 resolver addresses on UDP/TCP 53")
	}
	seen = map[string]bool{}
	for i, raw := range listener.DefaultUpstreams {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !fqdn.PublicResolverIPv4(ip) || ip == addr || seen[ip.String()] {
			return apierr.BadRequest("invalid_dns_default_upstreams", "Other-domain DNS requires distinct globally routable public IPv4 resolver addresses; private, reserved, local and empty addresses are not allowed")
		}
		seen[ip.String()] = true
		listener.DefaultUpstreams[i] = ip.String()
	}
	sort.Strings(listener.DefaultUpstreams)
	return nil
}

func validateLANListenerOwnership(ctx context.Context, tx pgx.Tx, org, site, gateway uuid.UUID, listener *ResolverLANListener) error {
	if listener == nil {
		return nil
	}
	values := append([]string{listener.Address}, listener.AllowedSources...)
	for _, value := range values {
		var approved bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM site_subnets ss JOIN sites s ON s.id=ss.site_id JOIN nodes n ON n.site_id=s.id AND n.org_id=s.org_id WHERE s.id=$1 AND s.org_id=$2 AND n.id=$3 AND n.status='active' AND n.revoked_at IS NULL AND ss.status='approved' AND $4::inet <<= ss.cidr)`, site, org, gateway, value).Scan(&approved)
		if err != nil {
			return err
		}
		if !approved {
			return apierr.Conflict("dns_lan_listener_unapproved", "LAN DNS address and client sources must be within approved subnets of the selected Site/Gateway")
		}
	}
	return nil
}

// Refuse unsupported authority before retiring a working profile. The fresh
// authenticated capability report proves this exact gateway understands the
// versioned static records and listener fields; normal upstream profiles retain
// their existing compatibility boundary.
func validateManagedDNSCapability(ctx context.Context, tx pgx.Tx, org, site, gateway uuid.UUID, minimumVersion int) error {
	var supported bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(status='active' AND revoked_at IS NULL AND cert_serial<>''
 AND policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()
 AND CASE WHEN jsonb_typeof(capabilities->'max_policy_version')='number'
 THEN (capabilities->>'max_policy_version')::numeric >= $4 ELSE false END,false)
 FROM nodes WHERE id=$1 AND org_id=$2 AND site_id=$3 FOR SHARE`, gateway, org, site, minimumVersion).Scan(&supported)
	if err == pgx.ErrNoRows || (err == nil && !supported) {
		return apierr.Conflict("managed_dns_gateway_upgrade_required", fmt.Sprintf("This DNS configuration requires an active gateway reporting policy version %d or newer within the last 90 seconds; upgrade the gateway and wait for a current report before activating this profile", minimumVersion))
	}
	return err
}

func validateLANDefaultContexts(profiles []ResolverProfile) error {
	defaults := map[string][]string{}
	privateEndpoints := map[string]bool{}
	for _, profile := range profiles {
		if len(profile.StaticRecords) > 0 {
			continue // Static endpoints complete configured aliases, not private-zone authority.
		}
		for _, endpoint := range profile.Endpoints {
			privateEndpoints[endpoint.Address] = true
		}
	}
	for _, profile := range profiles {
		if len(profile.StaticRecords) > 0 {
			for _, endpoint := range profile.Endpoints {
				if privateEndpoints[endpoint.Address] {
					return apierr.BadRequest("invalid_static_dns_endpoints", "A CNAME target resolver cannot also be a private-zone resolver endpoint")
				}
			}
		}
		listener := profile.LANListener
		if listener == nil || len(listener.DefaultUpstreams) == 0 {
			continue
		}
		key := listener.Address + "%" + listener.Interface
		if previous, exists := defaults[key]; exists && !slices.Equal(previous, listener.DefaultUpstreams) {
			return apierr.BadRequest("conflicting_dns_default_upstreams", "Profiles sharing a LAN DNS address and interface must use the same public default upstreams when enabled")
		}
		for _, upstream := range listener.DefaultUpstreams {
			if privateEndpoints[upstream] {
				return apierr.BadRequest("invalid_dns_default_upstreams", "A public default upstream cannot also be a private-zone resolver endpoint")
			}
		}
		defaults[key] = listener.DefaultUpstreams
	}
	return nil
}

// Static endpoints are optional, explicit transports for completing only configured CNAME targets.
func validateStaticEndpoints(endpoints []ResolverEndpoint) error {
	if len(endpoints) > 3 {
		return apierr.BadRequest("invalid_static_dns_endpoints", "CNAME completion requires at most 3 distinct public IPv4 resolvers on UDP/TCP 53")
	}
	seen := map[string]bool{}
	for i := range endpoints {
		endpoint := &endpoints[i]
		ip, err := netip.ParseAddr(strings.TrimSpace(endpoint.Address))
		if err != nil || !fqdn.PublicResolverIPv4(ip) || seen[ip.String()] || (endpoint.Port != 0 && endpoint.Port != 53) || (endpoint.Transport != "udp" && endpoint.Transport != "tcp") {
			return apierr.BadRequest("invalid_static_dns_endpoints", "CNAME target resolvers must be distinct public IPv4 addresses on UDP/TCP 53; private, reserved and local addresses are not allowed")
		}
		endpoint.Address, endpoint.Port = ip.String(), 53
		seen[ip.String()] = true
	}
	return nil
}

// A public address may still be locally routed in this Site. Do not create a resolver loop.
func validateStaticEndpointOwnership(ctx context.Context, tx pgx.Tx, org, site, gateway uuid.UUID, profile ResolverProfile) error {
	if len(profile.StaticRecords) == 0 {
		return nil
	}
	for _, endpoint := range profile.Endpoints {
		var local bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM site_subnets ss JOIN sites s ON s.id=ss.site_id WHERE s.id=$1 AND s.org_id=$2 AND ss.status='approved' AND $3::inet <<= ss.cidr)
   OR EXISTS(SELECT 1 FROM nodes n WHERE n.id=$4 AND n.org_id=$2 AND split_part(n.endpoint,':',1)=host($3::inet))`, site, org, endpoint.Address, gateway).Scan(&local)
		if err != nil {
			return err
		}
		if local {
			return apierr.BadRequest("invalid_static_dns_endpoints", "A CNAME target resolver cannot be a gateway address or an approved local Site subnet address")
		}
	}
	return nil
}
