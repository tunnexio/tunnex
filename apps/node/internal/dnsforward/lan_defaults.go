package dnsforward

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// Explicit public IPv4 only. There is no discovery through the host resolver,
// LAN router, private resolver profile, or system search domains.
var reservedLANUpstreamRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func compileLANDefaultUpstreams(raw []string) ([]netip.Addr, string) {
	if len(raw) > 3 {
		return nil, "at most three public IPv4 upstreams are supported"
	}
	var out []netip.Addr
	for _, value := range raw {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || value != ip.String() {
			return nil, "upstreams must be canonical public IPv4 addresses"
		}
		for _, prefix := range reservedLANUpstreamRanges {
			if prefix.Contains(ip) {
				return nil, "upstreams must be public IPv4 addresses outside reserved ranges"
			}
		}
		if slices.Contains(out, ip) {
			return nil, "duplicate public DNS upstream"
		}
		out = append(out, ip)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out, ""
}

// Only opted-in profiles grant public forwarding, each to its own source set.
// Private-only siblings neither conflict nor expand that grant. A conflict
// disables defaults for the bind without weakening private suffix authority.
func (f *Forwarder) lanDefaults(profiles *resolverProfiles, scope lanBindKey) (upstreams []netip.Addr, sources []netip.Prefix, config fqdnrpc.ResolverConfig, failure string) {
	for _, p := range profiles.entries {
		if p.lan == nil || p.lan.key != scope {
			continue
		}
		if p.lan.defaultError != "" {
			return nil, nil, config, p.lan.defaultError
		}
		if len(p.lan.defaultUpstreams) == 0 {
			continue
		}
		if !p.valid {
			return nil, nil, config, "resolver profile is invalid"
		}
		if len(upstreams) == 0 {
			upstreams = p.lan.defaultUpstreams
			config = p.config
		} else if !slices.Equal(upstreams, p.lan.defaultUpstreams) {
			return nil, nil, config, "profiles sharing this listener have conflicting public upstreams"
		}
		sources = append(sources, p.lan.sources...)
	}
	if len(upstreams) == 0 {
		return
	}
	for _, p := range profiles.entries {
		if p.static != nil && p.config.IPsecPath == nil {
			continue // Static target endpoints are public resolvers, not private upstreams.
		}
		for _, endpoint := range p.config.Endpoints {
			if ip, err := netip.ParseAddr(endpoint.Address); err == nil && slices.Contains(upstreams, ip) {
				return nil, nil, config, "public upstream overlaps a private resolver endpoint"
			}
		}
	}
	addresses := f.lanLocalAddresses
	if addresses == nil {
		addresses = net.InterfaceAddrs
	}
	local, err := addresses()
	if err != nil {
		return nil, nil, config, "cannot verify public upstream is not a local address"
	}
	for _, address := range local {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return nil, nil, config, "cannot verify local interface address"
		}
		if slices.Contains(upstreams, prefix.Addr().Unmap()) {
			return nil, nil, config, "public upstream is a local interface address"
		}
	}
	return
}

// All private routing scopes are a barrier to default forwarding, including
// private scopes not exposed to this LAN source or unavailable at this bind.
func (f *Forwarder) privateDNSName(name string, profiles *resolverProfiles) bool {
	name = strings.ToLower(name)
	for _, profile := range profiles.entries {
		for _, zone := range profile.zones {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				return true
			}
		}
	}
	if _, matched := f.tbl.Load().match(name); matched {
		return true
	}
	if f.k8s.Load().inZone(name) {
		return true
	}
	host := f.vpnHost.Load()
	return host != nil && strings.EqualFold(host.name, name)
}

func (f *Forwarder) answerLANDefault(id uint16, query []byte, q dnsmessage.Question, source netip.Addr, transport string, scope lanBindKey) []byte {
	profiles := f.profiles.Load()
	if q.Class != dnsmessage.ClassINET || f.privateDNSName(q.Name.String(), profiles) {
		return refuse(id, query)
	}
	upstreams, sources, config, failure := f.lanDefaults(profiles, scope)
	allowed := false
	for _, prefix := range sources {
		allowed = allowed || prefix.Contains(source)
	}
	if failure != "" {
		return servfail(id, query)
	}
	if len(upstreams) == 0 || !allowed || (transport != "udp" && transport != "tcp") {
		return refuse(id, query)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for _, upstream := range upstreams {
		if f.profiles.Load() != profiles || f.privateDNSName(q.Name.String(), profiles) {
			return servfail(id, query)
		}
		// This direct config is a separate LAN-only grant. Never reuse the
		// private profile's IPsec transport or extend WireGuard DNS authority.
		endpoint := fqdnrpc.ResolverEndpoint{Address: upstream.String(), Port: 53, Transport: transport}
		config.IPsecPath = nil
		config.Endpoints = []fqdnrpc.ResolverEndpoint{endpoint}
		attempt, stop := context.WithTimeout(ctx, 1200*time.Millisecond)
		response, err := fqdnrpc.ExchangeDNS(attempt, f.lanDefaultTransport, config, endpoint, query)
		stop()
		if err == nil {
			// No cached packet grant: withdrawal, changed sources/upstreams, or
			// newly private names suppress the response of an in-flight query.
			if f.profiles.Load() != profiles || f.privateDNSName(q.Name.String(), profiles) {
				return servfail(id, query)
			}
			if _, _, _, failure := f.lanDefaults(profiles, scope); failure != "" {
				return servfail(id, query)
			}
			return response
		}
		if ctx.Err() != nil {
			break
		}
	}
	return servfail(id, query)
}
