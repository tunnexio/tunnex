package dnsforward

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// Explicit upstreams extend only configured static aliases. They do not grant
// recursion for arbitrary names, and are independent of LAN default forwarding.
func validStaticTargetEndpoints(endpoints []fqdnrpc.ResolverEndpoint) bool {
	if len(endpoints) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, e := range endpoints {
		if _, failure := compileLANDefaultUpstreams([]string{e.Address}); failure != "" || e.Port != 53 || (e.Transport != "udp" && e.Transport != "tcp") || seen[e.Address] {
			return false
		}
		seen[e.Address] = true
	}
	return true
}

func (f *Forwarder) staticTargetEndpointsCurrent(profiles *resolverProfiles, p compiledResolverProfile) bool {
	if f.profiles.Load() != profiles {
		return false
	}
	addresses := f.lanLocalAddresses
	if addresses == nil {
		addresses = net.InterfaceAddrs
	}
	local, err := addresses()
	if err != nil {
		return false
	}
	for _, endpoint := range p.config.Endpoints {
		ip, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return false
		}
		for _, address := range local {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || prefix.Addr().Unmap() == ip {
				return false
			}
		}
		for _, other := range profiles.entries {
			if other.static != nil && other.config.IPsecPath == nil {
				continue
			}
			for _, private := range other.config.Endpoints {
				if private.Address == endpoint.Address {
					return false
				}
			}
		}
	}
	return true
}

func (f *Forwarder) answerStaticProfile(profiles *resolverProfiles, selected int, id uint16, query []byte, q dnsmessage.Question, transport string) []byte {
	p := profiles.entries[selected]
	target := strings.ToLower(q.Name.String())
	seen := map[string]bool{}
	hops := 0
	// A broader profile may contain a record shadowed by a nested profile. Every
	// local answer in this chain must retain the original effective owner, even
	// when no external completion endpoints are configured.
	for {
		rows := p.static[target]
		if len(rows) == 0 {
			break
		}
		owner, ambiguous := profiles.match(target)
		if ambiguous || owner != selected {
			return servfail(id, query)
		}
		if len(rows) != 1 || rows[0].Type != "CNAME" {
			break
		}
		if seen[target] || hops >= 8 {
			return servfail(id, query)
		}
		seen[target] = true
		hops++
		target = rows[0].Value
	}
	response := p.static.answer(id, query, q)
	if len(p.config.Endpoints) == 0 || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA) {
		return response
	}
	var out dnsmessage.Message
	if out.Unpack(response) != nil || out.RCode != dnsmessage.RCodeSuccess {
		return response
	}
	// Only the local chain's external tail may invoke explicit target resolvers.
	if hops == 0 || len(p.static[target]) > 0 {
		return response
	}
	if hops > 8 || !f.staticTargetEndpointsCurrent(profiles, p) {
		return servfail(id, query)
	}
	var original dnsmessage.Message
	if original.Unpack(query) != nil || original.Response || original.OpCode != 0 || len(original.Questions) != 1 {
		return refuse(id, query)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	externalNames := map[string]bool{}
	for {
		if ctx.Err() != nil || f.profiles.Load() != profiles || f.privateDNSName(target, profiles) {
			return servfail(id, query)
		}
		externalNames[target] = true
		name, err := dnsmessage.NewName(target)
		if err != nil {
			return servfail(id, query)
		}
		question := dnsmessage.Question{Name: name, Type: q.Type, Class: dnsmessage.ClassINET}
		request := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
		wire, err := request.Pack()
		if err != nil {
			return servfail(id, query)
		}
		var answer dnsmessage.Message
		received := false
		for _, endpoint := range p.config.Endpoints {
			if ctx.Err() != nil || f.profiles.Load() != profiles || f.privateDNSName(target, profiles) {
				return servfail(id, query)
			}
			config := p.config
			// TCP clients keep TCP. UDP may retry the same explicit server over TCP
			// using ExchangeDNS's existing identity and truncation validation.
			if transport == "tcp" {
				endpoint.Transport = "tcp"
				config.Endpoints = []fqdnrpc.ResolverEndpoint{endpoint}
			}
			attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
			raw, exchangeErr := fqdnrpc.ExchangeDNS(attempt, f.staticTargetTransport, config, endpoint, wire)
			stop()
			if exchangeErr != nil {
				continue
			}
			if answer.Unpack(raw) != nil {
				continue
			}
			if answer.RCode != dnsmessage.RCodeSuccess && answer.RCode != dnsmessage.RCodeNameError {
				continue
			}
			received = true
			break
		}
		if !received {
			return servfail(id, query)
		}
		start := target
		if len(answer.Answers) > 256 {
			return servfail(id, query)
		}
		byName := map[string][]dnsmessage.Resource{}
		for _, record := range answer.Answers {
			name := strings.ToLower(record.Header.Name.String())
			byName[name] = append(byName[name], record)
		}
		terminal := false
		for {
			if f.privateDNSName(target, profiles) {
				return servfail(id, query)
			}
			externalNames[target] = true
			records := byName[target]
			var aliases, addresses []dnsmessage.Resource
			addressTypes := 0
			for _, record := range records {
				if record.Header.Class != dnsmessage.ClassINET {
					return servfail(id, query)
				}
				switch record.Header.Type {
				case dnsmessage.TypeCNAME:
					if _, ok := record.Body.(*dnsmessage.CNAMEResource); !ok {
						return servfail(id, query)
					}
					aliases = append(aliases, record)
				case dnsmessage.TypeA, dnsmessage.TypeAAAA:
					addressTypes++
					if record.Header.Type == q.Type {
						addresses = append(addresses, record)
					}
				}
			}
			if len(aliases) > 0 {
				if len(aliases) != 1 || addressTypes > 0 || seen[target] || hops >= 8 {
					return servfail(id, query)
				}
				next := validStaticName(aliases[0].Body.(*dnsmessage.CNAMEResource).CNAME.String())
				if next == "" || seen[next] || next == target || f.privateDNSName(next, profiles) {
					return servfail(id, query)
				}
				seen[target] = true
				hops++
				out.Answers = append(out.Answers, aliases[0])
				target = next
				continue
			}
			if len(addresses) > 32 || len(addresses) > 0 && answer.RCode != dnsmessage.RCodeSuccess {
				return servfail(id, query)
			}
			for _, record := range addresses {
				var ip netip.Addr
				switch body := record.Body.(type) {
				case *dnsmessage.AResource:
					ip = netip.AddrFrom4(body.A)
				case *dnsmessage.AAAAResource:
					ip = netip.AddrFrom16(body.AAAA)
				default:
					return servfail(id, query)
				}
				if !ip.IsGlobalUnicast() {
					return servfail(id, query)
				}
				out.Answers = append(out.Answers, record)
			}
			// A recursive NODATA response has no terminal RR of the requested type.
			// An incomplete CNAME-only response is followed with one bounded new query.
			negativeSOA := false
			for _, record := range answer.Authorities {
				zone := strings.ToLower(record.Header.Name.String())
				if record.Header.Type == dnsmessage.TypeSOA && record.Header.Class == dnsmessage.ClassINET && (target == zone || strings.HasSuffix(target, "."+zone) || zone == ".") {
					negativeSOA = true
				}
			}
			terminal = len(addresses) > 0 || answer.RCode == dnsmessage.RCodeNameError || target == start || negativeSOA
			break
		}
		if !terminal {
			continue
		}
		out.RCode = answer.RCode
		out.Authoritative = false
		out.RecursionAvailable = true
		out.RecursionDesired = original.RecursionDesired
		// Retain only a relevant negative SOA; unrelated answer/additional records
		// cannot enter the synthesized response or acquire application authority.
		if len(out.Answers) == hops {
			for _, record := range answer.Authorities {
				zone := strings.ToLower(record.Header.Name.String())
				if record.Header.Type == dnsmessage.TypeSOA && record.Header.Class == dnsmessage.ClassINET && (target == zone || strings.HasSuffix(target, "."+zone) || zone == ".") {
					if _, ok := record.Body.(*dnsmessage.SOAResource); !ok {
						return servfail(id, query)
					}
					out.Authorities = append(out.Authorities, record)
					break
				}
			}
		}
		if ctx.Err() != nil || !f.staticTargetEndpointsCurrent(profiles, p) {
			return servfail(id, query)
		}
		for name := range externalNames {
			if f.privateDNSName(name, profiles) {
				return servfail(id, query)
			}
		}
		raw, err := out.Pack()
		if err != nil {
			return servfail(id, query)
		}
		return raw
	}
}
