package dnsforward

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

// ResolverProfile routes only its declared private suffixes. AllowedSources is
// a compiled DNS entitlement projection; it is not inferred from the source
// being connected to WireGuard. Empty/invalid sources authorize nobody.
type ResolverProfile struct {
	Config         fqdnrpc.ResolverConfig
	ZoneSuffixes   []string
	AllowedSources []string
}
type compiledResolverProfile struct {
	config  fqdnrpc.ResolverConfig
	zones   []string
	sources []netip.Prefix
	valid   bool
}
type resolverProfiles struct{ entries []compiledResolverProfile }

// SetResolverTransport is set once by the composition root before Serve.
func (f *Forwarder) SetResolverTransport(transport fqdnrpc.BoundTransport) { f.transport = transport }

func (f *Forwarder) SetResolverProfiles(entries []ResolverProfile) {
	result := &resolverProfiles{}
	for _, entry := range entries {
		p := compiledResolverProfile{config: entry.Config, valid: entry.Config.IPsecPath != nil && fqdnrpc.ValidResolverConfig(entry.Config)}
		p.config.Endpoints = append([]fqdnrpc.ResolverEndpoint(nil), entry.Config.Endpoints...)
		if entry.Config.IPsecPath != nil {
			path := *entry.Config.IPsecPath
			p.config.IPsecPath = &path
		}
		for _, zone := range entry.ZoneSuffixes {
			if normalized := normalizeDomain(zone); normalized != "" {
				p.zones = append(p.zones, normalized)
			}
		}
		if len(p.zones) == 0 {
			continue
		}
		for _, source := range entry.AllowedSources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 {
				p.valid = false
				break
			}
			p.sources = append(p.sources, prefix)
		}
		result.entries = append(result.entries, p)
	}
	if current := f.profiles.Load(); reflect.DeepEqual(current, result) {
		return
	}
	f.profiles.Store(result)
}

func (f *Forwarder) answerResolverProfile(id uint16, query []byte, q dnsmessage.Question, source netip.Addr) ([]byte, bool) {
	profiles := f.profiles.Load()
	if profiles == nil {
		return nil, false
	}
	name := strings.ToLower(q.Name.String())
	selected := -1
	length := -1
	ambiguous := false
	for index, p := range profiles.entries {
		for _, zone := range p.zones {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				if len(zone) > length {
					selected = index
					length = len(zone)
					ambiguous = false
				} else if len(zone) == length && selected != index {
					ambiguous = true
				}
			}
		}
	}
	if selected < 0 {
		return nil, false
	}
	p := profiles.entries[selected]
	if !p.valid || ambiguous || f.transport == nil {
		return servfail(id, query), true
	}
	allowed := false
	for _, prefix := range p.sources {
		if prefix.Contains(source) {
			allowed = true
		}
	}
	if !allowed {
		return refuse(id, query), true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, endpoint := range p.config.Endpoints {
		attempt, stop := context.WithTimeout(ctx, 2500*time.Millisecond)
		response, err := fqdnrpc.ExchangeDNS(attempt, f.transport, p.config, endpoint, query)
		stop()
		if err == nil {
			// Do not relay answers from a superseded/removed entitlement table.
			// This is fresh identity comparison, not a cached packet grant.
			if f.profiles.Load() != profiles {
				return servfail(id, query), true
			}
			return response, true
		}
		if ctx.Err() != nil {
			break
		}
	}
	return servfail(id, query), true
}
