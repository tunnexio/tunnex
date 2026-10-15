package dnsforward

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
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
	StaticRecords  []StaticRecord
	LANListener    *LANListener
}
type compiledResolverProfile struct {
	config  fqdnrpc.ResolverConfig
	zones   []string
	sources []netip.Prefix
	valid   bool
	static  staticAnswers
	lan     *compiledLANListener
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
		if len(entry.StaticRecords) > 0 {
			p.static, p.valid = compileStaticRecords(entry.StaticRecords, p.zones)
			_, configErr := uuid.Parse(entry.Config.ID)
			_, profileErr := uuid.Parse(entry.Config.ProfileID)
			p.valid = p.valid && entry.Config.IPsecPath == nil && validStaticTargetEndpoints(entry.Config.Endpoints) && configErr == nil && profileErr == nil && entry.Config.Version > 0
		}
		if entry.LANListener != nil {
			p.lan = compileLANListener(*entry.LANListener)
		}
		if len(p.zones) == 0 {
			continue
		}
		for _, source := range entry.AllowedSources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil || (p.static == nil && !prefix.Addr().Is4()) || prefix != prefix.Masked() || prefix.Bits() == 0 {
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

// match applies the same longest-suffix and ambiguity boundary to direct
// questions and each local record traversed through a static alias.
func (profiles *resolverProfiles) match(name string) (int, bool) {
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
	return selected, ambiguous
}

func (f *Forwarder) answerResolverProfile(id uint16, query []byte, q dnsmessage.Question, source netip.Addr, transport string) ([]byte, bool) {
	return f.answerScopedResolverProfile(id, query, q, source, transport, nil)
}

func (f *Forwarder) answerScopedResolverProfile(id uint16, query []byte, q dnsmessage.Question, source netip.Addr, transport string, scope *lanBindKey) ([]byte, bool) {
	profiles := f.profiles.Load()
	if profiles == nil {
		return nil, false
	}
	selected, ambiguous := profiles.match(strings.ToLower(q.Name.String()))
	if selected < 0 {
		return nil, false
	}
	p := profiles.entries[selected]
	if scope != nil && (p.lan == nil || p.lan.key != *scope) {
		return refuse(id, query), true
	}
	if !p.valid || ambiguous {
		return servfail(id, query), true
	}
	allowed := false
	sources := p.sources
	if scope != nil {
		sources = p.lan.sources
	}
	for _, prefix := range sources {
		if prefix.Contains(source) {
			allowed = true
		}
	}
	if !allowed {
		return refuse(id, query), true
	}
	if q.Class != dnsmessage.ClassINET {
		return refuse(id, query), true
	}
	if p.static != nil {
		response := f.answerStaticProfile(profiles, selected, id, query, q, transport)
		if f.profiles.Load() != profiles {
			return servfail(id, query), true
		}
		return response, true
	}
	if f.transport == nil {
		return servfail(id, query), true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, endpoint := range p.config.Endpoints {
		attempt, stop := context.WithTimeout(ctx, 2500*time.Millisecond)
		response, err := fqdnrpc.ExchangeProxyDNS(attempt, f.transport, p.config, endpoint, transport, query)
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
