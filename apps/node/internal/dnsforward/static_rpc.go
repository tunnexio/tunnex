package dnsforward

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"golang.org/x/net/dns/dnsmessage"
)

var errStaticRPC = errors.New("static resolver context unavailable")

// The request names an currently programmed resolver profile, never supplies records
// or authorizes a DNS route. Only the configured alias's external tail is sent.
func (f *Forwarder) ValidateDNSPath(ctx context.Context, c fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint) error {
	if ctx.Err() != nil || c.Kind != "static_cname" || c.IPsecPath != nil {
		return errStaticRPC
	}
	profiles := f.profiles.Load()
	if profiles == nil {
		return errStaticRPC
	}
	for _, p := range profiles.entries {
		if !p.valid || p.static == nil || p.config.IPsecPath != nil || p.config.ID != c.ID || p.config.Version != c.Version || p.config.ProfileID != c.ProfileID || !reflect.DeepEqual(p.config.Endpoints, c.Endpoints) {
			continue
		}
		listed := false
		for _, e := range c.Endpoints {
			listed = listed || e == endpoint
		}
		if !listed {
			return errStaticRPC
		}
		for _, zone := range p.zones {
			if strings.TrimSuffix(zone, ".") == c.MatchedSuffix && f.staticTargetEndpointsCurrent(profiles, p) {
				return nil
			}
		}
	}
	return errStaticRPC
}

func (f *Forwarder) ExchangeDNS(ctx context.Context, c fqdnrpc.ResolverConfig, endpoint fqdnrpc.ResolverEndpoint, query []byte) ([]byte, error) {
	if f.ValidateDNSPath(ctx, c, endpoint) != nil {
		return nil, errStaticRPC
	}
	var request dnsmessage.Message
	if request.Unpack(query) != nil || request.Response || len(request.Questions) != 1 || request.Questions[0].Class != dnsmessage.ClassINET || (request.Questions[0].Type != dnsmessage.TypeA && request.Questions[0].Type != dnsmessage.TypeAAAA) {
		return nil, errStaticRPC
	}
	profiles := f.profiles.Load()
	if profiles == nil {
		return nil, errStaticRPC
	}
	name := strings.ToLower(request.Questions[0].Name.String())
	selected, ambiguous := profiles.match(name)
	if ambiguous || selected < 0 {
		return nil, errStaticRPC
	}
	p := profiles.entries[selected]
	if p.config.ID != c.ID || p.config.Version != c.Version || p.config.ProfileID != c.ProfileID {
		return nil, errStaticRPC
	}
	rows := p.static[name]
	if len(rows) != 1 || rows[0].Type != "CNAME" {
		return nil, errStaticRPC
	}
	response := f.answerStaticProfileContext(ctx, profiles, selected, request.ID, query, request.Questions[0], endpoint.Transport, &endpoint)
	if ctx.Err() != nil || f.profiles.Load() != profiles || f.ValidateDNSPath(ctx, c, endpoint) != nil {
		return nil, errStaticRPC
	}
	return response, nil
}
