package appaccess

import (
	"context"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"net"
	"net/netip"
)

func (p *BrowserPool) checkPending(ctx context.Context, a BrowserAssignment) originpolicy.Result {
	checker := p.checker
	checker.ControlAddresses = append([]netip.Addr(nil), checker.ControlAddresses...)
	lookup := checker.Lookup
	if lookup == nil {
		resolver := checker.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return resolver.LookupNetIP(ctx, "ip", host)
		}
	}
	for _, host := range checker.ControlHosts {
		if address, e := netip.ParseAddr(host); e == nil {
			checker.ControlAddresses = append(checker.ControlAddresses, address)
			continue
		}
		addresses, e := lookup(ctx, host)
		if e != nil || len(addresses) == 0 || len(addresses) > 64 {
			return originpolicy.Result{Status: "origin_refused", DNS: "refused", Connect: "not_checked", TLS: "not_checked"}
		}
		checker.ControlAddresses = append(checker.ControlAddresses, addresses...)
	}
	return checker.Check(ctx, a.OriginURL, a.Policy)
}
