package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"net/netip"
	"testing"
)

func TestStaticCNAMECompletionNeverBecomesApplicationResolverGrant(t *testing.T) {
	g := fqdnresolver.ActiveGeneration{ResourceID: uuid.New(), Hostname: "app.office.test", Protocol: "tcp", Context: fqdnresolver.Context{ResolverID: uuid.NewString(), GatewayID: uuid.NewString()}, ResolverConfig: fqdnresolver.ResolverConfig{ID: uuid.NewString(), Version: 1, ProfileID: uuid.NewString(), MatchedSuffix: "office.test", StaticRecords: []fqdnresolver.StaticRecord{{Name: "app.office.test", Type: "A", Value: "10.180.10.229", TTL: 300}}}, Addresses: []netip.Addr{netip.MustParseAddr("10.180.10.229")}}
	for _, endpoints := range [][]fqdnresolver.ResolverEndpoint{nil, {{Address: netip.MustParseAddr("1.1.1.1"), Port: 53, Transport: "udp"}}} {
		g.ResolverConfig.Endpoints = endpoints
		got, err := fqdnResourceFromActiveGeneration(g, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
		if err != nil || got.Active == nil || len(got.Active.Answers) != 1 || got.Active.Answers[0] != "10.180.10.229" || len(got.Active.ResolverAddresses) != 0 {
			t.Fatal("fixed application record changed or public resolver granted", got, err)
		}
	}
	g.ResolverConfig.StaticRecords[0] = fqdnresolver.StaticRecord{Name: "app.office.test", Type: "CNAME", Value: "outside.example", TTL: 300}
	if _, err := fqdnResourceFromActiveGeneration(g, nil); err == nil {
		t.Fatal("external alias accepted an invented application generation")
	}
	g.ResolverConfig.StaticRecords[0] = fqdnresolver.StaticRecord{Name: "app.office.test", Type: "A", Value: "10.180.10.230", TTL: 300}
	if _, err := fqdnResourceFromActiveGeneration(g, nil); err == nil {
		t.Fatal("generation differs from immutable fixed record")
	}
}
