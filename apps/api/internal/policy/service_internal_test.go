package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
)

// canonicalCIDR must mask host bits so the stored + compiled DstCIDR is canonical
// (S7.2's nftables/ipset apply rejects or mis-reads a host-bits-set prefix).
func TestCanonicalCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.5.5/24":    "10.0.5.0/24",   // host bits set -> masked
		"10.0.5.0/24":    "10.0.5.0/24",   // already canonical
		"0.0.0.0/0":      "0.0.0.0/0",     // the internet
		"10.99.0.7/32":   "10.99.0.7/32",  // host route
		"2001:db8::5/32": "2001:db8::/32", // v6 host bits set
	}
	for in, want := range cases {
		if got := canonicalCIDR(in); got != want {
			t.Errorf("canonicalCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeFQDNGenerationReader struct {
	rows []fqdnresolver.ActiveGeneration
	err  error
	org  uuid.UUID
}

func (f *fakeFQDNGenerationReader) ActiveGenerations(_ context.Context, org uuid.UUID) ([]fqdnresolver.ActiveGeneration, error) {
	f.org = org
	return f.rows, f.err
}

func TestAppendActiveFQDNGenerationsFailsClosed(t *testing.T) {
	org, resource, site, gateway, config := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	reader := &fakeFQDNGenerationReader{rows: []fqdnresolver.ActiveGeneration{{
		OrgID: org, ResourceID: resource, Hostname: "api.example.test", Protocol: "tcp",
		Sequence: 7, Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: gateway.String()},
		ResolverConfig: fqdnresolver.ResolverConfig{ID: config.String(), Version: 1, Endpoints: []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "udp"}}},
		Addresses:      []netip.Addr{netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("fd00::3")},
	}}}
	snap := Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}
	if err := appendActiveFQDNGenerations(context.Background(), &snap, reader, org); err != nil {
		t.Fatal(err)
	}
	if reader.org != org || len(snap.FQDNResources) != 1 || snap.FQDNResources[0].ID != resource || snap.FQDNResources[0].Active == nil || snap.FQDNResources[0].Active.SelectedSiteID != site || len(snap.FQDNResources[0].Active.Answers) != 2 {
		t.Fatalf("active resolver generation was not projected exactly: %#v", snap)
	}

	for name, disabled := range map[string]Snapshot{
		"licence absent": {FQDNResourcesEnabled: true},
		"opt-in absent":  {FQDNResourcesLicensed: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := appendActiveFQDNGenerations(context.Background(), &disabled, reader, org); err != nil {
				t.Fatal(err)
			}
			if len(disabled.FQDNResources) != 0 {
				t.Fatalf("disabled snapshot must not receive active FQDN answers: %#v", disabled)
			}
		})
	}

	reader.err = errors.New("database unavailable")
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("authoritative FQDN snapshot read failure must not compile stale answers")
	}
	reader.err = nil
	reader.rows[0].Context.GatewayID = "not-a-uuid"
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("malformed selected context must fail closed")
	}
	reader.rows[0].Context.GatewayID = gateway.String()
	reader.rows[0].ResolverConfig.Version = 0
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("active generation without an immutable resolver config revision must fail closed")
	}
	reader.rows[0].ResolverConfig.Version = 1
	reader.rows[0].ResolverConfig.Endpoints = nil
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("active generation without direct resolver endpoints must fail closed")
	}
}
