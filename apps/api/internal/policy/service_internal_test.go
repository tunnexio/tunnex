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
	org, resource, site, gateway, config, profile := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	reader := &fakeFQDNGenerationReader{rows: []fqdnresolver.ActiveGeneration{{
		OrgID: org, ResourceID: resource, Hostname: "api.example.test", Protocol: "tcp",
		Sequence: 7, Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: gateway.String()},
		ResolverConfig: fqdnresolver.ResolverConfig{ID: config.String(), Version: 1, ProfileID: profile.String(), MatchedSuffix: "example.test", Endpoints: []fqdnresolver.ResolverEndpoint{
			{Address: netip.MustParseAddr("10.30.0.53"), Port: 53, Transport: "udp"},
			{Address: netip.MustParseAddr("10.20.0.54"), Port: 53, Transport: "udp"},
			{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "udp"},
			{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "tcp"},
			{Address: netip.MustParseAddr("10.20.0.54"), Port: 5353, Transport: "udp"},
			{Address: netip.MustParseAddr("10.20.0.55"), Port: 53, Transport: "tcp"},
		}},
		Addresses: []netip.Addr{netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("fd00::3")},
	}}}
	snap := Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true, SiteSubnets: []SiteSubnet{{SiteID: site, CIDR: "10.20.0.0/24"}}}
	if err := appendActiveFQDNGenerations(context.Background(), &snap, reader, org); err != nil {
		t.Fatal(err)
	}
	if reader.org != org || len(snap.FQDNResources) != 1 || snap.FQDNResources[0].ID != resource || snap.FQDNResources[0].Active == nil || snap.FQDNResources[0].Active.SelectedSiteID != site || snap.FQDNResources[0].Active.ResolverConfigID != config || snap.FQDNResources[0].Active.ResolverProfileID != profile || snap.FQDNResources[0].Active.ResolverMatchSuffix != "example.test" || snap.FQDNResources[0].Active.ResolverConfigVersion != 1 || len(snap.FQDNResources[0].Active.Answers) != 2 || len(snap.FQDNResources[0].Active.ResolverAddresses) != 1 || snap.FQDNResources[0].Active.ResolverAddresses[0] != "10.20.0.54/32" {
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
	reader.rows[0].ResolverConfig.ProfileID = ""
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("active generation without selected resolver profile provenance must fail closed")
	}
	reader.rows[0].ResolverConfig.ProfileID = profile.String()
	reader.rows[0].ResolverConfig.Version = 0
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("active generation without an immutable resolver config revision must fail closed")
	}
	reader.rows[0].ResolverConfig.Version = 1
	reader.rows[0].ResolverConfig.Endpoints = nil
	if err := appendActiveFQDNGenerations(context.Background(), &Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}, reader, org); err == nil {
		t.Fatal("active generation without direct resolver endpoints must fail closed")
	}
	reader.rows[0].ResolverConfig.Endpoints = []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.20.0.55"), Port: 53, Transport: "tcp"}}
	withoutDesktopResolver := Snapshot{FQDNResourcesLicensed: true, FQDNResourcesEnabled: true}
	if err := appendActiveFQDNGenerations(context.Background(), &withoutDesktopResolver, reader, org); err != nil {
		t.Fatalf("a valid TCP-only profile remains a valid answer generation: %v", err)
	}
	if got := withoutDesktopResolver.FQDNResources[0].Active.ResolverAddresses; len(got) != 0 {
		t.Fatalf("unsupported desktop endpoints must be excluded, got %v", got)
	}
}

// AI-SEC-2 grace mechanism: a deny goes out only to a gateway that can render it, and then only when the
// runtime already forwards through the gateway or the organization's grace is over.
func TestMCPDirectPathClosedGatingMatrix(t *testing.T) {
	cases := []struct {
		gateway, runtime, graceOpen, want bool
	}{
		{false, false, false, false}, // old gateway: never, it would refuse a v16 artifact and deny everything
		{false, false, true, false},
		{false, true, false, false},
		{false, true, true, false},
		{true, false, true, false}, // capable gateway, old runtime, inside grace: the old path stays
		{true, false, false, true}, // grace over (or never granted): closed
		{true, true, true, true},   // runtime forwards through the gateway: closed even inside grace
		{true, true, false, true},
	}
	for _, c := range cases {
		if got := mcpDirectPathClosed(c.gateway, c.runtime, c.graceOpen); got != c.want {
			t.Errorf("gateway=%v runtime=%v graceOpen=%v: closed=%v, want %v", c.gateway, c.runtime, c.graceOpen, got, c.want)
		}
	}
}

func TestGatewayRendersMCPDenyReadsCapabilities(t *testing.T) {
	cases := map[string]bool{
		`{"mcp_gateway_ready":true,"max_policy_version":16}`:   true,
		`{"mcp_gateway_ready":true,"max_policy_version":17}`:   true,
		`{"mcp_gateway_ready":true,"max_policy_version":15}`:   false, // it would refuse the artifact
		`{"mcp_gateway_ready":true}`:                           false,
		`{"mcp_gateway_ready":false,"max_policy_version":16}`:  false,
		`{"mcp_gateway_ready":"true","max_policy_version":16}`: false, // only the typed boolean counts
		`{"max_policy_version":16,"ai_vpn_http_ready":true}`:   false,
		`{}`:   false,
		``:     false,
		`null`: false,
		`[]`:   false,
	}
	for raw, want := range cases {
		if got := gatewayRendersMCPDeny([]byte(raw)); got != want {
			t.Errorf("gatewayRendersMCPDeny(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestMCPEndpointTarget(t *testing.T) {
	type target struct {
		host string
		port int
		ok   bool
	}
	cases := map[string]target{
		"http://10.20.0.5:8080/mcp":     {"10.20.0.5", 8080, true},
		"http://10.20.0.5/mcp":          {"10.20.0.5", 80, true},
		"https://10.20.0.5":             {"10.20.0.5", 443, true},
		"https://MCP.Example.com./mcp":  {"mcp.example.com", 443, true},
		"https://mcp.example.com:8443/": {"mcp.example.com", 8443, true},
		"http://[fd00::5]:9000/mcp":     {"fd00::5", 9000, true},
		"http://[::ffff:10.20.0.5]/mcp": {"10.20.0.5", 80, true},
		"ftp://10.20.0.5/mcp":           {"", 0, false}, // no default port to close
		"ftp://10.20.0.5:2121/mcp":      {"10.20.0.5", 2121, true},
		"http://10.20.0.5:0/mcp":        {"", 0, false},
		"http://10.20.0.5:99999/mcp":    {"", 0, false},
		"10.20.0.5:8080":                {"", 0, false},
		"http:///mcp":                   {"", 0, false},
		"":                              {"", 0, false},
	}
	for endpoint, want := range cases {
		host, port, ok := mcpEndpointTarget(endpoint)
		if host != want.host || port != want.port || ok != want.ok {
			t.Errorf("mcpEndpointTarget(%q) = %q %d %v, want %+v", endpoint, host, port, ok, want)
		}
	}
}
