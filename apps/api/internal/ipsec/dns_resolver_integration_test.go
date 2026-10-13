package ipsec_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"net/netip"
	"testing"
	"time"
)

func mustDNSAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
func TestIPsecDNSProfileOwnedRevisionAndLifecycle(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 219); err != nil {
		t.Fatal(err)
	}
	connections := ipsec.NewConnectionStore(p)
	connections.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := connections.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	svc := fqdnresources.New(p)
	newProfile := func() fqdnresources.ResolverProfile {
		return fqdnresources.ResolverProfile{Name: "AWS private", ProviderHint: "aws", ZoneSuffixes: []string{"private.example.test"}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "10.20.0.54", Port: 53, Transport: "tcp"}}, IPsecPath: &fqdnresources.ResolverIPsecPath{ConnectionID: c.ID, ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}}
	}
	set := func(orgID, site, gateway uuid.UUID, profile fqdnresources.ResolverProfile) (fqdnresources.ResolverConfig, error) {
		return svc.SetResolverProfiles(ctx, orgID, site, gateway, actor, "test", "owned IPsec DNS QA", []fqdnresources.ResolverProfile{profile})
	}
	if _, err := set(org, req.SiteID, req.GatewayID, newProfile()); err == nil {
		t.Fatal("disabled connection accepted")
	}
	c, err = connections.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := set(org, req.SiteID, req.GatewayID, newProfile()); err == nil {
		t.Fatal("old gateway without DNS over IPsec capability accepted")
	}
	if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}'::jsonb WHERE id=$1`, req.GatewayID); err != nil {
		t.Fatal(err)
	}
	config, err := set(org, req.SiteID, req.GatewayID, newProfile())
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || config.Profiles[0].IPsecPath == nil {
		t.Fatal("bound revision absent")
	}
	// PostgreSQL CHECK treats NULL as success unless each triplet field is explicitly required.
	for _, column := range []string{"ipsec_connection_id", "ipsec_configuration_revision", "ipsec_source_address"} {
		if _, err := p.Exec(ctx, "UPDATE fqdn_resolver_context_profiles SET "+column+"=NULL WHERE id=$1", config.Profiles[0].ID); err == nil {
			t.Fatalf("partial bound triplet accepted: %s", column)
		}
	}
	for _, kind := range []string{"crossorg", "site", "gateway", "revision", "source", "endpoint", "port"} {
		t.Run(kind, func(t *testing.T) {
			profile := newProfile()
			tenant, site, gateway := org, req.SiteID, req.GatewayID
			switch kind {
			case "crossorg":
				tenant = uuid.New()
			case "site":
				site = uuid.New()
			case "gateway":
				gateway = uuid.New()
			case "revision":
				profile.IPsecPath.ConfigurationRevision = 2
			case "source":
				profile.IPsecPath.SourceAddress = "10.99.0.5"
			case "endpoint":
				profile.Endpoints[0].Address = "10.99.0.53"
			case "port":
				profile.Endpoints[0].Port = 5353
			}
			if _, err := set(tenant, site, gateway, profile); err == nil {
				t.Fatal("invalid path accepted")
			}
			current, err := svc.ResolverConfig(ctx, org, req.SiteID, req.GatewayID)
			if err != nil || current.ID != config.ID || current.Version != 1 {
				t.Fatal("refused write retired good config", err)
			}
		})
	}
	current, err := svc.ResolverConfig(ctx, org, req.SiteID, req.GatewayID)
	if err != nil || current.Profiles[0].IPsecPath.SourceAddress != "10.10.0.5" {
		t.Fatal("read binding", err)
	}
	input := ipsec.RuntimePolicyInput{OrgID: org, SiteID: req.SiteID, NodeID: req.GatewayID, ConnectionID: c.ID, Config: req.Config}
	runtime, err := policy.CompileIPsecRuntimePolicy(ctx, sqlc.New(p), input)
	if err != nil || len(runtime.DNSResolverGrants) != 2 || len(runtime.DNSResolverProfiles) != 1 {
		t.Fatalf("scoped DNS authority: grants=%d profiles=%d err=%v", len(runtime.DNSResolverGrants), len(runtime.DNSResolverProfiles), err)
	}
	for _, g := range runtime.DNSResolverGrants {
		if g.SourceAddress != "10.10.0.5" || g.ConnectionID != c.ID.String() || g.ContextConfigID != config.ID.String() || g.ConfigurationRevision != 1 {
			t.Fatal("DNS authority widened")
		}
	}
	// Brokered direct lookup records the immutable path and invalidates on Disable.
	if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}'::jsonb WHERE id=$1`, req.GatewayID); err != nil {
		t.Fatal(err)
	}
	resource := uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id)VALUES($1,$2,'dns QA','service.private.example.test',$3,$4)`, resource, org, req.SiteID, req.GatewayID); err != nil {
		t.Fatal(err)
	}
	request := fqdnresolver.GatewayDNSRequest{Version: 2, RequestID: uuid.New(), OrgID: org, ResourceID: resource, SiteID: req.SiteID, GatewayID: req.GatewayID, ResolverConfigID: config.ID, ResolverConfigVersion: 1, ResolverProfileID: config.Profiles[0].ID, ResolverMatchSuffix: "private.example.test", Hostname: "service.private.example.test", RecordTypes: []fqdnresolver.RecordType{fqdnresolver.TypeA, fqdnresolver.TypeAAAA, fqdnresolver.TypeCNAME}, Deadline: time.Now().Add(20 * time.Second), ResolverIPsecPath: &fqdnresolver.ResolverIPsecPath{ConnectionID: c.ID.String(), ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}}
	for _, endpoint := range config.Profiles[0].Endpoints {
		request.ResolverEndpoints = append(request.ResolverEndpoints, fqdnresolver.ResolverEndpoint{Address: mustDNSAddr(t, endpoint.Address), Port: uint16(endpoint.Port), Transport: endpoint.Transport})
	}
	mailbox := fqdnresolver.NewPostgresGatewayDNSMailbox(p)
	if err := mailbox.Enqueue(ctx, request); err != nil {
		t.Fatal("enqueue", err)
	}
	pending, err := mailbox.PendingForGateway(ctx, org, req.GatewayID, 1)
	if err != nil || len(pending) != 1 || pending[0].ResolverIPsecPath == nil {
		t.Fatal("pending bound path", err)
	}
	c, err = connections.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "disabled")
	if err != nil {
		t.Fatal(err)
	}
	pending, err = mailbox.PendingForGateway(ctx, org, req.GatewayID, 1)
	if err != nil || len(pending) != 0 {
		t.Fatal("disabled path still deliverable", err)
	}
	runtime, err = policy.CompileIPsecRuntimePolicy(ctx, sqlc.New(p), input)
	if err != nil || len(runtime.DNSResolverGrants) != 0 {
		t.Fatal("disabled transport retained authority", err)
	}
	rows, err := sqlc.New(p).ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 1 || rows[0].TransportAvailable {
		t.Fatal("private zone declaration did not survive disable", err)
	}
	if _, err := set(org, req.SiteID, req.GatewayID, newProfile()); err == nil {
		t.Fatal("disabled context replacement accepted")
	}
	// Retiring configuration withdraws the declared table, rather than retaining process memory forever.
	if err := svc.DeleteResolverConfig(ctx, org, req.SiteID, req.GatewayID, actor, "test", "retire DNS QA"); err != nil {
		t.Fatal(err)
	}
	rows, err = sqlc.New(p).ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 0 {
		t.Fatal("retired declared zone persisted", err)
	}

}
