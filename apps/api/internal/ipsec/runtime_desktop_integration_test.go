package ipsec_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"strings"
	"testing"
)

func TestDesktopRoutedRangesAndLeaseLifecycle(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 228); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	req.Config = bgpConfigFixture()
	exec(`UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, org)
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, actor)
	exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_bgp_version":1,"ipsec_desktop_transit_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
	device, resource, rule := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES($1,$2,$3,$4,'desktop','ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=','10.199.0.7')`, device, org, actor, req.GatewayID)
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high) VALUES($1,$2,'cloud app','10.20.0.8/32','tcp',443,443)`, resource, org)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES($1,$2,'user',$3,'resource',$4)`, rule, org, actor, resource)
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	connection, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	routes := policy.NewService(p)
	check := func(want bool) {
		t.Helper()
		got, err := routes.DeviceIPsecRoutedRanges(ctx, org, device)
		if err != nil || want && (len(got) != 1 || got[0] != "10.20.0.8/32") || !want && len(got) != 0 {
			t.Fatalf("routes want=%t got=%v err=%v", want, got, err)
		}
	}
	check(false)
	connection, err = store.SetIntent(ctx, org, actor, connection.ID, connection.DesiredRevision, "enabled")
	if err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: req.GatewayID.String()}
	material, err := store.Material(ctx, principal, connection.ID, connection.DesiredRevision, sealer)
	if err != nil || len(material.Policy.DesktopGrants) != 1 {
		t.Fatalf("material desktop projection: %v grants=%d", err, len(material.Policy.DesktopGrants))
	}
	g := material.Policy.DesktopGrants[0]
	if g.Source != "10.199.0.7/32" || g.DeviceID != device.String() || g.PublicKey == "" {
		t.Fatal("lost enrolled identity")
	}
	check(true)
	// Ordinary private DNS is independently entitled and automatically points
	// at this device's gateway; no FQDN resource/licence is required.
	exec(`UPDATE nodes SET capabilities=capabilities || '{"max_policy_version":12,"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
	dnsResource, dnsRule := uuid.New(), uuid.New()
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol) VALUES($1,$2,'gateway DNS','10.199.0.1/32','any')`, dnsResource, org)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES($1,$2,'user',$3,'resource',$4)`, dnsRule, org, actor, dnsResource)
	profiles := fqdnresources.New(p)
	if _, err := profiles.SetResolverProfiles(ctx, org, req.SiteID, req.GatewayID, actor, "test", "desktop DNS contract", []fqdnresources.ResolverProfile{
		{Name: "Managed", ProviderHint: "on_premises", ZoneSuffixes: []string{"office.test"}, StaticRecords: []fqdnresources.ResolverStaticRecord{{Name: "app.office.test", Type: "A", Value: "10.20.0.8", TTL: 300}}, LANListener: &fqdnresources.ResolverLANListener{Address: "10.10.0.5", Interface: "eth0", AllowedSources: []string{"10.10.0.0/24"}}},
		{Name: "Cloud", ProviderHint: "aws", ZoneSuffixes: []string{"cloud.test"}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: &fqdnresources.ResolverIPsecPath{ConnectionID: connection.ID, ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}},
	}); err != nil {
		t.Fatal("private profiles", err)
	}
	checkDNS := func(want int) {
		t.Helper()
		got, err := routes.DeviceFQDNForwards(ctx, org, device, nil)
		if err != nil || len(got) != want {
			t.Fatalf("private forwards want%d got=%v err=%v", want, got, err)
		}
		for _, f := range got {
			if f.ResolverIP != "10.199.0.1" {
				t.Fatal("forward exposed upstream instead of gateway", f)
			}
		}
	}
	checkDNS(2)
	exec(`UPDATE policy_rules SET disabled=true WHERE id=$1`, dnsRule)
	checkDNS(0) // LAN permission does not publish a desktop suffix.
	exec(`UPDATE policy_rules SET disabled=false WHERE id=$1`, dnsRule)
	checkDNS(2)
	exec(`UPDATE policy_rules SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, dnsRule)
	checkDNS(0)
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, dnsRule)
	exec(`UPDATE memberships SET access_revoked_at=clock_timestamp() WHERE org_id=$1 AND user_id=$2`, org, actor)
	checkDNS(0)
	exec(`UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, org, actor)
	checkDNS(2)
	exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{max_policy_version}','10'::jsonb) WHERE id=$1`, req.GatewayID)
	checkDNS(0)
	exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{max_policy_version}','12'::jsonb) WHERE id=$1`, req.GatewayID)
	checkDNS(2)
	exec(`UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, req.GatewayID)
	checkDNS(0)
	exec(`UPDATE nodes SET policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
	checkDNS(2)
	// Resolver bindings now participate in the runtime hash; fetch its current material.
	material, err = store.Material(ctx, principal, connection.ID, connection.DesiredRevision, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := routes.DeviceIPsecRoutedRanges(ctx, org, uuid.New()); err != nil || len(got) != 0 {
		t.Fatal("foreign device routes", err, got)
	}
	lease := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: connection.DesiredRevision, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("a", 64)}
	if _, err := store.PermitLease(ctx, principal, connection.ID, lease); err != nil {
		t.Fatal("current desktop lease", err)
	}
	exec(`UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	check(false)
	checkDNS(0)
	if _, err := store.PermitLease(ctx, principal, connection.ID, lease); err == nil {
		t.Fatal("revoked desktop hash renewed")
	}
	exec(`UPDATE devices SET health_blocked=false WHERE id=$1`, device)
	check(true)
	exec(`UPDATE policy_rules SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, rule)
	check(false)
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	check(true)
	exec(`UPDATE nodes SET capabilities=capabilities-'ipsec_desktop_transit_version' WHERE id=$1`, req.GatewayID)
	check(false)
	exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_desktop_transit_version":1}'::jsonb WHERE id=$1`, req.GatewayID)
	check(true)
	if _, err = store.SetIntent(ctx, org, actor, connection.ID, connection.DesiredRevision, "disabled"); err != nil {
		t.Fatal(err)
	}
	check(false)
	checkDNS(1) // Static DNS survives disabling an independent cloud transport.
	if err := profiles.DeleteResolverConfig(ctx, org, req.SiteID, req.GatewayID, actor, "test", "retire private DNS"); err != nil {
		t.Fatal(err)
	}
	checkDNS(0)
}
