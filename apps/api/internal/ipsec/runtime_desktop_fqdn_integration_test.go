package ipsec_test

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"strings"
	"testing"
	"time"
)

// Real durable mailbox; only the authenticated gateway observation is a fixture.
type desktopCNAMEGateway struct {
	*fqdnresolver.PostgresGatewayDNSMailbox
	address string
	last    fqdnresolver.GatewayDNSRequest
}

func (m *desktopCNAMEGateway) Enqueue(ctx context.Context, r fqdnresolver.GatewayDNSRequest) error {
	if e := m.PostgresGatewayDNSMailbox.Enqueue(ctx, r); e != nil {
		return e
	}
	pending, e := m.PendingForGateway(ctx, r.OrgID, r.GatewayID, 10)
	if e != nil {
		return e
	}
	for _, q := range pending {
		if q.RequestID == r.RequestID {
			m.last = q
			return m.Complete(ctx, r.OrgID, r.GatewayID, m.response(q))
		}
	}
	return fqdnresolver.ErrGatewayDNSRPCUnavailable
}
func (m *desktopCNAMEGateway) response(r fqdnresolver.GatewayDNSRequest) fqdnresolver.GatewayDNSResponse {
	return fqdnresolver.GatewayDNSResponse{Version: r.Version, RequestID: r.RequestID, OrgID: r.OrgID, ResourceID: r.ResourceID, SiteID: r.SiteID, GatewayID: r.GatewayID, ResolverConfigID: r.ResolverConfigID, ResolverConfigVersion: r.ResolverConfigVersion, ResolverProfileID: r.ResolverProfileID, ResolverMatchSuffix: r.ResolverMatchSuffix, Hostname: r.Hostname, RecordTypes: r.RecordTypes, ResolverKind: r.ResolverKind, ObservedAt: time.Now(), Status: fqdnresolver.StatusNoError, Records: []fqdnresolver.GatewayDNSRecord{{Name: r.Hostname, Type: fqdnresolver.TypeCNAME, Target: "target.public.example", TTLSeconds: 60}, {Name: "target.public.example", Type: fqdnresolver.TypeA, Address: m.address, TTLSeconds: 45}}}
}

type desktopWorkResolver struct {
	transport *fqdnresolver.GatewayDNSRPCTransport
	work      fqdnresolver.Work
}

func (r desktopWorkResolver) Lookup(ctx context.Context, _ fqdnresolver.Context, _ string) ([]fqdnresolver.Response, error) {
	return r.transport.LookupWork(ctx, r.work)
}
func TestDesktopStaticCNAMETransactionalLifecycle(t *testing.T) {
	for _, profile := range []string{"bgp", "static"} {
		t.Run(profile, func(t *testing.T) { desktopCNAMETransactionalLifecycle(t, profile) })
	}
}
func desktopCNAMETransactionalLifecycle(t *testing.T, profile string) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 232); e != nil {
		t.Fatal(e)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	if profile == "bgp" {
		req.Config = bgpConfigFixture()
	}
	exec(`UPDATE organizations SET zero_trust_mode='enforcing',fqdn_resources_enabled=true WHERE id=$1`, org)
	exec(`INSERT INTO memberships(org_id,user_id,role)VALUES($1,$2,'owner')`, org, actor)
	exec(`UPDATE nodes SET capabilities=capabilities || '{"max_policy_version":14,"dns_resolve_rpc_version":2,"ipsec_recovery_version":1,"ipsec_bgp_version":1,"ipsec_desktop_transit_version":1,"ipsec_fqdn_policy_version":2,"ipsec_desktop_fqdn_version":1,"ipsec_desktop_static_version":2}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
	device := uuid.New()
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip)VALUES($1,$2,$3,$4,'desktop','ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=','10.199.0.7')`, device, org, actor, req.GatewayID)
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(policy.IPsecRuntimePolicyCompiler(func() bool { return true }))
	conn, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	conn, e = store.SetIntent(ctx, org, actor, conn.ID, conn.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	resources := fqdnresources.New(p)
	config, e := resources.SetResolverProfiles(ctx, org, req.SiteID, req.GatewayID, actor, "test", "CNAME application", []fqdnresources.ResolverProfile{{Name: "app", ProviderHint: "aws", ZoneSuffixes: []string{"office.test"}, StaticRecords: []fqdnresources.ResolverStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "target.public.example", TTL: 60}}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}}, {Name: "other", ProviderHint: "on_premises", ZoneSuffixes: []string{"other.test"}, StaticRecords: []fqdnresources.ResolverStaticRecord{{Name: "hidden.other.test", Type: "A", Value: "10.20.0.99", TTL: 60}}}})
	if e != nil {
		t.Fatal(e)
	}
	port := 443
	input := fqdnresources.Input{Name: "app", FQDN: "app.office.test", Protocol: "tcp", PortLow: &port, PortHigh: &port, Context: &fqdnresources.Context{SiteID: req.SiteID, GatewayID: req.GatewayID}, ApplicationIPsecPath: &fqdnresources.ApplicationIPsecPath{ConnectionID: conn.ID, ConfigurationRevision: 1}}
	if profile == "static" {
		exec(`UPDATE nodes SET capabilities=capabilities-'ipsec_desktop_static_version' WHERE id=$1`, req.GatewayID)
		if _, e := resources.Create(ctx, org, input, actor, "test", "legacy static denied"); e == nil {
			t.Fatal("legacy gateway accepted static hostname application")
		}
		exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_desktop_static_version":2}'::jsonb WHERE id=$1`, req.GatewayID)
	}
	resource, e := resources.Create(ctx, org, input, actor, "test", "CNAME app")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `UPDATE fqdn_resources SET application_ipsec_configuration_revision=NULL WHERE id=$1`, resource.ID); e == nil {
		t.Fatal("partial application binding accepted")
	}
	rule := uuid.New()
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_fqdn_resource_id)VALUES($1,$2,'user',$3,'fqdn_resource',$4)`, rule, org, actor, resource.ID)
	lifecycleStore := fqdnresolver.NewPostgresStore(p)
	mail := &desktopCNAMEGateway{PostgresGatewayDNSMailbox: fqdnresolver.NewPostgresGatewayDNSMailbox(p), address: "10.20.0.8"}
	transport := fqdnresolver.NewGatewayDNSRPCTransport(mail)
	refresh := func() {
		t.Helper()
		work, e := lifecycleStore.Due(ctx, time.Now().Add(time.Minute), 10)
		if e != nil || len(work) != 1 {
			t.Fatalf("work=%v err=%v", work, e)
		}
		w := work[0]
		if w.ResolverConfig.ResolverKind != "static_cname" || w.ResolverConfig.IPsecPath != nil || w.ApplicationDesiredRevision != conn.DesiredRevision {
			t.Fatal("resolution transport fabricated or stale", w)
		}
		var lifecycle fqdnresolver.Lifecycle
		got := lifecycle.Refresh(ctx, time.Now(), desktopWorkResolver{transport, w}, w.Context, w.Hostname)
		if got.Active == nil {
			t.Fatalf("gateway completion failed %+v", got)
		}
		if e := lifecycleStore.Publish(ctx, w, *got.Active); e != nil {
			t.Fatal(e)
		}
	}
	refresh()
	active, e := lifecycleStore.ActiveGenerations(ctx, org)
	if e != nil || len(active) != 1 || fqdnresolver.StaticGenerationMatches(active[0]) {
		t.Fatal("active generation or old-consumer failclosed contract", e, active)
	}
	routes := policy.NewService(p).WithFQDNGenerations(lifecycleStore, func() bool { return true })
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: req.GatewayID.String()}
	material := func() ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, conn.ID, conn.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	check := func(want string) {
		t.Helper()
		got, e := routes.DeviceIPsecRoutedRanges(ctx, org, device)
		if e != nil || want == "" && len(got) != 0 || want != "" && (len(got) != 1 || got[0] != want) {
			t.Fatalf("routes=%v want=%s err=%v", got, want, e)
		}
		dns, e := routes.DeviceFQDNForwards(ctx, org, device, nil)
		if e != nil || want == "" && len(dns) != 0 || want != "" && (len(dns) != 1 || dns[0].Domain != "office.test" || dns[0].ResolverIP != "10.199.0.1") {
			t.Fatalf("DNS=%v want=%s err=%v", dns, want, e)
		}
	}
	m := material()
	if profile == "static" && (m.Manifest.RecoveryVersion == nil || *m.Manifest.RecoveryVersion != 1 || m.Manifest.DesktopStaticVersion == nil || *m.Manifest.DesktopStaticVersion != 1) {
		t.Fatal("static application missing qualified recovery manifest")
	}
	if len(m.Policy.FQDNGrants) != 1 || len(m.Policy.DesktopGrants) != 0 || len(m.Policy.Grants) != 0 || len(m.Policy.DNSResolverGrants) != 0 {
		t.Fatal("widened/missing grants", m.Policy)
	}
	g := m.Policy.FQDNGrants[0]
	if g.DeviceID != device.String() || g.ResolverSourceAddress != "" || g.ConnectionID != conn.ID.String() || g.ResolverConfigID != config.ID.String() {
		t.Fatal("identity lost", g)
	}
	check("10.20.0.8/32")
	// Function-only rollback keeps all resource/generation history. Old readers
	// deny static application authority; BGP behavior remains available.
	if e := db.MigrateTo(p.Config().ConnString(), 231); e != nil {
		t.Fatal(e)
	}
	if profile == "static" {
		check("")
	} else {
		check("10.20.0.8/32")
	}
	var retained int
	if e := p.QueryRow(ctx, `SELECT count(*) FROM fqdn_resources WHERE id=$1`, resource.ID).Scan(&retained); e != nil || retained != 1 {
		t.Fatal("rollback discarded resource", e)
	}
	if e := db.MigrateTo(p.Config().ConnString(), 232); e != nil {
		t.Fatal(e)
	}
	check("10.20.0.8/32")
	if profile == "static" {
		exec(`UPDATE nodes SET capabilities=capabilities-'ipsec_desktop_static_version' WHERE id=$1`, req.GatewayID)
		check("")
		previous := ipsec.RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: conn.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: strings.Repeat("b", 64), FQDNGrants: m.Policy.FQDNGrants}
		if _, e := store.PermitLease(ctx, principal, conn.ID, previous); e == nil {
			t.Fatal("old static capability renewed FQDN lease")
		}
		_, unsupported := store.Material(ctx, principal, conn.ID, conn.DesiredRevision, sealer)
		if !errors.Is(unsupported, ipsec.ErrConnectionIneligible) {
			t.Fatal("legacy static gateway received FQDN authority")
		}
		if rows, e := lifecycleStore.ActiveGenerations(ctx, org); e != nil || len(rows) != 0 {
			t.Fatal("legacy gateway retained application snapshot", e)
		}
		exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_desktop_static_version":2}'::jsonb WHERE id=$1`, req.GatewayID)
		check("10.20.0.8/32")
	}
	lease := ipsec.RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: conn.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: strings.Repeat("a", 64), FQDNGrants: m.Policy.FQDNGrants}
	if _, e := store.PermitLease(ctx, principal, conn.ID, lease); e != nil {
		t.Fatal("fresh timed lease", e)
	}
	mail.address = "10.20.0.9"
	refresh()
	next := material()
	if len(next.Policy.FQDNGrants) != 1 || next.Policy.FQDNGrants[0].Generation == g.Generation || next.Policy.Hash == m.Policy.Hash {
		t.Fatal("same profile answer change did not change authority")
	}
	check("10.20.0.9/32")
	if _, e := store.PermitLease(ctx, principal, conn.ID, lease); e == nil {
		t.Fatal("retired IP renewed")
	}
	exec(`UPDATE policy_rules SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, rule)
	check("")
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	exec(`UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	check("")
	exec(`UPDATE devices SET health_blocked=false WHERE id=$1`, device)
	exec(`UPDATE nodes SET capabilities=capabilities-'ipsec_desktop_fqdn_version' WHERE id=$1`, req.GatewayID)
	check("")
	exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_desktop_fqdn_version":1,"ipsec_desktop_static_version":2}'::jsonb WHERE id=$1`, req.GatewayID)
	oldWork, e := lifecycleStore.Due(ctx, time.Now().Add(time.Minute), 10)
	if e != nil || len(oldWork) != 1 {
		t.Fatal(e)
	}
	conn, e = store.SetIntent(ctx, org, actor, conn.ID, conn.DesiredRevision, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	check("")
	cleanup, e := store.Cleanup(ctx, principal, conn.ID, conn.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	if e := store.Acknowledge(ctx, principal, conn.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: conn.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
		t.Fatal(e)
	}
	conn, e = store.SetIntent(ctx, org, actor, conn.ID, conn.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	check("")
	if _, e := transport.LookupWork(ctx, oldWork[0]); e == nil {
		t.Fatal("old pending revision revived")
	}
	refresh()
	material()
	check("10.20.0.9/32")
	mail.address = "10.90.0.8"
	refresh()
	if rows, e := lifecycleStore.ActiveGenerations(ctx, org); e != nil || len(rows) != 0 {
		t.Fatal("outside approved application prefix remained usable", e)
	}
	check("")
	if e := db.MigrateTo(p.Config().ConnString(), 229); e == nil {
		t.Fatal("destructive downgrade discarded application history")
	}
}
