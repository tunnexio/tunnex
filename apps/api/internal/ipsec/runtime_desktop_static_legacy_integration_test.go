package ipsec_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"testing"
)

func TestDesktopStaticLegacyDeliveryPreservesLAN(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 231); e != nil {
		t.Fatal(e)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE organizations SET zero_trust_mode='enforcing' WHERE id=$1`, org)
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, actor)
	device, resource := uuid.New(), uuid.New()
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip)VALUES($1,$2,$3,$4,'desktop','ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=','10.199.0.7')`, device, org, actor, req.GatewayID)
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high)VALUES($1,$2,'app','10.20.0.8/32','tcp',443,443)`, resource, org)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_resource_id)VALUES($1,$2,'user',$3,'resource',$4)`, uuid.New(), org, actor, resource)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_resource_id)VALUES($1,$2,'cidr','10.10.0.2/32','resource',$3)`, uuid.New(), org, resource)
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(policy.CompileIPsecRuntimePolicy)
	conn, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	conn, e = store.SetIntent(ctx, org, actor, conn.ID, conn.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: req.GatewayID.String()}
	material := func() ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, conn.ID, conn.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	legacy := material()
	if legacy.Manifest.RecoveryVersion != nil || len(legacy.Policy.Grants) != 1 || len(legacy.Policy.DesktopGrants) != 0 {
		t.Fatal("legacy fixture invalid")
	}
	exec(`UPDATE nodes SET capabilities=capabilities || '{"ipsec_recovery_version":1,"ipsec_bgp_version":1,"ipsec_desktop_transit_version":1,"ipsec_desktop_static_version":1,"ipsec_fqdn_policy_version":2,"ipsec_desktop_fqdn_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, req.GatewayID)
	upgraded := material()
	if upgraded.OwnershipDigest != legacy.OwnershipDigest || upgraded.Policy.Hash != legacy.Policy.Hash || len(upgraded.Policy.Grants) != 1 || len(upgraded.Policy.DesktopGrants) != 0 {
		t.Fatal("upgrade changed legacy LAN delivery or added unsupported desktop authority")
	}
	routes := policy.NewService(p)
	if got, e := routes.DeviceIPsecRoutedRanges(ctx, org, device); e != nil || len(got) != 0 {
		t.Fatal("legacy delivery exported desktop route", got, e)
	}
	applicationReady := func(want bool) {
		t.Helper()
		var got bool
		if e := p.QueryRow(ctx, `SELECT fqdn_application_ipsec_path_valid($1,$2,$3,$4,1)`, org, req.SiteID, req.GatewayID, conn.ID).Scan(&got); e != nil || got != want {
			t.Fatal("legacy application authority", got, e)
		}
	}
	applicationReady(false)
	// The normal disable/cleanup/enable lifecycle creates the supported immutable contract.
	conn, e = store.SetIntent(ctx, org, actor, conn.ID, conn.DesiredRevision, "disabled")
	if e != nil {
		t.Fatal(e)
	}
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
	current := material()
	if current.Manifest.RecoveryVersion == nil || *current.Manifest.RecoveryVersion != 1 || len(current.Policy.Grants) != 1 || len(current.Policy.DesktopGrants) != 1 {
		t.Fatal("new static contract missing authority")
	}
	if got, e := routes.DeviceIPsecRoutedRanges(ctx, org, device); e != nil || len(got) != 1 || got[0] != "10.20.0.8/32" {
		t.Fatal("new static route", got, e)
	}
	applicationReady(true)
}
