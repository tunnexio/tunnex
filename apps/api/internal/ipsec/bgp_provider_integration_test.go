package ipsec_test

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func TestBGPProviderPersistenceRefusalAndCleanup(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 214); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config = bgpConfigFixture()
	s := ipsec.NewConnectionStore(p)
	eligibility, err := s.ReadEligibility(ctx, org, req.SiteID, req.GatewayID)
	if err != nil || !eligibility.Eligible || eligibility.BGP == nil || eligibility.BGP.Eligible || eligibility.BGP.Reason != "unsupported" {
		t.Fatalf("BGP disabled creation prerequisites: %+v %v", eligibility, err)
	}
	c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadProvider(ctx, org, c.ID)
	if err != nil || got.ProfileID != "aws-bgp-ipv4-v1" || got.Config == nil || got.Config.BGP == nil || *got.Config.BGP != *req.Config.BGP {
		t.Fatalf("BGP read: %+v %v", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "psk") || strings.Contains(string(raw), "sealed") {
		t.Fatal("BGP projection disclosed secret metadata")
	}
	if err = db.DownOne(p.Config().ConnConfig.ConnString()); err == nil || !strings.Contains(err.Error(), "Cannot downgrade while BGP identities exist") {
		t.Fatal("downgrade admitted live BGP identity")
	}
	// migrate marks failed down dirty; reset only this disposable fixture's version.
	if _, err = p.Exec(ctx, `UPDATE schema_migrations SET version=214,dirty=false`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadProvider(ctx, uuid.New(), c.ID); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("cross-org read admitted")
	}
	if _, err = s.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("unqualified BGP activation: %v", err)
	}
	for _, q := range []string{
		`UPDATE ipsec_aws_bgp_configs SET maximum_prefixes=1 WHERE connection_id=$1`,
		`INSERT INTO ipsec_aws_bgp_configs(connection_id,org_id,local_asn,remote_asn,router_id,maximum_prefixes) SELECT connection_id,$2,local_asn,remote_asn,router_id,maximum_prefixes FROM ipsec_aws_bgp_configs WHERE connection_id=$1`,
		`DELETE FROM ipsec_aws_bgp_configs WHERE connection_id=$1`,
	} {
		tx, e := p.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		args := []any{c.ID}
		if strings.Contains(q, "$2") {
			args = append(args, uuid.New())
		}
		_, e = tx.Exec(ctx, q, args...)
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e == nil {
			t.Fatal("immutable/incomplete BGP mutation admitted")
		}
	}
	if _, err = s.Delete(ctx, org, actor, c.ID, 1); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadProvider(ctx, org, c.ID)
	if err != nil || got.Config != nil || got.ProfileID != "aws-bgp-ipv4-v1" {
		t.Fatalf("BGP tombstone: %+v %v", got, err)
	}
	if err = db.DownOne(p.Config().ConnConfig.ConnString()); err == nil || !strings.Contains(err.Error(), "Cannot downgrade while BGP identities exist") {
		t.Fatal("downgrade admitted retained BGP tombstone")
	}
	if _, err = p.Exec(ctx, `UPDATE schema_migrations SET version=214,dirty=false`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_aws_bgp_configs WHERE connection_id=$1`, c.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("BGP cleanup residue: %d %v", count, err)
	}
}

func TestBGPEmptyMigrationRollbackPreservesStatic(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 214); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	s := ipsec.NewConnectionStore(p)
	c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, providerRequest(identity))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DownOne(p.Config().ConnConfig.ConnString()); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadProvider(ctx, org, c.ID)
	if err != nil || got.ProfileID != "aws-static-ipv4-v1" || got.Config.BGP != nil {
		t.Fatalf("static changed on rollback: %v", err)
	}
	if err = db.Up(p.Config().ConnConfig.ConnString()); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadProvider(ctx, org, c.ID)
	if err != nil || got.ProfileID != "aws-static-ipv4-v1" || got.Config.BGP != nil {
		t.Fatalf("static changed on upgrade: %v", err)
	}
}

// The qualified capability here is a synthetic fixture, not a shipping node claim.
func TestBGPTransportManifestDeliveryCapability(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 215); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config = bgpConfigFixture()
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, c.ID); err == nil {
		t.Fatal("DB enabled BGP without capability")
	}
	// Each negative is isolated by restoring the original live gateway identity.
	for _, tc := range []struct{ name, mutation string }{
		{"missing", `capabilities='{"ipsec_config_version":1}'`},
		{"string", `capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":"1"}'`},
		{"future", `capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":2}'`},
		{"stale", `policy_reported_at=clock_timestamp()-interval '91 seconds'`},
		{"future report", `policy_reported_at=clock_timestamp()+interval '1 minute'`},
		{"revoked", `revoked_at=clock_timestamp()`},
		{"missing certificate", `cert_serial=''`},
	} {
		if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":1}',policy_reported_at=clock_timestamp(),revoked_at=NULL,status='active',cert_serial=$2,site_id=$3 WHERE id=$1`, identity.GatewayID, identity.GatewayID.String(), identity.SiteID); err != nil {
			t.Fatal(err)
		}
		if _, err = p.Exec(ctx, "UPDATE nodes SET "+tc.mutation+" WHERE id=$1", identity.GatewayID); err != nil {
			t.Fatal(err)
		}
		if _, err = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
			t.Fatalf("%s activation admitted: %v", tc.name, err)
		}
		var intent string
		var revision int64
		if err = p.QueryRow(ctx, `SELECT desired_intent,desired_revision FROM ipsec_connections WHERE id=$1`, c.ID).Scan(&intent, &revision); err != nil || intent != "disabled" || revision != 1 {
			t.Fatalf("%s refusal changed intent: %s %d %v", tc.name, intent, revision, err)
		}
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET cert_serial=$2,site_id=$3,revoked_at=NULL,status='active' WHERE id=$1`, identity.GatewayID, identity.GatewayID.String(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":1,"ipsec_recovery_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	// Tenant/site binding is also enforced by the persisted composite FK.
	if _, err = p.Exec(ctx, `UPDATE nodes SET site_id=NULL WHERE id=$1`, identity.GatewayID); err == nil {
		t.Fatal("persisted gateway site binding changed")
	}
	if _, err = store.SetIntent(ctx, uuid.New(), actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatalf("foreign tenant activation: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("opted out activation: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=true,revision=revision+1 WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	// Synthetic numeric capability fixture tests CP contracts, not actual worker qualification.
	eligibility, err := store.ReadEligibility(ctx, org, identity.SiteID, identity.GatewayID)
	if err != nil || !eligibility.Eligible || eligibility.BGP == nil || !eligibility.BGP.Eligible {
		t.Fatalf("qualified advisory: %+v %v", eligibility, err)
	}
	if _, err = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); err != nil {
		t.Fatalf("qualified service activation: %v", err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	material, err := store.Material(ctx, principal, c.ID, 2, sealer)
	if err != nil {
		t.Fatal(err)
	}
	m := material.Manifest
	if err = db.DownOne(p.Config().ConnString()); err == nil || !strings.Contains(err.Error(), "Cannot downgrade while BGP deliveries exist") {
		t.Fatalf("outstanding BGP delivery downgrade not refused: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE schema_migrations SET version=215,dirty=false`); err != nil {
		t.Fatal(err)
	}
	leaseRequest := ipsec.RuntimeLeaseRequest{DeliveryID: material.ID, DesiredRevision: 2, PolicyHash: material.Policy.Hash, Nonce: strings.Repeat("b", 64)}
	if _, err = store.PermitLease(ctx, principal, c.ID, leaseRequest); err != nil {
		t.Fatalf("BGP permit with fresh qualified capability: %v", err)
	}
	if m.ProfileID != "aws-bgp-ipv4-v1" || m.BGP == nil || m.BGPVersion == nil || *m.BGPVersion != 1 || m.RecoveryVersion != nil || m.Tunnels[0].Selected || m.Tunnels[1].Selected {
		t.Fatalf("BGP transport manifest: %+v", m)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":"1"}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Material(ctx, principal, c.ID, 2, sealer); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("string capability admitted: %v", err)
	}
	if _, err = store.PermitLease(ctx, principal, c.ID, leaseRequest); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("BGP permit with string capability: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	c, err = store.SetIntent(ctx, org, actor, c.ID, 2, "disabled")
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
	if err != nil || len(cleanup.Lineage) != 1 {
		t.Fatalf("cleanup blocked on capability loss: %v", err)
	}
	if err = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: c.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); err != nil {
		t.Fatal(err)
	}
	if err = db.DownOne(p.Config().ConnString()); err != nil {
		t.Fatalf("cleaned BGP delivery downgrade refused: %v", err)
	}
	if err = db.DownOne(p.Config().ConnString()); err == nil || !strings.Contains(err.Error(), "Cannot downgrade while BGP identities exist") {
		t.Fatalf("retained BGP identity downgrade not refused: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE schema_migrations SET version=214,dirty=false`); err != nil {
		t.Fatal(err)
	}

}
