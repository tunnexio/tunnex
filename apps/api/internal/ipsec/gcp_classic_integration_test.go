package ipsec_test

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func TestGCPClassicSingleActualTunnelLifecycle(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 223); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config.ProfileID = ipsec.GCPClassicProfile
	req.Config.Tunnels = req.Config.Tunnels[:1]
	req.TunnelIDs[1] = uuid.Nil
	req.Config.Tunnels[0].InsideCIDR = ""
	req.Config.Tunnels[0].CustomerInsideAddress = ""
	req.Config.Tunnels[0].CloudInsideAddress = ""
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.ReadProvider(ctx, org, c.ID)
	if err != nil || cfg.Config == nil || len(cfg.Config.Tunnels) != 1 || cfg.Config.Tunnels[0].CloudInsideAddress != "" {
		t.Fatal("Classic disabled read shape", err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_tunnels WHERE connection_id=$1`, c.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("fabricated second tunnel", err)
	}
	c, err = store.RotatePSKs(ctx, org, actor, c.ID, c.DesiredRevision, []ipsec.RotatePSK{{TunnelID: req.TunnelIDs[0], PSK: "0-rotated-GCP!"}}, sealer)
	if err != nil {
		t.Fatal("Classic PSK maintenance", err)
	}
	if _, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatal("unqualified Classic activated", err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	c, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	material, err := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if material.Manifest.TransportVersion == nil || *material.Manifest.TransportVersion != 1 || material.Manifest.TunnelCount == nil || *material.Manifest.TunnelCount != 1 || material.Manifest.Tunnels[1] != (ipsec.RuntimeTunnel{}) || material.Secrets[1] != (ipsec.RuntimeSecret{}) || material.Secrets[0].PSK != "0-rotated-GCP!" {
		t.Fatal("Classic material active count invalid")
	}
	version, n := 1, 1
	report := ipsec.RuntimeStatusReport{TransportVersion: &version, TunnelCount: &n, DeliveryID: material.ID, DesiredRevision: c.DesiredRevision, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: material.Manifest.Tunnels[0].ID, Slot: 1, Selected: true, Status: "up"}, {}}}
	if err = store.ReportStatus(ctx, principal, c.ID, report); err != nil {
		t.Fatal(err)
	}
	health, err := store.ReadStatus(ctx, org, c.ID)
	if err != nil || len(health.Tunnels) != 1 || health.Tunnels[0].Status != "up" {
		t.Fatal("Classic observed health", err)
	}
	report.Tunnels[1].Slot = 2
	if err = store.ReportStatus(ctx, principal, c.ID, report); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatal("inactive observation accepted", err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_gcp_classic_version' WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatal("revoked Classic material accepted", err)
	}
	c, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "disabled")
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
	if err != nil {
		t.Fatal(err)
	}
	err = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: c.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err = store.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
	if err != nil || c.FinalizedAt == nil {
		t.Fatal("Classic finalized delete", err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":1,"ipsec_retained_guard_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	req.ID = uuid.New()
	req.TunnelIDs[0] = uuid.New()
	recreated, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal("Classic disabled recreate", err)
	}
	recreated, err = store.SetIntent(ctx, org, actor, recreated.ID, recreated.DesiredRevision, "enabled")
	if err != nil {
		advisory, advisoryErr := store.ReadEligibility(ctx, org, req.SiteID, req.GatewayID)
		var configured, classic, retained, opted bool
		var age float64
		var cleanupPending bool
		probeErr := p.QueryRow(ctx, `SELECT COALESCE(n.capabilities->'ipsec_config_version'='1'::jsonb,false),COALESCE(n.capabilities->'ipsec_gcp_classic_version'='1'::jsonb,false),COALESCE(n.capabilities->'ipsec_retained_guard_version'='1'::jsonb,false),extract(epoch from clock_timestamp()-n.policy_reported_at)::float8,o.enabled,EXISTS(SELECT 1 FROM ipsec_runtime_state s WHERE s.connection_id=$2 AND s.current_cleanup_id IS NOT NULL) FROM nodes n JOIN ipsec_org_settings o ON o.org_id=n.org_id WHERE n.id=$1`, identity.GatewayID, req.ID).Scan(&configured, &classic, &retained, &age, &opted, &cleanupPending)
		t.Fatalf("Classic recreate enable: %v; advisory=%+v advisory_error=%v config_cap=%t classic_cap=%t retained_cap=%t report_age_seconds=%.3f opt_in=%t cleanup_pending=%t probe_error=%v", err, advisory, advisoryErr, configured, classic, retained, age, opted, cleanupPending, probeErr)
	}
	next, err := store.Material(ctx, principal, recreated.ID, recreated.DesiredRevision, sealer)
	if err != nil || len(next.Manifest.RetainedGuardPredecessors) != 1 {
		t.Fatal("Classic retained guard lineage", err)
	}
}

func TestGCPClassicMigrationRollbackWithoutHistory(t *testing.T) {
	_, p, _, _, _, _ := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 223); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(p.Config().ConnConfig.ConnString()); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 223); err != nil {
		t.Fatal(err)
	}
}
