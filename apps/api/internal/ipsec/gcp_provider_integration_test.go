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

func TestGCPHADisabledPersistenceCapabilityAndRollback(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config = bgpConfigFixture()
	req.Config.ProfileID = ipsec.GCPHAProfile
	// Ranges reserved by AWS are valid candidate peering pairs for Google.
	for i := range req.Config.Tunnels {
		if i == 0 {
			req.Config.Tunnels[i].InsideCIDR = "169.254.1.0/30"
			req.Config.Tunnels[i].CustomerInsideAddress = "169.254.1.1"
			req.Config.Tunnels[i].CloudInsideAddress = "169.254.1.2"
		} else {
			req.Config.Tunnels[i].InsideCIDR = "169.254.2.0/30"
			req.Config.Tunnels[i].CustomerInsideAddress = "169.254.2.1"
			req.Config.Tunnels[i].CloudInsideAddress = "169.254.2.2"
		}
		req.Config.Tunnels[i].PSK = "0-GCP-secret!"
	}
	req.Config.BGP.RemoteASN = 65002
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadProvider(ctx, org, c.ID)
	if err != nil || got.ProfileID != ipsec.GCPHAProfile || got.Config == nil || got.Config.ProfileID != ipsec.GCPHAProfile || got.Config.Tunnels[0].InsideCIDR != "169.254.1.0/30" {
		t.Fatalf("GCP read mismatch: %v", err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "psk") {
		t.Fatal("secret projection leaked")
	}
	if _, err = s.ReadProvider(ctx, uuid.New(), c.ID); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("cross-org read admitted")
	}
	if _, err = s.SetIntent(ctx, org, actor, c.ID, 1, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("legacy runtime enable: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities||'{"ipsec_bgp_version":1,"ipsec_gcp_ha_version":1}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	eligible, err := s.ReadEligibility(ctx, org, req.SiteID, req.GatewayID)
	if err != nil || eligible.GCPHA == nil || !eligible.GCPHA.Eligible {
		t.Fatalf("GCP capability ignored: %v", err)
	}
	enabled, err := s.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	material, err := s.Material(ctx, principal, c.ID, enabled.DesiredRevision, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if material.Manifest.ProfileID != ipsec.GCPHAProfile || material.Manifest.BGPVersion == nil || *material.Manifest.BGPVersion != 2 || material.Secrets[0].PSK != "0-GCP-secret!" {
		t.Fatal("GCP material contract mismatch")
	}
	again, err := s.Material(ctx, principal, c.ID, enabled.DesiredRevision, sealer)
	if err != nil || again.ID != material.ID {
		t.Fatal("GCP material not idempotent")
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities-'ipsec_gcp_ha_version' WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	report := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: enabled.DesiredRevision, ConfigurationRevision: 1, BGP: &ipsec.RuntimeBGPStatus{Version: 1}}
	if err = s.ReportStatus(ctx, principal, c.ID, report); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("revoked GCP observation admitted: %v", err)
	}
	if _, err = s.Material(ctx, principal, c.ID, enabled.DesiredRevision, sealer); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("revoked GCP material admitted: %v", err)
	}
	disabled, err := s.SetIntent(ctx, org, actor, c.ID, enabled.DesiredRevision, "disabled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetIntent(ctx, org, actor, c.ID, disabled.DesiredRevision, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatalf("revoked runtime capability admitted: %v", err)
	}
	if err = db.MigrateTo(p.Config().ConnConfig.ConnString(), 222); err != nil {
		t.Fatal(err)
	}
	if err = db.DownOne(p.Config().ConnConfig.ConnString()); err == nil || !strings.Contains(err.Error(), "GCP HA history") {
		t.Fatal("rollback discarded GCP history")
	}
}
func TestGCPHAMigrationRollbackWithoutHistory(t *testing.T) {
	_, p, _, _, _, _ := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(p.Config().ConnConfig.ConnString()); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err != nil {
		t.Fatal(err)
	}
}
