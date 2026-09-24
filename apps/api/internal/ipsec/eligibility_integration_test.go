package ipsec_test

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func TestEligibilityReadOnlyAndScope(t *testing.T) {
	ctx, p, org, _, _, r := createFixture(t)
	s := ipsec.NewConnectionStore(p)
	snapshot := func() string {
		t.Helper()
		var v string
		if err := p.QueryRow(ctx, `SELECT concat(o.xmin::text,':',(SELECT count(*) FROM audit_logs WHERE org_id=o.id),':',(SELECT revision FROM ipsec_org_settings WHERE org_id=o.id),':',(SELECT count(*) FROM ipsec_connections WHERE org_id=o.id)) FROM organizations o WHERE id=$1`, org).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := snapshot()
	got, err := s.ReadEligibility(ctx, org, r.SiteID, r.GatewayID)
	if err != nil || !got.Eligible || got.Reason != "eligible" {
		t.Fatalf("eligible=%+v %v", got, err)
	}
	if snapshot() != before {
		t.Fatal("read wrote state/version/audit")
	}
	for _, q := range [][2]uuid.UUID{{uuid.New(), r.GatewayID}, {r.SiteID, uuid.New()}} {
		got, err = s.ReadEligibility(ctx, org, q[0], q[1])
		if err != nil || got.Eligible || got.Reason != "gateway_unavailable" {
			t.Fatalf("scope=%+v %v", got, err)
		}
	}
	if _, err = s.ReadEligibility(ctx, uuid.New(), r.SiteID, r.GatewayID); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("foreign org exposed")
	}
	for _, tc := range []struct{ sql, reason string }{
		{`UPDATE nodes SET capabilities='{"ipsec_config_version":0}' WHERE id=$1`, "unsupported"},
		{`UPDATE nodes SET capabilities='{"ipsec_config_version":2}' WHERE id=$1`, "unsupported"},
		{`UPDATE nodes SET capabilities='{"ipsec_config_version":"1"}' WHERE id=$1`, "unsupported"},
		{`UPDATE nodes SET capabilities='{"ipsec_config_version":1}',policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, "report_stale"},
		{`UPDATE nodes SET policy_reported_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, "report_stale"},
		{`UPDATE nodes SET policy_reported_at=NULL WHERE id=$1`, "report_stale"},
		{`UPDATE nodes SET policy_reported_at=clock_timestamp(),revoked_at=clock_timestamp() WHERE id=$1`, "gateway_unavailable"},
		{`UPDATE nodes SET revoked_at=NULL,status='revoked' WHERE id=$1`, "gateway_unavailable"},
		{`UPDATE nodes SET status='active',cert_serial='' WHERE id=$1`, "gateway_unavailable"},
	} {
		if _, err = p.Exec(ctx, tc.sql, r.GatewayID); err != nil {
			t.Fatal(err)
		}
		before = snapshot()
		got, err = s.ReadEligibility(ctx, org, r.SiteID, r.GatewayID)
		if err != nil || got.Eligible || got.Reason != tc.reason {
			t.Fatalf("got=%+v err=%v want%s", got, err, tc.reason)
		}
		if snapshot() != before {
			t.Fatal("refusal read wrote")
		}
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_org_settings SET enabled=false,revision=revision+1 WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadEligibility(ctx, org, r.SiteID, r.GatewayID)
	if err != nil || got.Reason != "opt_in_required" {
		t.Fatalf("optin=%+v %v", got, err)
	}
}
func TestEligibilityMissingSettingsAndDeletedOrganization(t *testing.T) {
	ctx, p, org, _ := settingsFixture(t)
	s := ipsec.NewConnectionStore(p)
	got, err := s.ReadEligibility(ctx, org, uuid.New(), uuid.New())
	if err != nil || got.Reason != "opt_in_required" {
		t.Fatalf("missing settings=%+v %v", got, err)
	}
	var count int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_org_settings WHERE org_id=$1`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("read inserted settings: %d %v", count, err)
	}
	if _, err = p.Exec(ctx, `UPDATE organizations SET deleted_at=clock_timestamp() WHERE id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadEligibility(ctx, org, uuid.New(), uuid.New()); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("deleted org admitted")
	}
}
