package ipsec_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// Each fault is a new authority observation. A refused transition must leave the
// disabled identity/revision intact and expose no delivery, including future clocks.
func TestGCPClassicActivationCapabilityAndClockGates(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnConfig.ConnString(), 224); err != nil {
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
	baseline := `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_gcp_classic_version":1}'::jsonb,policy_reported_at=clock_timestamp(),revoked_at=NULL WHERE id=$1`
	cases := []struct{ name, statement, reason string }{
		{"absent provider capability", `UPDATE nodes SET capabilities=capabilities-'ipsec_gcp_classic_version' WHERE id=$1`, "unsupported"},
		{"string provider capability", `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":"1"}'::jsonb WHERE id=$1`, "unsupported"},
		{"future provider version", `UPDATE nodes SET capabilities=capabilities||'{"ipsec_gcp_classic_version":2}'::jsonb WHERE id=$1`, "unsupported"},
		{"string base capability", `UPDATE nodes SET capabilities=capabilities||'{"ipsec_config_version":"1"}'::jsonb WHERE id=$1`, "unsupported"},
		{"expired report", `UPDATE nodes SET policy_reported_at=clock_timestamp()-interval '91 seconds' WHERE id=$1`, "report_stale"},
		{"future report", `UPDATE nodes SET policy_reported_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, "report_stale"},
		{"missing report", `UPDATE nodes SET policy_reported_at=NULL WHERE id=$1`, "report_stale"},
		{"revoked enrollment", `UPDATE nodes SET revoked_at=clock_timestamp() WHERE id=$1`, "gateway_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Exec(ctx, baseline, identity.GatewayID); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(ctx, tc.statement, identity.GatewayID); err != nil {
				t.Fatal(err)
			}
			e, err := store.ReadEligibility(ctx, org, req.SiteID, req.GatewayID)
			if err != nil || e.GCPClassic == nil || e.GCPClassic.Eligible || e.GCPClassic.Reason != tc.reason {
				t.Fatalf("unexpected advisory reason: %+v error=%v", e, err)
			}
			if _, err := store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
				t.Fatalf("authority fault admitted: %v", err)
			}
			got, err := store.Read(ctx, org, c.ID)
			if err != nil || got.DesiredIntent != "disabled" || got.DesiredRevision != c.DesiredRevision {
				t.Fatal("refusal mutated intent/revision", err)
			}
			var deliveries int
			if err := p.QueryRow(ctx, `SELECT count(*) FROM ipsec_runtime_deliveries WHERE connection_id=$1`, c.ID).Scan(&deliveries); err != nil || deliveries != 0 {
				t.Fatal("refusal exposed delivery", err)
			}
		})
	}
	if _, err = p.Exec(ctx, baseline, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	store.ConfigureRuntimePolicy(nil)
	if _, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(err, ipsec.ErrConnectionIneligible) {
		t.Fatal("missing policy compiler admitted", err)
	}
	// Fresh numeric capability is independently accepted once the common compiler
	// is explicitly available; this is recovery from modeled faults, not a retry.
	store.ConfigureRuntimePolicy(runtimeCompiler)
	if _, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); err != nil {
		t.Fatal("qualified authority refused", err)
	}
}
