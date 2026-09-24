package ipsec_test

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func TestTunnelStatusIdentityFreshnessAndNoAuthority(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 161); e != nil {
		t.Fatal(e)
	}
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(func(context.Context, *sqlc.Queries, ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
		return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), Grants: []ipsec.RuntimeGrant{}}, nil
	})
	c, e := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	status, e := s.ReadStatus(ctx, org, c.ID)
	if e != nil || len(status.Tunnels) != 2 || status.ObservedAt != nil || status.Tunnels[0].Status != "unknown" {
		t.Fatal("missing report must be unknown", e)
	}
	c, e = s.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	var serial string
	if e = p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	material, e := s.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
	if e != nil {
		t.Fatal(e)
	}
	report := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: c.DesiredRevision, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: req.TunnelIDs[0], Slot: 1, Status: "up", Selected: true}, {ID: req.TunnelIDs[1], Slot: 2, Status: "down"}}}
	if e = s.ReportStatus(ctx, principal, c.ID, report); e != nil {
		t.Fatal(e)
	}
	status, e = s.ReadStatus(ctx, org, c.ID)
	if e != nil || status.ObservedAt == nil || status.Tunnels[0].Status != "up" || status.Tunnels[1].Status != "down" {
		t.Fatal("fresh evidence lost", e)
	}
	bad := report
	bad.Tunnels[0].ID = uuid.New()
	if e = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(e, ipsec.ErrConnectionInvalid) {
		t.Fatal("foreign tunnel accepted", e)
	}
	bad = report
	bad.DesiredRevision++
	if e = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("stale identity accepted", e)
	}
	for _, age := range []string{"91 seconds", "-1 seconds"} {
		if _, e = p.Exec(ctx, `UPDATE ipsec_tunnel_status SET received_at=clock_timestamp()-$2::interval WHERE connection_id=$1`, c.ID, age); e != nil {
			t.Fatal(e)
		}
		status, e = s.ReadStatus(ctx, org, c.ID)
		if e != nil || status.Tunnels[0].Status != "unknown" {
			t.Fatal("invalid freshness accepted", e)
		}
	}
	if e = s.ReportStatus(ctx, principal, c.ID, report); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE nodes SET revoked_at=clock_timestamp() WHERE id=$1`, req.GatewayID); e != nil {
		t.Fatal(e)
	}
	status, e = s.ReadStatus(ctx, org, c.ID)
	if e != nil || status.Tunnels[0].Status != "unknown" {
		t.Fatal("revoked gateway still Up", e)
	}
	if e = s.ReportStatus(ctx, principal, c.ID, report); !errors.Is(e, ipsec.ErrRuntimeUnauthorized) {
		t.Fatal("revoked report accepted", e)
	}

	var before, after string
	if e = p.QueryRow(ctx, `SELECT xmin::text FROM ipsec_tunnel_status WHERE connection_id=$1`, c.ID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadStatus(ctx, org, c.ID); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `SELECT xmin::text FROM ipsec_tunnel_status WHERE connection_id=$1`, c.ID).Scan(&after); e != nil || before != after {
		t.Fatal("read mutated observation", e)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 160); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_runtime_deliveries WHERE connection_id=$1`, c.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("telemetry rollback altered authority", e)
	}
	if e = db.MigrateTo(p.Config().ConnString(), 161); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadStatus(ctx, uuid.New(), c.ID); !errors.Is(e, ipsec.ErrConnectionNotFound) {
		t.Fatal("scope crossed", e)
	}
}
