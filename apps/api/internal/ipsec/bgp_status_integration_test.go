package ipsec_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
	"time"
)

func TestBGPStatusIdentitySequenceFreshnessAndNoAuthority(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 216); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config = bgpConfigFixture()
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP != nil || out.Tunnels[0].Selected {
		t.Fatalf("missing BGP projection aliases static: %+v %v", out, err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	// Synthetic full capability enables fixture delivery only; service activation stays closed.
	if _, err = p.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	material, err := s.Material(ctx, principal, c.ID, 2, sealer)
	if err != nil {
		t.Fatal(err)
	}
	r := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: 2, ConfigurationRevision: 1, BGP: &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]ipsec.RuntimeBGPPeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1}}, Routes: []ipsec.RuntimeBGPRoute{{Prefix: "10.20.0.0/16", Slot: 1}}}}
	for i := range r.Tunnels {
		r.Tunnels[i] = ipsec.RuntimeTunnelStatus{ID: material.Manifest.Tunnels[i].ID, Slot: i + 1, Status: "up"}
	}
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	out, err = s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP == nil || out.BGP.Sequence != 1 || out.ActiveSlot != nil || out.Tunnels[0].Selected {
		t.Fatalf("BGP readback: %+v %v", out, err)
	}
	missing := r
	missing.BGP = nil
	missing.Tunnels[0].Status = "unknown"
	if err = s.ReportStatus(ctx, principal, c.ID, missing); err != nil {
		t.Fatalf("missing observer report: %v", err)
	}
	out, err = s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP != nil || out.Tunnels[0].Status != "unknown" {
		t.Fatalf("old observation revived: %+v %v", out, err)
	}
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	out, err = s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP != nil {
		t.Fatal("equal sequence retry revived old BGP", err)
	}
	badMissing := missing
	v := 1
	badMissing.RecoveryVersion = &v
	if err = s.ReportStatus(ctx, principal, c.ID, badMissing); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("ambiguous recovery admitted: %v", err)
	}
	r.BGP.Sequence = 2
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	out, err = s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP == nil || out.BGP.Sequence != 2 {
		t.Fatal("fresh observation not restored", err)
	}
	if _, err = s.ReadStatus(ctx, uuid.New(), c.ID); !errors.Is(err, ipsec.ErrConnectionNotFound) {
		t.Fatal("cross-tenant BGP observation admitted")
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_bgp_status SET received_at=clock_timestamp()-interval '89 seconds' WHERE connection_id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err = p.QueryRow(ctx, `SELECT received_at FROM ipsec_bgp_status WHERE connection_id=$1`, c.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	if err = p.QueryRow(ctx, `SELECT received_at FROM ipsec_bgp_status WHERE connection_id=$1`, c.ID).Scan(&after); err != nil || !before.Equal(after) {
		t.Fatal("exact retry extended freshness", err)
	}
	clone := func() ipsec.RuntimeStatusReport {
		raw, _ := json.Marshal(r)
		var out ipsec.RuntimeStatusReport
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	bad := clone()
	bad.BGP.Peers[0].RejectedPrefixes = new(int)
	if err = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("same sequence changed body: %v", err)
	}
	bad = clone()
	bad.BGP.Routes[0].Prefix = "10.20.1.0/24"
	if err = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(err, ipsec.ErrConnectionInvalid) {
		t.Fatalf("unapproved more-specific route admitted: %v", err)
	}
	r.BGP.Sequence = 3
	r.BGP.Routes = []ipsec.RuntimeBGPRoute{}
	for i := range r.BGP.Peers {
		r.BGP.Peers[i].State = "idle"
		r.BGP.Peers[i].AcceptedPrefixes = 0
		r.BGP.Peers[i].InstalledPrefixes = 0
		r.Tunnels[i].Status = "down"
	}
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	bad = clone()
	bad.BGP.Sequence = 1
	if err = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(err, ipsec.ErrConnectionConflict) {
		t.Fatalf("lower sequence admitted: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE ipsec_bgp_status SET received_at=clock_timestamp()-interval '91 seconds' WHERE connection_id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	out, err = s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP != nil || out.Tunnels[0].Status != "unknown" {
		t.Fatal("stale BGP evidence reused", err)
	}
	// Status reporting cannot apply a configuration or create a forwarding lease.
	var applied *int64
	if err = p.QueryRow(ctx, `SELECT applied_revision FROM ipsec_runtime_state WHERE connection_id=$1`, c.ID).Scan(&applied); err != nil || applied != nil {
		t.Fatal("BGP status granted runtime authority", err)
	}
}

func TestBGPStatusPerPeerMigrationBound(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 217); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); err != nil {
		t.Fatal(err)
	}
	req := providerRequest(identity)
	req.Config = bgpConfigFixture()
	req.Config.BGP.MaximumPrefixes = 1
	req.Config.RemotePrefixes = []string{"10.20.0.0/16", "10.30.0.0/16"}
	s := ipsec.NewConnectionStore(p)
	s.ConfigureRuntimePolicy(runtimeCompiler)
	c, err := s.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.ReadStatus(ctx, org, c.ID)
	if err != nil || out.BGP != nil || out.Tunnels[0].Selected {
		t.Fatalf("missing BGP projection aliases static: %+v %v", out, err)
	}
	if _, err = p.Exec(ctx, `UPDATE nodes SET capabilities='{"ipsec_config_version":1,"ipsec_bgp_version":1}',policy_reported_at=clock_timestamp() WHERE id=$1`, identity.GatewayID); err != nil {
		t.Fatal(err)
	}
	// Synthetic full capability enables fixture delivery only; service activation stays closed.
	if _, err = p.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	material, err := s.Material(ctx, principal, c.ID, 2, sealer)
	if err != nil {
		t.Fatal(err)
	}

	r := ipsec.RuntimeStatusReport{DeliveryID: material.ID, DesiredRevision: 2, ConfigurationRevision: 1, BGP: &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 1, Peers: [2]ipsec.RuntimeBGPPeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}}, Routes: []ipsec.RuntimeBGPRoute{{Prefix: "10.20.0.0/16", Slot: 1}, {Prefix: "10.30.0.0/16", Slot: 2}}}}
	for i := range r.Tunnels {
		r.Tunnels[i] = ipsec.RuntimeTunnelStatus{ID: material.Manifest.Tunnels[i].ID, Slot: i + 1, Status: "up"}
	}
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal("disjoint per-peer limit1 union2", err)
	}
	raw, _ := json.Marshal(r)
	var before []byte
	if err = p.QueryRow(ctx, `SELECT report FROM ipsec_bgp_status WHERE connection_id=$1`, c.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = db.DownOne(p.Config().ConnString()); err == nil || !strings.Contains(err.Error(), "Cannot downgrade while BGP union exceeds legacy bound") {
		t.Fatalf("unsafe downgrade: %v", err)
	}
	if _, err = p.Exec(ctx, `UPDATE schema_migrations SET version=217,dirty=false`); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err = p.QueryRow(ctx, `SELECT report FROM ipsec_bgp_status WHERE connection_id=$1`, c.ID).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("downgrade changed status", err)
	}
	for _, mutation := range []string{"accepted", "unapproved"} {
		var bad ipsec.RuntimeStatusReport
		_ = json.Unmarshal(raw, &bad)
		bad.BGP.Sequence = 2
		if mutation == "accepted" {
			bad.BGP.Peers[0].AcceptedPrefixes = 2
		} else {
			bad.BGP.Routes[0].Prefix = "10.40.0.0/16"
		}
		if err = s.ReportStatus(ctx, principal, c.ID, bad); !errors.Is(err, ipsec.ErrConnectionInvalid) {
			t.Fatalf("%s admitted: %v", mutation, err)
		}
		badraw, _ := json.Marshal(bad)
		if _, err = p.Exec(ctx, `UPDATE ipsec_bgp_status SET report=$2 WHERE connection_id=$1`, c.ID, badraw); err == nil {
			t.Fatalf("DB %s admitted", mutation)
		}
	}
	r.BGP.Sequence = 2
	r.BGP.Routes = r.BGP.Routes[:1]
	r.BGP.Peers[1].InstalledPrefixes = 0
	if err = s.ReportStatus(ctx, principal, c.ID, r); err != nil {
		t.Fatal(err)
	}
	if err = db.DownOne(p.Config().ConnString()); err != nil {
		t.Fatal("compatible downgrade", err)
	}
}
